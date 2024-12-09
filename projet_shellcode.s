section .data
    magic_bytes db 0x7F, "ELF"    ; Signature ELF standard
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    err_len equ $ - err_msg
    dir_msg db "C'est un répertoire", 10
    dir_len equ $ - dir_msg
    elf_msg db "C'est un fichier ELF.", 10
    elf_len equ $ - elf_msg
    mod_msg db "Un segment PT_NOTE a été modifié en PT_LOAD avec les permissions RE", 10
    mod_len equ $ - mod_msg
    
section .bss
    fd resq 1
    filename resq 1
    elf_header resb 64
    stat_buf resb 144
    phdr resb 56          ; Structure pour stocker un program header

section .text
global _start

_start:
    pop rdi                 ; Nombre d'arguments
    pop rdi                 ; Nom du programme
    pop rdi                 ; Premier argument (nom du fichier)
    mov [filename], rdi
    
    ; Vérifier si c'est un répertoire
    mov rax, 4             ; sys_stat
    mov rsi, stat_buf
    syscall
    test rax, rax
    js exit
    
    ; Vérifier le type de fichier
    mov rax, qword [stat_buf + 24]
    and rax, 0o170000
    cmp rax, 0o040000
    je is_directory
    
    ; Ouvrir le fichier
    mov rdi, [filename]
    mov rax, 2             ; sys_open
    mov rsi, 2             ; O_RDWR pour pouvoir modifier le fichier
    syscall
    cmp rax, 0
    jl exit
    mov [fd], rax
    
    ; Lire l'en-tête ELF
    mov rdi, rax
    mov rax, 0             ; sys_read
    mov rsi, elf_header
    mov rdx, 64
    syscall
    
    ; Vérifier la signature ELF
    mov rsi, elf_header
    mov rdi, magic_bytes
    mov rcx, 4
    repe cmpsb
    jne not_elf
    
    ; Afficher que c'est un fichier ELF valide
    mov rax, 1
    mov rdi, 1
    mov rsi, elf_msg
    mov rdx, elf_len
    syscall
    
    ; Parcourir les Program Headers
    movzx rcx, word [elf_header + 56]  ; e_phnum (nombre de program headers)
    mov rbx, 0                         ; Index du program header actuel

scan_headers:
    cmp rbx, rcx
    jge exit

    ; Calculer l'offset du Program Header
    movzx rax, word [elf_header + 54]  ; e_phentsize
    mul rbx
    add rax, qword [elf_header + 32]   ; e_phoff
    
    ; Lire le Program Header
    mov rdi, [fd]
    mov rsi, rax                       ; Offset calculé
    xor rdx, rdx                       ; SEEK_SET
    mov rax, 8                         ; sys_lseek
    syscall
    
    mov rdi, [fd]
    mov rax, 0                         ; sys_read
    mov rsi, phdr
    mov rdx, 56                        ; Taille d'un program header
    syscall
    
    ; Vérifier si c'est un PT_NOTE (type 4)
    mov eax, dword [phdr]
    cmp eax, 4                         ; PT_NOTE
    je modify_header
    
    inc rbx
    jmp scan_headers

modify_header:
    ; Modifier le type en PT_LOAD (1)
    mov dword [phdr], 1
    
    ; Modifier les flags en RE (read + execute = 5)
    mov dword [phdr + 4], 5           ; PF_R | PF_X
    
    ; Écrire les modifications
    mov rdi, [fd]
    movzx rax, word [elf_header + 54]  ; e_phentsize
    mul rbx
    add rax, qword [elf_header + 32]   ; e_phoff
    
    mov rdi, [fd]
    mov rsi, rax
    xor rdx, rdx
    mov rax, 8                         ; sys_lseek
    syscall
    
    mov rdi, [fd]
    mov rax, 1                         ; sys_write
    mov rsi, phdr
    mov rdx, 56
    syscall
    
    ; Afficher le message de modification
    mov rax, 1
    mov rdi, 1
    mov rsi, mod_msg
    mov rdx, mod_len
    syscall
    
    jmp exit

is_directory:
    mov rax, 1
    mov rdi, 1
    mov rsi, dir_msg
    mov rdx, dir_len
    syscall
    jmp exit

not_elf:
    mov rax, 1
    mov rdi, 1
    mov rsi, err_msg
    mov rdx, err_len
    syscall
    jmp exit

exit:
    mov rax, 3                         ; sys_close
    mov rdi, [fd]
    syscall
    
    mov rax, 60                        ; sys_exit
    xor rdi, rdi
    syscall