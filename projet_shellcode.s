section .data
    magic_bytes db 0x7F, "ELF"    ; Signature ELF standard
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    err_len equ $ - err_msg
    dir_msg db "C'est un répertoire", 10
    dir_len equ $ - dir_msg
    elf_msg db "C'est un fichier ELF exécutable !", 10
    elf_len equ $ - elf_msg

section .bss
    header resb 16         ; Espace pour lire l'en-tête ELF
    stat_buf resb 144      ; Buffer pour stocker les informations stat

section .text
global _start

_start:
    ; Récupérer l'argument (nom du fichier)
    pop rdi                 ; Nombre d'arguments
    pop rdi                 ; Nom du programme
    pop rdi                 ; Premier argument (nom du fichier)
    
    ; Vérifier si c'est un répertoire avec stat
    mov rax, 4             ; sys_stat
    mov rsi, stat_buf      ; Buffer pour les informations
    syscall
    
    test rax, rax          ; Vérifier si stat a réussi
    js exit                ; Si erreur, sortir
    
    ; Vérifier si c'est un répertoire
    mov rax, qword [stat_buf + 24]  ; st_mode est à l'offset 24
    and rax, 0o170000      ; Masque pour obtenir le type de fichier
    cmp rax, 0o040000      ; Comparer avec S_IFDIR
    je is_directory
    
    ; Si ce n'est pas un répertoire, ouvrir le fichier
    mov rax, 2             ; sys_open
    mov rsi, 0             ; Mode lecture uniquement (O_RDONLY)
    syscall
    
    cmp rax, 0
    jl exit                ; Erreur si descripteur négatif
    
    ; Lire l'en-tête
    mov rdi, rax           ; Descripteur de fichier
    mov rax, 0             ; sys_read
    mov rsi, header        ; Buffer où stocker l'en-tête
    mov rdx, 16            ; Lire les 16 premiers octets
    syscall
    
    ; Vérifier la signature ELF
    mov rsi, header
    mov rdi, magic_bytes
    mov rcx, 4             ; Comparer les 4 octets
    repe cmpsb		   ; Instruction assembleur qui compare octet de rsi et de rdi
    jne not_elf
    
    ; C'est un fichier ELF
    mov rax, 1             ; sys_write
    mov rdi, 1             ; stdout
    mov rsi, elf_msg	   ; Afficher le message correspondant
    mov rdx, elf_len
    syscall
    jmp exit

is_directory:
    mov rax, 1             ; sys_write
    mov rdi, 1             ; stdout
    mov rsi, dir_msg
    mov rdx, dir_len
    syscall
    jmp exit
    
not_elf:
    mov rax, 1             ; sys_write
    mov rdi, 1             ; stdout
    mov rsi, err_msg
    mov rdx, err_len
    syscall
    
exit:
    mov rax, 60            ; sys_exit
    xor rdi, rdi           ; code 0
    syscall
