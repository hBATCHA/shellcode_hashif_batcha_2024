section .data
    magic_bytes db 0x7F, "ELF"    ; Signature ELF standard
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    err_len equ $ - err_msg
    ok_msg db "Fichier ELF valide trouvé", 10  
    ok_len equ $ - ok_msg

section .bss
    header resb 16    ; Espace pour lire l'en-tête ELF

section .text
global _start

_start:
    ; Ouvrir et lire l'en-tête du fichier
    mov rax, 2              ; sys_open
    pop rdi                 ; Nombre d'arguments
    pop rdi                 ; Nom du programme
    pop rdi                 ; Premier argument (nom du fichier)
    mov rsi, 0             ; O_RDONLY
    syscall
    
    cmp rax, 0
    jl exit                ; Erreur si descripteur négatif
    
    mov rdi, rax           ; Descripteur de fichier
    mov rax, 0             ; sys_read
    mov rsi, header        ; Buffer où stocker l'en-tête
    mov rdx, 16            ; Lire les 16 premiers octets
    syscall
    
    ; Vérifier la signature ELF
    mov rsi, header
    mov rdi, magic_bytes
    mov rcx, 4             ; Comparer les 4 octets
    repe cmpsb             ; Instruction assembleur qui compare octet de rsi et de rdi
    jne not_elf
    
    ; C'est un fichier ELF valide
    mov rax, 1             ; sys_write
    mov rdi, 1             ; stdout
    mov rsi, ok_msg  
    mov rdx, ok_len
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
