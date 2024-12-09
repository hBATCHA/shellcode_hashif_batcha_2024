section .data
    magic_bytes db 0x7F, "ELF"    ; Signature ELF standard
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    err_len equ $ - err_msg
    dir_msg db "C'est un répertoire", 10
    dir_len equ $ - dir_msg
    elf_msg db "C'est un fichier ELF.", 10
    elf_len equ $ - elf_msg
    
    ; Messages d'entête ELF
    msg_type db "Type de fichier: ", 0
    msg_machine db "Machine cible: ", 0
    msg_version db "Version: ", 0
    msg_entry db "Point d'entrée: ", 0
    msg_phoff db "Offset de la table des programmes: ", 0
    msg_shoff db "Offset de la table des sections: ", 0
    msg_flags db "Flags: ", 0
    msg_ehsize db "Taille de l'en-tête ELF: ", 0
    msg_phentsize db "Taille d'une entrée du programme: ", 0
    msg_phnum db "Nombre d'entrées du programme: ", 0
    msg_shentsize db "Taille d'une entrée de section: ", 0
    msg_shnum db "Nombre d'entrées de section: ", 0
    msg_shstrndx db "Index de la table des chaînes de section: ", 0
    
    ; Messages Program Header
    msg_ph db "Program Header ", 0
    msg_ph_type db "  p_type: ", 0
    msg_ph_flags db "  p_flags: ", 0
    msg_ph_offset db "  p_offset: ", 0
    msg_ph_vaddr db "  p_vaddr: ", 0
    msg_ph_paddr db "  p_paddr: ", 0
    msg_ph_filesz db "  p_filesz: ", 0
    msg_ph_memsz db "  p_memsz: ", 0
    msg_ph_align db "  p_align: ", 0
    
    ; Tableau des descripteurs de champs avec leurs messages et offsets
    msg_offsets:
        dq msg_ph_type,    0
        dq msg_ph_flags,   4
        dq msg_ph_offset,  8
        dq msg_ph_vaddr,   16
        dq msg_ph_paddr,   24
        dq msg_ph_filesz,  32
        dq msg_ph_memsz,   40
        dq msg_ph_align,   48
    NUM_FIELDS equ 8
    newline db 10, 0

section .bss
    fd resq 1
    filename resq 1        ; Pour stocker le nom du fichier
    elf_header resb 64
    stat_buf resb 144      ; Buffer pour stocker les informations stat
    phdr resb 56
    hex_string resb 17

section .text
global _start

_start:
    ; Récupérer l'argument (nom du fichier)
    pop rdi                 ; Nombre d'arguments
    pop rdi                 ; Nom du programme
    pop rdi                 ; Premier argument (nom du fichier)
    mov [filename], rdi     ; Sauvegarder le nom du fichier
    
    ; Vérifier si c'est un répertoire avec stat
    mov rax, 4             ; sys_stat
    mov rsi, stat_buf      ; Buffer pour les informations
    syscall
    test rax, rax          ; Vérifier si stat a réussi
    js exit                ; Si erreur, sortir
    
    ; Vérifier si c'est un répertoire
    mov rax, qword [stat_buf + 24]  ; st_mode est à l'offset 24
    and rax, 0o170000               ; Masque pour obtenir le type de fichier
    cmp rax, 0o040000               ; Comparer avec S_IFDIR
    je is_directory
    
    ; Si ce n'est pas un répertoire, ouvrir le fichier
    mov rdi, [filename]     ; Récupérer le nom du fichier
    mov rax, 2             ; sys_open
    mov rsi, 0             ; Mode lecture uniquement (O_RDONLY)
    syscall
    cmp rax, 0
    jl exit                ; Erreur si descripteur négatif
    mov [fd], rax          ; Sauvegarder le descripteur de fichier
    
    ; Lire l'en-tête ELF
    mov rdi, rax           ; Descripteur de fichier
    mov rax, 0             ; sys_read
    mov rsi, elf_header    ; Buffer où stocker l'en-tête
    mov rdx, 64            ; Lire les 64 premiers octets
    syscall
    
    ; Vérifier la signature ELF
    mov rsi, elf_header
    mov rdi, magic_bytes
    mov rcx, 4             ; Comparer les 4 octets
    repe cmpsb             ; Comparer les octets
    jne not_elf
    
    ; Afficher le message ELF valide
    mov rax, 1             ; sys_write
    mov rdi, 1             ; stdout
    mov rsi, elf_msg
    mov rdx, elf_len
    syscall
    
    ; Afficher l'entête ELF
    call print_elf_header
    
    ; Lire et afficher les Program Headers
    movzx rcx, word [elf_header + 56] ; Nombre d'entrées Program Header
    mov rbx, 0                        ; Index des Program Headers
    
print_ph_loop:
    cmp rbx, rcx               ; Vérifier si tous les Program Headers ont été affichés
    jge exit_success
    push rcx
    push rbx
    
    ; Calculer l'offset du Program Header
    movzx rax, word [elf_header + 54]  ; Récupérer phentsize
    mul rbx                            ; Multiplier par l'index
    add rax, qword [elf_header + 32]   ; Ajouter phoff
    
    ; Se positionner au bon endroit dans le fichier ELF
    mov rdi, [fd]              ; Descripteur du fichier
    mov rsi, rax               ; Offset calculé
    xor rdx, rdx               ; SEEK_SET = 0
    mov rax, 8                 ; sys_lseek
    syscall
    
    ; Lire le Program Header
    mov rax, 0                        ; sys_read
    mov rdi, [fd]
    mov rsi, phdr                     ; Stocker dans `phdr`
    movzx rdx, word [elf_header + 54] ; Utiliser phentsize pour la taille exacte
    syscall
    
    ; Afficher le Program Header
    call print_program_header
    pop rbx
    pop rcx
    inc rbx                    ; Passer au Program Header suivant
    jmp print_ph_loop
    
print_elf_header:
    ; Afficher tous les champs principaux de l'en-tête ELF
    mov rdi, msg_type
    call print_string
    movzx rax, word [elf_header + 16]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Machine
    mov rdi, msg_machine
    call print_string
    movzx rax, word [elf_header + 18]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Version
    mov rdi, msg_version
    call print_string
    mov eax, dword [elf_header + 20]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Entrée
    mov rdi, msg_entry
    call print_string
    mov rax, qword [elf_header + 24]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Programmes
    mov rdi, msg_phoff
    call print_string
    mov rax, qword [elf_header + 32]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Sections
    mov rdi, msg_shoff
    call print_string
    mov rax, qword [elf_header + 40]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Flags
    mov rdi, msg_flags
    call print_string
    mov eax, dword [elf_header + 48]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Taille ELF
    mov rdi, msg_ehsize
    call print_string
    movzx rax, word [elf_header + 52]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Taille Programme
    mov rdi, msg_phentsize
    call print_string
    movzx rax, word [elf_header + 54]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Nombre Programme
    mov rdi, msg_phnum
    call print_string
    movzx rax, word [elf_header + 56]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Taille Section
    mov rdi, msg_shentsize
    call print_string
    movzx rax, word [elf_header + 58]
    call print_hex_padded
    call print_newline
    
    ; Afficher les informations de l'en-tête Nombre Section
    mov rdi, msg_shnum
    call print_string
    movzx rax, word [elf_header + 60]
    call print_hex_padded
    call print_newline

    ; Afficher les informations de l'en-tête Index Section
    mov rdi, msg_shstrndx
    call print_string
    movzx rax, word [elf_header + 62]
    call print_hex_padded
    call print_newline
    ret
    
print_program_header:
    ; Affiche les champs du Program Header actuel
    push rbp
    mov rbp, rsp
    push r12  ; Sauvegarde des registres pour les boucles
    push r13
    push r14
    
    ; Afficher l'en-tête
    mov rdi, msg_ph           ; Affiche "Program Header X"
    call print_string
    mov rax, rbx              ; rbx contient l'index du Program Header
    call print_dec
    call print_newline
    
    ; Initialiser le compteur et le pointeur
    xor r12, r12              ; Initialiser le compteur des champs
    mov r13, msg_offsets      ; Pointer sur les messages et offsets des champs
    mov r14, NUM_FIELDS       ; Nombre total de champs à traiter
    
.loop:
    cmp r12, r14              ; Parcours des champs du Program Header
    jge .done
    
    mov rdi, [r13]            ; Afficher le message du champ
    call print_string
    
    ; Calculer l'adresse de la valeur dans phdr
    mov rax, phdr
    add rax, [r13 + 8]             ; Ajouter l'offset
    
    ; Charger la valeur en fonction de sa taille
    cmp qword [r13 + 8], 4         ; Si offset est 4 (p_flags)
    je .load_dword
    mov rax, [rax]                 ; Charger un qword par défaut
    jmp .print_value
    
.load_dword:
    mov eax, [rax]                 ; Charger un dword pour p_flags

.print_value:
    call print_hex_padded          ; Afficher la valeur en hexadécimal
    call print_newline
    add r13, 16                    ; Passer au prochain champ
    inc r12
    jmp .loop

.done:
    pop r14                   ; Restaurer les registres
    pop r13
    pop r12
    pop rbp
    ret

print_string:
    ; Affiche une chaîne de caractères terminée par null
    push rax
    push rcx
    push rdx
    mov rcx, -1
    mov rsi, rdi

.count:
    inc rcx
    cmp byte [rsi + rcx], 0
    jne .count
    mov rax, 1                ; sys_write
    mov rdx, rcx              ; Longueur de la chaîne
    mov rdi, 1                ; stdout
    syscall
    pop rdx
    pop rcx
    pop rax
    ret

print_hex_padded:
    ; Convertit une valeur en hexadécimal avec padding et l'affiche
    push rbx
    push rcx
    push rdx
    push rdi
    mov rdi, hex_string        ; Buffer pour le résultat
    mov rcx, 16                ; Taille fixe pour afficher 16 caractères

.convert_loop:
    rol rax, 4                 ; Extraire un nybble (4 bits)
    mov dl, al
    and dl, 0x0F
    add dl, '0'
    cmp dl, '9'
    jle .store
    add dl, 7

.store:
    mov [rdi], dl              ; Stocker le caractère
    inc rdi
    dec rcx
    jnz .convert_loop
    mov rax, 1                 ; sys_write
    mov rdi, 1
    mov rsi, hex_string        ; Afficher la chaîne hexadécimale
    mov rdx, 16
    syscall
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    ret
 
print_dec:
    ; Convertit une valeur en décimal et l'affiche
    push rax
    push rbx
    push rcx
    push rdx
    mov rcx, 0
    mov rbx, 10
.divide_loop:
    xor rdx, rdx               ; Division par 10 pour extraire les chiffres
    div rbx
    push rdx                   ; Stocker le chiffre
    inc rcx
    test rax, rax
    jnz .divide_loop
.print_loop:
    pop rax                    ; Charger les chiffres dans l'ordre
    add al, '0'
    mov [hex_string], al
    push rcx
    mov rax, 1                 ; sys_write
    mov rdi, 1
    mov rsi, hex_string
    mov rdx, 1
    syscall
    pop rcx
    loop .print_loop
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
 
print_newline:
    ; Affiche un saut de ligne
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 1                 ; sys_write
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

exit_success:
    mov rax, 60
    xor rdi, rdi
    syscall

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
    mov rax, 60
    xor rdi, rdi
    syscall
