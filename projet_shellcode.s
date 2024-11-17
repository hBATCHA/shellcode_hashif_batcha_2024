section .data
fichier db "hello_world.txt", 0  ; Nom du fichier qu'on veut ouvrir

section .bss
fd resq 1                 ; Variable pour stocker le numéro du fichier
buffer resb 256           ; Mémoire pour stocker les données lues

section .text
global _start             ; Début du programme

_start:
    ; Ouvrir le fichier
	mov rax, 2             ; Appel système pour "ouvrir un fichier"
	lea rdi, [fichier]     ; Le nom du fichier à ouvrir
	mov rsi, 2             ; Mode lecture seule
	xor rdx, rdx           ; Pas besoin d'options supplémentaires
	syscall                ; On demande au système d'ouvrir le fichier
	mov [fd], rax          ; On garde le numéro du fichier (retour de l'appel système)

    ; Lire le contenu du fichier
	mov rax, 0             ; Appel système pour "lire un fichier"
	mov rdi, [fd]          ; On utilise le fichier qu'on a ouvert
	lea rsi, [buffer]      ; On mettra ce qu'on lit dans ce buffer
	mov rdx, 256           ; On veut lire jusqu'à 256 octets
	syscall                ; Lecture effectuée
	mov r8, rax            ; On garde combien d'octets ont été lus

    ; Afficher ce qu'on a lu
	mov rax, 1             ; Appel système pour "écrire des données"
	mov rdi, 1             ; 1 correspond à la sortie standard
	lea rsi, [buffer]      ; Ce qu'on veut afficher est dans le buffer
	mov rdx, r8            ; On affiche juste la quantité qu'on a lue
	syscall                ; Lancer l'affichage

    ; Fermer le fichier
	mov rax, 3             ; Appel système pour "fermer un fichier"
	mov rdi, [fd]          ; Le fichier qu'on avait ouvert
	syscall                ; On demande au système de le fermer

    ; Quitter le programme
	mov rax, 60            ; Appel système pour "terminer le programme"
	xor rdi, rdi           ; On indique qu'il n'y a pas d'erreur (code 0)
	syscall                ; Fin du programme

