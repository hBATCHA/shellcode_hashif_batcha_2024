# 🦠 Infecteur de fichiers ELF

Projet réalisé dans le cadre du cours de sécurité shellcode. L'objectif était de créer un infecteur de fichiers ELF basique pour comprendre les techniques d'injection de shellcode et la manipulation des binaires sous Linux.

⚠️ **Important** : Ce projet est uniquement éducatif ! Ne l'utilisez pas pour faire n'importe quoi.

## C'est quoi au juste ?

C'est un petit programme qui peut modifier des fichiers ELF (les exécutables Linux, comme les .exe sous Windows) pour y ajouter du code tout en faisant en sorte que le programme continue de marcher normalement. 

## Ce qu'il peut faire

- Infecter un seul fichier
- Garder le programme original fonctionnel

## Pour l'installer

1. D'abord, clonez le projet :
```bash
git clone <lien_du_projet>
cd <dossier_du_projet>
```

2. Compilez l'infecteur avec ces commandes :
```bash
nasm -f elf64 projet_shellcode.s -o projet_shellcode.o
ld projet_shellcode.o -o projet_shellcode
```

## Comment l'utiliser

### Pour infecter un fichier
```bash
./projet_shellcode mon_fichier
```

Par exemple :
```bash
cp /bin/ls mon_ls  # On fait une copie de ls pour tester
./projet_shellcode mon_ls
```

### Pour tester si ça marche
Lancez simplement le fichier infecté :
```bash
./mon_ls
```
Vous devriez voir une petite surprise s'afficher avant que le programme fonctionne normalement 😉

### Pour voir ce qui a changé
Utilisez `readelf` pour voir les modifications dans le fichier :
```bash
readelf -l mon_ls
```

## Trucs à savoir

- Ça marche que sur Linux (testé sur x86_64)
- Les fichiers doivent être au format ELF (pas de .exe Windows !)

## Petit exemple complet

1. On prépare un fichier à infecter :
```bash
cp /bin/ls mon_ls
```

2. On infecte le fichier :
```bash
./projet_shellcode mon_ls
```

3. On teste :
```bash
./mon_ls  # Vous devriez voir le payload avant la liste des fichiers
```

## Comment ça marche ?

Le programme modifie le fichier ELF en :
1. Ajoutant une nouvelle section pour notre code
2. Modifiant le point d'entrée pour exécuter notre code d'abord
3. Retournant au programme original ensuite

## Auteur et licence

Fait par Hashif BATCHA pendant mes études. C'est un projet pour apprendre, pas pour faire des bêtises ! 