---
title: CTFs | 404CTF_2023 | Forensique | Le Mystère du roman d'amour 
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Forensique]
tags: [Forensique,Vi, SWP]
permalink: /CTFs/404CTF_2023/Forensique/Le_Mystere_du_roman_d
---

# Le Mystère du roman d'amour 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a9a8ff32-6271-40a1-a159-19b1e18ca58e)


In this challenge, we are given a `swp` file available [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Forensique/fichier-etrange.swp). By reading about this type of file we find that SWP files, also known as swap files, are temporary files created by text editors, particularly Vi/Vim, to store changes made to a file while it is being edited. These files are used to recover unsaved changes in the event of a system crash, editor crash, or other unexpected interruptions.

We get practically all the flag when we just use the `file` command on the file:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a1daf05e-3fdd-4e08-a52f-8b295d89995c)

The PID is `168`, the full path to the file is `~jaqueline/Documents/Livres/404 Histoires d'Amour pour les bibliophiles au coeur d'artichaut/brouillon.txt` and so, the name of the Rouletabille's friend is `jaqueline` and the hostname is `aime_ecrire`.

By reading about how to recover the initial content of the `swp` file, I found that we need to use the command `vim -r fichier-etrange.swp `:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9cd88d4c-33ba-4b7d-8f44-355e91983c8a)

We now press enter and to save what seems to be a `PNG` file we hit `:w found_image.png` then we quit vi using `:q!`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f62c5bd3-10c4-4e42-9caf-7395ccdc0b42)

This doesn't seems really helpfull so i try to upload it to [Aperisolve](https://aperisolve.fr/). I then find the hiddden QRCode in the image:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/60e8edb2-7e6a-4a78-9b37-65ab94e40f70)


The result of the QRCode is:
```
Il était une fois, dans un village rempli d'amour, deux amoureux qui s'aimaient...

Bien joué ! Notre écrivaine va pouvoir reprendre son chef-d'oeuvre grâce à vous !
Voici ce que vous devez rentrer dans la partie "contenu du fichier" du flag : 3n_V01L4_Un_Dr0l3_D3_R0m4N
```
The final flag is then: `404CTF{168-~jaqueline/Documents/Livres/404 Histoires d'Amour pour les bibliophiles au coeur d'artichaut/brouillon.txt-jaqueline-aime_ecrire-3n_V01L4_Un_Dr0l3_D3_R0m4N}`
