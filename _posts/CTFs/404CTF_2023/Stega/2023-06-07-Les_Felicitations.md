---
title: CTFs | 404CTF_2023 | Stega | Les Félicitations
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Stega]
tags: [Stega, Text]
permalink: /CTFs/404CTF_2023/Stega/Les_Felicitations
---

# Les Félicitations

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f6df6cff-a684-4558-93af-997ca4fa2217)

In this challenge, we just have the above text. If we try to decode the morse, we just find `LE CODE MORSE CEST SYMPA MAIS LA CA SERT A RIEN HAHA`... Nothing helpful. But if they put something like that in the text, it should be for a reason...

And if we take the text as 3 paragraphs, we can find 3 words. To do so, we need to take the first character of the first line, the second of the second line and so on... Note that spaces are counted as characters so don't forget them (as I did :'( ).

So the first paragraph is:

```
**T**ous étaient réunis dans la salle,
C**r**iblant leur feuille de mots et posant leurs esprits sur papier.
Tr**è**s encouragés par le déroulement des opérations,
Il **s**uffisait simplement de les regarder pour voir leur dévotion
```

So we got `Très`, now for the second paragraph:
```
**B**eaucoup d'entre eux étaient fiers de leur oeuvre
C**i**llant à peine quand dehors, un monstre jappait
Fi**e**rté mène cependant à orgueil
Et **n**'oubliez pas qu'orgueil mène à perte.
```

Now we have `Bien`, and last but not least:
```
**J**uste au moment où leurs travaux allaient finir,
H**o**rs du laboratoire, un cri retentissant fut émis
Pe**u** d'humains avaient entendu ce genre de cris.
Ext**é**nués par cette énième attaque, les scientifiques se remirent au travail.
```

And we have now `Joué`. So the final flag is `404CTF{TrèsBienJoué}`.
