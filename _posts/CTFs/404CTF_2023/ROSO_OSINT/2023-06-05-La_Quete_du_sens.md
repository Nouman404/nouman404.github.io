---
title: CTFs | 404CTF_2023 | ROSO_OSINT | La Quête du sens
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023]
tags: [ROSO,OSINT]
permalink: /CTFs/404CTF_2023/ROSO_OSINT/La_Quete_du_sens
---


# La Quête du sens

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e0f12962-fc20-4c88-b2d9-779173ac30e6)

For this challenge, we are given this [audio](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/ROSO_OSINT/LaQueteDuSens.mp3). We need to find the name of the text that this song comes from. We know that the name of the woman we are searching starts with Mar... Marie ? Margarette ? Marion ? Who knows ?

This took a while to get done. I first try Deezer or similar tools to find the music without success. I then tried to Google `poetesse morte francaise` because this hole CTF is about French literature and found two results that could be the good ones:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/006c3b39-16bb-4ffc-b333-24d55e015b4b)

But Marguerite Yourcenar was Belgian-born, so I tried the other one `Marceline Desbordes-Valmore`. On her [Wikipedia page](https://fr.wikipedia.org/wiki/Marceline_Desbordes-Valmore#Po%C3%A8mes_mis_en_musique), we can see a list of her poem that was set to music. The tune of the music didn't seem really classic, so i tried from the end of the list until I get into the music of `Julien Clerc` called `Les Séparés`. It is said that `Julien Clerc a ainsi mis en musique le poème « Les séparés », qui avait déjà été mis en musique par Henri Woollett, chanson intitulée Les Séparés dans l'album Julien, 1997 ;`. So I search the music on YouTube and at this [time watch](https://youtu.be/EgcULJSRK7M?t=50) of the music we hear the same tune of the piano that we had. 

The flag is then obviously: `404CTF{les_séparés}`
