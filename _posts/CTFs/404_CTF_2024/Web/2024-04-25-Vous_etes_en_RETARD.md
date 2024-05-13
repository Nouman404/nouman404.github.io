---
title: CTFs | 404CTF_2024 | Web | Vous etes en RETARD
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Web
tags:
  - Web
permalink: /CTFs/404_CTF_2024/Web/Vous_etes_en_RETARD
---
# Vous êtes en RETARD

![[retard_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/retard_enonce.png)

In this challenge we are just given an URL and we need to exploit this web site:

![[retard_home.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/retard_home.png)
Nothing interesting... Because we can't fuzz with gobuster, let's try looking in the source code for something interesting:

![[reatard_js.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/reatard_js.png)

As we can see, there is a page we didn't know about `/donnez-moi-mon-ticket-pitie`. Lets go there:

![[retard_barriere.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/retard_barriere.png)

This new page just tells us that we still don't have access to the stadium...

![[reatard_js2.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/reatard_js2.png)

We notice that is the `window.validable` includes our ticket ID, then we will get to the match, otherwise we won't have any access. Lets just add our billet ID to the valiable:

![[retard_js3.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/retard_js3.png)

With this, we have access to the match and we get a congratulation message:

![[retard_congrats.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/retard_congrats.png)

This lets us think that we need to look in the cookies:

![[reatard_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/reatard_flag.png)