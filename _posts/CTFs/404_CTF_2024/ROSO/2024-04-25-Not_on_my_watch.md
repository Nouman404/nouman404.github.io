---
title: CTFs | 404CTF_2024 | ROSO | Not on my watch
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - ROSO
tags:
  - ROSO
  - OSINT
permalink: /CTFs/404_CTF_2024/ROSO/Not_on_my_watch
---


# Not on my watch

![[watch_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/ROSO/Photos/watch_enonce.png)

Here, we have the following image:

![[pocket_watch.jpg]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/ROSO/Photos/pocket_watch.jpg)

The first thing I searched was the strings at the top of the watch `waltham mass AWWCO`. This gave me the website of [pocketwatchdatabase](https://pocketwatchdatabase.com/guide/trade-names/a.w.w.co). From here, I just had to give it the serial number `15404141`:

![[watch_web.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/ROSO/Photos/watch_web.png)

And thanks to this serial number, we have a lot of information, the number of mechanism sold included:

![[watch_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/ROSO/Photos/watch_flag.png)
So the flag is `404CTF{197,100}`.