---
title: CTFs | HeroCTF_2024 | Forensique | LazySysAdmin2
author: BatBato
date: 2024-10-26
categories:
  - CTFs
  - HeroCTF_2024
  - Forensique
tags:
  - Forensique
permalink: /CTFs/HeroCTF_2024/Forensique/LazySysAdmin2
---
# LazySysAdmin #2


![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_lazy_enonce.png]]

In this challenge, we are given an `.iso` file. We can mount it on our machine and see the root folder of a Linux machine:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_lazy_rootFolders.png]]

First I tried to look inside the `rr_moved` folder but there was nothing in it. The next guess I had was to look inside the `/tmp` folder because it's where we upload usually our stuff as attackers:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_lazy_tmp.png]]

We see two hidden files, `.script.sh` and `.wrapper_script.sh`:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_lazy_scripts.png]]

As we can see, the first script only run the second one and the second one recover strings from an URL. Lets curl the URL:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_lazy_curl.png]]

As we can see, there is a bunch of `base64`, lets decode it:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_lazy_base64Decode.png]]

And... Voila. We get the flag `HERO{AlwaYs-Ch3ck_What_u-C0Py-P4ste}`
