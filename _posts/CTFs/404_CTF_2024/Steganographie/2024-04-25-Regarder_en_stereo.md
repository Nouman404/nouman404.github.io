---
title: CTFs | 404CTF_2024 | Steganographie | Regarder en stereo
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Steganographie
tags:
  - Stega
permalink: /CTFs/404_CTF_2024/Steganographie/Regarder_en_stereo
---

# Regarder en stereo

![[stereo_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Steganographie/Photos/stereo_enonce.png)


The image we have doesn't look like anything I've ever seen:

![[chall_stega.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Steganographie/Photos/chall_stega.png)

First, I searched "Regarder en stereo" online. I found [this link](https://www.image-en-relief.org/stereo/comment-faire/voir-en-relief/172-vision-croisee-vision-parallele.) about crossed vision and it was talking about  a technique called `autostéréogramme` that looks like what we have:

![[stereo_requin.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Steganographie/Photos/stereo_requin.png)

I searched an online tool that could manage to do that and fond [this one](https://piellardj.github.io/stereogram-solver/):

![[stereo_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Steganographie/Photos/stereo_flag.png)

So the flag is (idk if you can read on the screenshot lmao) `404CTF{END_IS_NEAR}`.
