---
title: CTFs | 404CTF_2023 | Reverse | L’inspiration en images
author: BatBato
date: 2023-06-09
categories: [CTFs, 404CTF_2023, Reverse]
tags: [Reverse, Ghidra, OpenGL]
permalink: /CTFs/404CTF_2023/Reverse/L_inspiration_en_images
---

# L’inspiration en images

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/580cda6e-c135-434b-b859-352e38c98222)

In this challenge, we are given [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Reverse/vue_sur_un_etrange_tableau) executable. We need to recover the RGBA float values of the painting. But when we look at the paining, either by extracting the image using `binwalk` or running the program, we see only a black background:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/83c61d33-bdb6-416c-9548-9cbf8333a0ce)

So I started looking at the code for something referring to the color and found that:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Reverse/search.png)

This is the only function that contains the word `color`. So I looked at this function and found that the `glad_glClearColor` function is part of the `OpenGL` library and is used to specify the clear color for the color buffer. When you render graphics using `OpenGL`, the color buffer holds the pixel data for the current frame being displayed. The `glClearColor` function sets the color value that will be used to clear the color buffer before rendering the next frame.

So I decoded the hexadecimal values `0x3e4ccccd,0x3e99999a,0x3e99999a,0x3f800000` using the online tool [Scadacore](https://www.scadacore.com/tools/programming-calculators/online-hex-converter/) and found the float values:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Reverse/decode.png)

So the flag is `404CTF{vect4(0.2,0.3,0.3,1.0)}`
