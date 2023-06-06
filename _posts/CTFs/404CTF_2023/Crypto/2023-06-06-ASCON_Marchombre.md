---
title: CTFs | 404CTF_2023 | Crypto | ASCON Marchombre
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Crypto]
tags: [Crypto,ASCON, DeadFish, Hex]
permalink: /CTFs/404CTF_2023/Crypto/ASCON_Marchombre
---

#  ASCON Marchombre

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ef0d7989-6487-4770-a740-c53b00e19cb6)

In this challenge, we are given an ASCON encrypted text and multiple values to be able to decrypt it.

ASCON is a lightweight authenticated encryption algorithm designed to provide security with low resource usage. It operates on a fixed-length message and key and provides confidentiality and integrity of the data. ASCON uses a permutation-based design and features a simple and efficient implementation. It is resistant to various cryptographic attacks, including differential and linear cryptanalysis. ASCON is suitable for constrained environments, such as embedded systems or Internet of Things (IoT) devices, where limited resources are available.

I found [this github](https://github.com/meichlseder/pyascon) that allows us to decrypt the text. I took the necessary code and assembled [this one](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Crypto/ascon.py). We just have to run it and... Voilà

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4dfbb9b1-cb6a-4fa5-82f6-972b08569a4f)

The flag is `404CTF{V3r5_l4_lum1èr3.}`
