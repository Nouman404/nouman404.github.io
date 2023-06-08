---
title: CTFs | 404CTF_2023 | Reverse | Le Divin Crackme
author: BatBato
date: 2023-06-08
categories: [CTFs, 404CTF_2023, Reverse]
tags: [Reverse, Ghidra]
permalink: /CTFs/404CTF_2023/Pwn/Le_Divin_Crackme
---

# Le Divin Crackme

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e658c7c6-a501-4308-96b9-276d077f766a)

In this challenge, we are given [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Reverse/divin-crackme) executable.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a7699a6a-2dbf-41b5-8909-3ef7249ce5bb)

We can guess the password `L4_pH1l0soPh13_d4N5_l3_Cr4cKm3`. This is because the password is stored in the memory and the use of `strncmp` will allow the program to get the password split in 3 blocks of 10 characters. The variables are initialized in the following order `local_48`, `acStack_3e`, `acStack_34`. So they will follow each other in the memory. So when we do our first `strncmp`, we get the 10 characters in the position of `acStack_3e`. `acStack_3e` is in the second position, so we get from the 11th character to the 21st. Same for `local_48` and the first 10 characters and `acStack_34` and the last 10 characters..

The flag needs also to contain the compiler used to get this executable. It was `gcc`, this could be found in the `.comment` section of the executable:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9f456459-d26c-4335-a4b4-414c4f77c58c)

The final flag is then `404CTF{gcc:strncmp:L4_pH1l0soPh13_d4N5_l3_Cr4cKm3}`
