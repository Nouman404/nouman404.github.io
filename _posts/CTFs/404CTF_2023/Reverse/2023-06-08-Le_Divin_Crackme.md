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

In this challenge, we are given [this]() executable. We can guess the password `L4_pH1l0soPh13_d4N5_l3_Cr4cKm3`. This is because the password is stored in the memory and the use of `strncmp` will allow the program to get the password split in 3 blocks of 10 characters.

The flag needs also to contain the compiler used to get this executable. It was `gcc`, this could be found in the `.comment` section of the executable:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9f456459-d26c-4335-a4b4-414c4f77c58c)

The final flag is then `404CTF{gcc:strncmp:L4_pH1l0soPh13_d4N5_l3_Cr4cKm3}`
