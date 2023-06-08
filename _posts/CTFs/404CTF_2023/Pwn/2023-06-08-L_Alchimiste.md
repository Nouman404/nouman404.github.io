---
title: CTFs | 404CTF_2023 | Pwn | L'Alchimiste
author: BatBato
date: 2023-06-08
categories: [CTFs, 404CTF_2023, Pwn]
tags: [Pwn, Ghidra]
permalink: /CTFs/404CTF_2023/Pwn/L_Alchimiste
---

# L'Alchimiste

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/06a3eb5c-571f-41f9-93c9-5b7d9914e6df)

For this challenge, we are givent [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Reverse/l_alchimiste) executable. We can open it on Ghidra and/or un it to understand how it works.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/94c5dae2-5430-47cc-b15f-062c27f5f2d4)

As we can see, we have multiple options. I first tried to buya strength potion and to use it multiple time:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c07af379-31f3-4391-aded-708134021734)

As we can see, we have a double free error. This is because, when we use the strenght potion, we call the `useItem` function that does the following:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/353f2dfe-6e0a-4cee-b309-1f5092735677)

As we can see, we free the memory at the location of `param_1+0x10`. `0x10` is equal to  `16` in decimal. and if we look at the character, we can see the it is the 

To be continued...
