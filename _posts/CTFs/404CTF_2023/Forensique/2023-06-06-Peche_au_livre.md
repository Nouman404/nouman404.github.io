---
title: CTFs | 404CTF_2023 | Forensique | Pêche au livre
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Forensique]
tags: [Forensique,Wireshark]
permalink: /CTFs/404CTF_2023/Forensique/Peche_au_livre
---

# Pêche au livre

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e7b8cf87-1d59-4c7c-b4b9-1f551c3ace5d)

In this challenge, we are given a Wireshark capture available [here]().

To solve this challenge, we just have to dump all the file of the HTTP traffic like this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/40741c80-68ba-40b2-b7e0-175a607d7558)


We can click then on `Save All` or just save the images one by one:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a7e47b93-8c51-4e01-bfc0-9fbf4f495eee)

We can now look at the images:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/5479b122-49c1-44b8-8b2c-4cff2975dd09)

And if we open the `Hegel-sensei-uwu.png` file, we get the flag:

![image](Hegel-sensei-uwu.png)

The flag is `404CTF{345Y_W1r35h4rK}`
