---
title: CTFs | 404CTF_2023 | Forensique | Lettres volatiles
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Forensique]
tags: [Forensique,Volatility]
permalink: /CTFs/404CTF_2023/Forensique/Lettres_volatiles
---

# Lettres volatiles

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3c92950a-b252-4e3c-ad30-f9a76ab951c1)

In this challenge we are given a Windows home directory of the user `C311M1N1`. When looking around, we can find a zip file containing a pdf that is protected by a password:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1e7f5d48-3444-4bc1-b058-021548474ed0)


This may be where the flag is hidden. We can try to find the password now. In the directory `Documents/JumpBag/` we find a `raw` file that we can analyse using `Volatility`. In this particular case, we need to use [volatility2](https://github.com/volatilityfoundation/volatility/wiki/Installation). We first need to find the correct profile:

> [Here](https://blog.onfvp.com/post/volatility-cheatsheet/) is a, non complete, but still useful cheat-sheet about basic command in `Volatiltiy2` and their equivalent in  `Volatiltiy3`
{: .prompt-tip}

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e03695cc-7173-441b-b7d9-ac478e377712)

Now that we have the correct profil, we can execute any command we want. I tried looking a process running, on the network, at process to dump... But didn't find anything interesting. I then found the command `clipboard` that allows us to get the content of the clipboard and...

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Forensique/clipboard.png)

We then use the password `F3eMoBon8n3GD5xQ` on the `s3cR37.zip` file and... Voilà:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/57a7b1c4-4774-4431-b464-300c7adfc8c3)

When we open the `PDF` file we get:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Forensique/flag_lettre_volatiles.png)

The flag is `404CTF{V0147i1I7y_W1Ll_N3v3r_Wr8_loV3_l3ttEr5}`
