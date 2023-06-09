---
title: CTFs | 404CTF_2023 | Hardware | Un réveil difficile
author: BatBato
date: 2023-06-09
categories: [CTFs, 404CTF_2023, Hardware]
tags: [Hardware,CIRC, Logic Gates]
permalink: /CTFs/404CTF_2023/Hardware/Un_reveil_difficile
---

# Un réveil difficile

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/40065c9c-5aa5-441b-8e32-4fd0ff57a3f1)


In this challenge, we are given [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Hardware/reveil.circ) CIRC file. When we open it with [Logisim](https://sourceforge.net/projects/circuit/), we can see the following:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/bf20d6b8-18ba-4108-9c4b-92c5305ee75d)

As we can see in the challenge statement, we need to print `Un_c`. So we just modify the input matrix by clicking on the `0`s to modify them into `1`s:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e3b8ea73-522b-4445-b9f0-100694dd5016)

Now that we have `Un_c` as specified we need to use `CTRL+T` to tick the clock and get the message printed out:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/66a9d2c9-0810-461f-b3b4-aa7b06511adc)

We need to do that several times until we get back to `Un_c`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e01abd6f-cb58-458d-8ac0-c50dda3bcb1a)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1fd7abfe-3604-4510-902a-1eba1ee7b38b)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/352ae505-6465-4b67-ab08-3b686bae29e6)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f6c59a9d-3c96-4344-8406-3d3f4a6f0376)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ab93a81f-b9e0-43b6-98ad-68a5776765a3)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9f6186ae-e30c-4fb3-82d6-a9a52bcf970d)

Now we have everything we need to assemble the flag. As specified in the challenge statement, if we don't know what character is printed, we need to choose in this order `number`, `lower case`, and finally `upper case`. 

So with all that said, the flag is `404CTF{Un_cH1FFrA9e_A55e2_bi3n_d3PreCie}` 
