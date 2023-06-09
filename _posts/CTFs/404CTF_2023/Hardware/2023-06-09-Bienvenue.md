---
title: CTFs | 404CTF_2023 | Hardware | Bienvenue
author: BatBato
date: 2023-06-09
categories: [CTFs, 404CTF_2023, Hardware]
tags: [Hardware,CIRC, Logic Gates]
permalink: /CTFs/404CTF_2023/Hardware/Bienvenue
---

# Bienvenue

In this challenge, we are given [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Hardware/bienvenue.circ) `CIRC` file. By looking on the internet, I found that the tool [Logisim](https://sourceforge.net/projects/circuit/) could open such files. When we open the file we get this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e6b0e5c1-42b4-426c-a50a-d79d9d86c362)

So we go to the first part and now we have the first part of the flag `404CTF{L3_`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a0b5fd50-84b5-4255-9fbd-a14999a3e83e)

We now go to the second section:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4c773036-098d-4565-9d1d-ff152e3adb03)

The second and third sections are linked, so we look at what we have in the third section:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d51fde19-be2b-4fd6-b7fd-5f7daeacfb6e)

We need to fill the matrix with the entry of the Multiplexer of the part 2 by order of their arrival in the multiplexer. Here is an example of the first four:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/52d1c061-6942-4af7-b6ad-5fc268436778)

So the final hexadecimal values we need to set in the matrix are `4d 30 6d 33 6e 54 5f 33 53 74 5f 56 33 6e 55 33`. We can now spam the `CTRL+T` to tick several times, and the text field completes itself:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3824d616-4b7f-45f7-b832-f37032a9cad9)

We now have the second part of the flag `M0m3nT_3St_V3nU_`.

We now go to the 4th part:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6d66e1cb-1511-4e2d-b906-ab824e796973)

As we can see, it's like in the second part, so in the black box of the part 4 i just re-created the part 3 and set the input in the same way we did earlier. This time the hexadecimal string is `44 33 5f 35 34 6d 75 73 33 72 7d`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ffc29491-b528-4213-b707-9342d9ef0529)


As we did previously, we tick the clock with `CTRL+T` and we get the last part of the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/bcaccc3b-89ca-4d1a-b0bc-1c09c7051eb8)

The last part of the flag is `_D3_54mus3r}`.

The final flag is `404CTF{L3_M0m3nT_3St_V3nU_D3_54mus3r}`
