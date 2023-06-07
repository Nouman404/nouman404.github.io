---
title: CTFs | 404CTF_2023 | Stega | Le Rouge et le vert, avec un soupçon de bleu
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Stega]
tags: [Stega, Text, ASCII]
permalink: /CTFs/404CTF_2023/Stega/Le_Rouge_et_le_vert_avec_un_soupcon_de_bleu
---

# Le Rouge et le vert, avec un soupçon de bleu

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/5f783882-3167-4eaa-87ad-52c7bc5381af)

In this challenge, we just have [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Stega/Rouge_Vert_Bleu.jpg) image, but only the end is interesting:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b67f0484-3171-4089-8aee-8145ad9ca733)

If we try to decode the text `76 321021089710332 115116581089795118 95 1109599  108  114115125`, we get `L flag st:la_v_n_clrs}`. If we replace the missing values by `X`s, we get `LX flag Xst:la_vXX_Xn_cXXlXXrs}`. So first, we can notice that the first part should be `Le flag est`. From this we could have guessed that a space is equivalent to an `e` and so get `Le flag est:la_vXe_en_cXXleXrs}`.
Now we are just missing a few characters. We and guess the `i` of  `vie` and the word `couleur` can also be guessed.

This gives us the flag `404CTF{la_vie_en_couleurs}`
