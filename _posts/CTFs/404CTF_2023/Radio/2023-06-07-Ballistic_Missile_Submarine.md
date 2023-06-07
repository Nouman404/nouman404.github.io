---
title: CTFs | 404CTF_2023 | Radio | Ballistic Missile Submarine
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Radio]
tags: [Radio, Audacity]
permalink: /CTFs/404CTF_2023/Radio/Ballistic_Missile_Submarine
---

# Ballistic Missile Submarine

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/85aa3c96-ff9e-42b6-a142-4e9ef66559be)

We are given an audio file and told to set the frequency to `192 kHz`. We can set the rate by clicking on the arrow near the audio file name:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2377a63d-1053-4259-a4cc-3ed32b6ed625)

We now use the spectrogram but don't see anything interesting... Or do we ?

We can use the `Zoom to fit` feature to see everything. To access this option, you need to left click where the numbers are shown on the left:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b473ef7c-ea86-4b6c-a1cb-7b8db9b0f583)

Now we can see something that looks like dash and dots near 50kHz:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/95bc4d15-ae3d-4133-a04f-989972180d33)

When zooming near 40kHz, we can see the following:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Radio/audacity_morse.png)

We can now decode this morse using tools like [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')&input=Li4uIC0gLi0gLi0uIC0gLi0uLS4tIC4uLi4tIC0tLS0tIC4uLi4tIC0uLS4gLSAuLi0uIC4tLi0uLSAuLSAtLi0uIC0uLS4gLS0tIC4tLi4gLi0gLS4uIC4gLi0uLS4tIC4tLS4gLi4uLi0gLi4tIC4tLi4gLi4tLS4tIC4uLi0gLi4uLS0gLi0uIC4tLS0tIC4uLi4tIC4uIC0uIC4uLi0tIC4uLS0uLSAuLi4tLSAuLi4uLiAtIC4uLS0uLSAuLi0gLS4gLi4tLS4tIC0tIC0tLS0tIC4tLiAuLi4uLiAuLi4tLSAuLi0tLi0gLi4tLS4uIC4tLi0uLSAuLSAtLi0uIC0uLS4gLS0tIC4tLi4gLi0gLS4uIC4gLi0uLS4tIC4gLS4gLS4uIC4tLi0uLS4uLg):

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Radio/cyberchef.png)

The flag is `404CTF{P4UL_V3R14IN3_35T_UN_M0R53_?}`

