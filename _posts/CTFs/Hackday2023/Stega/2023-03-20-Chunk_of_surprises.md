---
title: CTFs | HackDay2023 | Chunk_of_surprises
author: BatBato
date: 2023-03-20
categories: [CTFs, HackDay2023, Chunk_of_surprises]
tags: [CTF, HackDay2023, Stegano]
permalink: /CTFs/Hackday2023/Stega/Chunk_of_surprises
---

# Chunk_of_surprises

In this challenge, we are given a [png image](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/Hackday2023/Stega/Chunk_of_surprises/Chunk_of_surprises.png). But when we try to open it, we get an error. So we look at the hexadecimal inside the image and we see that the headers and the trailer are not correct.



As we can see on [this website](https://www.garykessler.net/library/file_sigs.html), the png header should be ```89 50 4E 47 0D 0A 1A 0A``` but is ```01 50 4E 47 0D 0A 1A 0A``` so the first bit is not good.

![image](https://user-images.githubusercontent.com/73934639/226387580-6625cdc2-8e6e-47fd-ab5c-e1b7d80da6a4.png)

The second header should be IHDR but there is no IHDR so we add it by replacing the wrong hex value. We also modify the tailor as for the PNG header.
![image](https://user-images.githubusercontent.com/73934639/226387904-e832c415-0a12-4c1e-9c05-eb8a724d13f5.png)
![image](https://user-images.githubusercontent.com/73934639/226388003-b2f966a1-f007-4744-adc9-640f990cfdbc.png)

And we got [the flag](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/Hackday2023/Stega/Chunk_of_surprises/Flag.png) written in black at the top.

![image](https://user-images.githubusercontent.com/73934639/226389970-38254f91-1799-4bfc-b3a8-c19b7cc6b22e.png)
