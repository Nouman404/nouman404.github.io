---
title: CTFs | 404CTF_2023 | ROSO_OSINT | Le Tour de France
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023]
tags: [ROSO,OSINT]
permalink: /CTFs/404CTF_2023/ROSO_OSINT/Le_Tour_de_France
---

# Le Tour de France

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/af7b784d-ec60-4284-8fcb-555149da43a8)

On this chall we are given a picture of a road sign that we need to locate:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a0caa80a-8cfd-449c-a066-5e2de54647f2)


A quick search on google map by typing `E17 E21 besançon` we find a link to [E17 & E21]([https://www.google.com/maps/place/A6+%26+E15,+91320+Wissous/@48.7319043,2.3263739,14.67z/data=!4m10!1m2!2m1!1sa6+e15+besan%C3%A7on!3m6!1s0x47e6765448a24d3f:0xcfed0b6d5f9c58b!8m2!3d48.7334906!4d2.3159919!15sChBhNiBlMTUgYmVzYW7Dp29ukgEMaW50ZXJzZWN0aW9u4AEA!16s%2Fg%2F11rxtwd4b3?entry=ttu](https://www.google.com/maps/place/E17+%26+E21,+21200+Beaune/@47.0180996,4.8666473,17z/data=!3m1!4b1!4m6!3m5!1s0x47f2f2df313252c9:0x49e79fcc2acd58db!8m2!3d47.018096!4d4.8692222!16s%2Fg%2F11gd_hg5sg?entry=ttu))

Heading to street view, we can find the signs:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/68164400-42b7-4093-bf63-069214110908)

Looking at the [url](https://www.google.com/maps/@47.0150657,4.8676532,3a,75y,345.69h,91.43t/data=!3m6!1e1!3m4!1sxK1tkOhUlNjtJFpxBHpnwg!2e0!7i16384!8i8192?entry=ttu) we can see `47.0150657,4.8676532` and we then need to truncate this to the hundreds, the flag is then `404CTF{47.01,4.86}`
