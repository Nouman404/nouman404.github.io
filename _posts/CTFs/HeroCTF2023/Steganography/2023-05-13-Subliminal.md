---
title: CTFs | HeroCTF2023 | Steganography | Subliminal
author: BatBato
date: 2023-05-13
categories: [CTFs, HeroCTF2023, Steganography]
tags: [CTF, HeroCTF, Steganography]
permalink: /CTFs/HeroCTF2023/Steganography/Subliminal
---

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ad10901c-6ab4-4601-acb4-930f0f9cd6c3)

In this chall, we had to recover the subliminal image. We are given a video where we can see a square that appear on each frame. The video can be found [here]().

At first I tried to create a program that recover the squares by searching the shape of a square on the video... But this didn't work and was overcomplicated. I finally chose to just start at the first frame on the top left corner, save it in a folder named `squares` with its `ID` (first square ID=1, second ID=2...). I could find the squares because I knew they were 20\*20 with the help of my "useless" previous code. Then I just had to concatenate all the squares together. The EXIF of the video tells me that it has a frame of 1280\*720. I just had to create an image of 1280\*720 using only squares of 20\*20.

You can find my code [here]()

And the we got the flag:

![imageFlag]()
