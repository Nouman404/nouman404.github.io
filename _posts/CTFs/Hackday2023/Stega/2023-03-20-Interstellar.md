---
title: CTFs | HackDay2023 | Interstellar
author: BatBato
date: 2023-03-20
categories: [CTFs, HackDay2023, Interstellar]
tags: [CTF, HackDay2023, Stegano]
permalink: /CTFs/Hackday2023/Stega/Interstellar
---

# Interstellar
In this challenge, we have access to a network communication saved in a [pcap file](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/Hackday2023/Stega/Interstellar/dump.pcap).

We have just [ICMP requests](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol). At first I was thinking about some kind of ping pong challenge but it was not. But when we look at the ICMP packet sent, we can see some interesting stuff.

![image](https://user-images.githubusercontent.com/73934639/226409512-4db567de-1237-4d36-bb2f-7ece32ee717e.png)
![image](https://user-images.githubusercontent.com/73934639/226409994-3eb84d14-22f9-46e8-94d2-a83b14156ea3.png)

As we can see in the first and last request, we have the PNG header and its trailer that we know because it's explained on [this website](https://www.garykessler.net/library/file_sigs.html).

So I created a program that will extract every request and extract the hexadecimal of the image. Unfortunately, I couldn't manage to recreate the image directly in the python code. But [this website](https://codepen.io/abdhass/full/jdRNdj) allows us to do it.

We then download the image and we get the flag:

![image](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/Hackday2023/Stega/Interstellar/index.png)
