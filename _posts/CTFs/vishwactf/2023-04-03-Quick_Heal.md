---
title: CTFs | vishwactf | Quick_Heal
author: BatBato
date: 2023-03-04
categories: [CTFs, vishwactf]
tags: [CTF, vishwactf, Stegano]
permalink: /CTFs/vishwactf/Stegano/Quick_Heal
---

This CTF isn't hard but a bit boring to do. We had a [video]() that, when we launched it, has Morse code in it.

We first need to recover the sound of the audio, using any video editor online or not. Then, we can put it in audacity and look at the spectrogram:

![image](https://user-images.githubusercontent.com/73934639/229458744-51b4d7d9-3634-40f5-a1e9-c18cebadf81d.png)


And now with the spectrogram activated, we can see the Morse code loud and clear:

![image](https://user-images.githubusercontent.com/73934639/229458973-05938cdc-659e-48ad-aa2f-a259a0362b56.png)

You can use tools like [dcode.fr](https://www.dcode.fr/code-morse) or [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')&input=Li0uLS4tIC4uLi4uIC0uIC4tLS0gLS0tLS0gLS4tLSAuLS4tLi0gLS4tLiAtLS0tLSAuLi0gLi0tLiAtLS0tLSAtLiAuLi4g) to decode the morse:

![image](https://user-images.githubusercontent.com/73934639/229459403-12ada800-5e95-4684-86fb-d301250ec505.png)

But this isn't enough to get the flag. When looking at the video, we can see images that look like part of a QrCode:

![image](https://user-images.githubusercontent.com/73934639/229460382-27b7d5cc-fb98-4900-8b81-73a86a4eb747.png)

I recovered all of them and get the following QrCode:

![image](https://user-images.githubusercontent.com/73934639/229460601-91b76329-b418-481a-b304-e727ec921942.png)

This wasn't good enought because some part of the QrCode wasn't clean. I used a website to edit [QrCode](https://merricx.github.io/qrazybox/). 

> I choosed the ```Error Correction Level:``` as ```L``` and the ```Mask Pattern :``` as ```2```
{: .prompt-info}

This gives us the text ```VishwaCTF{S3cur1ty.S1mpl1f13d``` we add the previous part of the flag to it and we get the full flag ```VishwaCTF{S3cur1ty.S1mpl1f13d.5nj0y.c0up0ns}```.

> Don't forget to add the ```}``` at the end. It isn't displayed in the Morse code.
{: .prompt-warning}
