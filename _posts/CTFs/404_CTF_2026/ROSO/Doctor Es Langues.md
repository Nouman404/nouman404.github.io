---
title: CTFs | 404CTF_2026 | ROSO | Doctor Es Langues
author: BatBato
date: 2026-05-18
categories:
  - CTFs
  - 404_CTF_2026
  - ROSO
tags:
  - ROSO
  - OSINT
permalink: /CTFs/404_CTF_2026/ROSO/Doctor_Es_Langues
---

![[ROSO_Doctor_Es_Langues_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/ROSO/Photos/ROSO_Doctor_Es_Langues_enonce.png)

In this challenge we are given an image that is the banner of a scientist. We need to find a language where he is `confirmé`. First if we try `exiftool` on the image we get the following :

![[ROSO_Doctor_Es_Langues_exif.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/ROSO/Photos/ROSO_Doctor_Es_Langues_exif.png)

We now know the username of a Twitter account `SadiQuatrenot`. If we look at the Media the user posted, we can find his CV :

![[ROSO_Doctor_Es_Langues_twitter.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/ROSO/Photos/ROSO_Doctor_Es_Langues_twitter.png)

Now that we found this, we could try `404CTF{français}` or `404CTF{anglais}` but this doesn't work of course. So if we look at his post, we can see there is a personal blog :

![[ROSO_Doctor_Es_Langues_CV.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/ROSO/Photos/ROSO_Doctor_Es_Langues_CV.png)

There is nothing interesting on the blog. At least, nothing we didn't already knew. But if we look at it on `Way Back Machine`, we get what we where looking for :

![[ROSO_Doctor_Es_Langues_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/ROSO/Photos/ROSO_Doctor_Es_Langues_flag.png)

We didn't have this line before and it states that it has the `confirmé` level so... `404CTF{malais}` is the flag.