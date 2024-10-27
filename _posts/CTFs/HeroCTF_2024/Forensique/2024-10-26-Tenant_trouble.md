---
title: CTFs | HeroCTF_2024 | Forensique | Tenant trouble
author: BatBato
date: 2024-10-26
categories:
  - CTFs
  - HeroCTF_2024
  - Forensique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/HeroCTF_2024/Forensique/Tenant_trouble
---
# Tenant trouble

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_tenant_enonce.png)

In this chall, we are given a `.csv` file that looks like this:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_tenant_csv.png)

We can use the following bash command to list the number of connection of each user:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_tenant_users.png)

As we can see, the user `mister.bennet@winchester77.onmicrosoft.com` has much more connection than any other user. We can guess that this is the target of the attack. We can now `grep` this email in the`.csv` and see when we see a lot of `UserLoginFailed`:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_tenant_loginFailed.png)

With all this information, we can now create the flag `Hero{2024-05-02;mister.bennet@winchester77.onmicrosoft.com}`
