---
title: CTFs | FCSC2023 | Forensic | Ransomémoire
author: BatBato
date: 2023-05-02
categories: [CTFs, FCSC2023, Forensic]
tags: [CTF, FCSC, Forensic]
permalink: /CTFs/FCSC2023/Forensic/Ransomemoire
---

# Ransomémoire

![image](https://user-images.githubusercontent.com/73934639/235786504-74fb1720-6269-49d8-86b8-9dd28cc91059.png)

In this chall of forensic, we are given a 2Gb memory dump of a windows machine. To analyse a memory dump, a geat tool is [Volatility](https://github.com/volatilityfoundation/volatility3). In this chall, we coulnd't use Volatility2 so we needed to use the version 3. I found a good [blog](https://blog.onfvp.com/post/volatility-cheatsheet/) about the conversion of the Volatility2 to 3 commands (there are only the main ones, but still interesting).

We used the `sessions` command to find all the information we want (user, machine name and browser). The full command is `volatility3/vol.py -f fcsc.dmp windows.sessions`:

![image](https://user-images.githubusercontent.com/73934639/235790321-7076b837-e319-4b9f-a09e-51624bfb034f.png)

We have here everything we need to craft the flag: `FCSC{Admin:DESKTOP-PI234GP:brave}`.
