---
title: CTFs | FCSC2023 | Intro | Dystylosaurus
author: BatBato
date: 2023-05-02
categories: [CTFs, FCSC2023, Intro]
tags: [CTF, FCSC, SAL]
permalink: /CTFs/FCSC2023/Intro/Dystylosaurus
---

# Dystylosaurus

![image](https://user-images.githubusercontent.com/73934639/235744190-3e14838c-4511-4dde-a5e8-a6c75ee6bd20.png)

In this chall we just had a `.sal` file. After at least 10000000000 seraches on the web, we can finally know that the `.sal` extension is for:

![image](https://user-images.githubusercontent.com/73934639/235745207-87f993b1-2956-47ab-a09e-ff0e959bcee1.png)

We find the tool [Logic](https://www.saleae.com/) that could do the trick. We download it and open our `.sal` file:

![image](https://user-images.githubusercontent.com/73934639/235745636-cf77f84d-5169-4910-9b27-a0449a30e04d.png)

As we can see, the `Channel 3` is pretty busy. We find an analyser:

![image](https://user-images.githubusercontent.com/73934639/235745881-d3bb14d6-a30a-4669-b153-6653dd983750.png)


This analyser allows us to read a text that contains the flag:

![image](https://user-images.githubusercontent.com/73934639/235746240-1d35e7f1-e504-47df-b433-93bd4bca1e77.png)
