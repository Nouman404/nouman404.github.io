---
title: CTFs | FCSC2023 | Intro | Tri sélectif 
author: BatBato
date: 2023-05-02
categories: [CTFs, FCSC2023, Intro]
tags: [CTF, FCSC, Math]
permalink: /CTFs/FCSC2023/Intro/Tri_selectif 
---


# Tri sélectif 

![image](https://user-images.githubusercontent.com/73934639/235777230-cc3a13f2-7d11-43e4-918a-31b154706079.png)


This chall requires us to sort an array. But we don't see the array (can't know every values). We only can check two values to know which one is the greater, change the position of two values and finally, check if the array is sorted.

For that I used a basic selection sort algorithm:

```python
def trier(N):
    for i in range(N):
        min_index = i
        for j in range(i + 1, N):
            if comparer(j,min_index) == 1:
                min_index = j
        if min_index != i:
            echanger(i, min_index)
```

We only had to complete the function in the `client.py` file given and run it:

![image](https://user-images.githubusercontent.com/73934639/235778230-611b3782-db9b-4b63-8c0f-4572d95b20db.png)
