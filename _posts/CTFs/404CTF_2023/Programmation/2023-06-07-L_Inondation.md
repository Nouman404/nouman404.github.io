---
title: CTFs | 404CTF_2023 | Programmation | L'Inondation
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Programmation]
tags: [Programmation]
permalink: /CTFs/404CTF_2023/Programmation/L_Inondation
---

# L'Inondation

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ee37d73b-1c06-4751-b4d5-091498e11b34)

In this challenge, we can connect to a netcat server and we will be prompted with the message `«Allez, vite, il y a une pile de photos assez importante à traiter,comptes-moi le nombre de rhinos par photo. »`. Which means we need to recover the amount of rhinos that is printed. A rhino is printed as `~c'°^)`.  

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9b89fd5f-81e3-45a2-981d-fea74073f260)

I used the following function to get the text from the netcat server, send the number of rhinos found and return the text received:

```python
def find_rhino():
	
	text = io.recvuntil("> ").strip().decode("utf-8")
	# count the number of rhinos by splitting the string into an array of rhinos and getting the length
	rhinos = len(text.split("~c`°^)"))-1

	io.sendline(str(rhinos))
	returned_text = io.recvline().strip().decode("utf-8")
	return returned_text
```

Then I used this while loop to use this function until I can't find any more rhinos:
```python
flag = find_rhino()

while "Très bien, la suite arrive" in flag:
	try:
		flag = find_rhino()
	except Exception as e:
		print(io.recvline().decode("utf-8"))
	sleep(0.1)
```

At the end we get the full code:
```python
from pwn import *
from time import sleep
HOST, PORT = "challenges.404ctf.fr", 31420 
io = remote(HOST, PORT)
def find_rhino():
	
	text = io.recvuntil("> ").strip().decode("utf-8")
	rhinos = len(text.split("~c`°^)"))-1

	io.sendline(str(rhinos))
	returned_text = io.recvline().strip().decode("utf-8")
	return returned_text

flag = find_rhino()

while "Très bien, la suite arrive" in flag:
	try:
		flag = find_rhino()
	except Exception as e:
		print(io.recvline().decode("utf-8"))
	sleep(0.1)
```

By executing this code we get:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/0fea2d78-6520-4523-aa2c-0583df9f56b8)

The flag is `404CTF{4h,_l3s_P0uvo1rs_d3_l'iNforM4tiqu3!}`.
