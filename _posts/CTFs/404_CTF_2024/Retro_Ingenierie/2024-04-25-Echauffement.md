---
title: CTFs | 404CTF_2024 | Retro | Echauffement
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Retro
tags:
  - Retro
  - Reverse
permalink: /CTFs/404_CTF_2024/Retro/Echauffement
---
# Echauffement

![[echau_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/echau_enonce.png)

In this challenge, we are given the [echauffement.bin](Retro_Ingenierie/echauffement.bin) file. We open it using `ghidra` and we see the following code in the main function:

![[echau_main.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/echau_main.png)

As we can see, the `secret_function_dont_look_here` looks suspicious. Lets have a look at it:

![[echau_secret.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/echau_secret.png)

As we can see, the secret function is doing some mathematical operations on the `secret` data. Is we manage to get the `secret_data` we could do the same process to recover its original value.  In `ghidra` the `secret_data` point to the `DAT_00102008` variable that looks like:

![[echau_dat.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/echau_dat.png)

I recovered all those hex value and put them in my python code. I reverted the for loop of the `C` code in python and we have the following code:
```python
secret_data = bytes.fromhex("68 5f 66 83 a4 87 f0 d1 b6 c1 bc c5 5c dd be bd 56 c9 54 c9 d4 a9 50 cf d0 a5 ce 4b c8 bd 44 bd aa d9")

flag = ""
for i in range(len(secret_data)):
	flag += chr(int((secret_data[i] + i)/2))
print(flag)
```

And when we run this code, we have the flag `404CTF{l_ech4uff3m3nt_3st_t3rm1ne}`
