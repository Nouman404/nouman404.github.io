---
title: CTFs | 404CTF_2024 | Cryptanalyse | Bebe Nageur
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Cryptanalyse
tags:
  - Crypto
  - Python
permalink: /CTFs/404_CTF_2024/Cryptanalyse/Bebe_Nageur
---
# Bebe Nageur

![[bebe_nageur_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Cryptanalyse/Photos/bebe_nageur_enonce.png)

In this challenge, we are tasked to retro-engineer a python code and exploit its cryptographic flaws. The given code is the following:
```python
from flag import FLAG
import random as rd

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!"

def f(a,b,n,x):
	return (a*x+b)%n

def encrypt(message,a,b,n):
	encrypted = ""
	for char in message:
		x = charset.index(char)
		x = f(a,b,n,x)
		encrypted += charset[x]
	return encrypted

n = len(charset)
a = rd.randint(2,n-1)
b = rd.randint(1,n-1)
print(encrypt(FLAG,a,b,n))
# ENCRYPTED FLAG : -4-c57T5fUq9UdO0lOqiMqS4Hy0lqM4ekq-0vqwiNoqzUq5O9tyYoUq2_
```

So we notice that every character from the `FLAG` is encrypted using a random `a` and a random `b`. The `n` on the other hand is static because it's just the length of our charset. I ran the program with different input like `AAA`, or `BBB` and I got as a result `444`, `888`. So I believed that when a character is present in the encrypted flag every occurrences of this encrypted character  represent the same one. As an example, the beginning of the encrypted flag is `-4-` so we guess from that, that every `-` represent a `4` and every `4` represent a `0`.

At first I tried to solve the modulus equations but I found that hard to do :) so I found an easier way to exploit that.

As we said earlier, each encrypted character will gives us the same result when encrypted. So why not just create a dictionary with each key representing an encrypted character from the charset and each value, its decrypted (original) value.

I added the following code after the given one:

```python
prefix = "404CTF{"
enc_flag = "-4-c57T5fUq9UdO0lOqiMqS4Hy0lqM4ekq-0vqwiNoqzUq5O9tyYoUq2_"

def get_a_b():
	for new_b in range(1,n-1):
		for new_a in range(2,n-1):
			if encrypt(prefix, new_a, new_b, n) == "-4-c57T":
				print("[+] a = "+str(new_a))
				print("[+] b = "+str(new_b))
				return new_a,new_b

new_a, new_b = get_a_b()
"""
a=19
b=6
"""

arr = {}
# Create a dictionary with key=encrypted values=dec
#ex: key:"-"  and value:"4"
for lettre in charset:
	new_lettre = encrypt(lettre, new_a, new_b, n)
	if new_lettre not in arr.keys():
		arr[new_lettre] = lettre

flag = ""
for enc_val in enc_flag:
	flag += arr[enc_val]
print("[+] FLAG : "+flag)
```

And voilà... We have the flag:
![[beb_nageur_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Cryptanalyse/Photos/beb_nageur_flag.png)