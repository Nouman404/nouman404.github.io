---
title: CTFs | 404CTF_2024 | Retro | Intronisation du CHAUSSURE
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Retro
tags:
  - Retro
  - Reverse
permalink: /CTFs/404_CTF_2024/Retro/Intronisation_du_CHAUSSURE
---
# Intronisation du CHAUSSURE

![[intro_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/intro_enonce.png)

The binary is available [here](Retro_Ingenierie/intronisation). In the main function we see the following code:

![[intro_main.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/intro_main.png)

We notice the password split character by character and the order is the order of variable creation. I wrote the following python code:

```python
arr = {"local_27": 't', "local_21": 'r', "local_1e": '1', "local_1d": 's', "local_23": 'n',"local_24": '1', "local_26": 'u', "local_28": '5', "local_1f": 'n', "local_1c": '3',"local_20": '0', "local_25": 'p', "local_22": 't'
}
passwd =""
for val in ["local_28", "local_27", "local_26", "local_25", "local_24", "local_23", "local_22", "local_21", "local_20", "local_1f", "local_1e", "local_1d", "local_1c"]:
	passwd += arr[val]
print(passwd)
```

![[intro_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/intro_flag.png)

So the flag is `404CTF{5tup1ntr0n1s3}`.