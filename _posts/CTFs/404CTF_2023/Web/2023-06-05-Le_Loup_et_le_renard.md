---
title: CTFs | 404CTF_2023 | Web | Le Loup et le renard 
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023, Web]
tags: [Web,Source Code, Comments, JS]
permalink: /CTFs/404CTF_2023/Web/Le_Loup_et_le_renard
---

# Le Loup et le renard 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/69d209bf-1731-4a1e-99c4-a208902d8853)


## Secret in the source code ?

This is a basic web challenge. We need to recover the flag by any means.
First we arrive on the main page, we click on start and we have a form:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a92712a7-72ab-4ee8-ad7c-770af7e950c4)

Looking at the source code, we can see the credentials in clear text in the Java Script:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/945feebe-cbee-44f9-9dcf-69cb888fba03)

We connect with the credentials `admin:h5cf8gf2s5q7d`.

## Be careful with cookies

On the second part of the challenge, we have the title `Cookies` that give us a hint where to look for:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ac5891b1-eae8-44f8-b665-149c7fdaf195)

As we can see, we have a cookie `isAdmin` with the value `False`. We just need to set the value to `True` and press CTFL+F5 to refresh the page:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f59ec661-deaa-4a90-9870-6cd0a09aa8bc)

## Handle redirections

Looking again at the source code, we can see a redirection of the GET form:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/83d5ecd1-7b16-411f-9666-9ab15dc796fe)

We go to the page `/fable/partie-4-flag-final` and we got the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/395d21e8-b13a-4248-9f41-6e134e783fe2)

> Note that if you didn't click on the link from the source code but pasted it in the url, you would have been redirected (this was the challenge). You could have bypassed the redirection by intercepting the request with Burp or by using the cURL command.
{: .prompt-info}

So the flag is: `404CTF{N0_frOn1_3nD_auTh3nt1ficAti0n}`
