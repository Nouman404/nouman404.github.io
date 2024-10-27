---
title: CTFs | HeroCTF_2024 | Reverse | AutoInfector
author: BatBato
date: 2024-10-26
categories:
  - CTFs
  - HeroCTF_2024
  - Reverse
tags:
  - Reverse
permalink: /CTFs/HeroCTF_2024/Reverse/AutoInfector
---
# AutoInfector

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_reverse_autoInfector_enonce.png]]

When we get to this website we have a button to download a file. If we look at the `JS` that deals with the action of the button, we get the following code:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_reverse_autoInfector_code.png]]

Here is a clearer version of the code:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_reverse_autoInfector_codeBeau.png]]

> We can use deobfusctor websites like [JS Deobfuscator](https://deobfuscate.io/) so that we get a better view of the code.
{: .prompt-tip}

The interesting part starts with the `onclick` section. Lets break this down line by line:
1. First it will get an element from the web page (the title)
2. Then it will hash it in `md5` (`hash1`)
3. After that, it will prompt an input box to allow you to provide the password
4. If the provided string isn't empty, it will hash it in `md5` (`hash2`)
5. Then it will xor the `hash1` with `hash2`
6. If the result is equal to `11dfc83092be6f72c7e9e000e1de2960` (`hash3`) then it will prompt the flag

So basically we have: `hash3 = hash1 XOR hash2`

We know `hash3` and `hash1`. The only thing we don't know is `hash2` because it depends on what we input. So if we do a `XOR` operation between the two known hash, we should get the hash we don't know (basic `XOR` rule). So we can do the following:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_reverse_autoInfector_JS.png]]

Now that we have the hash we can crack it using `hashcat`:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_reverse_autoInfector_hashcat.png]]

> The full `hashcat` command is just`hashcat -m 0 known_hash ~/rockyou.txt`
{: .prompt-info}

And now we can use this as the password to get the flag. And.. Voila:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_reverse_autoInfector_flag.png]]