---
title: CTFs | DGHACK_2023 | Crypto | Cryptoneat
author: BatBato
date: 2023-11-30
categories: [CTFs, DGHACK_2023, Crypto]
tags: [Crypto,AES,CTR,IV,Padding]
permalink: /CTFs/DGHACK_2023/Crypto/Cryptoneat
---

# Cryptoneat

In this challenge, we have access to an HTML page that you can download [here](./page.html). In this page, we can see some kind of imported JS code from `Crypto JS 3.1.9-1`. After this big JS code, we can see another JS code more readable with functions to encrypt and decrypt messages using a password. When we get a quick look at the `encrypt` function, we can see that the function uses `AES` on the `CTR` mode and using padding (keep that in mind it will be useful later):

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4675c43f-0a64-4956-8a59-cd134e2683f2)

After those function declarations, we can see a big `encrypted_message1` and a smaller one called `encryptedMsg2`. Looking more in detail what vulnerabilities may be exploited for this kind of `AES` (`CTR` mode), we find [this blog](https://crypto.stackexchange.com/questions/2991/why-must-iv-key-pairs-not-be-reused-in-ctr-mode). It tells us that  `cipher_text = message XOR key`. It also tells us that if two messages have the same `IV` (initialise vector) and the same secret we could recover the content of a cipher text by just knowing one message and its plain text. Here we don't seem to have a clear text but if we look closer to what we have, we can see that the length of the `encryptedMsg2` and of the `cryptoThanks` are the relatively same:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/75a165a5-36a1-4cdb-bc2b-0e404c2230bd)

The length difference is due to the padding we saw earlier. Let's take `P1` (respectively `P2`) as `plaintext1` (respectively `plaintext2`) and `C1` (respectively `C2`) as `cipher_text1` (respectively `cipher_text2`).  So, because we know that `C1 = P1 XOR KEY` and `C2 = P2 XOR KEY` if we can find the `KEY`, we could recover the content of `P1` and `P2`. As we just said, we are assuming that `P2 = "Build with love, kitties and flowers"` and that `C2_known = "C19FW3jqqqxd6G/z0fcpnOSIBsUSvD+jZ7E9/VkscwDMrdk9i9efIvJw1Fj6Fs0R"`

> Note that we removed the `IV` (first 32 characters each time). The `IV` isn't part of the ciphered text it is concatenated to it.
{: .prompt-warning}


With that in mind, we need to add the padding to P2 to get the same length as the C2 one. The length difference is `48-36 = 12` and `12` in hexadecimal is `0xC`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/05b78ae9-a80d-4db9-9c70-52c529ba4a4c)

> Getting the same length is very important because if we don't have the same one, the `XOR` operation won't work properly.
{: .prompt-info}

If we now `XOR` P2 (with the added padding of `0xC` 12 times) converted to byte and C2 we get the `KEY`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/daf58597-9249-4c3f-8e85-cafa65c4b00c)

We can now use the `XOR` operation on `P1` with the found `KEY` and we get the plain text:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6230e2bc-b956-41e4-af97-1f5327441d44)

> Note that we decoded `P1` without its `IV`.
{: .prompt-info}

When I run [my code](./xor.py), I get the content of `P1` in a file called `p1.txt`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/65e7c32f-3e2d-486b-9bcf-29875e94b0a7)

We can now go to the URL given and use the password `My2uperPassphras3` to access the secret content and recover the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/71b7cb16-7dab-425c-bd21-adac4e04b8f8)

The flag is `DGHACK{w3ak_pa22word2_ar3n-t_n3at}`. You can find my full code [here](./xor.py).
