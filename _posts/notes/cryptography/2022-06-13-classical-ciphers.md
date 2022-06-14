---
title: Notes | Classical Ciphers
author: Zeropio
date: 2022-06-13
categories: [Notes, Cryptography]
tags: [crypto, caesar, vigenere]
permalink: /notes/cryptography/classical-ciphers
math: true
---

This cipher born before computers, so most of them are think for letters rather than bits. They are much simpler than DES (**Data Encryption Standard**)

---

# Caesar

It encrypts a message by shifting each of the letters down three positions in the alphabet, wrapping back around to A if the shift reaches Z
For example:
```
ZOO -> CRR
FDHVDU -> CAESAR
```
> The shift number can be change, by it does not provide a really secure encryption.
{: .prompt-tip }

---

# Vigenère

The Vigenère cipher is similar to the Caesar cipher, except that letters aren't shifted by three places but rather by values defined by a key, a collection of letters that represent numbers based on their position in the alphabet.
If the key is **DUH**, letters in the plaintext are shifted using the values **3, 20, 7**.
```
CRYPTO -> FLFSNV
```

Let's take the following encryption with DUH:
```
THEY DRINK THE TEA -> WBLBXYLHRWBLWYH
```
In order to break it, it is need to guess the key's length. The group **WBL** it repeat twice in nine letters. The key must be nine or a value that divides nine. The sequence WBL can be some usual word, like **the**.
The next step is to use the method *frequency analysis*. For example, in English the letter **E** is the most common, so the most repeteable value in the cipher could be this letter.

> The shift can be change to divide, multiply,... instead of shifting.
{: .prompt-tip }

---

# The One-Time Pad

Let's take the following:
- **C**: ciphertext
- **P**: plaintext
- **K**: key
- **⊕**: XOR.

$$ C = P ⊕ K $$
So we can say that:
$$ C ⊕ K = P ⊕ K ⊕ K = P $$

With the following example, where **P = 01101101** and **K = 10110100**, we can calculate:
$$ C = P = ⊕ K = ⊕ 01101101 10110100 = 11011001 $$
$$ P = C= ⊕ K = ⊕ 11011001 10110100 = 01101101 $$

> Key shouldn't repeat between different plaintext, or it can be decypher.
{: .prompt-danger }

The issue is that the key need to be as long as the plaintext.
