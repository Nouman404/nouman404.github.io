---
title: Notes | Password_Cracking
author: BatBato
date: 2022-08-25
categories: [Notes, Brute Force]
tags: [Brute Force, Passwords, Credentials, Cracking]
permalink: /Notes/Brute_Force/Password_Cracking
---

# Password Cracking

We are now in an era where password that you will find will not be in clear text and ready to use (most of the time). They will be "hashed". You may have heard terms like "hash", "hash functions", "cracking a hash"... But what does it mean ? First of all, what is a hash function ? A hash function is, as its name suggests, a mathematical function that generates a string (list of characters). This generated string is called a hash. Let's call the hash function "f" and "x" is the password that we want to hash. Then we get ```f(x)=y``` where "y" is the hash. What's cool about hashes it's that we can't reverse the function. This means that with "y" we can't find "x" even if we know "f". The other cool thing about hash functions is that whatever you put on it (our "x"), you will always have a different result. Let's take a concrete example. MD5 is an old hash function, we are going to hash ```password``` and ```password1``` with it :

```console
MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
MD5("password1") = 7c6a180b36896a0a8c02787eeafb0e4c
```

As you can see, we have used as input two strings that only have one difference but the two hashes are completely different. That's why hashing function are used instead of encoding. Because we can reverse encoding.

We often hear people saying "I cracked the hash" and you will tell me, "But how is it possible if we can't reverse it?". The first method (that you will never use) is to try any possible combination like "a", "b"..."aa", "ab"... This method takes too much time. What we will do instead is using a list containing many passwords that have been used by real people in the past and are likely to be used again. The word list we are going to use is called ```rockyou``` and contains 14 million passwords. 

> Wikipedia : "In December 2009, the RockYou company experienced a data breach resulting in the exposure of over ```32 million user accounts```. The company used an unencrypted database to store user account data, including ```plaintext passwords```. They also did not allow using special characters in the passwords. The hacker used a ```10-year-old SQL vulnerability``` to gain access to the database. The company took days to notify users after the incident, and initially incorrectly reported that the breach only affected older applications when it actually affected all RockYou users.The full list of passwords exposed as a result of the breach is ```available in Kali Linux```, and has been since its launch in 2013. Due to its easy attainability and comprehensive length, it is commonly ```used in dictionary attacks```"
{: .prompt-info }
