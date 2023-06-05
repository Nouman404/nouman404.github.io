---
title: CTFs | 404CTF_2023 | Web3 | L'Antiquaire, tête en l'air
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023, Web3]
tags: [Web3,BlockChain, Mementum, IPFS]
permalink: /CTFs/404CTF_2023/Web3/L_Antiquaire_tete_en_l_air
---

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e366d1f2-dc4b-48e6-8aef-57a373c00556)


In this challenge, we have access to a [memorendum.txt](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Web3/memorandum.txt) file. This file contains hex text. I tried decoding it using an online tool and find two links:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b4d2c78a-a52a-4fc9-a5db-ab277d29d34f)

The URL `https://shorturl.ac/mysecretpassword` is a ... You guessed what... And the interesting part is `/ipfs/bafybeia5g2umnaq5x5bt5drt2jodpsvfiauv5mowjv6mu7q5tmqufmo47i/metadata.json`. 

The InterPlanetary File System (IPFS) is a protocol, hypermedia and file sharing peer-to-peer network for storing and sharing data in a distributed file system. IPFS uses content-addressing to uniquely identify each file in a global namespace connecting IPFS hosts. IPFS can among others replace the location based hypermedia server protocols HTTP and HTTPS to distribute the World Wide Web.

When looking how to access IPFS files, we get to [this website](https://docs.ipfs.tech/how-to/address-ipfs-on-web/) where we can see how to access IPFS on the web:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/8a48a944-b723-4570-b47a-5152c54a0929)

We then go to the URL `https://ipfs.io/ipfs/bafybeia5g2umnaq5x5bt5drt2jodpsvfiauv5mowjv6mu7q5tmqufmo47i/metadata.json` and we found the JSON file:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/41d76779-16c1-4ed1-9f6a-5328b28b8372)

We are given another IPFS link `ipfs://bafybeic6ea7qi5ctdp6s6msddd7hwuic3boumwknrirlakftr2yrgnfiga/mystere.png`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c9e0ef5f-ef7e-4921-ba8d-a5e0753addc6)

> If you don't specify a file at the end of the IPFS address, you will see all the files shared on this IPFS.
{: .prompt-tip}

I first thought that this was the wallet of a certain user... But didn't find anything. I then typed `Sepolia` on my browser and I found this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/222a141f-99be-4c21-802e-a2ca6f7ca4f0)

When I go to [this website](https://sepolia.etherscan.io/), I enter the ETH address `0x96C962235F42C687bC9354eDac6Dfa6EdE73C188`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/414e2d54-38db-4d30-b833-e0a4350103dc)

We can see that this blockchain has a contract. And when we head down to the `Constructor Arguments` section, we can see the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9fa38942-71b5-466d-8cf2-b003ca2be775)

And we validate this challenge with `404CTF{M3M3_P45_13_73MP5_D3_53CH4UFF3r_QU3_C357_D3J4_F1N1!}`


