---
title: CTFs | 404CTF_2026 | Realiste | Les Cahiers de Curie
author: BatBato
date: 2026-05-18
categories:
  - CTFs
  - 404_CTF_2026
  - Realiste
tags:
  - Realiste
  - nxc
  - AD
  - LDAP
permalink: /CTFs/404_CTF_2026/Realiste/Les_Cahiers_de_Curie
---

![[Realiste_Les_Cahiers_de_Curie_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Les_Cahiers_de_Curie_enonce.png)

Here we need to find information in a directory. First lest nmap it :

![[Realiste_Les_Cahiers_de_Curie_nmap.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Les_Cahiers_de_Curie_nmap.png)

As we can see, there is LDAP that should be what we are looking for. Now lets try to authenticate without any user :

![[Realiste_Les_Cahiers_de_Curie_nxc.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Les_Cahiers_de_Curie_nxc.png)

So now we know that we can query LDAP information without knowing any user lets try to get users information. And... voilà :

![[Realiste_Les_Cahiers_de_Curie_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Les_Cahiers_de_Curie_flag.png)