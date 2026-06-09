---
title: CTFs | 404CTF_2026 | Divers | Super enquete libre 1/4
author: BatBato
date: 2026-05-18
categories:
  - CTFs
  - 404_CTF_2026
  - Divers
tags:
  - Divers
  - SQL
permalink: /CTFs/404_CTF_2026/Divers/Super_enquete_libre_1_4
---

![[Divers_Super_enquete_libre_1_4.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Divers/Photos/Divers_Super_enquete_libre_1_4.png)

In this chall, we are given a connection to an SQL server. We need to find the `active` badge number of `Laurent NOEL`. 

On the server we can list the available tables :

![[Divers_super_enquete_libre_1_tables.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Divers/Photos/Divers_super_enquete_libre_1_tables.png)

As we can see, there are the `Person` and `Badge` tables that should be interesting :

![[Divers_super_enquete_libre_1_schema.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Divers/Photos/Divers_super_enquete_libre_1_schema.png)

Now we can select the badges that are own by `Laurent NOEL` :

![[Divers_super_enquete_libre_1_select.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Divers/Photos/Divers_super_enquete_libre_1_select.png)

As we can see, we have two badges but only one is active. So the flag is `404CTF{165}`
