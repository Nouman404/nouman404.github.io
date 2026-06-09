---
title: CTFs | 404CTF_2026 | Realiste | Le Secret de Lavoisier
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
permalink: /CTFs/404_CTF_2026/Realiste/Le_Secret_de_Lavoisier
---

![[Realiste_Le_Secret_de_Lavoisier_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Le_Secret_de_Lavoisier_enonce.png)

![[Realiste_Le_Secret_de_Lavoisier_nmap.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Le_Secret_de_Lavoisier_nmap.png)

If we try to access shares we can't... Buf if we look at them we can see a `Backups` share but we can't acess it

![[Realiste_Le_Secret_de_Lavoisier_smbmap.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Le_Secret_de_Lavoisier_smbmap.png)

If we look inside the `SYSVOL` share, we have the `backup_reader` password :

![[Realiste_Le_Secret_de_Lavoisier_gpp.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Le_Secret_de_Lavoisier_gpp.png)

With that, we can now connect to the shared folder and if we login as him :

![[Realiste_Le_Secret_de_Lavoisier_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_Le_Secret_de_Lavoisier_flag.png)
