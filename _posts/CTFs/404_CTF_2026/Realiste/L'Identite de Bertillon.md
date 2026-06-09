---
title: CTFs | 404CTF_2026 | Realiste | L'Identité de Bertillon
author: BatBato
date: 2026-05-19
categories:
  - CTFs
  - 404_CTF_2026
  - Realiste
tags:
  - Realiste
  - AD
  - certipy
  - ADCS
permalink: /CTFs/404_CTF_2026/Realiste/L_Identite_de_Bertillon
---

![[Realiste_L_Identite_de_Bertillon_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_enonce.png)

In this challenge it is stated that there is a certificate authority so we can guess that we need to use ADCS exploits.

First lets check if it is vulnerable to any known ADCS exploits by running the command `certipy-ad find -u $USER@$DOMAIN -p $PASSWORD -vulnerable -dc-ip $DC_IP -stdout`

![[Realiste_L_Identite_de_Bertillon_certipy.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_certipy.png)

As we can see, the CA is vulnerable to ESC1. This means we can query a certificate for any user, lets say the `vip_auditor` specified in the chall description :

![[Realiste_L_Identite_de_Bertillon_pfx.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_pfx.png)

Now that we have the certificate, we can recover the NT hash of this user :

![[Realiste_L_Identite_de_Bertillon_hash.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_hash.png)

We can user this NT hash to check if we now have any interesting permissions and as we can see, we can now access the `AuditReports` folder :

![[Realiste_L_Identite_de_Bertillon_smbmap.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_smbmap.png)

We can authenticate with this hash and recover the flag :

![[Realiste_L_Identite_de_Bertillon_flag2.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_flag2.png)

OR...

We can crack the has that is a trivial password XD :

![[Realiste_L_Identite_de_Bertillon_cracked.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_cracked.png)

And authenticate with this password :

![[Realiste_L_Identite_de_Bertillon_flag_1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Realiste/Photos/Realiste_L_Identite_de_Bertillon_flag_1.png)

