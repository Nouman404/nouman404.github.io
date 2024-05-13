---
title: CTFs | 404CTF_2024 | Investigation Numerique | Tir aux logs
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Investigation Numerique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/404_CTF_2024/Investigation_Numerique/Tir_aux_logs
---
# Tir aux logs

In this challenge, we are given a text log file of 56 lines. The first look we have at the file, it looks like someone is trying to do an SQLi:

![[log_log.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/log_log.png)

There was two ways to solve it here. Either you understand SQLi or you look at status codes. I used the command `cat access.log| awk '{print $7}'` for better reading:

![[log_awk.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/log_awk.png)

We can notice the `admin"#&password=test`. This allows to bypass the verification of the password variable for the user `admin`.  As we can also see, we have a status code of `302` and right after a status code of `200` on the `admin.php` page. In the previous logs the pattern `302` before a `200` on the admin page refer to a successful connection.

The flag is `404CTF{?username=admin%27%23&password=test}`
