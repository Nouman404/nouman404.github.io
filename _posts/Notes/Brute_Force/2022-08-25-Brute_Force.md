---
title: Notes | Brute Force
author: BatBato
date: 2022-08-25
categories: [Notes, Web, Brute Force]
tags: [Web, Brute Force, Passwords, Credentials]
permalink: /Notes/Brute_Force/Brute_Force.md
---

# Brute Force

According to Wikipedia, "Brute Force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly". It may not be effective in the real world pentest because some web site may only allow 3 or 4 invalid attempt. This can lock an account or spot and clock us.

## Hydra

Hydra is a very powerful tool that can brute force a lot of services. The syntax is basically the same for every protocol (ftp, ssh, smtp...) except for the HTTP post form. [Here](https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/) is a very well written article about this specific syntax. For the other protocol you can use it like this :
```bash
└─$ hydra -l admin -P wordlist 10.10.10.10 ftp
```
Here we attack the host ```10.10.10.10```. We try to find a valid password for the user ```admin``` for the ftp server.
We can replace ```ftp``` by ```ssh```, ```rdp```, ```pop3```...
If you don't remember the syntax you can find a cheat sheet [here](https://github.com/frizb/Hydra-Cheatsheet).


## CrackMapExec 

This package is a swiss army knife for pentesting Windows/Active Directory environments. From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.
It can be used to brute force ```ldap```, ```winrm```, ```smb```, ```ssh``` or ```mssql```. It can be used like that :

```bash
└─$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```
Ex:
```bash
└─$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```

## Evil-WinRM

This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985).

```bash
└─$ evil-winrm -i 10.10.10.10 -u user -p password
```
Here ```user``` and ```password``` can either be a string or a file.

