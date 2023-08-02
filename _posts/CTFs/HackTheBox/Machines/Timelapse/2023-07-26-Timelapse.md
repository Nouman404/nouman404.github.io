---
title: CTFs | HackTheBox | Machines | Timelapse
author: BatBato
date: 2023-07-26
categories: [CTFs, HackTheBox, Machines]
tags: [CTF, HackTheBox, Machines, Windows, LAPS, john, pfx]
permalink: /CTFs/HackTheBox/Machines/Timelapse
---

# Timelapse

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c42c7b42-f1d8-4140-9cac-769137a9a066)

## Enumeration

As always, we run our nmap scan:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/fa9c8c10-570c-4178-9113-efe557c19d9c)


As we can see, we have `SMB` protocol available. We can try to access the shares using [smbmap](https://www.kali.org/tools/smbmap/):

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/59800daa-7168-4ec4-a4ce-3aa115ca1bef)


> Note that we can see the name `timelapse.htb`, this is because I added the IP address to the `/etc/hosts` file.
{: .prompt-info}

As we can see, we have access to the `Shares` share. This share contains two folders, `Dev` and `HelpDesk`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1eb0f72d-d099-4c3e-b28e-da428cf310af)

We have a zip file in the `Dev` folder and some `docx` files in the `HelpDesk` folder:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/189312c9-db9f-47c7-a60a-e1cbaf74cf4b)

After downloading the files, we can see that the files that were in the `HelpDesk` folder contain procedures to follow on the `LAPS` protocol to create an administrator password randomly and read it.

> Use the `--download PATH/TO/FILE` to download a file using smbmap.
{: .prompt-tip}

What is interesting, is that the zip file is protected by a password. We can use [zip2john](https://www.kali.org/tools/john/#zip2john) to get the hash and finally [john](https://www.kali.org/tools/john/) to recover the password:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/43f2f220-f20a-43ed-b143-d750eb0c8ba9)

We just have to provide the newly found password, and we get the `pfx` file from the `zip`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/198b71fc-a2f7-4bcf-b159-394e7da6fddd)

> PFX files (Personal Information Exchange) are a type of digital certificate file that contains both the public key and private key, often used for secure data encryption and authentication.
{: .prompt-info}

The pfx file is also protected, we use [pfx2john](https://www.kali.org/tools/john/#pfx2john) this time and crack again the password. After a few minutes, we cracked it:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6cb50c3f-41e9-4325-81a4-c38eb046cc2f)

We now can use it as specified on [this](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) website to recover the `certificate` and `RSA` key.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/023a0be8-dbd3-47dc-8236-2941afd1c365)

## Foothold

Now that we have the certificate and the private key, we can connect to the server using [evil-winrm](https://www.kali.org/tools/evil-winrm/) with `SSL`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/43a7f33d-6617-438c-9bba-a5fdf1690090)

> Don't forget the `-S`. If you do so, you will get an error saying that you need to specify a user.
{: .prompt-warning}


## User.txt

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/fb0cff83-45e3-45fd-aec8-ec75bea204a4)


## Horizontal Privilege Escalation

When we get the shell using `evil-winrm`, we don't seem to have that many rights... 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/efeda6dd-5156-46e2-9a26-67d17bc83110)

After a bit of roaming on the server, I didn't find much... But when I tried to get the powershell history at `C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, we find some credentials for the user `svc_deploy`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/71a330d9-7a4b-42e0-b0a9-4fcc1c352ec5)

## Vertical Privilege Escalation

Now that we have credentials, we can connect using those via `evil-winrm` as `svc_deploy`. 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/adc17918-1a04-490e-8714-cf10920afaf4)

As we can see, we have pretty much the same rights, but we are in the `LAPS_Readers` groups. This means that we could read the `Administrator` password that was generated randomly.

There are a lot of technics to get this password:
- We can use [crackmapexec](https://www.kali.org/tools/crackmapexec/) like `crackmapexec ldap 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' --kdcHost 10.10.11.152 -M laps`. But this didn't work.
- We can use other powershell tools specified on [hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps) or on [viperone's](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/laps) blog.
- None of the above worked for me, so I search a command to dump password using `LAPS` and found this `Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property *`. I added `select-object "ms-Mcs-AdmPwd"` at the end so I only get the password:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f9b17328-6c45-4766-b432-3acd556d6bf6)
- Finally, I found [this](https://github.com/n00py/LAPSDumper) python script that dumped the password too:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4559c39d-dd30-4ae7-a0cd-061a0ae54828)

## Root.txt

Now that we have the `Administrator` password, we can connect using `evil-winrm` as before. And... Voilà:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e37e5c82-0954-4861-942b-c1f3ff7fb08e)


