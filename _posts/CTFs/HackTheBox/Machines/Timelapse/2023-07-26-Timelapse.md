---
title: CTFs | HackTheBox | Machines | Timelapse
author: BatBato
date: 2023-07-26
categories: [CTFs, HackTheBox, Machines]
tags: [CTF, HackTheBox, Machines, Windows, LAPS]
permalink: /CTFs/HackTheBox/Machines/Timelapse
---

# Timelapse

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c42c7b42-f1d8-4140-9cac-769137a9a066)

# Enumeration

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

After downloading the files, we can see that the files that were in the `HelpDesk` folder contain procedures to follow on the `LAPS` protocol to create administrator password randomly and read it.

> Use the `--download PATH/TO/FILE` to download a file using smbmap.
{: .prompt-tip}

What is interesting, is that the zip file is protected by a password. We can use [zip2john](https://www.kali.org/tools/john/#zip2john) to get the hash and finally [john](https://www.kali.org/tools/john/) to recover the password:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/43f2f220-f20a-43ed-b143-d750eb0c8ba9)

We just have to provide the newly found password and we get the `pfx` file from the `zip`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/198b71fc-a2f7-4bcf-b159-394e7da6fddd)

The pfx file is also protected, we use [pfx2john](https://www.kali.org/tools/john/#pfx2john) this time and crack again the password. After a few minutes, we cracked it:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6cb50c3f-41e9-4325-81a4-c38eb046cc2f)

We now can use it as specified on [this](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) webiste to recover the `certificate` and `RSA` key.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/023a0be8-dbd3-47dc-8236-2941afd1c365)

Now that we have the certificate and the private key, we can connect to the server using [evil-winrm](https://www.kali.org/tools/evil-winrm/) with `SSL`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/43a7f33d-6617-438c-9bba-a5fdf1690090)

> Don't forget the `-S`. If you do so, you will get an error saying that you need to specify a user.
{. prompt-warning}
