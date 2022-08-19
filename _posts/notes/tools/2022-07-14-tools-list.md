---
title: Notes | Tools
author: Zeropio
date: 2022-07-14
categories: [Notes, Tools]
tags: []
permalink: /notes/tools
---

This are my personal selection of **must have** tools for pentesting, bug bounty, CTFs or machines:

# For Linux

This is the path I choose while setting a Kali:

1. Download the following list.
```
netcat
curl
nmap
hashcat
ffuf
hydra
zaproxy
maltego
seclists
nvim
smtp-user-enum 
eyewitness
crackmapexec
```

2. Set Impacket tools in the command-line for anywhere:
```console
zero@pio$ git clone https://github.com/SecureAuthCorp/impacket
zero@pio$ sudo python3 -m pip install .
```

3. Update the system (`sudo apt update --fix-missing; sudo apt upgrade -y; sudo apt autoremove -y; sudo apt autoclean -y`).
4. Remember to download Burp (visiting `http://burp` with the proxy set) and ZAP (inside Settings) certs for the browser and install them.
5. Unzip rockyou (`sudo gzip -d /usr/share/wordlist/rockyou.txt.gz`)

---

# For Windows

```
python
vscode
git
wsl2
openssh
openvpn
x32dbg
x64dbg
```

> Recommend using [Chocolatey](https://chocolatey.org/) for the installation.
{: .prompt-info}

---

Feel free to copy it and install.

> It will be increasing since I'm progressing.
{: .prompt-info }
