---
title: CTFs | 404CTF_2026 | Forensique | Exfiltration Kantik 1/3
author: BatBato
date: 2026-05-22
categories:
  - CTFs
  - 404_CTF_2026
  - Forensique
tags:
  - pcap
  - Forensique
  - Forensic
  - wireshark
permalink: /CTFs/404_CTF_2026/Forensique/Exfiltration_Kantik_1_3
---

![[Forensique_Exfiltration_Kantik_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/Forensique_Exfiltration_Kantik_enonce.png)

In this challenge, we are mandated to find a lot of information :
- IP attacker
- IP victim
- Apache server version
- CVE used by attacker
- Port of reverse shell

First on the wireshark capture, we see a bunch of `SYN` followed by `RST,ACK` which let us think of an nmap can. Then when we look at the TCP captures, we see the nmap NSE scripts doing some recon :

![[Forensique_Exfiltration_Kantik_nse.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/Forensique_Exfiltration_Kantik_nse.png)

So with this capture, we can guess that the Attacker IP is `192.168.122.133` and the victim IP is `133_192.168.122`. On this capture we also have the apache server version that is `2.4.66`.

If we continue to follow the TCP stream, we arrive at a TELNET connection :

![[Forensique_Exfiltration_Kantik_telnet.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/Forensique_Exfiltration_Kantik_telnet.png)

On this screenshot we clearly see the attacker being authenticated as the `root` user... Strange...
If we do a quick research on the `USER -f root` section, we arrive on this blog https://www.txone.com/blog/cve-2026-24061-gnu-inetutils-telnet-exploitation/ that explains how to get a `root` shell on a telnet server. This gives us the CVE version `CVE-2026-24061`. 

And we scroll down a bit, we arrive to the reverse shell section being put in `/opt/.system_update` :

![[Forensique_Exfiltration_Kantik_revShell.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/Forensique_Exfiltration_Kantik_revShell.png)

The port of the reverse shell is `4444`. So the final flag is  `404CTF{192.168.122.133_192.168.122.177_2.4.66_CVE-2026-24061_4444}`