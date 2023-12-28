---
title: CTFs | 404CTF_2023 | Forensique | Note de bas de page
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Forensique]
tags: [Forensique,Wireshark, Acropalypse, Crop]
permalink: /CTFs/404CTF_2023/Forensique/Note_de_bas_de_page
---

# Note de bas de page 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b750e678-7336-4431-9cdc-9bd85238374f)

In this challenge, we are given a [backup.pst](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Forensique/backup.pst) file. 

PST (Personal Storage Table) files are a file format used by Microsoft Outlook to store email messages, calendar events, contacts, and other data. PST files are used for local email storage and provide users with the ability to access their emails and other Outlook data even when not connected to a mail server.

I found this [online tool ](https://goldfynch.com/pst-viewer/index.html#0/32994/2097252):

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/0a93d020-2a73-4690-8b0a-43bed710eefa)

As we can see there is a picture in the attachment. The picture is:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Forensique/Capture%20d%E2%80%99%C3%A9cran%202023-05-07%20210840.png)

The image seems to have the flag at the bottom right corner, but we only have `404CTF{L`... Looking at some CVE that may allow us to recover the full image we can find [CVE-2023-21036](https://nvd.nist.gov/vuln/detail/cve-2023-21036). This CVE tells us that if a Pixel phone  from Google truncate an image it is possible to recover the initial image because it didn't truncate is and save the result in a new file but instead just added an `IEND` sooner.

We can now use [this tool](https://github.com/frankthetank-music/Acropalypse-Multi-Tool) to recover the whole image. I then run the `gui.py` and set these options:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e677aac7-499b-48fc-9c50-d56d90e74cff)


Now we just have to wait and save the result...

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/773830a5-32cf-4921-a48c-16e757edb7aa)

The final image is:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/Forensique/flag_bas_de_page.png)

Impressive!!! The flag is `404CTF{L3_f0rM1d@bl3_p09r35_d3s_lUm13re5}`
