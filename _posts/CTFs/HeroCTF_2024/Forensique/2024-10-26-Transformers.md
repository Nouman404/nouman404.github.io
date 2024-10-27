---
title: CTFs | HeroCTF_2024 | Forensique | Transformers
author: BatBato
date: 2024-10-26
categories:
  - CTFs
  - HeroCTF_2024
  - Forensique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/HeroCTF_2024/Forensique/Transformers
---
# Transformers #1

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_enonce1.png)

In this challenge, we are given an `.iso` file. We need to find the file extension of the malicious program and its `sha256`. To be able to read it easily, I've put this `.iso` in a windows VM. Now you just have to right click on it and mount it. Once this is done, you should see the following window that pops up:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_window.png)

For me the malicious program was the `.bat` file present in the `dev` folder that will download the virus on the machine but for the organizers the malicious file was the `Document` link that executes the `.bat` file:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_infoFolder.png)

To get the `SHA-256` we can either mount the file on Linux or copy it to our host to get the `sha256sum` or we can use the `Get-FileHash` Powershell command:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_powershellCommand.png)

And so the flag is : `HERO{lnk;c3bb38b34c7dfbb1e9e9d588d77f32505184c79cd3628a70ee6df6061e128f3e}`


# Transformer #2

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_enonce2.png)

For this chall, we need to get more information about the malicious file. We can drop the previously found `SHA-256` on `VirusTotal` and get a bunch of information. If we go to the `Community` section, we get the name of the dropper:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_dropper.png)

Now to know what is the domain requested, we have two option. Either we understand what the `.bat` files does or we use `VirusTotal`. 

## Finding the domain by hand

If we echo the command instead of executing it, we could understand what they are doing:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_echo.png)

Now, if we run this, we get the command executed printed out:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_powershell.png)

Finally we can `base64` decode the last string:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_base64.png)

And voilà... We have the domain `meeronixt.com`.

## Finding the domain with VirusTotal

Using `VirusTotal`, we can use a cool functionality available in the `Relation` section, the `Graph Summary`:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_graph1.png)

> Note that here we are working with the hash of the `.bat` file. Not the `.lnk` one.
{: .prompt-warning}

When we click on the graph, we are redirected to another interface and we can manipulate it easily :

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_graph2.png)

And here, we see clearly that it contacts a domain, and if we click on it:

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_forensique_transformers_domain.png)

And so, the flag is:
`HERO{BUMBLEBEE;meeronixt.com}`
