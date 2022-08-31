---
title: Notes | Common Services Enumeration
author: BatBato
date: 2022-08-31
categories: [Notes, Footprinting, Common Services Enumeration]
tags: [Common Services, Enumeration, Web, FTP, SMB, SMTP, POP3]
permalink: /Notes/Footprinting/Common_Services_Enumeration
---

# Common Services Enumeration

## Web Enumeration

When you are looking at a web interface there is basically 3 things I advise you to do :
1. Read page content to find useful information
2. Read source code to find dev comments or information about plugins
3. Fuzz the website to find interesting files and/or directories

I'll leave you with the reading part and now we are going to look for the fuzzing part. It may not be very "stealthy" on a real live environment but it's pretty common in CTFs. If you like GUI, you can check the [Zap](https://www.zaproxy.org/docs/desktop/start/features/spider/) tool and especialy the spider/crawler section. But I'm going to go more in depth with two non graphical tools, ```ffuf``` and ```gobuster```.

### Ffuf / Gobuster

[ffuf](https://www.kali.org/tools/ffuf/) is a fest web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing. And [Gobuster](https://www.kali.org/tools/gobuster/) is a tool used to brute-force URIs including directories and files as well as DNS subdomains.

### Web Enumeration

First we are going to look for web pages and directories.
On ```gobuser``` you can find directories and web pages like this :

```console
gobuster dir -u http://SITE -w WORDLIST -x txt,php,html
```
> I advise you to use the ```/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt``` wordlist as a first attempt to find files or directories.
{: .prompt-tip }

On ```ffuf``` you can do so like this :

```console
ffuf  -u http://SITE/FUZZ -w WORDLIST -e .txt,.php,.html
```

> You can use recursion depth to look for files and directories in directories you find with fuff by adding the ```-recursion -recursion-depth 1``` option (it will do a recursion of 1 depth but you can increase this amount)
{: .prompt-tip }

> On both tools you can increase the scan speed by increasing the number of threads with the ```-t X``` option. Just replace the ```X``` with the number of threads that you want. I advise you not to go over ```50``` because it may cause errors or overheat the server.
{: .prompt-tip }

> The web fuzzing we have done can also be done with the ```intruder``` of ```Burp Suite```.
{: .prompt-info }

### POST / GET Fuzzing

With ```fuff``` you can fuzz POST and GET parameters. The easiest parameter to fuzz is the GET parameter because it's very similar to a web page or directory fuzzing.

```console
ffuf -u http://SITE/?id=FUZZ -w WORDLIST 
```

or

```console
ffuf -u http://SITE/?FUZZ=key -w WORDLIST 
```

This should result in many errors so you can stop it and rerun it with the ```-fs XXX``` option where ```XXX``` is the size you found on error results.

For the POST fuzzing parameter you can do it with the ```-d "PARAM=FUZZ``` or ```-d "FUZZ=VAL```:

```console
-X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

### Vhost & Subdomains

COMMING SOON
