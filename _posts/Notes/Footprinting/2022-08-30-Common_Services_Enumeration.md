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

We already have seen how to discover VHosts in the [OSINT module](https://nouman404.github.io/Notes/Footprinting/OSINT#virtual-hosts-discovery). For subdomain enumeration it's much like POST and GET fuzzing :

```console 
ffuf -u https://FUZZ.example.com/ -w WORDLIST
```


>  If you don't have it yet you can download [Seclists](https://www.kali.org/tools/seclists/) with ```sudo apt install seclists```. You will find a lot of wordlist and the ones we are interested in here are the ones in the ```/usr/share/seclists/Discovery/DNS/``` directory. The ```subdomains-top1million-110000.txt``` is a pretty complete.
{: .prompt-tip }

> As you can see, ```ffuf``` is pretty versatile tool and can basically fuzz anything. You can also use it for brute force if you want, for example.
{: .prompt-info }

## FTP

File Transfert Protocol (FTP) is a standard communication protocol used for the transfer of files from a server to a client. To connect to an FTP server we can use the ```ftp IP -P PORT```command. The default FTP port is ```21``` so if you have the same port for the FTP server on the machine you are attacking then you don't have to specify the ```-P``` flag. When you run the command, you will be asked to connect with a ```username``` and ```password```. If you don't have such things, you can try to use the default ```anonymous``` user without a password. The ```anonymous``` connexion should be disabled but it's worth trying.

> The ```-sC``` of ```nmap``` can list files if anonymous login is enabled.
{: .prompt-tip }

> There may be hidden files so don't forget the ```-a``` flag of the ```ls``` command. The ```-R``` flag can also become handy to list files recursively.
{: .prompt-tip }

On an FTP server you can't read files like on a normal machine with ```cat``` or your preferred text editor. You'll have to download the file to read it locally. To download a file you can use the ```get FILE``` command and to upload a file the ```put FILE``` command. Whether it is for the ```get``` or the ```put``` command the default directory will be the one where the ```ftp``` command was launched. If you launched the command on the ```Desktop``` the files will be downloaded here and if the file you want to upload isn't on the desktop then you will need to specify its path.

> If you want information about ```FTP brute forcing``` you can check [this link](https://nouman404.github.io/Notes/Brute_Force/Brute_Force) 
{: .prompt-warning }

## SMB
