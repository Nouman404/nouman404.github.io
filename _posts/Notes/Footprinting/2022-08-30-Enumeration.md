---
title: Notes | Enumeration
author: BatBato
date: 2022-08-30
categories: [Notes, Enumeration]
tags: [Web, Fuzzing, Ports, Enumeration]
permalink: /Notes/Footprinting/Enumeration
---

# Enumeration

Capture The Flag (CTF) are challenges that allows us to train ourseves on different tools and techniques. The first step will usually be a port scanning. But in a real world environement we are first going to gather some informations. You can have more information about that on the [OSINT](https://nouman404.github.io/Notes/Footprinting/OSINT) section.

## Port Enumeration

In CTF where you have to pwn a machine, most of the time you will only have an IP address. The first thing we would like to do is a port scanning. "But what is a port or a port scanning?", well a port could be seen as any entrance in your house, whether it is your front/back door, windows, chimney... It can allow an attacker to get in your house (server). "So why don't we just close them all?", of course, if you don't need a certain port to be open it's a good thought to close it. But ports are often open for a reason, like, hosting a website, an FTP server, SMB shares... You can find [here](https://packetlife.net/media/library/23/common_ports.pdf) a list of the most common ports. As you can see they can be used for a lot of things. So if we scan all ports of a server we can know what is runing on it.

Of course you can create your own port enumeration tool. But here we are going to look to already created tools.
[Nmap](https://www.kali.org/tools/nmap/#nmap-1) is the most famous port scanning tool but there are many other tools like [Rustscan](https://github.com/RustScan/RustScan) which how his name state is coded in Rust and allow us to scan all the 65K port in less than 3s. I'll let you check Rustscan on your own because it is similar to Nmap.

### How to use Nmap
The easier way to use command is ```nmap IP/HOST``` where you use eather the ```IP``` or the ```HOST``` you want to scan. But there are many other flags (options) that we can use :

| **Flag** | **Description** |
| --------- | --------------|
| ```-v``` | Increase output verbosity  |
| ```-sC``` | Run default scripts (equivalent to --script=default)  |
| ```-sV``` | Probe open ports to determine service/version info  |
| ```-A``` | Enable OS detection, version detection, script scanning, and traceroute  |
| ```--script-updatedb``` | Update the script database  |

If you want fast result you may want to scan for ports and then to scan ONLY those ports. You can do so by using the ```-p``` flag and separate every port by a comma like ```nmap -p 80,22 -sC -sV 8.8.8.8```.

### Saving Results

When performing a pentest or even during a CTF it's a good practice to save result about what we do. Whether it is for our client or just to remember what we have done it's important to save them. We can do so using different flags :

| **Flag** | **Description** |
| --------- | --------------|
| ```-oN``` | Normal output with the .nmap file extension |
| ```-oG``` | Grepable output with the .gnmap file extension |
| ```-oX``` | XML output with the .xml file extension |
| ```-oA``` | Save the results in all formats |
| ```-iL``` | Scan all the hosts in the file provided |

When you get your ```.xml``` file you can generate a ```.html``` page report with the following command :

```console
xsltproc target.xml -o target.html
```

### Scripts

What makes the strength of ```Nmap``` is its scripts. You can see all the Nmap scripts in its folder ```/usr/share/nmap/scripts/```. There are many ```.nse``` files in this folder that can be used as script as follows :

```console
nmap --script=SCRIPT_NAME1,SCRIPT_NAME2,...,SCRIPT_NAMEn
```

You can use one or multiple scripts that you need to separate with a comma as shown above. Replace all the ```SCRIPT_NAMEx``` with the one you want to use and you can remove the ```.nse``` extension. Here is a list of several basic scripts :


| **Category** | **Description** |
| --------- | --------------|
| ```auth``` | Determination of authentication credentials. |
| ```broadcast``` | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| ```brute``` | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| ```default``` | Default scripts executed by using the -sC option. |
| ```discovery``` | Evaluation of accessible services. |
| ```dos``` | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| ```exploit``` | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| ```external``` | Scripts that use external services for further processing. |
| ```fuzzer``` | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| ```intrusive``` | Intrusive scripts that could negatively affect the target system. |
| ```malware``` | Checks if some malware infects the target system. |
| ```safe``` | Defensive scripts that do not perform intrusive and destructive access. |
| ```version``` | Extension for service detection. |
| ```vuln``` | Identification of specific vulnerabilities. |


### Performance

When we need to scan a large network or are dealing with poor network bandwidth, scanning performance is crucial. We can instruct Nmap using a number of options regarding the speed (-T <1-5>), frequency (—min-parallelism <number>), timeouts (—max-rtt-timeout <time>), number of test packets sent simultaneously (—min-rate <number>), and number of retries (—max-retries <number>) for the scanned ports of the targets to be scanned.
  
#### Timeouts
  


## Fuzzing 

Fuzz testing, sometimes known as "fuzzing," is a Black Box software testing technique that essentially entails detecting implementation defects by automated insertion of erroneous or semi-malformed data. A verry basic example woul be a GET parametter on a web page. If the URL looks like ```http://SITE/?id=0``` we may want to know which ```id``` are valid. 
