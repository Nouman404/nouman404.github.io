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





## Fuzzing 

Fuzz testing, sometimes known as "fuzzing," is a Black Box software testing technique that essentially entails detecting implementation defects by automated insertion of erroneous or semi-malformed data. A verry basic example woul be a GET parametter on a web page. If the URL looks like ```http://SITE/?id=0``` we may want to know which ```id``` are valid. 
