---
title: Notes | Metasploit
author: Zeropio
date: 2021-12-31
categories: [Notes, Tools]
tags: [tool, metasploit]
permalink: /notes/tools/metasploit
---


# Run metasploit

To run Metasploit we need to:
```console
@ update msf
@ postgresql start
@ msfdb.init
@ msfconsole
```

There are other basic commands like:
```console
@ db_status
```

# Basic use

We have the next commands to move in metasploit:
```console
$ back
$ exit
```

If we want to search an exploit:
```console
$ search ...
```
And then add the service we want to search and the version.

When we find the exploit we need to run it:
```console
$ use ...
```
Select one from the search result.

Then we need to configure the exploit:
```console
/exploit$ options
/exploit$ info
```
Now we need to check what is the exploit lacking and add it, for example:
```console
/exploit$ set rhost 192.168.0.1
/exploit$ unset rhost
```

Then we need to run the exploit, there are two options:
```console
/exploit$ run
/exploit$ exploit
```

# Payload generator

If we want to create or own payload we need to use the msfvenom tool (include in metasploit). 
```console
$ msfvenom ...
```
These are the options we have:
- **-p** select the payload
- **-e** encode
- **-i** encode X times
- **-f** extensiones we want to create it (linux: elf, win: exe)
And at the end **$ name.exe** to create into a file.

# Privilage escalation

As easy as:
```console
$ use priv
/priv$ getsystem
/priv$ getuid
```
We can see the options of **getsystem** with **-h**.
