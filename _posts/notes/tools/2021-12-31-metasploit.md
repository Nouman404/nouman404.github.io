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
msf6> back
msf6> exit
```

If we want to search an exploit:
```console
msf6> search exploit <name>
```
And then add the service we want to search and the version.

When we find the exploit we need to run it:
```console
msf6> use ...
```
Select one from the search result.

Then we need to configure the exploit:
```console
msf6 exploit(...)> options
msf6 exploit(...)> info
```
Now we need to check what is the exploit lacking and add it, for example:
```console
msf6 exploit(...)> set rhost 192.168.0.1
msf6 exploit(...)> unset rhost
```

Then we need to run the exploit:
```console
msf6 exploit(...)> check
msf6 exploit(...)> exploit
```
The check option will see if the server is vulnerable (not all the exploit have the `check` function).

> It can be use `run` instead of `exploit`
{: .prompt-tip }

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
