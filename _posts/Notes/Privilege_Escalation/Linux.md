---
title: Notes | Brute Force
author: BatBato
date: 2022-08-25
categories: [Notes, Privilege Escalation, Linux_PE]
tags: [Web, Privilege Escalation, Linux_PE, Root]
permalink: /Notes/Privilege_Escalation/Linux_PE
---

# Linux PE (Privilege Escalation)

Exploiting a bug, a design defect, or a configuration oversight in an operating system or software program to acquire elevated access to resources that are typically guarded from an application or user is known as privilege escalation.

As junior pentester we want to become administrator of a machine. We are not going to talk here about [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures) (Common Vulnerabilities and Exposures) that are numerous and change depending of the OS, service or method of attack. We are going to talk about basic PE and this list is not exhaustive.

# Sudo -l

When we get on a machine we would like to know what rights we have. For that we can type ```sudo -l```. This command will list what we are able to run with the ```sudo``` command. The ```sudo``` command allow us to execute other commands as another user. The output can look like this: 

```console
User kali may run the following commands on kali:
    (ALL : ALL) ALL
```

This output won't appear much when you connect on a vulnerable machine but a similar one may. First, what does it mean ? The output is of the form ```(user:group) command```. This output tells us that we can execute any command as any user or group.

The output may more likely look like this :
```console
User bob may run the following commands on vulnerable:
    (root) /usr/bin/find
```
Here we see that we can execute the ```find``` command as the ```root``` user, which is the admin on Linux.
You may say "OK, that's cool but how can the "find" command be useful in PE ?" and you will be right. How can a command that allows us to find files or directories allow us to become root ? Well, there is a wonderful website called [GTFOBins](https://gtfobins.github.io/) where you can find a list of binaries and how to PE with them. If we go [here](https://gtfobins.github.io/gtfobins/find/#sudo) we can see the line that will allow us to become root :

```console
sudo find . -exec /bin/sh \; -quit
```

The PE can be ```horizontal``` or ```vertical```. A ```horizontal``` PE as its name suggests, is a PE where you stay on the same level. Typically it happens when you change user (not root).
