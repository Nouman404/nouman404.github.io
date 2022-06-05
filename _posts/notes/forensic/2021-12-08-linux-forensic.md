---
title: Notes | Linux Forensic
author: Zeropio
date: 2021-12-08
categories: [Notes, Forensic]
tags: [linux, forensic]
permalink: /notes/forensic/linux
---



# List installed package
```console
dpkg-guest -l
apt list -i
```


# Privilage users
```console
/etc/sudoers
```


# Sign
```console
sha256sum
```


# Main files
```console
shadow
passwd
lastlog
bootlog
auth.log
```


# Search files with permissions
```console
find -type f - perm -444
```
It can be change f to d, and 444 to other permission.


# History
With the command: diff you can compare and earlier version.
```console
cat ~/.bash_history
```


# Some commands
- dig
- netstat
- ip addr
- ifconfig
- dmesg
- more

