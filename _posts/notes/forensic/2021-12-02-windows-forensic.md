---
title: Notes | Windows Forensic
author: Zeropio
date: 2021-12-02
categories: [Notes, Forensic]
tags: [windows, forensic]
permalink: /notes/forensic/windows
---

> First of all, we need to use a cmd (as admin).
{: .prompt-tip }

# Cookies
With this we can show all the cookies in the system.
```console
dir cookie*.* /s/p
```
Also, we can use the extension SQLite Manager to see it.

- /s: enumerate
- /p: pagination


# History
If we want to list all the history (from web browsers).
```console
dir index.dat /s/p/a
```

- /a: attributes


# Executed app
If we want to list all the executed apps.
```console
dir *.pf /s/a/p
```


# Thumbnail
If we want to see all the thumb in the system.
```console
dir thumb*.db /s/p/a
```


# History
If we want to list all the history (from web browsers).
```console
dir index.dat /s/p/a
```


# List files
Order the files from modification date.
```console
dir /t:w /a /s /o:d
```
Order the files from last access.
```console
dir /t:a /a /s /o:d
```

- /t:w type
- /o:d date

# Tools
- [MUI cache](https://www.nirsoft.net/utils/muicache_view.html): list all the programs that have write a key code.
- [dumpIt](https://dumpit.soft32.com/): create a memory dump of the RAM.
- [PsTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools): see all logged users.
- [WebBrowserPassView](https://www.nirsoft.net/utils/web_browser_password.html): find browser's password.
- [Volatility](https://www.volatilityfoundation.org/releases): memory dump.

