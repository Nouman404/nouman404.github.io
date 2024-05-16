---
title: CTFs | 404CTF_2024 | Investigation Numerique |  Vaut mieux sécuriser que guérir
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Investigation Numerique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/404_CTF_2024/Investigation_Numerique/Vaut_mieux_securiser_que_guerir
---
# Vaut mieux sécuriser que guérir

![[sec_enconce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_enconce.png)

This challenge had no sense for the first part of the flag, but we will see that later. 

Here we have a 2G memory dump. The fist thing, we notice is that we have a powershell instance running when we run the `pstree` command:

![[sec_ps.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_ps.png)

We can list the files to find the path to the powershell history as follows:

![[sec_ps_hist.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_ps_hist.png)

As we can see, the last command was `rm hascked.ps1` and we can wonder that this script deleted previous commands because the history file is empty. Because the file was deleted, we can't recover it... Or can't we ?

First of all i dumped the memory of the process `pwoershell` of PID `4852` using the command `volatility2  -f memory.dmp --profile=Win10x64_17134 memdump --pid 4852`. I then used the `strings` command on it and stored the result in a file to be able to analyse only readable characters. In this proc dump, we can find interesting information when we search the string `hacked.ps1`  but we also can  find information when searching for a string ending by `.ps1` (I used the regex `[a-zA-Z0-9]{1,9}\.ps1`)

![[sec_sound_ps1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_sound_ps1.png)

We can see another interesting information, that is the name of the task we are looking for:

![[sec_sound_LUL.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_sound_LUL.png)

Ok, now we know that the task name is `LUL`... It could be great if we could get the full content of `hacked.ps1` and `sound.ps1`. As we can see in the previous screenshot, we have a bit of powershell code in the dump file of the powershell process. The problem is that it is not a one bloc code but instead it is scatted in the whole dump. To be able to get the full content of the `hacked.ps1`  script we are going to head to the Windows Event Logs.

I dump every file on the system and then used the folowing command to set them as xml readable files `xargs -a event_log.lst -I {} sh -c 'python3 python-evtx/scripts/evtx_dump.py "{}" > "event_logs_xml/$(basename {} .evtx).xml"'`.

The flile called `file.1296.0xffffd50eb9c93500.vacb.xml` contains the full content of `hacked.ps1`:

![[sec_jakoby.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_jakoby.png)

With this, we can fully understand the kill chain (but it isn't needed for the challenge...). We can find the [hacked.ps1](https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB/blob/main/Payloads/Flip-Wallpaper-Troll/Wallpaper-Troll.ps1) script on [Jakoby](https://github.com/I-Am-Jakoby) github with the [clean-exfil](https://github.com/I-Am-Jakoby/PowerShell-for-Hackers/blob/main/Functions/Clean-Exfil.md) program used in by the attacker. But the only thing we are interested in is located in the middle of the code:

![[sec_enc_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/sec_enc_flag.png)

What does this script in the main line is creating a wallpaper to replace the one of the victim with a lot of information about the computer like the name of the user, the location, the wifi passwords saved... The string `e1ByQG5rM2Qt` wasn't in the original script of Jakoby but it didn't worked when I tried to use it as the flag... Strange... Why an attacker would print a random string on the victim desktop if it isn't the flag right ??? Well, my friend, this is where the nonsense begins. This string was base64 encoded. Why ? I don't know. Why an attacker would print a base64 string on a victim computer ? The victim won't understand it so... (You may have understood that it took me a while to find that this string was base64 encoded, where finding it was pretty easy...).

Well at least we have the full flag now... And... Voilà `404CTF{Pr@nk3d-LUL}`

> `{Pr@nk3d-` is the base64 decoded string of `e1ByQG5rM2Qt` and `LUL` is the name of the task executing `sound.ps1`
{: .prompt-info}

> Not that using the process `dwm.exe` or `explorer.exe`, we could have find the string `e1ByQG5rM2Qt` by printing the desktop content (that was how I found it first). You can find the steps on [this CTF](https://nouman404.github.io/CTFs/Finale_CTF_INSA_2024/Forensique/) 
{: .prompt-tip}

