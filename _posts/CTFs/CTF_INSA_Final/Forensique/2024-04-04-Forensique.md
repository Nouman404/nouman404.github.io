---
title: CTFs | Finale_CTF_INSA_2024 | Forensique
author: BatBato
date: 2024-04-04
categories:
  - CTFs
  - CTF_INSA_2024
  - Finale
  - Forensique
tags:
  - Forensique
  - bitlocker
  - john
  - keypass
permalink: /CTFs/Finale_CTF_INSA_2024/Forensique/
---
# Forensique

## My Name Is ?

In this challenge, we are asked to find the name of the user that juste have been powned. To do this, we just have to run the `envars` command of volatility.

Using volatility2, we first need to get the `image info`:

![[forensique_imageinfo1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_imageinfo1.png)

Now we use the `envars` to list all the environment variables:

![[forensique_envras1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_envras1.png)

And at the end of the file, we have the username we are looking for:

![[forensique_flag1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_flag1.png)

## Wallpaper

In this challenge, we are tasked to recover the wallpaper of the user. But when we try to dump the file `C:\Users\FLAG{GooDN4me}\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper.jpg` we get nothing extracted. This value was found in the registry key using the command `vol2 -f memory2.raw  --profile=Win7SP1x64 printkey -o 0xf8a00180f010 -K "Control Panel\Desktop" -v`

> Note that `0xf8a00180f010` is the virtual address of `ntuser.dat` when we used the `hivelist` function of volatility.
{: .prompt-info}

We can list all the process using the `pslist` function of volatility and we find those two process that are dealing with various aspects of the graphical user interface (GUI) in Windows:

![[forensique_wall_ps.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_wall_ps.png)
We can dump those process using their pid `1912` and `1932`:

![[forensique_wall_dump.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_wall_dump.png)

Now that we have the dump of both process, we can rename the dump file as `name.data`. This will allow us to open this raw data in GIMP and see the desktop. Using `dwm.exe`

![[forensique_wall_flag2.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_wall_flag2.png)

Using `explorer.exe`

![[forensique_wall_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_wall_flag.png)

> [Here](https://www.reddit.com/r/GIMP/comments/rqauj1/comment/hq9jy7w/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button) is a link talking about the raw vision of gimp
{: .prompt-info}

Thanks to `kwikkill` for the help he gave me to write this solution.

## MyPassword

As in the previous [CTF INSA](https://nouman404.github.io/CTFs/CTF_INSA_2024/Forensique/) forensic challenge, we had to mix a bit of all the previous techniques.
First we have to extract the hash of the disk image (boot sector) that is bitlocker encrypted:

![[forensique_bilocker1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_bilocker1.png)

Now we run `john` on the hash and retrieve the password:

![[forensique_john.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_john.png)

As seen previously [here](https://nouman404.github.io/CTFs/CTF_INSA_2024/Forensique/#bitlocker-2), we download the `dislocker` extension of volatility2 and use it to extract the `fvek` files:

![[forensique_fvek.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_fvek.png)

> Here is the command to copy paste :)
> `volatility2 -f memory.raw --profile=Win7SP1x64 bitlocker --dislocker export/`
{: .prompt-note}

Now we analyse the disk with `fdisk` and find an interesting device:

![[forensique_fdisk.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_fdisk.png)
We now use [dislocker](https://www.kali.org/tools/dislocker/#dislocker-1) to retrieve the unencrypted data:

![[forensique_dislocker.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_dislocker.png)

We mount the decripted disk to our file system and recover a keepass file:

![[forensique_mout.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_mout.png)

Now we just recover the hash using `keepass2john` and crack it with `john`:

![[forensique_john_keepass.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_john_keepass.png)

With the password of the keepass, we can open the file using `keepassxc` and recover the flag:

![[forensique_keepass.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024_Final/photos/forensique_keepass.png)
