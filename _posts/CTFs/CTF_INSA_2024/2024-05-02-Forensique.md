---
title: CTFs | CTF_INSA_2024 | Forensique
author: BatBato
date: 2024-02-05
categories:
  - CTFs
  - CTF_INSA_2024
  - Forensique
tags:
  - Forensique
  - Vi
  - SWP
  - bitlocker
  - john
  - keypass
  - firefox
permalink: /CTFs/CTF_INSA_2024/Forensique/
---
# Forensic

## Bitlocker 1

![[bit2_sujet.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit2_sujet.png)

In this challenge, we are given a `disk.raw` image that contains partition of a windows machine that has been ciphered using bitlocker. We can use the tool [bitlocker2john](https://www.kali.org/tools/john/#bitlocker2john) to extract the password used to encrypt those partitions. We then use john to crack the passwords: 

![[bit1_pass.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit1_pass.png)


Using `fdisk` we can see that a unit has a size of `512 bytes` and that it starts at the `128th` one.
![[bit_fdisk.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit_fdisk.png)


This allows us to decrypt the partition at the correct location. We can use [dislocker](https://www.kali.org/tools/dislocker/#dislocker-1)to recover the decrypted partition:

![[bit_dislocker.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit_dislocker.png)

Now, we can mount the partition on one of our folder and recover the flag:

![[bit_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit_flag.png)


>Note that we needed to copy in an other folder the partition because it was only accessible in read-only. We may have been able to modify the rights of the file but this is easier :)  
{: .prompt-warning}

## Bitlocker 2


In this challenge, we are given two files. A `Bitlocker` encrypted partition and a memory dump of a windows machine.
I used [volatility2docker](https://github.com/p0dalirius/volatility2docker) for this challenge because `Volatility2` has some issues some times. The use of docker images is great because you don't have to install all the dependencies needed for the tool.

I found [this Github](https://github.com/breppo/Volatility-BitLocker) repository that talks about how to recover the content of a `Bitlocker` encrypted partition from a memory dump of the machine. First we need to add the `Bitlocker` script in the  `Volatility2` plugins list:

![[bit2_vol2_bitlocker.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit2_vol2_bitlocker.png)


Now we can analyse the image and we find it to be a windows10 machine:

![[bit2_imageinfo.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit2_imageinfo.png)


Now we need to recover the Full Volume Encryption Key (FVEK).
The Full Volume Encryption Key (FVEK) is a cryptographic key used in full disk encryption (FDE) systems to encrypt and decrypt the entire contents of a storage volume. It serves as the primary encryption key for the entire volume and is typically generated randomly during the encryption process. The FVEK is used to protect the confidentiality of data stored on the disk by encrypting it, making the data unreadable without the key. It is essential for securing sensitive information and ensuring data privacy and security in scenarios where entire disk volumes need to be protected. 

We use the newly added plugin `bilocker` to export the `FVEK`:

![[bit2_dislocker.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit2_dislocker.png)


Because we had a mounted volume on the docker, we have the files directly on our machine. We use `fdisk` to check the size of the units:

![[bit2_fdisk.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit2_fdisk.png)


We run the `dislocker` tool as in the previous exercice but this time we specify the `FVEK` file we want to use, the disk image and the folder to mount. Then we copy the decrypted partition in another folder and we mount it to a last folder where we can now read the flag:
![[bit2_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/bit2_flag.png)


> Some interesting reading on the subject on [LinkedIn](https://www.linkedin.com/pulse/bitlocker-full-volume-encryption-key-recovery-jiri-holoska/)
{: .prompt-info}

## Keypass

`Keepass` is a tool used to store credentials. It is a password manager. If the master password, that is used to cipher all the credentials, is weak, then we can have access to all the credentials stored in the `Keepass` file. We use [keepass2john](https://www.kali.org/tools/john/#keepass2john) to recover the hash of the password protecting the file, then we use john to crack it:

![[keypass_pass.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/keypass_pass.png)

Now we can install [KeepassXC](https://keepassxc.org/download/) on our computer and load the `bob.kdbx` file in it. We are asked for a password and we specify `spongebob`. We get the following result:


![[keepass_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/keepass_flag.png)


As you can see, we get the flag from the `Keepass` file.

> You may not have the flag showed directly. You may have to click on the eye to be able to see the value that by default is replaced by several dots.
{: .prompt-warning}
## Connaissez-vous la forensique 1

![[forensic1_sujet.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/forensic1_sujet.png)


Here, we are tasked to recover the password of the Firefox session and we are given several folder. I found the tool [firepwd](https://github.com/lclevy/firepwd) that allows us to recover all the password saved in Firefox if we specify a profile. We just have to run the following command: 

```bash
python firepwd/firepwd.py -d Roaming/Mozilla/Firefox/Profiles/aiaj08g4.default-release
```

And now we have at the bottom of the terminal the password for bob's account on amazon:

![[CTF-INSA/https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/forensic_flag(https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/CTF-INSA)
.png]]

##  Connaissez vous le Forensic 


![[forensic_sujet.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/forensic_sujet.png)


On this challenge, we need to recover the content of the Notepad application. I did a simple research on internet and found the following [blog](https://andreafortuna.org/2018/03/02/volatility-tips-extract-text-typed-in-a-notepad-window-from-a-windows-memory-dump/) . It gives us all the command we need to run to retrieve the content of our application.

I used the docker image of `Volatility3`. In the version 3, we don't need to specify the profile of the memory image we have. This allows me to directly recover the list of all the process and recover the `PID` of Notepad (4100):

![[forensic_notepad.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/forensic_notepad.png)


> Note the use of `>` to store the result of the command. It is a good practice to store the result of the commands we run in a file when using `Volatility` because it may take time to run it several times if we don't save the results.
{: .prompt-tip}

Now we can dump the memory of this process:

![[forensic_memdump.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/forensic_memdump.png)


This gives us a file called `pid.4100.dmp` and we can use the `string` and `grep` commands to recover the flag:

![[forensic_flag 1.png](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/forensic_flag 1)
]

> Note the use of `-e l` in the string command. If you dont specify to use the little endian mode, you won't be able to get any result. This is because Notepad stores text in this format.
{: .prompt-danger}
