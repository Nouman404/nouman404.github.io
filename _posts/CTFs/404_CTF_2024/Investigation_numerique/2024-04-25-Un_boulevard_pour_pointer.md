---
title: CTFs | 404CTF_2024 | Investigation Numerique |  Un boulevard pour pointer
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Investigation Numerique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/404_CTF_2024/Investigation_Numerique/Un_boulevard_pour_pointer
---
# Un boulevard pour pointer

![[boulevard_enonce.png]]

In this challenge, we are given a zip file containing two PDF and a disk image. The two PDF contains linux forensic commands like `file`, `strings`, `fdisk -l` or `mmls`.

First lets run the `fdisk -l` command to get more information on the disk image:

![[boulevard_fdisk.png]]

As we can see, there are three partitions and one of the (`Linux root (x86-64)`) is 5.5G big. Lets mount this partitions on local directories:

![[boulevard_mount.png]]

Now if we look into the `partition2` folder we can see the following structure:

![[boulevard_ls.png]]

We can now go into the `/root` folder and read the `.bash_history` file we can see the following information:

![[boulevard_history.png]]

As we can see, we have a backup file that was saved using `xfsdump`. After a bit of research, I found [this blog](https://linuxconfig.org/how-to-backup-and-restore-an-xfs-filesystem-using-xfsdump-and-xfsrestore) about `xfsdump` and `xfsrestore` so I used the following command to recover the original home folder:

![[boulevard_xfsrestore.png]]

Now we can navigate to the `backup_folder` and list the files:

![[boulevard_tree.png]]

And now, we have the flag in the last `PDF`:

![[boulevard_FLAG.png]]

So the flag is `404CTF{bi1_joué_br4vo_c_le_fl4g}`.