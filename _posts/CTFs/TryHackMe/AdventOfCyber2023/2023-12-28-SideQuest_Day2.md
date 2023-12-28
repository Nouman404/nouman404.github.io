---
title: CTFs | TryHackMe | AdventOfCyber2023 | Side Quest Day 2
author: BatBato
date: 2023-12-28
categories: [CTFs, TryHackMe, AdventOfCyber2023]
tags: [Vim, Nano, Docker, Side Quest, THM]
permalink: /CTFs/TryHackMe/AdventOfCyber2023/SideQuest_Day2
---

# Side Quest - Day 2

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ec91b792-59d0-4384-ab3e-d2b61869dc74)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ce1bde2d-6c8c-464c-8dff-02f8892a7bb6)


# Enumeration

In this challenge, we are just given the an IP address. So we start our enumeration phase by running our nmap:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/37e4f260-e8cf-4148-9796-e3344fc4351c)

> As you can see, I used only `-sV`. This is because the result of `-A` (<=> `-sC -sV`) can't be contained in a screenshot :)
{: .prompt-warning}

As we can see, we got a lot of open ports. The port `80` gives us an error when we try to access it, so I search for anything else on the other ports. We can connect to the ftp as `anonymous` on port `8075` and we can collect all the files:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/868cd438-ba69-4438-923e-76141710a56c)

We get the first flag in `flag-1-of-4.txt`. Now we look at the `flag-2-of-4.sh` and we see this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/22edd2e1-1654-499a-9f40-88bbbdb74f5e)

This means that it is stored in the environment variable of the machine. So if we can run `echo $FLAG2`, we could get the flag.

# Foothold

As we can see, there is `Nano` and `Vim` on ports `8095` and `8085`???? What is that ???
We know that we can run command via those editors. Lets connect to vim using the following command:

```bash
telnet IP 8085
```

We now have access to `Vim` running on the server:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a41e0119-5710-4401-97ad-f3c81fbb639f)

We can recover the second flag by running the command:

```bash
:echo $FLAG2
```

This prints us the flag in `Vim`.

Now I want a shell on the machine. But when I try to execute `:!sh` I get the following error:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/08b655ac-58af-41fb-928e-ef7348367c98)

We can use `Nano` or `Vim` as an `ls` command. In nano, we just need to press `CTRL+R` followed by `CTRL+T` and we can browse every file/directory on the server:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2a35d0aa-84e3-4e71-959c-8014413456f0)

`Vim` can also do that but it is less pretty and less easy to use. To do so in `Vim`, will use the `python3` interpreter incorporated in it, but we will talk about it a bit later.

After roaming around with nano, I found some files that look strange like `/usr/frosty/sh` or `/etc/passwd` that is writeable. What is strange is that there is no binary in the `/bin` and `/usr/bin` folder and there are no default binaries like `sh`, `ls`, `find` or `chmod` in `/usr/sbin`... Strange...

But without a shell I won't be able to do anything interesting, so I need to find a way to create my own.

When looking at the `Vim` version (`:version`), we see that there is `python3` included in `Vim`. That's cool because it is not installed on the machine so we may be able to run some scripts.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d8f9d4cc-e80f-46fd-84d9-c56dc297d0ed)

We can now run `python3` commands like the one below, but it would be better if we could use all the binary we want:

```bash
python3 import os; print(os.listdir("/tmp/"))
```

# Getting a shell

I uploaded via the `FTP` all these binaries `sh, ls, id, cat, grep, find, mv, cp, chmod, mkdir, dirname, sed, touch, head, sleep, capsh`. This will allow me to test a lot of commands. After uploading all these commands in the `FTP`, I need to move them to the `/tmp` folder because we don't have rights on the `/tmp/ftp` one. To move all those files, I used the `python3` command:

```bash
python3 import shutil; shutil.copyfile("/tmp/ftp/sh", "/tmp/sh"); shutil.copyfile("/tmp/ftp/ls", "/tmp/ls"); shutil.copyfile("/tmp/ftp/id", "/tmp/id"); shutil.copyfile("/tmp/ftp/cat", "/tmp/cat"); shutil.copyfile("/tmp/ftp/grep", "/tmp/grep"); shutil.copyfile("/tmp/ftp/find", "/tmp/find"); shutil.copyfile("/tmp/ftp/mv", "/tmp/mv"); shutil.copyfile("/tmp/ftp/cp", "/tmp/cp"); shutil.copyfile("/tmp/ftp/chmod", "/tmp/chmod"); shutil.copyfile("/tmp/ftp/mkdir", "/tmp/mkdir"); shutil.copyfile("/tmp/ftp/dirname", "/tmp/dirname"); shutil.copyfile("/tmp/ftp/sed", "/tmp/sed"); shutil.copyfile("/tmp/ftp/touch", "/tmp/touch"); shutil.copyfile("/tmp/ftp/head", "/tmp/head"); shutil.copyfile("/tmp/ftp/sleep", "/tmp/sleep"); shutil.copyfile("/tmp/ftp/capsh", "/tmp/capsh")
```

With all my files in the `/tmp` folder, I now need to give them the execution right:

```bash
python3 import os;os.chmod("/tmp/sh", 0o777) ;os.chmod("/tmp/ls", 0o777) ;os.chmod("/tmp/id", 0o777) ;os.chmod("/tmp/cat", 0o777) ;os.chmod("/tmp/grep", 0o777) ;os.chmod("/tmp/find", 0o777) ;os.chmod("/tmp/mv", 0o777) ;os.chmod("/tmp/cp", 0o777) ;os.chmod("/tmp/chmod", 0o777)  ;os.chmod("/tmp/mkdir", 0o777) ;os.chmod("/tmp/dirname", 0o777) ;os.chmod("/tmp/sed", 0o777) ;os.chmod("/tmp/touch", 0o777) ;os.chmod("/tmp/head", 0o777) ;os.chmod("/tmp/sleep", 0o777);os.chmod("/tmp/capsh", 0o777);os.chmod("/tmp/docker", 0o777)
```

> Note the use of the python `chmod`. We are not setting the value as `777` but as `0o777` to use the octal representation of the rights.
{: .prompt-tip}

Now we should be able to run `!/tmp/sh`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a83a2aef-6ec3-481f-bef0-d5485a352484)

# Privilege Escalation

Now, we can try to privesc. Unfortunately, tools like `Linpeas` won't work because it needs a lot of binaries that are not on this machine... But as we saw earlier, there is a `/usr/frosty/sh` file that caught our attention. If we look at the file, it is empty:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4ea233ed-16c3-49fc-9660-db52dbb1cda0)

What if we put our `/tmp/sh` in this file ? Well it doesn't change anything :

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3a3dc805-9a0c-46c7-a833-cb8420ef72ce)

Or maybe it changed something we didn't think was directly linked to it ? If we get back to our nmap scan, we see that there is a port `8065` opened that we didn't use for now. And we didn't use it because when we tried to connect to it we got some errors, but now that we changed this `sh` binary, we get a beautiful root shell:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a14e551c-55c0-4f82-9466-e75ca204b747)

And we get the root flag that is the 3rd one:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1dde6316-dd5b-4956-b4b9-85dd6a821029)

# Escaping the whale

As we can see, we have a `.dockerenv`, that is a file generally located in docker containers. This means that we need to escape the container to be able to get the last flag.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a468dcb8-98ff-4673-837a-bc1fa38fddd3)

To escape a container, the easiest way is to have a volume that is linked to our container from the host and to mount the host file system in our docker. To do so, we need to do the following:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/aad366b0-2008-451f-b28d-99d33f867f27)

The `cat /proc/cmdline` allows us to recover the `UUID` or, in this case, the `PARTUUID`. This value allows us to get the path to the underlying host filesystem.

> In a Docker container, the concept of UUID (Universally Unique Identifier) or PARTUUID (Partition UUID) is typically associated with the host system rather than the container itself. Docker containers share the kernel of the host system and do not have their own dedicated kernel or access to low-level hardware details.
{: .prompt-info}

> You can find more information on how to escape a docker container via the [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation) blog.
{: .prompt-tip}

We now run the `findfs` command on this `PARTUUID` to recover the underlying host filesystem:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/cc69f6b2-698a-4c12-8434-c8ec70add4d8)

But now, we have a problem. There is no `mount` binary on this system and I can't use the `mount` binary from my kali since it is a `Debian` system and not an `Ubuntu` one. So what I did, and it may be hardcore just for this task, but I went on my `Ubuntu` VM sent it to my `Kali` and uploaded it via the `FTP` :)

As we  can see, we have successfully mounted the volume to our `/mnt-test` folder and have now access to the host:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/91498eef-172b-429a-acb2-e5da06746417)

We can go into the `/mnt-test/root` folder and recover the final flag and the `yetikey3.txt`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3ef203b6-b9b4-4431-a1ca-be7d8860483c)
