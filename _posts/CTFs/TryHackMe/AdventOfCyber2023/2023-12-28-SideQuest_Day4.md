---
title: CTFs | TryHackMe | AdventOfCyber2023 | Side Quest Day 4
author: BatBato
date: 2023-12-28
categories: [CTFs, TryHackMe, AdventOfCyber2023]
tags: [Flask, Werkzeug, SQLi, Side Quest, THM]
permalink: /CTFs/TryHackMe/AdventOfCyber2023/SideQuest_Day4
---

# Side Quest - Day 4

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/0107442e-812e-4859-ac36-16cb7266c920)

In this challenge, we need to become root, so let's start with the enumeration phase.

# Enumeration

As we can see, we only have two open ports:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3038a085-f8f9-4331-a4af-d7edb33320da)

We go see the website and notice that we can download the three images that we see:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d0940e93-15c6-4a69-8853-0b179bafb3ff)

If we look carfully at the source code, we can see what looks like an SQLi:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/806f1857-083e-4329-8325-ce7c0201e2de)

# SQLi

We try to reach the image with `id=0` and we get this beautiful error from `Flask`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c6d6428b-74dd-405b-82f7-f571cb9539df)

This means that we should have a `Werkzeug` console at `/console`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/cdea4aab-568f-41bd-97f6-fae7d215f712)


This console is protected with a PIN but there is a technique to recover it. I won't go into too much detail on how I generated it but you can read my write-up of a previous CTF [here](https://nouman404.github.io/CTFs/HackTheBox/Machines/Agile) to have a better understanding.

So, let's see if we can leverage our SQLi to get an LFI and be able to read interesting files on the server:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/44b00f5f-b62f-434c-bf72-c9d784bedaa8)

# LFI

The payload `id=0' union select all concat('file:///etc/passwd')-- -` allows us to download the `/etc/passwd` file:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c97e40aa-5ada-468f-8415-f30d7a928316)

I now used [this](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/TryHackMe/AdventOfCyber2023/getFiles.sh) script to download all the necessary files to recover the pin.

Thanks to this I know that the user is `mcskidy`, I have the machine ID, the `node UUID`, the `mod name` is `flask.app` and the `app name` is `Flask`. The path of the app is given in the error (`/home/mcskidy/.local/lib/python3.8/site-packages/flask/app.py`).

We just have to get the hexadecimal value of the `node UUID`. Here we have `02:77:eb:08:09:ed` which is `2714067536365` in decimal. I now use [my script](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/TryHackMe/AdventOfCyber2023/pin_generator.py) to generate the PIN:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a3291eba-3549-4cc8-a03c-88c3918db5de)

> Note that I put the `cron.service` (available in the `cgroup` file). But for some reason, sometimes it worked with it appended to the machine ID and sometimes without. So be aware of that.
{: .prompt-warning}

# RCE

I now head back to the console and get the access:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a3d50184-07dd-4625-bc73-b6e394a540b0)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c2872e7e-6164-418c-b413-5ee961c55043)

Now we can have RCE running commands like `__import__('os').popen('whoami"').read()` but we can also use it to get a reverse shell:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6b20b5a1-3eaf-4a3d-8710-5724116d1fca)

We now have access to the server and can recover the `user.txt` flag in our home directory:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c4e941a5-384b-4039-85f3-f48d978138bc)

As we know from the previous steps, the app is in our home directory so we can now have full access to the code:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/fdb2872e-e916-47cd-9e46-4d5ee5d5bb78)

We notice a `.git` folder. We can search for previous interesting commits:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/61776b44-431b-4426-8391-a7fc125b2777)

Let's check the difference from the code we have and this one:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/87917696-4032-4072-985a-d68e994fd2d6)

As we can see, we have a password that was changed. Let's try to use it for our user:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4b30336a-78c0-423e-92e2-7e4debe41d76)

# Privilege Escalation

So the deleted password was the one for the user `mcskidy`. Now we can check the `/opt/check.sh` script to try getting a root shell:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6573a165-14a7-4500-9303-2ab639dba23a)

As we can see, the `/opt/check.sh` uses its own `.bashrc` file and start the program from our home directory. As we saw on the `sudo -l` command, our home directory is in the `secure_path`. This means that when we run the script as the `root` user, we will have our home directory in the path. So if we have our reverse shell in our home directory, it will be loaded.

But the source code of the `check.sh` script has only absolute path for the different binaries. But if we look at the `/opt/.bashrc` file, we can see something that isn't present in the one of `mkscidy`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9dbb6cf8-1d12-423e-ade8-86e745930fb6)

Because the `#` is a comment in bash, this means that we only have to understand what comes before it. `enable -n` means that it will disable the `[` command. This `[` is present in our `check.sh` file. This means that the `[` will not be interpreted as part of the `if` statement. So we could try to have a reverse shell in a file called `[`.

> For more information about the `enable -n` you can check out [this blog](https://linuxsimply.com/enable-command-in-linux/#Example_2_Disable_a_Built-in_Command_And_Print_All_the_Disabled_Built-in_Commands).
{: .prompt-info}

So we just have to create our reverse shell into our home directory and we have it ready to go:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/31634fe5-f318-4733-a151-a6956573c61c)

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4b71343a-dfcc-48cb-937a-3067d564514f)

And voilà, we have our last flag and the yeti's key:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2131877e-c7f3-4794-8795-eed9ef33c869)




