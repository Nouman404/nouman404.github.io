---
title: CTFs | CTF_INSA_2024 | Web | MegaUpload
author: BatBato
date: 2024-02-05
categories:
  - CTFs
  - CTF_INSA_2024
  - Web
tags:
  - upload
  - ssh
permalink: /CTFs/CTF_INSA_2024/Web/MegaUpload/
---
# MegaUpload

![[mega_sujet.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_sujet.png)


## 1 - Bypass upload filter

For this challenge, we have a website where we can upload files. But the upload is limited to image files (.jpg) and text files (.txt), other files return an error:

![[mega_denied.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_denied.png)
Each uploaded files are in `/uploads/` directory. We can see that if we run a `Gobuster` on the website.

We need to bypass the filter extension, for that, we can try to upload a `.htaccess` file with a new rule read by the web server.

![[mega_htaccess.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_htaccess.png)
> This rule allows web server to run PHP code inside `.jpg` files.
{: .prompt-tip}

> [Here](https://thibaud-robin.fr/articles/bypass-filter-upload/) is a blog talking more in detail about bypass filter upload.  
{: .prompt-info}

And it works!

![[mega_success.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_success.png)

With this rule, we can now upload and execute arbitrary PHP code inside `.jpg` files and, with this [script](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php), get a reverse shell:

![[mega_rs_upload.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_rs_upload.png)

## 2 - Become another user

First we get a shell and beautify it:

![[mega_rs_id.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_rs_id.png)

 We can read the `/etc/passwd` to check all existant user.

![[mega_passwd.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_passwd.png)

There is a user named `debian`, so we go see what it has in his home directory and find a readable ssh private key:

![[mega_id_rsa.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_id_rsa.png)

We try to connect with the ssh key to `debian` user but ssh asks for a password:

![[mega_passwd_ssh.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_passwd_ssh.png)

This means the key is encrypted, so we have to find the key password. For that, we download the key on our kali and use [ssh2john](https://www.kali.org/tools/john/#ssh2john) to extract the hash in a john format. And now we can use john to crack the hash using the `rockyou` word list.

![[mega_pwd_ssh.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_pwd_ssh.png)

Fine, we can connect to `debian` user:

![[mega_connexion.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_connexion.png)

## 3 - Become root

We try `sudo -l` to see which command can execute `debian`:

![[mega_sudo_l.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_sudo_l.png)

`debian` can execute `tar` with no password as any user (ex: root), we search on [gtfobin](https://gtfobins.github.io/) the `tar` command that can gives us a root shell:

![[mega_gtfobins.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_gtfobins.png)

We execute the given tar command and as you can see, we get a root shell:

![[mega_sudo_cmd.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_sudo_cmd.png)

And the flag is inside the `/root` directory.

![[mega_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/CTF_INSA_2024/photos/mega_flag.png)

