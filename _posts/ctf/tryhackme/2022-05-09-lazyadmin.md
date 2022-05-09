---
layout: post
title: 'TryHackMe | LazyAdmin'
permalink: /ctf/thm/lazyadmin/
---

# Enumeration
We start a nmap at the IP.
{% highlight mysql %}
Nmap scan report for 10.10.46.20
Host is up (0.076s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
{% endhighlight %}

The website has a default Apache index, so we can start fuzzing it:
{% highlight mysql %}
> dirsearch -r -u http://10.10.253.214/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -e php,txt,html -f
{% endhighlight %}

We can see there are a **/content/** site with a CMS.

The page told us about other parts, we can fuzzing it:
{% highlight mysql %}
> gobuster dir -u http://10.10.46.20/content/ -w /usr/share/wordlists/dirb/common.txt
    /as                   (Status: 301) [Size: 315] [--> http://10.10.46.20/content/as/]  
    /attachment           (Status: 301) [Size: 323] [--> http://10.10.46.20/content/attachment/]
    /inc                  (Status: 301) [Size: 316] [--> http://10.10.46.20/content/inc/]  
{% endhighlight %}


# Explotation
Inside **/inc/** we can see many files.
Inside the file **mysql_bakup_20191129023059-1.5.1.sql** we can get two users (**admin** and **manager**) and a hash with the password: **Password123**.

We can try this credentials in the **/as/**, where we have a login.
With **searchsploit** we can search for the version of the SweetRice:
{% highlight mysql %}
> searchsploit -m php/webapps/40716.py
{% endhighlight %}
We can use it to upload a reverse shell and get access to the machine.


# Privilege Escalation
We can check our privileges with:
{% highlight mysql %}
> sudo -l
{% endhighlight %}

We can see that we can use a pl file. We can copy it to the **/tmp/** and change the content with a reverse shell.