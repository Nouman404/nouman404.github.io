---
layout: post
title: 'HTB | Crocodile'
date: 2022-02-27
permalink: /htb/crocodile/
---

# [](#header-4)Connection

We will connect with ftp and the user **anonymous**. There we can download two files, with users and passwords.
{% highlight plain %}
$ ftp 10.129.122.93
{% endhighlight %}
With **gobuster** we can check for others files in the webpage, and we can see a **login.php**:
{% highlight plain %}
$ gobuster dir -u http://10.129.122.93/ -w /usr/share/wordlists/directory-list-2.3-small.txt -x php
{% endhighlight %}


# [](#header-4)Flag

We will have now this page:
<img src="./img/Screenshot_2.jpg" weight="50%" />
With the **admin** login we can enter and get our flag.
