---
layout: post
title: 'HTB | Appointment'
date: 2022-02-27
permalink: /htb/appointment/
---

# [](#header-4)Connection

We can search the IP in the navbar to get a website.
![login](../../../img/htb/starting-point/Screenshot_1.jpg)

We will try a basic sql-injection, login with the user:
{% highlight plain %}
' or '1'='1' #
{% endhighlight %}
For the password we just need to write a letter.

# [](#header-4)Flag

The flag will be in front of us.
