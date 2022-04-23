---
layout: post
title: 'Notes | Linux Forensic'
date: 2021-12-08
permalink: /notes/forensic/linux/
---


# [](#header-4)List installed package

{% highlight plain %}
dpkg-guest -l
apt list -i
{% endhighlight %}


# [](#header-4)Privilage users

{% highlight plain %}
/etc/sudoers
{% endhighlight %}


# [](#header-4)Sign

{% highlight plain %}
sha256sum
{% endhighlight %}


# [](#header-4)Main files

{% highlight plain %}
shadow
passwd
lastlog
bootlog
auth.log
{% endhighlight %}


# [](#header-4)Search files with permissions

{% highlight plain %}
find -type f - perm -444
{% endhighlight %}
It can be change f to d, and 444 to other permission.


# [](#header-4)History

With the command: diff you can compare and earlier version.
{% highlight plain %}
cat ~/.bash_history
{% endhighlight %}


# [](#header-4)Some commands

- dig
- netstat
- ip addr
- ifconfig
- dmesg
- more

