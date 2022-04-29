---
layout: post
title: 'Notes | Linux Forensic'
permalink: /notes/forensic/linux/
---


# List installed package
{% highlight bash %}
dpkg-guest -l
apt list -i
{% endhighlight %}


# Privilage users
{% highlight bash %}
/etc/sudoers
{% endhighlight %}


# Sign
{% highlight bash %}
sha256sum
{% endhighlight %}


# Main files
{% highlight bash %}
shadow
passwd
lastlog
bootlog
auth.log
{% endhighlight %}


# Search files with permissions
{% highlight bash %}
find -type f - perm -444
{% endhighlight %}
It can be change f to d, and 444 to other permission.


# History
With the command: diff you can compare and earlier version.
{% highlight bash %}
cat ~/.bash_history
{% endhighlight %}


# Some commands
- dig
- netstat
- ip addr
- ifconfig
- dmesg
- more

