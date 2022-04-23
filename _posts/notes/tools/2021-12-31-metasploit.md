---
layout: post
title: 'Notes | Metasploit'
date: 2021-12-31
permalink: /notes/tools/metasploit/
---

# [](#header-4)Run metasploit

To run Metasploit we need to:
{% highlight plain %}
@ update msf
@ postgresql start
@ msfdb.init
@ msfconsole
{% endhighlight %}

There are other basic commands like:
{% highlight plain %}
@ db_status
{% endhighlight %}

# [](#header-4)Basic use

We have the next commands to move in metasploit:
{% highlight plain %}
> back
> exit
{% endhighlight %}

If we want to search an exploit:
{% highlight plain %}
> search ...
{% endhighlight %}
And then add the service we want to search and the version.

When we find the exploit we need to run it:
{% highlight plain %}
> use ...
{% endhighlight %}
Select one from the search result.

Then we need to configure the exploit:
{% highlight plain %}
/exploit> options
/exploit> info
{% endhighlight %}
Now we need to check what is the exploit lacking and add it, for example:
{% highlight plain %}
/exploit> set rhost 192.168.0.1
/exploit> unset rhost
{% endhighlight %}

Then we need to run the exploit, there are two options:
{% highlight plain %}
/exploit> run
/exploit> exploit
{% endhighlight %}

# [](#header-4)Payload generator

If we want to create or own payload we need to use the msfvenom tool (include in metasploit). 
{% highlight plain %}
> msfvenom ...
{% endhighlight %}
These are the options we have:
- **-p** select the payload
- **-e** encode
- **-i** encode X times
- **-f** extensiones we want to create it (linux: elf, win: exe)
And at the end **> name.exe** to create into a file.

# [](#header-4)Privilage escalation

As easy as:
{% highlight plain %}
> use priv
/priv> getsystem
/priv> getuid
{% endhighlight %}
We can see the options of **getsystem** with **-h**.
