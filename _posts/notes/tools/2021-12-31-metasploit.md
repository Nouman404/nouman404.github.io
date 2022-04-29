---
layout: post
title: 'Notes | Metasploit'
permalink: /notes/tools/metasploit/
---

# Run metasploit

To run Metasploit we need to:
{% highlight bash %}
@ update msf
@ postgresql start
@ msfdb.init
@ msfconsole
{% endhighlight %}

There are other basic commands like:
{% highlight bash %}
@ db_status
{% endhighlight %}

# Basic use

We have the next commands to move in metasploit:
{% highlight bash %}
> back
> exit
{% endhighlight %}

If we want to search an exploit:
{% highlight bash %}
> search ...
{% endhighlight %}
And then add the service we want to search and the version.

When we find the exploit we need to run it:
{% highlight bash %}
> use ...
{% endhighlight %}
Select one from the search result.

Then we need to configure the exploit:
{% highlight bash %}
/exploit> options
/exploit> info
{% endhighlight %}
Now we need to check what is the exploit lacking and add it, for example:
{% highlight bash %}
/exploit> set rhost 192.168.0.1
/exploit> unset rhost
{% endhighlight %}

Then we need to run the exploit, there are two options:
{% highlight bash %}
/exploit> run
/exploit> exploit
{% endhighlight %}

# Payload generator

If we want to create or own payload we need to use the msfvenom tool (include in metasploit). 
{% highlight bash %}
> msfvenom ...
{% endhighlight %}
These are the options we have:
- **-p** select the payload
- **-e** encode
- **-i** encode X times
- **-f** extensiones we want to create it (linux: elf, win: exe)
And at the end **> name.exe** to create into a file.

# Privilage escalation

As easy as:
{% highlight bash %}
> use priv
/priv> getsystem
/priv> getuid
{% endhighlight %}
We can see the options of **getsystem** with **-h**.
