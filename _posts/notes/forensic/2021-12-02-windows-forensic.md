---
layout: post
title: 'Notes | Windows Forensic'
date: 2021-12-02
permalink: /notes/forensic/windows/
---

First of all, we need to use a cmd (as admin).


# [](#header-4)Cookies

With this we can show all the cookies in the system.
{% highlight plain %}
dir cookie*.* /s/p
{% endhighlight %}
Also, we can use the extension SQLite Manager to see it.

- /s: enumerate
- /p: pagination


# [](#header-4)History

If we want to list all the history (from web browsers).
{% highlight plain %}
dir index.dat /s/p/a
{% endhighlight %}

- /a: attributes


# [](#header-4)Executed app

If we want to list all the executed apps.
{% highlight plain %}
dir *.pf /s/a/p
{% endhighlight %}


# [](#header-4)Thumbnail

If we want to see all the thumb in the system.
{% highlight plain %}
dir thumb*.db /s/p/a
{% endhighlight %}


# [](#header-4)History

If we want to list all the history (from web browsers).
{% highlight plain %}
dir index.dat /s/p/a
{% endhighlight %}


# [](#header-4)List files

Order the files from modification date.
{% highlight plain %}
dir /t:w /a /s /o:d
{% endhighlight %}
Order the files from last access.
{% highlight plain %}
dir /t:a /a /s /o:d
{% endhighlight %}

- /t:w type
- /o:d date

# [](#header-4)Tools

- [MUI cache](https://www.nirsoft.net/utils/muicache_view.html): list all the programs that have write a key code.
- [dumpIt](https://dumpit.soft32.com/): create a memory dump of the RAM.
- [PsTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools): see all logged users.
- [WebBrowserPassView](https://www.nirsoft.net/utils/web_browser_password.html): find browser's password.
- [Volatility](https://www.volatilityfoundation.org/releases): memory dump.

