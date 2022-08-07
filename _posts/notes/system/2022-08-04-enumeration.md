---
title: Notes | Enumeration
author: Zeropio
date: 2022-08-04
categories: [Notes, System]
tags: [enumeration]
permalink: /notes/system/enumeration
---

**Enumeration** is a widely used term in cyber security. It stands for information gathering using active and passive methods. Information can be gathered from domains, IP addresses, accessible services, and many other sources. Once we have identified targets in our client's infrastructure, we need to examine the individual services and protocols. In most cases, these are services that enable communication between customers, the infrastructure, the administration, and the employees.

Our goal is not to get at the systems but to find all the ways to get there.

The enumeration principles are based on some questions:
- What can we see?
- What reasons can we have for seeing it?
- What image does what we see create for us?
- What do we gain from it?
- How can we use it?
- What can we not see?
- What reasons can there be that we do not see?
- What image results for us from what we do not see?

These are the three principles for the enumeration:
1. There is more than meets the eye. Consider all points of view.
2. Distinguish between what we see and what we do not see.
3. There are always ways to gain more information. Understand the target.

Complex processes must have a standardized methodology that helps us keep our bearings and avoid omitting any aspects by mistake. Especially with the variety of cases that the target systems can offer us, it is almost unpredictable how our approach should be designed. The whole enumeration process is divided into three different levels:
- **Infrastructure-based** enumeration
- **Host-based** enumeration
- **OS-based** enumeration

![Enumeration methodology](/assets/img/notes/system/enum-method3.png)

Consider these lines as some kind of obstacle. These layers are:

| **Layer**    | **Description**    | **Information Categories**    |
|---------------- | --------------- | --------------- |
| **Internet Presence** | Identification of internet presence and externally accessible infrastructure | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures |
| **Gateway** | Identify the possible security measures to protect the company's external and internal infrastructure | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare |
| **Accessible Services** | Identify accessible interfaces and services that are hosted externally or internally | Service Type, Functionality, Configuration, Port, Version, Interface |
| **Processes** | Identify the internal processes, sources, and destinations associated with the services | PID, Proceed Data, Tasks, Source, Destination |
| **Privileges** | Identification of the internal permissions and privileges to the accessible services | Groups, Users, Permissions, Restrictions, Environment |
| **OS Setup** | Identification of the internal components and systems setup | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files |

The interesting and very common fact is that not all the gaps we find can lead us inside. 

### Layer No.1: Internet Presence 

The goal of this layer is to identify all possible target systems and interfaces that can be tested. 

### Layer No.2: Gateway 

The goal is to understand what we are dealing with and what we have to watch out for.

### Layer No.3: Accessible Services 

This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.

### Layer No.4: Processes 

The goal here is to understand these factors and identify the dependencies between them. 

### Layer No.5: Privileges 

It is crucial to identify these and understand what is and is not possible with these privileges.

### Layer No.6: OS Setup 

The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.

---

# FTP 

In an FTP connection, two channels are opened. First, the client and server establish a control channel through **TCP port 21**. The client sends commands to the server, and the server returns status codes. Then both communication participants can establish the data channel via **TCP port 20**. This channel is used exclusively for data transmission, and the protocol watches for errors during this process.

**Trivial File Transfer Protocol** (**TFTP**) is simpler than FTP and performs file transfers between client and server processes. However, it does not provide user authentication and other valuable features supported by FTP. In addition, while FTP uses TCP, TFTP uses UDP, making it an unreliable protocol and causing it to use UDP-assisted application layer recovery.

One of the most used FTP servers on Linux-based distributions is **vsFTPd**. The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`{: .filepath}, and some settings are already predefined by default. With vsFTPd, the optional settings that can be added to the configuration file for the anonymous login look like this:

| **Setting**  | **Description**    |
|--------------- | --------------- |
| `anonymous_enable=YES` | Allowing anonymous login | 
| `anon_upload_enable=YES` | Allowing anonymous to upload files |
| `anon_mkdir_write_enable=YES` | Allowing anonymous to create new directories |
| `no_anon_password=YES` | Don't ask anonymous for password |
| `anon_root=/home/username/ftp` | Directory for anonymous |
| `write_enable=YES` | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE |

To login as a anonymous:
```console
zero@pio$ ftp <TARGET> 

...
Name (<TARGET>:zero): anonymous 

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> 
```

To get the first overview of the server's settings, we can use the following command:
```console
ftp> status 

Connected to <TARGET>.
No proxy connection.
Connecting using address family: any.
Mode: stream; Type: binary; Form: non-print; Structure: file
Verbose: on; Bell: off; Prompting: on; Globbing: on
Store unique: off; Receive unique: off
Case: off; CR stripping: on
Quote control characters: on
Ntrans: off
Nmap: off
Hash mark printing: off; Use of PORT cmds: on
Tick counter printing: off
```

Some commands should be used occasionally, as these will make the server show us more information that we can use for our purposes. These commands include `debug` and `trace`:
```console
ftp> debug

Debugging on (debug=1).


ftp> trace

Packet tracing on.


ftp> ls

---> PORT 10,10,14,4,188,195
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
...
```

If the `hide_ids=YES` setting is present, the UID and GUID representation of the service will be overwritten, making it more difficult for us to identify with which rights these files are written and uploaded:
```console
ftp> ls

---> TYPE A
200 Switching to ASCII mode.
ftp: setsockopt (ignored): Permission denied
---> PORT 10,10,14,4,223,101
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
...
```

This setting is a security feature to prevent local usernames from being revealed. With the usernames, we could attack the services like FTP and SSH and many others with a brute-force attack in theory. Another helpful setting we can use for our purposes is the `ls_recurse_enable=YES`:
```console
ftp> ls -R

---> PORT 10,10,14,4,222,149
200 PORT command successful. Consider using PASV.
---> LIST -R
150 Here comes the directory listing.
...
```

All the NSE scripts are located in ` /usr/share/nmap/scripts/`{: .filepath}:
```console
zero@pio$ find / -type f -name ftp* 2>/dev/null | grep scripts

/usr/share/nmap/scripts/ftp-syst.nse
/usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-vuln-cve2010-4221.nse
/usr/share/nmap/scripts/ftp-proftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-bounce.nse
/usr/share/nmap/scripts/ftp-libopie.nse
/usr/share/nmap/scripts/ftp-anon.nse
/usr/share/nmap/scripts/ftp-brute.nse
```

We can run the default scripts (`-sC`) tracking them:
```console
zero@pio$ sudo nmap -sV -p<PORT> -sC -A <TARGET> --script-trace
```

Also, we can use the **Banner Grabbing**:
```console
zero@pio$ nc -nv <TARGET> <PORT>
zero@pio$ telnet <TARGET> <PORT>
```

It looks slightly different if the FTP server runs with TLS/SSL encryption. Because then we need a client that can handle TLS/SSL. For this, we can use the client openssl and communicate with the FTP server. The good thing about using openssl is that we can see the SSL certificate, which can also be helpful.
```console
zero@pio$ openssl s_client -connect <TARGET>:<PORT> -starttls ftp
```

---

# SMB 

An SMB server can provide arbitrary parts of its local file system as shares. Therefore the hierarchy visible to a client is partially independent of the structure on the server. Access rights are defined by **Access Control Lists** (**ACL**). They can be controlled in a fine-grained manner based on attributes such as **execute**, **read**, and **full access** for individual users or user groups. There is an alternative variant to the SMB server, called **Samba**, developed for Unix-based operating system. Samba implements the **Common Internet File System** (**CIFS**) network protocol. So when we pass SMB commands over Samba to an older NetBIOS service, it usually connects to the Samba server over TCP ports **137**, **138**, **139**, but CIFS uses TCP port **445** only. 

The config file is `/etc/samba/smb.conf`{: .filepath}.

Some of the above settings already bring some sensitive options:

| **Setting**   | **Description**    |
|--------------- | --------------- |
| `browseable = yes` | 	Allow listing available shares in the current share | 
| `read only = no` | Forbid the creation and modification of files | 
| `writable = yes` | Allow users to create and modify files |
| `guest ok = yes` | Allow connecting to the service without using a password |
| `enable privileges = yes` | Honor privileges assigned to specific SID |
| `create mask = 0777` | What permissions must be assigned to the newly created files |
| `directory mask = 0777` | What permissions must be assigned to the newly created directories |
| `logon script = script.sh` | What script needs to be executed on the user's login |
| `magic script = script.sh` | Which script should be executed when the script gets closed |
| `magic output = script.out` | Where the output of the magic script needs to be stored |

Let's use the following config file as an example:
```bash
...
[notes]
	comment = CheckIT
	path = /mnt/notes/

	browseable = yes
	read only = no
	writable = yes
	guest ok = yes

	enable privileges = yes
	create mask = 0777
	directory mask = 0777
...
```

Now we can display a list (`-L`) of the server's shares with the `smbclient` command from our host. We use the so-called null session (`-N`), which is **anonymous** access without the input of existing users or valid passwords:
```console
zero@pio$ smbclient -N -L //<TARGET>

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        home            Disk      Home Samba
        dev             Disk      DEVenv
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled -- no workgroup available
```

Take note that `print$` and an `IPC$` are already included by default in the basic setting. We can try to connect with one or the folders:
```console
zero@pio$ smbclient //<TARGET>/notes 

Enter WORKGROUP\<username>'s password: 
Anonymous login successful
Try "help" to get a list of possible commands.


smb: \>
```

From the administrative point of view, we can check these connections using `smbstatus`:
```console
root@samba:~# smbstatus
```

Nmap also has many options and NSE scripts that can help us examine the target's SMB service more closely and get more information. The downside, however, is that these scans can take a long time.
```console
zero@pio$ sudo nmap <TARGET> -sV -sC -p<PORTS>
```

One useful tool for enumerate is **rpcclient**. The **Remote Procedure Call** (**RPC**) is a concept and, therefore, also a central tool to realize operational and work-sharing structures in networks and client-server architectures.
```console
zero@pio$ rpcclient -U "" <TARGET>
```

The rpcclient offers us many different requests with which we can execute specific functions on the SMB server to get information:

| **Query**   | **Description**    |
|--------------- | --------------- |
| `srvinfo` | Server information | 
| `enumdomains` | Enumerate all domains that are deployed in the network | 
| `querydominfo` | Provides domain, server, and user information of deployed domains |
| `netshareenumall` | Enumerates all available shares |
| `netsharegetinfo <SHARE>` | Provides information about a specific share |
| `enumdomusers` | Enumerates all domain users |
| `queryuser <RID>` | Provides information about a specific user |
| `querygroup <RID>` |  Provides information about a specific group |

```console
rpcclient $> srvinfo

...

rpcclient $> netsharegetinfo notes
```

However, it can also happen that not all commands are available to us, and we have certain restrictions based on the user. We can use the rpcclient to brute force the RIDs to get information:
```console
zero@pio$ for i in $(seq 500 1100);do rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

The [samrdump.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/samrdump.py) from the **Impacket** can do the same.
```console
zero@pio$ samrdump.py <TARGET>
```

With the help of [SMBMap](https://github.com/ShawnDEvans/smbmap) or [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) we can get a better enumeration.
```console
zero@pio$ smbmap -H <TARGET>
```

```console
zero@pio$ crackmapexec smb <TARGET> --shares -u '' -p ''
```

Also, [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) automates many of the queries (but not all):
```console
zero@pio$ ./enum4linux-ng.py <TARGET> -A
```

---

# NFS 

 A significant advantage of **NFSv4** over its predecessors is that only one UDP or TCP port **2049** is used to run the service, which simplifies the use of the protocol across firewalls. NFS is based on the **Open Network Computing Remote Procedure Call** (**ONC-RPC**/**SUN-RPC**) protocol exposed on TCP and UDP ports **111**, which uses **External Data Representation** (**XDR**) for the system-independent exchange of data. The NFS protocol has **no mechanism for authentication** or authorization. Instead, authentication is completely shifted to the RPC protocol's options. The most common authentication is via UNIX UID/GID and group memberships.

The config file is located in `/etc/exports`{: .filepath}. Even with NFS, some settings can be dangerous for the company and its infrastructure. Here are some of them listed:
:
| **Option**   | **Description**    |
|--------------- | --------------- |
| `rw` | Read and write permissions |
| `insecure` | Ports above 1024 will be used |
| `nohide` | If another file system was mounted below an exported directory, this directory is exported by its own exports entry |
| `no_root_squash` | All files created by root are kept with the UID/GID 0 |

When footprinting NFS, the TCP ports **111** and **2049** are essential:
```console
zero@pio$ sudo nmap <TARGET> -p 111,2049 -sV -sC
```

The rpcinfo NSE script retrieves a list of all currently running RPC services, their names and descriptions, and the ports they use. These can then show us, for example, the contents of the share and its stats.
```console
zero@pio$ sudo nmap --script nfs* <TARGET> -sV -p 111,2049
```

Once we have discovered such an NFS service, we can mount it on our local machine. Once mounted, we can navigate it and view the contents just like our local system:
```console
zero@pio$ showmount -e <TARGET>
zero@pio$ mkdir target-NFS 
zero@pio$ mount -t nfs <TARGET>:/ ./target-NFS/ -o nolock
```

Now, we can see the usernames and group names:
```console
zero@pio$ ls -l /mnt/nfs/
```

Or their UIDs and GUIDs:
```console
zero@pio$ ls -n /mnt/nfs/
```

---

# DNS 

There are several types of DNS servers that are used worldwide:

| **Server Type**   | **Description**    |
|--------------- | --------------- |
| DNS Root Server | The root servers of the DNS are responsible for the top-level domains (TLD) |
| Authoritative Nameserver | Authoritative name servers hold authority for a particular zone |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone |
| Caching DNS Server | Caching DNS servers cache information from other name servers for a specified period |
| Forwarding Server | Forwarding servers perform only one function: they forward DNS queries to another DNS server |
| Resolver | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router |

DNS is mainly unencrypted. By default, IT security professionals apply **DNS over TLS** (**DoT**) or **DNS over HTTPS** (**DoH**) here. In addition, the network protocol **NSCrypt** also encrypts the traffic between the computer and the name server.  A DNS query can therefore also be used, for example, to determine which computer serves as the e-mail server for the domain in question or what the domain's name servers are called. 

Different **DNS records** are used for the DNS queries:

| **DNS Record**   | **Description**    |
|--------------- | --------------- |
| `A` |	Returns an IPv4 address of the requested domain as a result |
| `AAAA` | Returns an IPv6 address of the requested domain |
| `MX` | Returns the responsible mail servers as a result |
| `NS` | Returns the DNS servers (nameservers) of the domain |
| `TXT` | This record can contain various information |
| `CNAME` | This record serves as an alias |
| `PTR` | It converts IP addresses into valid domain names |
| `SOA` | Provides information about the corresponding DNS zone |

All DNS servers work with three different types of configuration files:
- local DNS configuration files
- zone files
- reverse name resolution files

The DNS server **Bind9** is very often used on Linux-based distributions. Its local configuration file (`/etc/bind/named.conf`{: .filepath}) is roughly divided into two sections, firstly the options section for general settings and secondly the zone entries for the individual domains. The local configuration files are usually:
- `named.conf.local`{: .filepath}
- `named.conf.options`{: .filepath}
- `named.conf.log`{: .filepath}

This are some dangerous configuration:

| **Option**   | **Description**    |
|--------------- | --------------- |
| `allow-query` | Defines which hosts are allowed to send requests to the DNS server | 
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server |
| `allow-transfer` | Defines which hosts are allowed to receive zone transfers from the DNS server |
| `zone-statistics` | Collects statistical data of zones |

To enumerate it, check [here](https://zeropio.github.io/notes/web/enumeration).

---

# SMTP 

By default, SMTP servers accept connection requests on port **25**. However, newer SMTP servers also use other ports such as TCP port **587**. This port is used to receive mail from authenticated users/servers, usually using the STARTTLS command to switch the existing plaintext connection to an encrypted connection. SMTP works unencrypted without further measures and transmits all commands, data, or authentication information in plain text. To prevent unauthorized reading of data, the SMTP is used in conjunction with SSL/TLS encryption. Under certain circumstances, a server uses a port other than the standard TCP port **25** for the encrypted connection, for example, TCP port **465**.

You can found [here](https://serversmtp.com/smtp-error/) a list of the status code.

We can test this port with telnet. We can use the commands `HELO` or `EHLO` to test it:
```console
zero@pio$ telnet <TARGET> 25

...
220 ESMTP Server 

HELO mail1.<TARGET>

250 mail1.<TARGET>
```

The command `VRFY` can be used to enumerate existing users on the system.
```console
zero@pio$ telnet <TARGET> 25

...
VRFY root

252 2.0.0 root

VRFY aaaaaaaaaaaaaaaaaaaaaaaaaaaa

252 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

However, some protections can blocked it. We can test also the receive and send of emails:
```console
zero@pio$ telnet <TARGET> 25

...
220 ESMTP Server

MAIL FROM: <test@TARGET DOMAIN>

250 2.1.0 Ok

RCPT TO: <test2@TARGET DOMAIN> NOTIFY=success,failure

250 2.1.5 Ok 

DATA 

...

QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

Often, administrators have no overview of which IP ranges they have to allow. Therefore, they allow all IP addresses not to cause errors in the email traffic and thus not to disturb or unintentionally interrupt the communication with potential and current customers.
```bash
mynetworks = 0.0.0.0/0
```

The default Nmap scripts include smtp-commands, which uses the EHLO command to list all possible commands that can be executed on the target SMTP server.
```console
zero@pio$ nmap <TARGET> -sC -sV -p25
```

However, we can also use the smtp-open-relay NSE script to identify the target SMTP server as an open relay using 16 different tests.
```console
zero@pio$ nmap <TARGET> -p25 --script smtp-open-relay -v
```

We can use the command `smtp-user-enum` to enumerate users:
```console
zero@pio$ smtp-user-enum -M VRFY -U <WORDLIST> -t <TARGET> -w <SEG TO WAIT> -v
```

---

# IMAP / POP3 

The client establishes the connection to the server via port **143**. For communication, it uses text-based commands in ASCII format. Without further measures, IMAP works unencrypted and transmits commands, emails, or usernames and passwords in plain text. Depending on the method and implementation used, the encrypted connection uses the standard port **143** or an alternative port such as **993**. 

Both IMAP and POP3 have a large number of configuration options, making it difficult to deep dive into each component in more detail. Here are a list of IMAP commands:

| **Command** | **Description** |
| ----------- | --------------- |
| `1 LOGIN username password` | User's login |
| `1 LIST "" *` | Lists all directories |
| `1 CREATE "INBOX"` | Creates a mailbox with a specified name | 
| `1 DELETE "INBOX"` | Deletes a mailbox |
| `1 RENAME "ToRead" "Important` | Renames a mailbox |
| `1 LSUB "" *` | Returns a subset of names from the set of names that the User has declared as being **active** or **subscribed** |
| `1 SELECT INBOX` | Selects a mailbox so that messages in the mailbox can be accessed |
| `1 UNSELECT INBOX` | Exits the selected mailbox |
| `1 FETCH <ID> all` | Retrieves data associated with a message in the mailbox |
| `1 FETCH 1 (BODY[<NUMBER>])` | Retrieves a concrete data |
| `1 CLOSE` | Removes all messages with the **Deleted** flag set |
| `1 LOGOUT` | Closes the connection with the IMAP server |

And for POP3 commands:

| **Command** | **Description** |
| ----------- | --------------- |
| `USER <USERNAME>` | Identifies the user |
| `PASS <PASSWORD>` | Authentication of the user using its password |
| `STAT` | Requests the number of saved emails from the server |
| `LIST` | Requests from the server the number and size of all emails | 
| `RETR <ID>` | Requests the server to deliver the requested email by ID |
| `DELE <ID>` | Requests the server to delete the requested email by ID |
| `CAPA` | Requests the server to display the server capabilities |
| `RSET` | Requests the server to reset the transmitted information | 
| `QUIT` | Closes the connection with the POP3 server |

Some of dangerous configuration include:

| **Setting**   | **Description**    |
|--------------- | --------------- |
| `auth_debug` | 	Enables all authentication debug logging |
| `auth_debug_passwords` | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged |
| `auth_verbose` | Logs unsuccessful authentication attempts and their reasons |
| `auth_verbose_passwords` | Passwords used for authentication are logged and can also be truncated |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism |

By default, ports **110**, **143**, **993**, and **995** are used for IMAP and POP3. The two higher ports use **TLS**/**SSL** to encrypt the communication between client and server.
```console
zero@pio$ sudo nmap <TARGET> -sV -p110,143,993,995 -sC
```

If we successfully figure out the access credentials for one of the employees, an attacker could log in to the mail server and read or even send the individual messages:
```console
zero@pio$ curl -k 'imaps://<TARGET>' --user <USER>:<PASSWORD> -v
```

If we also use the verbose (`-v`) option, we will see how the connection is made. From this, we can see the version of TLS used for encryption, further details of the SSL certificate, and even the banner, which will often contain the version of the mail server. To interact with the IMAP or POP3 server over SSL, we can use openssl, as well as ncat. The commands for this would look like this:
```console
zero@pio$ openssl s_client -connect <TARGET>:pop3s
zero@pio$ openssl s_client -connect <TARGET>:imaps
```

---

# SNMP 

SNMP also transmits control commands using agents over **UDP port 161**. SNMP also enables the use of so-called traps over **UDP port 162**. To ensure that SNMP access works across manufacturers and with different client-server combinations, the **Management Information Base** (**MIB**) was created. MIB is an independent format for storing device information. The MIBs do not contain data, but they explain where to find which information and what it looks like, which returns values for the specific **OID** (**Object Identifier Registry**), or which data type is used.

**Community strings** can be seen as passwords that are used to determine whether the requested information can be viewed or not. It is important to note that many organizations are still using **SNMPv2**, as the transition to **SNMPv3** can be very complex. SNMPv2 existed in different versions. The version that still exists today is **v2c**, and extension **c** means community-based SNMP. A significant problem with the initial execution of the SNMP protocol is that the community string that provides security is only transmitted in plain text. The security has been increased enormously for SNMPv3 by security features such as username and password and transmission encryption (via **pre-shared key**) of the data. 

We can found the config files in `/etc/snmp/snmpd.conf`{: .filepath}. Some dangerous settings that the administrator can make with SNMP are:

| **Settings**   | **Description**    |
|--------------- | --------------- |
| `rwuser noauth` | Provides access to the full OID tree without authentication |
| `rwcommunity <community string> <IPv4 address>` | Provides access to the full OID tree regardless of where the requests were sent from |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with **rwcommunity** with the difference of using IPv6 |

For footprinting SNMP, we can use tools like **snmpwalk**, **onesixtyone**, and **braa**. Snmpwalk is used to query the OIDs with their information. Onesixtyone can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator.
```console
zero@pio$ snmpwalk -v2c -c public <TARGET>
```

```console
zero@pio$ onesixtyone -c <WORDLIST> <TARGET>
```

We can use a wordlist like `/usr/share/seclists//Discovery/SNMP/snmp.txt`{: .filepath}. Once we know a community string, we can use it with **braa** to brute-force the individual OIDs and enumerate the information behind them:
```console
zero@pio$ braa <COMMUNITY STRING>@<IP>:.1.3.6.*
```

---

# MySQL 

MySQL works according to the client-server principle and consists of a MySQL server and one or more MySQL clients. Sensitive data such as passwords can be stored in their plain-text form by MySQL; however, they are generally encrypted beforehand by the PHP scripts using secure methods such as One-Way-Encryption. We can found the config file in `/etc/mysql/mysql.conf.d/mysqld.cnf`{: .filepath}.

The main options that are security-relevant are:

| **Setting**   | **Description**    |
|--------------- | --------------- |
| `user` | Sets which user the MySQL service will run as |
| `password` | Sets the password for the MySQL user |
| `admin_address` | The IP address on which to listen for TCP/IP connections on the administrative network interface |
| `debug` | This variable indicates the current debugging settings |
| `sql_warnings` | This variable controls whether single-row INSERT statements produce an information string if warnings occur |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations |

The settings `user`, `password`, and `admin_address` are security-relevant because the entries are made in plain text. The `debug` and `sql_warnings` settings provide verbose information output in case of errors, which are essential for the administrator but should not be seen by others. 

Usually, the MySQL server runs on **TCP port 3306**.
```console
zero@pio$ sudo nmap <TARGET> -sVC -p 3306 --script mysql*
```

The most important databases for the MySQL server are the **system schema** (`sys`) and **information schema** (`information_schema`). The system schema contains tables, information, and metadata necessary for management. The **information schema** is also a database that contains metadata. However, this metadata is mainly retrieved from the **system schema** database. The reason for the existence of these two is the ANSI/ISO standard that has been established. **System schema** is a Microsoft system catalog for SQL servers and contains much more information than the **information schema**.

---

# MSSQL 

**Microsoft SQL** (**MSSQL**) is Microsoft's SQL-based relational database management system. Unlike MySQL, which we discussed in the last section, MSSQL is closed source and was initially written to run on Windows operating systems. **SQL Server Management Studio** (**SSMS**) comes as a feature that can be installed with the MSSQL install package or can be downloaded & installed separately. Many other clients can be used to access a database running on MSSQL. Including but not limited to:
- mssql-cli	
- SQL Server PowerShell	
- HediSQL	SQLPro	
- Impacket's mssqlclient.py

Here are the default databases and a brief description of each:

| **Default System Database**   | **Description**    |
|--------------- | --------------- |
| `master` | Tracks all system information for an SQL server instance |
| `model` | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb` | The SQL Server Agent uses this database to schedule jobs & alerts |
| `tempdb` | Stores temporary objects |
| `resource` | Read-only database containing system objects included with SQL server |

When an admin initially installs and configures MSSQL to be network accessible, the SQL service will likely run as `NT SERVICE\MSSQLSERVER`. Authentication being set to Windows Authentication means that the underlying Windows OS will process the login request and use either the local SAM database or the domain controller before allowing connectivity to the database management system.

There is not an extensive list of dangerous settings because there are countless ways MSSQL databases can be configured by admins based on the needs of their respective organizations. We may benefit from looking into the following:
- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default **sa** credentials. Admins may forget to disable this account

NMAP has default mssql scripts that can be used to target the default **TCP port 1433** that MSSQL listens on: 
```console
zero@pio$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET>
```

We can also use Metasploit to run an auxiliary scanner called `mssql_ping` that will scan the MSSQL service and provide helpful information in our footprinting process:
```console
msf6 auxiliary(scanner/mssql/mssql_ping) >
```

We can use **mssqlclient.py** and list the databases there:
```console
zero@pio$ python3 mssqlclient.py Administrator@<TARGET> -windows-auth

SQL> select name from sys.databases
```

---

# IPMI 

**Intelligent Platform Management Interface** (**IPMI**) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. IPMI is typically used in three ways:
- Before the OS has booted to modify BIOS settings
- When the host is fully powered down
- Access to a host after a system failure

IPMI communicates over **port 623 UDP**. Systems that use the IPMI protocol are called **Baseboard Management Controllers** (**BMCs**). If we can access a BMC during an assessment, we would gain full access to the host motherboard and be able to monitor, reboot, power off, or even reinstall the host operating system. Gaining access to a BMC is nearly equivalent to physical access to a system.

We can footprint the service as:
```console
zero@pio$ sudo nmap -sU --script ipmi-version -p 623 <TARGET>
```

We can also use the Metasploit scanner module:
```console
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
```

During internal penetration tests, we often find BMCs where the administrators have not changed the default password. Some unique default passwords to keep in our cheatsheets include:

| **Product**    | **Username**    | **Password**    |
|---------------- | --------------- | --------------- |
| Dell iDRAC | root |	calvin |
| HP iLO |	Administrator	| randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN	| ADMIN |

If default credentials do not work to access a BMC, we can turn to a flaw in the RAKP protocol in IPMI 2.0. During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place. These password hashes can then be cracked offline using a dictionary attack using **Hashcat mode 7300**. In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`. 

To retrieve IPMI hashes, we can use the Metasploit IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval module:
```console
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
```

---

# Remote Management Protocols 

## Linux Remote Management Protocols

These applications and services can be found on almost every server in the public network. It is time-saving since we do not have to be physically present at the server, and the working environment still looks the same. These protocols and applications for remote systems management are an exciting target for these reasons. 

## SSH 

SSH enables two computers to establish an encrypted and direct connection within a possibly insecure network on the standard **port TCP 22**. Despite the SSH protocol being one of the most secure protocols available today, some misconfigurations can still make the SSH server vulnerable to easy-to-execute attacks. Let us take a look at the following settings:

| **Setting**   | **Description**    |
|--------------- | --------------- |
| `PasswordAuthentication yes` | Allows password-based authentication |
| `PermitEmptyPasswords yes` | 	Allows the use of empty passwords |
| `PermitRootLogin yes` | Allows to log in as the root user |
| `Protocol 1` | Uses an outdated version of encryption |
| `X11Forwarding yes` | Allows X11 forwarding for GUI applications |
| `AllowTcpForwarding yes` | Allows forwarding of TCP ports |
| `PermitTunnel` | Allows tunneling |
| `DebianBanner yes` | Displays a specific banner when logging in |

We can use the tool **ssh-audit** to test it:
```console
zero@pio$ ./ssh-audit.py <TARGET>
```

One option is changing the authentication method. First, check which ones are allowed:
```console
zero@pio$ ssh -v user@<TARGET>
```

And then select one:
```console
zero@pio$ ssh -v user@<TARGET> -o PreferredAuthentications=passwords
```

## Windows Remote Management Protocols 

Windows servers can be managed locally using Server Manager administration tasks on remote servers. Remote management is enabled by default starting with Windows Server 2016. The main components used for remote management of Windows and Windows servers are the following:
- Remote Desktop Protocol (**RDP**)
- Windows Remote Management (**WinRM**)
- Windows Management Instrumentation (**WMI**)

### RDP 

RDP works at the application layer in the TCP/IP reference model, typically utilizing **TCP port **3389 as the transport protocol. However, the connectionless UDP protocol can use **port 3389** also for remote administration. RDP has handled Transport Layer Security (TLS/SSL) since Windows Vista, which means that all data, and especially the login process, is protected in the network by its good encryption.

```console
zero@pio$ nmap -sVC <TARGET> -p 3389 --script rdp*
```

We can help us with **rdp-sec-check**:
```console
zero@pio$ ./rdp-sec-check.pl <TARGET>
```

Authentication and connection to such RDP servers can be made in several ways. For example, using **xfreerdp**, **rdesktop**, or **Remmina**.
```console
zero@pio$ xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET>
```

### WinRM 

The Windows Remote Management (WinRM) is a simple Windows integrated remote management protocol based on the command line. WinRM relies on **TCP ports 5985** and **5986** for communication, with the last port **5986** using HTTPS, as ports 80 and 443 were previously used for this task. Another component that fits WinRM for administration is **Windows Remote Shell** (**WinRS**), which lets us execute arbitrary commands on the remote system. 
```console
zero@pio$ nmap -sVC <TARGET> -p 5985,5986 --disable-arp-ping -n
```

In Linux-based environments, we can use the tool called evil-winrm:
```console
zero@pio$ evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>
```

### WMI 

**Windows Management Instrumentation** (**WMI**) is Microsoft's implementation and also an extension of the **Common Information Model** (**CIM**), core functionality of the standardized **Web-Based Enterprise Management** (**WBEM**) for the Windows platform. WMI allows read and write access to almost all settings on Windows systems. WMI is typically accessed via PowerShell, VBScript, or the **Windows Management Instrumentation Console** (**WMIC**).

The initialization of the WMI communication always takes place on TCP port 135. The program **wmiexec.py** from the Impacket toolkit can be used for this:
```console
zero@pio$ wmiexec.py <USER>:<PASSWORD>@<TARGET> "hostname"
```

---

# Tools 

| **Link**   | **Description**    |
|--------------- | --------------- |
| **General** |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | A swiss army knife for pentesting networks |
| **SMB** | 
| [SMBMap](https://github.com/ShawnDEvans/smbmap) | Handy SMB enumeration tool | 
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | A next generation version of enum4linux |
| **DNS** |
| [DNSenum](https://github.com/fwaeytens/dnsenum) | Perl script that enumerates DNS information |
| **MSSQL** |
| [Impacket](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/mssqlclient.py) | Impacket for MSSQL |
| **SSH** | 
| [ssh-audit](https://github.com/jtesta/ssh-audit) | SSH server & client auditing |
| **RDP** |
| [rdp-sec-check](https://github.com/CiscoCXSecurity/rdp-sec-check) | Perl script to enumerate security settings of an RDP Service |
| **WinRM** |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | The ultimate WinRM shell for hacking/pentesting |
| **WMI** |
| [Impacket](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/wmiexec.py) | Impacket for WMI |

> For Web Enumeration check [here](https://zeropio.github.io/notes/web/enumeration-web)
{: .prompt-alert}

