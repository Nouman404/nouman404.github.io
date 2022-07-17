---
title: Notes | Active Directory 
author: Zeropio
date: 2022-07-16
categories: [Notes, System]
tags: [ad]
permalink: /notes/system/active-directory
---

**Active Directory** (AD) is a directory service developed by Microsoft for Windows domain networks. It is included in most Windows Server operating systems as a set of processes and services. Initially, Active Directory was used only for centralized domain management. Many features are arguably not "secure by default," and it can be easily misconfigured. Active Directory flaws and misconfigurations can often be used to obtain a foothold (internal access), move laterally and vertically within a network, and gain unauthorized access to protected resources such as databases, file shares, source code, and more.

A basic AD user with no privileges can enumerate:
- Domain Computers	
- Domain Users
- Domain Group Information	
- Organizational Units (OUs)
- Default Domain Policy	
- Functional Domain Levels
- Password Policy	
- Group Policy Objects (GPOs)
- Domain Trusts	
- Access Control Lists (ACLs)


Some of the common vulnerabilities are:
- PrintNightmare
- Shadow Credentials
- noPac
- ZeroLogon
- DCShadow

---

# Fundamentals

## Structure

AD works in a hierarchical tree structure, a forest at the top contains one or more domains, which have subdomains.
The forest is the security boundary within all objects are under. It can contain many domains, each domain can contain childs or subdomains.
A domain contains objects (users, computers and groups). It has many built-in **Organizational Units** (OUs), such as Domain Controllers, Users, Computers, and new OUs can be created as required. OUs may contain objects and sub-OUs, allowing for the assignment of different group policies.

An AD structure can be seem like:
```
ZEROPIO.LOCAL/
├── ADMIN.ZEROPIO.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── rick.astley
├── APP.ZEROPIO.LOCAL
└── DEV.ZEROPIO.LOCAL
```

It is common to see forest/domains linked together via trust relationship. It is often quicker and easier to create a trust relationship with another domain/forest than recreate all new users in the current domain.

## Terminology

- **Object**: any resource in the AD (OU, printer, user, domain controller,...).
- **Attributes**: characteristics of the given object.
- **Schema**: it defines what types of objects can exist in the AD database and their associated attributes.
- **Domain**: is a logical group of objects such as computers, users, OUs, groups,...
- **Forest**: is a collection of Active Directory domains.
- **Tree**: is a collection of Active Directory domains that begins at a single root domain.
- **Container**: objects hold other objects and have a defined place in the directory subtree hierarchy.
- **Leaf**: objects do not contain other objects and are found at the end of the subtree hierarchy.
- **GUID** (Global Unique Identifier): is a unique 128-bit value assigned when a domain user or group is created. This GUID value is unique across the enterprise, similar to a MAC address. Every single object created by Active Directory is assigned a GUID.
- **Security Principals**: are domain objects that can manage access to other resources within the domain.
- **SID** (Security Identifier): is used as a unique identifier for a security principal or security group, there are [well-known SID](https://ldapwiki.com/wiki/Well-known%20Security%20Identifiers).
- **DN** (Distinguished Name): describes the full path to an object in AD, for example *cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local*.
  - **CN** (Common Name): is just one way the user object could be searched for or accessed within the domain.
  - **DC** (Domain Controllers).
- **RDN** (Relative Distinguished Name): is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy.
- **sAMAccountName**: is the user's logon name.
- **userPrincipalName**: is another way to identify users in AD.
- **FSMO** (Flexible Single Master Operation) **Roles**: these give DC the ability to continue authenticating users and granting permissions without interruption. FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed.There are five roles:
  - Schema Master.
  - Domain Naming Master (one for each forest).
  - Relative ID (RID) Master (one per domain).
  - Primary Domain Controller (PDC) Emulator (one per domain).
  - Infrastructure Master (one per domain).
- **GC** (Global Catalog): is a domain controller that stores copies of ALL objects in an Active Directory forest, provides *Authentication* and *Object search*.
- **RODC** (Read-Only Domain Controller): has a read-only Active Directory database.
- **Replication**: happens in AD when AD objects are updated and transferred from one Domain Controller to another.
  - **KCC** (Knowledge Consistency Checker): whenever a DC is added, KCC create connection to manage replication between them.
- **SPN** (Service Principal Name): uniquely identifies a service instance (Kerberos authentication).
- **GPO** (Group Policy Object): are virtual collections of policy settings.
- **ACL** (Access Control List): s the ordered collection of ACEs that apply to an object.
- **ACEs** (Access Control Entities): each ACE in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.
- **DACL** (Discretionary Access Control List): define which security principles are granted or denied access to an object (it contains a list of ACEs). If an object does NOT have a DACL, then the system will grant full access to everyone, but if the DACL has no ACE entries, the system will deny all access attempts.
- **SACL** (System Access Control Lists): allows for administrators to log access attempts that are made to secured objects.
- **FQDN** (Fully Qualified Domain Name): is the complete name for a specific computer or host, can be used to locate hosts in an Active Directory without knowing the IP address.
- **Tombstone**: is a container object in AD that holds deleted AD objects.
- **AD Recycle Bin**: facilitate the recovery of deleted AD objects.
- **SYSVOL**: folder, or share, stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment.
- **AdminSDHolder**: is used to manage ACLs for members of built-in groups in AD marked as privileged (remove attacker's persitence).
- **dsHeuristics**: attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings.
- **adminCount**: attribute determines whether or not the SDProp process protects a user, attackers will often look for accounts with the adminCount attribute set to 1 to target in an internal environment.
- **ADUC** (Active Directory Users and Computers): is a GUI console commonly used for managing users, groups, computers, and contacts in AD .
- **ADSI Edit**: is a GUI tool used to manage objects in AD .
- **sIDHistory**: holds any SIDs that an object was assigned previously, this attribute can potentially be abused if set insecurely, allowing an attacker to gain prior elevated access that an account had before a migration if SID Filtering is not enabled.
- **NTDS.DIT**: file can be considered the heart of Active Directory.

## Objects

An object can be defined as ANY resource present within an AD.

- **Users**: Users are considered *leaf objects* network. They are leafs, but also *security principals* (they cannot contain other objects). A user object is considered a security principal and has a security identifier (SID) and a global unique identifier (GUID). User objects have many possible attributes, such as their display name, last login time, date of last password change, email address, account description, manager, address, and more (over 800).
- **Contacts**: is usually used to represent an external user and contains informational attributes such as first name, last name, email address, telephone number, etc,... They are leaf objects and are NOT *security principals* (they don't have SID, only GUID).
- **Printers**: points to a printer accessible within the AD network (also, the don't are *security principals*).
- **Computers**: is any computer joined to the AD network. They are *leafs*, but also *security principals*.
- **Shared folders**: points to a shared folder on the specific computer where the folder resides. Shared folders are NOT *security principles* and only have a GUID.
- **Groups**: is considered a container object because it can contain other objects, including users, computers, and even other groups. A group IS regarded as a security principal. There are nested groups (a group added as a member of another group). The tool [BloodHound](https://github.com/BloodHoundAD/BloodHoundAD) helps discovering attack paths in groups.
- **OU** (Organizational Units): is a container that systems administrators can use to store similar objects for ease of administration. OUs are often used for administrative delegation of tasks without granting a user account full administrative rights.
- **Domain**: is the structure of an AD network.
- **Domain Controllers**: are the brains of an AD network. They handle authentication requests, verify users on the network, and control who can access the various resources in the domain.
- **Sites**: is a set of computers across one or more subnets connected using high-speed links.
- **Built-in**: is a container that holds [default groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups) in an AD domain. They are predefined when an AD domain is created.
- **FSP** (Foreign Security Principals): is an object created in AD to represent a security principal that belongs to a trusted external forest. They are created when an object such as a user, group, or computer from an external (outside of the current) forest is added to a group in the current domain. 


## Functionality

Taking back the **FSMO** roles:

| **Roles**   | **Description**    |
|--------------- | --------------- |
| *Schema Master*   | This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD.   |
| *Domain Naming Master*   | Manages domain names and ensures that two domains of the same name are not created in the same forest.   |
| *Relative ID (RID) Master*   | The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID.   |
| *PDC Emulator*   | The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain.  |
| *Infrastructure Master* | This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names. |

Depending on the organization, these roles may be assigned to specific DCs or as defaults each time a new DC is added. Issues with FSMO roles will lead to authentication and authorization difficulties within a domain.

### Levels

There are levels to determinate the features and capabilities in Active Directory Domain Services (**AD DS**). Also specify which Windows Server can run a DC.
For example:

| **Domain Functional Level**    | **Features Available**    | **Supported Domain Controller Operating Systems**    |
|---------------- | --------------- | --------------- |
| Windows 2000 native   | Universal groups for distribution and security groups, group nesting, group conversion, SID history   | Windows Server 2008 R2, Windows Server 2008, Windows Server 2003, Windows 2000    |
| Windows Server 2003   | Netdom.exe domain management tool, lastLogonTimestamp attribute introduced, well-known users and computers containers, constrained delegation, selective authentication    | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008, Windows Server 2003    |
| Windows Server 2008  | Distributed File System (DFS) replication support, Advanced Encryption Standard (AES 128 and AES 256) support for the Kerberos protocol, Fine-grained password policies   | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008   |
| Windows Server 2008 R2	   | Authentication mechanism assurance, Managed Service Accounts  | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2   |
| Windows Server 2012 |  KDC support for claims, compound authentication, and Kerberos armoring | Windows Server 2012 R2, Windows Server 2012 |
| Windows Server 2012 R2 | Extra protections for members of the Protected Users group, Authentication Policies, Authentication Policy Silos | Windows Server 2012 R2 |
| Windows Server 2016 | Smart card required for interactive logon new Kerberos features and new credential protection features | Windows Server 2019 and Windows Server 2016 |

A new functional level was not added with the release of Windows Server 2019. However, Windows Server 2008 functional level is the minimum requirement for adding Server 2019 Domain Controllers to an environment.

Forest functional levels have introduced a few key capabilities over the years:

| **Version**   | **Capabilities**    |
|--------------- | --------------- |
| Windows Server 2003	  | saw the introduction of the forest trust, domain renaming, read-only domain controllers (RODC), and more   |
| Windows Server 2008  | All new domains added to the forest default to the Server 2008 domain functional level. No additional new features   |
| Windows Server 2008 R2 | Active Directory Recycle Bin provides the ability to restore deleted objects when AD DS is running   |
| Windows Server 2012	  | All new domains added to the forest default to the Server 2012 domain functional level. No additional new features   |
| Windows Server 2012 R2 | All new domains added to the forest default to the Server 2012 R2 domain functional level. No additional new features |
| Windows Server 2016 | Privileged access management (PAM) using Microsoft Identity Manager (MIM) |

### Trusts

A trust is used to establish *forest-forest* or *domain-domain* authentication. There are several trust types:

| **Trust Type**   | **Description**    |
|--------------- | --------------- |
| Parent-child   | Domains within the same forest   |
| Cross-link  | a trust between child domains to speed up authentication   |
| External   | A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust (SID filtering)   |
| Tree-root   | a two-way transitive trust between a forest root domain and a new tree root domain   |
| Forest | a transitive trust between two forest root domains |

There are two types of trust:
- **Transitive**: trust is extended to objects that the child domain trusts 
- **Non-transitive**: only the child domain itself is trusted

Also can be set up:
- **One-way**: only users in a trusted domain can access resources in a trusting domain, the direction of trust is opposite to the direction of access 
- **Two-way** (bidirectional): users from both trusting domains can access resources

Domain trusts can be set up incorrectly, leading to attack paths.

---

# Protocols

AD require a wide variety of protocols: **LDAP** (Lightweight Directory Access Protocol), **Kerberos**, **DNS** and **MSRPC** (RPC - Remote Procedure Call).

## Kerberos

Kerberos is a stateless authentication protocol based on tickets instead of transmitting user passwords over the network. The Kerberos protocol uses port 88 (both TCP and UDP). When enumerating an Active Directory environment, we can often locate Domain Controllers by performing port scans looking for open port 88 using a tool such as Nmap. The authentication process is the following:
1. The user logs on, and their password is converted to an **NTLM hash**, which is used to encrypt the **TGT** (Ticket Granting Ticket) ticket. This decouples the user's credentials from requests to resources.
2. The **KDC** (Key Distribution Centre) service on the DC checks the authentication service request (**AS-REQ**), verifies the user information, and creates a TGT, which is delivered to the user.
3. The user presents the TGT to the DC, requesting a Ticket Granting Service (**TGS**) ticket for a specific service. This is the **TGS-REQ**. If the TGT is successfully validated, its data is copied to create a TGS ticket.
4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the **TGS_REP**.
5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (**AP_REQ**).

## DNS

AD DS uses DNS to allow clients locate DC. AD maintains a database of services running on the network in the form of service records (**SRV**). 

We can use **nslookup** to check:
- Forward DNS lookup

```console
PS C:\zeropio> nslookup ZEROPIO.LOCAL

Server:  172.16.6.5
Address:  172.16.6.5

Name:    ZEROPIO.LOCAL
Address:  172.16.6.5
```

- Reverse DNS lookup

```console
PS C:\zeropio> nslookup 172.16.6.5

Server:  172.16.6.5
Address:  172.16.6.5

Name:    DEV.ZEROPIO.LOCAL
Address:  172.16.6.5
```

- Finding IP Address of a Host 

```console
PS C:\zeropio> nslookup DEV

Server:   172.16.6.5
Address:  172.16.6.5

Name:    DEV.ZEROPIO.LOCAL
Address:  172.16.6.5
```

## LDAP

LDAP is an open-source and cross-platform protocol used for authentication against various directory services (such as AD). LDAP uses port 389, and LDAP over SSL (LDAPS) communicates over port 636. LDAP is how systems in the network environment can "speak" to AD. An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests. The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, Active Directory is a directory server that uses the LDAP protocol.

There are two types of LDAP Authentication:
- **Simple authentication**: anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server.
- **SASL** (Simple Authentication and Security Layer) **Authentication**: framework uses other authentication services (like Kerberos) o bind to the LDAP server and then uses this authentication service to authenticate to LDAP. The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service, which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication.

LDAP authentication messages are sent in cleartext by default so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

## MSRPC 

MSRPC is Microsoft's implementation of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications.

| **Interface Name**  | **Description**    |
|--------------- | --------------- |
| *lsarpc*   | A set of RPC calls to the Local Security Authority (LSA) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.   |
| *netlogon*  | Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.   |
| *samr*   | Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as BloodHound to visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved.   |
| *drsuapi*   | Is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. Attackers can utilize drsuapi to create a copy of the Active Directory domain database (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM.  |

## NTLM Authentication

Other authentication method used is NTLM (**LM**, **NTLM**, **NTLMv1**, and **NTLMv2**). **LM** and **NTLM** are the hashes names. **NTLMv1** and **NTLMv2** are authentication protocols that utilize the LM or NT hash.

| **Hash/Protocol**    | **Cryptographic technique**    | **Mutual Authentication**    | **Message Type** | **Trusted Third Party** |
|---------------- | --------------- | --------------- | ------------------------ | ----------------- |
| *NTLM*   | Symmetric key cryptography	   | No    | Random number | Domain Controller |
| *NTLMv1*   | Symmetric key cryptography	   | No    | MD4 hash, random number | Domain Controller |
| *NTLMv2*  | Symmetric key cryptography	   | No   | MD4 hash, random number | Domain Controller |
| *Kerberos*   | Symmetric key cryptography & asymmetric cryptography   | Yes   | Encrypted ticket using DES, MD5 | Domain Controller,/Key Distribution Center (KDC) |

### LM 

**Lan Manager** (LM) hashes are the oldest password storage mechanism used by the Windows operating system. If in use, they are stored in the SAM database on a Windows host and the NTDS.DIT database on a Domain Controller. Passwords using LM are limited to a maximum of **14** characters. Passwords are not case sensitive and are converted to uppercase before generating the hashed value, limiting the keyspace to a total of 69 characters making it relatively easy to crack these hashes using a tool such as Hashcat.

### NTHash (NTLM)

**NT LAN Manager** (NTLM) hashes are used on modern Windows systems. It is a challenge-response authentication protocol in three steps:
1. a client first sends a **NEGOTIATE_MESSAGE** to the server
2. whose response is a **CHALLENGE_MESSAGE** to verify the client's identity
3. the client responds with an **AUTHENTICATE_MESSAGE**

These hashes are stored locally in the SAM database or the NTDS.DIT database file on a Domain Controller.
NTLM is vulnerable to the **pass-the-hash** attack, which means an attacker can use just the NTLM hash (after obtaining via another successful attack) to authenticate to target systems where the user is a local admin without needing to know the cleartext value of the password.

An NTLM hash seems like:
```
Zeropio:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```

Where:
- **Zeropio** is the username
- **500** is the RID (500 for **administrator** account)
- **aad3c435b514a4eeaad3b935b51304fe** is the LM hash 
- **e46b9e548fa0d122de7f59fb6d48eaa2** is the NT hash

With a tool, like [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec), we can break the hash:
```console
zero@pio$ crackmapexec smb 10.129.41.19 -u zeropio -H e46b9e548fa0d122de7f59fb6d48eaa2

SMB         10.129.43.9     445    DC01      [*] Windows 10.0 Build 17763 (name:DC01) (domain:ZEROPIO.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    DC01      [+] INLANEFREIGHT.LOCAL\zeropio:e46b9e548fa0d122de7f59fb6d48eaa2 (Pwn3d!)
```

### NTLMv1 (Net-NTMLv1)

The NTLM protocol performs a challenge/response between a server and client using the NT hash. TLMv1 uses both the NT and the LM hash, which can make it easier to "crack" offline after capturing a hash using a tool such as [Responder](https://github.com/lgandx/Responder) or via an [NTLM relay attack](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html).

An example could be:
```
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

### NTLMv2 (Net-NTLMv2)

The NTLMv2 protocol was created as a stronger alternative to NTLMv1.

An example could be:
```
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```

### MSCache2

The Domain Cached Credentials (**DCC**), also known as **MS Cache v1** and **v2** solve the potential issue of a domain-joined host being unable to communicate with a domain controller. Hosts save the last ten hashes for any domain users that successfully log into the machine in the `HKEY_LOCAL_MACHINE\SECURITY\Cache`{: .filepath} registry key. The **pass-the-hash** attacks don't work.


---

# Users

User accounts are created on both local systems and in Active Directory to give a person or a program the ability to log on to a computer and access resources based on their rights. 

## Local Accounts 

Local accounts are stored locally on a particular server or workstation. Any rights assigned can only be granted to that specific host and will not work across the domain. Local user accounts are considered security principals but can only manage access to and secure resources on a standalone host.
There are some default local user:
- **Administrator**: this account has the SID S-1-5-domain-500. It has full control over almost every resource on the system. It cannot be deleted or locked, but it can be disabled or renamed. 
- **Guest**: this account is disabled by default.
- **SYSTEM**: The SYSTEM (or **NT AUTHORITY\SYSTEM**) account on a Windows host is the default account installed and used by the operating system to perform many of its internal functions. Unlike the Root account on Linux, SYSTEM is a service account and does not run entirely in the same context as a regular user. A SYSTEM account is the highest permission level one can achieve on a Windows host and, by default, is granted Full Control permissions to all files on a Windows system.
- **Network Service**: this is a predefined local account used by the Service Control Manager (SCM) for running Windows services.
- **Local Service**: this is another predefined local account used by the Service Control Manager (SCM) for running Windows services.

More info [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts).

## Domain Users

Domain users differ from local users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on the permissions granted to their user account or the group that account is a member of.
One key account is **KRBTGT**, this account acts as a service account for the Key Distribution service providing authentication and access for domain resources. It can be leveraged for privilege escalation and persistence in a domain through attacks such as the [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) attack.

## User naming attributes 

| *UserPrincipalName* (UPN)   | This is the primary logon name for the user. By convention, the UPN uses the email address of the user.    |
| *ObjectGUID*	  | This is a unique identifier of the user. In AD, the ObjectGUID attribute name never changes and remains unique even if the user is removed.   |
| *SAMAccountName*  | This is a logon name that supports the previous version of Windows clients and servers.   |
| *objectSID*	   | The user's Security Identifier (SID). This attribute identifies a user and its group memberships during security interactions with the server.   |
| *sIDHistory*   | This contains previous SIDs for the user object if moved from another domain and is typically seen in migration scenarios from domain to domain. After a migration occurs, the last SID will be added to the **sIDHistory** property, and the new SID will become its **objectSID**.   |

To check attributes:
```console
PS C:\zeropio> Get-ADUser -Identity zero-pio

DistinguishedName : CN=zero,CN=Users,DC=ZEROPIO,DC=LOCAL
Enabled           : True
GivenName         : zero
Name              : zeropio
ObjectClass       : user
ObjectGUID        : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName    : zero-pio
SID               : S-1-5-21-3842939050-3880317879-2865463114-1111
Surname           : pio
UserPrincipalName : zero-pio@ZEROPIO.LOCAL
```

More attributes [here](https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes).

## Domain joined machines 

- **Domain joined**: Hosts joined to a domain have greater ease of information sharing within the enterprise and a central management point (the DC) to gather resources, policies, and updates from. A host joined to a domain will acquire any configurations or changes necessary through the domain's Group Policy. 

- **Non-domain joined**: are not managed by domain policy. Sharing resources outside your local network is much more complicated than it would be on a domain. This is fine for computers meant for home use or small business clusters on the same LAN.

## Groups

Groups can place similar users together and mass assign rights and access. They are another key target for attackers and penetration testers.

### Types
The are to main types:
- **Security groups**: for assigning permissions and rights to a collection of users instead of one at a time.
- **Distribution Groups**: is used by email applications to distribute messages to group members.

### Scopes

There are three different scopes:
- **Domain Local Group**: can only be used to manage permissions to domain resources in the domain where it was created. Local groups cannot be used in other domains but CAN contain users from OTHER domains. Local groups can be nested into other local groups but NOT within global groups.
- **Global Group**: can be used to grant access to resources in another domain.
- **Universal Group**: can be used to manage resources distributed across multiple domains and can be given permissions to any object within the same forest.

An example could be:
```console
PS C:\zeropio> et-ADGroup  -Filter * |select samaccountname,groupscope

samaccountname                           groupscope
--------------                           ----------
Administrators                          DomainLocal
Users                                   DomainLocal
Guests                                  DomainLocal
Print Operators                         DomainLocal
Backup Operators                        DomainLocal
Replicator                              DomainLocal
Remote Desktop Users                    DomainLocal
Network Configuration Operators         DomainLocal
Distributed COM Users                   DomainLocal
IIS_IUSRS                               DomainLocal
Cryptographic Operators                 DomainLocal
Event Log Readers                       DomainLocal
Certificate Service DCOM Access         DomainLocal
RDS Remote Access Servers               DomainLocal
RDS Endpoint Servers                    DomainLocal
RDS Management Servers                  DomainLocal
Hyper-V Administrators                  DomainLocal
Access Control Assistance Operators     DomainLocal
Remote Management Users                 DomainLocal
Storage Replica Administrators          DomainLocal
Domain Computers                             Global
Domain Controllers                           Global
Schema Admins                             Universal
Enterprise Admins                         Universal
Cert Publishers                         DomainLocal
Domain Admins                                Global
Domain Users                                 Global
Domain Guests                                Global
```

Scopes can be changed with some restrictions:
- A Global Group can only be converted to a Universal Group if it is NOT part of another Global Group.
- A Domain Local Group can only be converted to a Universal Group if the Domain Local Group does NOT contain any other Domain Local Groups as members.
- A Universal Group can be converted to a Domain Local Group without any restrictions.
- A Universal Group can only be converted to a Global Group if it does NOT contain any other Universal Groups as members.

There are some built-in groups, some examples can be **Domain Admins**.

### Nested Group Membership 

Through this membership, a user may inherit privileges not assigned directly to their account or even the group they are directly a member of. This could lead to privilege escalation.

[BloodHound](https://github.com/BloodHoundAD/BloodHound) helps finding it.

### Attributes 

Some of the most importan attributes:
- **cn**: Common-Name
- **member**: which user, group, and contact objects are members of the group 
- **groupType**: specifies the group type and scope 
- **memberOf**: nested group membership 
- **objectSid**: SID of the group 

## Rights and Privileges 

Rights are typically assigned to users or groups and deal with permissions to access an object such as a file, while privileges grant a user permission to perform an action such as run a program, shut down a system, reset passwords, etc. Windows computers have a concept called User Rights Assignment, which, while referred to as rights, are actually types of privileges granted to a user. 

### Built-in AD Groups 

| **Group Name** | **Description**    |
|--------------- | --------------- |
| **Account Operators** |	Members can create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers. They cannot manage the Administrator account, administrative user accounts, or members of the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups. |
| **Administrators** |	Members have full and unrestricted access to a computer or an entire domain if they are in this group on a Domain Controller. |
| **Backup Operators** |	Members can back up and restore all files on a computer, regardless of the permissions set on the files. Backup Operators can also log on to and shut down the computer. Members can log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, which, if taken, can be used to extract credentials and other juicy info. |
| **DnsAdmins** |	Members have access to network DNS information. The group will only be created if the DNS server role is or was at one time installed on a domain controller in the domain. |
| **Domain Admins** |	Members have full access to administer the domain and are members of the local administrator's group on all domain-joined machines. |
| **Domain Computers** |	Any computers created in the domain (aside from domain controllers) are added to this group. |
| **Domain Controllers** |	Contains all DCs within a domain. New DCs are added to this group automatically. |
| **Domain Guest**s |	This group includes the domain's built-in Guest account. Members of this group have a domain profile created when signing onto a domain-joined computer as a local guest. |
| **Domain Users** |	This group contains all user accounts in a domain. A new user account created in the domain is automatically added to this group. |
| **Enterprise Admins** |	Membership in this group provides complete configuration access within the domain. The group only exists in the root domain of an AD forest. Members in this group are granted the ability to make forest-wide changes such as adding a child domain or creating a trust. The Administrator account for the forest root domain is the only member of this group by default. |
| **Event Log Readers** |	Members can read event logs on local computers. The group is only created when a host is promoted to a domain controller. |
| **Group Policy Creator Owners** |	Members create, edit, or delete Group Policy Objects in the domain. |
| **Hyper-V Administrators** |	Members have complete and unrestricted access to all the features in Hyper-V. If there are virtual DCs in the domain, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins. |
| **IIS_IUSRS** |	This is a built-in group used by Internet Information Services (IIS), beginning with IIS 7.0. |
| **Pre–Windows 2000 Compatible Access** |	This group exists for backward compatibility for computers running Windows NT 4.0 and earlier. Membership in this group is often a leftover legacy configuration. It can lead to flaws where anyone on the network can read information from AD without requiring a valid AD username and password. |
| **Print Operators** |	Members can manage, create, share, and delete printers that are connected to domain controllers in the domain along with any printer objects in AD. Members are allowed to log on to DCs locally and may be used to load a malicious printer driver and escalate privileges within the domain. |
| **Protected Users** |	Members of this group are provided additional protections against credential theft and tactics such as Kerberos abuse. |
| **Read-only Domain Controllers** |	Contains all Read-only domain controllers in the domain. |
| **Remote Desktop Users** |	This group is used to grant users and groups permission to connect to a host via Remote Desktop (RDP). This group cannot be renamed, deleted, or moved. |
| **Remote Management Users** |	This group can be used to grant users remote access to computers via Windows Remote Management (WinRM)
| **Schema Admins** |	Members can modify the Active Directory schema, which is the way all objects with AD are defined. This group only exists in the root domain of an AD forest. The Administrator account for the forest root domain is the only member of this group by default. |
| **Server Operators** |	This group only exists on domain controllers. Members can modify services, access SMB shares, and backup files on domain controllers. By default, this group has no members. |

- Server Operators Group Details

```console
PS C:\zeropio> Get-ADGroup -Identity "Server Operators" -Properties *

adminCount                      : 1
CanonicalName                   : INLANEFREIGHT.LOCAL/Builtin/Server Operators
CN                              : Server Operators
Created                         : 10/27/2021 8:14:34 AM
createTimeStamp                 : 10/27/2021 8:14:34 AM
Deleted                         : 
Description                     : Members can administer domain servers
DisplayName                     : 
DistinguishedName               : CN=Server Operators,CN=Builtin,DC=ZEROPIO,DC=LOCAL
dSCorePropagationData           : {10/28/2021 1:47:52 PM, 10/28/2021 1:44:12 PM, 10/28/2021 1:44:11 PM, 10/27/2021 
                                  8:50:25 AM...}
GroupCategory                   : Security
GroupScope                      : DomainLocal
groupType                       : -2147483643
HomePage                        : 
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : 
LastKnownParent                 : 
ManagedBy                       : 
MemberOf                        : {}
Members                         : {}
Modified                        : 10/28/2021 1:47:52 PM
modifyTimeStamp                 : 10/28/2021 1:47:52 PM
Name                            : Server Operators
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=ZEROPIO,DC=LOCAL
ObjectClass                     : group
ObjectGUID                      : 0887487b-7b07-4d85-82aa-40d25526ec17
objectSid                       : S-1-5-32-549
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Server Operators
sAMAccountType                  : 536870912
sDRightsEffective               : 0
SID                             : S-1-5-32-549
SIDHistory                      : {}
systemFlags                     : -1946157056
uSNChanged                      : 228556
uSNCreated                      : 12360
whenChanged                     : 10/28/2021 1:47:52 PM
whenCreated                     : 10/27/2021 8:14:34 AM
```

- Domain Admins Group Membership 

```console
PS C:\zeropio> Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members

DistinguishedName : CN=Domain Admins,CN=Users,DC=ZEROPIO,DC=LOCAL
GroupCategory     : Security
GroupScope        : Global
Name              : Domain Admins
```

### User Rights Assignment 

Users can have various rights assigned to their account. With [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) we can elevate privileges.
[Here](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) Microsoft provides a wide range of privileges. Some of the common one are:

| **Privilege**   | **Description**    |
|--------------- | --------------- |
| **SeRemoteInteractiveLogonRight** |	This privilege could give our target user the right to log onto a host via Remote Desktop (RDP), which could potentially be used to obtain sensitive data or escalate privileges. |
| **SeBackupPrivilege** |	This grants a user the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file. |
| **SeDebugPrivilege** | 	This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as Mimikatz to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory. |
| **SeImpersonatePrivilege** | 	This privilege allows us to impersonate a token of a privileged account such as NT AUTHORITY\SYSTEM. This could be leveraged with a tool such as JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system. |
| **SeLoadDriverPrivilege** | 	A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system. |
| **SeTakeOwnershipPrivilege** | 	This allows a process to take ownership of an object. At its most basic level, we could use this privilege to gain access to a file share or a file on a share that was otherwise not accessible to us. |

Some techniques for escalation could be [this](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e?gi=9d148d729c71) or [this](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens).

### Viewing a User's Privileges 

- Standard Domain User's Rights 

```console
PS C:\zeropio> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

- Domain Admin Rights Non-Elevated

```console
PS C:\zeropio> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

- Domain Admin Rights Elevated

```console
PS C:\zeropio> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

- Backup Operator Rights

```console
PS C:\zeropio> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

---

# Securing AD 

## General Hardening Measures 

### LAPS 

Accounts can be set up to have their password rotated on a fixed interval (i.e., 12 hours, 24 hours, etc.).

### Audit Policy Settings (Logging and Monitoring) 

Every organization needs to have logging and monitoring setup to detect and react to unexpected changes or activities that may indicate an attack. 

### Group Policy Security Settings 

hese can be used to apply a wide variety of security policies to help harden Active Directory. For example:
- Account Policies 
- Local Policies 
- Software Restriction Policies
- Application Control Policies 
- Advanced Audit Policy Configuration

### Update Management (SCCM/WSUS)

The Windows Server Update Service (WSUS) can be installed as a role on a Windows Server and can be used to minimize the manual task of patching Windows systems. System Center Configuration Manager (SCCM) is a paid solution that relies on the WSUS Windows Server role being installed and offers more features than WSUS on its own.

### Group Managed Service Accounts (gMSA) 

A gMSA is an account managed by the domain that offers a higher level of security than other types of service accounts for use with non-interactive applications, services, processes, and tasks that are run automatically but require credentials to run. 

### Security Groups 

Security groups offer an easy way to assign access to network resources.

### Account Separation 

Administrators must have two separate accounts. One for their day-to-day work and a second for any administrative tasks they must perform. This can help ensure that if a user's host is compromised (through a phishing attack, for example).

### Password Complexity Policies + Passphrases + 2FA 

### Limiting Domain Admin Account Usage 

All-powerful Domain Admin accounts should only be used to log in to Domain Controllers, not personal workstations, jump hosts, web servers, etc. 

### Periodically Auditing and Removing Stale Users and Objects 

### Auditing Permissions and Access 

### Audit Policies & Logging 

### Using Restricted Groups 

### Limiting Server Roles 

It is important not to install additional roles on sensitive hosts, such as installing the Internet Information Server (IIS) role on a Domain Controller.  

### Limiting Local Admin and RDP Rights 

Organizations should tightly control which users have local admin rights on which computers. As stated above, this can be achieved using Restricted Groups.

More secured practices [here](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory).













