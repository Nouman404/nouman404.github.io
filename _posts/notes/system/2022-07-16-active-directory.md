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















































