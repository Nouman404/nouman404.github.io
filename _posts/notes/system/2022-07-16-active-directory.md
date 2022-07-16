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

- **Object**: any resource in the AD (OU, printer, user, domain controller,...)
- **Attributes**: 




