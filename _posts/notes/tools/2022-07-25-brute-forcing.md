---
title: Notes | Brute Forcing
author: Zeropio
date: 2022-07-25
categories: [Notes, Tools]
tags: [brute-forcing]
permalink: /notes/tools/brute-forcing
---

A Brute Force attack is a method of attempting to guess passwords or keys by automated probing. An example of a brute-force attack is password cracking.  Passwords are usually not stored in clear text on the systems but as hash values. Here is a small list of files that can contain hashed passwords:

| **Windows**   | **Linux**    |
|--------------- | --------------- |
| unattend.xml	| shadow |
| sysprep.inf	| shadow.bak |
| SAM   | password |

Since the password cannot be calculated backward from the hash value, the brute force method determines the hash values belonging to the randomly selected passwords until a hash value matches the stored hash value.

### Brute Force Attack 

A **Brute Force Attack** does not depend on a wordlist of common passwords, but it works by trying all possible character combinations for the length we specified. Once the password length starts to increase, and we start testing for mixed casings, numbers, and special characters, the time it would take to brute force, these passwords can take millions of years. That is why we should consider methods that may increase our odds of guessing the correct password, like **Dictionary Attacks**.

### Dictionary Attack 

A Dictionary Attack tries to guess passwords with the help of lists. The goal is to use a list of known passwords to guess an unknown password. We can check out the [SecLists](https://github.com/danielmiessler/SecLists) for wordlists, as it has a huge variety of wordlists, covering many types of attacks. We can found in `/usr/share/seclists/Passwords`{: .filepath} and `/usr/share/seclists/Usernames`{: .filepath}.

### Methods of Brute Force Attacks 

This are some methodologies for brute forcing:

| **Attack**   | **Description**    |
|--------------- | --------------- |
| Online Brute Force Attack | Attacking a live application over the network, like HTTP, HTTPs, SSH, FTP, and others |
| Offline Brute Force Attack | Also known as Offline Password Cracking, where you attempt to crack a hash of an encrypted password |
| Reverse Brute Force Attack | Also known as username brute-forcing, where you try a single common password with a list of usernames on a certain service |
| Hybrid Brute Force Attack | Attacking a user by creating a customized password wordlist, built using known intelligence about the user or the service |

---

# Basic HTTP Auth 

## Password Attacks 

This are the different types of password attacks:
- Dictionary attack
- Brute force
- Traffic interception
- Man In the Middle
- Key Logging
- Social engineering

## Default Passwords 

Default passwords are often used for user accounts for testing purposes. They are easy to remember and are also used for default accounts of services and applications intended to simplify first access.

Let's start with **Hydra**. Hydra is a tool for brute forcing. The installation is as simply as:
```console
zero@pio$ sudo apt install hydra -y
```

As always, the option `-h` provides with useful information.

At first, if we don't know which user brute force, we have to brute force usernames also. For the example, we will be using `/usr/share/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt`{: .filepath}:
```console
zero@pio$ hydra - C /usr/share/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <ip> -s <port> http-get <path> # For example / 
```

## Username Brute Force 

Another important wordlist is **rockyou.txt**, located in `/usr/share/wordlists/rockyou.txt`{: .filepath}, which contains more than fourteen millions password. With `/usr/share/SecLists/Usernames/Names/names.txt`{: .filepath} can be really powerful.

Hydra requires three things to a *username/password attack*:
- Credentials 
- Target host 
- Target path

As the following:
```console
zero@pio$ hydra -L /usr/share/SecLists/Usernames/Names/names.txt -P /usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f <ip> -s <port> http-get /
```

If we only want to brute force a username, and know the password we can use the option `-p` (if we know the user `-l`)

---

# Web Form Brute Forcing 

This are the supported services for Hydra:
```console
zero@pio$ hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e

Supported			        ldap3[-{cram|digest}md5][s]	rsh
services			        memcached					rtsp
				            mongodb						s7-300
adam6500			        mssql						sip
asterisk			        mysql						smb
cisco				        nntp						smtp[s]
cisco-enable		        oracle-listener				smtp-enum
cvs				            oracle-sid					snmp
firebird			        pcanywhere					socks5
ftp[s]				        pcnfs						ssh
http[s]-{head|get|post}		pop3[s]						sshkey
http[s]-{get|post}-form		postgres					svn
http-proxy		        	radmin2						teamspeak
http-proxy-urlenum		    rdp				  		    telnet[s]
icq				            redis						vmauthd
imap[s]		        		rexec						vnc
irc				            rlogin						xmpp
ldap2[s]		        	rpcap
```

For http:
- http[s]-{head|get|post}
- http[s]-post-form

The first one is used for basic authentication, while the second one is for login forms. We can list the requiered parameters with:
```console
zero@pio$ hydra http-post-form -U
```

For this case we need to provide three arguments:
- *URL path*, which holds the login form
- *POST parameters* for username/password
- A *failed/success login string*, which lets hydra recognize whether the login attempt was successful or not

Using the following example, the first parameter will be:
```
/login.php
```

With the second:
```
/login.php:[user parameter]=^USER^&[password parameter]=^PASS^
```

And the third:
```
/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:[FAIL/SUCCESS]=[success/failed string]
```

To make it possible for hydra to distinguish between successfully submitted credentials and failed attempts, we have to specify a unique string from the source code of the page we're using to log in. Hydra will examine the HTML code of the response page it gets after each attempt, looking for the string we provided. We can specify two different types of analysis that act as a Boolean value:

| **Type**    | **Boolean Value**    | **Flag**    |
|---------------- | --------------- | --------------- |
| `Fail`    | False    | `F=html_content` |
| `Success` | True | `S=html_content` |

If we provide a **fail** string, it will keep looking until the string is not found in the response. Another way is if we provide a **success** string, it will keep looking until the string is found in the response.

A **better strategy** is to pick something from the HTML source of the login page. What we have to pick should be very unlikely to be present after logging in, like the **login button** or the **password field**. For example, with the following code:
```html
  <form name='login' autocomplete='off' class='form' action='' method='post'>
```

We will use:
```
"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"
```

To get the POST parameters we can inspect the page with the browser or with Burp. For the following parameters:
```
username=admin&password=admin
```

It will be:
```bash
"/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

The final output will be:
```console
zero@pio$ hydra -C /usr/share/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <ip> -s <port> http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

---

# Personalized Wordlists

To create a personalized wordlist for the user, we will need to collect some information about them.

## CUPP 

With an easy installation:
```console
zero@pio$ sudo apt install cupp
```

We have an interactive option to run with `-i`, which will be asking us for entries:
```console
zero@pio$ cupp -i
```

## Usernames 

We can use the following Github, [Username Anarchy](https://github.com/urbanadventurer/username-anarchy), to generate wordlist of usernames from one word:
```console
zero@pio$ ./username-anarchy <word> > wordlist.txt
```

---

# Service Authentication Brute Forcing 

We simply have to provide the username/password wordlists, and add `service://SERVER_IP:PORT` at the end. As usual, we will add the `-u` `-f` flags.

## SSH Attack

When we run the command for the first time, hydra will suggest that we add the `-t 4` flag for a max number of parallel attempts, as many SSH limit the number of parallel connections and drop other connections, resulting in many of our attempts being dropped. Our final command should be as follows:
```console
zero@pio$ hydra -L <wordlist> -P <password> -u -f ssh://<ip>:<port> -t 4
```

## FTP Brute Forcing 

Similar to the SSH:
```console
zero@pio$ hydra -l <wordlist> -P <wordlist> ftp://<ip>
```


--- 

# Hydra Flags 

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-C`   | Combined Credentials Wordlist   |
| `-l` | Set the user |
| `-L` | Username wordlist |
| `-p` | Set the password |
| `-P` | Password wordlist |
| `-u` | Loop around users, not passwords |
| `-s <port>` | Target port |
| `-f` | Stop after the first successful try |
| `http-get` | Request method | 





















