---
title: Notes | Password Cracking
author: BatBato
date: 2022-08-25
categories: [Notes, Brute Force]
tags: [Brute Force, Passwords, Credentials, Cracking]
permalink: /Notes/Brute_Force/Password_Cracking
---

# Password Cracking

We are now in an era where password that you will find will not be in clear text and ready to use (most of the time). They will be "hashed". You may have heard terms like "hash", "hash functions", "cracking a hash"... But what does it mean ? First of all, what is a hash function ? A hash function is, as its name suggests, a mathematical function that generates a string (list of characters). This generated string is called a hash. Let's call the hash function "f" and "x" is the password that we want to hash. Then we get ```f(x)=y``` where "y" is the hash. What's cool about hashes it's that we can't reverse the function. This means that with "y" we can't find "x" even if we know "f". The other cool thing about hash functions is that whatever you put on it (our "x"), you will always have a different result. Let's take a concrete example. MD5 is an old hash function, we are going to hash ```password``` and ```password1``` with it :

```console
MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
MD5("password1") = 7c6a180b36896a0a8c02787eeafb0e4c
```

As you can see, we have used as input two strings that only have one difference but the two hashes are completely different. That's why hashing function are used instead of encoding. Because we can reverse encoding.

We often hear people saying "I cracked the hash" and you will tell me, "But how is it possible if we can't reverse it?". The first method (that you will never use) is to try any possible combination like "a", "b"..."aa", "ab"... This method takes too much time. What we will do instead is using a list containing many passwords that have been used by real people in the past and are likely to be used again. The word list we are going to use is called ```rockyou``` and contains 14 million passwords but we can use others depending on the country the victim is and/or create our own wordlists. 

> The rockyou file is located at ```/usr/share/wordlists/rockyou.txt```. If you haven't a ```.txt``` file you may have a ```.tar.gz``` file that you can unzip with the command ```tar -xf rockyou.tar.gz```. You can download it from [here](https://github.com/praetorian-inc/Hob0Rules) for example.
{: .prompt-tip }

> Wikipedia : "In December 2009, the RockYou company experienced a data breach resulting in the exposure of over ```32 million user accounts```. The company used an unencrypted database to store user account data, including ```plaintext passwords```. They also did not allow using special characters in the passwords. The hacker used a ```10-year-old SQL vulnerability``` to gain access to the database. The company took days to notify users after the incident, and initially incorrectly reported that the breach only affected older applications when it actually affected all RockYou users.The full list of passwords exposed as a result of the breach is ```available in Kali Linux```, and has been since its launch in 2013. Due to its easy attainability and comprehensive length, it is commonly ```used in dictionary attacks```"
{: .prompt-info }


## Hashcat

Of course you can create your own python script to "crack" the hash. But here we aregoing to see how to use already available tools.
Let's beggin with ```hashcat``` which is an advanced CPU-based password recovery utility.

> You can install ```hashcat``` with the following command : ```sudo apt install hashcat```
{: .prompt-info }

The basic hashcat command looks like this : ```hashcat -m MODE HASH|HASHFILE DICTIONARY```. Where ```MODE``` will be a number that tells hashcat which hashing algorithm was used. ```HASH``` or ```HASHFILE``` represents the hash string or a file containing one or more hash. ```DICTIONARY``` will be our dictionary (ex: ```rockyou```).

### Mode 

To know which mode to use you need to know which hash algorithm was used (MD5, SHA, NTLM...). The first option will be to use already existing tools such as ```hash-identifier``` or ```hashid```. There are many other tools that you can use but we will talk about this two here.

To use ```hash-identifier``` you only need to type ```hash-identifier``` in your terminal and once it's done you need to give a hash. Let's use the MD5 hash of "password":

```console
└─$ hash-identifier                                                               
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 5f4dcc3b5aa765d61d8327deb882cf99

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
```

As you can see the tool tells you that the most possible hash type is ```MD5```. Some times, this tools can give you false positive so try another hash type if the first hash type is not the good one.

To use ```hashid``` you only need to type ```hashid HASH``` in your terminal. Let's use the MD5 hash of "password":

```console
└─$ hashid 5f4dcc3b5aa765d61d8327deb882cf99
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
```

> You can use the ```-m``` flag to show hashcat mode for each hash type with ```hashid``` like : ```hashid HASH -m```
{: .prompt-tip }

When you know the hash type you can ```CTRL+F``` the hash name on [this site](https://hashcat.net/wiki/doku.php?id=example_hashes) to know which mode to use.
The number in the first column is the hash type. You can also ```CTRL+F``` to search for patterns, for example ```sha512crypt``` always begin with ```$6$``` so if you search for this string you will get the hash type ```1800```.

### Cracking

Now that we know that ```MD5``` is the mode ```0```, we can try to recover the password.

```console
└─$ hashcat -m 0 5f4dcc3b5aa765d61d8327deb882cf99 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

5f4dcc3b5aa765d61d8327deb882cf99:password                 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 5f4dcc3b5aa765d61d8327deb882cf99
Time.Started.....: Mon Aug 29 12:12:44 2022 (0 secs)
Time.Estimated...: Mon Aug 29 12:12:44 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    94480 H/s (0.25ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> oooooo
Hardware.Mon.#1..: Util:  7%

Started: Mon Aug 29 12:12:38 2022
Stopped: Mon Aug 29 12:12:46 2022
```

So how you can see, the status is ```Cracked``` and the password is printed just before the big block beginning with the ```Session``` section as ```HASH:PASSWORD```

### Rules

COMMING SOON

## John The Ripper

Just like ```hashcat``` ```John The Ripper``` also known as ```john``` is a password cracking tool. You can use ```john``` as follows:
```john HASHFILE``` or ```john --wordlist=WORDLIST HASHFILE```. You don't need to specify the type of hash but it's preferable to do so because if not it will take more time. You can use it like this 
```console
john hash.txt --format=raw-md5 --wordlist=wordlist.txt
```

> You can install ```John``` with the following command : ```sudo apt install john```
{: .prompt-info }
> You can see all formats with the command ```john --list=formats```. I advise you to grep the type you are looking for like ```john --list=formats | grep -iF "md5"```
{: .prompt-tip }

John can also be used to crack files protected with a password. We are going to see how to crack some.

### John and RSA key

```SSH keys``` can be used to connect to a server without passwords. Thank's to this an attacker can't connect to the server if he doesn't have the key. To increase the security, we can add a ```password``` to the SSH key. John allows us to crack this password. 

1. 
```console
python  /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
```
2. 
```console
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

The first step put the password hash in a file called ```id_rsa.hash```. The second step try to crack it. You can now connect to the victim machine with the command and then provide the password for the ssh key: 
```ssh -i id_rsa user@IP```

### Unshadow

If you arrive on a machine and can access the ```passwd``` and the ```shadow``` file, this can be leveraged to get the password of any user (if their hash can be cracked). The ```unshadow``` command is a Linux command that allows us to combine the passwd and the shadow files. It can be used like this : ```unshadow passwd shadow > unshadowed.txt```. We can now try to crack the passwords of each user with the following command :


```console
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```

### Zir and RAR files

You can encounter zip or rar files protected with a password. As for the SSH key, we will proceed in two steps. First we recover the hash of the password and then we crack it.

#### Zip

```console
zip2john crack2.zip > zip.hashes
```

```console
john zip.hashes
```
or
```console
john --wordlist=wordlist.txt zip.hashes
```


#### Rar

```console
rar2john crack.rar > zip.hashes
```

```console
john --wordlist=wordlist.txt zip.hashes
```

### More John functionalities

There are many more type of files that john can crack here are some more examples :
```
bitlocker2john
dmg2john
eapmd5tojohn
gpg2john
hccap2john
keepass2john
putty2john
racf2john
rar2john
raw2dyna
uaf2john
vncpcap2john
wpapcap2john
zip2john
```
