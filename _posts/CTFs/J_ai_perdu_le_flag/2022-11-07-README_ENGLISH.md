---
title: CTFs | HackDay | J'ai perdu le flag English
author: BatBato
date: 2022-11-07
categories: [CTFs, HackDay, J'ai perdu le flag]
tags: [CTF, HackDay, Stegano]
permalink: /CTFs/HackDay/Stegano/J_ai_perdu_le_flag_English
---

# WriteUp CTF HackDay : J'ai perdu le flag

We start this challenge with a *johnnix* folder and a zip *johnHacked.zip* as shown below.

![image](https://user-images.githubusercontent.com/73934639/164445255-afb931e6-c79f-45c3-bd89-703bdf6be187.png)

The zip is protected by a password. So we go to the *johnnix* folder which contains a lot of text files. The text files don't seem to be important except for some base64 encoded strings.

![image](https://user-images.githubusercontent.com/73934639/164445865-88a78daf-2471-48b3-9495-d116bbe87aaa.png)

In this folder there is an image of the logo of the event. So we go to [aperisolve](https://aperisolve.fr). We are told that the image contains a *Readme* file. We extract it with **steghide** without using passwords.

![image](https://user-images.githubusercontent.com/73934639/164446356-3e11759e-cf00-4730-97a4-40d70079f1f3.png)

The text is available [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/J_ai_perdu_le_flag/readme).\
I feel like the challenge is in two parts, OSINT and retrieving the words from each file. I start a quick search for this *john nix* without success. So I create a script to retrieve the **first word of line 24 of the following files :\
682910xecoz\
537w3zly33p\
u3ow02q3r77\
2i64pvpe639\
99u6ov4n2p2\
b0448gpzn49\
n68ktas0402\
fkz90adazd1**

The result is as follows:

![image](https://user-images.githubusercontent.com/73934639/164447762-1012d31f-0edd-4308-979a-985cacf4ea51.png)

I have the impression that we'll have to go back to doing OSINT.\
At the end of the file, there is the name and surname of the person who wrote the file, but also his email **mailto@john.nix@gmx.fr**.\
So I send an e-mail to dear John and .... gets an automatic answer:

![image](https://user-images.githubusercontent.com/73934639/164448862-9d441085-0382-4111-8407-cbcefe7f6e72.png)

Instagram and LinkedIn links don't work... But the Twitter does!

![image](https://user-images.githubusercontent.com/73934639/164449403-077a4e41-16c5-4daf-8f5d-b03074372125.png)

We go to the mega link and download a ".wav" file.
My first reflex (after listening to this sweet melodious sound) is to use [sonic visualizer](https://www.sonicvisualiser.org/download.html) which is very useful for audio CTF challenges. We add a spectrogram and ... taddaaaaa :

![image](https://user-images.githubusercontent.com/73934639/164449972-4d97366b-6e06-4515-8da3-ded32570ad41.png)

The zip password... or not. In fact, it is the name of a file. We go to the 24th line of the file and the first word is :
```NzQgOTcgNjggMTExIDgyIDEwMSA3NiA5NyA4MyAxMTYgMTAxIDEwMyA5NyAxMTAgMTExIDM1IDEwOSAxMDggMzYgNDkgMzYgMTAyIDEwMSA1NiA5OSAxMDEgNTUgNTQgOTcgNTMgNDk=```

For this part the [CyberChef](https://gchq.github.io/CyberChef/) tool can help.
This text is obviously base 64 encoded which gives us once decoded : \
```74 97 68 111 82 101 76 97 83 116 101 103 97 110 111 35 109 108 36 49 36 102 101 56 99 101 55 54 97 53 49```  

This new text is obviously base 10 encoded which gives us once decoded : ```JaDoReLaStegano#ml$1$fe8ce76a51```

Bingo the password of the zip!

We unzip it and we get ... 19 new images.
I put the 1st one in aprerisolve and there is a file that can be extracted with steghide without password, same for the 2nd and the 3rd...
I create a script to automate all this and ... back to square one. Texts, an image of Rick and a readme which says to us:

```
Hey ! Tu y es presque ...
Encore un peu de recherche :)

🎶 NEVER GONNA GIVE YOU UP 🎶 
🎶 NEVER GONNA LET YOU DOWN 🎶
```

I put the image *ImRick.jpg* in aperisolve and ... it contains another file (fkz90adazd1_) containing the string: ```fnB0Jnh7Kkx0K3doekllY2JwREhfPUNO```

Again base64 which gives us : ```~pt&x{*Lt+whzIecbpDH_=CN```

The tool [dcode](https://www.dcode.fr/identification-chiffrement) can be useful for this part.
I try to find the encoding of this string and the ROT47 gives us a rather satisfactory result : ```OAEUILY{EZH9Kx643Asw0lr}```

Well, it's not the flag but it looks like it.

From there we have two options:
1. We have already decoded the base64 strings of the previous files containing the false flags
2. We haven't done it

If we have done it we see that the false flags are of the form **HackFlag[xxx]**. We test to decode with vigenère and the key *HACKFLAG* and ... END. We have the flag.

Otherwise we can guess it. We test for example the key HACKDAY and we obtain : ```HACKFLA{XZF9Au643Aup0lp}```

From there, either we brute force the key of the form *HACK** or we use *HACKFLA* and ... END... ah no the flag **HACKDAY{XZF9As643Psp0lp}** does not work. After a little thought we try *HACKFLAG* and then we have the right flag.



