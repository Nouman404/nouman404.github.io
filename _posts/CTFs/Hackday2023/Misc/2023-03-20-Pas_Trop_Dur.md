---
title: CTFs | HackDay2023 | Pas_Trop_Dur
author: BatBato
date: 2023-03-20
categories: [CTFs, HackDay2023, Pas_Trop_Dur]
tags: [CTF, HackDay2023, Misc]
permalink: /CTFs/Hackday2023/Misc/Pas_Trop_Dur
---

# Pas_Trop_Dur

In this chall, we are given a [Wireshark communication](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/Hackday2023/Misc/chall.pcapng) and the goal is to find the password used by the hacker on its malicious file.

When we filter the HTTP packet we can see a "maliciouswebshell.php".

![image](https://user-images.githubusercontent.com/73934639/226461574-3c0e24c0-9da9-4d84-9249-32433e8a3173.png)

When we try to download it, we get a lot of unprintable characters:
![image](https://user-images.githubusercontent.com/73934639/226462228-b02a9d9e-b254-4f67-9d14-6f8fff2b72ef.png)

We see a lot of strings that look like base64, but... aren't the "==" at the end ?

![image](https://user-images.githubusercontent.com/73934639/226462482-61107ee7-061a-46b6-a8e6-b8493e7d8d18.png)

Using the basic regex ```"[=0-9a-zA-Z]+"``` on your favourite code editor you can recover all the base64 strings. This regex means that I am looking for every string that is between quotes and that contain at least one character that should be a letter (upper or lower case), a number or an equal sign (the "+" means "at least once").

You can save the result in a file and remove every quote. Then you can use the linux command ```cat yourfile | rev | base64 -d > maliciouswebshell.php```. This will save the web page source code in the "maliciouswebshell.php". We first need to reverse the string (```rev``` command) because the we noticed that the ```==``` was at the beginning but in base64 they should be at the end.

You can find the file [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/Hackday2023/Misc/maliciouswebshell.php).
Now that we have the code we need to understand it. 

> We can host it locally with the php command ```php -S localhost:8080```
{: .prompt-tip}

The form sends itself (```onsubmit="return login(this)"```) to the ```login``` function. We now check this function. This function directly call the ```addEncKey``` function. The code of the function is the following:
```js
		function addEncKey(form){
			var encKey = document.createElement("input");
			encKey.type = "hidden";
			pref = ENCKEY.substr(0, PRELEN);
			encKey.name = pref.split("").reverse().join("") + pref;
			encKey.value = btoa(ENCKEY);
			form.appendChild(encKey);
			return form;
		}
```
What we need to understand is that it gives the field name pref and its reverse. So ```encKey.name``` is just a palindrome and the ```encKey.value``` is a base64 of ```ENCKEY``` which was at first base64 decoded, so we have in it the initial value that you can find at the top of the file.

After that, the ```login``` function calls the ```setValue``` and ```setName```. We are just going to look at the value because it is what we are inputting.
```js
		function setValue(str){
			return btoa(xorStr(str));
		}
```
So this is not a big function and it only xor the string and base64 encode it. There is a ```getValue``` function in the file so we don't need to reinventing the wheel. Now is we try to intercept the request with burp, wen we send the string ```a``` we have the result ```Lg==```.
![image](https://user-images.githubusercontent.com/73934639/226467954-682c02ca-da93-45ca-998c-3779a675b9fc.png)

So we know that we can reverse this value with the ```getValue``` function. To do that, we can use the console of our browser (press F12 > Console).
![image](https://user-images.githubusercontent.com/73934639/226468224-960bf0b9-2cb4-4757-bfb5-6eb4dc578f37.png)

Now that we know how to reverse a given string we need to find the password the hacker used. Getting back to Wireshark, when we inspect the TCP of the penultimate ```maliciouswebshell.php``` we can find the cookies like before. The first one of these packets is not the good one but the second one gives us the password:

![image](https://user-images.githubusercontent.com/73934639/226469312-3a0c4829-2585-489e-80fa-48834798edb1.png)

![image](https://user-images.githubusercontent.com/73934639/226469263-fffa096d-3a9f-4a29-a80b-19b822c50896.png)

The flag was ```HACKDAY{Wabbajack12345678}```.

