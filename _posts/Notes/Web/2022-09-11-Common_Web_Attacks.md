---
title: Notes | Common Web Attacks
author: BatBato
date: 2022-09-11
categories: [Notes, Common Web Attacks]
tags: [Web, Common Web Attacks, XSS, XXE, IDOR, SQLi]
permalink: /Notes/Web/Common_Web_Attacks
---

# Common Web Attacks

The World Wide Web allows us to access a lot of information over the internet, whether it is a movie, your family pictures or your mail. This is also a very big battlefield between every kind of hackers. Here, we are going to talk about common web vulnerabilities such as Cross Site Scripting (```XSS```), XML External Entity (```XXE```), Insecure Direct Object Reference (```IDOR```) and SQL Injection (```SQLi```).

## XSS

XSS vulnerability result in the possibility for a user to execute Java Script code in the web page. This can change the content of the page or steal connection cookies, for example. You can find a basic exmplanation of XSS on [this video](https://www.youtube.com/watch?v=L5l9lSnNMxg). There are three different type of XSS :

- [Reflected XSS](/Notes/Web/Common_Web_Attacks#reflected-xss), where the malicious script comes from the current HTTP request.
- [Stored XSS](/Notes/Web/Common_Web_Attacks#stored-xss), where the malicious script comes from the website's database.
- [DOM-based XSS](/Notes/Web/Common_Web_Attacks#dom-based-xss), where the vulnerability exists in client-side code rather than server-side code.


### Reflected XSS

The most basic type of cross-site scripting is ```Reflected XSS```. It occurs when an application receives data from an HTTP request and unsafely incorporates that data into the immediate response.

A very simple example will be the following. Imagine a webpage that ask for the user name and execute the following ```GET``` request :
```console
https://insecure-website.com/search?name=bob
```

This request will then print ```Your name is : NAME``` where ```NAME``` will be replaced by the name given. If the website is vulnerable to ```Reflected XSS```, we could put a script as a name like :
```console
https://insecure-website.com/search?name=<script>JS_CODE</script>
```
You can replace ```JS_CODE``` by anything you want. A basic test could be :
```js
<script>alert(1)</script>
```

The ```alert``` JS function will create a pop-up that will display the text between the brackets. But as stated in [this video](https://www.youtube.com/watch?v=KHwVjzWei1c) of [LiveOverflow](https://www.youtube.com/c/LiveOverflow), the ```alert(1)``` isn't a good practice and can lead to false positive. A better way to test XSS could be the use of ```alert(document.domain)``` or ```alert(windows.origin)``` you could even use the ```console.log``` JS function.


### Stored XSS

```Second-order``` or ```persistent XSS```, often known as ```Stored XSS```, occurs when an application obtains data from an unreliable source and includes that data inadvertently in subsequent HTTP responses.

### DOM-based XSS

When client-side JavaScript in an application handles data from an untrusted source in an unsafe manner, typically by publishing the data back to the DOM, this is referred to as ```DOM-based XSS```, also known as ```DOM XSS```.
