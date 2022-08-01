---
title: Notes | Broken Authentication
author: Zeropio
date: 2022-07-31
categories: [Notes, Web]
tags: [brute-force, auth]
permalink: /notes/web/broken-auth
---

Authentication is defined as **the act of proving an assertion**. The most widespread authentication method used in web applications is **login forms**, where a user enters their username and password to prove their identity. Authentication is probably the most widespread security measure, and it is the first line of defense against unauthorized access. During the authentication phase, the entity who wants to authenticate sends an **identification string** that could be an ID, a username, email, along with additional data.

There are some types of authentication:

## Multi-Factor Authentication 

**Multi-Factor Authentication**, commonly known as **MFA** (or **2FA** when there are just two factors involved), can result in a much more robust authentication process. These factos can be:
- something the user **knows**
- something the user **has**
- something the user **is**

When an authentication process requires the entity to send data that belongs to more than one of these domains, it should be considered an MFA process. Single Factor Authentication usually requires something the user knows: **username** and **password**.

## Form-Based Authentication 

The most common authentication method for web applications is **Form-Based Authentication** (**FBA**). Some web apps require the user to pass through multiple steps of authentication, for example the username, password and then a **One-time Password** (**OTP**). 

## HTTP Based Authentication 

Many applications offer **HTTP-based** login functionality. All HTTP authentication schemes revolve around the **401 status code** and the **WWW-Authenticate** response header and are used by application servers to challenge a client request and provide authentication details (Challenge-Response process). When using HTTP-based authentication, the Authorization header holds the authentication data and should be present in every request for the user to be authenticated.

## Other Forms of Authentication 

While uncommon, it is also possible that authentication is performed by checking the source IP address. Modern applications could use third parties to authenticate users, such as SAML. Also, APIs usually require a specific authentication form, often based on a multi-step approach. Attacks against API authentication and authorization, Single Sign-On, and OAuth share the same foundations as attacks against classic web applications.

---

Authentication attacks can take place against a total of three domains. These three domains are divided into the following categories:
- The **HAS** domain
- The **IS** domain
- The **KNOWS** domain

## Attacking the HAS Domain 

The has domain looks quite plain because we either own a hardware token or do not. Things are more complicated than they appear, though:
- A badge could be **cloned** without taking it over
- A cryptographic algorithm used to generate One-Time Passwords could be **broken**
- Any physical device could be **stolen**

A long-range antenna can easily achieve a working distance of 50cm and clone a classic NFC badge. Multiple people are within reach to perform such a cloning attack every day.

## Attacking the IS Domain 

If a person relies on *something* to prove their identity and this *something* is compromised, they lose the unique way of proving their identity since there is no way one can change the way they are. Retina scan, fingerprint readers, facial recognition have been all proved to be breakable. All of them can be broken through a third-party leak, a high-definition picture, a skimmer, or even an evil maid that steals the right glass.

## Attacking the KNOWS Domain

This domain refers to things a user knows, like a username or a password. And is the one we will be working with.

--- 

# Login Bruteforcing

## Default Credentials 

It is common to find devices with **default credentials** due to human error or a breakdown in/lack of proper process. In the [cirt](https://www.cirt.net/passwords) web there is a database of default credentials. [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv) has also a list based on CIRT. Another list is [SCADA](https://github.com/scadastrangelove/SCADAPASS/blob/master/scadapass.csv). Also don't forget about the classic **admin:admin** and **admin:password**.

It should be noted that we may not find default or known credentials for every device or application inside the lists mentioned above and databases. In this case, a Google search could lead to very interesting findings. It is also common to come across easily guessable or weak user accounts in custom applications. This is why we should always try combinations such as: **user:user**, **tech:tech**.

## Weak Bruteforce Protections 

There are many different security mechanisms designed to prevent automated attacks. For example:
- **CAPTCHA**
- **Rate Limits**

### CAPTCHA 

CAPTCHA is a widely used security measure named after the Completely Automated Public Turing test to tell Computers and Humans Apart sentence, can have many different forms. As developers, we should not develop our own CAPTCHA but rely on a well-tested one and require it after very few failed logins. Always check the source code, to find some way to bypass the CAPTCHA.

### Rate Limiting 

Another standard protection is rate-limiting. Having a counter that increments after each failed attempt, an application can block a user after three failed attempts within 60 seconds and notifies the user accordingly. 

A standard brute force attack will not be efficient when rate-limiting is in place. When the tool used is not aware of this protection, it will try username and password combinations that are never actually validated by the attacked web application. In such a case, the majority of attempted credentials will appear as invalid (**false negatives**). Most standard rate-limiting implementations that we see nowadays impose a delay after N failed attempts. For example, a user can try to log in three times, and then they must wait 1 minute before trying again. After three additional failed attempts, they must wait 2 minutes and so on.

### Insufficient Protections 

When an attacker can tamper with data taken into consideration to increase security, they can bypass all or some protections. For example, changing the **User-Agent** header is easy. Some web applications or web application firewalls leverage headers like **X-Forwarded-For** to guess the actual source IP address. This is done because many internet providers, mobile carriers, or big corporations usually *hide* users behind NAT. Blocking an IP address without the help of a header like **X-Forwarded-For** may result in blocking all users behind the specific NAT.

A simple vulnerable example could be:
```php
<?php
// get IP address
if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']))[0];
} else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_CLIENT_IP']))[0];
} else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['REMOTE_ADDR']))[0];
}

echo "<div>Your real IP address is: " . htmlspecialchars($realip) . "</div>";
?>
```

The plugin’s developers introduced a security improvement that would block a login attempt from the same IP address. Unfortunately, this security measure could be bypassed by crafting an **X-Forwarded-For** header. For example like:
```
"X-Forwarded-For": "1.2.3.4"
```

## Bruteforcing Usernames 

**Username enumeration** is frequently overlooked, probably because it is assumed that a username is not private information.  The same username is oftentimes reused to access other services such as FTP, RDP and SSH, among others. Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. 

### Error Message

One way to enumerate usernames is if we can see the response message after submitting a non-existent username stating that the entered username is unknown. Also, if we can see the response message after submitting a valid username (and a wrong password) stating that the entered username exists, but the password is incorrect.

When a failed login occurs, and the application replies with *Unknown username* or a similar message, an attacker can perform a brute force attack against the login functionality in search of a, *The password you entered for the username X is incorrect* or a similar message. [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames) provides a wide range of usernames. Or some tools like [Username Anarchy](https://github.com/urbanadventurer/username-anarchy). 

We can use some tools like Burp, wfuzz, fuff,...

### Timing Attack 

Sometimes a web application may not explicitly state that it does not know a specific username but allows an attacker to infer this piece of information. Some web applications prefill the username input value if the username is valid and known but leave the input value empty or with a default value when the username is unknown. Carefully inspect responses watching for differences in both HTTP headers and the HTML source code.

There are timing attacks, where we can guess which user exits base on the time the web respond to them. [Here](https://academy.hackthebox.com/storage/modules/80/scripts/timing_py.txt) are an example provide by HackTheBox.

### Enumerate through Password Reset 

Reset forms are often less well protected than login ones. Like we have already discussed, an application that replies with a *You should receive a message shortly* when a valid username has been found and *Username unknown, check your data* for an invalid entry leaks the presence of registered users. 

### Enumerate through Registration Form 

By default, a registration form that prompts users to choose their username usually replies with a clear message when the selected username already exists or provides other “tells” if this is the case.

One interesting feature of email addresses that many people do not know or do not have ready in mind while testing is sub-addressing. This extension, defined at [RFC5233](https://datatracker.ietf.org/doc/html/rfc5233), says that any `+tag` in the left part of an email address should be ignored by the **Mail Transport Agent** (**MTA**) and used as a tag for sieve filters. This means that writing to an email address like `zeropio+hack@pm.me` will deliver the email to `zeropio@pm.me` and, if filters are supported and properly configured, will be placed in folder **hack**. Very few web applications respect this RFC, which leads to the possibility of registering almost infinite users by using a tag and only one actual email address. 

### Predictable Usernames 

While uncommon, you may run into accounts like **user1000**, **user1001**. It is also possible that *administrative* users have a predictable naming convention, like **support.it**, **support.fr**, or similar.

## Bruteforcing Passwords 

After having success at username enumeration, an attacker is often just one step from the goal of bypassing authentication, and that step is the user’s password.

### Policy Inference 

The chances of executing a successful brute force attack increase after a proper policy evaluation. Knowing what the minimum password requirements are, allows an attacker to start testing only compliant passwords. Trying to use the username as a password, or a very weak password like **123456**, often results in an error that will reveal the policy (or some parts of it) in a human-readable format. Usually this policy is:
- owercase characters, like **abcd..z**
- uppercase characters, like **ABCD..Z**
- digit, numbers from **0 to 9**
- special characters, like **,./.?!** or any other printable one (space is a char)

It is possible that an application replies with a *Password does not meet complexity requirements* message at first and reveals the exact policy conditions after a certain number of failed registrations. This is why it is recommended to test three or four times before giving up. The same attack could be carried on a password reset page. When a user can reset her password, the reset form may leak the password policy (or parts of it).

The command below will work with **rockyou.txt**. This command finds lines have at least one uppercase character (`'[[:upper:]]'`), and then only lines that also have a lowercase one (`'[[:lower:]]'`) and with a length of 8 and 12 chars (`'^.{8,12}$'`) using extended regular expressions (`-E`).:
```console
zero@pio$ grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$'
```

You can try with the following table:

| **Password** | **Lower** | **Upper** | **Digit** | **Special** | **>=8chars** | **>=20chars** |
|---------------- | --------------- | --------------- | ---------- | ------------ | ---------- | ---------- |
| `qwerty` | ✅ | ⬜️ | ⬜️ | ⬜️ | ⬜️ | ⬜️ |
| `Qwerty` | ✅ | ✅ | ⬜️ | ⬜️ | ⬜️ | ⬜️ |
| `Qwerty1` | ✅ | ✅ | ✅ | ⬜️ | ⬜️ | ⬜️ |
| `Qwertyu1` | ✅ | ✅ | ✅ | ⬜️ | ✅ | ⬜️ |
| `Qwert1!` | ✅ | ✅ | ✅ | ✅ | ⬜️ | ⬜️ |
| `Qwerty1!` | ✅ | ✅ | ✅ | ✅ | ✅ | ⬜️ |
| `QWERTY1` | ⬜️ | ✅ | ✅ | ⬜️ | ⬜️ | ⬜️ |
| `QWERT1!` | ⬜️ | ✅ | ✅ | ✅ | ⬜️ | ⬜️ |
| `QWERTY1!` | ⬜️ | ✅ | ✅ | ✅ | ✅ | ⬜️ |
| `Qwerty!` | ✅ | ✅ | ⬜️ | ✅ | ⬜️ | ⬜️ |
| `Qwertyuiop12345!@#$%` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## Predictable Reset Token

Reset tokens are secret pieces of data generated mainly by the application when a password reset is requested. If you forgot your password, you could reset it by answering these questions again. We can consider these answers as tokens too.

### Reset Token by Email

If an application lets the user reset her password using a URL or a temporary password sent by email, it should contain a robust token generation function. However, developers often implement their own functions that may introduce logic flaws and weak encryption or implement security through obscurity.

### Weak Token Generation

Some applications create a token using known or predictable values, such as local time or the username that requested the action and then hash or encode the value. This is a poor security practice because a token doesn't need to contain any information from the actual user to be validated and should be a pure-random value. We should try to brute force any weak hash using known combinations like time+username or time+email when a reset token is requested for a given user. Take for example this PHP code:
```php
<?php
function generate_reset_token($username) {
  $time = intval(microtime(true) * 1000);
  $token = md5($username . $time);
  return $token;
}
```

An attacker that knows a valid username can get the server time by reading the Date header (which is almost always present in the HTTP response). The attacker can then brute force the $time value in a matter of seconds and get a valid reset token.

### Short Tokens 

Another bad practice is the use of short tokens. Probably to help mobile users, an application might generate a token with a length of 5/6 numerical characters that sometimes could be easily brute-forced. In reality, there is no need to use a short one because tokens are received mainly by e-mail and could be embedded in an HTTP link that can be validated using a simple GET.

If we wanted to perform a brute force attack against the abovementioned application’s tokens, we could use wfuzz. Specifically, we could use a string match for the case-sensitive string Valid (`--ss "Valid"`). Or we could use a *reverse match* by looking for any response that does not contain Invalid token using `--hs "Invalid"`. For example:
```console
zero@pio$ wfuzz -z range,00000-99999 --ss "Valid" "https://<TARGET>/token.php?user=admin&token=FUZZ"
```

### Weak Cryptography

Even cryptographically generated tokens could be predictable. It has been observed that some developers try to create their own crypto routine, often resorting to security through obscurity processes. Rolling your own encryption is never a good idea. To stay on the safe side, we should always use modern and well-known encryption algorithms that have been heavily reviewed.

### Reset Token as Temp Password 

It should be noted that some applications use reset tokens as actual temporary passwords. By design, any temporary password should be invalidated as soon as the user logs in and changes it. It is improbable that such temporary passwords are not invalidated immediately after use. That being said, try to be as thorough as possible and check if any reset tokens being used as temporary passwords can be reused.

---

#

### Weak Cryptography

Even cryptographically generated tokens could be predictable. It has been observed that some developers try to create their own crypto routine, often resorting to security through obscurity processes. Rolling your own encryption is never a good idea. To stay on the safe side, we should always use modern and well-known encryption algorithms that have been heavily reviewed.

### Reset Token as Temp Password 

It should be noted that some applications use reset tokens as actual temporary passwords. By design, any temporary password should be invalidated as soon as the user logs in and changes it. It is improbable that such temporary passwords are not invalidated immediately after use. That being said, try to be as thorough as possible and check if any reset tokens being used as temporary passwords can be reused.

---

# Password Attacks 

By **authentication credentials handling**, we mean how an application operates on passwords (password reset, password recovery, or password change). Speaking about typical web applications, users who forget their password can get a new one in three ways when no external authentication factor is used:
- By requesting a new one that will be sent via email by the application
- By requesting a URL that will allow them to set a new one
- By answering prefilled questions as proof of identity and then setting a new one

## Guessable Answers 

Often web applications authenticate users who lost their password by requesting that they answer one or multiple questions. Those questions, usually presented to the user during the registration phase, are mostly hardcoded and cannot be chosen by them. They are, therefore, quite generic.  It is common to find questions like the below.
- *What is your mother's maiden name?*
- *What city were you born in?*

## Username Injection

When trying to understand the high-level logic behind a reset form, it is unimportant if it sends a token, a temporary password, or requires the correct answer. At a high level, when a user inputs the expected value, the reset functionality lets the user change the password or pass the authentication phase. The function that checks if a reset token is valid and is also the right one for a given account is usually carefully developed and tested with security in mind. An example of vulnerable code looks like this:
```php
<?php
  if isset($_REQUEST['userid']) {
	$userid = $_REQUEST['userid'];
  } else if isset($_SESSION['userid']) {
	$userid = $_SESSION['userid'];
  } else {
	die("unknown userid");
  }
```

We can modify our request (for example in a password change) to the **userid** of other account. For example adding the **userid** during the request, even if doesn't appear.

---

# Session Attacks

## Bruteforcing Cookies 

### Cookie token tampering 

Like password reset tokens, session tokens could also be based on guessable information. Often, homebrewed web applications feature custom session handling and custom cookie-building mechanisms to have user-related details handy. Whether a user is an admin, operator, or basic user, this is information that can be part of the data used to create the cookie.

### Remember me token 

We could consider a **rememberme** token as a session cookie that lasts for a longer time than usual. **rememberme** tokens usually last for at least seven days or even for an entire month. 

### Encrypted or encoded token 

Cookies could also contain the result of the encryption of a sequence of data. Of course, a weak crypto algorithm could lead to privilege escalation or authentication bypass, just like plain encoding could. Always checking for magic bytes when you have a sequence of bytes that looks like junk to you since they can help you identify the format, [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures) has a list of file signatures. Or using [Decodify](https://github.com/s0md3v/Decodify). 

### Weak session token 

Even when cookies are generated using strong randomization, resulting in a difficult-to-guess string, it could be possible that the token is not long enough. This could be a problem if the tested web application has many concurrent users, both from a functional and security perspective. We could try to brute force a session cookie. The time needed would depend on the length and the charset used to create the token itself. Given this is a guessing game, we think a truly incremental approach that starts with **aaaaaa** to **zzzzzz** would not pay dividends. That is why we prefer to use **John the Ripper**, which generates non-linear values, for our brute-forcing session. With **wfuzz**, we can try bruteforcing it:
```console
zero@pio$ john --incremental=LowerNum --min-length=6 --max-length=6 --stdout| wfuzz -z stdin -b COOKIE=FUZZ --ss "Welcome" -u http://<target>
```

## Insecure Token Handling 

One difference between cookies and tokens is that cookies are used to send and store arbitrary data, while tokens are explicitly used to send authorization data. A token should expire after the user has been inactive for a given amount of time, for example, after 1 hour, and should expire even if there is activity after a given amount of time, such as 24 hours. If a token never expires and an attacker could try to brute force a valid session token created in the past.

### Session Fixation 

One of the most important rules about a cookie token is that its value should change as soon as the access level changes. This means that a guest user should receive a cookie, and as soon as they authenticate, the token should change. The same should happen if the user gets more grants during a sudo-like session. If this does not occur, the web application, or better any authenticated user, could be vulnerable to **Session Fixation**. A simple example could be a web application that also sets **SESSIONID** from a URL parameter like this:
```
https://brokenauthentication/view.php?SESSIONID=anyrandomvalue
```

### Token in URL

Until recent days, it was possible to catch a valid session token by making the user browse away from a website where they had been authenticated, moving to a website controlled by the attacker. The **Referer** header carried the full URL of the previous website, including both the domain and parameters and the webserver would log it. However, it could still be an issue if the web application suffers from a **Local File Inclusion** vulnerability or the **Referer-Policy** header is set in an unsafe manner.

### Session Security 

If a cookie contains only a random sequence, an attacker will have a tough time. On the other side, the web application should hold every detail safely and use a cookie value just as an id to fetch the correct session.

### Cookie Security 

Most tokens are sent and received using cookies. Therefore, cookie security should always be checked. The cookie should be created with the correct path value, be set as httponly and secure, and have the proper domain scope. An unsecured cookie could be stolen and reused quite easily through **Cross-Site Scripting** (XSS) or **Man in the Middle** (MitM) attacks.

