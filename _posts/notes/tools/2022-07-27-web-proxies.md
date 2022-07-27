---
title: Notes | Web Proxies
author: Zeropio
date: 2022-07-27
categories: [Notes, Tools]
tags: [proxy]
permalink: /notes/tools/web-proxies
---

Web proxies are specialized tools that can be set up between a browser/mobile application and a back-end server to capture and view all the web requests being sent between both ends, essentially acting as man-in-the-middle (MITM) tools. This are the following uses for Web Proxies:
- Web application vulnerability scanning
- Web fuzzing
- Web crawling
- Web application mapping
- Web request analysis
- Web configuration testing
- Code reviews

---

# Web Proxy

## Setup

In order to a fast change between proxies, we must use the extension **FoxyProxy**, which allow us make different proxy profiles. Set the configuration to `127.0.0.1:8080`, because **Burp** and **ZAP** uses that port to capture requests.

Now install the CA Certificate, to avoid errors while doing HTTPS requests. Select the Burp's proxy and navigate to `http://burp` to download it. For the ZAP's Certificate go to `Tools > Options > Dynamic SSL Certificate` and save it. Now navigate to [about:preferences#privacy](about:preferences#privacy) to see the certificates. Import the new ones, trusting them.

## Intercepting Web Requests 

For Burp, in the `Proxy` tab, the `Intercept` sub-tab. Now load the page we want to intercept, we will see all the request there.

![Proxy Burp](/assets/img/notes/tools/burp_intercept_htb_on.jpg)

ZAP interception is off by default. We can see at the top (green means is off). Clicking or with `ctrl + b` we can turn on/off.

![Proxy ZAP](/assets/img/notes/tools/zap_intercept_htb_on.jpg)

ZAP also has a feature called **HUD** (Heads Up Display) which allows us to control ZAP's features within the pre-configured browser. We can enable it in the following button:

![Button ZAP](/assets/img/notes/tools/zap_enable_HUD.jpg)

### Manipulating Intercepted Requests 

Take for example a web that ping a IP. This will be the request from the page:
```html
POST /ping HTTP/1.1
Host: 46.101.23.188:30820
Content-Length: 4
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://46.101.23.188:30820
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://46.101.23.188:30820/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

ip=1
```

If we change the input (`...=1`) by a command, for example `ip=; ls;` we are injecting commands on the web console.

## Intercepting Responses

In some instances, we may need to intercept the HTTP responses from the server before they reach the browser.

In Burp, we can enable response interception by going to (`Proxy>Options`) and enabling **Intercept Response** under **Intercept Server Responses**:

![Burp Responses](/assets/img/notes/tools/response_interception_enable.jpg)

Refresh the page and check the intercepted response. We can know modify the code and click on `Forward` to send that page. It also has some features, which can be enabled in `Proxy > Options > Response Modification`, where we can select `Unhide hidden form fields`.

For ZAP, once we intercept the request, click on `Step`. It will send the request and intercept the response. Now we can modify it and click on `Continue`.

## Automatic Modification

In Burp we have the option in `Proxy > Options > Match and Replace`, click on `Add` and we can, through a regex, find some pattern and modify it. Once we enter the above options and click `Ok`, our new Match and Replace option will be added and enabled and will start automatically replacing.

ZAP has a similar option called `Replacer`, which can be accessing pressing `ctrl + b`. It is similar as Burp. ZAP also provides the option to set the **Initiators**. Initiators enable us to select where our **Replacer** option will be applied. We will keep the default option of `Apply to all HTTP(S) messages to apply everywhere`.

## Repeating Requests 

In Burp, we can go to `Proxy > HTTP History` to see previous request and responses intercepted. In ZAP HUD we can find at the bottom as **History**.

Once we localize the request we want to repeat, press `ctrl + r` to send it to the **Repeater**. We can navigate there directly with `ctrl + shift + b`. There, we can click on `Send` to send the request. In ZAP, we can right click on it and select `Open/Resend with Request Editor`, which allows us to send it.

## Encoding/Decoding 

As we modify and send custom HTTP requests, we may have to perform various types of encoding and decoding to interact with the webserver properly.

### URL Encoding 

Inside of Burp, select the text and right click on it, select `Convert Selection > URL > URL encode key characters` or simply press `ctrl + u`. Burp also supports URL-encoding as we type if we right-click and enable that option, which will encode all of our text as we type it. On the other hand, ZAP should automatically URL-encode all of our request data in the background before sending the request, though we may not see that explicitly. 

There are other types of URL-encoding, like **Full URL-Encoding** or **Unicode URL encoding**.

### Decoding 

It is very common for web applications to encode their data, so we should be able to quickly decode that data to examine the original text. The following are some of the other types of encoders supported by both tools:
- HTML
- Unicode
- Base64
- ASCII hex

To access the full encoder in Burp, we can go to the **Decoder** tab. In ZAP, we can use the **Encoder/Decoder/Hash** by pressing `ctrl + e`. we can also use the **Burp Inspector** tool to perform encoding and decoding, which can be found in various places like **Burp Proxy** or **Burp Repeater**.

### Encoding 

The same options can be used for encoding as well.

## Proxying Tools

One very useful tool in Linux is **proxychains**, which routes all traffic coming from any command-line tool to any proxy we specify. To use proxychains, we first have to edit `/etc/proxychains.conf`{: .filepath}, comment the final line and add the following two lines at the end of it:
```bash
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
https 127.0.0.1 8080
```

We should also enable **Quiet Mode** to reduce noise by un-commenting `quiet_mode`. For example, a cURL with proxychains:
```console
zero@pio$ proxychains curl http://<ip>
```

Now our tools will intercept the request. For nmap we have a option:
```console
zero@pio$ nmap --proxies http://127.0.0.1:8080 SERVER_IP
```

The same goes for Metasploit, where we can add a proxy:
```console
msf6 auxiliary(...) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080
```

---

# Web Fuzzer 

## Burp Intruder 

Right click on the request and send it to the Intruder or press `ctrl + i`. Go to the Intruder clicking on it or with `ctrl + shift + i`. On the first tab, **Target**, we see the details of the target we will be fuzzing, which is fed from the request we sent to Intruder.

The second tab, **Positions**, is where we place the payload position pointer, which is the point where words from our wordlist will be placed and iterated over. We will need to select **DIRECTORY** as the payload position, by either wrapping it with § or by selecting the word **DIRECTORY** and clicking on the the `Add $` button:

![Img](/assets/img/notes/tools/burp_intruder_position.jpg)

> **DIRECTORY** can be any word
{: .prompt-info}

The final thing to select in the target tab is the **Attack Type**. The attack type defines how many payload pointers are used and determines which payload is assigned to which position.

On the third tab, **Payloads**, we get to choose and customize our payloads/wordlists. We can specify different types of payload, generate our own or upload some payloads from Internet.

We can also encode the payload.

