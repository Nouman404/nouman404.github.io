---
title: Notes | Enumeration Web
author: Zeropio
date: 2022-04-27
categories: [Notes, Web]
tags: [enumeration]
permalink: /notes/web/enumeration-web
---

The information gathering phase is the first step in every penetration test where we need to simulate external attackers without internal information from the target organization. During this process, our objective is to identify as much information as we can from the following areas:
- **Domains** and **Subdomains**
- **IP Ranges**
- **Infraestructure**
- **Virtual Hosts**

The gathering process can be divided in two categories:
- **Passive information gathering**: we collect publicly available information using search engines, whois, certificate information,...
- **Active information gathering**: we directly interact with the target at this stage.

---

# Passive Information Gathering 

## WHOIS 

It is a TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default. We can use it for querying databases containing domain names, IP addresses, or autonomous systems and provide information services to Internet users. More info [here](https://datatracker.ietf.org/doc/html/rfc3912). The Whois database is a searchable list of all domains currently registered worldwide.

We can use it in web-based tools or with the Linux command `whois` (there is a Windows version, `whois`):
```console
zero@pio$ whois <target>
```

## DNS 

The **Domain Name System** (**DNS**) is an excellent place to look for data to identify particular targets.

### Nslookup and DIG

The command-line utility `nslookup` with `dig` could be really helpful for identifying DNS:
```console
zero@pio$ nslookup <target>
```

We can also specify a nameserver if needed by adding `@<nameserver/IP>` to the command. Unlike nslookup, DIG shows us some more information that can be of importance:
```console
zero@pio$ dig facebook.com @1.1.1.1
```

To search for **A record**:
```console
zero@pio$ nslookup -query=A <target>
zero@pio$ dig a <target> @<ip>
```

For **PTR records**:
```console
zero@pio$ nslookup -query=PTR <target>
zero@pio$ dig -x <target> @<ip>
```

For ANY records:
```console
zero@pio$ nslookup -query=ANY <target>
zero@pio$ dig any <target> @<ip>
```

> The more recent [RFC8482](https://datatracker.ietf.org/doc/html/rfc8482) could limit ANY query.
{: .prompt-alert}

For TXT records:
```console
zero@pio$ nslookup -query=TXT <target>
zero@pio$ dig txt <target> @<ip>
```

For MX records:
```console
zero@pio$ nslookup -query=MX <target>
zero@pio$ dig mx <target> @<ip>
```

Usually, organizations rely on **ISPs** and hosting provides that lease smaller netblocks to them. We can combine some of the results gathered via nslookup with the whois database to determine if our target organization uses hosting providers.

---

# Passive Subdomain Enumeration

## VirusTotal 

VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them. To receive information about a domain, type the domain name into the search bar and click on the **Relations** tab.

## Project Sonar 

Rapid7's Project Sonar is a security research project that conducts internet-wide surveys across various services and protocols to gather insight into worldwide vulnerability exposure. The information collected is made public to facilitate security research. We can made the request with cURL to the API:
```
https://sonar.omnisint.io/subdomains/{domain} - All subdomains for a given domain
https://sonar.omnisint.io/tlds/{domain}       - All tlds found for a given domain
https://sonar.omnisint.io/all/{domain}        - All results across all tlds for a given domain
https://sonar.omnisint.io/reverse/{ip}        - Reverse DNS lookup on IP address
https://sonar.omnisint.io/reverse/{ip}/{mask} - Reverse DNS lookup of a CIDR range
```

For example, to find all the subdomains from a target:
```console
zero@pio$ curl -s https://sonar.omnisint.io/subdomains/<target> | jq -r '.[]' | sort -u
```

To find others TLDs (Top Level Domain):
```console
zero@pio$ curl -s https://sonar.omnisint.io/tlds/<target> | jq -r '.[]' | sort -u
```

To find result among all the TLDs:
```console
zero@pio$ curl -s https://sonar.omnisint.io/all/<target> | jq -r '.[]' | sort -u
```

## Certificates 

Another interesting source of information we can use to extract subdomains is SSL/TLS certificates. We can use [Censys](https://search.censys.io/certificates) or[crt.sh](https://crt.sh/). We can also use cURL to search:
```console
zero@pio$ curl -s "https://crt.sh/?q=<target>&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u
```

We can also use `openssl`:
```console
zero@pio$ openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "<target>:<port>" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

## Automating Passive Subdomain Enumeration 

We can use [theHarvester](https://github.com/laramies/theHarvester) to an automatic search for emails, names, subdomains, IP addresses, and URLs. We can create the following sources list, this are a wide range of webpages where we can gatherer information:
```
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

With this **theHarvester** will work:
```console
zero@pio$ cat sources.txt | while read source; do theHarvester -d "<target>" -b $source -f "${source}_<target>";done
```

Now we can manipulate the json file as output, for example extracting all the subdomains:
```console
zero@pio$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "<target>_theHarvester.txt"
```

---

# Passive Infrastructure Identification 

We can use some webpage as [Netcraft](https://www.netcraft.com/) or [Wayback Machine](https://web.archive.org/). It also has a command-line utility:
```console
zero@pio$ waybackurls -dates <target>
```

---

# Active Infrastructure Identification 

## Web Servers 

We need to discover as much information as possible from the webserver to understand its functionality, which can affect future testing. The first thing we can do to identify the webserver version is to look at the response headers:
```console
zero@pio$ curl -I 'http://<target>'
```

We should look also to others headers like:
- `X-Powered-By header`: this header can tell us what the web app is using (like PHP, ASP, .NET, JSP, ...)
- `Cookies`: we can gather information about the format. For example:
  - **.NET**: `ASPSESSIONID<RANDOM>=<COOKIE_VALUE>`
  - **PHP**: `PHPSESSID=<COOKIE_VALUE>`
  - **JAVA**: `JSESSION=<COOKIE_VALUE>`

Other important tool could be **whatweb**. For example:
```console
zero@pio$ whatweb -a3 http://<target> -v
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-a<number>` | Aggression level |
| `-v` | Verbosity |

[Wappalyzer](https://www.wappalyzer.com/) is a must have tool. And [wafw00f](https://github.com/EnableSecurity/wafw00f) to check for WAFs.
```console
zero@pio$ wafw00f -v https://<target>
```

[Aquatone](https://github.com/michenriksen/aquatone) is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking and screenshot. This is helpful, especially when dealing with huge subdomain lists.
```console
zero@pio$ cat subdomain_list.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```

When it finished it will create a file called **aquatone_report.html**.

---

# Active Subdomain Enumeration

## ZoneTransfers 

The zone transfer is how a secondary DNS server receives information from the primary DNS server and updates it. The master-slave approach is used to organize DNS servers within a domain, with the slaves receiving updated DNS information from the master DNS. The master DNS server should be configured to enable zone transfers from secondary (slave) DNS servers, although this might be misconfigured.

We can utilize the [HackerTarget Zone Transfer](https://hackertarget.com/zone-transfer/) service. For a manual usage, first identify the nameserver:
```console
zero@pio$ nslookup -type=NS <target>

...
Non-authoritative answer:
zonetransfer.me	nameserver = sub.zero.pio.
```

Perform the Zone Transfer with `type=any` and `-query=AXFR`:
```console
zero@pio$ nslookup -type=any -query=AXFR <target> sub.zero.pio.
```

We can use **Gobuster** with the **SecLists**.

---

# Virtual Hosts 

A virtual host (**vHost**) is a feature that allows several websites to be hosted on a single server. There are two ways to configure virtual hosts:
- **IP**-based virtual hosting: different servers can be addressed under different IP addresses on this host
- **Name**-based virtual hosting: distinction for which domain the service was requested is made at the application level 

We can test it sending a cURL with a different host:
```console
zero@pio$ curl -s http://<target> -H "Host: randomtarget.com"
```

With the wordlist `/usr/share/SecLists/Discovery/DNS/namelist.txt`{: .filepath} we can fuzz for vHosts:
```console
zero@pio$ ffuf -w ./vhosts -u http://<target> -H "HOST: FUZZ.<target>" -fs <bytes>
```

---

# Cloud Resources 

The use of cloud, such as AWS, GCP, Azure, and others, is now one of the essential components for many companies nowadays. There are often vulnerabilities between Amazon (AWS), Google (GCP), and Microsoft (Azure). We can use the Google Dorks `inurl:` and `intext:` to narrow our search to specific terms: `intex:<EXAMPLE> inurl:amazonaws.com` or `intext:<EXAMPLE> inurl:blob.core.windows.net`.

With the help of some tools like [GrayHat](https://buckets.grayhatwarfare.com/) we can make a faster enumeration. Sometimes, this page can contain leaked SSH keys.


---

# Other

## Webpages 

| **Link**   | **Description**    |
|--------------- | --------------- |
| **WHOIS** |
| [Whois](https://whois.domaintools.com/) | WHOIS web-based |
| **Certificates** |
| [Censys](https://search.censys.io/certificates) | Certificate searcher |
| [crt.sh](https://crt.sh/) | Certificate searcher |
| **General Enumeration** |
| [netcraft](https://sitereport.netcraft.com/) | To enumerate technology |
| [robtex](https://www.robtex.com/) | To get more DNS information |
| [reverseip](https://viewdns.info/reverseip/) | To get reverse ip information |
| [HackerTarget](https://hackertarget.com/) | Major tools |
| [Domain Glass](https://domain.glass/) | DNS Record, IP address hostname, and WHOIS |
| [GrayHat Buckets](https://buckets.grayhatwarfare.com/) | Cloud information |



## Tools

| **Link**   | **Description**    |
|--------------- | --------------- |
| [Knock Subdomain Scan](https://github.com/guelfoweb/knock) | Dictionary to guess subdomains |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | List subdomains |

## Tips

> To check if a webpage has php we can add to the url **index.html** and **index.php**.
{: .prompt-tip }
