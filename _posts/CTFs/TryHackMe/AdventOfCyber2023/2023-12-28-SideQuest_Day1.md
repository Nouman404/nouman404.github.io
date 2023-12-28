---
title: CTFs | TryHackMe | AdventOfCyber2023 | Side Quest Day 1
author: BatBato
date: 2023-12-28
categories: [CTFs, TryHackMe, AdventOfCyber2023, RDP]
tags: [RDP, Mimikatz, RDPReplay, Side Quest, THM]
permalink: /CTFs/TryHackMe/AdventOfCyber2023/SideQuest_Day1
---

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/dbe5f9cb-11bf-429f-9313-c22fbbb8285b)

In this challenge, we are given a wireshark capture called [VanSpy.pcapng](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/TryHackMe/AdventOfCyber2023/VanSpy.pcapng). When we open it with wireshark, we just see the following:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e1f1ea16-896f-48e5-ba04-1be032538c12)

The protocol `802.11` is the one used for Wifi communication. Because we don't have any other protocol, we guess that we have to crack the wifi password to recover the traffic. To do so, we are going to  export the hash of the Wifi password and crack it using hashcat. I found [this blog](https://www.cyberark.com/resources/threat-research-blog/cracking-wifi-at-scale-with-one-simple-trick) that explains a lot about Wifi attacks and in our case how to recover and crack the hash of the Wifi. First we run the following command:

```bash
hcxpcapngtool -o VanSpy.hash VanSpy.pcapng
```

We get some output like this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ed7a556a-44b0-4c1b-9745-98b45a869ded)

But what is interesting is that we recovered the hash of the Wifi in our text file:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4756abf7-badd-424b-abac-ba7de6327182)

We can now run hashcat on it like so:

```
hashcat -m 22000 VanSpy.hash /usr/share/wordlists/rockyou.txt 
```

> To know which mode to use with hashcat just go to the [hashcat website](https://hashcat.net/wiki/doku.php?id=example_hashes) and search for a similar-looking hash.
{: .prompt-info}

The password is pretty weak so we find pretty fast the clear text password `Christmas`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/65fdc8f7-a26c-461e-8134-0b7826ad8420)


We now have to specify it in our wireshark. To do so, we go to the `Edit` menu, then in `Preferences`, then in the `Protocols` subsection we search the protocol `IEEE 802.11` and specify the `Decryption Key`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2612b688-6eb5-4002-9da2-c6cec6c3c7c8)

We specify the key as follows:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ad189723-a80d-444f-a65f-11cc30eabdd5)

Now we can search in our Wireshark file as we would have done in a normal capture. We can search for `TCP`, `HTTP`, `FTP` traffic... After a bit of digging, we can see that there is a use of the port `4444`... Which is the default port for `Metasploit`... Should be interesting:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3d88f54c-f203-443a-85a4-ee54aa6543cf)

As we can see, there are a lot of `PSH, ACK`. This means that data are exchanged here. If we right click on on of them and select `Follow` > `TCP Stream` like this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/19ba63f8-a4da-476f-86a9-95d763c187c5)

We get the following result:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/86cea52c-dac6-4eb2-a02a-220f1433b713)

Mmmmh... Looks like a non-standard user we got here... What we see is that the user is running as `Administrator` and run [Mimikatz](https://github.com/gentilkiwi/mimikatz) commands to increase its privileges to `NT AUTHORITY\SYSTEM` and export the RDP certificate:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/0bb94434-53fd-4a5f-9929-72f0fa6a4281)

Thanks to our attacker, we get the content of the `LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx` certificate because he converted it to base64:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e2bd2f25-d19f-4938-9a70-6b8a914f3262)

For some reason converting the base64 directelly from the terminal didn't work so I used [Cyber Chef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=TUlJSnVRSUJBekNDQ1hVR0NTcUdTSWIzRFFFSEFhQ0NDV1lFZ2dsaU1JSUpYakNDQmVjR0NTcUdTSWIzRFFFSEFhQ0NCZGdFZ2dYVU1JSUYwRENDQmN3R0N5cUdTSWIzRFFFTUNnRUNvSUlFL2pDQ0JQb3dIQVlLS29aSWh2Y05BUXdCQXpBT0JBaUF3OWRaMHFndlVRSUNCOUFFZ2dUWWJNS25hMFlxSjFlTjNGR0tLVXRzb0NaQUo4S3piU0tNQmM4NnNDWmRVQkxzVHE4WjRzV25GZ1FpdEx0WElyRG5pb2FDOU42YWtnRzh4OHVMTFVuZG1UcmVOQWZRUmNMaUFMR0pvS2Y3OXJnUTZJNEJoNkZ6cGhOanV3Q0x6YXFOaWtuU0JXcUpSWjdOKy9HNzZIOWpMV3FOSWZ4ck1kdEFMOWRMZmJqOFpiN24wcndVSWI1V2QzaHJ6b3drOXRySWxQblNoa3V6eXl2QVNGSU9OTGNsci9TMlFrOHNuWjFJSS9LMmM4YzZMcXB1Y3NkRGI4QTdMcU04dU5kM1A4c0U4UlcrL3FEczkybU9XNmlSMWpFRUdBT0dsa0lLYmRMRkJYZFI2WHJhSzhpREh5Z3hjSEtiTTB6M05oNUJPbTNDMEpUS1RsVDMyWWh4cjlmUjZaTWR2RE9JcytIdjBiajJDV1h3R0ZEOHlkZXJpUm42N2NFdmhHdmJQcXFzbmNxZmsrNkxwbWp3Rk9Hbzh4d21oTk4xNXZTL0p0b29KMEVXQWV2akVKbWJSc29pSlBWRmE0d3FzRVprR2VVTXdFbEwzeFQxTmYwNko1N240cHRpSDlzeUNveVZDUW9KVTlRZ0RpSUVNS0JLcTZvRDZCSkZyVzM0aW83WitmMmloUzlIeldaeFAza2VZdmlsUHZldGFZbjVtTWhXZHJJVWxUOFpvQW4rNFhhWVhPSDBJZ1RobXh3S1lhY0VOYlgveS9RR1R3TlU5VU14STBuR1RUU0ZXamFmaTZDa1JFbVN3MklFeHdsQVlEOVVuc3dqOTNjT0hSdlpkU3N4Y3lEMjJRdzUxdDYyTGViMDBockdKSUxETUl3WHFpRlpBdHA0cnEvTS9KOHBjd2dTNW9qMFlUOFRTRWtOUFN3RmRUZXcrQWNEbXpEN3JQNkdWdmV4Z3hUZDM3V2RyUUJDTUszZTFla0VETTFGaGNFMEh0cHVUNWM5eTJJT3RzZ2tTQ2lJNm5YK09FMGxnZjlvbnBBUDJQQ25KdjhDSmY3Smw1dmRUc2tSRzcxc09hL1pSSXgyUU5jYnBlNWZtbWZweGlOYXRreStCdEZwY3FFb1VDWFpYWElQYXYwQjF1bWhRN0pEV1NrR2FKcENIWW1DZ3Z0cUVUSk1OSXQ2SzUvV1hoWWNQMi92aUIxbi9KRndGeVplczVFNnJ4YzdYdFJEYy9KMm43SGR1WVJ2MmlTbE54a0dLRmtpVER5ZUtDZXh0TzVsNzRaRnZOZXBhRnRUWkdsNE9KZ1lQWVRyREFUWWszQkpvc1ZRdU5oUE81b2p3ZGtmaHlRejJIRXpBZldVY29RZW1kZU51QzMwSmVDTVRyZ1o1ZmcvSG41MjlCQ09iR0NvdGtSOUZmQ0xTRG5KSnYvUjlWT2FCK1JNdGI1QjduZ1BHU3NDcjlNRVphMGtYQXpaZERGOS9lZWJZWXRPd3NqNnFMcnhjZ3hnWDY5a1ZZdGRKUVlTUDhOem9mOHliZG4yYlNJNThFNDRPUWtPRFVQSy9aWTJLN0FWTzZNcmVzYjBCKzJsOXZBMFBrZ2MxK1E0UFhpbHowaHhHUjVRckhqUHJ1YWZwcHp6d2l4QndhWERZZGl1RFB2MGFLMk5zcXgzOGRpdFRwQmpnanRWelZuTVBsZ3AzZUdPRUo5MzQ2ZkhNbWp4UmtybllNQnEyYmF3OXJkd0FSS0NieitSZzRqNEZGa2c1ckliK1h1MkxWSEpycjh0Y1VTck41emNCcDZBN01aMzB0UDRrR3VoeTB3SGpXR0dPeEVVTzNWTktqbndWRUF0UEYxNGtHM1ZINWNSZVFha0s4bDZEc20xM3lKWFFSbFhFNzNRL2w3N2pTYmZsZVNIcVQvTWxVNlFMdnNjdVFITHphbWNMVXI3U3IwQjZzelowcWRDbnZ2R0hTeFRGMGsrTitIMHU3dlRoZWdhR3VBRFRZOVZBTlNDb1pPVUx1KzIrSWxkaytBRUtpdzA1TGtXa3JjU1hlWGIzWHNJSWlYTktOVDIyaDUvZzRTaDdZbThodHhrSUJ0RnFSUEN2VWI2Mjk5dFd3RVhCVlhXNEVMWmhyaDZJVVV2RUVnUkV1NXE5TDk5cHRtY2Y1b2wvaW81dEttYVdmSlAzRUcwSjlIOVp4ZFNqcEFLeXRKR3J3WVBmY1ZJNVRHQnVqQU5CZ2tyQmdFRUFZSTNFUUl4QURBVEJna3Foa2lHOXcwQkNSVXhCZ1FFQVFBQUFEQW5CZ2txaGtpRzl3MEJDUlF4R2g0WUFGUUFVd0JUQUdVQVl3QkxBR1VBZVFCVEFHVUFkQUF4TUdzR0NTc0dBUVFCZ2pjUkFURmVIbHdBVFFCcEFHTUFjZ0J2QUhNQWJ3Qm1BSFFBSUFCRkFHNEFhQUJoQUc0QVl3QmxBR1FBSUFCREFISUFlUUJ3QUhRQWJ3Qm5BSElBWVFCd0FHZ0FhUUJqQUNBQVVBQnlBRzhBZGdCcEFHUUFaUUJ5QUNBQWRnQXhBQzRBTURDQ0EyOEdDU3FHU0liM0RRRUhCcUNDQTJBd2dnTmNBZ0VBTUlJRFZRWUpLb1pJaHZjTkFRY0JNQndHQ2lxR1NJYjNEUUVNQVFNd0RnUUlaUjV2Z2kxLzlUd0NBZ2ZRZ0lJREtNQU16SFBmTUxhdTdJWmF3TWhPZDA2QWNPMlNYUUZzWjNLeVBMUUdyRldjc3hFaVVERG1jalE1clpSeVNPYVJ5ejVQenlJRkNVQ0hjS3A1Y21sWUpUZEg0ZlNsZmFIeUM5VEtKcmRFdVQyUG44cHE5Qy9zbmp1RTIzTFU3MGMyVStOU1FocUF1bFVjQTY0ZVREeVBvNzRaMk9kUms1aklRMFkwaFlFL0YrRFNEYm4zSjJ0a2ZrbFN5dWZKbG9CUUFyNXAxZVpPL2xqNU9kWm16Q0hHUDlic0luS1gzY3VENXliejFLTU5QUWQvb0h1TUZIL0RCNzlaYU1vb2VyRmgyMlFVdHJ5M1pFZ01jaitDRTBIM0I2N3FUWDVOeUhWRHpaUm94WXJqVG94NWNPZkRqcm9aeC9MZmVTYmVpK0JDN2dCRksybERPVHA0TlhldkNPc1JKLzhPanB5aXpHSVVBaElLWVVaU3VnQWd3OHIzODdRaW1XSW1LWXJXZUxqMHJxWWwwUy8rRytIRXJRbTM4VnE2S3RnR2M5am1vTWJIRFh5azJQSzlJVjFHb3JTSitkbjNMRFRyenJCcG1zK2ZrTmp4SGg2a2UvNFVRaWk2dFBLRVduek55c3graHdNUk9MNVFPNWpacDY1OUhCbG9UbW8zc01QK2hvdUZRMlBGMTVXZDROci91am9EVFNWVUtCb1AwcSszVTF0SlEyallUUlp2dTRZQzJBOFJXWVNJNHZEcS8vaTIxeWtaSFE2SVhVOE9qWXBnc3V3dXBYcGR6cWd0NGpCQnBBbitxV083NDd4dzgrOFMvaHlxWWdBTUNwWk8xaDJub2xVc0ttYy9lajFCMlZIVDQrRHlRaTJ2THpTbGtpUmRZVE94eDNaL0liZUJpU2FZRUJ4UWJzK0tBTTRqTFNGTmdsbEhjRDhVZUpNUUpGWnlXWWVHNEN1Uk1iUzQrRDVRSDZuRit4STJOWnJxbElKcEk4QlhSNWd1aDJmeFZ3YzhQdzJXMXl0bUg4azI3Ry9aajV5TFFwd2p2K3pUbTFUU29MWXR6bG5mWThXcEtYbXRDT3lFQ3JDRTg3NUJ3WU9CSllCTFV5UTN2WWg3UCtUM3JFMDhsMllqYWNpL25hRXp0ZEUwSEJTczFOaFJIOWpRNFV2NGlJbHEvMlo5bFlSUnlkSTRGY0F3dC83cklqZW4vZUExWWNzd09UbVhsd2E0UHJ1dVBnY1ZneHVTTFMwYldXNWZQbWU4cG1WZzJmWGp0VTNaRVpQRkM0RmxpWVVtdHlOa01Ga1Y1djR2SXNNTUNwa3pGMGdtc1pYUS9CSWg1MzlPYXdVRkdlSW5KRTBCanFvZTA1TFh1dW1GM1BxWCtUS1FHLzJzLzhZRG1MVm5yVDJSTlBGV3pEdVFtTTFidWlCL1FDdndsbDRYa2JFd096QWZNQWNHQlNzT0F3SWFCQlI2ZnROSHlzODhaQ1l3ZmRQOExheFFyNVhmdHdRVXRiM2lrQlZDMU9KS3FYZG9vUzZZN3BoRXFjWUNBZ2ZR) to recover the original content of the file.

Now we have our `LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx` we should be able to recover the private key and decode the RDP traffic... But it seems like there is a password...

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ad29c3d2-91d1-4b3c-80c8-b5dd2c17d511)

After trying to crack it using `rockyou` (unsuccessful) I search on the internet for a way to recover it... All to get to know that it was... `mimikatz`...

So we run the previous command and specify the password as `mimikatz` and we get a pretty `server.pem` private key:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c913040a-939c-4f15-a2da-0dd93c515df3)

We can remove the header to just keep the part that starts with `-----BEGIN PRIVATE KEY-----` and we then specify it in the `Protocols` section (as we saw earlier) but this time in the `RDP` section:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d6d9c86e-7e48-4e55-94a3-8da6968c5a69)

> More information about RDP decryption can be found on this [hackingarticles](https://www.hackingarticles.in/wireshark-for-pentester-decrypting-rdp-traffic/) blog and this [paloaltonetworks](https://unit42.paloaltonetworks.com/wireshark-tutorial-decrypting-rdp-traffic/) one.
{: .prompt-info}

We then specify the IP address of the server (the one with the port `3389`), the port `3389`, the protocol `tpkt` and the path of the private key:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d3e3b2f2-f169-4b05-852e-ac1205548f87)

When we search for `RDP` in the search bar, we now have plenty of results:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c00de180-f281-4abf-ba97-b8b39193e546)

Here I was blocked... I tried to look at every packet, but didn't find anything... All the packets had non-printable characters so it was a dead end... Or was it ?
I then realised that RDP is like a video stream, so maybe we could recover this video ? I search for a tool that would do that and found this incredible tool [pyrdp](https://github.com/GoSecure/pyrdp). I also found this blog from [kalilinuxtutorials](https://kalilinuxtutorials.com/pyrdp/) that helped me understand how to use it.

So I exported the PDU by clicking on the `File` menu, then `Export PDUs to file` and we select `OSI Layer 7`. Now we have some `RDP` traffic without any colour:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a649ed55-c94b-4440-99f1-cae7e5665adf)

> A Protocol Data Unit (PDU) in Wireshark refers to a unit of data at the transport layer of a network protocol. When exported from Wireshark, a PDU capture typically contains the raw data exchanged between network devices during communication. PDUs are useful for analyzing and troubleshooting network issues, providing insights into the structure and content of data packets.
{: .prompt-info}

We then save it as a `pcap` file:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/94379ef5-afbd-4b2e-9ce5-9d79ecb50be9)

> Note that the format `pcap` is important. Using the default `pcapng` will not work for the tool `pyrdp`.
{: .prompt-warning}

I ran the `pyrdp` in a venv to have less trouble with dependencies. I ran the following commands:

```bash
python3 -m venv venv
cd pyrdp
pip3 install -U -e '.[full]'
cd ..
```

We then run the following command to export the `PDUs` in a format that `pyrdp` understands:

```bash
python3 pyrdp/pyrdp/bin/convert.py -o py_rdp_output export_pdu.pcap 
```

And we get this beautiful output:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f24c26f7-846f-4e84-9b85-e91514916ae7)

For some unknown reason the `pyrdp-player` wouldn't run when using its binary from the `venv` so I ran it from the docker like so:

```bash
sudo docker run -v "$PWD/py_rdp_output:/pwd" -e DISPLAY=$DISPLAY -e QT_X11_NO_MITSHM=1 --net=host gosecure/pyrdp pyrdp-player
```

We have this window that pops up:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a779aceb-b33a-40d9-ba89-9da89f22b5f9)

We go to the `File` > `Open` section and select in our folder the file called `[STRIP].pycap` and we open it:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/35da1d3d-1134-4408-ba6f-fb410d3ff26f)

> Note that we need to look in OUR directory. Because we are using the docker image, it is not in the default folder that is open when you get to this menu. You need to go in the `/pwd` folder because this is the name I gave in the docker command (`-v "$PWD/py_rdp_output:/pwd"`).
{: .prompt-danger}

We get this window that is AWESOME!!! Let me explain. Now, we have the full replay of the `RDP` communication that went through the wireshark capture. And what is fantastic is that we have the key pressed by the user and also the content of the clipboard!!!

We now just have to press play and wait for the answers to come to us:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d4e7f562-7235-4b93-9ba8-828f507ea557)

And we now have the key to validate the challenge.
