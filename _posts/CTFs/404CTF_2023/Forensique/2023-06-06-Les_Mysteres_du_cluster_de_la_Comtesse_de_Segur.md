---
title: CTFs | 404CTF_2023 | Forensique | Les Mystères du cluster de la Comtesse de Ségur
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Forensique]
tags: [Forensique,K8s]
permalink: /CTFs/404CTF_2023/Forensique/Les_Mysteres_du_cluster_de_la_Comtesse_de_Segur
---

# Les Mystères du cluster de la Comtesse de Ségur

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3e915de2-fe7b-4935-9a91-9a95fb98fbd4)

For this challenge, we need to recover the flag from a folder containing information about a cluster.

When looking at the files, we see a folder `checkpoint`.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/551d93ab-af71-4f1f-b0f6-8ef4bec6e16d)

A checkpoint folder is a directory in Kubernetes where checkpoint information is stored for a particular application or process. The checkpoint folder is a crucial part of Kubernetes stateful applications, as it enables applications to restart from where they left off in case of a failure or a system crash. The checkpoint folder typically contains metadata, state information, and any other necessary resources required to restore the application's state. This folder is usually located on a persistent volume, which enables it to survive pod and node restarts. It is worth noting that the location of the checkpoint folder may vary depending on the Kubernetes setup. However, it is usually specified in the pod's YAML configuration file or through a command-line argument. In summary, the checkpoint folder is a vital component in Kubernetes stateful applications, as it provides the necessary information required to restore an application's state in case of a failure or system crash.

When we take a closer look at the files in this `checkpoint` folder, we see a lot of `.img` files:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b16108fe-0427-4fb4-976c-d039035c696d)

Using a basic `sudo grep -iRl 404ctf .` command to find any file that may contain this string (case insensitive with the `-i`) we find only one file:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a0800c0c-bd50-4dd2-85a3-763e6162db85)

We can look at what we found by using the `grep` command piped with the `string`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4db590ea-0e4b-4f07-a187-cc19f2140c30)

We see that a zip file is uploaded using the cURL command on the domain `agent.challenges.404ctf.fr`. When we open the zip file, we can see two files:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a0d3d858-e208-4554-9b8f-ef34bf2591cb)

The agent file is a Linux executable that need to be run on K8s and the `flag.txt` gives us what we are looking for: `404CTF{K8S_checkpoints_utile_pour_le_forensic}`
