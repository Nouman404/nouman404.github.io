---
title: CTFs | 404CTF_2023 | Cloud | Harpagon et le magot
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Cloud]
tags: [Cloud,Helm, K8s]
permalink: /CTFs/404CTF_2023/Cloud/Harpagon_et_le_magot
---

# Harpagon et le magot

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1fef3805-7904-40a9-a4a6-2cd14eb7e3b5)

For this challenge, we are given an `ssh` connection to a server. The hint we are given is that `Harpagon n'est pas très doué et n'a jamais réussi à utiliser sa cassette.`. Which means that we need to do something with a `cassette`.

## What is Helm

To reach the flag, we need to use `Helm`. 

`Helm` is a powerful package manager for `Kubernetes` that facilitates the deployment and management of applications and services. It simplifies the process of `installing`, `upgrading`, and `managing` complex applications on Kubernetes clusters. With `Helm`, you can package your applications into charts, which contain all the necessary configurations, dependencies, and Kubernetes manifests. These charts can be easily shared and reused, fostering collaboration within the Kubernetes community. Helm also enables effective configuration management, allowing you to customize deployments for different environments. It provides a straightforward way to update or roll back applications, ensuring smooth updates and minimizing downtime. Overall, Helm enhances productivity, promotes consistency, and streamlines application management on Kubernetes.

> Note that you could have guessed the use of `Helm` because when you connect to the server, you see information links to `K3s`, `Kubectl` and `Helm`.
{: .prompt-info}

## Basic Enumeration

We now try some basic Helm command like `helm list`. This command allows us to get all the available charts:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c4f1105e-a36c-421e-8cd6-86fa6ce50207)


As we can see, and could have guessed, there is one chart named `cassette`, as in the hint. We can get more information about it by running the command `helm history cassette`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/526c4aec-abeb-47b2-9c8f-4db60eaee036)

> The `helm history` command provides information about the revision history of a release in Helm. When you deploy or upgrade a chart, `Helm` creates a new revision of that release. 
{: .prompt-info}

## Exploitation

We can see that there are two `revisions` for the release `cassette`. The first one is `superseded` and the second one is `deployed`. A release is marked as `superseded` when a new revision of the release is deployed, effectively replacing the previous revision. This typically happens when you upgrade or roll back a release. The superseded revision is still stored in the release history, allowing you to `roll back` to it if needed.A release is marked as `deployed` when it represents the currently active or running revision of the release. It indicates that this particular revision is the one currently in use.

So as stated in the definition, we can `roll back` to the `superseded` revision. To do so, run the command `helm rollback cassette 1`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/fee48dfe-55f8-44e8-b094-963715dc0f86)


As shown in the above screenshot, the message `Rollback was a success! Happy Helming!` shows us that everything went  well. We can now get information about the register using the command `helm get all cassette`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a6e5d4d9-2aa6-45a3-a563-3ae1d900770c)


The command gives us a lot of result, but we got the flag in the `adminToken`. If you went from the bottom of the output, you may have encountered the base64 encoded version of the flag `fWVtMXRjaXZfN3MzX2wxXzduMGRfdUAzbGZfMV83czNfM2MxcjR2QGx7RlRDNDA0` but using the `echo "fWVtMXRjaXZfN3MzX2wxXzduMGRfdUAzbGZfMV83czNfM2MxcjR2QGx7RlRDNDA0" | base64 -d` gives us the same result as the previous decoded flag. We just need to use the `rev` tool on the terminal to recover the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3592f341-d38f-4168-bf66-9223b698d857)

The flag is `404CTF{l@v4r1c3_3s7_1_fl3@u_d0n7_1l_3s7_vict1me}`.

