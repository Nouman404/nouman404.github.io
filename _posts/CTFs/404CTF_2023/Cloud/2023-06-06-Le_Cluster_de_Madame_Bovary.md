---
title: CTFs | 404CTF_2023 | Cloud | Le Cluster de Madame Bovary
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Cloud]
tags: [Cloud,K8s,kubctl,Pods]
permalink: /CTFs/404CTF_2023/Cloud/Le_Cluster_de_Madame_Bovary
---

# Le Cluster de Madame Bovary 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/deb117f6-5de2-4588-9b0a-35fde4b1b190)

For this challenge, we are given a virtual machine. When we arrive on the machine we first run the `kubctl` command to find pods:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c2de7d4f-c5f0-4a12-8d29-3439db73076c)

As we can see, there is one pod `agent`. A Pod in Kubernetes is the smallest deployable unit that represents a running process. It can contain one or more containers that share the same network and storage resources. Pods are used to encapsulate and manage containers, providing an abstraction layer for scheduling, scaling, and managing applications within a Kubernetes cluster.

We can access the pod and find an executable in the `/opt` folder:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9125e2f6-4bbd-4238-a005-236b18875f55)

If we try to run it, we get the same result as if we ran the command `kubctl logs agent`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/bf01d08a-331e-49fe-b2ce-b7dd3f2adf3c)

When looking at docker hub, we can find this container [here](https://hub.docker.com/r/404ctf/the-container). We can't just use it on our own machine because we get an error for not running it on Kubernetes (K8s). So I created a script to deploy a pod that will deploy this container:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: thecontainer404
  namespace: 404ctf
spec:
  replicas: 1
  selector:
    matchLabels:
      app: thecontainer404
  template:
    metadata:
      labels:
        app: thecontainer404
    spec:
      containers:
        - name: thecontainer404
          image: 404ctf/the-container
```

> I specified the namespace `404ctf` because if you don't, you will get an error saying that the container desn't run on the correct namespace (`err: not in namespace 404ctf`). To create it, run the command `kubectl create namespace 404ctf`
{: .prompt-info}

We can deploy our pod using the command:

```bash
kubectl apply -f deployment.yml 
```

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/cdf60b1d-b1b0-4a18-ba4e-3696cff89dfb)

We now can access the pod using the command `kubectl exec -it deployment.apps/thecontainer404 --namespace=404ctf -- sh`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e67cbc91-7e0d-40ce-9567-c5537e9ae7eb)

> Don't forget the `--namespace=404ctf`. If you do, you will get an error saying that the pod wasn't found.
{: .prompt-warning}

When executing `/opt/the-container`, we get several errors that we can correct:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e2d0f803-be64-4125-8279-4f459392fadf)

We have the first half of the flag `404CTF{A_la_decouv`. We know now that the rest of the flag is in the container `404ctf/web-server`. We do the same steps as before and once on the machine we find a `Go` program for a webserver:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/0fff8320-1a19-4f5a-82de-eca784655d02)

We can read the content of `web-server.go` and find the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/30332e45-5290-463a-90b8-0beb4015b31a)

Or just request it with the cURL command:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a45973f1-865f-4268-8d06-d6542eecafa7)

The complete flag is then: `404CTF{A_la_decouverte_de_k8s}`


