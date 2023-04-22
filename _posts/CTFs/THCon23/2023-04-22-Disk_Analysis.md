---
title: CTFs | THCon23 | Disk_Analysis
author: BatBato
date: 2023-04-22
categories: [CTFs, THcon23, Disk_Analysis]
tags: [CTF, THCon23, Disk_Analysis, testdisk]
permalink: /CTFs/THCon23/Disk_Analysis
---

# Disk Analysis

For this challenge, we have a zip file containing a ```ReadMe.md``` and a ```suspectDisk.raw```. The ```ReadMe.md``` file tells us:

```
#Context
Our informations are that a flag is hidden on this disk. However, we have trouble finding it. Can you help us ?
```

## Setup

First of all, we need to create a mounting point so that we can mount the raw file on it and being able to read its content. I did the following:

```bash
sudo losetup -f --show ./suspectDisk.raw
sudo mkdir /mnt/THCon23
sudo mount /dev/loop0 /mnt/THCon23
```

> The first command returned ```/dev/loop0``` so this is what I used in the last one.
{: .prompt-info}


## Recover Deleted Files [ TestDisk ]

Now we need to use [TestDisk](https://www.kali.org/tools/testdisk/) to read the content of the ```raw``` file we just mounted. Just run ```testdisk``` and select ```No Logs```.

Now you can select your mounted device.

![image](https://user-images.githubusercontent.com/73934639/233797319-dfcadaed-0c2c-4f65-89f4-75ece6353f3e.png)

Then we can select ```None```.

![image](https://user-images.githubusercontent.com/73934639/233797378-926d6a66-abf1-4341-a594-85698bc48a20.png)

> We can see at the bottom that ```TestDisk``` advise us to use ```None```.
{: .prompt-tip}


We can now list the content of the mounted device:

![image](https://user-images.githubusercontent.com/73934639/233797455-1cd12c37-74c5-45e6-9e93-431dc4ebe6a3.png)

In the ```Content``` directory we can see that there is a ```LetsDoIt``` folder that was deleted. We can list its content and we find a folder with the password of the zip it contains:

![image](https://user-images.githubusercontent.com/73934639/233797507-a76262fb-1723-4197-9f05-37a9a28241e1.png)

We can now download the zip file using the capital ```C``` on it:

![image](https://user-images.githubusercontent.com/73934639/233797549-313062fa-2943-4d0d-a054-1c0779544594.png)

You can select any folder where you want to save it. I choosed the root folder of my working directory.
As we can see, the file was saved using the same tree structure:

![image](https://user-images.githubusercontent.com/73934639/233797639-427581e4-c5c8-414b-978c-fa3ced211ec1.png)

## Finding the flag

When looking at the tree structure of the zip file once unzipped...

![image](https://user-images.githubusercontent.com/73934639/233797754-4752c960-5a74-41dc-a556-b4975ec6d338.png)


We can look for a file with "flag" in it:

![image](https://user-images.githubusercontent.com/73934639/233797805-c1fa6735-c9dc-4925-a08b-d67206542a15.png)


Well...There are a few... I tried to look if there were a folder or a file with a specific name like ```.txt``` file or a file that isn't a ```.png``` file but didn't find anything. I then wondered... "How is the chall created ???" and I thought that the tree structured was created with all the shitty images and then the flag was put in a specific folder. I then tried to look for the last modified file and:

![image](https://user-images.githubusercontent.com/73934639/233797979-87fe9247-2f21-4797-971d-829bdcc910ad.png)


![image](https://user-images.githubusercontent.com/73934639/233797992-f54228c0-82a9-4f06-b2b8-cbc5e38f8c4f.png)

> To remove the created folder and the mounted device you can use the following commands: ```sudo umount /mnt/disk_thcon``` and ```sudo losetup -d /dev/loop0```.
{: .prompt-tip}
