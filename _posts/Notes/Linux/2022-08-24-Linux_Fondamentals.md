---
title: Notes | Linux Fondamentals
author: BatBato
date: 2022-08-24
categories: [Notes, Linux]
tags: [Linux]
permalink: /Notes/Linux/Linux Fondamentals
---
# Linux Fondamentals

First of all, why learn Linux? Well, when it comes to computing, Linux is a very useful operating system. It has many useful tools and offers high performance on different networks, it is light, FREE and much more...

You may say, "OK, now I need to use Linux but which one ? There are many distributions like Ubuntu, Debian, Arch...". And you are right, there is a lot of distribution. But the one you chose doesn't really matter. Personally I like to advise using Kali Linux (a debian fork), because there is a lot of tools pre-installed on it. But don't fall for it and try leaning all the tools or worst, trying to use them without understanding what they are used for. 

For the next part, I'm going to assume that you have downloaded a virtual machine tool as VMWare or Virtualbox and installed Kali Linux on it [here is a tuto on how to install kali on Virtualbox](https://www.youtube.com/watch?v=l97dVIKlmVg).

Most of the time in Linux OS (Operating System), we are going to use the terminal. Which, once launched, look like this :

## The console / Terminal

```console
┌──(kali㉿kali)-[~/Desktop]
└─$ 
```
Let's break this down. This tells you that your current user is kali (the first one), that the host name (name of the machine) is kali (second one), that you are in the directory located at ```~/Desktop``` and that you are a regular user (the ```$``` sign). If you were an administrator (called ```root```) on Linux, then you should have a ```#``` instead of the ```$```.

> From now I will use the notation ```└─$ COMMAND```. Don't write ```└─$``` in your terminal, just write the command.
{: .prompt-warning }

## Directories

On Linux, we begin the directories at the root ```/```. There is nothing before. Any user on the machine has a "home directory" which is located at ```/home/username```. So if your name is "bob" then your home directory is located at ```/home/bob```. Your home directory can also be written as ```~/``` it's the same as ```/home/username```.

## Basic commands

Commands are what we are going to use in the terminal instead of the mouse. I'm going to show you some basic commands and useful combination but you can find cheat sheet on the internet [like this one](https://cheatography.com/davechild/cheat-sheets/linux-command-line/).

First we may want to see what's in our curent directory. We are going to use the ```ls``` command.
```console
└─$ ls
test_dir  test_file
```

Here we see a file and a directory. You can tell this thank's to the name or by the colour (in the terminal you may have different colours for the files and directories). But what if we want to be sure the an object called ```my_directory``` is really a directory ? Then you can use the ```-l``` option. And I advise you to combine it with the ```-a``` option so that they show you also the hidden files. Hidden files are named like this : ```.name```.

```console
└─$ ls -la                                      
total 20
drwxr-xr-x  3 kali kali 4096 Aug 24 18:15 .
drwxr-xr-x 10 kali kali 4096 Aug 24 18:14 ..
-rw-r--r--  1 kali kali   12 Aug 24 18:15 .hidden_file
drwxr-xr-x  2 kali kali 4096 Aug 24 18:14 test_dir
-rw-r--r--  1 kali kali   19 Aug 24 18:14 test_file
```
Here we see the line of the object called ```test_dir``` begin with a "d" which means "directory" and the line of the object ```test_file``` begin with a "-" which means that it's a file. We can also see the hidden file ```.hidden_file```.

You can change your position in the machine by using the ```cd``` command. First we need to clarify some notations. The ```./``` or ```.``` means "the curent directory" (the one we are in). ```../``` means the previous one. For exemple if we are in ```~/``` and we want to go on the desktop we should type :
```console
└─$ cd Desktop 
```
Or 
```console
└─$ cd ./Desktop 
```
Or
```console
└─$ cd ~/Desktop 
```
> You can use multiple ```../```` like ```../..``` to go back in two or more directories
{: .prompt-tip }


### Rights

Thank's to the ```-l``` option of the ```ls``` command you can also see the right of a file or directory. So if we skip the first character ("d" or "-") we get something like this ```rw-r--r--```. This can be split in 3 parts like this ```XXXYYYZZZ```. The "X" part represents the rights for the user  that owns the file. The "Y" part represents the rights for the group that owns the file. The "Z" part represents the rights for the other users on the machine.
You can notice that there is either a "r", a "w" or a "x". They are respectively for "read" permission, "write" permission and "eXecute" permission. 

The user that owns the file is (here) ```kali``` (the first one) and the group is ```kali``` (the second one). Here is an [article](https://linuxfoundation.org/blog/classic-sysadmin-understanding-linux-file-permissions/) about rights in linux.

## Files

You can see the content of a file with the ```cat``` command as follow :
```console
└─$ cat test_file
Some text in a file
```

You can also open it in a text editor like ```nano```, ```vi``` or ```vim```. You use these commands like this : ```text_editor text_file```
To save your modification in nano we use the shortcut ```CTRL+O``` and ```CTRL+X``` to leave the text editor. For ```vi``` or ```vim``` you need to enter in ```insert mode``` by typing ```I```. When you have finished modifying the file you need to press ```ESC``` and write ```:x```. If you made a mistake and need to live the text editor you can use the command ```:qa!```.

# Find things on the machine

If you need to find a file or directory on the machine you can use the ```find``` command as follows :
```console
└─$ find / -type f -name my_name 2>/dev/null
```
The ```/``` means that we want to search from the root directory. The ```f``` means that we want to look for a file (respectively "d" for a directory).

> You can use the -iname instead of -name if you are not sure about the case of the name (if it's "my_name" or "mY_NaMe")
{: .prompt-tip }
> Note the ```2>/dev/null```, this is just to redirect errors so you don't see them and don't overload the output.
{: .prompt-info }


If you know a word that the file contains then you can use the ```grep``` command. the grep command is usualy used like this :
```console
└─$ grep "word(s) to find" file_name
```
But if you don't know in which file to look then you can use the command as follows :
```console
└─$ grep -iRl "word(s) to find" / 2>/dev/null
```
