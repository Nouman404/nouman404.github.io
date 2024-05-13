---
title: CTFs | 404CTF_2024 | Retro | Bugdroid Fight
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Retro
tags:
  - Retro
  - Reverse
permalink: /CTFs/404_CTF_2024/Retro/Bugdroid_Fight
---
# Bugdroid Fight

![[bug_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/bug_enonce.png)

Here, we have the [following](Retro_Ingenierie/) `apk`. 

First I converted the `apk` into a `JAR` file using the following command:

```bash
./dex-tools-v2.4/d2j-dex2jar.sh Bugdroid_Fight_-_Part_1.apk
```

> The `dex-tools` came from [this](https://github.com/pxb1988/dex2jar/releases/) repo. 
{: .prompt-info}

Now that I have the `JAR` file, I can open it in a Java decompiler like [those](https://java-decompiler.github.io/) and now we have access to the java source code:

![[bug_source.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/bug_source.png)

We can see that it is calling `MainActivityKt` so we go there and have the first part of the flag:

![[bug_flag1.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/bug_flag1.png)

We see under this the concatenation of 3 strings that create the flag:

![[bug_concat.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/bug_concat.png)

So we already have `Br4v0_tU_as_`. We have in `Utils` the variable `lastPart` :
![[bug_last.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/bug_last.png)

So now we know that the flag is `Br4v0_tU_as_XXXXX_m3S5ag3!`. The second part of the flag is in `R.string.attr_special`. But when we go to `R.string.attr_special`, we only have the index of this value. The string is located under a `values` folder into a `string.xml` file:

![[bug_strings.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Retro_Ingenierie/Photos/bug_strings.png)

So the flag is obviously `404CTF{Br4v0_tU_as_tr0uv3_m0N_m3S5ag3!}`.
