---
title: CTFs | CTF_INSA_2024 | Web | Attention_au_swap
author: BatBato
date: 2024-02-05
categories:
  - CTFs
  - CTF_INSA_2024
  - Web
tags:
  - web
  - swap
  - vim
permalink: /CTFs/CTF_INSA_2024/Web/Attention_au_swap/
---
# Attention au swap 

![[swap_sujet.png]]

In this challenge, we are asked to demonstrate some kind of vulnerability regarding the text editor `vim`. The name of the challenge gives us a hint on where to look for (`swap`). First I searched `swap vim` and I found this link [https://www.baeldung.com/linux/vim-swap-files](https://www.baeldung.com/linux/vim-swap-files). It explains what is a swap file and that if a file called `{filename_whit_extention}` is created then its swap file name will be `.{filename_whit_extention}.swp`. Now lets have a look at the website:


![[swap_index.png]]

As we can see, we have the `index.php` file. We can try to recover its swap file by searching the following URL:

`http://ctf.insa-cvl.fr:1004/.index.php.swp`

When the file is downloaded, we can open it with `Vim` recovery mode:

`vim -r .index.php.swp`

When `Vim` is opened, we see the following:

![[swap_vim.png]]

We can now save the file as `index.php` by running th following command in `Vim`:

`:q! index.php`

And we can print in our terminal the flag by running the following command:

`head index.php`

