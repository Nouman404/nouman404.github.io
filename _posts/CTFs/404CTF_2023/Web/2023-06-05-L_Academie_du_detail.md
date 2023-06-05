---
title: CTFs | 404CTF_2023 | Web | L'Académie du détail 
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023, Web]
tags: [Web,JWT, Cookie]
permalink: /CTFs/404CTF_2023/Web/L_Academie_du_detail
---

# L'Académie du détail 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/97ccf7bf-cdcc-440d-bb00-e2a8445ba237)

In this challenge, we arrive on a web page. We have login page available, and we can connect with any credentials we want (ex: a:a). We now have a tab called `Liste des membres` that appears at the top:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/35b04678-0700-4d6d-a92c-c9c9cce818e6)

But when we try to connect to it, we get this error:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4916e4b7-065d-43da-b0c8-4a56a7179d1e)

We try looking around and we can see a cookie called `access-token`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1b8f69f4-5f2d-46c9-8e42-2ceb7a4bf0ed)

This cookie looks really like a JWT... When we put it on the website [JWT.io](https://jwt.io/), we can see that it is indeed a JWT:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9d61ec9f-e5be-4346-a42f-358e6f8637f7)

We try a basic attack on JWT that consist of, putting the `alg` attribute to `none` and this should bypass the signature (if this works). We can put the username to `admin` and we have :

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/37542d5a-1646-48f2-909a-83eb8fb840c0)

> In case you are wondering, the encoded values of the JWT is only base64 encoded so we can decode it and encode whatever we want. We just can't modify the signature part, hence the `None` algorithm chose.
{: .prompt-info}

> Pay attention to the case of the `none`. `None` won't work if you try it with an upper-case `N`.
{: .prompt-danger}

We press CTRL+F5 to refresh the page and we get the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/306d3889-77df-4630-a350-cd418e3bef60)

The flag is `404CTF{JWT_M41_1MP13M3N73_=L35_Pr0813M35} `
