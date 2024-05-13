---
title: CTFs | 404CTF_2024 | Web | Le match du siecle
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Web
tags:
  - Web
permalink: /CTFs/404_CTF_2024/Web/Le_match_du_siecle
---
# Le match du siecle \[1/2\]

![[match_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_enonce.png)

Here, we need to find a way to get a ticket for the match. We arrives on a basic page and we see that we can create an account so that's what i did and I connect to it:

![[match_home.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_home.png)
As we can see, there is now a `Solde` that tells us we didn't put any money on the website and a button to check our newly bought tickets. I checked the cookie to see if there was anything interesting...

![[match_cookie.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_cookie.png)

So... Obviously, I put `10000` in the `balance` and now...:

![[match_balance.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_balance.png)

Now that we have enough money to buy any ticket, lets buy the `Tribune Laterale`:

![[match_tribune.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_tribune.png)

We receive a message that tells us that we have bought the ticket and if we check our tickets:

![[match_our_ticket.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_our_ticket.png)

Lets obtain it and... Voilà:

![[match_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match_flag.png)

# Le match du siecle \[2/2]

![[match2_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match2_enonce.png)

Now that we "bought" our ticket, and we would like to get a `VIP` one. But those ticket are not available anymore... Lets see how we got the first flag by intercepting the request:

![[match2_burp.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match2_burp.png)

As we can see, we have in `token` the name of our ticket. Lets change it to `VIP`:

![[match2_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Web/Photos/match2_flag.png)

As you can see we got another flag.