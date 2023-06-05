---
title: CTFs | 404CTF_2023 | ROSO_OSINT | Mentions gastronomiques
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023]
tags: [ROSO,OSINT]
permalink: /CTFs/404CTF_2023/ROSO_OSINT/Mentions_gastronomiques
---

# Mentions gastronomiques

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/605f8e11-25d0-4d1e-8899-3bb9ef0bd4cb)

This challenge requires us to recover the price of the meal that `Margot Paquet` ate. This was a bit tricky because there was an American lady that is named also Margot Paquet and that posted a picture of her meal that she ate for her wedding anniversary.

After a lot of tries, I found another [account](https://www.instagram.com/margot.paquet/) on Instagram this time. It didn't look really legitimate, it may be the good one this time:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d4d8e00c-ed19-438a-bd79-acf11aabd162)

As stated on one of the images, she likes to eat `Boeuf Bourguignon` at the restaurant if it cost less than 15€:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/3f71a5a7-ae29-4038-ac30-075ea29aae50)

Her account was tagged by the [Futurionix](https://www.instagram.com/futurionix/) Instagram account. Looking at the images posted by this account, we can see that they ate in Paris near The Louvre museum:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/142d0b0a-2bbd-4923-a2c7-e7b523cdb934)

And they say that they are going to set their HQ near this location. Looking for restaurant near this location that are not expensive, we find the `La Frégate`. We can find pictures of the menu on [google maps](https://www.google.com/maps/place/La+Fr%C3%A9gate/@48.8593972,2.3294139,3a,75y,90t/data=!3m8!1e2!3m6!1sAF1QipM0FNxsVwTS8e3WWwHe76bPjBu6ePznPgDPtRoA!2e10!3e12!6shttps:%2F%2Flh5.googleusercontent.com%2Fp%2FAF1QipM0FNxsVwTS8e3WWwHe76bPjBu6ePznPgDPtRoA%3Dw203-h247-k-no!7i1372!8i1675!4m13!1m2!2m1!1sla+fr%C3%A9gate+paris!3m9!1s0x47e66e290c953943:0xe8b7374033b34848!8m2!3d48.8593972!4d2.3294139!10e5!14m1!1BCgIYIQ!15sChFsYSBmcsOpZ2F0ZSBwYXJpc1oTIhFsYSBmcsOpZ2F0ZSBwYXJpc5IBFHJlc3RhdXJhbnRfYnJhc3Nlcmll4AEA!16s%2Fg%2F1tds5_zf?entry=/ttu). And... a `Boeuf Bourguignon` at 13.5€!!! (We may have wasted time on the website that isn't up to date):

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/1a170c8a-c011-4bc4-83b5-48b6d969658f)

But the flag `404CTF{la_fregate_13.5}` didn't work. She may have eaten something with the `Boeuf Bourguignon`. Heading back to the Instagram account, we see that she ate a `Tarte Tatin` the day before the post of the picture:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/90b8f5d5-4c1f-46c8-b0e4-3e0a5dd346c9)

And the `Boeuf Bourguignon` picture was posted the 26th of April, one day after the `Tarte Tatin` post. So looking at the price of the `Tarte Tatin` we find two prices. One at 9€ and the other one at 10.5€:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/470a3a9c-cd5f-498f-8d45-a831969f432e)

The final flag was (13.5+10.5=24): `404CTF{la_fregate_24.0}`

