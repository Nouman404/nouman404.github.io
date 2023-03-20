---
title: CTFs | HackDay2023 | Astronauts_Poem
author: BatBato
date: 2023-03-20
categories: [CTFs, HackDay2023, Astronauts_Poem]
tags: [CTF, HackDay2023, Stegano]
permalink: /CTFs/Hackday2023/Stega/Astronauts_Poem
---

# Astronauts_Poem

On this chall, we have a PDF file. When we look at the exif we can see a link to a wiki. 

![image](https://user-images.githubusercontent.com/73934639/226390466-a79d4a3c-7507-46d9-aaf2-8d839ebf020a.png)

When heading to the bottom of the page, we can see two links to old website available on the [waybackmachine](https://web.archive.org/web/20210506123139/https://mcaweb.matc.edu/winslojr/vicom128/final/tio/index.html).
We extract the text of the pdf with a tool like [pdftotext](https://poppler.freedesktop.org/). When putting the text on the website we get the message: 
![image](https://user-images.githubusercontent.com/73934639/226391851-446b60ec-918a-4c1b-9de4-2b873dfbf879.png)

The 10th line is ```Drove by our curiosity, I found my way: patrolling our spacecraft. You remembered wishes of hope. I am close to```.

We create a program to count each word length and replace it with the correct brainfuck character as explained on the wiki.

After that we get the  value ```>]+9[>]+0+0+0<]-[]>]``` which gives us 270 in decimal. 

The NGC 270 is in the constellation of the whale which in French is ```baleine``` so the flag is: ```HACKDAY{baleine}```
