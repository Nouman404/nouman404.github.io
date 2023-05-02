---
title: CTFs | FCSC2023 | SPAnosaurus
author: BatBato
date: 2023-05-02
categories: [CTFs, FCSC2023, Intro]
tags: [CTF, FCSC, Signal]
permalink: /CTFs/FCSC2023/Intro/SPAnosaurus
---

# SPAnosaurus

![image](https://user-images.githubusercontent.com/73934639/235778633-e78f8cd4-a942-4c99-999f-5d2a1e76a28a.png)


In this chall we had 3 files but only the image was useful. The above code makes us understand that this is a recursive function. The image of the signals, as said in the chall desciption, are the electrical consumsion of the computer when runing the above function.

We notice that the more calculation is used when we are in the `else` statement. This only happen when the number is `odd`. So when we look at the graph, we can easily understand that the spikes apear when the `odd` calculation is done. The chall description tells us that the number `2727955623` is equal to `10100010100110010100110010100111` in binary. Which we can find on the graph:

![image](https://user-images.githubusercontent.com/73934639/235781664-4640e6ab-c69b-4092-8520-d8ce63c53153.png)

Knowing that, we can find the value of the admin trace:

![image](https://user-images.githubusercontent.com/73934639/235781715-aebfccbf-9ced-4f04-a0cd-ce6c723cab48.png)


And so, because `2327373741` the flag is `FCSC{2327373741}`
