---
title: CTFs | 404CTF_2023 | Radio | Avez-vous vu les cascades du hérisson ?
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Radio]
tags: [Radio, Audacity, Waterfall]
permalink: /CTFs/404CTF_2023/Radio/Avez_vous_vu_les_cascades_du_herisson
---

#  Avez-vous vu les cascades du hérisson ?

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/56699be1-954d-4977-b989-95f6e1520b33)

In this challenge, we are given a `raw` audio file. When listening to it, we don't hear anything... But looking at the spectrogram gives us quite the result:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/d2872aca-ea60-4a8a-bec6-0a66ead7ed0d)

> You may have only yellow stuff and not this beautiful result. If so, when you import your `raw` data, don't forget to click on `Detect` before clicking on `Import` once your audio is selected.
{: .prompt-warning}

We don't see everything, we may use the `Zoom to fit` feature to see everything. To access this option, you need to left click where the numbers are shown on the left.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9c5d2056-1607-4570-88f5-49723b5d0bd8)

Now we have everything:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9811e3bb-e81b-42b1-9aa8-312314822484)

But this is pretty hard to read. To have a better result I used the following settings for the spectrogram:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/7517682c-ebd1-40c8-992e-b9bd654b2cfc)

> You can access those settings by clicking on the arrow, near the name of the audio, then click on `spectrogram settings`
{: .prompt-tip}

We can play with the size of the audio and the zoom on it to get this:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/98bc7d31-272f-45d6-ba8d-218cc0fc9aa0)

We can now see the flag by squinting `404CTF{413X4NDR3_D4N5_UN3_C45C4D35_?}`
