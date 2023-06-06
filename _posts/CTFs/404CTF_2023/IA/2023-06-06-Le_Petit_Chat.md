---
title: CTFs | 404CTF_2023 | IA | Le Petit Chat
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, IA]
tags: [IA,MNIST, Images]
permalink: /CTFs/404CTF_2023/IA/Le_Petit_Chat
---

# Le Petit Chat

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b46b291c-5e9d-4d1f-aaf9-e1733002c3e7)


First of all we need to understand a bit what [the code](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/IA/verificateur.py) does. The first part of the code just loads the ResNet50 model. This model is already trained. So we can't modify any weight in this neural network to bypass the verification done after in the code. Then the image is loaded and the server checks if it is recognised as a `teapot`. Then the server look at each pixel of the given image (the cat we give) and check if it is the same as the original one more or less 70. If the modification is less than 70 then it's ok. This basically means that we can't just take an image of a teapot and send it to the server.

Then we need to find attacks that are available for this. And I found this [Google Colab](https://colab.research.google.com/github/phlippe/uvadlc_notebooks/blob/master/docs/tutorial_notebooks/tutorial10/Adversarial_Attacks.ipynb#scrollTo=CaFRbmOWTlDO). This Colab tells us about Adversarial attacks.

Adversarial attacks are techniques used to intentionally manipulate or deceive artificial intelligence (AI) models. The goal of these attacks is to exploit vulnerabilities in the model's behavior and trick it into making incorrect predictions or classifications. Adversarial attacks typically involve introducing carefully crafted, imperceptible modifications to the input data, such as images or text, in order to deceive the model. These attacks can be designed to cause misclassification, bypass security measures, or exploit weaknesses in AI systems. Adversarial attacks are important to study as they help researchers and developers understand the limitations of AI models and develop more robust and secure systems.

[This](https://github.com/aaronchong888/Targeted-Adversarial-Attacks) github code gives us everything we need to be able to perform this attack. We can now run the following command:
`python generate_adversarial_example_targeted.py chat.jpg "teapot"`

We can now [host](https://imgbb.com/) our image of a cat that is now a beautiful teapot as you can see:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/92bbbe34-50d3-4bf4-b6e1-0dcb7a6824ec)

We can now connect to the `nc` server and give the URL of our [cat](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/IA/teapot.png) to it:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/9661bcd3-b683-4a0c-9de7-42194ada4107)


The flag is `404CTF{qU3l_M4n1f1qu3_the13R3_0r4ng3}`
