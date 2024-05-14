---
title: CTFs | 404CTF_2024 | Investigation Numerique | Du poison
author: BatBato
date: 2024-04-25
categories:
  - CTFs
  - 404_CTF_2024
  - Investigation Numerique
tags:
  - Forensique
  - Forensic
permalink: /CTFs/404_CTF_2024/Investigation_Numerique/Du_poison
---

# Du poison

![[ia_enonce.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/ia_enonce.png)

In this AI challenge, we are tasked to deteriorate the accuracy of the AI model that is trained locally. In this challenge, to be able to do this, we can modify the value of the weights. 

In an AI, weights are adjustable parameters that determine how data is processed and interpreted by the AI model during learning. Each connection between neurons in an artificial neural network has an associated weight, representing the significance of that connection in the model.

Weights are crucial because they directly influence the performance and predictive capability of an AI model. During the learning phase, the model adjusts these weights to minimize the error between the model's predictions and the ground truth of the training data. The better the weights are adjusted, the more the model is capable of generalizing and producing accurate predictions on new data.

Modifying the values of weights can be critical because it can drastically alter the behavior and performance of the model. If weights are modified inappropriately or unintentionally, it can lead to incorrect results, poor generalization, or even total model failure. For example, incorrect weights can lead to erroneous predictions, loss of interpretability of the model, or even undesirable consequences in critical applications such as health or safety. Therefore, handling weights must be done with caution and within the framework of rigorous design and validation of the AI model.

So now that we know what are the weights, we can provide random values and expect to have a poor accuracy. But first lets check the code to know where we need to do the modifications:

![[IA_model.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/IA_model.png)

As you can see the original python notebook, we have the `model_base` used in the `train_and_test` function. The `model_base` variable stores the weights so we just have to recover their content and change their values. Not that we have an accuracy of `94%` and we need to get under `50%`.

We just have to add `10000` to the weights and it should get us pretty low. To do that we can use the following code:

![[IA_ch_wheights.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/IA_ch_wheights.png)

As you can see, we have now an accuracy of `8%`. So it is a bit under the `50%` required XD. We can now launch the end of the code and...

![[IA_flag.png]](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/IA_flag.png)

Voilà. The flag is `404CTF{0h___dU_P01sON}`.

The full colab code is available [here](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404_CTF_2024/Investigation_numerique/Photos/ma_versionchall_1.ipynb)