---
title: CTFs | 404CTF_2023 | IA | De la poésie
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, IA]
tags: [IA,MNIST, Images]
permalink: /CTFs/404CTF_2023/IA/De_la_poesie
---

# De la poésie

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/11e9d364-ba4b-4b00-b52b-10c8a20cf198)

In this challenge, we need to recognise `6535` images and do something with them.

I found a [Google Colab](https://colab.research.google.com/github/skorch-dev/skorch/blob/master/notebooks/MNIST.ipynb) that did some hand writting number recognition. I added this code at the end:

```python
from google.colab import drive
# get the zip archive from my drive and unzip it
"""
drive.mount('/content/drive')
!cp drive/MyDrive/poeme.zip .
!unzip poeme.zip
"""

import os
from PIL import Image
from torchvision.transforms import ToTensor
predictions = []
work_dir = os.getcwd() 
for i in range(6536):
  # Load the image from the given path and convert it to grayscale
  img = Image.open(img_path).convert('L')

  # Convert the image to a tensor
  img = ToTensor()(img)

  # Add an extra dimension to the tensor to represent the batch size
  img = img.unsqueeze(0)

  # Make a prediction using the CNN model on the image
  pred_result = cnn.predict(img)

  # Convert the prediction result to a string and append it to the list of predictions
  predictions.append(str(pred_result[0]))

print(''.join(predictions))
```

This will give us a really long string of integer. We now need to focus on the hint given in the text `Être pair ou ne pas l'être.` (to be even or not to be).

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/f15b04e6-e715-4dce-bbe0-c34ff2d3ba2d)

We can try to set every even number as a `0` and every odd number as `1`. We then split in block of `8` and decode the binary character found in ASCII.

```python
chaine = "6580616563912104..."
chaine = list(chaine)
def pair_impair():
  pair = ""
  impair = ""
  for i in range(len(chaine)):
    if int(chaine[i]) % 2 == 0:
      pair += chaine[i]
    else:
      impair += chaine[i]


  print(pair)
  print(impair)

def split_string(string, length):
    return [string[i:i+length] for i in range(0, len(string), length)]
    
substring_length = 8
substrings = split_string(chaine, substring_length)
flag = []
new_chaine = ""
for chaines in substrings:
  for num in chaines:
    #pair
    if int(num) % 2 == 0:
      new_chaine += "0"
    else:
      new_chaine += "1"
  flag.append(new_chaine)
  new_chaine = ""
# Convert each segment to decimal and then to ASCII character
flag = ''.join([chr(int(segment, 2)) for segment in flag])

print(flag)
```

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6612cec8-454d-41d0-bdfa-70fce8d6a165)

There are some errors in the process of number recognition but we can find the flag `404CTF{d3_L4_p03S1e_qU3lqU3_P3u_C0nT3mp0r4in3}`
