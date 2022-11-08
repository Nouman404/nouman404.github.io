---
title: CTFs | 404CTF | Stegano | Un logo obese 1
author: BatBato
date: 2022-11-07
categories: [CTFs, 404CTF, Stegano, Un logo obèse]
tags: [CTF, 404CTF, Stegano]
permalink: /CTFs/404CTF/Stegano/PNG_Un_logo_obese/Un_logo_obese1
---

# PNG : Un logo obèse 1/4

On commence avec une image contenant le logo de Hallebarde 
![image](https://user-images.githubusercontent.com/73934639/200651965-1150d67b-f42f-41aa-a197-517debf2a362.png)
 

En effectuant la commande "string" dessus, nous voyons un certain fichier "out/stage2.png"  
 ![image](https://user-images.githubusercontent.com/73934639/174495612-10816276-1bc8-4795-884f-f25163f9a170.png)


 
On essaye de l'extraire avec Binwalk 
 ![image](https://user-images.githubusercontent.com/73934639/174495715-862272a2-042c-4109-8bfa-cb9f47fd78cc.png)


 
Et voilà, on a notre flag :)  

![stage2](https://user-images.githubusercontent.com/73934639/174495794-95dbfa77-4d2f-4bb7-a53d-4a1ea81f1eb4.png)
