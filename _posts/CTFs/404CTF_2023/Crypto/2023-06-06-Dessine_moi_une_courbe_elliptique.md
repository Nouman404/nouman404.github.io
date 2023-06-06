---
title: CTFs | 404CTF_2023 | Crypto | Dessine-moi une courbe elliptique
author: BatBato
date: 2023-06-06
categories: [CTFs, 404CTF_2023, Crypto]
tags: [Crypto,Elliptic Curve, Maths]
permalink: /CTFs/404CTF_2023/Crypto/Dessine_moi_une_courbe_elliptique
---

# Dessine-moi une courbe elliptique

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b2d3efc6-6433-431e-ad05-6cb1d53bbf64)


In this challenge, we are given the [following](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Crypto/challenge.py) code and its [output](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Crypto/data.txt).

After some research on the elliptic curves, I found [this blog](https://ctf-wiki.mahaloz.re/crypto/asymmetric/discrete-log/ecc/) that explains how they solved a CTF. It is not like us because they have `a` and `b`, and that's what we are looking for. But in this WU, we find the formula for the elliptic curve on the finite field that is `y**2=x**3+ax+b` (where `**` is the mathematical power ).

> Note that I stated that its an elliptic curve on the finite field because of what is said in the little story above and because, as in the challenge code, we have the formula `4a**3+27b**2%p!=0` that need to be true.
{: .prompt-info}

But the more acurate equation is `y**2=x**3+ax+b%p`. We have two point on the curve, `H` and `G`. We can take the `x` and `y` coordinates as `G_x` and `G_y` (recpectively `H_x` and `H_y`).

So we have the following equations:

```python
G_y**2 = G_x**3+a*G_x+b%p 

and

H_y**2 = H_x**3+a*H_x+b%p
```

Let's simplify the equations by removing, for now, the modulus `p`. We can find the value of `b`:

```python
G_y**2 = G_x**3+a*G_x+b
<=> 
G_y**2 - G_x**3 = a*G_x+b
<=>
G_y**2 - G_x**3 - a*G_x = b
<=>
b = G_y**2 - G_x**3 - a*G_x
and

H_y**2 = H_x**3+a*H_x+b
<=> 
H_y**2 - H_x**3 = a*H_x+b
<=>
H_y**2 - H_x**3 - a*H_x = b
<=>
b = H_y**2 - H_x**3 - a*H_x
```

To Be Continued
