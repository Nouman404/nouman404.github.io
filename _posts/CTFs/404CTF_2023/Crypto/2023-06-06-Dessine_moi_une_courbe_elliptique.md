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

Now that we just found the equation to solve `b` for `G` and `H`, we can mix both equations because they are both equal to `b`:

```python
b = G_y**2 - G_x**3 - a*G_x
and
b = H_y**2 - H_x**3 - a*H_x

=>

G_y**2 - G_x**3 - a*G_x = H_y**2 - H_x**3 - a*H_x
<=>
G_y**2 - G_x**3 - H_y**2 + H_x**3 = a*G_x - a*H_x
<=>
G_y**2 - G_x**3 - H_y**2 + H_x**3 = a*(G_x - H_x)
<=>
(G_y**2 - G_x**3 - H_y**2 + H_x**3)/(G_x - H_x) = a
<=>
a = (G_y**2 - G_x**3 - H_y**2 + H_x**3)/(G_x - H_x)
```

Now, before replacing the `x`s and `y`s, we first need to put back the modulus. For the equation to be still valid, we need to have:

```python
a = ( (G_y**2 - G_x**3 - H_y**2 + H_x**3)* pow((G_x - H_x), -1,p) ) % p
```

This will do a division modulus `p` and the whole calculation needs to be modulus `p`.

So we have:

```python
a = ( (G_y**2 - G_x**3 - H_y**2 + H_x**3)* pow((G_x - H_x), -1,p) ) % p

and

b = ( G_y**2 - G_x**3 - a*G_x ) % p
```

I then put everything in a python code available [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Crypto/eliptic.py).

We can run this code, and we have the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/bfe5b9e4-9b69-4347-a28e-7cba3e8a3e41)

The flag is `404CTF{70u735_l35_gr4nd35_p3r50nn3s_0nt_d_@b0rd_373_d35_3nf4n7s}`


