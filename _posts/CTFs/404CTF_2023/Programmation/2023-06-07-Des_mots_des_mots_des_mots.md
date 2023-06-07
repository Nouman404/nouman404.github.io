---
title: CTFs | 404CTF_2023 | Programmation | Des mots, des mots, des mots
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Programmation]
tags: [Programmation]
permalink: /CTFs/404CTF_2023/Programmation/Des_mots_des_mots_des_mots
---

# Des mots, des mots, des mots

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/bdc27c48-7ce0-41c8-b2ea-8b626613b521)

In this challenge, we need to access a netcat server and create a code that will respect the different rules stated:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/4c122cda-62a9-42bb-84ce-fb2b3baf9f51)

The rule 0 is an example. It just ask us to send back the same string. So, because we have `cosette`, we send `cosette`.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/7106b317-20e5-4c3e-b53d-2be8d595a2e5)

For the rule 1, we need to reverse all the characters. So `cosette` become `ettesoc`.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/b700185f-361a-4752-911a-4d063d8eb02f)

For the rule 2, if the word has an even number of letters, swap the 1st and 2nd parts of the resulting word. Otherwise, remove all the letters in the word corresponding to the central letter.
We had `ettesoc`, so we now need to send `ttsoc` because the length of the word is odd, then we remove the letter `e` that is at the center of the word.

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6f597e7a-7576-4517-944f-43728354423f)

For the 3rd rule, if the word has 3 or more letters, then if the 3rd letter of the resulting word is a consonant, "shift" the vowels to the left in the original word, then reapply rules 1 and 2. Otherwise: same thing, but shift them to the right. If the word has less than 3 letters we just return the word. This "shift" just means that we need to move only the vowels. The consonant doesn't change position. The example is `poteau` that become `petauo` after the left shift. As you can see, the `p` is still the first letter and the `t` is still the 3rd letter. Only vowels have moved. So `ttsoc` become `ottsc`.
 
![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/419c5ef1-309e-48c4-929a-06a06247d949)

The 4th rule is the harder one. To explain it I will show and explain the code to solve it:

```python
def regle4(mot):
	mot = list(mot)
	n = 0
	while n < len(mot):
		c = mot[n]
		# check if c == consonne
		if c.lower() not in voyelles and c.isalpha():
			vp = getVoyelle(c)
			s = mySomme(mot, n)
			a = ((vp + s) % 95) + 32
			mot.insert((n+1),chr(a))
		n += 1
	return "".join(mot)
```




You can find the hole code [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Programmation/desMots.py)
