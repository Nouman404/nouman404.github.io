---
title: CTFs | 404CTF_2023 | Stega | Odobenus Rosmarus
author: BatBato
date: 2023-06-07
categories: [CTFs, 404CTF_2023, Stega]
tags: [Stega, Morse]
permalink: /CTFs/404CTF_2023/Stega/Odobenus_Rosmarus
---

# Odobenus Rosmarus

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/6d9557fa-26bf-4f69-b7ef-7e4c761bd2d0)


In this challenge, the name was a hint:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/133d2384-b4f3-46cf-896f-426955b60008)

We now know that it is something in morse code, but what.... That is the question that I asked myself during long ours of thinking... Then I explained to my dad the problem I was facing, and by explaining that, in morse code, we have `.` that stand for short (Court in French), `-` that stand for long (Long in French) and spaces (Espace in French). By saying that... I just understood the challenge. We only have capital `C`, `L` and `E` for `Court`, `Long` and `Espace`. I then used the following program to decode the text:

```python
MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}
def decrypt(message):
    # extra space added at the end to access the
    # last morse code
    message += ' '
    decipher = ''
    citext = ''
    for letter in message:
 
        # checks for space
        if (letter != ' '):
            # counter to keep track of space
            i = 0
            # storing morse code of a single character
            citext += letter
        # in case of space
        else:
            # if i = 1 that indicates a new character
            i += 1
            # if i = 2 that indicates a new word
            if i == 2 :
                 # adding space to separate words
                decipher += ' '
            else:
                # accessing the keys using their values (reverse of encryption)
                decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT
                .values()).index(citext)]
                citext = ''
    return decipher

text = "Ce soir je Célèbre Le Concert Electro Comme Louis Et Lou. Comme La nuit Commence Et Continue Clairement, Et Clignote Lascivement il Chasse sans Chausser En Clapant Encore Classiquement Les Cerclages du Clergé. Encore Car Encore, Louis Lou Entamant Longuement La Lullabile En Commençant Le Cercle Exhaltant de Club Comique Cannais Et Clermontois."

morse = ""
for mot in text:
	if mot[0] == "L":
		morse += "-"
	elif mot[0] == "E":
		morse += " "
	elif mot[0] == "C":
		morse += "."

print()
print("Morse :", morse)
print("\n---------------------\n")
print("Flag: 404CTF{"+ decrypt(morse).lower() + "}")
```

And thanks to that, we get the flag:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/72b182c2-f333-4d90-8984-a49c3f09cb84)

The flag is `404CTF{facilelemorse}`
