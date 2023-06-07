from pwn import *
from math import pow
import warnings
warnings.filterwarnings("ignore", category=BytesWarning)


HOST, PORT = "challenges.404ctf.fr", 30980

io = remote(HOST, PORT)

voyelles = ["a", "e", "i", "o", "u", "y"]
#Règle 0 : Aucune modification
def regle0(mot):
	return mot

#Règle 1 : Inverser les lettres
def regle1(mot):
	return mot[::-1]

"""
Règle 2 :
- Si le mot à un nombre de lettres pair, échanger la 1ere et la 2e partie du mot obtenu
- Sinon, enlever toutes les lettres du mot correspondant à la lettre centrale
"""
def regle2(mot):
	if len(mot)%2 == 0:
		temp = mot[0:int(len(mot)/2)]
		new_mot = mot[int(len(mot)/2):] + temp
		return new_mot
	else:
		lettre = mot[int(len(mot)/2)]
		return mot.replace(lettre, "")

def decalage_gauche(mot):
	lettre_deb = ""
	lettre = ""
	indice = -1
	mot = list(mot)
	for i in range(len(mot)):
		if mot[i] in voyelles:
			if indice == -1:
				lettre_deb = mot[i]
			else:
				mot[indice] = mot[i]
			indice = i
	mot[indice] = lettre_deb

	return "".join(mot)

def decalage_droite(mot):
	lettre = ""
	indice = -1
	mot = list(mot)
	for i in range(len(mot)):
		if mot[i] in voyelles:
			if indice == -1:
				lettre = mot[i]
				indice = i
			else:
				tmp  = mot[i]
				mot[i] = lettre
				lettre = tmp
	mot[indice] = lettre
	
	return "".join(mot)

"""
Règle 3 :
Si le mot a 3 lettres ou plus :

- Si la 3e lettre du mot obtenu est une consonne, "décaler" les voyelles vers la gauche dans le mot original, puis réappliquer les règles 1 et 2.
- Sinon : la même chose mais les décaler vers la droite.

> Ex de décalage : poteau => petauo // drapeau => drupaea
"""
def regle3(mot, mot_original):
	if len(mot) >= 3:
		# est une consonne
		if mot[2] not in voyelles:
			return decalage_gauche(mot_original)
		else:
			return decalage_droite(mot_original)
	return mot

def getVoyelle(c):
	code = ord(c)
	while 1:
		code -=1
		if chr(code).lower() in voyelles:
			return code

def mySomme(mot, n):
	somme = 0
	if n == 1:
		if mot[0].lower() in voyelles:
			return ord(mot[0])*2

	for i in range((n-1), -1, -1):
		if mot[i].lower() in voyelles:
			somme += ord(mot[i])*(2**(n-i))
	return somme

"""
Règle 4 :
- Pour `n` allant de 0 à la fin du mot, si le caractère `c` à la position `n` du mot est une consonne (majuscule ou minuscule), insérer en position `n+1` le caractère de code ASCII `a = ((vp + s) % 95) + 32`, où `vp` est le code ASCII de la voyelle précédant la consonne `c` dans l'alphabet (si `c = 'F'`, `vp = 'E'`), et `s = SOMME{i=n-1 -> 0}(a{i}*2^(n-i)*Id(l{i} est une voyelle))`, où `a{i}` est le code ASCII de la `i`-ième lettre du mot, `Id(x)` vaut `1` si `x` est vrai, `0` sinon, et `l{i}` la `i`-ième lettre du mot. _Attention à bien appliquer cette règle aussi sur les caractères insérés au mot._

> Ex : futur => f&ut\\ur@	(PS: Only 1 backslash in the result of futur)

- Enfin, trier le mot par ordre décroissant d'occurrences des caractères, puis par ordre croissant en code ASCII pour les égalités

> Ex de tri : patate => aattep
"""
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

# 2e partie regle 4
# trier le mot par ordre décroissant d'occurrences des caractères, puis par ordre croissant en code ASCII pour les égalités
def trieRegle(mot):
	val = {}
	for char in mot:
		if char in val.keys():
			val[char] += 1
		else:
			val[char] = 1
	sorted_dict = {k: v for k, v in sorted(val.items(), key=lambda item: (-item[1], item[0]))}
	mot_final = ""
	for key in sorted_dict.keys():
		mot_final += key*sorted_dict[key]
	return mot_final

def sendAllInit():
	p1 = io.recvuntil(">> ").decode()
	mot_original = p1.split("{")[1].split("}")[0]
	mot = regle0(mot_original)
	io.sendline(mot)
	mot = regle1(mot)
	p1 = io.recvuntil(">> ").decode()
	io.sendline(mot)
	mot = regle2(mot)
	p1 = io.recvuntil(">> ").decode()
	io.sendline(mot)
	mot = regle3(mot,mot_original)
	p1 = io.recvuntil(">> ").decode()
	mot = regle1(mot)
	mot = regle2(mot)
	io.sendline(mot)
	p1 = io.recvuntil(">> ").decode()
	mot = regle4(mot)
	mot = trieRegle(mot)
	io.sendline(mot)

def sendAll(mot_original):
	mot = regle0(mot_original)
	mot = regle1(mot)
	mot = regle2(mot)
	mot = regle3(mot,mot_original)
	mot = regle1(mot)
	mot = regle2(mot)
	mot = regle4(mot)
	mot = trieRegle(mot)
	return mot

#Init
sendAllInit()

io.recvuntil("{")
text = io.recvuntil("}")[:-1].decode()
print(text)
flag = ""
arr_text = text.split(" ")
trad_text = ""

for mot in arr_text:
	trad_text += sendAll(mot) + " "
print("\n------------------\n")
print(trad_text[:-1])
io.sendline(trad_text[:-1])

print(io.recvline().decode())
print(io.recvline().decode())
print(io.recvline().decode())
