---
title: CTFs | 404CTF_2023 | ROSO_OSINT | L'âme d'un poète et le coeur d'une femme
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023]
tags: [ROSO,OSINT]
permalink: /CTFs/404CTF_2023/ROSO_OSINT/L_ame_d_un_poete_et_le_coeur_d_une_femme
---


# L'âme d'un poète et le coeur d'une femme

This OSINT challenge is split in 4 parts.


# L'âme d'un poète et le coeur d'une femme 1/4

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/a6d4c968-335e-4f15-8154-73d9f913fe01)

We are looking for a woman called `Louise Colet`. Looking at social networks, we find a Facebook user with this name. Looking at the [profile](https://www.facebook.com/profile.php?id=100091643933854&sk=about_details), we can see in her favourite quotes the first flag : `404CTF{4_mon_ch3r_4mi_v1ctor}`

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/2d6dc60c-4e07-480e-9fcc-ba7b0d87e469)


# L'âme d'un poète et le coeur d'une femme 2/4

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/c3aa9343-22cf-445d-84dc-cba967aada39)


During our first part of enumeration, I noticed that there was an [Instagram account](https://www.instagram.com/colet_louise/) of Louise Colet just like the Facebook one. It has only one picture that contains a text explaining that a discord was created the 25th of may:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/dd0e39b1-67fc-407c-bbd2-6c86622d8659)


The flag is: `404CTF{25_mai_colet_louise}`
  
# L'âme d'un poète et le coeur d'une femme 3/4

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/0a59bef6-e5e9-4a04-a69e-ae1113f90217)

We are now looking for the discord invitation link. After a lot of time looking at the Instagram, Facebook accounts or on Twitter, The Way Back Machine, YouTube... I finally head back to GitHub and find a project called [Salon-litteraire-de-Louise-Colet](https://github.com/LouiseRevoil/Salon-litteraire-de-Louise-Colet). That's what we are looking for!!! At the bottom of the page there is the invitation to the discord server and the flag: `404CTF{B13nv3nue_d4ns_le_s4lon_l1tter4ir3_de_lou1se_C0l3t}`.


# L'âme d'un poète et le coeur d'une femme 4/4

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/07a6489b-7c6f-403d-989e-6de2832f9a51)


When arriving on the discord we are told to enter in the chat `le_petit_salon`. Once this is done, we have a new channel that appears with the name we just typed. 

![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/ROSO_OSINT/Chall1.png)

We need to find the year when the walker with white moustaches was in the Tuileries Garden (as specified in the above text. By using the query string in google `"promeneur inoccupé qui, sortant du jardin des Tuileries"`, I found a webpage of [Un_drame_dans_la_rue_de_Rivoli](https://books.google.com/books/about/Un_drame_dans_la_rue_de_Rivoli.html?id=Mh4nDwAAQBAJ) that had the same text and then found the year `1835`.

Then we are asked:
![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/ROSO_OSINT/Chall2.png)

I then used the query `"Les triomphes, le bruit," poeme` in google and found the website of the [poesie française](https://www.poesie-francaise.fr/louise-colet/poeme-la-voix-dune-mere.php) that gives us the poem. We then concatenate everything and we get the answer: `Pour nous, aimer et croire Au bonheur nous conduit. Coule une vie obscure Que le devoir remplit ; L'onde à l'ombre est plus pure, Rien ne trouble son lit.`

The final question, and not the easier one was:
![image](https://raw.githubusercontent.com/Nouman404/nouman404.github.io/main/_posts/CTFs/404CTF_2023/ROSO_OSINT/Chall3.png)

And after a lot of search on the internet, I found the website of [gallica](https://gallica.bnf.fr/ark:/12148/bpt6k8572147/f9.item.r=louise%20colet) with the information:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/65f72233-6afb-4333-ba4c-88abfbc5863d)

We could have been duped because they already saw each other before. The final answer was then: `Gernesey_1857`

We then recover the flag in the last discord channel:
`404CTF{j3_su1s_ravie_d_av0ir_fait_v0tre_connaiss4nce}`

