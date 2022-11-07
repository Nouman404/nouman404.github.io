# PNG : Un logo obèse 2/4

Maintenant,  nous nous retrouvons avec une image de cassette : </br>
![stage2](https://user-images.githubusercontent.com/73934639/174495794-95dbfa77-4d2f-4bb7-a53d-4a1ea81f1eb4.png)</br></br>
En regardant le code hexa de cette image on se rend compte qu'il y a dans la signature de la fonction deux en-têtes IHDR et entre ces deux en-têtes il y a un en-tête sTeG.</br>
Etrange !?!

![image](https://user-images.githubusercontent.com/73934639/174496636-cc0d1fc6-43f4-4147-a5c1-959d58ea6fdf.png)

 
On essaye de supprimer la partie entre les deux IHDR et on supprime le deuxième :
![image](https://user-images.githubusercontent.com/73934639/174496723-45495724-f1c4-4a08-9079-8b834e693e69.png) </br></br>

Notre signature PNG est maintenant correcte, on sauvegarde et on a le 2e flag : 
![stage2](https://user-images.githubusercontent.com/73934639/174496777-d9b597d7-44f8-4c09-8b42-e1367a401328.png)

Ressources :</br>
Bless (éditeur hexa)</br>
https://www.w3.org/TR/PNG/#11IHDR</br>
