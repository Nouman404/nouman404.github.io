# Je suis une théière 

Pour ce challenge, on devait trouver une page où se trouvait une théière. Mais où ???
Si on  [regarde les sous-domaines](https://www.nmmapper.com/sys/tools/subdomainfinder/) du site http://404ctf.fr, on trouve un domaine étrange : https://hello-world.404ctf.fr/

Il faut résoudre le labyrinthe. On se déplace du nombre de case qui est indiquée par celle sur laquelle on est (ex.: on est sur une case avec le numéro 2, ça veut dire qu'on peut se déplacer de deux cases dans n'importe quelle direction.
![image](https://user-images.githubusercontent.com/73934639/174500243-6c168ca4-d32d-44be-879f-7ad8f8eaaffa.png)

Le chemin est le suivant :</br>
![image](https://user-images.githubusercontent.com/73934639/174500492-58d7695d-2581-4b51-8a65-9e8f7cde4646.png)

À chaque déplacement, on note les valeurs qu'il y a sur le four et on obtient une chaine en base64. On décode et on a le flag :</br>

![image](https://user-images.githubusercontent.com/73934639/174500205-0a7e0fb3-2888-4483-a8d2-802e1ecced53.png)

