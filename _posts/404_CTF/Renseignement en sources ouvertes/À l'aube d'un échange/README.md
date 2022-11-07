# À l'aube d'un échange

Nous avons ici [une image prise au coucher de soleil](https://github.com/Nouman404/404CTF_2022/blob/main/Renseignement%20en%20sources%20ouvertes/%C3%80%20l'aube%20d'un%20%C3%A9change/Lieu.jpg). On ne voit pas grand-chose hormis deux gratte-ciels et une église.</br>
Soit on sait qu'ils se trouvent à Lyon soit nous devons chercher la [liste des gratte-ciel de France](https://fr.wikipedia.org/wiki/Liste_des_plus_hauts_gratte-ciel_de_France).
On trouve rapidement le "Tour Incity" puis la "Tour Part-Dieu".</br>
![image](https://user-images.githubusercontent.com/73934639/174500911-3d361fa9-a479-4eeb-ab9d-10bad7e27db7.png)
![image](https://user-images.githubusercontent.com/73934639/174500905-5b11b0d5-8df4-4652-a401-0a1b86d54cb4.png)

Personnellement, j'ai préféré utiliser [Google Earth](https://earth.google.com/web) pour la dernière partie qui consiste à trouver l'emplacement exact de la photo. 
En se déplaçant, on trouve [le lieu](https://earth.google.com/web/search/Lyon/@45.76430214,4.82785665,190.54575291a,149.36929066d,35y,89.25874082h,74.58394822t,359.99999999r/data=CigiJgokCbknia3_XTJAEUvQckFhczXAGUF_Xpx--VtAIRHSMIRJhGLA) grâce aux deux tours et à l'église (St-Nizier) sur la gauche :</br>
![image](https://user-images.githubusercontent.com/73934639/174501350-113816fa-7326-422d-adf8-03eb37c28e48.png)

On voit que le numéro de rue est ```17 Mnt Saint-Barthélemy```:  </br>
![image](https://user-images.githubusercontent.com/73934639/174501431-8b721fea-fb12-44dc-a20b-64efdc305bac.png)</br>

Le flag doit être de la forme : </br>
![image](https://user-images.githubusercontent.com/73934639/174501489-fb16889f-32c8-4e02-9741-f49b55c39be7.png)

On a donc md5(mnt-saint-barthelemy). Mais ```mnt``` signifie ```montée``` (cf: [abréviation](https://www.cohesion-territoires.gouv.fr/sites/default/files/2019-05/Comite%20scientfique%20de%20l%27observation%20des%20loyers_Annexe_abreviations_des_noms_de_voie.pdf))
Ce qui nous donne : md5(montee-saint-barthelemy) = eb66c65861da9fe667f26667b3427d2c
Le flag est donc : ```404CTF{eb66c65861da9fe667f26667b3427d2c}```
