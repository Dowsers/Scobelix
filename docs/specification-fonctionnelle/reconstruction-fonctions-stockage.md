# Reconstruction des fonctions, des paramètres et de la structure du stockage

Ce document (préfixe `STOR`) spécifie le post-traitement qui s'applique aux traces structurées produites par le pipeline de décompilation : la caractérisation de chaque fonction (payable, lecture seule, constante, getter, ordre d'affichage), l'inférence de ses paramètres, la reconstruction de la structure du stockage du contrat (mappings, tableaux, structures, champs masqués, nommage et résilience emplacement par emplacement), l'unification des accès entre fonctions, la détection des slots de proxy standardisés et la liste des constantes du contrat.

La production des traces est décrite dans [pipeline-decompilation.md](pipeline-decompilation.md) (dont la section 11 définit le vocabulaire des nœuds employé ici) ; la résolution des sélecteurs en noms de fonctions et de paramètres est dans [resolution-signatures.md](resolution-signatures.md) ; le rendu des résultats de ce post-traitement, dans le texte comme dans l'AST JSON, est dans [sorties.md](sorties.md), et leur traduction en variables d'état Solidity dans [generation-solidity.md](generation-solidity.md). L'enchaînement global est dans [architecture.md](architecture.md). Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-STOR-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

Chaque fonction décompilée est d'abord caractérisée isolément, à partir de sa seule trace ; la structure du stockage, elle, ne peut être déduite que de l'ensemble des accès de toutes les fonctions et est donc reconstruite une seule fois pour tout le contrat. Dans l'état actuel du système, le contrat est reconstruit comme une fonction de repli unique `_fallback(?)` (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 3) : les règles ci-dessous s'appliquent à cette fonction, qui porte l'arbre de dispatch complet.

## 2. Caractérisation d'une fonction

- **FR-STOR-01** : Le système DOIT considérer une fonction comme non payable lorsque la première instruction de sa trace est un test de la valeur transférée (`callvalue`) dont la branche prise pour une valeur non nulle commence par un rejet sans données ou par `invalid` ; il DOIT alors retirer ce test de la trace et ne conserver que la branche de poursuite. Dans tous les autres cas, la fonction est considérée comme payable.
- **FR-STOR-02** : Le système DOIT considérer une fonction comme en lecture seule si et seulement si sa trace ne contient aucune écriture de stockage (`store`), ni `selfdestruct`, ni `call`, ni `delegatecall`, ni `create`, la détection se faisant par recherche de ces opérateurs dans la représentation textuelle de la trace.

*Note contextuelle : cette détection n'inclut pas `staticcall` (qui est bien sans effet), mais pas non plus `callcode`, `create2` ni `tstore` ; une fonction qui n'effectue que l'une de ces trois opérations est donc, à tort, jugée en lecture seule.*

- **FR-STOR-03** : Le système DOIT considérer comme constante une fonction en lecture seule dont la trace ne contient aucun accès au stockage ni aux données d'appel (détection par recherche textuelle dans la trace) et comporte exactement un retour ; la constante est représentée par cette instruction de retour, et sa valeur affichée est la valeur retournée.
- **FR-STOR-04** : Le système DOIT considérer comme getter une fonction non constante, en lecture seule et à retour unique, dont la valeur retournée est soit une lecture de stockage, éventuellement masquée ou convertie en booléen, soit une suite de lectures de stockage portant toutes sur un même emplacement ou sur des emplacements consécutifs d'un même emplacement de base (structure), soit une suite de valeurs lues à partir d'un même emplacement haché (structure dans un mapping).
- **FR-STOR-05** : Le système DOIT reconnaître comme getter de chaîne une fonction en lecture seule dont tous les retours renvoient un tableau dont la longueur est la longueur d'une chaîne en stockage, et remplacer sa trace par le retour unique de cette chaîne.
- **FR-STOR-06** : Une fonction qui n'est ni constante ni getter DOIT être considérée comme une fonction régulière.
- **FR-STOR-07** : Le système DOIT ordonner l'affichage des fonctions régulières en plaçant d'abord celles qui contiennent un `selfdestruct`, puis les autres par longueur croissante de leur texte rendu.

## 3. Inférence des paramètres

- **FR-STOR-08** : Lorsque la signature de la fonction est connue avec sa liste de paramètres (voir [resolution-signatures.md](resolution-signatures.md)), le système DOIT associer au k-ième paramètre (k à partir de 0) le décalage 4 + 32 × k des données d'appel, avec le type et le nom issus de la signature.
- **FR-STOR-09** : Sinon, le système DOIT déduire les paramètres des accès de la trace aux données d'appel : chaque décalage lu autre que 0 (le sélecteur) définit un paramètre, dont la taille est celle de sa première lecture rencontrée dans la trace : la taille du masque appliqué si cette lecture est masquée, 256 bits sinon.
- **FR-STOR-10** : Un décalage utilisé comme pointeur (lecture à l'adresse « 4 + valeur lue à ce décalage ») DOIT faire classer le paramètre correspondant comme tableau (`array`) ; un paramètre dont toutes les utilisations sont des tests booléens (conversion booléenne, condition, test de nullité) DOIT être classé `bool` ; tout autre paramètre reçoit le plus petit type de la table suivante dont la taille est supérieure ou égale à sa taille observée.

  | Taille (bits) | Type |
  |---|---|
  | 1 | `bool` |
  | 8, 16, 32, 64, 128 | `uint8`, `uint16`, `uint32`, `uint64`, `uint128` |
  | 160 | `address` |
  | 256 | `uint256` |

- **FR-STOR-11** : Si l'un des décalages lus n'est pas de la forme 4 + 32 × k (ou n'est pas une constante), le système DOIT journaliser l'avertissement `unusual cd (not aligned)` et n'inférer aucun paramètre pour la fonction.
- **FR-STOR-12** : Le système DOIT nommer les paramètres inférés `_param1`, `_param2`… dans l'ordre croissant de leur décalage.
- **FR-STOR-13** : Pour une fonction identifiée par un sélecteur non résolu, le système DOIT compléter son nom de repli (voir [resolution-signatures.md](resolution-signatures.md), section 4.1) par la liste des paramètres inférés, sous la forme `(<type> _param1, …)` pour le nom affiché et `(<type>,…)` pour le nom ABI.
- **FR-STOR-14** : Le système DOIT retirer de la trace les masques et conversions devenus redondants avec le type d'un paramètre (conversion booléenne d'un paramètre `bool`, masque dont la taille est celle du type du paramètre), puis, au niveau du contrat, remplacer chaque lecture des données d'appel à un décalage de paramètre par une référence nommée `param` à ce paramètre.

*Note contextuelle : l'inférence héritée prévoit un type `tuple`, mais la condition qui devrait le produire n'est jamais atteinte ; de même, la mise à jour de la taille d'un paramètre lorsque des lectures plus étroites sont observées est inopérante : seule la taille observée à la première lecture est retenue.*

## 4. Reconstruction de la structure du stockage

### 4.1 Collecte et résolution des emplacements

- **FR-STOR-15** : Le système DOIT collecter tous les accès au stockage (lectures et écritures) de toutes les fonctions décompilées et les résoudre ensemble, en une seule reconstruction pour le contrat.
- **FR-STOR-16** : Le système DOIT reconnaître les emplacements hachés au moyen d'une table précalculée des hachés keccak-256 des emplacements 0 à 19 et des clés 0 et 1 appliquées à ces emplacements : une constante d'au moins 39 chiffres hexadécimaux dont l'écriture hexadécimale, préfixe `0x` compris et sans zéro de tête, est contenue dans l'une des entrées de la table (ce qui revient à en être un préfixe) est remplacée par l'emplacement ou l'accès de mapping correspondant, la comparaison par inclusion tolérant des hachés dont les derniers chiffres auraient été tronqués.

*Note contextuelle : les entrées de la table étant écrites sur 64 chiffres avec leurs zéros de tête, les trois hachés qui commencent par le chiffre 0 (emplacements 5 et 11, et clé 0 appliquée à l'emplacement 5) ne peuvent jamais être reconnus ; un tableau dynamique aux emplacements 5 ou 11, par exemple, reste exprimé par son haché brut.*
- **FR-STOR-17** : Le système DOIT interpréter un haché d'une constante comme l'emplacement de base d'un tableau dynamique (`loc`), le haché d'une clé et d'un emplacement comme un accès de mapping (`map`, clé, emplacement), récursivement pour les mappings imbriqués, et l'addition d'un index à un emplacement comme un accès de tableau (`array`, index, emplacement).
- **FR-STOR-18** : Le système DOIT interpréter l'addition d'une constante N à un emplacement de base comme un champ de structure, en ajoutant 256 × N bits au décalage de l'accès.
- **FR-STOR-19** : Un emplacement constant qui est par ailleurs utilisé comme base d'un tableau ou d'un mapping DOIT être interprété comme la longueur de ce tableau (`length`) ; tout autre emplacement constant est un emplacement simple (`loc`).
- **FR-STOR-20** : Après reconstruction, chaque accès DOIT être exprimé sous la forme `stor` (taille, décalage, emplacement), l'emplacement étant l'une des formes `loc` (numéro), `map` (clé, emplacement), `array` (index, emplacement), `length` (emplacement) ou `name` (nom, numéro), et les écritures de stockage de la trace étant réécrites avec la même forme.

### 4.2 Types et définitions

- **FR-STOR-21** : Le système DOIT regrouper les accès par numéro d'emplacement de base ; un accès dont l'emplacement de base ne peut être déterminé est rangé sous la valeur sentinelle 99, et un accès dont l'emplacement de base n'est pas un entier n'engendre aucune définition.
- **FR-STOR-22** : Pour un emplacement dont au moins un accès n'est pas un accès simple, le système DOIT produire au plus une définition, déterminée par le premier de ces accès dans l'ordre de tri : un mapping s'il s'agit d'un accès de mapping, un tableau s'il s'agit d'un accès de tableau ou de longueur, aucune définition sinon ; le type d'élément est alors : une structure si des champs à des décalages non nuls ont été observés parmi les accès de mapping et de tableau (structure de N octets lorsque la taille de l'élément peut être déduite de l'index), sinon la plus petite taille observée parmi ces accès en dehors de 256 bits, ou 256 bits à défaut.
- **FR-STOR-23** : Pour un emplacement dont tous les accès sont des accès simples, le système DOIT produire une définition par champ distinct observé, de type masqué (taille, décalage).
- **FR-STOR-24** : Le système DOIT produire les définitions de stockage triées par numéro d'emplacement, chacune associant un nom, un emplacement et l'un des types de FR-STOR-22 et FR-STOR-23 (représentation dans [sorties.md](sorties.md), sections 2.1 et 3).

### 4.3 Nommage

- **FR-STOR-25** : Le système DOIT nommer une variable d'état d'après le getter qui la lit : nom de la fonction sans sa liste de paramètres, privé du préfixe `get` s'il est suivi d'au moins un caractère, et dont l'initiale est mise en minuscule sauf si le nom est entièrement en majuscules ; pour un getter d'adresse (lecture de 160 bits), le suffixe `Address` est ajouté si le nom ne contient pas déjà `address`, `addr`, `account` ou `owner` (sans tenir compte de la casse) ; pour un mapping ou un tableau, le nom est tronqué juste avant sa première occurrence de `Address`, pourvu qu'il en reste au moins un caractère.
- **FR-STOR-26** : Un getter qui lit un emplacement simple DOIT donner son nom à tous les accès à cet emplacement qui portent sur le même champ (même taille et même décalage) ; un getter qui lit un mapping, un tableau ou une structure DOIT donner son nom à tous les accès fondés sur le même emplacement de base ; un getter qui retourne la longueur d'un tableau NE DOIT nommer aucun emplacement et DOIT journaliser l'avertissement `storage pattern not found`. Les getters booléens sont traités en dernier et ne nomment un emplacement simple que s'il n'a pas déjà reçu un nom et n'a pas servi de base à un mapping ou à un tableau nommé, y compris lors d'une décompilation précédente dans le même processus.
- **FR-STOR-27** : À défaut de getter, le système DOIT nommer la variable `stor<N>` d'après son numéro d'emplacement ; pour un emplacement simple de numéro supérieur ou égal à 1 000, le nom est formé de `stor` suivi des quatre premiers chiffres hexadécimaux du numéro en majuscules (par exemple `stor3608` pour le slot d'implémentation EIP-1967).

### 4.4 Résilience

- **FR-STOR-28** : Si la reconstruction de l'ensemble des accès échoue, le système DOIT rechercher un accès qui échoue à lui seul, l'exclure, et recommencer, jusqu'à réussir ou jusqu'à ne plus trouver d'accès fautif isolable ; en cas de réussite après exclusion, il DOIT journaliser l'avertissement `Storage postprocessing: <n> slot(s) excluded as unresolvable, <m> slot(s) still resolved normally: <liste>`, les autres emplacements restant nommés et typés normalement.
- **FR-STOR-29** : Si l'échec persiste sans accès fautif isolable (défaut qui n'apparaît que par l'interaction de plusieurs accès, ou plus aucun accès à exclure), le système DOIT abandonner la reconstruction, journaliser `Storage postprocessing failed. This is very bad!`, ne produire aucune définition de stockage (valeur `{}`) et laisser les traces non renommées, sans faire échouer la décompilation.

*Note contextuelle : un accès exclu par FR-STOR-28 qui est aussi la cible d'une écriture de stockage fait ensuite échouer la réécriture des traces, ce qui conduit au repli global de FR-STOR-29 (comportement reproduit en isolant artificiellement un accès écrit sur un bytecode de référence) ; la résilience emplacement par emplacement n'est donc pleinement effective que pour des accès en lecture seule, l'accès exclu restant alors exprimé sous sa forme brute dans la trace.*

### 4.5 Unification entre fonctions et affichage

- **FR-STOR-30** : Pour l'affichage, le système DOIT convertir les écritures de stockage en affectations et nommer chaque emplacement simple resté sans nom selon la règle de FR-STOR-27, un emplacement symbolique étant nommé `stor` suivi de son expression.
- **FR-STOR-31** : Le système DOIT supprimer, dans l'affichage, la conversion de type ou la sélection de champ d'un accès au stockage lorsque tous les accès observés au même emplacement, dans toutes les fonctions, utilisent le même type et le même décalage ; dans le cas contraire, la conversion ou le champ explicites (`field_<décalage>`) DOIVENT être conservés.
- **FR-STOR-32** : Lorsque deux emplacements différents reçoivent le même nom, le système DOIT journaliser l'erreur `Seems like we have two locations / storages with the same name: …` et poursuivre.

## 5. Détection des slots de proxy connus

- **FR-STOR-33** : Le système DOIT comparer l'immédiat entier brut de chaque instruction `pushN` du bytecode aux quatre constantes suivantes et produire un indice pour chacune qui y apparaît :

  | Constante | Nom | Description |
  |---|---|---|
  | `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` | `eip1967.proxy.implementation` | `EIP-1967 implementation slot` |
  | `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103` | `eip1967.proxy.admin` | `EIP-1967 admin slot` |
  | `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50` | `eip1967.proxy.beacon` | `EIP-1967 beacon slot` |
  | `0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7` | `PROXIABLE` | `EIP-1822 (UUPS) proxiable UUID slot` |

  Les trois premières valent keccak-256 du nom diminué de 1, conformément à EIP-1967 ; la dernière est le haché brut, conformément à EIP-1822.
- **FR-STOR-34** : Le système DOIT dédoublonner les indices par constante, en ne conservant que la première occurrence dans l'ordre du bytecode, et porter pour chaque indice la position de l'instruction, la constante en hexadécimal, le nom et la description de la table (format dans [sorties.md](sorties.md), section 3).
- **FR-STOR-35** : La détection DOIT rester purement indicative : elle NE DOIT ni lire l'état de la chaîne, ni modifier les traces, ni affirmer que le contrat se comporte comme un proxy ; un contrat peut être un proxy sans utiliser ces slots, et la présence d'une constante ne prouve pas son usage.

## 6. Constantes du contrat

- **FR-STOR-36** : Le système DOIT établir la liste des fonctions constantes du contrat en plaçant d'abord celles dont le nom n'est pas entièrement en majuscules, puis celles dont le nom est entièrement en majuscules (place et format d'affichage dans [sorties.md](sorties.md), section 2.1).

---

Navigation : [architecture.md](architecture.md) · [pipeline-decompilation.md](pipeline-decompilation.md) · [resolution-signatures.md](resolution-signatures.md) · [generation-solidity.md](generation-solidity.md) · [sorties.md](sorties.md) · [integration.md](integration.md) · [README.md](../README.md)
