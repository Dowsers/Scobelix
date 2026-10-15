# Reconstruction des fonctions, des paramètres et de la structure du stockage

Ce document (préfixe `STOR`) spécifie le post-traitement qui s'applique aux traces structurées produites par le pipeline de décompilation : la caractérisation de chaque fonction (payable, lecture seule, constante, getter, ordre d'affichage), l'inférence de ses paramètres, la reconstruction de la structure du stockage du contrat (mappings, tableaux, structures, champs masqués, nommage et résilience emplacement par emplacement), l'unification des accès entre fonctions, la détection des slots de proxy standardisés et la liste des constantes du contrat.

La production des traces est décrite dans [pipeline-decompilation.md](pipeline-decompilation.md) (dont la section 11 définit le vocabulaire des nœuds employé ici, et la section 1 la distinction entre trace exacte et trace d'affichage) ; la résolution des sélecteurs en noms de fonctions et de paramètres est dans [resolution-signatures.md](resolution-signatures.md) ; le rendu des résultats de ce post-traitement, dans le texte comme dans l'AST JSON, est dans [sorties.md](sorties.md), et leur traduction en variables d'état Solidity dans [generation-solidity.md](generation-solidity.md). L'enchaînement global est dans [architecture.md](architecture.md). Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-STOR-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

Le contrat est décompilé en une fonction par sélecteur, plus une fonction de repli et, le cas échéant, une fonction de réception (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 3). Chaque fonction est d'abord caractérisée isolément : ses traits (payable, lecture seule, constante, getter) sont lus sur sa trace d'affichage, ses paramètres sont inférés de sa trace exacte. La structure du stockage, elle, ne peut être déduite que de l'ensemble des accès de toutes les fonctions et est donc reconstruite une seule fois pour tout le contrat, sur les traces d'affichage. Ce post-traitement ne modifie que les traces d'affichage : la trace exacte de chaque fonction reste celle du pipeline.

## 2. Caractérisation d'une fonction

- **FR-STOR-01** : Le système DOIT considérer une fonction comme non payable lorsque la première instruction de sa trace d'affichage qui suit ses écritures mémoire initiales (voir [pipeline-decompilation.md](pipeline-decompilation.md), FR-DEC-24) est un test de la valeur transférée (`callvalue` ou sa négation) dont la branche prise pour une valeur non nulle commence par un rejet sans données ou par `invalid` ; il DOIT alors retirer ce test de la trace d'affichage, qui garde ses écritures mémoire initiales suivies de la branche de poursuite. À défaut d'un tel test, la fonction est non payable si l'analyse du dispatcher l'a marquée comme protégée par un test de la valeur transférée remonté au-dessus du dispatcher (FR-DEC-20), et payable dans tous les autres cas.
- **FR-STOR-02** : Le système DOIT considérer une fonction comme en lecture seule si et seulement si sa trace d'affichage ne contient aucune écriture de stockage (`store`) ou de stockage transitoire (`tstore`), ni `selfdestruct`, `call`, `delegatecall`, `callcode`, `create`, `create2` ou `log`, la détection se faisant par recherche de ces opérateurs dans la représentation textuelle de la trace ; un `staticcall` ou un appel de précompilé ne retire pas ce caractère.
- **FR-STOR-03** : Le système DOIT considérer comme constante une fonction en lecture seule dont la trace d'affichage, après ses écritures mémoire initiales (et après le retrait du test de FR-STOR-01), se réduit à un unique retour d'une valeur constante : un entier, ou un opérateur pur (arithmétique, bits, comparaisons, `mask_shl`, `bytes`, `data`, `arr`, `max`, `min`, `sha3`) appliqué à des constantes, sans aucune lecture de stockage, de données d'appel, de mémoire ou d'environnement. La constante est représentée par cette instruction de retour, et sa valeur affichée est la valeur retournée.
- **FR-STOR-04** : Le système DOIT considérer comme getter une fonction non constante, en lecture seule et à retour unique, dont la valeur retournée est soit une lecture de stockage, éventuellement masquée ou convertie en booléen, soit une suite de lectures de stockage portant toutes sur un même emplacement ou sur des emplacements consécutifs d'un même emplacement de base (structure), soit une suite de valeurs lues à partir d'un même emplacement haché (structure dans un mapping).
- **FR-STOR-05** : Le système DOIT reconnaître comme getter de chaîne une fonction en lecture seule dont tous les retours, au moins un, renvoient la copie d'une même chaîne de stockage (tableau dont la longueur est la longueur de cette chaîne en stockage), et lui associer la lecture de toute la chaîne. Dans la trace d'affichage, un bloc qui ne fait que recopier la chaîne en mémoire puis la retourner (directement, ou dans les deux branches d'un test de sa longueur) DOIT être remplacé par le retour de cette lecture, les autres lignes (contrôles, écritures, appels) et les branches des alternatives étant conservées.
- **FR-STOR-06** : Une fonction qui n'est ni constante ni getter DOIT être considérée comme une fonction régulière.
- **FR-STOR-07** : Le système DOIT ordonner l'affichage des fonctions régulières en plaçant d'abord celles qui contiennent un `selfdestruct`, puis les autres par longueur croissante de leur texte rendu.

## 3. Inférence des paramètres

- **FR-STOR-08** : Lorsque la signature de la fonction est connue avec sa liste de paramètres (voir [resolution-signatures.md](resolution-signatures.md)), le système DOIT associer au k-ième paramètre (k à partir de 0) le décalage 4 + 32 × k des données d'appel, avec le type et le nom issus de la signature.
- **FR-STOR-09** : Sinon, le système DOIT déduire les paramètres de la trace exacte de la fonction, en combinant, de la plus forte à la plus faible, les sources suivantes : les contrôles que le décodeur ABI place en tête de la fonction (FR-STOR-10 à FR-STOR-13), puis l'usage de chaque mot de tête là où il est lu (FR-STOR-14). Un mot de tête est un mot des données d'appel au décalage 4 + 32 × j.
- **FR-STOR-10** : Les contrôles du décodeur DOIVENT être les conditions des gardes de rejet sans données qui ouvrent la fonction, après ses écritures mémoire initiales, prises dans l'ordre où elles sont testées ; la première instruction d'une autre forme arrête cette lecture.
- **FR-STOR-11** : Un contrôle de la forme « taille des données d'appel − 4 inférieure à 32 × k » (comparaison signée ou non signée, 32 × k au plus égal à 32 768) DOIT fixer à k le nombre de mots de tête ; tout mot de tête que la fonction ne lit jamais reçoit alors le type `uint256`, de sorte que les paramètres suivent les positions ABI.
- **FR-STOR-12** : Un contrôle de validation de type d'un mot de tête P DOIT donner le type de ce mot selon la table suivante :

  | Condition de rejet portant sur P | Type |
  |---|---|
  | P ≠ P (code non optimisé, qui contrôle aussi les types de 256 bits) | `uint256` |
  | P ≠ `bool(P)` | `bool` |
  | P ≠ ses N bits de poids faible | `address` si N = 160, `uintN` si N est un multiple de 8 (autre largeur : FR-STOR-16) |
  | P ≠ ses N bits de poids fort (N multiple de 8) | `bytes<N/8>` |
  | P ≠ son extension de signe depuis l'octet b | `int<8 × (b + 1)>` |
  | bits de P au-dessus du bit N non nuls (chaîne via-IR, éventuellement niés deux fois) | `address` si N = 160, `uintN` sinon |
  | P ≥ K, avec 0 < K < 256 | `uint8` (énumération), sauf si P sert à calculer un emplacement de stockage (borne d'un index de tableau) |

  Une non-égalité « P ≠ C » peut aussi prendre la forme d'une différence non nulle entre P et C. Tout contrôle de cette table autre que celui des énumérations signale l'ABI coder v2 (FR-STOR-16).
- **FR-STOR-13** : Un contrôle de borne du décalage d'un paramètre dynamique (P > 2^64 − 1 ou P > 2^32) DOIT classer le mot comme tableau (`array`) ; un contrôle de sa longueur contre la taille des données d'appel DOIT le préciser en `bytes` lorsque la longueur compte des octets et le laisser `array` lorsqu'elle compte des mots de 32 octets.
- **FR-STOR-14** : Le système DOIT aussi examiner chaque lecture d'un mot de tête : un masque à partir du bit 0 donne une largeur, la plus étroite étant retenue ; un masque des N bits de poids fort (N multiple de 8) suggère `bytes<N/8>` et une extension de signe `intN` ; un masque de largeur calculée à l'exécution, un décalage vers la droite, une extraction d'octet ou un décalage vers la gauche qui ne perd que les bits sortant du mot ne disent rien du type (256 bits) ; une copie des données d'un paramètre dynamique classe le mot en `bytes` (longueur comptée en octets) ou en `array` (longueur comptée en mots) ; une lecture à l'adresse 4 + valeur d'un mot, ou à un décalage constant au-delà de la valeur d'un seul mot de tête, classe ce mot comme tableau ; une lecture à un décalage calculé est ignorée.
- **FR-STOR-15** : Si l'un des décalages constants lus, autre que 0 (le sélecteur), n'est pas celui d'un mot de tête, le système DOIT journaliser l'avertissement `unusual cd (not aligned)` et n'inférer aucun paramètre pour la fonction.
- **FR-STOR-16** : Le type de chaque mot DOIT être choisi dans cet ordre : le type donné par son contrôle de validation ; sinon sa nature dynamique (`bytes` l'emportant sur `array`) ; sinon `uint256` lorsque la fonction ou une autre fonction du contrat comporte un contrôle signalant l'ABI coder v2 (le décodeur v2 contrôle tout type plus étroit que 256 bits) ; sinon le type suggéré à l'usage (`bytesN`, `intN`) s'il tient dans la largeur observée ; sinon `bool` si toutes ses utilisations sont des tests booléens (conversion booléenne, condition, test de nullité) ; sinon le type de sa largeur observée : `address` pour 160 bits, `uintN` pour un multiple de 8, et pour toute autre largeur le plus petit type de la table historique (`bool` 1, `uint8`, `uint16`, `uint32`, `uint64`, `uint128`, `address` 160, `uint256`) qui la contient. Un mot contrôlé par le décodeur mais jamais lu ailleurs reçoit aussi son type.
- **FR-STOR-17** : Le système DOIT nommer les paramètres inférés `_param1`, `_param2`… dans l'ordre croissant de leur décalage.
- **FR-STOR-18** : Pour une fonction identifiée par un sélecteur non résolu, le système DOIT compléter son nom de repli (voir [resolution-signatures.md](resolution-signatures.md), section 4.1) par la liste des paramètres inférés, sous la forme `(<type> _param1, …)` pour le nom affiché et `(<type>,…)` pour le nom ABI.
- **FR-STOR-19** : Le système DOIT retirer de la trace d'affichage les masques et conversions devenus redondants avec le type d'un paramètre (conversion booléenne d'un paramètre `bool`, masque dont la taille est celle du type du paramètre), puis, au niveau du contrat, remplacer dans la trace d'affichage chaque lecture des données d'appel à un décalage de paramètre par une référence nommée `param` à ce paramètre.

*Note contextuelle : certains types ne sont pas décidables à partir du bytecode. Le code optimisé de l'ABI coder v2 ne contrôle pas les types de 256 bits : un contrat dont tous les paramètres sont de 256 bits ne révèle donc pas son codeur, et un masque appliqué à l'usage peut alors rétrécir un type ; `bytes32` et `int256` ne se distinguent pas de `uint256` ; avec l'ABI coder v1, un paramètre dynamique dont seule la longueur est lue devient `array`, un `bytesN` seulement lu décalé devient `uint256`, une chaîne recopiée mot à mot devient `array` ; une garde écrite par l'auteur en tête de fonction et rejetant sans données, `require(x < K)` avec K < 256 ou `require(x <= 2**64 - 1)`, est prise pour le contrôle d'une énumération ou d'une borne de décalage. Lorsque le sélecteur est connu, les types et noms de la signature l'emportent (FR-STOR-08).*

## 4. Reconstruction de la structure du stockage

### 4.1 Collecte et résolution des emplacements

- **FR-STOR-20** : Le système DOIT collecter tous les accès au stockage (lectures, et emplacements des écritures) des traces d'affichage de toutes les fonctions décompilées, chacun une seule fois dans l'ordre de sa première apparition, et les résoudre ensemble, en une seule reconstruction pour le contrat.
- **FR-STOR-21** : Le système DOIT reconnaître une constante, d'au moins 2^64, qui diffère de moins de 2^24 du haché keccak-256 d'un emplacement inférieur à 4 096 — un élément ou un membre k des données d'un tableau dynamique ou d'une chaîne, k pouvant être négatif (−1 pour un `pop`) — et la remplacer par cet emplacement de base (`loc`) augmenté de k ; à défaut, une constante égale au haché d'une clé 0 ou 1 appliquée à un emplacement de 0 à 19 DOIT être remplacée par l'accès de mapping correspondant. La comparaison porte sur les valeurs entières.
- **FR-STOR-22** : Le système DOIT interpréter un haché d'une constante comme l'emplacement de base d'un tableau dynamique (`loc`), le haché d'une clé et d'un emplacement comme un accès de mapping (`map`, clé, emplacement), récursivement pour les mappings imbriqués, l'addition d'un index à un emplacement comme un accès de tableau (`array`, index, emplacement), et leurs combinaisons (tableau dans un mapping, élément d'un tableau de tableaux) par imbrication de ces formes.
- **FR-STOR-23** : Le système DOIT interpréter l'addition d'une constante N à un emplacement de base comme un champ de structure, en ajoutant 256 × N bits au décalage de l'accès.
- **FR-STOR-24** : Un emplacement constant qui est par ailleurs utilisé comme base d'un tableau ou d'un mapping DOIT être interprété comme la longueur de ce tableau (`length`) ; tout autre emplacement constant est un emplacement simple (`loc`).
- **FR-STOR-25** : Après reconstruction, chaque accès DOIT être exprimé sous la forme `stor` (taille, décalage, emplacement), l'emplacement étant l'une des formes `loc` (numéro), `map` (clé, emplacement), `array` (index, emplacement), `length` (emplacement) ou `name` (nom, numéro), et les écritures de stockage des traces d'affichage étant réécrites avec la même forme ; un accès que la reconstruction n'a pas résolu (FR-STOR-33) garde sa forme brute.

### 4.2 Types et définitions

- **FR-STOR-26** : Le système DOIT regrouper les accès par numéro d'emplacement de base ; un accès dont l'emplacement de base ne peut être déterminé, ou n'est pas un entier, n'engendre aucune définition.
- **FR-STOR-27** : Pour un emplacement dont au moins un accès n'est pas un accès simple, le système DOIT produire au plus une définition, déterminée par le premier de ces accès dans l'ordre de tri : un mapping s'il s'agit d'un accès de mapping, un tableau s'il s'agit d'un accès de tableau ou de longueur, aucune définition sinon ; le type d'élément est alors : une structure si des champs à des décalages non nuls ont été observés parmi les accès de mapping et de tableau (structure de N octets lorsque la taille de l'élément peut être déduite de l'index), sinon la plus petite taille observée parmi ces accès en dehors de 256 bits, ou 256 bits à défaut.
- **FR-STOR-28** : Pour un emplacement dont tous les accès sont des accès simples, le système DOIT produire une définition par champ distinct observé, de type masqué (taille, décalage).
- **FR-STOR-29** : Le système DOIT produire les définitions de stockage triées par numéro d'emplacement, chacune associant un nom, un emplacement et l'un des types de FR-STOR-27 et FR-STOR-28 (représentation dans [sorties.md](sorties.md), sections 2.1 et 3).

### 4.3 Nommage

- **FR-STOR-30** : Le système DOIT nommer une variable d'état d'après le getter qui la lit : nom de la fonction sans sa liste de paramètres, privé du préfixe `get` s'il est suivi d'au moins un caractère, et dont l'initiale est mise en minuscule sauf si le nom est entièrement en majuscules ; pour un getter d'adresse (lecture de 160 bits), le suffixe `Address` est ajouté si le nom ne contient pas déjà `address`, `addr`, `account` ou `owner` (sans tenir compte de la casse) ; pour un mapping, un tableau ou une structure, le nom est tronqué juste avant sa première occurrence de `Address`, pourvu qu'il en reste au moins un caractère.
- **FR-STOR-31** : Un getter qui lit un emplacement simple DOIT donner son nom à tous les accès à cet emplacement qui portent sur le même champ (même taille et même décalage) ; un getter qui lit un mapping, un tableau ou une structure DOIT donner son nom à tous les accès fondés sur le même emplacement de base ; un getter qui retourne la longueur d'un tableau NE DOIT nommer aucun emplacement et DOIT journaliser l'avertissement `storage pattern not found`. Les getters booléens sont traités en dernier : celui d'un emplacement simple ne nomme que les accès de ce champ restés sans nom, et seulement si l'emplacement n'a pas servi de base à un mapping ou à un tableau nommé ; celui qui lit à travers un mapping ou un tableau (`isAdmin(address)`, par exemple) nomme l'emplacement de base auquel l'accès se résout, s'il n'a pas déjà été nommé ainsi. Les noms attribués ne valent que pour le contrat en cours de décompilation.
- **FR-STOR-32** : À défaut de getter, le système DOIT nommer la variable `stor<N>` d'après son numéro d'emplacement ; pour un emplacement simple de numéro supérieur ou égal à 1 000, le nom est formé de `stor` suivi des quatre premiers chiffres hexadécimaux du numéro en majuscules (par exemple `stor3608` pour le slot d'implémentation EIP-1967).

### 4.4 Résilience

- **FR-STOR-33** : Si la reconstruction de l'ensemble des accès échoue, le système DOIT rechercher un accès qui échoue à lui seul, l'exclure, et recommencer, jusqu'à réussir ou jusqu'à ne plus trouver d'accès fautif isolable ; en cas de réussite après exclusion, il DOIT journaliser l'avertissement `Storage postprocessing: <n> slot(s) excluded as unresolvable, <m> slot(s) still resolved normally: <liste>`, les autres emplacements restant nommés et typés normalement.
- **FR-STOR-34** : Si l'échec persiste sans accès fautif isolable (défaut qui n'apparaît que par l'interaction de plusieurs accès, ou plus aucun accès à exclure), le système DOIT abandonner la reconstruction, journaliser `Storage postprocessing failed. This is very bad!`, ne produire aucune définition de stockage (valeur `{}`) et laisser les traces non renommées, sans faire échouer la décompilation.

*Note contextuelle : un accès exclu par FR-STOR-33 garde sa forme brute aussi bien dans les lectures que dans les écritures de stockage, sans empêcher la réécriture des autres accès : la résilience emplacement par emplacement vaut donc aussi pour un emplacement écrit.*

### 4.5 Unification entre fonctions et affichage

- **FR-STOR-35** : Pour l'affichage, le système DOIT convertir les écritures de stockage en affectations et nommer chaque emplacement simple resté sans nom selon la règle de FR-STOR-32, un emplacement symbolique étant nommé `stor` suivi de son expression.
- **FR-STOR-36** : Le système DOIT supprimer, dans l'affichage, la conversion de type ou la sélection de champ d'un accès au stockage lorsque tous les accès observés au même emplacement, dans toutes les fonctions, utilisent le même type et le même décalage ; dans le cas contraire, la conversion ou le champ explicites (`field_<décalage>`) DOIVENT être conservés.
- **FR-STOR-37** : Lorsque deux emplacements différents reçoivent le même nom, le système DOIT journaliser l'erreur `Seems like we have two locations / storages with the same name: …` et poursuivre.

## 5. Détection des slots de proxy connus

- **FR-STOR-38** : Le système DOIT comparer l'immédiat entier brut de chaque instruction `pushN` du bytecode désassemblé aux quatre constantes suivantes et produire un indice pour chacune qui y apparaît :

  | Constante | Nom | Description |
  |---|---|---|
  | `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` | `eip1967.proxy.implementation` | `EIP-1967 implementation slot` |
  | `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103` | `eip1967.proxy.admin` | `EIP-1967 admin slot` |
  | `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50` | `eip1967.proxy.beacon` | `EIP-1967 beacon slot` |
  | `0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7` | `PROXIABLE` | `EIP-1822 (UUPS) proxiable UUID slot` |

  Les trois premières valent keccak-256 du nom diminué de 1, conformément à EIP-1967 ; la dernière est le haché brut, conformément à EIP-1822.
- **FR-STOR-39** : Le système DOIT dédoublonner les indices par constante, en ne conservant que la première occurrence dans l'ordre du bytecode, et porter pour chaque indice la position de l'instruction, la constante en hexadécimal, le nom et la description de la table (format dans [sorties.md](sorties.md), section 3).
- **FR-STOR-40** : La détection DOIT rester purement indicative : elle NE DOIT ni lire l'état de la chaîne, ni modifier les traces, ni affirmer que le contrat se comporte comme un proxy ; un contrat peut être un proxy sans utiliser ces slots, et la présence d'une constante ne prouve pas son usage.

## 6. Constantes du contrat

- **FR-STOR-41** : Le système DOIT établir la liste des fonctions constantes du contrat en plaçant d'abord celles dont le nom n'est pas entièrement en majuscules, puis celles dont le nom est entièrement en majuscules (place et format d'affichage dans [sorties.md](sorties.md), section 2.1).

---

Navigation : [architecture.md](architecture.md) · [pipeline-decompilation.md](pipeline-decompilation.md) · [resolution-signatures.md](resolution-signatures.md) · [generation-solidity.md](generation-solidity.md) · [sorties.md](sorties.md) · [integration.md](integration.md) · [README.md](../README.md)
