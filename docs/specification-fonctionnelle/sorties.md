# Sorties produites par Scobelix

Ce document (préfixe `SOR`) spécifie le format exact de tout ce que le système produit : le pseudo-code texte (structure, blocs, syntaxe des lignes et des expressions, couleurs), l'AST JSON clé par clé, le payload JSON combiné, la sortie Solidity de la commande et son résumé de vérification, le rapport de vérification, ainsi que la journalisation, le fichier de profil et les autres effets observables. Il ne décrit pas comment ces contenus sont calculés.

Le contenu du code Solidity généré (en-tête, traduction, niveaux de réécriture, confiance) est spécifié dans [generation-solidity.md](generation-solidity.md), auquel les sections 4 à 6 renvoient ; le vocabulaire de la trace sérialisée dans l'AST est défini dans [pipeline-decompilation.md](pipeline-decompilation.md), section 11 ; la façon dont les options de la commande sélectionnent une sortie est dans [architecture.md](architecture.md), section 7 ; les effets sur le système de fichiers, vus comme échanges avec l'environnement, sont dans [integration.md](integration.md), section 3. Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-SOR-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

| Sortie | Obtenue par | Canal |
|---|---|---|
| Pseudo-code texte | commande sans drapeau de format ; champ `text` de l'interface Python | sortie standard |
| AST JSON indenté | `--json` ; champ `json` | sortie standard |
| Payload JSON combiné | `--combined-json` | sortie standard |
| Code Solidity | `--solidity` ; génération par l'interface Python | sortie standard |
| Résumé de vérification | `--solidity --verify` | sortie d'erreur |
| Rapport de vérification | `--combined-json --solidity --verify` (clé `solgen_verification`) ; vérification par l'interface Python | sortie standard |
| Statut de validation | `--solidity --validate-solidity` ; validation par l'interface Python | sortie d'erreur |
| Désassemblage, bytecode, fonctions en mémoire | champs `asm`, `bytecode` et `functions` de l'interface Python uniquement | — |
| Message d'entrée invalide | bytecode qui n'est pas une chaîne hexadécimale | sortie d'erreur |
| Journalisation | toute exécution | sortie d'erreur |
| Profil d'exécution | `--profile` | fichier `scobelix.prof` |

- **FR-SOR-01** : La commande DOIT écrire exactement une sortie principale par entrée traitée sur la sortie standard, et réserver la sortie d'erreur à la journalisation, au résumé de vérification, au statut de validation et au message d'une entrée invalide, sous la seule réserve du mode `--explain` (voir [architecture.md](architecture.md), section 7).
- **FR-SOR-02** : Le texte, l'AST et le payload combiné d'une même décompilation DOIVENT être cohérents entre eux : mêmes fonctions, mêmes échecs, mêmes définitions de stockage et mêmes indices de proxy.

## 2. Pseudo-code texte (sortie par défaut)

### 2.1 Organisation du texte

- **FR-SOR-03** : Le texte DOIT commencer par la ligne `# Palkeoramix decompiler. ` (avec l'espace final).
- **FR-SOR-04** : Lorsqu'au moins un slot de proxy est reconnu, le texte DOIT comporter ensuite le bloc suivant, suivi d'une ligne vide, avec une ligne par indice :

```
#
#  Detected known proxy storage slot(s):
#  - <slot en hexadécimal> (<description>)
#
```

- **FR-SOR-05** : Lorsqu'au moins une fonction a échoué, le texte DOIT comporter ensuite le bloc suivant, avec une ligne par fonction en échec portant son nom :

```
#
#  I failed with these: 
#  - <nom de la fonction>
#  All the rest is below.
#
```

- **FR-SOR-06** : Le texte DOIT comporter ensuite une ligne vide, puis, dans cet ordre : les constantes, une ligne par constante `const <nom> = <valeur>` (le nom étant le nom affiché de la fonction privé d'une liste de paramètres vide « () » éventuelle, soit par exemple `const magic = 'ABCDEFGH'` pour une fonction `magic()`), suivies d'une ligne vide s'il y en a ; le bloc de stockage (FR-SOR-07) s'il existe au moins une définition ; les getters ; les fonctions régulières, dans l'ordre de [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 2 ; chaque getter et chaque fonction régulière étant suivi d'une ligne vide.
- **FR-SOR-07** : Le bloc de stockage DOIT commencer par la ligne `def storage:` et comporter une ligne par définition, `  <nom> is <type> at storage <emplacement>`, le bloc étant suivi d'une ligne vide ; le type s'écrit `uint<N>`, `address` ou `bool` pour un champ simple, avec le suffixe ` offset <décalage>` lorsque le champ est décalé, `mapping of <type>`, `array of <type>`, `struct` ou `struct <N> bytes` ; l'emplacement s'écrit en hexadécimal lorsqu'il est strictement supérieur à 1 000 et en décimal sinon.
- **FR-SOR-08** : Lorsque des constantes ou des getters ont été affichés et qu'il reste au moins une fonction régulière à afficher, le texte DOIT insérer avant les fonctions régulières le séparateur suivant, suivi d'une ligne vide :

```
#
#  Regular functions
#
```

- **FR-SOR-09** : Une fonction régulière dont la simplification a été arrêtée par sa limite de temps (voir [architecture.md](architecture.md), section 4) DOIT être précédée de la ligne de commentaire `# (simplification stopped at its time limit: exact, not fully simplified)` ; le code affiché reste exact, seulement moins simplifié.

*Note contextuelle : une constante ou un getter dont la simplification a été arrêtée de la même façon n'est pas précédé de cette ligne ; la marque figure toutefois dans l'AST (FR-SOR-38).*

- **FR-SOR-10** : Pour un bytecode vide, ou réduit au seul bloc de métadonnées du compilateur, le texte DOIT se réduire à la seule ligne `# No code found for this contract.`, sans en-tête.

### 2.2 En-tête et corps d'une fonction

- **FR-SOR-11** : L'en-tête d'une fonction non constante DOIT avoir la forme `def <nom>[ payable]: <commentaire>`, où le nom est `nom(type nom, …)`, `_fallback(?)` pour la fonction de repli ou `_receive(?)` pour la fonction de réception, où ` payable` est présent si la fonction est payable, et où le commentaire vaut `# not payable` pour une fonction non payable, `# default function` pour la fonction de repli payable, `# not payable, default function` pour la fonction de repli non payable, `# receive function (empty calldata)` pour la fonction de réception, et est vide sinon.
- **FR-SOR-12** : Le corps DOIT être indenté de deux espaces au premier niveau, puis de quatre espaces supplémentaires par niveau d'imbrication ; un corps vide DOIT être affiché `  stop`, et une instruction `stop` finale au premier niveau NE DOIT PAS être affichée.
- **FR-SOR-13** : Le corps DOIT être rendu à partir de la vue pliée de la fonction (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 10), sans modifier la trace portée par l'AST.

### 2.3 Syntaxe des instructions

- **FR-SOR-14** : Un test dont une branche se réduit à un rejet sans données ou à `invalid` DOIT être affiché `require <condition qui évite le rejet>` suivi des instructions de l'autre branche au même niveau ; un nœud `require` DOIT être affiché `require <condition>` lorsque son échec est un rejet sans données ou `invalid`, et sinon `if <négation de la condition>:` suivi de l'instruction d'échec indentée (par exemple `if caller <= 0:` puis `revert with Panic(1)`).
- **FR-SOR-15** : Les autres tests DOIVENT être affichés `if <condition>:` suivi de la branche vraie indentée et, le cas échéant, de `else:` suivi de la branche fausse indentée ; une boucle DOIT être affichée par les affectations initiales de ses variables (`<variable> = <valeur>`), puis `while <condition>:` suivi du corps indenté ; un retour en tête de boucle DOIT être affiché par ses réaffectations, une par ligne, puis `continue `. Lorsque la valeur d'une réaffectation lit une variable réaffectée avant elle dans ce même retour, les réaffectations DOIVENT être regroupées en une seule affectation parallèle `<v1>, <v2>, … = <valeur1>, <valeur2>, …`, toutes les valeurs étant celles d'avant le retour.
- **FR-SOR-16** : Une affectation de variable DOIT être affichée `<variable> = <valeur>`, une écriture mémoire `mem[<adresse>] = <valeur>` (ou `mem[<adresse> len <longueur>] = <valeur>` pour une longueur autre que 32 octets), une écriture de stockage transitoire `tstorage[<emplacement>] = <valeur>`.
- **FR-SOR-17** : Une écriture de stockage DOIT être affichée `<variable> = <valeur>`, ou sous la forme abrégée `<variable>++`, `<variable>--`, `<variable> += <v>` ou `<variable> -= <v>` lorsque la valeur est la variable elle-même augmentée ou diminuée d'une quantité.
- **FR-SOR-18** : Un retour ou un rejet DOIT être affiché `return <valeurs>` ou `revert with <valeurs>` (valeurs séparées par des virgules, suites de mots reconnues comme chaînes affichées entre apostrophes), `return` seul pour un retour sans données, `revert` seul pour un rejet sans données ou une instruction `invalid`, et, lorsque les données sont une zone mémoire non résolue, `return memory` ou `revert with memory` suivi de deux lignes donnant le début et la longueur (ou la fin) de la zone. Lorsque les données d'un rejet commencent par un sélecteur d'erreur que la base de signatures nomme (voir [resolution-signatures.md](resolution-signatures.md), section 4.2), ce sélecteur DOIT être affiché par la signature de l'erreur, par exemple `revert with Error(string reason), 'insufficient balance'`.
- **FR-SOR-19** : Un rejet dont les données sont le sélecteur `Panic(uint256)` (0x4e487b71), sous la forme d'une partie de 4 octets, suivi d'un code entier constant DOIT être affiché `revert with Panic(<code en décimal>)`, suivi, pour les codes connus, d'un commentaire `# <libellé>` tiré de la table suivante :

  | Code | Libellé affiché |
  |---|---|
  | 0x00 | Used for generic compiler inserted panics. |
  | 0x01 | If you call assert with an argument that evaluates to false. |
  | 0x11 | If an arithmetic operation results in underflow or overflow outside of an unchecked { ... } block. |
  | 0x12 | If you divide or modulo by zero (e.g. 5 / 0 or 23 % 0). |
  | 0x21 | If you convert a value that is too big or negative into an enum type. |
  | 0x22 | If you access a storage byte array that is incorrectly encoded. |
  | 0x31 | If you call .pop() on an empty array. |
  | 0x32 | If you access an array, bytesN or an array slice at an out-of-bounds or negative index (i.e. x[i] where i >= x.length or i < 0). |
  | 0x41 | If you allocate too much memory or create an array that is too large. |
  | 0x51 | If you call a zero-initialized variable of internal function type. |

- **FR-SOR-20** : Un retour ou un rejet d'une suite de données dont la représentation atteint 120 caractères visibles DOIT être découpé sur plusieurs lignes, une valeur par ligne alignée sous la première, une valeur initiale `32` étant regroupée avec la suivante.
- **FR-SOR-21** : Une décompilation interrompue ou un saut non résolu DOIT être affiché `...  # Decompilation aborted, sorry: <paramètres>`.
- **FR-SOR-22** : Un journal d'événement DOIT être affiché `log <événement>(<type> <nom>=<valeur>)` pour un paramètre unique, sur plusieurs lignes (une par paramètre) lorsqu'il y en a plusieurs, `log <événement>` lorsqu'il n'a pas de données, et `log <événement>: <valeurs>` lorsque l'événement n'est pas résolu (voir [resolution-signatures.md](resolution-signatures.md), section 4.2). Lorsqu'au moins un sujet est calculé à l'exécution, seul le premier sujet DOIT désigner l'événement, les suivants étant affichés comme des valeurs après les données ; lorsque tous les sujets sont des constantes, chacun DOIT être affiché sur sa propre ligne `log`, seul le premier étant cherché comme événement, et un journal sans aucun sujet (`log0`) n'est pas affiché.
- **FR-SOR-23** : Un appel externe DOIT être affiché sur plusieurs lignes : `call <adresse>.<fonction> with:` (ou `call <adresse> with:` suivi de `   funct <sélecteur>`), puis `   value <valeur> wei` si une valeur est transférée, `     gas <gas> wei`, et `    args <arguments>` s'il y en a ; un appel en lecture seule suit le même schéma avec `static call`, un appel délégué avec `delegate` et un appel `callcode` avec `codecall`. Lorsque les données de l'appel commencent par une partie de 4 octets, cette partie DOIT être affichée comme la fonction appelée et le reste comme ses arguments.
- **FR-SOR-24** : `selfdestruct(<bénéficiaire>)`, `<variable> = <précompilé>(<arguments>) # precompiled`, `create contract with <valeur> wei` suivi de `                code: <code>`, et `create2 contract with <valeur> wei` suivi des lignes `salt:` et `code:` DOIVENT être les formes d'affichage respectives de l'autodestruction, d'un appel de précompilé et des créations de contrat.
- **FR-SOR-25** : Les lignes de commentaire insérées par le mode `--verbose` DOIVENT être affichées précédées de `# `, et un label résiduel sous la forme `label Node(…) setvars: …` (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 7).

*Note contextuelle : les deux derniers cas de FR-SOR-22 sont des limites de l'affichage hérité : un `log4` dont les quatre sujets sont des constantes apparaît comme quatre journaux distincts, et un `log0` disparaît du texte ; l'AST JSON (FR-SOR-39) et le code Solidity généré conservent chaque journal tel qu'il est.*

### 2.4 Syntaxe des expressions

- **FR-SOR-26** : Les valeurs d'environnement DOIVENT être affichées ainsi :

  | Valeur | Affichage |
  |---|---|
  | valeur transférée, appelant, origine | `call.value`, `caller`, `tx.origin` |
  | adresse du contrat, solde | `this.address`, `eth.balance(<adresse>)` |
  | sélecteur appelé (mot 0 des données d'appel) | `call.func_hash` |
  | taille des données d'appel, des données de retour | `calldata.size`, `return_data.size` |
  | numéro, horodatage, bénéficiaire, limite de gas du bloc | `block.number`, `block.timestamp`, `block.coinbase`, `block.gas_limit` |
  | aléa, frais de base, frais de blob, prix du gas | `block.prevrandao`, `block.basefee`, `block.blobbasefee`, `block.gasprice` |
  | haché de bloc, haché de blob | `block.hash(<n>)`, `block.blobhash(<i>)` |
  | gas restant | `gas_remaining` |
  | haché et taille du code d'un compte | `<adresse>.codehash`, `<adresse>.code.length` |
  | stockage transitoire | `tstorage[<emplacement>]` |

- **FR-SOR-27** : Les opérateurs DOIVENT être affichés en notation infixe (`+`, `-`, `*`, `/`, `%`, `^` pour la puissance, `<<`, `>>`, `<`, `>`, `<=`, `>=`, `==`, `!=`, `and`, `or`, `xor`), les comparaisons et opérations signées étant marquées d'un prime (`<′`, `>′`, `<=′`, `>=′`, `/′`, `%′`, `>>′` …), la négation bit à bit sous la forme `!(<valeur>)`, un test de nullité qui n'est pas une comparaison sous la forme `(<valeur> == 0)` et une constante négative opérande d'une comparaison sans signe sous la forme `2^256 - <n>` ; les opérations sans équivalent infixe DOIVENT être affichées comme des appels : `min(…)`, `max(…)`, `addmod(…)`, `mulmod(…)` et `byte(<indice>, <valeur>)`.
- **FR-SOR-28** : Les masques DOIVENT être affichés comme des conversions de type lorsque leur taille correspond à un type (`uint8(…)`, `uint32(…)`, `address(…)`, `bool(…)`…, ainsi que `uint255(…)`), sous la forme d'un modulo par une puissance de deux pour une taille inférieure à 64 bits sans type correspondant, sous la forme `Mask(<taille>, <décalage>, <valeur>)` sinon, les décalages de moins de 8 bits étant rendus par une multiplication ou une division par une puissance de deux et les autres par `<<` ou `>>` ; les arrondis à 32 octets sont affichés `ceil32(…)` et `floor32(…)`, et l'extension de signe d'un entier de N bits `int<N>(…)`.
- **FR-SOR-29** : Les accès aux données DOIVENT être affichés `mem[<adresse>]` (ou `mem[<adresse> len <longueur>]`), `call.data[<début> len <longueur>]` (ou `call.data[<début>]` pour 32 octets), `ext_call.return_data[…]`, `code.data[<début> len <longueur>]`, un tableau dynamique `Array(len=<longueur>, data=<données>)`, un paramètre par son nom, la longueur ou l'élément d'un paramètre tableau `<nom>.length` et `<nom>[<k>]`, et les autres lectures de données d'appel `cd[<décalage>]`.
- **FR-SOR-30** : Les accès au stockage DOIVENT être affichés par le nom de la variable d'état, suivi de `[<clé>]` pour un mapping ou un tableau (`[<clé1>][<clé2>]` pour un mapping imbriqué), de `.length` pour une longueur et de `.field_<décalage>` pour un champ de structure ; une variable de 256 bits dont le type doit être rendu explicite est affichée `uint256(<variable>)`, et un emplacement non résolu `stor[<emplacement>]`.
- **FR-SOR-31** : Les variables DOIVENT être affichées par leur nom lisible (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 8), et les booléens littéraux qui subsistent dans la vue d'affichage par `True` et `False` ; la simplification ayant déjà ramené la plupart des booléens littéraux de la trace aux entiers 1 et 0 (même section), ceux-ci s'affichent comme des entiers.
- **FR-SOR-32** : Les entiers DOIVENT être affichés selon la première des règles suivantes qui s'applique : (1) un multiple de 86 400 strictement supérieur à 86 400 sous la forme `<n> * 24 * 3600` (voir la note ci-dessous) ; (2) un multiple de 3 600 strictement supérieur à 3 600 sous la forme `<n> * 3600` ; (3) un entier strictement compris entre 10^15 et 2^256 dont les octets, zéros de fin exceptés, sont tous non nuls et forment un texte de caractères imprimables, sous la forme de ce texte entre apostrophes (par exemple `'Hello'`) ; (4) un entier supérieur à 2^150 en hexadécimal ; (5) un multiple non nul de 10^k, pour la plus grande valeur de k prise de 18 à 9 puis 6, sous la forme `10^<k>` ou `<n> * 10^<k>` ; (6) en décimal s'il est négatif ou inférieur à 2^90 ; (7) en hexadécimal sinon. Dans les règles (1) et (2), n est lui-même mis en forme selon ces règles et l'ensemble est placé entre parenthèses à l'intérieur d'une expression (par exemple 9 × 10^18 est affiché `25 * 10^14 * 3600`). Un entier NE DOIT PAS être remplacé par une signature du seul fait qu'il coïncide avec un sélecteur connu (0xa9059cbb s'affiche `2835717307`) : seules les positions de FR-SOR-33 portent des noms.

*Note contextuelle : une règle héritée destinée aux durées en jours affiche un multiple de 86 400 strictement supérieur à 86 400 sous la forme `<n> * 24 * 3600` où n est le nombre d'heures et non de jours ; par exemple 172 800 (deux jours) est affiché `(48 * 24 * 3600)`, expression qui vaut 24 fois la valeur réelle. L'AST JSON conserve la valeur exacte.*

- **FR-SOR-33** : Une valeur placée en position de sélecteur (voir [resolution-signatures.md](resolution-signatures.md), section 4.2) DOIT être affichée par la signature que lui donne la base de signatures et, à défaut, lorsqu'elle est comparée au sélecteur appelé ou à la tête de 4 octets d'un autre mot, sous la forme `0x` suivie de huit chiffres hexadécimaux. Une partie non nulle d'une suite d'octets dont la largeur explicite est inférieure à 32 octets DOIT être affichée comme un texte entre apostrophes lorsque ses octets, au moins deux, sont tous des caractères imprimables autres que l'apostrophe, et sinon sous la forme `0x` suivie de tous ses chiffres hexadécimaux (par exemple `0x1901`), de sorte que sa largeur reste visible.

### 2.5 Couleurs

- **FR-SOR-34** : Le texte DOIT contenir, qu'il soit destiné à un terminal ou non, des séquences d'échappement ANSI de sélection de couleur (`ESC[…m`) : gris pour l'en-tête, les commentaires et les indications de type, magenta pour les mots-clés `def` des fonctions et `const`, vert pour le mot-clé `def` du bloc de stockage, les noms de variables d'état et de paramètres et les mots-clés de boucle, bleu pour les variables locales, gras pour les opérateurs, rouge pour les fonctions en échec et les bénéficiaires d'autodestruction, jaune pour les appels délégués et les décompilations interrompues ; un appelant qui souhaite un texte brut DOIT retirer ces séquences.

## 3. AST JSON (`--json` et champ `json`)

- **FR-SOR-35** : L'AST DOIT être un objet à six clés, dans cet ordre : `problems`, `stor_defs`, `functions`, `proxy_hints`, `metadata`, `dispatcher`.
- **FR-SOR-36** : `problems` DOIT être un objet associant l'identifiant de chaque fonction en échec (`_fallback`, `_receive` ou un sélecteur écrit `0x` suivi de huit chiffres hexadécimaux en minuscules) à son nom affiché ; il est vide en l'absence d'échec.
- **FR-SOR-37** : `stor_defs` DOIT être une liste de quadruplets `["def", <nom>, <emplacement>, <type>]`, où l'emplacement est un entier et le type l'une des formes `["mapping", T]`, `["array", T]` ou `["mask", <taille>, <décalage>]`, T étant une taille en bits, la chaîne `"struct"` ou `["struct", <N>]` ; elle est vide si aucun stockage n'est accédé, et vaut l'objet vide `{}` lorsque la reconstruction du stockage a échoué (voir [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 4).
- **FR-SOR-38** : `functions` DOIT être une liste d'objets, un par fonction décompilée avec succès, portant dans cet ordre les clés `hash` (identifiant), `name` (nom affiché), `color_name` (nom avec les noms de paramètres colorés), `abi_name` (`nom(type,type)`, `_fallback(?)` ou `_receive(?)`), `length` (couple `[nombre de lignes, nombre de caractères]` du texte de la fonction, séquences de couleur comprises), `getter` (expression lue par le getter, ou `null`), `const` (instruction de retour de la constante, ou `null`), `payable` (booléen), `print` (texte de la fonction tel qu'affiché, avec couleurs), `trace` et `params`, suivies, pour une fonction dont la simplification a été arrêtée par sa limite de temps (FR-SOR-09), de la clé `time_limited` valant `true` ; cette clé est absente pour les autres fonctions.
- **FR-SOR-39** : `trace` DOIT être la trace arborescente non pliée de la vue d'affichage de la fonction — sa forme simplifiée, à laquelle s'appliquent aussi les heuristiques de lisibilité de [pipeline-decompilation.md](pipeline-decompilation.md), section 9.1, puis le nommage des paramètres et des variables d'état — exprimée dans le vocabulaire de la section 11 du même document, les n-uplets étant convertis en listes et tout objet non natif en sa représentation textuelle. Elle NE DOIT PAS être prise pour la sémantique exacte de la fonction : la trace exacte n'est exposée que par les fonctions en mémoire de l'interface Python ([architecture.md](architecture.md), section 8).
- **FR-SOR-40** : `params` DOIT être un objet associant à chaque décalage de paramètre, écrit en chaîne décimale (par exemple `"4"`, `"36"`), le couple `[<type>, <nom>]`.
- **FR-SOR-41** : `proxy_hints` DOIT être une liste d'objets à quatre clés : `line` (position de l'instruction, entier), `slot` (constante en hexadécimal minuscule préfixée `0x`), `name` et `description` (voir [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 5).
- **FR-SOR-42** : `metadata` DOIT valoir `null` lorsque le bytecode ne se termine pas par un bloc de métadonnées de compilateur reconnu (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 2), et sinon un objet portant dans cet ordre les clés `compiler` (`solc` ou `vyper`), `version` (version exacte `X.Y.Z` lorsque le bloc l'indique, sinon `null`), `version_range` (couple `[minimum, maximum]` lorsque seule une plage peut être déduite, sinon `null`), `prerelease` (texte complet d'une version de préversion, sinon `null`), `hash_kind` (`ipfs`, `bzzr0`, `bzzr1` ou `null`), `hash` (haché en hexadécimal ou `null`), `experimental` (booléen), `offset` et `length` (position et taille en octets du bloc dans le bytecode) et `raw` (contenu décodé du bloc, les chaînes d'octets en hexadécimal).
- **FR-SOR-43** : `dispatcher` DOIT être un objet décrivant l'analyse du dispatch (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 3), portant dans cet ordre les clés `selectors` (liste d'objets `selector`, `function`, `target`, `callvalue_hoisted`), `fallback` (objet `function`, `target`, `kind` parmi `nomatch`, `short`, `empty` et `whole_code`, `present`, `default_revert`, `consistent`), `receive` (objet `function`, `target`, `kind`, ou `null`), `callvalue_hoisted` (booléen), `regular` (booléen), `exits` (liste d'objets `kind`, `target`, `function`), `guard_reverts` (entier) et `duplicates` (liste d'objets `selector`, `target`, `ignored_target`). Un code sans dispatch de sélecteurs DOIT donner une liste `selectors` vide et une fonction de repli de genre `whole_code` à la position 0.
- **FR-SOR-44** : L'AST DOIT être l'objet vide `{}`, sans aucune clé, dans les deux cas prévus par [architecture.md](architecture.md) : bytecode vide (section 2) et échec de sérialisation (section 6).
- **FR-SOR-45** : Avec `--json`, la commande DOIT imprimer l'AST indenté de deux espaces, les caractères non ASCII étant échappés, suivi d'un saut de ligne.

## 4. Payload JSON combiné (`--combined-json`)

- **FR-SOR-46** : Avec `--combined-json`, la commande DOIT imprimer, pour chaque entrée, un unique objet JSON sur une seule ligne (sans indentation, séparateurs `, ` et `: `, caractères non ASCII et séquences de couleur échappés), suivi d'un unique saut de ligne.
- **FR-SOR-47** : L'objet combiné DOIT toujours contenir, dans cet ordre, les clés `text` (le pseudo-code, couleurs comprises) et `json` (l'AST, éventuellement `{}`).
- **FR-SOR-48** : Lorsque `--solidity` est également présent, l'objet combiné DOIT contenir en plus, dans cet ordre, `solidity` (le code généré), `solgen_confidence` (objet associant à l'identifiant de chaque fonction `high`, `medium`, `low` ou `none`), `solgen_warnings` (liste de chaînes) et `solgen_functions` (FR-SOR-49) ; lorsque `--verify` est aussi présent, il DOIT contenir ensuite `solgen_verification` (FR-SOR-50) ; lorsque `--validate-solidity` est aussi présent, il DOIT contenir en dernier `solgen_validation`, objet à trois clés `status`, `errors` et `warnings`.
- **FR-SOR-49** : `solgen_functions` DOIT être un objet associant à l'identifiant de chaque fonction du code généré (`0x` suivi du sélecteur, `_fallback` ou `_receive`) un objet portant les clés `name`, `signature`, `selector`, `kind`, `routed`, `payable`, `mutability`, `tier` (`idiomatic`, `partial` ou `exact`), `verdict` (`unverified` ou un verdict de FR-SOR-56), `passes`, `disabled_passes`, `flags`, `guards`, `calls`, `coverage`, `folded`, `abi`, `arith`, `loops`, `naming`, `modifiers` et `confidence`, auxquelles s'ajoutent `counterexample` lorsque la vérification a trouvé une différence et `reason` lorsque le vérificateur en a donné une ; la signification de ces champs est spécifiée dans [generation-solidity.md](generation-solidity.md), section 1.
- **FR-SOR-50** : `solgen_verification` DOIT être le rapport de vérification du code renvoyé (section 6), complété de la clé `search` qui décrit la boucle de vérification (voir [generation-solidity.md](generation-solidity.md), section 7) ; lorsqu'aucun rapport n'a pu être établi, il DOIT valoir l'objet `{"passed": false, "levels": {}, "summary": {}, "functions": {}, "warnings": [...]}`, la liste reprenant les avertissements du générateur qui commencent par `verification`.
- **FR-SOR-51** : Le payload combiné DOIT constituer le contrat d'intégration générique du système pour tout programme appelant qui souhaite obtenir texte, AST et reconstruction Solidity en une seule exécution et les lire par une unique analyse JSON de la sortie standard.

## 5. Sortie Solidity (`--solidity`)

- **FR-SOR-52** : Avec `--solidity` sans `--combined-json`, la commande DOIT imprimer sur la sortie standard le code source tel que produit par le générateur (voir [generation-solidity.md](generation-solidity.md)), qui se termine déjà par un saut de ligne, suivi d'un saut de ligne supplémentaire.
- **FR-SOR-53** : Avec `--verify` en plus, la commande DOIT écrire ensuite sur la sortie d'erreur, et jamais sur la sortie standard, le résumé de la vérification : une première ligne `# verification: L0=<statut>  L1=<statut>  L2=<statut>  L3=<statut>  L4=<statut>`, puis une ligne `#   <ligne>` pour chacune des autres lignes de synthèse que l'en-tête du code reprend (`verdicts: …`, `tiers: …`, `loop: …` et, selon le cas, les lignes `L0:`, `L2:`, `backed off:`, `L4:` et de budget), une ligne `#   time: <secondes> s` (une décimale), et enfin une ligne `#   <avertissement>` pour chaque avertissement du générateur qui commence par `verification` ; lorsqu'aucun rapport n'a pu être établi, la première ligne DOIT être `# verification: unavailable`.
- **FR-SOR-54** : Avec `--validate-solidity` en plus, la commande DOIT écrire sur la sortie d'erreur, et jamais sur la sortie standard, après le résumé de vérification éventuel, la ligne `# solc validation: <statut>`, puis, lorsque le code n'est accepté que par le pipeline IR du compilateur, la ligne `#   compiles with --via-ir --optimize only: the default pipeline of solc reports 'Stack too deep'`, puis une ligne `#   <erreur>` par erreur de compilation ; les avertissements du compilateur ne sont pas imprimés.

## 6. Rapport de vérification

Le rapport compare un code Solidity au bytecode runtime d'origine (voir [architecture.md](architecture.md), sections 2 et 8) ; la commande l'expose sous la clé `solgen_verification` du payload combiné (FR-SOR-50).

- **FR-SOR-55** : Le rapport DOIT être un objet portant dans cet ordre les clés `passed` (booléen), `levels`, `summary` (nombre de fonctions par verdict, verdicts absents omis), `functions`, `sequences`, `original` (`size` et `metadata` du bytecode d'origine), `candidate` (contrat, compilateur et réglages du code compilé), `backend` (`bulk`, `confirm` et liste `available` des machines EVM disponibles), `warnings` et `elapsed` (secondes) ; `levels` DOIT associer à chacun des niveaux `L0` (compilation), `L1` (même interface externe : sélecteurs, mutabilité, événements, erreurs), `L2` (même disposition du stockage), `L3` (équivalence observée par exécution différentielle) et `L4` (bytecode identique aux métadonnées et immuables près) un objet portant au moins `status` (`pass`, `fail`, `inconclusive`, `skipped` ou `error`) et `reason`, un niveau non demandé étant `skipped` avec la raison `not requested`. `passed` DOIT être vrai lorsque tous les niveaux qui ont été exécutés ont réussi et qu'au moins un a réussi, `L4` n'étant pas pris en compte dans le rapport produit par la génération.
- **FR-SOR-56** : `functions` DOIT associer à chaque fonction, identifiée par `0x` suivi de son sélecteur, `fallback` ou `receive`, un objet portant les clés `key`, `signature`, `origin`, `abi` (`MATCH`, `MISSING`, `EXTRA`, `ROUTED` ou `null`), `verdict`, `reason`, `calls`, `original_success`, `divergences`, `sequence_divergences`, `env_divergences`, `gas_divergences`, `kinds`, `coverage`, `payable`, `checked_bytes`, `counterexample`, `elapsed` et `selector` ; le verdict DOIT être l'un de `EQUIVALENT` (aucune différence sur des appels dont certains ont été acceptés par l'original), `EQUIVALENT_REVERTS_ONLY` (aucune différence, mais l'original a rejeté tous les appels), `DIVERGENT` (au moins une différence), `MISSING` (sélecteur de l'original absent du code comparé), `EXTRA` (sélecteur inconnu de l'original), `ROUTED` (fonction servie par la fonction de repli du code comparé et non exécutée), `INCONCLUSIVE` (différence que l'environnement peut expliquer, FR-SOR-57) ou `SKIPPED` (comportement non vérifié).
- **FR-SOR-57** : Une fonction dont les seules différences tiennent à l'environnement d'exécution DOIT recevoir le verdict `INCONCLUSIVE` avec une raison commençant par `env:` ; en particulier, lorsque l'original épuise le gas d'un bloc entier là où le code comparé termine, et qu'aucune autre différence n'est observée, la raison DOIT commencer par `env: gas:` et le contre-exemple DOIT être conservé ; une telle différence NE DOIT PAS mettre fin à la recherche : les appels suivants sont essayés, et toute autre différence observée donne `DIVERGENT` ; un code comparé qui épuise le gas là où l'original termine reste `DIVERGENT`. Le niveau `L3` DOIT être `fail` lorsqu'au moins une fonction diverge sans explication par l'environnement, et `inconclusive` lorsque les seules différences sont de ce type ou que le budget de temps a manqué pour certaines fonctions.
- **FR-SOR-58** : Le contre-exemple d'une fonction DOIT être un objet portant `kinds` (natures des différences), `label` (`per_call`, `sequence` ou `dirty_storage`), `backend`, `call` (`sender`, `via`, `value`, `calldata`, `mutation`, `reentry`), `prestate` (`storage`, `balances`, `mocks`, `block`, `stub_code_at_hardcoded_addresses`), `original` et `candidate` (pour chaque côté : `success`, `error`, `output`, `logs`, `storage_changes` et, le cas échéant, `calls`, `created` et `contract`), et `sequence` lorsque la différence n'apparaît qu'après une suite d'appels ; les données binaires y sont écrites en hexadécimal tronqué à 1 024 octets, et les listes bornées.

## 7. Autres productions

Le désassemblage n'est exposé que par l'interface Python ([architecture.md](architecture.md), section 8), au format de [pipeline-decompilation.md](pipeline-decompilation.md), section 2.

- **FR-SOR-59** : La journalisation de la commande DOIT suivre le format `<AAAA-MM-JJ HH:MM:SS,mmm> <hôte> <composant>[<processus>] <NIVEAU> <message>` sur la sortie d'erreur, au niveau choisi par l'option `-v`.
- **FR-SOR-60** : Au niveau INFO, une décompilation DOIT journaliser au minimum `Running light execution to find functions.`, puis pour chaque fonction `Decompiling <nom>...`, ` -> Interpreting EVM on function...` et ` -> Cleaning up AST, identifying loops...`, puis `Functions decompilation finished, now doing post-processing.`, précédés en mode adresse de `Fetching code for <adresse>...`, ainsi que les messages de progression de [pipeline-decompilation.md](pipeline-decompilation.md) (sections 4 et 8) et, lors de sa première construction, ceux de la base de signatures (`Building the signature database <chemin> (once)...` puis `signature database <chemin> built in <durée>s`, voir [resolution-signatures.md](resolution-signatures.md), section 3).
- **FR-SOR-61** : Les avertissements de dépassement de budget ([pipeline-decompilation.md](pipeline-decompilation.md), sections 4 et 8), d'arrêt de la simplification à sa limite de temps (`simplification stopped at its time limit (<n> s): the trace is exact but not fully simplified`, puis, pour la fonction concernée, `<nom>: simplification stopped at its time limit (PANORAMIX_WHILES_TIMEOUT, PANORAMIX_FUNCTION_TIMEOUT): the code is exact but not fully simplified`), d'exclusion d'emplacements de stockage ([reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 4.4) et d'indisponibilité de la base de signatures ([resolution-signatures.md](resolution-signatures.md), section 3) DOIVENT être journalisés au niveau WARNING ; l'échec d'une fonction DOIT être journalisé au niveau ERROR par le message `Problem with <nom>` accompagné de la trace de l'exception.
- **FR-SOR-62** : Une entrée de la commande qui n'est pas une chaîne hexadécimale DOIT produire sur la sortie d'erreur la seule ligne `scobelix: error: invalid bytecode: <raison>`, sans trace d'exception, la raison nommant le premier caractère non hexadécimal et sa position (`not hexadecimal: 'z' at position 0`) ou le nombre impair de chiffres (`odd number of hex digits (3): the last byte is incomplete`) ; le code de sortie est spécifié dans [architecture.md](architecture.md), section 7.
- **FR-SOR-63** : Le fichier de profil `scobelix.prof` ([architecture.md](architecture.md), section 7) DOIT être au format de statistiques du profileur standard de Python, exploitable par les outils standards d'analyse de profil.

Les effets sur le système de fichiers (base de signatures, compilateurs téléchargés, fichier de profil, répertoire temporaire de validation) sont spécifiés dans [integration.md](integration.md), section 3.

---

Navigation : [architecture.md](architecture.md) · [pipeline-decompilation.md](pipeline-decompilation.md) · [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) · [resolution-signatures.md](resolution-signatures.md) · [generation-solidity.md](generation-solidity.md) · [integration.md](integration.md) · [README.md](../README.md)
