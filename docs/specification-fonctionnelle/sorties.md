# Sorties produites par Scobelix

Ce document (préfixe `SOR`) spécifie le format exact de tout ce que le système produit : le pseudo-code texte (structure, blocs, syntaxe des lignes et des expressions, couleurs), l'AST JSON clé par clé, le payload JSON combiné, la sortie Solidity de la commande, ainsi que la journalisation, le fichier de profil et les autres effets observables. Il ne décrit pas comment ces contenus sont calculés.

Le contenu du code Solidity généré (en-tête, traduction, confiance) est spécifié dans [generation-solidity.md](generation-solidity.md), auquel les sections 4 et 5 renvoient ; le vocabulaire de la trace sérialisée dans l'AST est défini dans [pipeline-decompilation.md](pipeline-decompilation.md), section 11 ; la façon dont les options de la commande sélectionnent une sortie est dans [architecture.md](architecture.md), section 7 ; les effets sur le système de fichiers, vus comme échanges avec l'environnement, sont dans [integration.md](integration.md), section 3. Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-SOR-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

| Sortie | Obtenue par | Canal |
|---|---|---|
| Pseudo-code texte | commande sans drapeau de format ; champ `text` de l'interface Python | sortie standard |
| AST JSON indenté | `--json` ; champ `json` | sortie standard |
| Payload JSON combiné | `--combined-json` | sortie standard |
| Code Solidity | `--solidity` ; génération par l'interface Python | sortie standard |
| Statut de validation | `--solidity --validate-solidity` ; validation par l'interface Python | sortie d'erreur |
| Désassemblage | champ `asm` de l'interface Python uniquement | — |
| Journalisation | toute exécution | sortie d'erreur |
| Profil d'exécution | `--profile` | fichier `scobelix.prof` |

- **FR-SOR-01** : La commande DOIT écrire exactement une sortie principale par entrée traitée sur la sortie standard, et réserver la sortie d'erreur à la journalisation et au statut de validation, sous la seule réserve du mode `--explain` (voir [architecture.md](architecture.md), section 7).
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

- **FR-SOR-06** : Le texte DOIT comporter ensuite une ligne vide, puis, dans cet ordre : les constantes, une ligne par constante `const <nom> = <valeur>` (le nom étant celui de la fonction privé d'une liste de paramètres vide « () » éventuelle, soit par exemple `const _fallback(?) = 42`), suivies d'une ligne vide s'il y en a ; le bloc de stockage (FR-SOR-07) s'il existe au moins une définition ; les getters ; les fonctions régulières, dans l'ordre de [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 2 ; chaque getter et chaque fonction régulière étant suivi d'une ligne vide.
- **FR-SOR-07** : Le bloc de stockage DOIT commencer par la ligne `def storage:` et comporter une ligne par définition, `  <nom> is <type> at storage <emplacement>`, le bloc étant suivi d'une ligne vide ; le type s'écrit `uint<N>`, `address` ou `bool` pour un champ simple, avec le suffixe ` offset <décalage>` lorsque le champ est décalé, `mapping of <type>`, `array of <type>`, `struct` ou `struct <N> bytes` ; l'emplacement s'écrit en hexadécimal lorsqu'il est strictement supérieur à 1 000 et en décimal sinon.
- **FR-SOR-08** : Lorsque des constantes ou des getters ont été affichés et qu'il reste au moins une fonction régulière à afficher, le texte DOIT insérer avant les fonctions régulières le séparateur suivant, suivi d'une ligne vide :

```
#
#  Regular functions
#
```

*Note contextuelle : le contrat étant reconstruit comme une seule fonction de repli, qui est soit une constante, soit un getter, soit une fonction régulière, ce séparateur n'apparaît pas en pratique.*

- **FR-SOR-09** : Pour un bytecode vide, le texte DOIT se réduire à la seule ligne `# No code found for this contract.`, sans en-tête.

### 2.2 En-tête et corps d'une fonction

- **FR-SOR-10** : L'en-tête d'une fonction non constante DOIT avoir la forme `def <nom>[ payable]: <commentaire>`, où le nom est `nom(type nom, …)` ou `_fallback(?)`, où ` payable` est présent si la fonction est payable, et où le commentaire vaut `# not payable` pour une fonction non payable, `# default function` pour la fonction de repli payable, `# not payable, default function` pour la fonction de repli non payable, et est vide sinon.
- **FR-SOR-11** : Le corps DOIT être indenté de deux espaces au premier niveau, puis de quatre espaces supplémentaires par niveau d'imbrication ; un corps vide DOIT être affiché `  stop`, et une instruction `stop` finale au premier niveau NE DOIT PAS être affichée.
- **FR-SOR-12** : Le corps DOIT être rendu à partir de la vue pliée de la fonction (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 10), sans modifier la trace portée par l'AST.

### 2.3 Syntaxe des instructions

- **FR-SOR-13** : Un test dont une branche se réduit à un rejet sans données ou à `invalid` DOIT être affiché `require <condition qui évite le rejet>` suivi des instructions de l'autre branche au même niveau ; un nœud `require` DOIT être affiché `require <condition>`.
- **FR-SOR-14** : Les autres tests DOIVENT être affichés `if <condition>:` suivi de la branche vraie indentée et, le cas échéant, de `else:` suivi de la branche fausse indentée ; une boucle DOIT être affichée par les affectations initiales de ses variables (`<variable> = <valeur>`), puis `while <condition>:` suivi du corps indenté ; un retour en tête de boucle DOIT être affiché par ses réaffectations puis `continue `.
- **FR-SOR-15** : Une affectation de variable DOIT être affichée `<variable> = <valeur>`, une écriture mémoire `mem[<adresse>] = <valeur>` (ou `mem[<adresse> len <longueur>] = <valeur>` pour une longueur autre que 32 octets), une écriture de stockage transitoire `tstorage[<emplacement>] = <valeur>`.
- **FR-SOR-16** : Une écriture de stockage DOIT être affichée `<variable> = <valeur>`, ou sous la forme abrégée `<variable>++`, `<variable>--`, `<variable> += <v>` ou `<variable> -= <v>` lorsque la valeur est la variable elle-même augmentée ou diminuée d'une quantité.
- **FR-SOR-17** : Un retour ou un rejet DOIT être affiché `return <valeurs>` ou `revert with <valeurs>` (valeurs séparées par des virgules, suites de mots reconnues comme chaînes affichées entre apostrophes), `revert` seul pour un rejet sans données ou une instruction `invalid`, et, lorsque les données sont une zone mémoire non résolue, `return memory` ou `revert with memory` suivi de deux lignes donnant le début et la longueur (ou la fin) de la zone.
- **FR-SOR-18** : Un rejet dont les données sont le sélecteur d'erreur `Panic(uint256)` suivi d'un code entier DOIT être affiché `revert with Panic(<code en décimal>)`, suivi, pour les codes connus, d'un commentaire `# <libellé>` tiré de la table suivante :

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

*Note contextuelle : cette présentation n'est obtenue que lorsque le sélecteur de `Panic` apparaît dans la trace sous sa forme littérale imprimable ; dans les bytecodes de référence compilés avec optimisation, il apparaît souvent réduit et le rejet est alors affiché `revert with 0, 17`.*

- **FR-SOR-19** : Un retour ou un rejet d'une suite de données dont la représentation atteint 120 caractères visibles DOIT être découpé sur plusieurs lignes, une valeur par ligne alignée sous la première, une valeur initiale `32` étant regroupée avec la suivante.
- **FR-SOR-20** : Une décompilation interrompue ou un saut non résolu DOIT être affiché `...  # Decompilation aborted, sorry: <paramètres>`.
- **FR-SOR-21** : Un journal d'événement DOIT être affiché `log <événement>(<type> <nom>=<valeur>)` pour un paramètre unique, sur plusieurs lignes (une par paramètre) lorsqu'il y en a plusieurs, `log <événement>` lorsqu'il n'a pas de données, et `log <événement>: <valeurs>` lorsque l'événement n'est pas résolu (voir [resolution-signatures.md](resolution-signatures.md), section 4).
- **FR-SOR-22** : Un appel externe DOIT être affiché sur plusieurs lignes : `call <adresse>.<fonction> with:` (ou `call <adresse> with:` suivi de `   funct <sélecteur>`), puis `   value <valeur> wei` si une valeur est transférée, `     gas <gas> wei`, et `    args <arguments>` s'il y en a ; un appel en lecture seule suit le même schéma avec `static call`, un appel délégué avec `delegate` et un appel `callcode` avec `codecall`.
- **FR-SOR-23** : `selfdestruct(<bénéficiaire>)`, `<variable> = <précompilé>(<arguments>) # precompiled`, `create contract with <valeur> wei` suivi de `                code: <code>`, et `create2 contract with <valeur> wei` suivi des lignes `salt:` et `code:` DOIVENT être les formes d'affichage respectives de l'autodestruction, d'un appel de précompilé et des créations de contrat.
- **FR-SOR-24** : Les lignes de commentaire insérées par le mode `--verbose` DOIVENT être affichées précédées de `# `, et un label résiduel sous la forme `label Node(…) setvars: …` (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 7).

### 2.4 Syntaxe des expressions

- **FR-SOR-25** : Les valeurs d'environnement DOIVENT être affichées ainsi :

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

- **FR-SOR-26** : Les opérateurs DOIVENT être affichés en notation infixe (`+`, `-`, `*`, `/`, `%`, `^` pour la puissance, `<<`, `>>`, `<`, `>`, `<=`, `>=`, `==`, `!=`, `and`, `or`, `xor`), les comparaisons et opérations signées étant marquées d'un prime (`<′`, `>′`, `<=′`, `>=′`, `/′` …), la négation bit à bit sous la forme `!(<valeur>)` et un test de nullité qui n'est pas une comparaison sous la forme `(<valeur> == 0)`.
- **FR-SOR-27** : Les masques DOIVENT être affichés comme des conversions de type lorsque leur taille correspond à un type (`uint8(…)`, `uint32(…)`, `address(…)`, `bool(…)`…), sous la forme d'un modulo par une puissance de deux pour une taille inférieure à 64 bits sans type correspondant, sous la forme `Mask(<taille>, <décalage>, <valeur>)` sinon, les décalages de moins de 8 bits étant rendus par une multiplication ou une division par une puissance de deux et les autres par `<<` ou `>>` ; les arrondis à 32 octets sont affichés `ceil32(…)` et `floor32(…)`.
- **FR-SOR-28** : Les accès aux données DOIVENT être affichés `mem[<adresse>]` (ou `mem[<adresse> len <longueur>]`), `call.data[<début> len <longueur>]` (ou `call.data[<début>]` pour 32 octets), `ext_call.return_data[…]`, `code.data[<début> len <longueur>]`, un tableau dynamique `Array(len=<longueur>, data=<données>)`, un paramètre par son nom, la longueur ou l'élément d'un paramètre tableau `<nom>.length` et `<nom>[<k>]`, et les autres lectures de données d'appel `cd[<décalage>]`.
- **FR-SOR-29** : Les accès au stockage DOIVENT être affichés par le nom de la variable d'état, suivi de `[<clé>]` pour un mapping ou un tableau (`[<clé1>][<clé2>]` pour un mapping imbriqué), de `.length` pour une longueur et de `.field_<décalage>` pour un champ de structure ; une variable de 256 bits dont le type doit être rendu explicite est affichée `uint256(<variable>)`, et un emplacement non résolu `stor[<emplacement>]`.
- **FR-SOR-30** : Les variables DOIVENT être affichées par leur nom lisible (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 8), et les booléens littéraux qui subsistent dans la vue d'affichage par `True` et `False` ; la simplification ayant déjà ramené la plupart des booléens littéraux de la trace aux entiers 1 et 0 (même section), ceux-ci s'affichent comme des entiers.
- **FR-SOR-31** : Les entiers DOIVENT être affichés selon la première des règles suivantes qui s'applique : (1) un multiple de 86 400 strictement supérieur à 86 400 sous la forme `<n> * 24 * 3600` (voir la note ci-dessous) ; (2) un multiple de 3 600 strictement supérieur à 3 600 sous la forme `<n> * 3600` ; (3) un entier supérieur à 2^150 en hexadécimal ; (4) un multiple non nul de 10^k, pour la plus grande valeur de k prise de 18 à 9 puis 6, sous la forme `10^<k>` ou `<n> * 10^<k>` ; (5) un entier qui coïncide avec un sélecteur connu sous forme de signature (voir [resolution-signatures.md](resolution-signatures.md), section 4) ; (6) en décimal s'il est négatif ou inférieur à 2^90 ; (7) en hexadécimal sinon. Dans les règles (1) et (2), n est lui-même mis en forme selon ces règles et l'ensemble est placé entre parenthèses à l'intérieur d'une expression (par exemple 9 × 10^18 est affiché `25 * 10^14 * 3600`).

*Note contextuelle : une règle héritée destinée aux durées en jours affiche un multiple de 86 400 strictement supérieur à 86 400 sous la forme `<n> * 24 * 3600` où n est le nombre d'heures et non de jours ; par exemple 172 800 (deux jours) est affiché `(48 * 24 * 3600)`, expression qui vaut 24 fois la valeur réelle. L'AST JSON conserve la valeur exacte.*

### 2.5 Couleurs

- **FR-SOR-32** : Le texte DOIT contenir, qu'il soit destiné à un terminal ou non, des séquences d'échappement ANSI de sélection de couleur (`ESC[…m`) : gris pour l'en-tête, les commentaires et les indications de type, magenta pour les mots-clés `def` des fonctions et `const`, vert pour le mot-clé `def` du bloc de stockage, les noms de variables d'état et de paramètres et les mots-clés de boucle, bleu pour les variables locales, gras pour les opérateurs, rouge pour les fonctions en échec et les bénéficiaires d'autodestruction, jaune pour les appels délégués et les décompilations interrompues ; un appelant qui souhaite un texte brut DOIT retirer ces séquences.

## 3. AST JSON (`--json` et champ `json`)

- **FR-SOR-33** : L'AST DOIT être un objet à quatre clés, dans cet ordre : `problems`, `stor_defs`, `functions`, `proxy_hints`.
- **FR-SOR-34** : `problems` DOIT être un objet associant l'identifiant de chaque fonction en échec (`_fallback` ou un sélecteur) à son nom affiché ; il est vide en l'absence d'échec.
- **FR-SOR-35** : `stor_defs` DOIT être une liste de quadruplets `["def", <nom>, <emplacement>, <type>]`, où l'emplacement est un entier et le type l'une des formes `["mapping", T]`, `["array", T]` ou `["mask", <taille>, <décalage>]`, T étant une taille en bits, la chaîne `"struct"` ou `["struct", <N>]` ; elle est vide si aucun stockage n'est accédé, et vaut l'objet vide `{}` lorsque la reconstruction du stockage a échoué (voir [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 4).
- **FR-SOR-36** : `functions` DOIT être une liste d'objets, un par fonction décompilée avec succès, portant dans cet ordre les clés `hash` (identifiant), `name` (nom affiché), `color_name` (nom avec les noms de paramètres colorés), `abi_name` (`nom(type,type)` ou `_fallback(?)`), `length` (couple `[nombre de lignes, nombre de caractères]` du texte de la fonction, séquences de couleur comprises), `getter` (expression lue par le getter, ou `null`), `const` (instruction de retour de la constante, ou `null`), `payable` (booléen), `print` (texte de la fonction tel qu'affiché, avec couleurs), `trace` et `params`.
- **FR-SOR-37** : `trace` DOIT être la trace arborescente non pliée de la fonction (voir [pipeline-decompilation.md](pipeline-decompilation.md), section 10), exprimée dans le vocabulaire de la section 11 du même document, les n-uplets étant convertis en listes et tout objet non natif en sa représentation textuelle.
- **FR-SOR-38** : `params` DOIT être un objet associant à chaque décalage de paramètre, écrit en chaîne décimale (par exemple `"4"`, `"36"`), le couple `[<type>, <nom>]`.
- **FR-SOR-39** : `proxy_hints` DOIT être une liste d'objets à quatre clés : `line` (position de l'instruction, entier), `slot` (constante en hexadécimal minuscule préfixée `0x`), `name` et `description` (voir [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 5).
- **FR-SOR-40** : L'AST DOIT être l'objet vide `{}`, sans aucune clé, dans les deux cas prévus par [architecture.md](architecture.md) : bytecode vide (section 2) et échec de sérialisation (section 6).
- **FR-SOR-41** : Avec `--json`, la commande DOIT imprimer l'AST indenté de deux espaces, les caractères non ASCII étant échappés, suivi d'un saut de ligne.

## 4. Payload JSON combiné (`--combined-json`)

- **FR-SOR-42** : Avec `--combined-json`, la commande DOIT imprimer, pour chaque entrée, un unique objet JSON sur une seule ligne (sans indentation, séparateurs `, ` et `: `, caractères non ASCII et séquences de couleur échappés), suivi d'un unique saut de ligne.
- **FR-SOR-43** : L'objet combiné DOIT toujours contenir, dans cet ordre, les clés `text` (le pseudo-code, couleurs comprises) et `json` (l'AST, éventuellement `{}`).
- **FR-SOR-44** : Lorsque `--solidity` est également présent, l'objet combiné DOIT contenir en plus, dans cet ordre, `solidity` (le code généré), `solgen_confidence` (objet associant à l'identifiant de chaque fonction `high`, `medium` ou `low`) et `solgen_warnings` (liste de chaînes) ; lorsque `--validate-solidity` est aussi présent, il DOIT contenir en dernier `solgen_validation`, objet à trois clés `status`, `errors` et `warnings`.
- **FR-SOR-45** : Le payload combiné DOIT constituer le contrat d'intégration générique du système pour tout programme appelant qui souhaite obtenir texte, AST et reconstruction Solidity en une seule exécution et les lire par une unique analyse JSON de la sortie standard.

## 5. Sortie Solidity (`--solidity`)

- **FR-SOR-46** : Avec `--solidity` sans `--combined-json`, la commande DOIT imprimer sur la sortie standard le code source tel que produit par le générateur (voir [generation-solidity.md](generation-solidity.md)), qui se termine déjà par un saut de ligne, suivi d'un saut de ligne supplémentaire.
- **FR-SOR-47** : Avec `--validate-solidity` en plus, la commande DOIT écrire sur la sortie d'erreur, et jamais sur la sortie standard, la ligne `# solc validation: <statut>` puis une ligne `#   <erreur>` par erreur de compilation ; les avertissements du compilateur ne sont pas imprimés.

## 6. Autres productions

Le désassemblage n'est exposé que par l'interface Python ([architecture.md](architecture.md), section 8), au format de [pipeline-decompilation.md](pipeline-decompilation.md), section 2.

- **FR-SOR-48** : La journalisation de la commande DOIT suivre le format `<AAAA-MM-JJ HH:MM:SS,mmm> <hôte> <composant>[<processus>] <NIVEAU> <message>` sur la sortie d'erreur, au niveau choisi par l'option `-v`.
- **FR-SOR-49** : Au niveau INFO, une décompilation DOIT journaliser au minimum `Running light execution to find functions.`, puis pour chaque fonction `Decompiling <nom>...`, ` -> Interpreting EVM on function...` et ` -> Cleaning up AST, identifying loops...`, puis `Functions decompilation finished, now doing post-processing.`, précédés en mode adresse de `Fetching code for <adresse>...`, ainsi que les messages de progression de [pipeline-decompilation.md](pipeline-decompilation.md) (sections 4 et 8) et ceux de construction du cache de signatures ([resolution-signatures.md](resolution-signatures.md), section 3).
- **FR-SOR-50** : Les avertissements de dépassement de budget ([pipeline-decompilation.md](pipeline-decompilation.md), sections 4 et 8) et d'exclusion d'emplacements de stockage ([reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 4.4) DOIVENT être journalisés au niveau WARNING ; l'échec d'une fonction DOIT être journalisé au niveau ERROR par le message `Problem with <nom>` accompagné de la trace de l'exception.
- **FR-SOR-51** : Le fichier de profil `scobelix.prof` ([architecture.md](architecture.md), section 7) DOIT être au format de statistiques du profileur standard de Python, exploitable par les outils standards d'analyse de profil.

Les effets sur le système de fichiers (cache de signatures, fichier de profil, répertoire temporaire de validation) sont spécifiés dans [integration.md](integration.md), section 3.

---

Navigation : [architecture.md](architecture.md) · [pipeline-decompilation.md](pipeline-decompilation.md) · [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) · [resolution-signatures.md](resolution-signatures.md) · [generation-solidity.md](generation-solidity.md) · [integration.md](integration.md) · [README.md](../README.md)
