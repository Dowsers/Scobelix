# Spécification de paramétrage des bases de signatures de Scobelix

Ce document énonce, sous forme d'exigences numérotées (préfixe `FR-PARAM`), le **format** que doivent respecter les données de signatures, externes au code, pour être exploitables par le système : le fichier de signatures locales, le fichier de signatures organisées, le dump de signatures compressé, les fichiers ABI acceptés en entrée par l'outil de régénération, et le fichier de base de signatures que désigne la variable `SCOBELIX_SIGDB`.

Ce document décrit un format, pas des données : les entrées réelles (1 534 891 lignes dans le dump, 1 004 entrées dans le fichier de signatures organisées et 557 entrées dans le fichier de signatures locales à ce jour, chiffres vivants) ne sont pas reproduites ici ; elles sont livrées avec le paquet et peuvent être régénérées ou remplacées. Le comportement de **construction** de la base de signatures, de **résolution** et de **régénération** qui exploite ces données est décrit dans [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) ; l'emplacement de ces fichiers et du cache dans l'environnement d'exécution est décrit dans [integration.md](../specification-fonctionnelle/integration.md), section 3. Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-PARAM-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

Quatre sources de signatures alimentent la base de signatures du système. Trois sont des fichiers de données livrés avec le paquet, régénérables ou remplaçables : le fichier de signatures locales (section 2), le fichier de signatures organisées (section 3) et le dump compressé (section 4). La quatrième est une table interne qui fait partie du système lui-même (section 7). Chaque entrée est vérifiée et rangée lors de la construction de la base, qui a lieu automatiquement dès que l'une de ces sources change (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), sections 2 et 3).

- **FR-PARAM-01** : Un sélecteur de fonction ou d'erreur DOIT désigner les 4 premiers octets du haché keccak-256 de la signature canonique (FR-PARAM-02), et le topic0 d'un événement l'intégralité de ce haché (32 octets). Une clé de fichier de données DOIT être un entier hexadécimal d'au plus 4 octets, préfixe `0x` facultatif et casse indifférente ; la forme `0x` suivie d'exactement 8 chiffres hexadécimaux minuscules, écrite par l'outil de régénération, est la forme recommandée.
- **FR-PARAM-02** : La signature canonique DOIT s'écrire `nom(t1,t2,…)`, sans espaces ni noms de paramètres, le nom étant un identifiant (lettre, `_` ou `$`, puis lettres, chiffres, `_` ou `$`) et chaque type étant écrit sous sa forme canonique. Les types acceptés sont les suivants, chacun pouvant être suivi d'un nombre quelconque de suffixes de tableau `[]` ou `[<k>]` ; un alias est remplacé par sa forme canonique avant le calcul du haché :

  | Famille | Types acceptés | Alias |
  |---|---|---|
  | Entiers | `uint<M>` et `int<M>` pour M multiple de 8 de 8 à 256 | `uint` = `uint256`, `int` = `int256` |
  | Scalaires | `address`, `bool`, `string`, `bytes`, `function` | — |
  | Octets fixes | `bytes1` à `bytes32` | `byte` = `bytes1` |
  | Virgule fixe | `fixed<M>x<N>` et `ufixed<M>x<N>` pour M multiple de 8 de 8 à 256 et N de 0 à 80 | `fixed` = `fixed128x18`, `ufixed` = `ufixed128x18` |
  | Tuples | type `tuple` accompagné de la liste `components` de ses composants, ou tuple écrit développé `(<t1>,<t2>,…)` ; forme canonique développée | — |

- **FR-PARAM-03** : Une entrée de signature DOIT être un objet portant un nom (`name`, identifiant) et, facultativement, la liste `inputs` de ses paramètres (absente : aucun paramètre) ; chaque paramètre DOIT être un objet portant un type textuel (`type`) et PEUT porter un nom (`name`, chaîne éventuellement vide), la liste `components` d'un type tuple et, pour un événement, le drapeau `indexed`. Une entrée malformée, une entrée dont la signature canonique n'a pas pour haché sa clé et un substitut (nom `unknown` suivi des 8 chiffres hexadécimaux de sa propre clé) sont ignorés et comptés (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 2).

## 2. Fichier de signatures locales

- **FR-PARAM-04** : Le fichier de signatures locales (`local_sigs.json`) DOIT contenir un unique objet JSON dont chaque clé est un sélecteur de fonction (FR-PARAM-01) et chaque valeur une entrée `{"name": <chaîne>, "inputs": [ {"type": <chaîne>, "name": <chaîne>}, … ]}` (FR-PARAM-03) ; toutes ses entrées sont des fonctions. Une entrée PEUT porter en outre `outputs` et `stateMutability`, exploités comme ceux du fichier de signatures organisées (FR-PARAM-11).
- **FR-PARAM-05** : Les noms de paramètres PEUVENT être vides. Un nom vide ou synthétique (`param<k>`, écrit par l'outil de régénération) ne l'emporte jamais sur le nom fourni par une autre source pour la même signature, et un nom vide est remplacé à l'affichage d'un point d'entrée (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), sections 2 et 4).
- **FR-PARAM-06** : Le fichier produit par l'outil de régénération DOIT être trié par clé à tous les niveaux, indenté de deux espaces, encodé en UTF-8 avec les caractères non ASCII échappés, et sans saut de ligne final ; à la lecture, tout document JSON valide encodé en UTF-8 et respectant le schéma de FR-PARAM-04 DOIT être accepté, quelle que soit sa mise en forme.
- **FR-PARAM-07** : Le fichier DOIT être un document JSON valide dans son ensemble : une erreur de syntaxe fait échouer la construction de la base, qui devient indisponible pour toutes les sources et non pour ce seul fichier (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3). Le fichier PEUT être absent : la base est alors construite sans lui, avec un avertissement.
- **FR-PARAM-08** : Chaque clé DOIT être le sélecteur de la signature canonique de son entrée : une clé calculée sur une écriture non canonique des types (`f(uint)` au lieu de `f(uint256)`) ne correspond pas au haché de la signature canonique, et l'entrée est rejetée à la construction de la base.

## 3. Fichier de signatures organisées

- **FR-PARAM-09** : Le fichier de signatures organisées (`extra_sigs.json`) DOIT contenir un unique objet JSON dont la clé `abi` est une liste d'entrées d'ABI ; les autres clés (`format`, `description`) sont libres et ne sont pas exploitées. Un fichier qui n'est pas un JSON valide ou qui n'a pas de clé `abi` fait échouer la construction de la base, qui devient indisponible (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3).
- **FR-PARAM-10** : Chaque entrée DOIT porter une nature (`type`) : `function`, `event` ou `error` ; une entrée d'une autre nature (`constructor`, `fallback`, `receive`) est ignorée sans être comptée, et une entrée sans nature est rejetée comme malformée. Les entrées ne portent pas de clé : chacune est rangée sous le haché de sa propre signature.
- **FR-PARAM-11** : Une fonction DEVRAIT porter ses types de retour (`outputs`, liste de paramètres) et sa mutabilité (`stateMutability` : `pure`, `view`, `nonpayable` ou `payable`, ou à défaut les anciens drapeaux `constant` et `payable`) : sans liste `outputs`, types de retour et mutabilité sont tenus pour inconnus, et une valeur `outputs` qui n'est pas une liste fait rejeter l'entrée. Un événement DEVRAIT porter le drapeau `indexed` de chacun de ses paramètres (absent : non indexé) et PEUT porter `anonymous`. Les autres champs (`internalType`, `gas`, …) sont ignorés.
- **FR-PARAM-12** : Les types des paramètres d'un événement ou d'une erreur DOIVENT être des types acceptés (FR-PARAM-02), faute de quoi l'entrée est rejetée ; une fonction dont un type n'est pas accepté (fonction de bibliothèque, par exemple `Lib.Data storage`) est conservée avec ses types tels qu'écrits et marquée comme telle.

## 4. Dump de signatures compressé

- **FR-PARAM-13** : Le dump (`abi_dump.xz`) DOIT être un fichier compressé au format xz contenant du JSON Lines encodé en UTF-8 : une ligne par entrée, chaque ligne étant un objet JSON complet.
- **FR-PARAM-14** : Chaque ligne DOIT porter une clé `selector` (clé de 4 octets, FR-PARAM-01) et une clé `abi` (entrée, FR-PARAM-03). Pour une signature typée, `abi.type` DOIT valoir `function`, `event` ou `error` ; absente ou d'une autre valeur, l'entrée est une signature non typée, rangée parmi les fonctions. Un événement DOIT être rangé sous les 4 premiers octets de son topic0.
- **FR-PARAM-15** : Le champ `inputs` PEUT être absent (aucun paramètre) ; une signature non typée sans paramètre PEUT être écrite avec un unique paramètre de type vide, lu comme une liste vide. Sont exploités en outre `outputs`, `stateMutability`, `constant` et `payable` pour une fonction typée (FR-PARAM-11), `indexed` et `anonymous` pour un événement ; les autres champs sont ignorés.
- **FR-PARAM-16** : Une ligne qui n'est pas un JSON valide, ou qui ne porte pas les clés attendues sous la forme attendue, DOIT être ignorée et comptée comme malformée, sans interrompre la construction de la base.
- **FR-PARAM-17** : Une entrée substitut (nom `unknown` suivi des 8 chiffres hexadécimaux de sa propre clé), une entrée dont le nom n'est pas un identifiant et une entrée dont la signature canonique n'a pas pour haché sa clé DOIVENT être ignorées et comptées ; un objet `abi` vide est ainsi une entrée sans nom, ignorée.
- **FR-PARAM-18** : Le dump NE DOIT PAS contenir deux entrées valides de même clé dans un même espace de noms (même sélecteur pour les fonctions et les signatures non typées, qui partagent un espace, ou pour les erreurs ; même topic0 pour les événements), sauf si la table interne, le fichier de signatures organisées ou le fichier de signatures locales porte aussi cette clé dans cet espace : la construction échoue sinon sur une violation d'unicité, et la base est indisponible (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3).
- **FR-PARAM-19** : L'archive DOIT être complète et lisible : une archive tronquée ou endommagée fait échouer la construction de la base, qui devient indisponible.

*Note contextuelle : le dump livré ne contient aucune clé répétée, ce que confirme la réussite de sa construction ; la violation de FR-PARAM-18 a été reproduite en bac à sable avec un dump simulé contenant deux fois la même ligne. Une modification du dump, comme de toute autre source, est prise en compte sans intervention : elle change le nom du fichier de base attendu, qui est construit à la première recherche suivante, la construction remplaçant la base de manière atomique (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3).*

## 5. Fichiers ABI d'entrée de l'outil de régénération

- **FR-PARAM-20** : Un fichier ABI d'entrée DOIT avoir un nom qui commence par `abi` et se termine par `.json`, et PEUT se trouver à toute profondeur sous l'un des répertoires désignés par `SCOBELIX_ABI_ROOTS`.
- **FR-PARAM-21** : Le contenu DOIT être du JSON, lu en UTF-8, les octets non décodables étant ignorés ; un contenu qui n'est pas un JSON valide fait ignorer le fichier.
- **FR-PARAM-22** : Le contenu DOIT prendre l'une des formes suivantes : (a) une liste d'entrées ABI ; (b) un objet dont la clé `abi` est une liste d'entrées ABI ; (c) un objet dont la clé `result` est un objet dont la clé `abi` est une liste d'entrées ABI ; (d) tout autre objet JSON, dont les chaînes de caractères, à toute profondeur, sont analysées comme du texte (FR-PARAM-27). Un document JSON dont la racine n'est ni une liste ni un objet ne produit aucune signature.

*Note contextuelle : une réponse d'explorateur de blocs dont la clé `result` contient l'ABI sous forme de chaîne JSON (et non d'objet) relève de la forme (d) : cette chaîne est alors analysée comme du texte ; une ABI sérialisée en JSON ne contenant aucune signature écrite sous la forme `nom(types)`, elle ne produit en pratique aucune signature. Une telle réponse doit être convertie dans l'une des formes (a) à (c) avant régénération.*

- **FR-PARAM-23** : Dans les formes (a) à (c), seules les entrées de type `function` pourvues d'un nom non vide DOIVENT être retenues ; leur liste `inputs` PEUT être absente (fonction sans paramètre), et chaque paramètre DOIT porter un `type`, ainsi que, pour un type tuple, la liste `components` de ses composants.
- **FR-PARAM-24** : Les types de paramètres acceptés par l'outil DOIVENT être les suivants, chacun pouvant être suivi d'un nombre quelconque de suffixes de tableau `[]` ou `[<k>]` :

  | Famille | Types acceptés |
  |---|---|
  | Entiers | `uint`, `int`, `uint<M>` et `int<M>` pour M multiple de 8 de 8 à 256 |
  | Scalaires | `address`, `bool`, `string`, `bytes`, `function` |
  | Octets fixes | `bytes1` à `bytes32` |
  | Virgule fixe | `fixed<M>x<N>` et `ufixed<M>x<N>` pour M multiple de 8 de 8 à 256 et N de 1 à 32 |
  | Tuples | tout type commençant par `tuple`, aplati en `(<t1>,<t2>,…)` suivi de son suffixe de tableau, à partir de ses composants |

- **FR-PARAM-25** : Une fonction dont l'un des paramètres a un type non accepté DOIT être ignorée entièrement.
- **FR-PARAM-26** : Les types DEVRAIENT être écrits sous leur forme canonique (`uint256` plutôt que `uint`, par exemple) : l'outil ne canonicalise pas les types et calcule le sélecteur sur la signature telle qu'écrite ; une fonction écrite avec un type abrégé est donc rangée sous une clé qui n'est pas le sélecteur de sa signature canonique, et son entrée est rejetée à la construction de la base (FR-PARAM-08).

*Note contextuelle : pour un tuple, un composant de type non accepté est retiré silencieusement de la signature aplatie tant qu'il reste au moins un composant accepté ; la signature, et donc le sélecteur, obtenus sont alors inexacts, et l'entrée, cohérente avec la clé ainsi calculée, est acceptée par la base sans pouvoir nommer la fonction réelle.*

- **FR-PARAM-27** : Dans la forme (d), une chaîne DOIT être reconnue comme signature si elle contient `function <nom>(<paramètres>)` ou `<nom>(<paramètres>)`, où le nom est un identifiant (lettre ou `_`, puis lettres, chiffres ou `_`) autre que `function` et où chaque paramètre, séparé par une virgule, est réduit à son premier mot (le type) ; une chaîne sans parenthèse de la forme `<type>:<nom>`, où le type est accepté et le nom est un identifiant, DOIT être reconnue comme la signature sans paramètre `<nom>` suivie d'une liste vide. Les types tuples entre parenthèses ne sont pas reconnus sous cette forme : la signature qui en contient un est ignorée.

## 6. Fichier de base de signatures

- **FR-PARAM-28** : Un fichier désigné par `SCOBELIX_SIGDB` PEUT être fourni déjà construit ; il DOIT alors être une base produite par la construction du système, c'est-à-dire une base SQLite dont la table de métadonnées `meta` indique la version de schéma courante (`schema` vaut `2`) et une construction achevée (`complete` vaut `1`). Une base de signatures incomplète ou d'une autre version de schéma est reconstruite à sa place ; un fichier absent ou vide est construit.
- **FR-PARAM-29** : La variable NE DOIT PAS désigner un fichier d'une autre nature (fichier de données, base SQLite d'un autre programme, base illisible, répertoire) : un tel fichier n'est jamais remplacé ni modifié, aucun fichier n'est créé à côté de lui, et la base est indisponible pour le processus (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3).

## 7. Table interne (hors paramétrage)

- **FR-PARAM-30** : La table interne prioritaire DOIT respecter le schéma d'entrée du fichier de signatures locales (FR-PARAM-04), ses clés étant les sélecteurs de leurs signatures canoniques, mais elle fait partie du système et non de ses données : elle NE DOIT PAS être considérée comme un paramétrage, et toute évolution de son contenu constitue une évolution du système (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 2).

---

Pour le comportement de construction, de résolution et de régénération qui exploite ces données, voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) ; pour leur place dans l'environnement d'exécution, voir [integration.md](../specification-fonctionnelle/integration.md) ; pour la vue d'ensemble du système, voir [architecture.md](../specification-fonctionnelle/architecture.md). Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.
