# Spécification de paramétrage des bases de signatures de Scobelix

Ce document énonce, sous forme d'exigences numérotées (préfixe `FR-PARAM`), le **format** que doivent respecter les données de signatures de 4 octets, externes au code, pour être exploitables par le système : le fichier de signatures locales, le dump de signatures compressé, et les fichiers ABI acceptés en entrée par l'outil de régénération.

Ce document décrit un format, pas des données : les entrées réelles (1 534 891 lignes dans le dump et 557 entrées dans le fichier de signatures locales à ce jour, chiffres vivants) ne sont pas reproduites ici ; elles sont livrées avec le paquet et peuvent être régénérées ou remplacées. Le comportement de **résolution** (ordre des sources, cache disque, nommage) et de **régénération** qui exploite ces données est décrit dans [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) ; l'emplacement de ces fichiers et du cache dans l'environnement d'exécution est décrit dans [integration.md](../specification-fonctionnelle/integration.md), section 3. Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-PARAM-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

Trois sources de signatures sont consultées par le système. Deux sont des fichiers de données livrés avec le paquet, régénérables ou remplaçables : le dump compressé (section 3) et le fichier de signatures locales (section 2). La troisième est une table interne qui fait partie du système lui-même (section 5).

- **FR-PARAM-01** : Un sélecteur DOIT désigner les 4 premiers octets du haché keccak-256 de la signature canonique de la fonction, `nom(type1,type2,…)`, écrite sans espaces ni noms de paramètres, et être écrit dans les fichiers de données sous la forme `0x` suivie d'exactement 8 chiffres hexadécimaux minuscules.
- **FR-PARAM-02** : Une entrée de signature DOIT, dans toutes les sources, associer à un sélecteur un objet portant au minimum un nom de fonction (`name`, chaîne) et une liste de paramètres (`inputs`), chaque paramètre étant un objet portant un type (`type`, chaîne) et un nom (`name`, chaîne, éventuellement vide).

## 2. Fichier de signatures locales

- **FR-PARAM-03** : Le fichier de signatures locales (`local_sigs.json`) DOIT contenir un unique objet JSON dont chaque clé est un sélecteur au format de FR-PARAM-01 ; une clé qui n'est pas exactement sous ce format ne peut jamais être atteinte par la résolution, qui compare les sélecteurs normalisés à l'identique.
- **FR-PARAM-04** : Chaque valeur DOIT être un objet `{"name": <chaîne>, "inputs": [ {"type": <chaîne>, "name": <chaîne>}, … ]}` ; la liste `inputs` PEUT être vide pour une fonction sans paramètre, mais NE DOIT PAS être absente.
- **FR-PARAM-05** : Les noms de paramètres PEUVENT être vides ; les noms écrits par l'outil de régénération et le remplacement des noms vides à l'affichage sont spécifiés dans [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), sections 4 et 5.
- **FR-PARAM-06** : Le fichier produit par l'outil de régénération DOIT être trié par clé à tous les niveaux, indenté de deux espaces, encodé en UTF-8 avec les caractères non ASCII échappés, et sans saut de ligne final ; à la lecture, tout document JSON valide respectant le schéma de FR-PARAM-03 et FR-PARAM-04 DOIT être accepté, quelle que soit sa mise en forme.
- **FR-PARAM-07** : Le fichier DOIT être un document JSON valide dans son ensemble : une seule erreur de syntaxe rend inexploitable la totalité de ses entrées (comportement de repli dans [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 2).

## 3. Dump de signatures compressé

- **FR-PARAM-08** : Le dump (`abi_dump.xz`) DOIT être un fichier compressé au format xz contenant du JSON Lines : une ligne par entrée, chaque ligne étant un objet JSON complet.
- **FR-PARAM-09** : Chaque ligne DOIT porter une clé `selector`, chaîne au format de FR-PARAM-01 utilisée telle quelle comme clé de recherche sans normalisation, et une clé `abi`, objet d'entrée ABI.
- **FR-PARAM-10** : L'objet `abi` DOIT contenir au minimum `name` (chaîne) et `inputs` (liste d'objets `{name, type}`) ; les autres champs usuels d'une entrée ABI (`type`, `stateMutability`, `outputs`, `constant`, `payable`, `anonymous`, `gas`, et dans les paramètres `internalType`, `indexed`, `components`) sont tolérés et ignorés.
- **FR-PARAM-11** : Le champ `inputs` DOIT être présent dans chaque entrée : une entrée qui en est dépourvue fait échouer, par une assertion, la mise en forme de toute constante qui coïncide avec son sélecteur ; l'AST de la décompilation concernée est alors remplacé par `{}` et la décompilation entière échoue par une erreur propagée à l'appelant (comportement reproduit en simulant de telles entrées).
- **FR-PARAM-12** : Le système NE DOIT PAS exiger l'unicité des sélecteurs du dump, ni l'unicité ou le caractère significatif des noms, les données pouvant contenir des noms en collision ou synthétiques ; la règle appliquée à un sélecteur répété (la dernière ligne l'emporte) est spécifiée dans [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3.
- **FR-PARAM-13** : Chaque ligne DOIT être un JSON valide portant les clés `selector` et `abi` : une ligne invalide ou incomplète interrompt la construction du cache disque par une erreur, qui fait échouer la décompilation en cours.

Un objet `abi` vide équivaut à l'absence d'entrée pour le sélecteur concerné : ce comportement de résolution est spécifié dans [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 2.

Toute modification du dump n'est prise en compte qu'après suppression manuelle du cache disque construit à partir de lui (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3).

*Note contextuelle : le fichier de cache est créé dès le début de sa construction ; une construction interrompue (ligne invalide, arrêt du processus) laisse donc un cache partiel, limité aux lignes lues avant l'interruption, que les exécutions suivantes considèrent comme complet, jusqu'à sa suppression manuelle (comportement reproduit avec un cache temporaire et un dump simulé).*

## 4. Fichiers ABI d'entrée de l'outil de régénération

- **FR-PARAM-14** : Un fichier ABI d'entrée DOIT avoir un nom qui commence par `abi` et se termine par `.json`, et PEUT se trouver à toute profondeur sous l'un des répertoires désignés par `SCOBELIX_ABI_ROOTS`.
- **FR-PARAM-15** : Le contenu DOIT être du JSON, lu en UTF-8, les octets non décodables étant ignorés ; un contenu qui n'est pas un JSON valide fait ignorer le fichier.
- **FR-PARAM-16** : Le contenu DOIT prendre l'une des formes suivantes : (a) une liste d'entrées ABI ; (b) un objet dont la clé `abi` est une liste d'entrées ABI ; (c) un objet dont la clé `result` est un objet dont la clé `abi` est une liste d'entrées ABI ; (d) tout autre objet JSON, dont les chaînes de caractères, à toute profondeur, sont analysées comme du texte (FR-PARAM-21). Un document JSON dont la racine n'est ni une liste ni un objet ne produit aucune signature.

*Note contextuelle : une réponse d'explorateur de blocs dont la clé `result` contient l'ABI sous forme de chaîne JSON (et non d'objet) relève de la forme (d) : cette chaîne est alors analysée comme du texte ; une ABI sérialisée en JSON ne contenant aucune signature écrite sous la forme `nom(types)`, elle ne produit en pratique aucune signature. Une telle réponse doit être convertie dans l'une des formes (a) à (c) avant régénération.*

- **FR-PARAM-17** : Dans les formes (a) à (c), seules les entrées de type `function` pourvues d'un nom non vide DOIVENT être retenues ; leur liste `inputs` PEUT être absente (fonction sans paramètre), et chaque paramètre DOIT porter un `type`, ainsi que, pour un type tuple, la liste `components` de ses composants.
- **FR-PARAM-18** : Les types de paramètres acceptés DOIVENT être les suivants, chacun pouvant être suivi d'un nombre quelconque de suffixes de tableau `[]` ou `[<k>]` :

  | Famille | Types acceptés |
  |---|---|
  | Entiers | `uint`, `int`, `uint<M>` et `int<M>` pour M multiple de 8 de 8 à 256 |
  | Scalaires | `address`, `bool`, `string`, `bytes`, `function` |
  | Octets fixes | `bytes1` à `bytes32` |
  | Virgule fixe | `fixed<M>x<N>` et `ufixed<M>x<N>` pour M multiple de 8 de 8 à 256 et N de 1 à 32 |
  | Tuples | tout type commençant par `tuple`, aplati en `(<t1>,<t2>,…)` suivi de son suffixe de tableau, à partir de ses composants |

- **FR-PARAM-19** : Une fonction dont l'un des paramètres a un type non accepté DOIT être ignorée entièrement.
- **FR-PARAM-20** : Les types DEVRAIENT être écrits sous leur forme canonique (`uint256` plutôt que `uint`, par exemple) : l'outil ne canonicalise pas les types, et un type abrégé produit un sélecteur calculé sur une signature non canonique, qui ne correspond pas au sélecteur réel de la fonction.

*Note contextuelle : pour un tuple, un composant de type non accepté est retiré silencieusement de la signature aplatie tant qu'il reste au moins un composant accepté ; la signature, et donc le sélecteur, obtenus sont alors inexacts.*

- **FR-PARAM-21** : Dans la forme (d), une chaîne DOIT être reconnue comme signature si elle contient `function <nom>(<paramètres>)` ou `<nom>(<paramètres>)`, où le nom est un identifiant (lettre ou `_`, puis lettres, chiffres ou `_`) autre que `function` et où chaque paramètre, séparé par une virgule, est réduit à son premier mot (le type) ; une chaîne sans parenthèse de la forme `<type>:<nom>`, où le type est accepté et le nom est un identifiant, DOIT être reconnue comme la signature sans paramètre `<nom>` suivie d'une liste vide. Les types tuples entre parenthèses ne sont pas reconnus sous cette forme : la signature qui en contient un est ignorée.

## 5. Table interne (hors paramétrage)

- **FR-PARAM-22** : La table interne prioritaire DOIT respecter le même schéma d'entrée que les autres sources (FR-PARAM-02), mais elle fait partie du système et non de ses données : elle NE DOIT PAS être considérée comme un paramétrage, et toute évolution de son contenu constitue une évolution du système (voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 2).

---

Pour le comportement de résolution et de régénération qui exploite ces données, voir [resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) ; pour leur place dans l'environnement d'exécution, voir [integration.md](../specification-fonctionnelle/integration.md) ; pour la vue d'ensemble du système, voir [architecture.md](../specification-fonctionnelle/architecture.md). Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.
