# Résolution des signatures 4 octets et régénération de la base locale

Ce document (préfixe `SIG`) spécifie comment le système nomme les fonctions et leurs paramètres à partir des sélecteurs de 4 octets : les trois sources consultées et leur ordre de précédence, la normalisation des sélecteurs, la construction et l'usage du cache disque, le nommage de repli, la résolution des sélecteurs rencontrés comme constantes dans le code, et le comportement de l'outil de régénération de la base locale.

Le **format** des fichiers de signatures (fichier de signatures locales, dump compressé, fichiers ABI d'entrée de l'outil) est spécifié dans [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) ; l'emplacement et la taille du cache disque, en tant qu'effet sur le système de fichiers, sont dans [integration.md](integration.md), section 3 ; l'invocation de l'outil de régénération est dans [architecture.md](architecture.md), section 9 ; l'usage des paramètres ainsi nommés par l'inférence des paramètres est dans [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 3. Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-SIG-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Vue d'ensemble

Un sélecteur est formé des 4 premiers octets du haché keccak-256 de la signature canonique d'une fonction (`nom(type1,type2)`). Le système l'utilise à deux fins : nommer chaque point d'entrée découvert d'après son identifiant, et afficher sous forme de signature lisible les constantes entières du code qui coïncident avec un sélecteur connu (comparaisons de l'arbre de dispatch, appels externes, sujets de journaux). Toutes les sources sont locales.

## 2. Sources de signatures et précédence

- **FR-SIG-01** : Avant toute recherche, le système DOIT normaliser un sélecteur, fourni sous forme d'entier ou de chaîne hexadécimale, en la chaîne `0x` suivie d'au moins 8 chiffres hexadécimaux minuscules, complétée par des zéros à gauche ; une valeur supérieure à 32 bits produit une chaîne plus longue qui ne correspond à aucune entrée.
- **FR-SIG-02** : Le système DOIT consulter les sources dans cet ordre strict et retenir la première correspondance : (1) une table interne de 121 sélecteurs usuels (jeton ERC-20, coffre ERC-4626, prêt et emprunt, staking et récompenses, proxys et mises à niveau, Diamond EIP-2535, paire et routeur d'AMM) ; (2) le cache disque construit à partir du dump embarqué (section 3) ; (3) le fichier de signatures locales embarqué ; en l'absence de correspondance, le sélecteur est non résolu.
- **FR-SIG-03** : Une entrée trouvée mais vide dans le cache disque DOIT être traitée comme une absence de correspondance et la recherche poursuivie dans la source suivante.
- **FR-SIG-04** : Le système DOIT mémoriser le résultat de chaque recherche, pour chaque valeur d'argument distincte, pendant toute la durée du processus, aucune source en ligne n'étant jamais consultée (voir [architecture.md](architecture.md), section 1).
- **FR-SIG-05** : Le système DOIT charger le fichier de signatures locales une seule fois par processus, lors de sa première consultation ; un fichier absent DOIT être traité comme une source vide, et un fichier illisible ou invalide DOIT être journalisé (`Failed to load local_sigs.json`) puis traité comme une source vide.
- **FR-SIG-06** : La table interne DOIT faire partie du système lui-même et non de son paramétrage : son contenu ne peut évoluer que par une nouvelle version du système (voir [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md), section 5).

*Note contextuelle : la table interne compte 123 entrées littérales pour 121 sélecteurs distincts : les sélecteurs `0x6e553f65` et `0x2e1a7d4d` y sont définis deux fois, et la seconde définition l'emporte silencieusement (`deposit(uint256 value, address addr)` et `withdraw(uint256 value)` plutôt que les variantes ERC-4626 et de staking définies plus haut).*

## 3. Cache disque de signatures

- **FR-SIG-07** : Le système DOIT interroger le dump de signatures au travers d'une base clé-valeur sur disque, le cache disque, dont l'emplacement est spécifié dans [integration.md](integration.md), section 3.
- **FR-SIG-08** : Au début de toute recherche non mémorisée, quelle que soit la source qui fournira finalement la réponse, si le fichier de cache n'existe pas, le système DOIT d'abord le construire en décompressant intégralement le dump embarqué (environ 296 Mio de texte à ce jour) et en y inscrivant une entrée par ligne, indexée par le sélecteur tel qu'il est écrit dans le dump, une ligne ultérieure portant le même sélecteur remplaçant la précédente.
- **FR-SIG-09** : La construction DOIT être journalisée au niveau INFO, au début (`Loading <dump> into <cache>...`) et à la fin (`<cache> is ready.`) ; elle représente un coût ponctuel notable, supporté par la première décompilation qui résout un sélecteur sur une machine donnée.
- **FR-SIG-10** : Le système DOIT vérifier l'existence du fichier de cache à chaque recherche non mémorisée, mais NE DOIT ni invalider ni versionner ce cache : une mise à jour du dump embarqué (nouvelle version du paquet) n'est prise en compte qu'après suppression manuelle du fichier de cache.

## 4. Nommage des fonctions et de leurs paramètres

### 4.1 Points d'entrée

- **FR-SIG-11** : Pour un point d'entrée identifié par un sélecteur résolu, le système DOIT construire le nom affiché `nom(type nom, …)` à partir de la signature, les noms de paramètres vides étant remplacés par `_param<k>` (k à partir de 1), ainsi que le nom ABI `nom(type,type)` sans espaces ni noms de paramètres.
- **FR-SIG-12** : Pour un point d'entrée identifié par un sélecteur non résolu, le système DOIT utiliser le nom de repli `unknown` suivi du sélecteur sans son préfixe `0x`, que la caractérisation de la fonction complète ensuite par les paramètres inférés (voir [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), section 3).
- **FR-SIG-13** : Pour un point d'entrée dont l'identifiant n'est pas hexadécimal, le système DOIT utiliser l'identifiant tel quel comme nom et, faute de liste de paramètres, l'afficher suivi de `(?)` ; c'est le cas de la fonction de repli `_fallback(?)`, seul point d'entrée produit dans l'état actuel du système.

*Note contextuelle : le remplacement des noms de paramètres vides par `_param<k>` s'effectue directement dans l'entrée de signature mémorisée, qui est partagée ; les affichages ultérieurs du même sélecteur dans le même processus portent donc les noms remplacés.*

### 4.2 Constantes rencontrées dans le code

- **FR-SIG-14** : Lors du rendu du texte, le système DOIT rechercher dans la base de signatures toute constante entière d'au moins 6 chiffres hexadécimaux, sous réserve de FR-SIG-15, en essayant successivement : ses 8 premiers chiffres hexadécimaux (poids forts) ; pour une constante d'au moins 61 chiffres, les 8 premiers chiffres de sa forme alignée sur 64 chiffres ; pour une constante d'au plus 8 chiffres, sa forme complétée à 8 chiffres.
- **FR-SIG-15** : Les constantes prises en charge par une règle de mise en forme numérique prioritaire (grandes valeurs, puissances de dix, durées : voir [sorties.md](sorties.md), section 2.4) NE DOIVENT PAS être recherchées.
- **FR-SIG-16** : Lorsqu'une constante numérique d'une expression est résolue, le système DOIT l'afficher sous la forme `nom(type nom, …)` à la place de sa valeur numérique, quel que soit le nom trouvé ; ce mécanisme fait apparaître les noms des fonctions ABI dans l'arbre de dispatch (par exemple « if totalSupply() == uint32(call.func_hash) >> 224: ») ; les noms de paramètres y sont repris tels qu'ils figurent dans la source, un nom vide laissant le type seul suivi d'une espace.
- **FR-SIG-17** : Pour le premier sujet (topic) d'une ligne de journal d'événement et pour le fragment de sélecteur constant d'un appel externe, le système DOIT rechercher la valeur de la même manière (le sujet l'étant donc par ses 4 premiers octets) et afficher la signature trouvée si son nom ne contient pas `unknown_`, ou à défaut la valeur en hexadécimal, réduite pour un sujet à `0x` suivi de ses 8 premiers chiffres hexadécimaux.

*Note contextuelle : la base contenant plus d'un million et demi de sélecteurs, une constante numérique qui coïncide par hasard avec les premiers octets d'un sélecteur connu est affichée comme une signature de fonction (par exemple un masque de 128 bits, ou la constante 1 048 576 affichée `unknown00100000(uint256 _param1)`). Environ un quart des entrées du dump portent en effet un nom synthétique de la forme `unknown<sélecteur>`, que l'exclusion de FR-SIG-17 (noms contenant `unknown_`, avec un tiret bas) ne filtre pas : aucune donnée embarquée ne déclenche cette exclusion. Le texte doit donc être relu avec cette réserve ; l'AST JSON conserve toujours la valeur numérique.*

## 5. Outil de régénération de la base locale

L'outil reconstruit le fichier de signatures locales à partir d'un corpus d'ABI fourni par l'utilisateur ; aucun corpus n'est livré avec le dépôt.

- **FR-SIG-18** : L'outil DOIT parcourir récursivement chacun des répertoires de `SCOBELIX_ABI_ROOTS` (liste séparée par des deux-points, les éléments vides étant ignorés) à la recherche des fichiers ABI nommés conformément à [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md), section 4.
- **FR-SIG-19** : Un répertoire inexistant DOIT provoquer l'affichage de `warning: <répertoire> does not exist, skipping` sur la sortie standard et la poursuite du parcours des autres répertoires.
- **FR-SIG-20** : L'outil DOIT dédoublonner les fichiers trouvés d'après leur chemin absolu résolu et les traiter dans l'ordre lexicographique de ces chemins.
- **FR-SIG-21** : Pour chaque fichier, l'outil DOIT extraire les signatures de fonctions selon les formes de contenu, les entrées et les types acceptés par [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md), section 4, en ignorant sans message tout fichier, entrée ou signature non conforme, et construire pour chaque fonction retenue sa signature canonique `nom(t1,t2,…)` en joignant les types de ses paramètres par des virgules, sans espace.
- **FR-SIG-22** : L'outil DOIT conserver la première occurrence de chaque signature rencontrée, avec les noms de paramètres de l'ABI ou, à défaut, `param<k>` (k à partir de 1).
- **FR-SIG-23** : L'outil DOIT calculer localement le sélecteur de chaque signature (4 premiers octets du haché keccak-256), sans recourir à aucun binaire externe.
- **FR-SIG-24** : Pour chaque sélecteur, l'outil DOIT conserver la première signature rencontrée ; une signature ultérieure de même sélecteur et de nom différent DOIT être comptée comme collision et ignorée, et une signature de même sélecteur et de même nom DOIT être ignorée sans être comptée.
- **FR-SIG-25** : L'outil DOIT écrire le résultat, en remplacement complet du contenu antérieur, dans le fichier désigné par `SCOBELIX_SIGS_OUT` (par défaut le fichier de signatures locales embarqué dans le paquet), en créant au besoin son répertoire parent, sous la forme décrite dans [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md), section 2.
- **FR-SIG-26** : L'outil DOIT terminer par le message `wrote <fichier> with <N> signatures (<C> conflicts skipped)` sur la sortie standard.
- **FR-SIG-27** : Un fichier de signatures locales régénéré à l'emplacement par défaut DOIT être pris en compte, comme troisième source (FR-SIG-02), par tout processus de décompilation démarré après son écriture, sans cache à invalider (FR-SIG-05) ; un fichier écrit ailleurs au moyen de `SCOBELIX_SIGS_OUT` n'est jamais lu par la décompilation.

---

Navigation : [architecture.md](architecture.md) · [pipeline-decompilation.md](pipeline-decompilation.md) · [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) · [generation-solidity.md](generation-solidity.md) · [sorties.md](sorties.md) · [integration.md](integration.md) · [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) · [README.md](../README.md)
