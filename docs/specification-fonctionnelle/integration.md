# Intégration de Scobelix dans son environnement

Ce document (préfixe `INT`) spécifie tout ce que le système échange avec l'extérieur et ce qu'il attend de ces tiers : le nœud Ethereum interrogé en mode adresse, le compilateur Solidity invoqué comme binaire externe, le système de fichiers (cache utilisateur, données embarquées, fichier de profil), la distribution sous forme de paquet installable, l'intégration continue et le versionnage automatique, la suite de tests considérée comme contrat de non-régression, et le statut des scripts de vérification hérités. Scobelix étant un outil autonome, il n'a pas d'autre intégration : tout programme appelant l'utilise par sa commande ou par son interface Python, décrites dans [architecture.md](architecture.md), sections 7 et 8, et peut s'appuyer sur le payload combiné de [sorties.md](sorties.md), section 4.

Ce document ne redécrit ni la sémantique de la validation par le compilateur ([generation-solidity.md](generation-solidity.md), section 5) ni celle du cache de signatures ([resolution-signatures.md](resolution-signatures.md), section 3) : il en fixe le contrat externe. Voir [README.md](../README.md) pour la table des matières du répertoire `docs/`.

Chaque exigence est identifiée par un code FR-INT-NN. Sauf mention contraire (« DEVRAIT », « PEUT », « NE DOIT PAS »), une exigence est obligatoire (« DOIT »).

## 1. Nœud Ethereum (mode adresse)

- **FR-INT-01** : La lecture du code d'un contrat auprès d'un nœud Ethereum, seul échange réseau du système (voir [architecture.md](architecture.md), section 1), DOIT n'être déclenchée que par une décompilation depuis une adresse (entrée de 42 caractères de la commande, ou fonction de décompilation par adresse de l'interface Python).
- **FR-INT-02** : Le système DOIT exiger une adresse composée uniquement de caractères alphanumériques (une adresse contenant tout autre caractère provoque une erreur avant tout accès réseau), la convertir en minuscules, puis au format checksum avant l'interrogation ; une adresse alphanumérique qui n'est pas une adresse hexadécimale valide est rejetée par cette conversion, également avant tout accès réseau.

*Note contextuelle : le contrôle du caractère alphanumérique est une auto-vérification interne, qui disparaît lorsque l'interpréteur est lancé en mode optimisé ; l'adresse invalide est alors rejetée par la seule conversion au format checksum.*
- **FR-INT-03** : Le système DOIT demander le code déployé à l'adresse pour le bloc le plus récent, puis décompiler le code hexadécimal obtenu exactement comme un bytecode fourni directement ; un compte sans code DOIT aboutir au résultat « aucun code » de [architecture.md](architecture.md), section 2.
- **FR-INT-04** : Le nœud interrogé DOIT être déterminé par la bibliothèque d'accès Ethereum, qui retient le premier point d'accès joignable dans l'ordre suivant : celui que désigne `WEB3_PROVIDER_URI` (schéma `http`/`https`, `ws`/`wss` ou `file` pour une socket IPC) lorsqu'elle est définie, puis les points d'accès locaux par défaut (socket IPC, HTTP puis WebSocket) ; un point désigné mais injoignable est donc silencieusement remplacé par un nœud local joignable, un schéma non pris en charge provoque une erreur, et en l'absence de tout nœud joignable l'erreur de la bibliothèque DOIT être propagée.
- **FR-INT-05** : Le système NE DOIT appliquer ni reprise sur erreur ni délai d'attente propre à l'interrogation du nœud : toute erreur du nœud ou du transport DOIT être propagée à l'appelant sans être transformée.
- **FR-INT-06** : Le système DOIT attendre du tiers un point d'accès JSON-RPC Ethereum qui réponde à la lecture du code d'un compte (méthode standard de lecture du code) par le bytecode runtime en hexadécimal.

## 2. Compilateur Solidity (binaire externe facultatif)

Le compilateur n'est pas une dépendance déclarée du paquet (voir [architecture.md](architecture.md), section 5) ; sa localisation, son invocation, son délai maximal et le traitement de son absence sont spécifiés dans [generation-solidity.md](generation-solidity.md), section 5. Cette section fixe ce que le système attend de lui.

- **FR-INT-07** : Le système DOIT attendre du compilateur qu'il accepte le pragma `^0.8.0` (donc un compilateur de la série 0.8), l'option `--bin` suivie d'un chemin de fichier, qu'il termine avec un code non nul en cas d'échec et qu'il écrive ses diagnostics sur sa sortie d'erreur dans le format texte dont les lignes commencent par `Error` ou `Warning`.
- **FR-INT-08** : Les tests de compilation réelle DOIVENT épingler la version 0.8.19 du compilateur au moyen de la variable d'environnement `SOLC_VERSION` du sélecteur de versions de compilateur, variable sans effet sur un compilateur installé directement.

## 3. Système de fichiers

- **FR-INT-09** : Le système DOIT placer le cache de signatures dans le répertoire de cache utilisateur standard de la plateforme pour l'application `scobelix` (sous Linux, `~/.cache/scobelix`, ou le sous-répertoire `scobelix` de `XDG_CACHE_HOME` lorsque cette variable est définie), créé à la demande, sous le nom de fichier `abi_db.shelve`.
- **FR-INT-10** : Le système NE DOIT offrir aucune option pour désactiver ce cache ni pour en choisir un autre emplacement ; son volume observé est d'environ 370 Mio pour un dump embarqué d'environ 22,8 Mio (cycle de vie dans [resolution-signatures.md](resolution-signatures.md), section 3).

*Note contextuelle : d'après le code, le cache suppose un moteur de base clé-valeur de l'interpréteur qui enregistre la base dans un fichier unique portant exactement le nom demandé ; un moteur qui ajouterait des extensions au nom de fichier ferait échouer la vérification effectuée après la construction du cache, et chaque résolution de sélecteur échouerait.*

- **FR-INT-11** : Le système DOIT lire ses fichiers de données de signatures (dump compressé et fichier de signatures locales) à l'intérieur du paquet installé ; seul l'outil de régénération, avec sa destination par défaut, écrit dans le paquet, ce qui suppose un droit d'écriture sur l'installation.
- **FR-INT-12** : Le système NE DOIT écrire dans le répertoire courant que le fichier de profil `scobelix.prof`, et seulement sur demande (`--profile`).
- **FR-INT-13** : La validation par compilation DOIT n'utiliser qu'un répertoire temporaire propre à chaque invocation, supprimé à la fin de celle-ci, y compris en cas d'échec ou de dépassement de délai.

*Note contextuelle : les deux fichiers de données embarqués (environ 22,8 Mio pour le dump) sont suivis directement par le gestionnaire de versions du dépôt, sans mécanisme dédié aux fichiers volumineux.*

## 4. Distribution sous forme de paquet

- **FR-INT-14** : Le système DOIT être distribué comme un paquet Python construit par le moteur de construction poetry-core (version 1.2.0 ou ultérieure), dont la version unique est déclarée dans le manifeste du projet au format `X.Y.Z` (0.7.3 à la date de ce document).
- **FR-INT-15** : Le paquet DOIT déclarer le script console `scobelix`, la contrainte d'interpréteur `>=3.9,<4` (voir [architecture.md](architecture.md), section 5), les dépendances d'exécution (journalisation colorée ^15, client HTTP ^2, bibliothèque d'accès Ethereum 6.0.0-beta.8 avec autorisation des préversions, délais par signaux ^0.5, répertoires utilisateur ^1.4) et, dans un groupe séparé de dépendances de développement, l'outil de test pytest ^7.
- **FR-INT-16** : Le paquet DOIT inclure les fichiers de données de signatures situés dans son arborescence, de sorte qu'une installation soit fonctionnelle sans téléchargement complémentaire.
- **FR-INT-17** : La configuration de test du paquet DOIT désigner le répertoire de tests et désactiver le greffon de test enregistré par la bibliothèque d'accès Ethereum figée, dont le chargement échoue avec les versions récentes de ses propres dépendances.
- **FR-INT-18** : L'environnement d'installation et d'exécution DOIT fournir un outillage de construction Python (setuptools) de version antérieure à 81 : la bibliothèque d'accès Ethereum figée importe, dès son chargement, une interface de gestion des ressources de paquets retirée à partir de cette version. Cette contrainte n'est pas déclarée par le paquet ; sans elle, le mode adresse, la génération Solidity et l'outil de régénération échouent, tandis que la décompilation d'un bytecode, qui n'utilise pas cette bibliothèque, reste possible.

*Note contextuelle : le dépôt contient encore un manifeste d'inclusion de données hérité de l'ancien outillage de construction ; il est sans effet avec le moteur actuel, qui inclut déjà les données. Il contient aussi une configuration du vérificateur de style (quatre règles ignorées, longueur de ligne maximale de 100 caractères) utilisée par l'intégration continue en mode informatif.*

## 5. Intégration continue et versionnage

- **FR-INT-19** : Le workflow de tests DOIT se déclencher à chaque envoi de commits et à chaque demande de fusion visant la branche de travail du dépôt ou la branche `master`, à l'exception des envois et des demandes de fusion dont le commit de tête contient le marqueur `[skip ci]` (ou l'un des marqueurs équivalents reconnus par la plateforme d'intégration continue), cas du commit de version de FR-INT-25.
- **FR-INT-20** : Le workflow de tests DOIT s'exécuter sur une machine Ubuntu, pour chacune des versions Python 3.9, 3.10 et 3.11, l'échec d'une version n'interrompant pas les autres.
- **FR-INT-21** : Le workflow de tests DOIT, dans cet ordre : mettre à jour l'installateur de paquets, installer un outillage de construction antérieur à la version 81, installer le système en mode éditable, installer pytest, le vérificateur de style et le sélecteur de versions du compilateur, installer et activer le compilateur Solidity 0.8.19, puis exécuter l'intégralité de la suite de tests en mode verbeux.
- **FR-INT-22** : Le workflow de tests DOIT exécuter le vérificateur de style sur le code du système en mode informatif uniquement : ses constats sont affichés mais NE DOIVENT jamais faire échouer le workflow.
- **FR-INT-23** : Le workflow de versionnage DOIT se déclencher à chaque envoi de commits sur la branche de travail, à l'exception des envois dont le commit de tête contient le marqueur `[skip ci]` : c'est ce marqueur, porté par le commit de version de FR-INT-25, qui empêche le workflow de se relancer sur son propre envoi.
- **FR-INT-24** : Le workflow de versionnage DOIT lire la version déclarée dans le manifeste du projet et la plus récente étiquette de la forme `vX.Y.Z` (tri par version), partir de la plus grande des deux, en incrémenter le numéro de correctif, et remplacer uniquement la ligne de version du manifeste, sans reformater le reste du fichier.
- **FR-INT-25** : Le workflow de versionnage DOIT ensuite créer, si le manifeste a changé, un commit de message `chore: bump version [skip ci]` dont l'auteur déclaré est le robot d'automatisation (`github-actions[bot]`), envoyer la branche de travail, puis créer et envoyer l'étiquette `v<nouvelle version>` lue dans le manifeste.
- **FR-INT-26** : Le workflow de versionnage DOIT utiliser un jeton d'accès dédié, fourni comme secret du dépôt (`BUMP_VERSION_TOKEN`), pour récupérer l'historique complet et envoyer commit et étiquette.

*Note contextuelle : le workflow de versionnage exclut aussi l'acteur `github-actions[bot]`, mais cette exclusion est inopérante. L'envoi étant authentifié par le jeton dédié de FR-INT-26, l'acteur de l'envoi est le titulaire de ce jeton, et non le robot, dont l'identité ne sert que d'auteur déclaré du commit ; seul le marqueur `[skip ci]` évite la boucle. Ce marqueur a un effet de bord : tant que le commit de version reste en tête de la branche de travail, une demande de fusion issue de cette branche ne déclenche pas non plus le workflow de tests. L'envoi de l'étiquette ne déclenche aucun des deux workflows, qui ne réagissent qu'aux branches.*

*Note contextuelle : la branche par défaut du dépôt distant (`master`) porte l'historique de l'outil amont, alors que le travail propre au système, les deux workflows et les étiquettes de version se trouvent sur une branche de travail distincte. La branche `master` ne contenant pas elle-même ces workflows, un envoi direct sur elle ne déclenche en l'état aucun test ; seuls les envois sur la branche de travail et les demandes de fusion qui incluent les workflows les déclenchent.*

## 6. Suite de tests comme contrat de non-régression

- **FR-INT-27** : Le système DOIT être accompagné d'une suite de tests pytest (52 tests à ce jour, chiffre vivant) couvrant : le pipeline complet sur des bytecodes de référence (stockage et sélecteurs résolus, slot de proxy et appel délégué reconstruits, boucle structurée en `while`) ; la structure du code Solidity généré et sa compilation réelle pour chacun des huit bytecodes de référence ; la résilience de la reconstruction du stockage ; des règles de simplification ; la détection des slots de proxy ; la validation par compilation ; la table des événements connus ; le calcul local des sélecteurs ; les clés et le format monoligne du payload combiné.
- **FR-INT-28** : Les tests de compilation réelle DOIVENT être ignorés automatiquement lorsqu'aucun compilateur n'est présent dans le `PATH`, et, lorsqu'il est présent, exiger un code de sortie nul et la présence de `Binary:` dans la sortie standard du compilateur, chaque compilation étant bornée à 60 secondes.
- **FR-INT-29** : Les bytecodes de référence DOIVENT être des bytecodes runtime stockés chacun sur une seule ligne hexadécimale sans préfixe `0x` ni saut de ligne final, accompagnés des sources Solidity dont ils sont issus (neuf sources pour huit bytecodes, l'une d'elles étant une base d'héritage), écrites pour le pragma `^0.8.19` et compilées avec solc 0.8.19 en mode optimisé (200 exécutions) sauf mention contraire dans la source ; toute nouvelle référence DEVRAIT suivre la même convention.
- **FR-INT-30** : La suite DOIT contenir un test marqué « échec attendu strict » qui documente la limite de suivi des accumulateurs de boucle ([pipeline-decompilation.md](pipeline-decompilation.md), section 5) : si ce test venait à réussir, la suite DOIT échouer, afin d'imposer la mise à jour de la documentation de la limite.
- **FR-INT-31** : Les exemples exécutables intégrés au composant de filtrage par motifs PEUVENT être exécutés séparément comme tests de documentation ; ils ne font pas partie de la suite.

## 7. Scripts de vérification hérités

- **FR-INT-32** : Le dépôt contient un pipeline d'intégration Jenkins et un script shell local hérités, qui décompilent un contrat déployé fixe récupéré auprès d'un point d'accès RPC public codé en dur, retirent les couleurs de la sortie, vérifient seulement qu'elle n'est pas vide et l'enregistrent sous une extension de fichier Vyper (le pipeline l'archivant en outre comme artefact) ; ces scripts NE DOIVENT PAS être considérés comme faisant partie du contrat d'intégration du système, qui ne dépend d'eux en rien.

*Note contextuelle : ces scripts ne sont plus maintenus et ont été remplacés par les tests sur bytecodes de référence (section 6). Ils sont trompeurs à plusieurs titres : la sortie enregistrée est du pseudo-code et non du Vyper ; l'étape Jenkins intitulée « vérification Vyper » n'invoque aucun compilateur Vyper, et les outils de test installés par le pipeline ne sont jamais exécutés ; le script local tente une compilation Vyper sans jamais échouer et suppose un chemin de dépôt personnel.*

---

Navigation : [architecture.md](architecture.md) · [pipeline-decompilation.md](pipeline-decompilation.md) · [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) · [resolution-signatures.md](resolution-signatures.md) · [generation-solidity.md](generation-solidity.md) · [sorties.md](sorties.md) · [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) · [README.md](../README.md)
