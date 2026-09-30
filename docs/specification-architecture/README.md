# Traçabilité d'architecture de Scobelix

Ce répertoire trace chaque exigence fonctionnelle de [../specification-fonctionnelle/](../specification-fonctionnelle/) et [../specification-parametrage/](../specification-parametrage/) vers son implémentation réelle dans le code du dépôt Scobelix : fichier, fonction ou élément précis, et explication du mécanisme effectif.

Contrairement aux deux autres répertoires — délibérément « boîte noire », sans aucune référence au code — celui-ci existe précisément pour faire le pont entre l'exigence et l'implémentation : chaque tableau ci-dessous cite des chemins de fichiers relatifs à la racine du dépôt, des noms de fonctions, de classes ou de constantes, et, pour les fichiers de configuration (manifeste du projet, workflows d'intégration continue), la clé ou l'étape concernée.

## Sommaire

| Fichier | Trace les exigences de |
|---|---|
| [architecture.md](architecture.md) | [../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md) (`FR-ARCH-01` à `71`) |
| [pipeline-decompilation.md](pipeline-decompilation.md) | [../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md) (`FR-DEC-01` à `90`) |
| [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) | [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md) (`FR-STOR-01` à `36`) |
| [resolution-signatures.md](resolution-signatures.md) | [../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) (`FR-SIG-01` à `27`) |
| [generation-solidity.md](generation-solidity.md) | [../specification-fonctionnelle/generation-solidity.md](../specification-fonctionnelle/generation-solidity.md) (`FR-SOL-01` à `51`) |
| [sorties.md](sorties.md) | [../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md) (`FR-SOR-01` à `51`) |
| [integration.md](integration.md) | [../specification-fonctionnelle/integration.md](../specification-fonctionnelle/integration.md) (`FR-INT-01` à `32`) |
| [parametrage-signatures.md](parametrage-signatures.md) | [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) (`FR-PARAM-01` à `22`) |

Les 380 exigences fonctionnelles du répertoire `docs/` sont couvertes — chaque identifiant apparaît au moins une fois, vérifié mécaniquement. Pour une vue consolidée de cette couverture (une ligne par exigence, sans l'explication détaillée), voir [matrice-couverture.md](matrice-couverture.md).

## Comment lire un tableau de traçabilité

Chaque document reprend exactement les sections et l'ordre du document fonctionnel correspondant ; une section introductive sans exigence est résumée en une phrase. Chaque ligne associe :
- **Exigence** — l'identifiant (`FR-<PRÉFIXE>-NN`) suivi d'un résumé très court ; l'énoncé complet reste dans le document fonctionnel, pas ici.
- **Fichier — Fonction/élément** — le chemin relatif à la racine du dépôt et le nom précis de la fonction, méthode (`Classe.méthode()`), classe, constante, clé de configuration ou étape de workflow concernée.
- **Explication** — comment ce code satisfait concrètement l'exigence (pas une reformulation de l'exigence elle-même).

Les notes contextuelles des documents fonctionnels sont reprises sous les tableaux, sous la forme « Note contextuelle du document source (…) : confirmée par … ». Quand une exigence n'a pas de traduction directe en un point de code précis — une convention documentaire, une absence de mécanisme, un comportement délégué à une dépendance tierce (fournisseur de nœud de la bibliothèque d'accès Ethereum, mode à signaux de la bibliothèque de délais, format de la bibliothèque de journalisation) — cela est dit explicitement plutôt que rattaché arbitrairement à un fichier.

## Note de méthode et limites

Ces citations de code sont un instantané de l'état du dépôt au 2026-09-29 : le code peut évoluer sans que ce répertoire soit mis à jour en parallèle. En cas de doute sur une citation, vérifier directement dans le fichier source cité plutôt que de faire confiance à l'ancienneté du document. Les chiffres vivants (nombre de tests, d'entrées de signatures, taille du cache) y sont datés.

Les comportements dont la mention indique « vérifié en bac à sable » ont été reproduits en exécutant le code du dépôt dans un répertoire temporaire, sans accès réseau et sans écriture dans le dépôt (cache de signatures existant utilisé en lecture, ou cache temporaire dédié) ; les autres sont établis par lecture du code.

Plusieurs écarts réels entre l'énoncé attendu d'un décompilateur et le comportement effectif du code ont été mis au jour et sont documentés explicitement, dans le document fonctionnel (note contextuelle) comme dans la traçabilité, plutôt que corrigés silencieusement — par exemple : la génération Solidity qui échoue sur un masque à décalage symbolique alors qu'elle se veut infaillible, la garde de succès d'un appel externe traduite en condition toujours vraie, un `balance` sur adresse concrète qui fait échouer la fonction, trois hachés de la table arc-en-ciel jamais reconnus, `addmod` calculé comme `mulmod`, ou la résilience du stockage inopérante pour les accès écrits. Ce ne sont pas des erreurs de ce répertoire : c'est le comportement réel du code, différent de ce que l'intention affichée laisse penser — une piste utile pour une revue de code ultérieure.

Voir [../README.md](../README.md) pour la table des matières complète du répertoire `docs/`.
