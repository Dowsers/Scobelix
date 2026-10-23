# Traçabilité d'architecture de Scobelix

Ce répertoire trace chaque exigence fonctionnelle de [../specification-fonctionnelle/](../specification-fonctionnelle/) et [../specification-parametrage/](../specification-parametrage/) vers son implémentation réelle dans le code du dépôt Scobelix : fichier, fonction ou élément précis, et explication du mécanisme effectif.

Contrairement aux deux autres répertoires — délibérément « boîte noire », sans aucune référence au code — celui-ci existe précisément pour faire le pont entre l'exigence et l'implémentation : chaque tableau ci-dessous cite des chemins de fichiers relatifs à la racine du dépôt, des noms de fonctions, de classes ou de constantes, et, pour les fichiers de configuration (manifeste du projet, workflows d'intégration continue), la clé ou l'étape concernée.

## Sommaire

| Fichier | Trace les exigences de |
|---|---|
| [architecture.md](architecture.md) | [../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md) (`FR-ARCH-01` à `81`) |
| [pipeline-decompilation.md](pipeline-decompilation.md) | [../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md) (`FR-DEC-01` à `108`) |
| [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) | [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md) (`FR-STOR-01` à `41`) |
| [resolution-signatures.md](resolution-signatures.md) | [../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) (`FR-SIG-01` à `46`) |
| [generation-solidity.md](generation-solidity.md) | [../specification-fonctionnelle/generation-solidity.md](../specification-fonctionnelle/generation-solidity.md) (`FR-SOL-01` à `73`) |
| [sorties.md](sorties.md) | [../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md) (`FR-SOR-01` à `65`) |
| [integration.md](integration.md) | [../specification-fonctionnelle/integration.md](../specification-fonctionnelle/integration.md) (`FR-INT-01` à `38`) |
| [parametrage-signatures.md](parametrage-signatures.md) | [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) (`FR-PARAM-01` à `30`) |

Les 482 exigences fonctionnelles du répertoire `docs/` sont couvertes — chaque identifiant a exactement une ligne dans le document de traçabilité de son domaine, dans l'ordre du document fonctionnel, vérifié mécaniquement. Pour une vue consolidée de cette couverture (une ligne par exigence : objet abrégé et localisation, sans l'explication détaillée), voir [matrice-couverture.md](matrice-couverture.md).

## Comment lire un tableau de traçabilité

Chaque document reprend exactement les sections et l'ordre du document fonctionnel correspondant ; une section introductive sans exigence est résumée en une phrase. Chaque ligne associe :
- **Exigence** — l'identifiant (`FR-<PRÉFIXE>-NN`) suivi d'un résumé très court ; l'énoncé complet reste dans le document fonctionnel, pas ici.
- **Fichier — Fonction/élément** — le chemin relatif à la racine du dépôt et le nom précis de la fonction, méthode (`Classe.méthode()`), classe, constante, clé de configuration ou étape de workflow concernée.
- **Explication** — comment ce code satisfait concrètement l'exigence (pas une reformulation de l'exigence elle-même).

Les notes contextuelles des documents fonctionnels sont reprises sous les tableaux, sous la forme « Note contextuelle du document source (…) : confirmée par … ». Quand une exigence n'a pas de traduction directe en un point de code précis — une convention documentaire, une absence de mécanisme, un comportement délégué à une dépendance tierce (fournisseur de nœud de la bibliothèque d'accès Ethereum, compilateur Solidity, machines EVM de la vérification, mode à signaux de la bibliothèque de délais, format de la bibliothèque de journalisation) — cela est dit explicitement plutôt que rattaché arbitrairement à un fichier.

## Note de méthode et limites

Ces citations de code sont un instantané de l'état du dépôt au 2026-10-15, mis à jour le 2026-10-21 pour le budget de temps global, l'échec de la génération dans le payload combiné, la nature de l'entrée de la commande et la version visée par les constructions de Cancun : le code peut évoluer sans que ce répertoire soit mis à jour en parallèle. En cas de doute sur une citation, vérifier directement dans le fichier source cité plutôt que de faire confiance à l'ancienneté du document. Les chiffres vivants (nombre de tests et de bytecodes de référence, lignes de la base de signatures, volume du fichier de la base) y sont datés.

Les comportements dont la mention indique « vérifié en bac à sable » ont été reproduits en exécutant le code du dépôt hors du dépôt, sans accès réseau et sans écriture dans le dépôt : base de signatures existante ouverte en lecture seule, ou base dédiée désignée par `SCOBELIX_SIGDB` dans un répertoire temporaire ; compilateurs Solidity déjà installés et machines EVM de l'option `verify` pour la génération vérifiée ; bytecodes de référence de `tests/fixtures/`. Les autres comportements — notamment le mode adresse face à un nœud réel et le téléchargement d'un compilateur — sont établis par lecture du code.

Plusieurs écarts réels entre l'intention affichée et le comportement effectif du code sont documentés explicitement, dans le document fonctionnel (note contextuelle) comme dans la traçabilité, plutôt que corrigés silencieusement — par exemple : une heuristique de lisibilité qui compare la branche vraie d'un test avec elle-même ([../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md), section 9.1) ; une règle héritée qui affiche un multiple de 86 400 secondes comme un nombre d'heures × 24 × 3600, soit 24 fois la valeur réelle ([../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md), section 2.4) ; les options du générateur Solidity analysées mais ignorées sans message en l'absence de `--solidity` ([../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md), section 7) ; un fichier de source de signatures invalide qui rend toute la base indisponible, et non cette seule source ([../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md), section 3). Ce ne sont pas des erreurs de ce répertoire : c'est le comportement réel du code — une piste utile pour une revue de code ultérieure. La liste des limites connues qui restent ouvertes figure dans le [TODO.md](../../TODO.md) du dépôt.

Voir [../README.md](../README.md) pour la table des matières complète du répertoire `docs/`.
