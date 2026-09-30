# Traçabilité d'architecture — Intégration de Scobelix dans son environnement

Ce document trace chaque exigence de [../specification-fonctionnelle/integration.md](../specification-fonctionnelle/integration.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement. Plusieurs exigences portent sur des fichiers de configuration (manifeste du projet, workflows d'intégration continue) plutôt que sur du code : l'élément cité est alors la clé ou l'étape concernée.

## 1. Nœud Ethereum (mode adresse)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-01** : lecture de code déclenchée seulement par la décompilation d'une adresse | `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/__main__.py` — `print_decompilation()` | `load_addr()` n'est appelée que par `decompile_address()` ; la commande n'appelle cette dernière que pour un argument de 42 caractères. |
| **FR-INT-02** : adresse alphanumérique, minuscules, checksum, avant tout accès | `scobelix/loader.py` — `Loader.load_addr()` | `assert address.isalnum()`, `address.lower()`, puis `Web3.to_checksum_address(address)`, évalué avant l'appel `get_code()`. Vérifié en bac à sable : `0x-…` lève `AssertionError`, `0xzz…` et `0xg1…` lèvent `ValueError`, sans connexion. |

Note contextuelle du document source (contrôle désactivé en mode optimisé) : confirmée — le contrôle est une instruction `assert`, supprimée par l'option `-O` de l'interpréteur.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-03** : code au dernier bloc, décompilé comme un bytecode, compte sans code → « aucun code » | `scobelix/loader.py` — `Loader.load_addr()`, `Loader.load_binary()` | `w3.eth.get_code(…)` sans bloc explicite (défaut `latest` de la bibliothèque), `.hex().removeprefix("0x")` puis `self.load_binary(code)` ; un code vide mène au retour anticipé de `_decompile_with_loader()`. |
| **FR-INT-04** : choix du nœud par la bibliothèque | `scobelix/loader.py` — `Loader.load_addr()` | `from web3.auto import w3` : instance `Web3()` sans fournisseur explicite, donc fournisseur automatique de la bibliothèque. Dans la version installée (6.0.0-beta.8), celui-ci essaie dans l'ordre le fournisseur construit depuis `WEB3_PROVIDER_URI` (schémas `file`, `http`/`https`, `ws`/`wss`, `NotImplementedError` sinon), puis les fournisseurs IPC, HTTP et WebSocket par défaut, en retenant le premier connecté, et lève `CannotHandleRequest` si aucun ne l'est. Comportement d'une dépendance tierce, constaté dans sa source installée, sans code propre au dépôt. |
| **FR-INT-05** : ni reprise ni délai propre | `scobelix/loader.py` — `Loader.load_addr()` | L'appel `get_code()` n'est entouré d'aucun `try`, d'aucune boucle ni d'aucun délai ; seul le fournisseur automatique de la bibliothèque renouvelle une fois sa requête, en redécouvrant le fournisseur, après une erreur d'entrée-sortie (`OSError`). |
| **FR-INT-06** : point d'accès JSON-RPC répondant à la lecture du code | `scobelix/loader.py` — `Loader.load_addr()` | `w3.eth.get_code()` émet la méthode standard `eth_getCode` ; exigence portant sur le tiers, sans autre code. |

## 2. Compilateur Solidity (binaire externe facultatif)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-07** : série 0.8, option `--bin`, code de sortie, diagnostics `Error`/`Warning` | `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | Le pragma émis est `^0.8.0` ; la commande est `[solc, "--bin", chemin]` ; le statut dépend de `returncode` et des lignes de `stderr` commençant par `Error`/`Warning`. |
| **FR-INT-08** : tests épinglés sur 0.8.19 via `SOLC_VERSION` | `tests/test_solgen.py` — `test_generated_solidity_actually_compiles()` ; `.github/workflows/ci.yml` — étape `Install solc 0.8.19` | Le test lance le compilateur avec `env = dict(os.environ, SOLC_VERSION="0.8.19")` ; l'intégration continue installe et active 0.8.19 par le sélecteur de versions. |

## 3. Système de fichiers

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-09** : cache dans le répertoire de cache utilisateur de `scobelix`, fichier `abi_db.shelve` | `scobelix/utils/helpers.py` — `cache_dir()` ; `scobelix/utils/supplement.py` — `abi_path()` | `Path(user_cache_dir("scobelix", "scobelix"))`, créé par `mkdir(parents=True)` s'il manque ; `abi_path()` y ajoute `abi_db.shelve`. Vérifié en bac à sable : avec `XDG_CACHE_HOME` défini, le cache est placé dans son sous-répertoire `scobelix`. |
| **FR-INT-10** : aucune option de désactivation ni d'emplacement, volume observé | `scobelix/utils/supplement.py` — `abi_path()`, `check_supplements()` | Chemin calculé sans paramètre ni variable d'environnement propre ; fichier de 370 528 256 octets observé sur la machine de rédaction (moteur `dbm.gnu`). |

Note contextuelle du document source (moteur à fichier unique supposé) : confirmée par `assert abi_path().is_file()` en fin de `check_supplements()` et par la réouverture sous le même nom dans `fetch_sig()`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-11** : données lues dans le paquet, écriture par l'outil seulement | `scobelix/utils/supplement.py` — `LOCAL_SIGS_BULK_PATH`, `check_supplements()` ; `scobelix/tools/build_local_sigs.py` — `OUT_PATH` | Chemins relatifs à `Path(__file__)` (dossier `data` du paquet) ; seule la destination par défaut `OUT_PATH` de l'outil pointe vers ce dossier en écriture. |
| **FR-INT-12** : seul `scobelix.prof` écrit dans le répertoire courant | `scobelix/__main__.py` — `main()` | `profile.dump_stats("scobelix.prof")` est l'unique écriture par chemin relatif ; le cache va dans le répertoire utilisateur, la validation dans un répertoire temporaire. |
| **FR-INT-13** : répertoire temporaire propre à chaque validation, supprimé | `scobelix/solgen/validate.py` — `validate_solidity()` | `with tempfile.TemporaryDirectory() as tmpdir:` englobe l'écriture et la compilation ; la sortie du bloc supprime le répertoire, y compris lors des retours anticipés sur `TimeoutExpired` et `OSError`. |

Note contextuelle du document source (fichiers de données suivis sans mécanisme dédié) : confirmée — `scobelix/data/abi_dump.xz` et `scobelix/data/local_sigs.json` figurent dans l'index git et le dépôt n'a pas de fichier `.gitattributes`.

## 4. Distribution sous forme de paquet

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-14** : paquet construit par poetry-core ≥ 1.2.0, version unique `X.Y.Z` | `pyproject.toml` — `[build-system]`, clé `version` | `requires = ["poetry-core>=1.2.0"]`, `build-backend = "poetry.core.masonry.api"` ; `version = "0.7.3"` à la date de rédaction. |
| **FR-INT-15** : script console, contrainte d'interpréteur, dépendances | `pyproject.toml` — `[tool.poetry.scripts]`, `[tool.poetry.dependencies]`, `[tool.poetry.group.dev.dependencies]` | `scobelix = "scobelix.__main__:main"` ; `coloredlogs = "^15"`, `requests = "^2"`, `web3 = {version = "6.0.0-beta.8", allow-prereleases = true}`, `timeout_decorator = "^0.5"`, `appdirs = "^1.4"` ; groupe `dev` : `pytest = "^7"`. |
| **FR-INT-16** : données incluses dans le paquet | `pyproject.toml` — clé `packages` | `{ include="scobelix", from="." }` : le moteur de construction inclut les fichiers du dossier `scobelix/data`, situé dans le paquet. |
| **FR-INT-17** : répertoire de tests et greffon de test désactivé | `pyproject.toml` — `[tool.pytest.ini_options]` | `testpaths = ["tests"]` et `addopts = "-p no:pytest_ethereum"`, avec commentaire expliquant l'échec de chargement du greffon. |
| **FR-INT-18** : setuptools < 81 requis à l'installation et à l'exécution, non déclaré | `.github/workflows/ci.yml` — étape `Install dependencies` ; `pyproject.toml` | L'intégration continue installe `"setuptools<81"` avec un commentaire sur l'interface `pkg_resources` ; `pyproject.toml` ne déclare pas cette contrainte. La bibliothèque installée importe `pkg_resources` à la première ligne de son module principal (constaté dans sa source) ; la décompilation d'un bytecode n'importe pas cette bibliothèque (voir la traçabilité de FR-ARCH-32 dans [architecture.md](architecture.md)). |

Note contextuelle du document source (manifeste d'inclusion hérité, configuration du vérificateur de style) : confirmée — `MANIFEST.in` ne contient que `graft scobelix/data`, sans effet pour le moteur poetry-core ; `.flake8` déclare `ignore = E203, E266, W503, E741` et `max-line-length = 100`.

## 5. Intégration continue et versionnage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-19** : déclenchement sur envoi et demande de fusion vers la branche de travail ou `master`, sauf commit de tête marqué `[skip ci]` | `.github/workflows/ci.yml` — clé `on` ; `.github/workflows/bump-version.yml` — étape `Commit and push changes` | `push.branches` et `pull_request.branches` listent tous deux la branche de travail et `master`, sans autre filtre. L'exception n'est portée par aucun code du dépôt : GitHub Actions n'exécute pas les workflows `on: push` et `on: pull_request` lorsque le commit de tête contient `[skip ci]`, marqueur que le workflow de versionnage place dans son message `chore: bump version [skip ci]`. |
| **FR-INT-20** : Ubuntu, Python 3.9 / 3.10 / 3.11, sans arrêt global | `.github/workflows/ci.yml` — job `test` | `runs-on: ubuntu-latest`, `strategy.fail-fast: false`, `matrix.python-version: ["3.9", "3.10", "3.11"]`. |
| **FR-INT-21** : étapes dans l'ordre | `.github/workflows/ci.yml` — étapes `Install dependencies`, `Install solc 0.8.19`, `Run tests` | `pip install --upgrade pip`, `"setuptools<81"`, `-e .`, `pytest flake8 solc-select` ; `solc-select install 0.8.19` et `use 0.8.19` ; `python -m pytest tests/ -v`. |
| **FR-INT-22** : vérificateur de style informatif | `.github/workflows/ci.yml` — étape `Lint (report only - not a merge gate yet)` | `python -m flake8 scobelix/ \|\| true` : le code de sortie est toujours nul. |
| **FR-INT-23** : versionnage sur envoi vers la branche de travail, non relancé grâce à `[skip ci]` | `.github/workflows/bump-version.yml` — clé `on`, étape `Commit and push changes` | `on.push.branches` ne liste que la branche de travail. La non-relance tient au message `chore: bump version [skip ci]` du commit envoyé par `git push origin` vers la branche de travail : la plateforme supprime alors le déclenchement `push`. La garde `if: github.actor != 'github-actions[bot]'` du job `bump-version` n'y contribue pas (voir la note sous le tableau). |
| **FR-INT-24** : version = max(manifeste, dernière étiquette) + correctif, ligne unique réécrite | `.github/workflows/bump-version.yml` — étape `Bump version in pyproject.toml` | Script Python : expression régulière `^version = "(\d+)\.(\d+)\.(\d+)"`, étiquettes listées par `git for-each-ref --sort=-v:refname` et filtrées par `^v(\d+)\.(\d+)\.(\d+)$`, `max(file_version, tag_version)`, `patch + 1`, `re.sub(…, count=1)` sur la seule ligne de version. |
| **FR-INT-25** : commit si changement, auteur déclaré robot, envoi de la branche, étiquette | `.github/workflows/bump-version.yml` — étapes `Commit and push changes`, `Tag the new version` | `git config user.name "github-actions[bot]"` et `user.email` (identité d'auteur du commit seulement), `git diff --cached --quiet \|\| git commit -m "chore: bump version [skip ci]"`, `git push` de la branche de travail (inconditionnel), puis version relue par `grep -m1 '^version = '` et `git tag "v${NEW_VERSION}"` + `git push`. |
| **FR-INT-26** : jeton dédié, historique complet | `.github/workflows/bump-version.yml` — étape `Checkout repo` | `actions/checkout@v4` avec `fetch-depth: 0` et `token: ${{ secrets.BUMP_VERSION_TOKEN }}`, jeton réutilisé par les `git push` suivants. |

Note contextuelle du document source (exclusion de l'acteur robot inopérante, effet de bord de `[skip ci]`) : confirmée. `actions/checkout` enregistre `BUMP_VERSION_TOKEN` comme identifiant des `git push` : l'acteur `github.actor` de l'exécution qui suit est donc le titulaire du jeton, jamais `github-actions[bot]` (un envoi fait avec le jeton par défaut du workflow ne déclencherait d'ailleurs aucun workflow). Le `git config user.name` ne fixe que l'auteur du commit. La garde `if: github.actor != 'github-actions[bot]'` ne filtre donc rien. Le `[skip ci]` du commit de tête s'applique aussi à l'événement `pull_request` de `ci.yml`, et les deux workflows ne déclarent que `branches` sous `push` : l'envoi `git push origin "v${NEW_VERSION}"` de l'étiquette ne les déclenche pas.

Note contextuelle du document source (branche `master` sans workflows) : confirmée par lecture de l'arbre de `master` (`git ls-tree`) : 37 fichiers issus de l'outil amont, sans répertoire `.github/` ; la référence `origin/HEAD` du dépôt local pointe sur `master`.

## 6. Suite de tests comme contrat de non-régression

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-27** : suite pytest et couverture | `tests/test_golden_fixtures.py`, `tests/test_solgen.py`, `tests/test_sparser_resilience.py`, `tests/test_simplify.py`, `tests/test_proxy_detect.py`, `tests/test_solgen_validate.py`, `tests/test_event_signatures.py`, `tests/test_build_local_sigs.py`, `tests/test_main_combined_json.py` | 45 fonctions de test, dont une paramétrée sur les huit bytecodes, soit 52 tests collectés (comptage du 2026-09-29) ; chaque fichier couvre l'un des thèmes énumérés par l'exigence. |
| **FR-INT-28** : tests de compilation ignorés sans compilateur, `Binary:`, 60 s | `tests/test_solgen.py` — `test_generated_solidity_actually_compiles()` | `@pytest.mark.skipif(SOLC is None, …)` avec `SOLC = shutil.which("solc")` ; `timeout=60` ; `assert result.returncode == 0` et `assert "Binary:" in result.stdout`. |
| **FR-INT-29** : format des bytecodes et sources de référence | `tests/fixtures/bytecode/`, `tests/fixtures/sources/` ; `tests/test_golden_fixtures.py` (docstring) | Huit fichiers `.hex` d'une seule ligne, sans `0x` ni saut de ligne final (vérifié), neuf sources `pragma solidity ^0.8.19;` dont `Ownable.sol` ; la docstring indique solc 0.8.19, `--optimize --optimize-runs 200` « unless noted otherwise ». |
| **FR-INT-30** : test « échec attendu strict » | `tests/test_golden_fixtures.py` — `test_loop_accumulator_value_is_tracked()` | `@pytest.mark.xfail(…, strict=True)` : un succès inattendu fait échouer la suite. |
| **FR-INT-31** : exemples exécutables du filtrage par motifs hors suite | `scobelix/matcher.py` | Bloc `if __name__ == "__main__": doctest.testmod()` ; aucun fichier de `tests/` ne les invoque et `testpaths` se limite à `tests`. |

## 7. Scripts de vérification hérités

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-INT-32** : pipeline Jenkins et script shell hérités, hors contrat | `Jenkinsfile` (étapes `Fetch bytecode & decompile`, `Verify Vyper file`, bloc `post`) ; `decompile_link.sh` | Requête `eth_getCode` par `curl` vers un point d'accès public codé en dur pour une adresse fixe, retrait des couleurs par `sed`, contrôle de non-vacuité, fichier `link_decompilation.vy`, archivé par `archiveArtifacts` dans le pipeline ; aucun fichier du paquet ni des tests n'y fait référence. |

Note contextuelle du document source (scripts trompeurs) : confirmée — l'étape `Verify Vyper file` ne teste que l'existence et la taille du fichier ; `pytest flake8` est installé mais jamais exécuté ; `decompile_link.sh` commence par `cd ~/Documents/Scobelix` et termine par `exit 0` dans les deux branches du test `vyper`.

---

Navigation : [../specification-fonctionnelle/integration.md](../specification-fonctionnelle/integration.md) · [../README.md](../README.md)
