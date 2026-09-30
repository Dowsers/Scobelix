# Traçabilité d'architecture — Résolution des signatures 4 octets et régénération de la base locale

Ce document trace chaque exigence de [../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble

Section introductive sans exigence numérotée : la résolution est portée par `fetch_sig()` (`scobelix/utils/supplement.py`), appelée d'une part par `make_abi()` (`scobelix/utils/signatures.py`) pour les points d'entrée, d'autre part par `Loader.find_sig()` (`scobelix/loader.py`) pour l'affichage des constantes ; l'outil de régénération est `scobelix/tools/build_local_sigs.py`.

## 2. Sources de signatures et précédence

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SIG-01** : normalisation `0x` + au moins 8 chiffres minuscules | `scobelix/utils/supplement.py` — `fetch_sig()` | `if type(hash) == str: hash = int(hash, 16)` puis `hash = "{:#010x}".format(hash)` : complétion par des zéros à 8 chiffres, écriture plus longue au-delà de 32 bits. |
| **FR-SIG-02** : ordre table interne → cache disque → fichier local | `scobelix/utils/supplement.py` — `fetch_sig()`, `LOCAL_SIGS` | `if hash in LOCAL_SIGS` ; sinon `shelve.open(str(abi_path()))` et `s.get(hash)` ; sinon `load_local_sigs_bulk()` puis `LOCAL_SIGS_BULK` ; sinon `None`. La table compte 123 clés littérales pour 121 sélecteurs distincts (comptage du 2026-09-29). |
| **FR-SIG-03** : entrée vide du cache = absence | `scobelix/utils/supplement.py` — `fetch_sig()` | `res = s.get(hash); if res: return res` : un objet vide est faux et la recherche continue. |
| **FR-SIG-04** : mémorisation par valeur d'argument, aucune source en ligne | `scobelix/utils/supplement.py` — `fetch_sig()` ; `scobelix/utils/helpers.py` — `cached()` ; `scobelix/loader.py` — `Loader.find_sig()` | `fetch_sig()` est décorée par `@cached` (clé = arguments tels que passés, chaîne ou entier) ; `Loader.find_sig()` mémorise en plus le nom formaté dans `cache_sigs[add_color]`. Aucune de ces fonctions n'effectue de requête réseau. |
| **FR-SIG-05** : fichier local chargé une fois, absence ou erreur → source vide | `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` | `if LOCAL_SIGS_BULK is not None: return` ; `is_file()` faux → `{}` ; exception de lecture ou de décodage → `logger.exception("Failed to load local_sigs.json")` et `{}`. |
| **FR-SIG-06** : table interne partie du système | `scobelix/utils/supplement.py` — `LOCAL_SIGS` | Dictionnaire littéral du module : il ne peut changer qu'avec le code. |

Note contextuelle du document source (deux sélecteurs définis deux fois) : confirmée — `0x6e553f65` et `0x2e1a7d4d` apparaissent deux fois dans le littéral `LOCAL_SIGS` ; l'évaluation Python d'un dictionnaire littéral conserve la dernière valeur (`deposit(uint256 value, address addr)`, `withdraw(uint256 value)`), vérifié par évaluation du littéral.

## 3. Cache disque de signatures

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SIG-07** : dump interrogé via une base clé-valeur sur disque | `scobelix/utils/supplement.py` — `abi_path()`, `fetch_sig()` | `abi_path()` renvoie `cache_dir() / "abi_db.shelve"`, ouvert par `shelve.open()` à chaque recherche non mémorisée. |
| **FR-SIG-08** : construction à la première recherche, décompression intégrale, dernière ligne gagnante | `scobelix/utils/supplement.py` — `check_supplements()`, `fetch_sig()` | `fetch_sig()` appelle `check_supplements()` avant même la table interne ; si le fichier n'existe pas : `lzma.open(abi_dump.xz)` lu ligne par ligne, `out[selector] = abi` avec la clé telle qu'écrite (une clé répétée est réécrite). |
| **FR-SIG-09** : journalisation INFO début et fin | `scobelix/utils/supplement.py` — `check_supplements()` | `logger.info("Loading %s into %s...", …)` puis `logger.info("%s is ready.", abi_path())`. Coût ponctuel : décompression de l'intégralité du dump (296,4 Mio de texte à la date de rédaction). |
| **FR-SIG-10** : existence vérifiée, jamais invalidé | `scobelix/utils/supplement.py` — `check_supplements()` | Le seul test est `if not abi_path().is_file()` : aucune comparaison de date, de taille ni de version avec le dump embarqué. |

## 4. Nommage des fonctions et de leurs paramètres

### 4.1 Points d'entrée

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SIG-11** : sélecteur résolu → `nom(type nom, …)` et nom ABI | `scobelix/utils/signatures.py` — `make_abi()`, `fix_input_names()`, `get_func_name()`, `get_abi_name()` | `make_abi()` stocke `{"name": sig["name"], "inputs": fix_input_names(sig["inputs"])}` ; `fix_input_names()` remplace un nom vide par `f"_param{i+1}"` ; `get_func_name()` joint `type nom` par `, ` et `get_abi_name()` les types par `,`. |
| **FR-SIG-12** : sélecteur non résolu → `unknown<sélecteur>` | `scobelix/utils/signatures.py` — `make_abi()` ; `scobelix/function.py` — `Function.make_names()` | Valeur initiale `{"name": "unknown" + h[2:]}` conservée si `fetch_sig()` échoue ; `Function.__init__()` appelle `make_names()` lorsque le nom contient `unknown`. |
| **FR-SIG-13** : identifiant non hexadécimal utilisé tel quel, suivi de `(?)` | `scobelix/utils/signatures.py` — `make_abi()`, `get_func_name()` | Branche `else` (`h` ne commençant pas par `0x`) : `{"name": h}` sans `inputs` ; `get_func_name()` renvoie alors `"{}(?)".format(a["name"])`. |

Note contextuelle du document source (remplacement dans l'entrée mémorisée partagée) : confirmée — `fix_input_names()` modifie en place la liste `inputs` du dictionnaire renvoyé par `fetch_sig()`, lequel est l'objet mémorisé par `@cached`.

### 4.2 Constantes rencontrées dans le code

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SIG-14** : constantes d'au moins 6 chiffres, trois essais | `scobelix/prettify.py` — `try_fname()` ; `scobelix/loader.py` — `Loader.find_sig()` | Essais `hex(exp)[:10]`, puis si `len(hex(exp)) >= 63` `padded_hex(exp, 64)[:10]`, puis si `len(hex(exp)) >= 8` `padded_hex(exp, 8)[:10]` ; `find_sig()` rejette les clés de moins de 8 caractères (`0x` + 6 chiffres) et celles qui contiennent `???` (forme renvoyée par `padded_hex()` pour une valeur trop longue). |
| **FR-SIG-15** : règles numériques prioritaires non recherchées | `scobelix/prettify.py` — `prettify()`, `pretty_num()` | Les durées sont transformées en produits dans `prettify()` avant `pretty_num()` ; dans `pretty_num()`, les tests `exp > 8**50` et puissances de dix retournent avant l'appel à `try_fname()`. |
| **FR-SIG-16** : constante résolue affichée comme signature, quel que soit le nom | `scobelix/prettify.py` — `pretty_num()` ; `scobelix/loader.py` — `Loader.find_sig()` | `if try_fname(exp, add_color) != None: return try_fname(exp, add_color)`, sans filtrage du nom ; `find_sig()` formate `nom(type nom, …)` avec `colorize(x["type"], …) + " " + x["name"]`, d'où un type suivi d'une espace si le nom est vide. |
| **FR-SIG-17** : sujets de journal et fragments d'appel, exclusion des noms contenant `unknown_` | `scobelix/prettify.py` — `pretty_fname()`, `pretty_line()` | `pretty_fname()` renvoie la signature si `fname and "unknown_" not in fname`, sinon `hex(exp)` ; pour les journaux, `pretty_line()` tronque à `x[:10]` toute valeur commençant par `0x`. |

Note contextuelle du document source (coïncidences numériques, noms synthétiques non filtrés) : confirmée — 391 351 lignes du dump portent un nom commençant par `unknown` sans tiret bas, aucune ne contient `unknown_` (comptage du 2026-09-29) ; vérifié en bac à sable : `pretty_num(0x100000)` rend `unknown00100000(uint256 _param1)`.

## 5. Outil de régénération de la base locale

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SIG-18** : parcours récursif des répertoires de `SCOBELIX_ABI_ROOTS` | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `main()` | `[Path(p) for p in _abi_roots_env.split(":") if p]` puis `root.rglob("abi*.json")`. |
| **FR-SIG-19** : répertoire inexistant → avertissement sur la sortie standard | `scobelix/tools/build_local_sigs.py` — `main()` | `print(f"warning: {root} does not exist, skipping")` puis `continue`. |
| **FR-SIG-20** : dédoublonnage par chemin résolu, ordre lexicographique | `scobelix/tools/build_local_sigs.py` — `main()` | `abi_paths = sorted({p.resolve() for p in abi_paths})`. |
| **FR-SIG-21** : extraction des signatures, silence sur les non-conformités | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `abi_functions()`, `walk_misc_signatures()`, `signature()` | `load_abi()` renvoie une liste ABI ou l'objet brut ; `abi_functions()` filtre les entrées ; `walk_misc_signatures()` analyse les chaînes ; `signature()` produit `f"{name}({','.join(types)})"`. Aucun de ces chemins n'imprime de message. |
| **FR-SIG-22** : première occurrence d'une signature, noms `param<k>` à défaut | `scobelix/tools/build_local_sigs.py` — `main()` | `if sig not in sig_inputs` ; `n = inp.get("name") or f"param{idx+1}"` (forme ABI) ; `{"type": t, "name": f"param{idx+1}"}` (forme texte). |
| **FR-SIG-23** : sélecteur calculé localement | `scobelix/tools/build_local_sigs.py` — `compute_selector()` | `bytes(Web3.keccak(text=sig))[:4]`, sans sous-processus ; `tests/test_build_local_sigs.py` le compare à trois sélecteurs publiés. |
| **FR-SIG-24** : première signature par sélecteur, collisions comptées | `scobelix/tools/build_local_sigs.py` — `main()` | `if selector in out: if out[selector]["name"] != name: conflicts += 1; continue`. |
| **FR-SIG-25** : écriture complète à `SCOBELIX_SIGS_OUT`, répertoire créé | `scobelix/tools/build_local_sigs.py` — `OUT_PATH`, `main()` | Défaut `REPO_ROOT / "scobelix" / "data" / "local_sigs.json"` (`REPO_ROOT` = parent du paquet, donc le fichier embarqué) ; `OUT_PATH.parent.mkdir(parents=True, exist_ok=True)` puis `write_text(json.dumps(out, indent=2, sort_keys=True))`. |
| **FR-SIG-26** : message récapitulatif | `scobelix/tools/build_local_sigs.py` — `main()` | `print(f"wrote {OUT_PATH} with {len(out)} signatures ({conflicts} conflicts skipped)")`. |
| **FR-SIG-27** : fichier régénéré pris en compte au démarrage suivant, emplacement par défaut seulement | `scobelix/utils/supplement.py` — `LOCAL_SIGS_BULK_PATH`, `load_local_sigs_bulk()` | La décompilation ne lit que `Path(__file__).parent.parent / "data" / "local_sigs.json"`, une fois par processus ; `SCOBELIX_SIGS_OUT` n'est lue que par l'outil. |

---

Navigation : [../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md) · [../README.md](../README.md)
