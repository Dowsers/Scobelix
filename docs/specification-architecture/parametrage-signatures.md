# Traçabilité d'architecture — Spécification de paramétrage des bases de signatures de Scobelix

Ce document trace chaque exigence de [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-01** : sélecteur = 4 premiers octets du keccak-256 de la signature canonique, écrit `0x` + 8 chiffres minuscules | `scobelix/tools/build_local_sigs.py` — `compute_selector()`, `signature()` ; `scobelix/utils/supplement.py` — `fetch_sig()` | L'outil calcule `"0x" + bytes(Web3.keccak(text=sig))[:4].hex()` sur `nom(t1,t2)` sans espaces ; la résolution compare à la clé normalisée `"{:#010x}"`, donc minuscule et sur 8 chiffres. |
| **FR-PARAM-02** : entrée = `name` + `inputs` (`type`, `name`) | `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/utils/signatures.py` — `make_abi()` | `find_sig()` lit `a["name"]`, `a["inputs"]` et, pour chaque paramètre, `x["type"]` et `x["name"]` ; `make_abi()` lit `sig["name"]` et `sig["inputs"]`. |

## 2. Fichier de signatures locales

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-03** : objet JSON unique à clés sélecteurs normalisés | `scobelix/utils/supplement.py` — `load_local_sigs_bulk()`, `fetch_sig()` | `json.loads()` du fichier entier ; recherche `if hash in LOCAL_SIGS_BULK` avec la clé normalisée, donc égalité exacte de chaîne. |
| **FR-PARAM-04** : valeur `{name, inputs}`, `inputs` éventuellement vide mais présent | `scobelix/loader.py` — `Loader.find_sig()` | `assert "inputs" in a` avant la mise en forme ; une liste vide produit `nom()`. |
| **FR-PARAM-05** : noms de paramètres éventuellement vides | `scobelix/utils/signatures.py` — `fix_input_names()` ; `scobelix/tools/build_local_sigs.py` — `main()` | Les noms vides sont remplacés par `_param<k>` pour les points d'entrée ; l'outil écrit `param<k>` à défaut de nom. |
| **FR-PARAM-06** : forme produite par l'outil, lecture tolérante | `scobelix/tools/build_local_sigs.py` — `main()` ; `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` | `OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")` : tri à tous les niveaux, `ensure_ascii` par défaut, aucun saut de ligne final ; la lecture par `json.loads()` ignore la mise en forme. Vérifié : le fichier embarqué est identique à `json.dumps(d, indent=2, sort_keys=True)`. |
| **FR-PARAM-07** : document JSON valide dans son ensemble | `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` | Une exception de `json.loads()` fait journaliser `Failed to load local_sigs.json` et remplacer toute la source par `{}`. |

## 3. Dump de signatures compressé

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-08** : archive xz de JSON Lines | `scobelix/utils/supplement.py` — `check_supplements()` | `lzma.open(compressed_supplements)` puis `for line in inf: line = json.loads(line)`. |
| **FR-PARAM-09** : clés `selector` (utilisée telle quelle) et `abi` | `scobelix/utils/supplement.py` — `check_supplements()` | `selector, abi = line["selector"], line["abi"]` puis `out[selector] = abi`, sans normalisation. |
| **FR-PARAM-10** : `abi` avec au minimum `name` et `inputs`, autres champs ignorés | `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/utils/signatures.py` — `make_abi()` | Seuls `name`, `inputs` et, dans chaque paramètre, `type` et `name` sont lus ; les autres clés (`type`, `stateMutability`, `outputs`…) ne sont consultées nulle part. |
| **FR-PARAM-11** : `inputs` obligatoire, sinon échec de la décompilation | `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `assert "inputs" in a` lève `AssertionError` pendant la mise en forme : d'abord dans `Function.print()` appelée par la sérialisation (rattrapée, AST `{}` et `Failed json serialization.`), puis dans le rendu du texte (non rattrapée). Vérifié en bac à sable en substituant à `fetch_sig()` une version qui retire `inputs`. |
| **FR-PARAM-12** : unicité des sélecteurs et des noms non exigée | `scobelix/utils/supplement.py` — `check_supplements()` | Aucun contrôle d'unicité ni de nom à la construction ; l'affectation `out[selector] = abi` d'une clé déjà présente remplace la valeur précédente. Le dump embarqué ne contient aucun sélecteur dupliqué (vérifié). |
| **FR-PARAM-13** : ligne invalide ou incomplète → construction interrompue | `scobelix/utils/supplement.py` — `check_supplements()` | `json.loads()` (`JSONDecodeError`) ou l'accès `line["selector"]`/`line["abi"]` (`KeyError`) lève une exception non rattrapée, propagée par `fetch_sig()` jusqu'à la décompilation en cours. |

Le paragraphe du document source sur l'objet `abi` vide renvoie à un comportement de résolution, porté par le test `if res: return res` de `fetch_sig()` (`scobelix/utils/supplement.py`). Le paragraphe du document source sur la prise en compte d'une modification du dump (suppression manuelle du cache) est confirmé par le test unique `if not abi_path().is_file()` de `check_supplements()`.

Note contextuelle du document source (cache partiel après interruption) : confirmée — `shelve.open()` crée le fichier dès l'ouverture ; vérifié en bac à sable avec un répertoire de cache temporaire (`XDG_CACHE_HOME`) et un dump simulé dont la deuxième ligne est invalide : le fichier subsiste avec la seule première clé et n'est pas reconstruit ensuite.

## 4. Fichiers ABI d'entrée de l'outil de régénération

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-14** : nom `abi*.json`, à toute profondeur | `scobelix/tools/build_local_sigs.py` — `main()` | `root.rglob("abi*.json")` pour chaque racine de `ABI_ROOTS`. |
| **FR-PARAM-15** : JSON lu en UTF-8, octets invalides ignorés, fichier invalide ignoré | `scobelix/tools/build_local_sigs.py` — `load_abi()` | `path.read_text(encoding="utf-8", errors="ignore")` dans un `try` ; toute exception renvoie `[]`, sans message. |
| **FR-PARAM-16** : quatre formes de contenu | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `main()` | Liste → liste ; objet avec `abi` liste → `data["abi"]` ; objet avec `result` objet contenant `abi` liste → `res["abi"]` ; autre objet → renvoyé tel quel et parcouru par `walk_misc_signatures()` ; racine ni liste ni objet → `[]`. |

Note contextuelle du document source (ABI sous forme de chaîne JSON dans `result`) : confirmée — `load_abi()` exige `isinstance(data["result"], dict)` puis `isinstance(res["abi"], list)` ; une chaîne fait retomber sur l'objet entier, dont les chaînes passent par `parse_signature_string()`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-17** : entrées `function` nommées, `inputs` facultatif, `type` et `components` | `scobelix/tools/build_local_sigs.py` — `abi_functions()`, `format_type()` | Filtres `item.get("type") != "function"` et `if not name` ; `inputs = item.get("inputs") or []` ; `format_type()` lit `entry.get("type")` et, pour un `tuple`, `entry.get("components")`. |
| **FR-PARAM-18** : types acceptés, suffixes de tableau, tuples aplatis | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `format_type()` | Suffixes `\[[0-9]*\]$` retirés en boucle ; expressions régulières pour `u?int<M>`, `bytes<1..32>`, `fixed<M>x<N>`, `ufixed<M>x<N>` et liste `address`, `bool`, `string`, `bytes`, `function`, plus `uint`/`int` ; tuple → `f"({inner}){suffix}"`. |
| **FR-PARAM-19** : un type non accepté → fonction ignorée | `scobelix/tools/build_local_sigs.py` — `abi_functions()` | Un `format_type()` nul vide `types` et interrompt la boucle ; `if not types and inputs: continue`. |
| **FR-PARAM-20** : types canoniques recommandés, aucune canonicalisation | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `signature()` | `uint` et `int` sont acceptés et recopiés tels quels dans `signature()` ; aucun code ne les réécrit en `uint256`/`int256`. |

Note contextuelle du document source (composant de tuple non accepté retiré) : confirmée — `",".join(filter(None, (format_type(c) for c in components)))` écarte les composants nuls et `format_type()` ne renvoie `None` que si aucun composant ne reste.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-21** : signatures reconnues dans les chaînes de la forme (d) | `scobelix/tools/build_local_sigs.py` — `parse_signature_string()`, `walk_misc_signatures()`, `main()` | Forme `type:nom` (sans `function` ni `(`) → `f"{name}()"` ; sinon `function\s+nom\s*\(…\)` puis `nom\s*\(…\)`, nom identifiant autre que `function`, paramètres réduits à `raw.strip().split(" ")[0]` ; `main()` rejette la signature si l'un des types échoue à `is_supported_type()`, ce qui écarte les tuples entre parenthèses. |

## 5. Table interne (hors paramétrage)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-22** : même schéma, partie du système | `scobelix/utils/supplement.py` — `LOCAL_SIGS` | Littéral du module dont toutes les valeurs portent `name` et `inputs` (vérifié par évaluation du littéral) ; il n'est lu dans aucun fichier externe. |

---

Navigation : [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) · [../README.md](../README.md)
