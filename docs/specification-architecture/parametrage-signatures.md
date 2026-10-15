# Traçabilité d'architecture — Spécification de paramétrage des bases de signatures de Scobelix

Ce document trace chaque exigence de [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-01** : sélecteur, topic0 et forme des clés | `scobelix/utils/sigdb.py` — `function_selector()`, `event_topic()`, `_key_int()` ; `scobelix/tools/build_local_sigs.py` — `compute_selector()` | `function_selector()` prend les 4 premiers octets de `keccak256(signature)`, `event_topic()` le haché entier ; `_key_int(value, 4)` lit une clé textuelle par `int(value, 16)` (préfixe `0x` et casse acceptés) et refuse une valeur hors de 4 octets ; l'outil écrit `"0x" + digest.hex()`, soit 8 chiffres minuscules. |
| **FR-PARAM-02** : signature canonique, types acceptés et alias | `scobelix/utils/sigdb.py` — `_IDENTIFIER`, `_canonical_elementary()`, `_ELEMENTARY_ALIASES`, `_type_info()`, `_split_types()`, `_parse_params()`, `canonical_signature()` | `_IDENTIFIER` vaut `[A-Za-z_$][A-Za-z0-9_$]*` ; `_canonical_elementary()` accepte les scalaires, `u?int<M>` (M multiple de 8, au plus 256), `bytes<1..32>`, `u?fixed<M>x<N>` (N au plus 80) et remplace les alias de `_ELEMENTARY_ALIASES` ; `_type_info()` retire les suffixes `_ARRAY_SUFFIX`, reconnaît `tuple` (composants exigés par `_parse_params()`) et les tuples écrits développés, découpés par `_split_types()`. |
| **FR-PARAM-03** : schéma d'une entrée | `scobelix/utils/sigdb.py` — `_make_entry()`, `_parse_params()` | `_make_entry()` lit `abi.get("name")` et `abi.get("inputs", [])` ; `_parse_params()` exige une liste d'objets à `type` textuel, garde `p.get("name") or ""`, les `components` d'un tuple et, pour un événement, `bool(p.get("indexed"))` ; les rejets suivent `_Rejected` et `_fill()` (voir [resolution-signatures.md](resolution-signatures.md), FR-SIG-03). |

## 2. Fichier de signatures locales

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-04** : objet JSON de sélecteurs vers entrées de fonctions | `scobelix/utils/sigdb.py` — `_read_selector_json()`, `_read_selector_table()`, `_make_entry()` | `json.loads()` du fichier entier lu en UTF-8 ; chaque paire donne `(valeur, FUNCTION, _key_int(clé, 4))` ; comme la nature est `function`, `_make_entry()` exploite aussi `outputs` et `stateMutability` s'ils sont présents. |
| **FR-PARAM-05** : noms vides ou synthétiques | `scobelix/utils/sigdb.py` — `_is_generic()`, `_representative()`, `_NAMES_PRIORITY` ; `scobelix/utils/signatures.py` — `fix_input_names()` ; `scobelix/tools/build_local_sigs.py` — `main()` | `_GENERIC_NAME` reconnaît `param<k>` et le vide ; `_NAMES_PRIORITY` place la source locale en dernier et `_representative()` préfère un membre aux noms non génériques ; `fix_input_names()` remplace un nom vide à l'affichage d'un point d'entrée ; l'outil écrit `param<k>` à défaut de nom. |
| **FR-PARAM-06** : forme produite par l'outil, lecture tolérante | `scobelix/tools/build_local_sigs.py` — `main()` ; `scobelix/utils/sigdb.py` — `_read_selector_json()` | `OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")` : tri à tous les niveaux, `ensure_ascii` par défaut, aucun saut de ligne final ; la lecture par `json.loads()` ignore la mise en forme. |
| **FR-PARAM-07** : document JSON valide dans son ensemble, fichier facultatif | `scobelix/utils/sigdb.py` — `_fill()`, `_read_selector_json()`, `_open_default()` | `_fill()` appelle le lecteur hors du `try` propre à chaque entrée : une `JSONDecodeError` interrompt `build()`, et `_open_default()` rend la base indisponible ; un fichier absent est seulement signalé (`signature source local not found`). Vérifié en bac à sable avec un fichier réduit à `{`. |
| **FR-PARAM-08** : clé égale au sélecteur de la signature canonique | `scobelix/utils/sigdb.py` — `_make_entry()` | La signature est recomposée avec les types canoniques (`uint` devient `uint256`) avant le hachage ; une clé calculée sur `k(uint)` lève `_Rejected("keccak-mismatch")` (vérifié en bac à sable). |

## 3. Fichier de signatures organisées

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-09** : objet JSON à clé `abi` | `scobelix/utils/sigdb.py` — `_read_curated()`, `data_hash()`, `_fill()` | `_read_curated()` renvoie `json.loads(…)["abi"]` : une `JSONDecodeError` ou une `KeyError` s'y produit hors du `try` des entrées et interrompt `build()` ; les autres clés ne sont lues que par `data_hash()`, qui hache le fichier entier. Vérifié en bac à sable (JSON invalide, clé `abi` absente). |
| **FR-PARAM-10** : nature de chaque entrée | `scobelix/utils/sigdb.py` — `_read_curated()`, `_fill()` | Le décodeur lit `abi["type"]` (`KeyError` comptée `malformed`) et renvoie `None` hors de `KINDS`, que `_fill()` saute sans compter ; la clé attendue vaut `None`. |
| **FR-PARAM-11** : types de retour, mutabilité, drapeaux d'événement | `scobelix/utils/sigdb.py` — `_mutability()`, `_make_entry()`, `_parse_params()` | `_make_entry()` analyse `abi["outputs"]` par `_parse_params()`, qui lève `_Rejected("bad-params")` pour une valeur qui n'est pas une liste ; `_mutability()` lit `stateMutability`, `constant` et `payable` ; `indexed` et `anonymous` sont convertis en booléens ; `_parse_params()` ne conserve aucun autre champ. |
| **FR-PARAM-12** : types ABI exigés pour un événement ou une erreur | `scobelix/utils/sigdb.py` — `_make_entry()` | `library = canon is None` ; `if library and kind not in (FUNCTION, None): raise _Rejected("bad-params")`. |

## 4. Dump de signatures compressé

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-13** : archive xz de JSON Lines en UTF-8 | `scobelix/utils/sigdb.py` — `_read_dump()` | `lzma.open(str(path), "rt", encoding="utf-8")`, lu ligne par ligne. |
| **FR-PARAM-14** : clés `selector` et `abi`, nature, événements sous le préfixe du topic0 | `scobelix/utils/sigdb.py` — `_read_dump()`, `_make_entry()` | `d = json.loads(line)`, `abi = d["abi"]`, nature `abi.get("type")` gardée si elle est dans `KINDS`, sinon `None` ; clé `_key_int(d["selector"], 4)` comparée aux 4 premiers octets du haché, y compris pour un événement dont la clé stockée est le haché entier. |
| **FR-PARAM-15** : `inputs` facultatif, champs exploités | `scobelix/utils/sigdb.py` — `_make_entry()` | `abi.get("inputs", [])` ; pour une nature `None`, une liste d'un seul paramètre de type `""` devient `[]` ; `outputs` et la mutabilité ne sont lus que si la nature est donnée (`kind is not None`). |
| **FR-PARAM-16** : ligne invalide ignorée et comptée | `scobelix/utils/sigdb.py` — `_fill()` | Le décodage a lieu dans le `try` de chaque entrée : `KeyError`, `TypeError`, `ValueError` (dont `JSONDecodeError`) et `AttributeError` sont comptées `malformed` (vérifié en bac à sable : deux lignes invalides, construction achevée). |
| **FR-PARAM-17** : substituts, noms invalides, hachés faux ignorés | `scobelix/utils/sigdb.py` — `_read_dump()`, `_make_entry()` | `_read_dump()` reconnaît sans analyse JSON une ligne `"name": "unknown<sélecteur>"` ; `_make_entry()` lève `placeholder`, `bad-name` (un objet `{}` n'a pas de nom) ou `keccak-mismatch`. |
| **FR-PARAM-18** : unicité des clés valides par espace de noms | `scobelix/utils/sigdb.py` — `_fill()`, `_row()`, `_SCHEMA_SQL` | Une entrée du dump dont la clé est absente des petites sources est insérée directement au rang 0 ; une seconde entrée valide de même clé viole `PRIMARY KEY (selector, rank)` ou `(topic0, rank)` et lève `sqlite3.IntegrityError`. Vérifié en bac à sable : échec avec deux lignes identiques, succès quand la table interne porte aussi la clé. |
| **FR-PARAM-19** : archive complète et lisible | `scobelix/utils/sigdb.py` — `_read_dump()`, `_fill()` | Le générateur de lignes est parcouru par la boucle `for item in items`, hors du `try` des entrées : `EOFError` ou `lzma.LZMAError` interrompt `build()` (`tests/test_sigdb.py::test_damaged_bundled_data_leaves_lookups_empty`). |

Note contextuelle du document source (dump livré sans clé répétée, prise en compte des modifications) : confirmée — la base `sigdb-2-22573342bc08ca5b.sqlite` est construite à partir du dump livré ; `data_hash()` hache les octets du dump, et `build()` remplace la base par `os.replace()`.

## 5. Fichiers ABI d'entrée de l'outil de régénération

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-20** : nom `abi*.json`, à toute profondeur | `scobelix/tools/build_local_sigs.py` — `main()` | `root.rglob("abi*.json")` pour chaque racine de `ABI_ROOTS`. |
| **FR-PARAM-21** : JSON lu en UTF-8, octets invalides ignorés, fichier invalide ignoré | `scobelix/tools/build_local_sigs.py` — `load_abi()` | `path.read_text(encoding="utf-8", errors="ignore")` dans un `try` ; toute exception renvoie `[]`, sans message. |
| **FR-PARAM-22** : quatre formes de contenu | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `main()` | Liste → liste ; objet avec `abi` liste → `data["abi"]` ; objet avec `result` objet contenant `abi` liste → `res["abi"]` ; autre objet → renvoyé tel quel et parcouru par `walk_misc_signatures()` ; racine ni liste ni objet → `[]`. |

Note contextuelle du document source (ABI sous forme de chaîne JSON dans `result`) : confirmée — `load_abi()` exige `isinstance(data["result"], dict)` puis `isinstance(res["abi"], list)` ; une chaîne fait retomber sur l'objet entier, dont les chaînes passent par `parse_signature_string()`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-23** : entrées `function` nommées, `inputs` facultatif, `type` et `components` | `scobelix/tools/build_local_sigs.py` — `abi_functions()`, `format_type()` | Filtres `item.get("type") != "function"` et `if not name` ; `inputs = item.get("inputs") or []` ; `format_type()` lit `entry.get("type")` et, pour un `tuple`, `entry.get("components")`. |
| **FR-PARAM-24** : types acceptés par l'outil, suffixes de tableau, tuples aplatis | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `format_type()` | Suffixes `\[[0-9]*\]$` retirés en boucle ; expressions régulières pour `u?int<M>`, `bytes<1..32>`, `fixed<M>x<N>`, `ufixed<M>x<N>` (N de 1 à 32) et liste `address`, `bool`, `string`, `bytes`, `function`, plus `uint`/`int` ; tuple → `f"({inner}){suffix}"`. |
| **FR-PARAM-25** : un type non accepté → fonction ignorée | `scobelix/tools/build_local_sigs.py` — `abi_functions()` | Un `format_type()` nul vide `types` et interrompt la boucle ; `if not types and inputs: continue`. |
| **FR-PARAM-26** : types canoniques recommandés, rejet à la construction | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `signature()`, `compute_selector()` ; `scobelix/utils/sigdb.py` — `_make_entry()` | `uint` et `int` sont acceptés et recopiés tels quels dans `signature()`, dont `compute_selector()` hache la forme écrite ; `_make_entry()` hache la forme canonique et rejette l'entrée (`keccak-mismatch`). |

Note contextuelle du document source (composant de tuple non accepté retiré) : confirmée — `",".join(filter(None, (format_type(c) for c in components)))` écarte les composants nuls et `format_type()` ne renvoie `None` que si aucun composant ne reste ; `main()` enregistre pour chaque paramètre le même type aplati (`format_type(inp)`), si bien que `_make_entry()` recompose la signature réduite et la trouve cohérente avec sa clé.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-27** : signatures reconnues dans les chaînes de la forme (d) | `scobelix/tools/build_local_sigs.py` — `parse_signature_string()`, `walk_misc_signatures()`, `main()` | Forme `type:nom` (sans `function` ni `(`) → `f"{name}()"` ; sinon `function\s+nom\s*\(…\)` puis `nom\s*\(…\)`, nom identifiant autre que `function`, paramètres réduits à `raw.strip().split(" ")[0]` ; `main()` rejette la signature si l'un des types échoue à `is_supported_type()`, ce qui écarte les tuples entre parenthèses. |

## 6. Fichier de base de signatures

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-28** : base fournie construite, schéma et marque d'achèvement | `scobelix/utils/sigdb.py` — `ensure_built()`, `_is_complete()`, `_check_replaceable()`, `SigDB` | `ensure_built()` renvoie le chemin tel quel si `_is_complete()` trouve `schema` égal à `SCHEMA_VERSION` et `complete` égal à `"1"` dans `meta` ; sinon `_check_replaceable()` admet une base pourvue de `meta` ou un fichier vide, que `build()` remplace ; le constructeur de `SigDB` refuse un autre schéma (`ValueError`). |
| **FR-PARAM-29** : aucun autre fichier à cet emplacement | `scobelix/utils/sigdb.py` — `_check_replaceable()`, `_has_meta_table()`, `_open_default()` | Refus `FileExistsError` avant toute création de fichier ; `_open_default()` journalise l'indisponibilité et renvoie `None` (`tests/test_sigdb.py::test_a_file_that_is_no_database_is_never_replaced`). |

## 7. Table interne (hors paramétrage)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-PARAM-30** : même schéma que le fichier local, partie du système | `scobelix/utils/supplement.py` — `LOCAL_SIGS` ; `scobelix/utils/sigdb.py` — `default_sources()`, `_read_selector_table()` | Littéral du module, lu par le même `_read_selector_table()` que le fichier local, donc soumis aux mêmes vérifications ; il n'est lu dans aucun fichier externe ; `tests/test_sigdb.py::test_bundled_small_sources_are_consistent` vérifie qu'aucune de ses 121 entrées n'est rejetée. |

---

Navigation : [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md) · [../README.md](../README.md)
