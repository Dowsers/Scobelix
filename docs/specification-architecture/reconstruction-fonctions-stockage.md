# Traçabilité d'architecture — Reconstruction des fonctions, des paramètres et de la structure du stockage

Ce document trace chaque exigence de [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement. « Vérifié en bac à sable » signale un comportement constaté en décompilant un bytecode de `tests/fixtures/bytecode/`.

## 1. Vue d'ensemble

Section introductive sans exigence numérotée : la caractérisation fonction par fonction est portée par le constructeur de `Function` (`scobelix/function.py`), qui garde la trace exacte dans `orig_trace` et travaille sur la trace d'affichage `trace` ; l'inférence des paramètres lit `orig_trace` (`Function.make_params()`) ; la reconstruction du stockage au niveau du contrat est portée par `Contract.postprocess()` (`scobelix/contract.py`), qui appelle `rewrite_functions()` (`scobelix/sparser.py`) une seule fois sur les `trace` de toutes les fonctions. Aucune de ces étapes n'écrit `orig_trace`.

## 2. Caractérisation d'une fonction

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-01** : non payable par test de `callvalue` en tête, ou par test remonté du dispatcher | `scobelix/function.py` — `Function.analyse()`, `_memory_seed_length()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `k = _memory_seed_length(self.trace)` saute les `setmem` initiaux ; si `self.trace[k]` est un `if` dont `simplify_bool(cond)` vaut `callvalue` et dont la branche vraie commence par `("revert", None)` ou `invalid` (ou l'inverse pour `iszero(callvalue)`), `self.trace = self.trace[:k] + autre branche` et `payable = False` ; sinon `payable = not self.callvalue_guarded`, valeur passée par le décompilateur (`hash in callvalue_guarded`). Vérifié en bac à sable : dans `DispatchBoth`, `b()` est payable et `a()`, `s()` ne le sont pas ; dans `DispatchAllNonPayable`, aucune fonction ne l'est. |
| **FR-STOR-02** : lecture seule par recherche textuelle | `scobelix/function.py` — `Function.analyse()`, `STATE_CHANGING_OPS` | `for op in STATE_CHANGING_OPS: if f"'{op}'" in str(self.trace): self.read_only = False`, la liste valant `store`, `tstore`, `selfdestruct`, `call`, `delegatecall`, `callcode`, `create`, `create2`, `log` ; les guillemets écartent `staticcall`. Vérifié en bac à sable : `ping()` de `FunctionTraits`, qui émet un événement, n'est pas en lecture seule ; `stamp()` et `ownBalance()` le sont. |
| **FR-STOR-03** : constante | `scobelix/function.py` — `Function.analyse()`, `is_constant()`, `PURE_OPS` | `body = self.trace[k:]` ; `self.const = body[0]` si la fonction est en lecture seule, `len(body) == 1`, `body[0]` est `("return", val)` avec `val` non `None` et `is_constant(val)` (entier, ou tête de `PURE_OPS` sur des constantes) ; `_print()` affiche `val`. Vérifié en bac à sable : `fortyTwo()` de `FunctionTraits` donne `const = ("return", 42)`, `ping()`, qui retourne aussi 42, n'est pas constante. |
| **FR-STOR-04** : getter | `scobelix/function.py` — `Function.analyse()` | Pour une fonction non constante, en lecture seule, à retour unique : `bool(storage)`, `mask_shl(…, storage)` (on retient la lecture), `storage`, ou `data` dont tous les termes lisent le même emplacement ou `add(k, loc)`, ou des `sha3` portant le même emplacement (< 1000), qui donne `("struct", ("loc", loc))`. Vérifié en bac à sable : `total()` de `FunctionTraits` a pour getter `("storage", 256, 0, 0)`. |
| **FR-STOR-05** : getter de chaîne, copie repliée dans la trace d'affichage | `scobelix/function.py` — `Function.find_string_getter()`, `fold_string_copies()`, `STRING_COPY_RETURN` | `find_string_getter()` exige la lecture seule, au moins un retour et le motif `STRING_COPY_RETURN` sur le même `loc` pour tous, et rend `("storage", 256, 0, ("array", ("range", 0, ("storage", 256, 0, ("length", loc))), loc))` ; `fold_string_copies()` remplace par `("return", getter)` les blocs de `setmem`/`setvar`/`while` terminés par ce retour, récursivement dans les `if`. Vérifié en bac à sable : `labelChecked()` de `FunctionTraitsLegacy` est un getter de chaîne dont la trace d'affichage garde son `require`. |
| **FR-STOR-06** : fonction régulière | `scobelix/function.py` — `Function.__init__()` | `self.is_regular = self.const is None and self.getter is None`. |
| **FR-STOR-07** : ordre d'affichage | `scobelix/function.py` — `Function.priority()`, `Function.ast_length()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `priority()` renvoie −1 si `"selfdestruct"` figure dans la trace, sinon la longueur en caractères du texte rendu ; `func_list.sort(key=lambda f: f.priority())`. |

## 3. Inférence des paramètres

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-08** : signature connue → décalages 4 + 32k | `scobelix/function.py` — `Function.make_params()` | `params = get_func_params(self.hash)` ; si non vide, `res[idx] = (p["type"], p["name"])` avec `idx` partant de 4 par pas de 32. |
| **FR-STOR-09** : inférence sur la trace exacte, sources par ordre de force | `scobelix/function.py` — `Function.make_params()`, `infer_params()` | `make_params()` appelle `infer_params(self.orig_trace, self.abi_coder_v2)`, dont la docstring énumère les sources ; `_is_head_word()` reconnaît les décalages 4 + 32j. |
| **FR-STOR-10** : contrôles du décodeur = gardes de rejet sans données en tête | `scobelix/function.py` — `_prologue_conditions()`, `_revert_condition()`, `BARE_REVERT` | `_prologue_conditions()` saute les `setmem`, puis ajoute la condition de rejet de chaque `if` dont une branche vaut `[("revert", None)]` ou de chaque `("require", cond, ("revert", None))`, en continuant dans l'autre branche, jusqu'à la première autre ligne. |
| **FR-STOR-11** : nombre de mots de tête, mots non lus en `uint256` | `scobelix/function.py` — `infer_params()`, `MAX_HEAD_WORDS` | Motif `(op, ("add", -4, "calldatasize"), k)` avec `op` dans `("slt", "lt")`, `k % 32 == 0` et `0 <= k <= 32 * MAX_HEAD_WORDS` (1 024) → `heads = k // 32` ; en fin de calcul, `kinds.setdefault(4 + 32 * j, "uint256")` pour chaque `j < heads`. |
| **FR-STOR-12** : contrôles de validation de type | `scobelix/function.py` — `_validator()`, `_cleaned_type()`, `_uint_type()`, `_indexes_storage()` | `_validator()` dépouille `iszero(iszero(·))`, `bool(·)` et `mul(-1, ·)`, puis reconnaît `iszero(eq(P, nettoyage))` et `add(a, mul(-1, b))` via `_cleaned_type()` (P → `uint256`, `bool`, masque bas → `_uint_type()`, masque haut → `bytesN`, `signextend` → `intN`), `mask_shl(256 - N, N, 0, P)` → `_uint_type(N)`, et `ge(P, K)` / `le(K, P)` → `uint8` sans drapeau v2 ; `infer_params()` écarte ce dernier si `_indexes_storage(trace, idx)`. |
| **FR-STOR-13** : paramètres dynamiques par les bornes du décodeur | `scobelix/function.py` — `_dynamic_check()`, `WORD_MAX` | `gt(P, K)` avec `K` dans `(WORD_MAX, 2**32)` → `array` ; `gt(add(36, P, len), calldatasize)` → `bytes` si `len` est la longueur `cd(4 + P)`, `array` si c'est 32 fois cette longueur ; `infer_params()` ne laisse `array` remplacer aucune entrée existante. |
| **FR-STOR-14** : indices à l'usage | `scobelix/function.py` — `infer_params()` (`f()`, `narrower()`) | `find_f_list(trace, f)` collecte les `mask_shl(…, cd)`, `cd`, `signextend(b, cd)` et `call.data(add(36, cd(i)), len)` ; la boucle applique les règles du document (taille 256 pour une largeur non entière, un `shl` négatif ou un débordement à gauche ; `used[idx]` pour `bytesN`/`intN` ; `("add", 4, ("cd", i))` ou une somme portant un seul mot de tête → `array` ; décalage non entier ignoré), et `narrower()` retient la largeur la plus étroite, une nature dynamique l'emportant. |
| **FR-STOR-15** : décalage non aligné → avertissement et aucun paramètre | `scobelix/function.py` — `infer_params()` | `if not _is_head_word(idx): logger.warning("unusual cd (not aligned)"); return {}` après avoir écarté `idx == 0`. |
| **FR-STOR-16** : ordre de choix du type | `scobelix/function.py` — `infer_params()`, `has_validators()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/core/masks.py` — `mask_to_type()` | Cascade `validated` → `type(size) == str` → `coder_v2` (`uint256`) → `used[idx]` si `type_to_mask(used[idx]) <= size` → `bool` si tous les parents sont `bool`/`if`/`iszero` → `_uint_type(size)` (`mask_to_type(size, force=True)` hors multiples de 8) ; `coder_v2` vaut l'argument `abi_coder_v2` (`any(has_validators(trace) …)` sur tout le contrat) ou un validateur v2 de la fonction ; `kinds.setdefault()` ajoute les mots seulement validés. Vérifié en bac à sable sur `ParamTypes` : `bytes`, `int16`, `address`, `bool`, `array` et la paire `uint256`, `uint8`. |
| **FR-STOR-17** : noms `_param1`, `_param2`… | `scobelix/function.py` — `infer_params()` | `for count, idx in enumerate(sorted(kinds), 1)` avec `f"_param{count}"`. |
| **FR-STOR-18** : nom complété pour un sélecteur non résolu | `scobelix/function.py` — `Function.make_names()` | Appelée si `"unknown" in self.name` ; construit `nom(type _paramN, …)` (nom affiché et nom coloré) et `nom(type,…)` (nom ABI). Vérifié en bac à sable : `unknown33b6fbf1(uint256 _param1, uint8 _param2)`. |
| **FR-STOR-19** : masques redondants retirés, lectures remplacées par `param` | `scobelix/function.py` — `Function.cleanup_masks()` ; `scobelix/contract.py` — `Contract.postprocess()` | `cleanup_masks(self.trace)` supprime `bool(cd)` d'un paramètre `bool` et `mask_shl(size, 0, 0, cd)` si `size == type_to_mask(kind)` ; `postprocess()` applique `replace_names` à `func.trace` : `("cd", idx)` → `("param", nom)` pour chaque `idx` de `inferred_params`. |

Note contextuelle du document source (types indécidables par nature) : confirmée — `infer_params()` ne dispose que des contrôles du décodeur et des usages ; vérifié en bac à sable : le paramètre `bytes` de `qpData` (sélecteur `0x2a36c4c1`) est inféré `bytes` sur `ParamTypes` (solc 0.8.19) et `array` sur `ParamTypesLegacy` (solc 0.5.17, ABI coder v1).

## 4. Reconstruction de la structure du stockage

### 4.1 Collecte et résolution des emplacements

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-20** : collecte de tous les accès, ordre de première apparition, reconstruction unique | `scobelix/sparser.py` — `rewrite_functions()`, `find_stores()`, `_find_stores()` | `find_stores([f.trace for f in functions])` remplit un dictionnaire (ordre d'insertion) des lectures `storage` et des écritures `store` converties en `("storage", size, off, idx)`, puis un seul appel `_sparser_resilient(storages)`. |
| **FR-STOR-21** : constantes proches d'un haché keccak, table des mappings | `scobelix/sparser.py` — `rainbow_sha3()`, `_keccak_slots()`, `KECCAK_SLOTS`, `KECCAK_SPAN`, `sha3_loc_table`, `sha3_loc_values` | `_keccak_slots()` calcule et trie keccak(slot) pour `slot < KECCAK_SLOTS` (4 096) ; `rainbow_sha3()` ignore les valeurs inférieures à 2^64, cherche par `bisect` le haché juste en dessous et juste au-dessus et rend `("loc", slot)` ou `("add", k, ("loc", slot))` si `-KECCAK_SPAN < k < KECCAK_SPAN` (2^24), sinon `sha3_loc_values.get(exp, exp)`, table entière des 20 emplacements et des 40 accès de mapping (clés 0 et 1) ; sans implémentation de keccak, seules les entrées de la table sont utilisées. |
| **FR-STOR-22** : `loc`, `map`, `array` et leurs imbrications | `scobelix/sparser.py` — `_sparser()` | `simplify_sha3()` : `("sha3", N)` → `("loc", N)`, `("sha3", idx, N)` → `("map", idx, ("loc", N))`, haché imbriqué → `map` de `data` ; `add_to_arr()` : `add` avec un `loc` → `("array", idx, loc)` ; `double_map()` traite les mappings imbriqués, les tableaux de mappings et `add(num, sha3(array…))` (tableau de tableaux). |
| **FR-STOR-23** : constante ajoutée → champ décalé de 256 × N bits | `scobelix/sparser.py` — `_sparser()` | `if m := match(idx, ("add", ":int:num", ...))` et un `loc` dans les autres termes : `offset += 256 * m.num`. |
| **FR-STOR-24** : emplacement constant aussi base d'un tableau → `length` | `scobelix/sparser.py` — `_sparser()` | `if type(idx) == int: if str(("loc", idx)) in str(storages): idx = ("length", ("loc", idx)) else: idx = ("loc", idx)`. |
| **FR-STOR-25** : forme `stor`, réécriture des traces, accès non résolus | `scobelix/sparser.py` — `_sparser()`, `repl_stor()` | Les accès sont exprimés `("stor", size, offset, idx)` ; `repl_stor()` remplace chaque lecture présente dans l'association et chaque écriture par `("store",) + dest[1:] + (valeur,)`, avec `dest = assoc.get(("storage", size, off, idx), ("stor", size, off, idx))` pour un accès absent. |

### 4.2 Types et définitions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-26** : regroupement par emplacement, aucune définition sans base entière | `scobelix/sparser.py` — `rewrite_functions()`, `get_loc()` | `loc = get_loc(d)` ; `if loc is None: continue` ; `if type(loc) != int: continue` après création d'une entrée vide, qui ne produit aucune définition. |
| **FR-STOR-27** : au plus une définition pour un emplacement non simple, type d'élément | `scobelix/sparser.py` — `rewrite_functions()`, `get_type()` | Premier accès trié qui n'est ni `loc` ni `name` : `map` → `("mapping", T)`, `array`/`length` → `("array", T)`, puis `break` ; `get_type()` : `"struct"` ou `("struct", -siz + 1)` si des décalages non nuls existent, sinon `min(sizes)` hors 256, ou 256. Vérifié en bac à sable : `SimpleToken` donne `("def", "balanceOf", 0, ("mapping", 256))`. |
| **FR-STOR-28** : emplacement à accès simples → une définition masquée par champ | `scobelix/sparser.py` — `rewrite_functions()` | Clause `else` de la boucle `for` : `defs.append(("def", name, loc, ("mask", l[1], l[2])))` pour chaque accès distinct. Vérifié en bac à sable : `StorageShapes` donne, pour l'emplacement 0, `flag` (8 bits au décalage 160), `small`, `stamp` et `owner` (160 bits au décalage 0). |
| **FR-STOR-29** : définitions triées par emplacement | `scobelix/sparser.py` — `rewrite_functions()` | `for loc in sort(stordefs.keys())`, `sort()` retombant sur `key=str` si les clés ne sont pas comparables ; retour de la liste `defs` de quadruplets. |

### 4.3 Nommage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-30** : nom tiré du getter | `scobelix/sparser.py` — `find_storage_names()`, `_name_composite()` | Préfixe `get` retiré si `len(name.split("(")[0]) > 3`, initiale minuscule si `name != name.upper()`, suffixe `Address` pour `("storage", 160, …)` hors noms contenant `address`/`addr`/`account`/`owner` ; pour mapping/tableau/struct, `name.split("Address")[0]` s'il reste un caractère. Vérifié en bac à sable : `StorageShapes` nomme `owner` et `whoAddress` deux champs de 160 bits. |
| **FR-STOR-31** : portée du nommage, getters de longueur et booléens, remise à zéro par contrat | `scobelix/sparser.py` — `replace_names_in_assoc()`, `replace_names_in_assoc_bool()`, `_name_composite()`, `used_locs`, `rewrite_functions()` | Emplacement simple : seules les valeurs égales à `stor_id` reçoivent `("name", name, num)` ; mapping/tableau/struct : `_name_composite()` renomme toutes les valeurs de même `get_loc()` et ajoute `("array", loc)` à `used_locs` ; longueur : `logger.warning("storage pattern not found")` ; booléens : un emplacement non entier passe par `storages_assoc.get(getter[1])` et `_name_composite()` si sa base n'est pas dans `used_locs`, un emplacement entier n'est renommé que si `("array", loc)` n'est pas dans `used_locs` et seulement pour les valeurs encore égales à `("stor", size, off, ("loc", loc))` ; `rewrite_functions()` commence par `used_locs.clear()`. |

Deux écarts de code, sans effet observable distinct de l'énoncé, sont à signaler : la vérification « l'emplacement n'est accédé que comme emplacement simple » de `replace_names_in_assoc()` parcourt les clés d'origine (formes `storage`, sans `loc`) et est donc toujours vraie ; le test `("stor", size, off, loc) in used_locs` de `replace_names_in_assoc_bool()` ne peut jamais réussir, les éléments ajoutés ayant la forme `("stor", size, off, ("loc", num))`. C'est l'égalité de motif qui empêche effectivement le double nommage.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-32** : noms `stor<N>` et `stor<HEX>` | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.make_ast()` | `name = "stor" + str(loc)` (mapping/tableau) ; pour les champs : `"stor" + hex(loc)[2:6].upper()` si `loc >= 1000` ; même règle dans `loc_to_name()` de `make_ast()` (`num < 1000` sinon hexadécimal). |

### 4.4 Résilience

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-33** : exclusion un par un, avertissement | `scobelix/sparser.py` — `_sparser_resilient()`, `_find_unresolvable_storage()` | Sur exception de `_sparser(remaining)`, `_find_unresolvable_storage()` teste chaque accès isolément ; le coupable est retiré et la boucle recommence ; en cas de succès avec exclusions, `logger.warning("Storage postprocessing: %d slot(s) excluded as unresolvable, %d slot(s) still resolved normally: %r", …)`. |
| **FR-STOR-34** : échec global → `{}`, traces non renommées | `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/contract.py` — `Contract.postprocess()` | Sans coupable isolable, l'exception est relancée (précédée d'un `logger.exception` si des accès avaient déjà été exclus) ; `postprocess()` la rattrape : `logger.exception("Storage postprocessing failed. This is very bad!")` et `self.stor_defs = {}` ; `repl_stor()` n'ayant pas été appelé, les traces gardent leurs formes `storage`. |

Note contextuelle du document source (accès exclu gardant sa forme brute, lu ou écrit) : confirmée — `repl_stor()` emploie `assoc.get(…, ("stor", size, off, idx))` pour une écriture et laisse inchangée une lecture absente de l'association ; confirmé par `tests/test_sparser_resilience.py`.

### 4.5 Unification entre fonctions et affichage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-35** : écritures en affectations, emplacements restants nommés | `scobelix/contract.py` — `Contract.make_ast()` | `store_to_set()` → `("set", ("stor", …), val)` ; `loc_to_name()` → `("name", "stor…", num)`, ou `"stor" + prettify(num)` pour un emplacement symbolique. |
| **FR-STOR-36** : conversion ou champ supprimés si uniformes dans toutes les fonctions | `scobelix/contract.py` — `Contract.make_asts()` | `stor_loc_to_masks` et `stor_name_to_masks` sont calculés sur les AST de toutes les fonctions (masques dédoublonnés par `dict.fromkeys`, dans l'ordre des fonctions) ; `cleanup()` retire `type`/`field` seulement si tous les masques du même emplacement ou nom ont même type et même décalage, sinon l'expression reste (rendue `field_<décalage>` par `pretty_stor()`). |
| **FR-STOR-37** : même nom pour deux emplacements → erreur journalisée | `scobelix/contract.py` — `Contract.make_asts()` | `logger.error("Seems like we have two locations / storages with the same name: %s %s %s", …)` puis poursuite. |

## 5. Détection des slots de proxy connus

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-38** : quatre constantes, immédiats entiers bruts | `scobelix/utils/proxy_detect.py` — `KNOWN_PROXY_SLOTS`, `detect_proxy_slots()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | Dictionnaire constante → (nom, description) ; seules les instructions dont `op.startswith("push")` et `isinstance(param, int)` sont examinées, sur `loader.parsed_lines` (code avant la terminaison de métadonnées). |
| **FR-STOR-39** : dédoublonnage et contenu de l'indice | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | Ensemble `seen` ; chaque indice est `{"line": line_no, "slot": hex(param), "name": …, "description": …}`. Vérifié en bac à sable : `Eip1967Proxy` donne un seul indice, `line` 9, `slot` `0x360894a1…382bbc`, `eip1967.proxy.implementation`. |
| **FR-STOR-40** : purement indicatif | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | Fonction pure sur le désassemblage : aucun accès réseau, aucune modification des traces (la docstring le précise). |

## 6. Constantes du contrat

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-41** : constantes, noms entièrement en majuscules en dernier | `scobelix/contract.py` — `Contract.postprocess()` | `self.consts = [f … if f.const and f.name.upper() != f.name] + [f … if f.const and f.name.upper() == f.name]`. |

---

Navigation : [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md) · [../README.md](../README.md)
