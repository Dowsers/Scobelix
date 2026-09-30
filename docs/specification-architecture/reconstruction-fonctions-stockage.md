# Traçabilité d'architecture — Reconstruction des fonctions, des paramètres et de la structure du stockage

Ce document trace chaque exigence de [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble

Section introductive sans exigence numérotée : la caractérisation fonction par fonction est portée par le constructeur de `Function` (`scobelix/function.py`), la reconstruction du stockage au niveau du contrat par `Contract.postprocess()` (`scobelix/contract.py`), qui appelle `rewrite_functions()` (`scobelix/sparser.py`) une seule fois.

## 2. Caractérisation d'une fonction

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-01** : non payable si la trace commence par un test de `callvalue` menant à un rejet | `scobelix/function.py` — `Function.analyse()` | Si `first = self.trace[0]` est un `if` dont `simplify_bool(cond)` vaut `callvalue` et dont la branche vraie commence par `("revert", 0)` ou `invalid` (ou l'inverse pour `iszero(callvalue)`), la trace est remplacée par l'autre branche et `payable = False` ; sinon `payable = True`. |
| **FR-STOR-02** : lecture seule par recherche textuelle | `scobelix/function.py` — `Function.analyse()` | `for op in ["store", "selfdestruct", "call", "delegatecall", "codecall", "create"]: if f"'{op}'" in str(self.trace): self.read_only = False`. |

Note contextuelle du document source (`callcode`, `create2`, `tstore` non détectés) : confirmée — la recherche porte sur les noms exacts entre apostrophes ; `'codecall'` ne correspond à aucun nœud réel (l'opérateur produit est `callcode`).

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-03** : constante | `scobelix/function.py` — `Function.analyse()`, `Function._print()` | `self.const = self.read_only`, annulé si `storage`, `calldata`, `calldataload`, `store` ou `cd` figure dans `str(self.trace)` ou si `len(self.returns) != 1` ; sinon `self.const = self.returns[0]`, soit le n-uplet `("return", valeur)` (les tests `len(self.const) == 3` suivants ne s'appliquent jamais) ; `_print()` affiche `val[1]`. |
| **FR-STOR-04** : getter | `scobelix/function.py` — `Function.analyse()` | Pour une fonction non constante, en lecture seule, à retour unique : `bool(storage)`, `mask_shl(…, storage)` (on retient la lecture), `storage`, ou `data` dont tous les termes lisent le même emplacement ou `add(k, loc)`, ou des `sha3` portant le même emplacement (< 1000), qui donne `("struct", ("loc", loc))`. |
| **FR-STOR-05** : getter de chaîne | `scobelix/function.py` — `Function.simplify_string_getter_from_storage()` | Si tous les retours ont la forme `("return", ("data", ("arr", ("storage", 256, 0, ("length", loc)), …)))`, la trace devient le retour unique du tableau de stockage et `self.getter` est positionné. |
| **FR-STOR-06** : fonction régulière | `scobelix/function.py` — `Function.__init__()` | `self.is_regular = self.const is None and self.getter is None`. |
| **FR-STOR-07** : ordre d'affichage | `scobelix/function.py` — `Function.priority()`, `Function.ast_length()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `priority()` renvoie −1 si `"selfdestruct"` figure dans la trace, sinon la longueur en caractères du texte rendu ; `func_list.sort(key=lambda f: f.priority())`. |

## 3. Inférence des paramètres

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-08** : signature connue → décalages 4 + 32k | `scobelix/function.py` — `Function.make_params()` | `params = get_func_params(self.hash)` ; si non vide, `res[idx] = (p["type"], p["name"])` avec `idx` partant de 4 par pas de 32. |
| **FR-STOR-09** : paramètres déduits des lectures, taille de la première lecture | `scobelix/function.py` — `Function.make_params()` | `find_f_list()` collecte en ordre de parcours les `mask_shl(…, cd)` et les `cd` ; `if idx == 0: continue` ; la première occurrence fixe `sizes[idx]` (taille du masque, ou 256). |
| **FR-STOR-10** : tableau, booléen, plus petit type englobant | `scobelix/function.py` — `Function.make_params()` ; `scobelix/core/masks.py` — `mask_to_type()` | `("add", 4, ("cd", i))` → `sizes[i] = -1` (`array`) ; si tous les parents de `("cd", idx)` sont `bool`, `if` ou `iszero` → `sizes[idx] = 1` (`bool`) ; sinon `mask_to_type(size, force=True)`, qui choisit l'entrée exacte ou la première plus grande de la table 1/8/16/32/64/128/160/256. |
| **FR-STOR-11** : décalage non aligné → avertissement et aucun paramètre | `scobelix/function.py` — `Function.make_params()` | `if type(idx) != int or (idx - 4) % 32 != 0: logger.warning("unusual cd (not aligned)"); return {}`. |
| **FR-STOR-12** : noms `_param1`, `_param2`… | `scobelix/function.py` — `Function.make_params()` | `for idx in sorted(sizes.keys())` avec `f"_param{count}"`, `count` partant de 1. |
| **FR-STOR-13** : nom complété pour un sélecteur non résolu | `scobelix/function.py` — `Function.make_names()` | Appelée si `"unknown" in self.name` ; construit `nom(type _paramN, …)` (nom affiché et nom coloré) et `nom(type,…)` (nom ABI). |
| **FR-STOR-14** : masques redondants retirés, lectures remplacées par `param` | `scobelix/function.py` — `Function.cleanup_masks()` ; `scobelix/contract.py` — `Contract.postprocess()` | `rem_masks()` supprime `bool(cd)` d'un paramètre `bool` et `mask_shl(size, 0, 0, cd)` si `size == type_to_mask(kind)` ; `postprocess()` applique `replace_names` : `("cd", idx)` → `("param", nom)` pour chaque `idx` de `inferred_params`. |

Note contextuelle du document source (type `tuple` inatteignable, taille jamais réduite) : confirmée — dans `make_params()`, le test de masque qui produirait `-2` suit un `break` exécuté pour tout parent autre que `bool`/`if`/`iszero`, et `sizes[idx] == size` est une comparaison sans affectation.

## 4. Reconstruction de la structure du stockage

### 4.1 Collecte et résolution des emplacements

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-15** : collecte de tous les accès, reconstruction unique | `scobelix/sparser.py` — `rewrite_functions()`, `find_stores()` | `storages = list(find_stores([f.trace for f in functions]))` rassemble lectures `storage` et écritures `store` (converties en `("storage", size, off, idx)`) de toutes les fonctions, puis un seul appel `_sparser_resilient(storages)`. |
| **FR-STOR-16** : table arc-en-ciel, correspondance par inclusion | `scobelix/sparser.py` — `rainbow_sha3()`, `sha3_loc_table` | `if type(exp) == int and len(hex(exp)) > 40` puis `if hex(exp) in src` pour chaque clé de la table (hachés des emplacements 0 à 19 et des clés 0 et 1 sur ces emplacements). |

Note contextuelle du document source (hachés à zéro de tête jamais reconnus) : confirmée — `hex()` n'écrit pas les zéros de tête ; vérifié en bac à sable : les entrées `("loc", 5)`, `("loc", 11)` et `("map", 0, ("loc", 5))` sont les trois seules que `rainbow_sha3()` ne retrouve pas à partir de leur propre valeur.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-17** : `loc`, `map`, `array` | `scobelix/sparser.py` — `_sparser()` | `simplify_sha3()` : `("sha3", N)` → `("loc", N)`, `("sha3", idx, N)` → `("map", idx, ("loc", N))`, haché imbriqué → `map` de `data` ; `double_map()` traite les imbrications ; `add_to_arr()` : `add` avec un `loc` → `("array", idx, loc)`. |
| **FR-STOR-18** : constante ajoutée → champ décalé de 256 × N bits | `scobelix/sparser.py` — `_sparser()` | `if m := match(idx, ("add", ":int:num", ...))` et un `loc` dans les autres termes : `offset += 256 * m.num`. |
| **FR-STOR-19** : emplacement constant aussi base d'un tableau → `length` | `scobelix/sparser.py` — `_sparser()` | `if type(idx) == int: if str(("loc", idx)) in str(storages): idx = ("length", ("loc", idx)) else: idx = ("loc", idx)`. |
| **FR-STOR-20** : forme `stor` et réécriture des traces | `scobelix/sparser.py` — `_sparser()`, `repl_stor()` | Les accès sont exprimés `("stor", size, offset, idx)` ; `repl_stor()` remplace chaque lecture par sa forme reconstruite et chaque écriture par `("store",) + dest[1:] + (valeur,)`. |

### 4.2 Types et définitions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-21** : regroupement par emplacement, sentinelle 99 | `scobelix/sparser.py` — `rewrite_functions()` | `loc = get_loc(d)` ; `if loc is None: loc = 99` ; `if type(loc) != int: continue` après création d'une entrée vide, qui ne produit aucune définition. |
| **FR-STOR-22** : au plus une définition pour un emplacement non simple, type d'élément | `scobelix/sparser.py` — `rewrite_functions()`, `get_type()` | Premier accès trié qui n'est ni `loc` ni `name` : `map` → `("mapping", T)`, `array`/`length` → `("array", T)`, puis `break` ; `get_type()` : `"struct"` ou `("struct", -siz + 1)` si des décalages non nuls existent, sinon `min(sizes)` hors 256, ou 256. |
| **FR-STOR-23** : emplacement à accès simples → une définition masquée par champ | `scobelix/sparser.py` — `rewrite_functions()` | Clause `else` de la boucle `for` : `defs.append(("def", name, loc, ("mask", l[1], l[2])))` pour chaque accès distinct. |
| **FR-STOR-24** : définitions triées par emplacement | `scobelix/sparser.py` — `rewrite_functions()` | `for loc in sort(stordefs.keys())`, `sort()` retombant sur `key=str` si les clés ne sont pas comparables ; retour de la liste `defs` de quadruplets. |

### 4.3 Nommage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-25** : nom tiré du getter | `scobelix/sparser.py` — `find_storage_names()`, `replace_names_in_assoc()` | Préfixe `get` retiré si `len(name.split("(")[0]) > 3`, initiale minuscule si `name != name.upper()`, suffixe `Address` pour `("storage", 160, …)` hors noms contenant `address`/`addr`/`account`/`owner` ; pour mapping/tableau/struct, `name.split("Address")[0]` s'il reste un caractère. |
| **FR-STOR-26** : portée du nommage, getters de longueur et booléens | `scobelix/sparser.py` — `replace_names_in_assoc()`, `replace_names_in_assoc_bool()`, `used_locs` | Emplacement simple : seules les valeurs égales à `stor_id` (même taille, même décalage) reçoivent `("name", name, num)` ; mapping/tableau/struct : toutes les valeurs de même `get_loc()` ; longueur : `logger.warning("storage pattern not found")` ; booléens traités ensuite, ignorés si `("array", loc)` est dans `used_locs` (ensemble de niveau module), et ne renommant que les valeurs encore égales à `("stor", size, off, ("loc", loc))`. |

Deux écarts de code, sans effet observable distinct de l'énoncé, sont à signaler : la vérification « l'emplacement n'est accédé que comme emplacement simple » de `replace_names_in_assoc()` parcourt les clés d'origine (formes `storage`, sans `loc`) et est donc toujours vraie ; le test `("stor", size, off, loc) in used_locs` de `replace_names_in_assoc_bool()` ne peut jamais réussir, les éléments ajoutés ayant la forme `("stor", size, off, ("loc", num))`. C'est l'égalité de motif qui empêche effectivement le double nommage.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-27** : noms `stor<N>` et `stor<HEX>` | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.make_ast()` | `name = "stor" + str(loc)` (mapping/tableau) ; pour les champs : `"stor" + hex(loc)[2:6].upper()` si `loc >= 1000` ; même règle dans `loc_to_name()` de `make_ast()` (`num < 1000` sinon hexadécimal). |

### 4.4 Résilience

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-28** : exclusion un par un, avertissement | `scobelix/sparser.py` — `_sparser_resilient()`, `_find_unresolvable_storage()` | Sur exception de `_sparser(remaining)`, `_find_unresolvable_storage()` teste chaque accès isolément ; le coupable est retiré et la boucle recommence ; en cas de succès avec exclusions, `logger.warning("Storage postprocessing: %d slot(s) excluded as unresolvable, %d slot(s) still resolved normally: %r", …)`. |
| **FR-STOR-29** : échec global → `{}`, traces non renommées | `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/contract.py` — `Contract.postprocess()` | Sans coupable isolable, l'exception est relancée (précédée d'un `logger.exception` si des accès avaient déjà été exclus) ; `postprocess()` la rattrape : `logger.exception("Storage postprocessing failed. This is very bad!")` et `self.stor_defs = {}` ; `repl_stor()` n'ayant pas été appelé, les traces gardent leurs formes `storage`. |

Note contextuelle du document source (accès exclu et écrit → repli global) : confirmée — `repl_stor()` indexe `assoc[("storage", size, off, idx)]` pour chaque écriture, ce qui lève `KeyError` pour un accès exclu ; vérifié en bac à sable en forçant l'échec d'un accès écrit de `SimpleToken` (résultat `stor_defs == {}`), alors que l'exclusion d'un accès en lecture seule laisse les deux définitions intactes.

### 4.5 Unification entre fonctions et affichage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-30** : écritures en affectations, emplacements restants nommés | `scobelix/contract.py` — `Contract.make_ast()` | `store_to_set()` → `("set", ("stor", …), val)` ; `loc_to_name()` → `("name", "stor…", num)`, ou `"stor" + prettify(num)` pour un emplacement symbolique. |
| **FR-STOR-31** : conversion ou champ supprimés si uniformes dans toutes les fonctions | `scobelix/contract.py` — `Contract.make_asts()` | `stor_loc_to_masks` et `stor_name_to_masks` sont calculés sur les AST de toutes les fonctions ; `cleanup()` retire `type`/`field` seulement si tous les masques du même emplacement ou nom ont même type et même décalage, sinon l'expression reste (rendue `field_<décalage>` par `pretty_stor()`). |
| **FR-STOR-32** : même nom pour deux emplacements → erreur journalisée | `scobelix/contract.py` — `Contract.make_asts()` | `logger.error("Seems like we have two locations / storages with the same name: %s %s %s", …)` puis poursuite. |

## 5. Détection des slots de proxy connus

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-33** : quatre constantes, immédiats entiers bruts | `scobelix/utils/proxy_detect.py` — `KNOWN_PROXY_SLOTS`, `detect_proxy_slots()` | Dictionnaire constante → (nom, description) ; seules les instructions dont `op.startswith("push")` et `isinstance(param, int)` sont examinées. |
| **FR-STOR-34** : dédoublonnage et contenu de l'indice | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | Ensemble `seen` ; chaque indice est `{"line": line_no, "slot": hex(param), "name": …, "description": …}`. |
| **FR-STOR-35** : purement indicatif | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | Fonction pure sur le désassemblage : aucun accès réseau, aucune modification des traces (la docstring le précise). |

## 6. Constantes du contrat

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-STOR-36** : constantes, noms entièrement en majuscules en dernier | `scobelix/contract.py` — `Contract.postprocess()` | `self.consts = [f … if f.const and f.name.upper() != f.name] + [f … if f.const and f.name.upper() == f.name]`. |

---

Navigation : [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md) · [../README.md](../README.md)
