# Traçabilité d'architecture — Sorties produites par Scobelix

Ce document trace chaque exigence de [../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-01** : une sortie principale par entrée sur la sortie standard, sortie d'erreur pour journal et validation | `scobelix/__main__.py` — `print_decompilation()` | Chaque branche fait un seul `print()` sur la sortie standard ; le statut de validation utilise `file=sys.stderr` ; la journalisation installée par `coloredlogs.install()` écrit sur la sortie d'erreur. Les impressions de `--explain` (`scobelix/prettify.py` — `explain()`) sont la seule exception. |
| **FR-SOR-02** : cohérence texte / AST / payload | `scobelix/decompiler.py` — `_decompile_with_loader()` | Le texte et l'AST sont produits à partir des mêmes objets `contract` et `functions`, et du même `proxy_hints` ; le payload combiné réunit `decompilation.text` et `decompilation.json` d'une même décompilation. |

## 2. Pseudo-code texte (sortie par défaut)

### 2.1 Organisation du texte

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-03** : première ligne `# Palkeoramix decompiler. ` | `scobelix/decompiler.py` — `_decompile_with_loader()` | `print(C.gray + "# Palkeoramix decompiler. " + C.end)`. |
| **FR-SOR-04** : bloc des slots de proxy | `scobelix/decompiler.py` — `_decompile_with_loader()` | `if decompilation.proxy_hints:` : `#`, `#  Detected known proxy storage slot(s):`, une ligne `#  - {slot} ({description})` par indice, `#`, puis `print()`. |
| **FR-SOR-05** : bloc des fonctions en échec | `scobelix/decompiler.py` — `_decompile_with_loader()` | `if len(problems) > 0:` : `#`, `#  I failed with these: `, une ligne `#  - {nom}` par valeur de `problems`, `#  All the rest is below.`, `#`. |
| **FR-SOR-06** : ligne vide, constantes, stockage, getters, fonctions régulières | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/function.py` — `Function._print()` | `print()` puis boucle sur `contract.consts` (`const {nom} = {valeur}`, nom = `color_name.split("()")[0]`), `print()` si au moins une constante, bloc `def storage:` si `len(contract.stor_defs) > 0`, getters suivis de `print()`, fonctions régulières triées par `priority()` suivies de `print()`. |
| **FR-SOR-07** : bloc de stockage et syntaxe des types | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/prettify.py` — `pretty_type()` | `print(f"{C.green}def {C.end}storage:")` puis `pretty_type(s)` par définition : `  {nom} is {type} at storage {loc}`, `loc = hex(loc)` si `loc > 1000` ; masque → `mask_to_type(size, force=True)` plus ` offset {off}` si `off > 0` ; `mapping of`, `array of`, `struct`, `struct {N} bytes`. |
| **FR-SOR-08** : séparateur `Regular functions` | `scobelix/decompiler.py` — `_decompile_with_loader()` | `if shown_already and any(1 for f in func_list if f.hash not in shown_already)` : `print(C.gray + "#\n#  Regular functions\n#" + C.end + "\n")`. |

Note contextuelle du document source (séparateur absent en pratique) : confirmée — avec une seule fonction, `shown_already` et la liste des fonctions restantes ne peuvent être non vides simultanément.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-09** : bytecode vide → `# No code found for this contract.` | `scobelix/decompiler.py` — `_decompile_with_loader()` | Retour anticipé `Decompilation(text=C.gray + "# No code found for this contract." + C.end)`, avant le bloc qui imprime l'en-tête. |

### 2.2 En-tête et corps d'une fonction

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-10** : `def <nom>[ payable]: <commentaire>` | `scobelix/function.py` — `Function._print()` | `color("def ", C.header) + self.color_name + (" payable" si payable) + ": " + color(comment, C.gray)` ; `comment` = `# not payable`, remplacé pour `_fallback(?)` par `# default function` ou `# not payable, default function` ; `color()` rend `""` pour un commentaire vide. |
| **FR-SOR-11** : indentation 2 puis +4, corps vide `  stop`, `stop` final masqué | `scobelix/prettify.py` — `pprint_logic()` ; `scobelix/function.py` — `Function._print()` | `pprint_logic(exp, indent=2)` avec `INDENT_LEN = 4` ; dans la branche liste, `if idx == len(exp) - 1 and indent == 2 and line == ("stop",): pass` ; `_print()` renvoie `["  stop"]` si aucune ligne. |
| **FR-SOR-12** : corps rendu depuis la vue pliée | `scobelix/function.py` — `Function._print()` | `res = list(pprint_logic(self.ast))` lorsque `self.ast` existe (calculé par `Contract.make_ast()` à partir de `folder.fold()`), la trace non pliée restant dans `self.trace`. |

### 2.3 Syntaxe des instructions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-13** : `require` | `scobelix/prettify.py` — `pprint_logic()` | Nœud `require` → `require {cond}` ; `if` à une ou deux branches dont une branche vaut `[("revert", 0)]` ou `invalid` → `require` sur la condition (ou `is_zero(cond)`), suivi de l'autre branche au même niveau. |
| **FR-SOR-14** : `if`/`else`, `while`, `continue` | `scobelix/prettify.py` — `pprint_logic()`, `pretty_line()` | `if {cond}:` + branche indentée + `else:` ; `while` : lignes `setvar` des valeurs initiales puis `while {cond}:` ; `pretty_line()` rend un `continue` par ses `setvar` puis `continue `. |
| **FR-SOR-15** : affectations, écritures mémoire, stockage transitoire | `scobelix/prettify.py` — `prettify()`, `pretty_line()` | `setvar` → `{var} = {val}` ; `setmem` → `mem[…] = …` (plage de 32 octets ramenée à `mem[adresse]`, sinon `mem[a len l]`) ; `tstore` → `tstorage[{idx}] = {val}`. |
| **FR-SOR-16** : écritures de stockage et formes abrégées | `scobelix/prettify.py` — `pretty_line()` ; `scobelix/contract.py` — `Contract.make_ast()` | `make_ast()` convertit `store` en `("set", stor, val)` ; `pretty_line()` produit `++`, `--`, `+= v`, `-= v` selon les motifs `("add", k, idx)`, `("add", idx, ("mul", -1, v))`…, sinon `= val`. |
| **FR-SOR-17** : `return` / `revert with`, `revert` seul, mémoire non résolue | `scobelix/prettify.py` — `pretty_line()`, `pretty_memory()` | `invalid` et `("revert", 0)` → `revert` ; `(op, ("mem", ("range", i, l)))` → `return memory` / `revert with memory` puis `  from …` et `   len …` (ou `    to …`) ; sinon valeurs de `pretty_memory()`, qui regroupe en chaîne entre apostrophes une suite `32, longueur, mots`. |
| **FR-SOR-18** : `Panic(<code>)` et libellés | `scobelix/prettify.py` — `PANIC_CODES`, `pretty_line()` | Motif `("revert", ("data", "'NH{q'", ":int:panic_code"))` → `revert with Panic({code})` suivi de `# {PANIC_CODES[code]}` pour les dix codes de la table. |

Note contextuelle du document source (forme littérale du sélecteur `Panic` requise) : confirmée — le motif exige la chaîne `'NH{q'`, produite seulement lorsque la constante 256 bits du sélecteur est poussée entière et convertie par `pretty_bignum()` ; un sélecteur construit par décalage reste un entier.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-19** : découpage des longs retours | `scobelix/prettify.py` — `pretty_line()` | `elif len(clean_color(ret_val)) < 120 or opcode(param) != "data"` sur une ligne ; sinon une valeur par ligne indentée de `len(op) + 1`, un `32` initial fusionné avec la valeur suivante. |
| **FR-SOR-20** : décompilation interrompue | `scobelix/prettify.py` — `pretty_line()` | `undefined` → `...` suivi de `  # Decompilation aborted, sorry: {params}`. |
| **FR-SOR-21** : journaux d'événements | `scobelix/prettify.py` — `pretty_line()`, `pretty_fname()` | Nom de l'événement via `pretty_fname(e, force=True)` ; signature non résolue (`e.count("(") != 1`) → `log {e}: {valeurs}` ; sans données → `log {e}` ; un paramètre → `log nom(type nom=valeur)` ; plusieurs → une ligne par paramètre. |
| **FR-SOR-22** : appels externes | `scobelix/prettify.py` — `pretty_line()`, `pretty_gas()` | Branches `call` (`call {addr}.{f} with:` ou `call {addr} with:` + `   funct …`), `staticcall` (`static call`), `delegatecall` (`delegate`), `callcode` (`codecall`), puis `   value … wei` si la valeur n'est pas nulle, `     gas … wei`, `    args …` (indentations propres à `static call`). |
| **FR-SOR-23** : `selfdestruct`, précompilé, créations | `scobelix/prettify.py` — `pretty_line()` | `selfdestruct({addr})` ; `{var} = {nom}({args}) # precompiled` ; `create contract with {wei} wei` + `                code: …` ; `create2` avec `salt:` puis `code:`. |
| **FR-SOR-24** : lignes `--verbose` et label résiduel | `scobelix/prettify.py` — `pretty_line()` | Une chaîne `r` → `COLOR_GRAY + "# " + r` ; `("label", name, setvars)` → `label {name} setvars: {setvars}`. |

### 2.4 Syntaxe des expressions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-25** : valeurs d'environnement | `scobelix/prettify.py` — `prettify()` | Correspondances littérales : `callvalue` → `call.value`, `address` → `this.address`, `("cd", 0)` → `call.func_hash`, `calldatasize` → `calldata.size`, `gaslimit` → `block.gas_limit`, `gas` → `gas_remaining`, `balance` → `eth.balance(…)`, `blockhash` → `block.hash(…)`, `extcodehash` → `….codehash`, `extcodesize` → `….code.length`, `tload` → `tstorage[…]`, etc. |
| **FR-SOR-26** : opérateurs infixes, primes pour le signé, `!(…)`, `(… == 0)` | `scobelix/prettify.py` — `prettify()` | Dictionnaire `opcode_to_arithm` (dont `sge` → ` >=′ `, `sdiv` → ` /′ `, `exp` → `^`) ; `not` → `!({inner})` ; `iszero` de `gt`/`lt`/`eq` → `<=`/`>=`/`!=`, sinon `({val} == 0)` ; les sommes passent par `pretty_adds()` (termes négatifs rendus par ` - `). |
| **FR-SOR-27** : masques et conversions de type, `Mask(…)`, `ceil32`/`floor32` | `scobelix/prettify.py` — `prettify()` ; `scobelix/core/masks.py` — `mask_to_type()` | Branche `mask_shl` : petits décalages rendus par `*`/`/` d'une puissance de deux, autres par `shl`/`shr` ; `("mask", size, 0, val)` → `{type}(…)` si `mask_to_type(size)` existe, `val % 2^size` si `size < 64`, sinon `Mask(size, offset, val)` ; motif `mask_shl(>245, 5, 0, …)` → `ceil32`/`floor32`. |
| **FR-SOR-28** : accès aux données | `scobelix/prettify.py` — `prettify()` ; `scobelix/utils/signatures.py` — `get_param_name()` | `mem[…]`, `{nom}[{début} len {longueur}]` pour les tranches de `ARRAY_OPCODES` (sans `len` pour 32), `code.data[… len …]`, `Array(len=…, data=…)`, `param` → nom ; `get_param_name()` rend `nom.length`, `nom[k]` ou le nom du paramètre, et à défaut `cd[…]`. |
| **FR-SOR-29** : accès au stockage | `scobelix/prettify.py` — `pretty_stor()` | `name` → nom ; `map`/`array` → `base[clé]` (`][` entre les termes d'une clé `data`) ; `length` → `.length` ; `field` → `.field_{off}` ; `type` de 256 bits → `uint256(…)` ; emplacement brut → `stor[…]`. |
| **FR-SOR-30** : noms lisibles, `True`/`False` résiduels | `scobelix/prettify.py` — `prettify()` ; `scobelix/postprocess.py` — `cleanup_mul_1()` | `("var", int)` → `nice_names[idx]` ou `var{idx}` ; `("bool", 1)` → `True`, `("bool", 0)` → `False` ; `cleanup_mul_1()` a auparavant converti la plupart des `("bool", entier)` de la trace en 1 ou 0. |
| **FR-SOR-31** : mise en forme des entiers par règles ordonnées | `scobelix/prettify.py` — `prettify()`, `pretty_num()`, `try_fname()` | `prettify()` transforme d'abord les multiples de 86 400 (> 86 400) en `("mul", exp // 3600, 24, 3600)` puis ceux de 3 600 (> 3 600) en `("mul", exp // 3600, 3600)` ; `pretty_num()` teste ensuite `exp > 8**50` (hexadécimal), les puissances de dix de 18 à 9 puis 6, `try_fname()`, `(exp & 2**256 - 1) < 8**30` (décimal), sinon hexadécimal. Vérifié en bac à sable (`9 × 10^18` → `25 * 10^14 * 3600`, `2^151` en hexadécimal, `0xa9059cbb` → `transfer(address to, uint256 amount)`). |

Note contextuelle du document source (durées en jours exprimées en heures) : confirmée — `exp // 3600` (et non `exp // 86400`) est placé devant `24, 3600` ; vérifié en bac à sable : 172 800 est rendu `(48 * 24 * 3600)`.

### 2.5 Couleurs

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-32** : séquences ANSI toujours présentes | `scobelix/utils/helpers.py` — classe `C`, `color()`, `clean_color()` ; `scobelix/prettify.py` — `prettify()`, `pretty_line()` | Codes `\033[…m` concaténés sans test de terminal : gris `C.gray` (en-tête, commentaires, types), magenta `C.header` (`def`, `const`), vert `C.green`/`COLOR_GREEN` (bloc de stockage, noms, `while`, `continue`), bleu `COLOR_BLUE` (variables), gras `COLOR_BOLD` (opérateurs), rouge `C.fail`/`FAIL` (échecs, bénéficiaire d'autodestruction), jaune `COLOR_WARNING` (`delegate`, `codecall`, `...`) ; `clean_color()` permet de les retirer. |

## 3. AST JSON (`--json` et champ `json`)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-33** : quatre clés dans l'ordre | `scobelix/contract.py` — `Contract.json()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `json()` renvoie `problems`, `stor_defs`, `functions` ; `_decompile_with_loader()` ajoute `proxy_hints` en dernier. |
| **FR-SOR-34** : `problems` identifiant → nom | `scobelix/decompiler.py` — `_decompile_with_loader()` | `problems[hash] = fname`, `hash` valant `_fallback` ou un sélecteur. |
| **FR-SOR-35** : `stor_defs` liste de quadruplets, `{}` en cas d'échec | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.postprocess()` | `rewrite_functions()` renvoie la liste `defs` de n-uplets `("def", nom, loc, type)` (sérialisés en listes) ; `postprocess()` lui substitue `{}` en cas d'exception ; `Contract.__init__()` initialise `stor_defs = {}` (dictionnaire), remplacé par la liste lors du post-traitement. |
| **FR-SOR-36** : objet fonction, clés et ordre | `scobelix/function.py` — `Function.serialize()` | Dictionnaire littéral `hash`, `name`, `color_name`, `abi_name`, `length` (`ast_length()` : lignes et caractères de `print()`), `getter`, `const`, `payable`, `print`, `trace`, `params`. |
| **FR-SOR-37** : `trace` non pliée, listes et textes | `scobelix/function.py` — `Function.serialize()` | `json_safe(self.trace)` : n-uplets et ensembles → listes, objet de classe `Node` ou autre → `str(obj)`. |
| **FR-SOR-38** : `params` à clés décimales | `scobelix/function.py` — `Function.serialize()` | `json_safe(self.inferred_params)` : `{str(k): …}`, valeurs `(type, nom)` → `[type, nom]`. |
| **FR-SOR-39** : `proxy_hints` | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | Dictionnaires `line`, `slot` (`hex(param)`, donc minuscules préfixées `0x`), `name`, `description`. |
| **FR-SOR-40** : AST `{}` pour un bytecode vide ou un échec de sérialisation | `scobelix/decompiler.py` — classe `Decompilation`, `_decompile_with_loader()` | Valeur par défaut `dict` du retour anticipé « aucun code » ; `decompilation.json = {}` dans le `except` de sérialisation. |
| **FR-SOR-41** : `--json` indenté de deux espaces | `scobelix/__main__.py` — `print_decompilation()` | `print(json.dumps(decompilation.json, indent=2))`, `ensure_ascii` restant à sa valeur par défaut (vrai). |

## 4. Payload JSON combiné (`--combined-json`)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-42** : objet sur une ligne, séparateurs par défaut, saut de ligne final | `scobelix/__main__.py` — `print_decompilation()` ; `tests/test_main_combined_json.py` — `test_combined_json_output_is_valid_single_line_json()` | `print(json.dumps(payload))` : pas d'indentation, séparateurs `, ` et `: `, caractères non ASCII (dont `ESC` des couleurs) échappés en `\u001b` ; le test vérifie qu'il n'y a qu'un seul `\n`. |
| **FR-SOR-43** : `text` et `json` toujours présents, dans cet ordre | `scobelix/__main__.py` — `print_decompilation()` | `payload = {"text": decompilation.text, "json": decompilation.json}`. |
| **FR-SOR-44** : clés Solidity et validation | `scobelix/__main__.py` — `print_decompilation()` | Sous `if args.solidity` : `solidity`, `solgen_confidence`, `solgen_warnings`, puis sous `if args.validate_solidity` : `solgen_validation` = `{status, errors, warnings}` ; ordre d'insertion conservé par `json.dumps()`. |
| **FR-SOR-45** : contrat d'intégration générique | `tests/test_main_combined_json.py` ; `scobelix/__main__.py` — `parse_args()` | Convention documentaire : l'aide de `--combined-json` décrit ce mode comme destiné aux appelants qui veulent tout obtenir d'une seule passe, et les trois tests du fichier en fixent les clés et le format monoligne. |

## 5. Sortie Solidity (`--solidity`)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-46** : code généré imprimé, saut de ligne supplémentaire | `scobelix/__main__.py` — `print_decompilation()` | `print(result.solidity)` : le texte se termine déjà par `\n` (dernier élément vide de `SolidityEmitter.generate()`), `print()` en ajoute un. |
| **FR-SOR-47** : statut et erreurs sur la sortie d'erreur, avertissements omis | `scobelix/__main__.py` — `print_decompilation()` | `print(f"# solc validation: {v.status}", file=sys.stderr)` puis `print(f"#   {e}", file=sys.stderr)` pour chaque erreur ; `v.warnings` n'est pas imprimé. |

## 6. Autres productions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOR-48** : format de journal | `scobelix/__main__.py` — `main()` | `coloredlogs.install(level=…, milliseconds=True)` applique le format par défaut de la bibliothèque (`%(asctime)s %(hostname)s %(name)s[%(process)d] %(levelname)s %(message)s`, millisecondes après une virgule) sur la sortie d'erreur ; format observé en bac à sable. |
| **FR-SOR-49** : messages INFO minimaux | `scobelix/decompiler.py` — `_decompile_with_loader()`, `dec()` ; `scobelix/loader.py` — `Loader.load_addr()` | `logger.info("Running light execution to find functions.")`, `"Decompiling %s..."`, `" -> Interpreting EVM on function..."`, `" -> Cleaning up AST, identifying loops..."`, `"Functions decompilation finished, now doing post-processing."` ; `"Fetching code for %s..."` dans `load_addr()` ; progression dans `scobelix/vm.py` et `scobelix/simplify.py`, cache dans `scobelix/utils/supplement.py`. |
| **FR-SOR-50** : avertissements et erreur d'échec de fonction | `scobelix/vm.py` — `VM.run()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `logger.warning` pour `VM stopped prematurely…`, `simplify_trace timed out.` et `Storage postprocessing: … excluded …` ; `logger.exception("Problem with %s%s", fname, C.end)` (niveau ERROR avec trace). |
| **FR-SOR-51** : profil au format pstats | `scobelix/__main__.py` — `main()` | `cProfile.Profile().dump_stats("scobelix.prof")`, format lisible par le module standard `pstats`. |

---

Navigation : [../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md) · [../README.md](../README.md)
