# Traçabilité d'architecture — Pipeline de décompilation : désassemblage, exécution symbolique, structuration et simplification

Ce document trace chaque exigence de [../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble

Section introductive sans exigence numérotée : le diagramme du document source correspond à l'enchaînement codé dans `scobelix/decompiler.py` (`_decompile_with_loader()`), qui appelle successivement `scobelix/loader.py`, `scobelix/vm.py`, `scobelix/whiles.py` (qui délègue à `scobelix/simplify.py`) et, pour la vue texte, `scobelix/folder.py`.

## 2. Désassemblage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-01** : préfixe `0x` retiré, paires converties, chiffre isolé final, erreur sur caractère non hexadécimal | `scobelix/loader.py` — `Loader.load_binary()` | `if source[:2] == "0x"` retire le préfixe (en minuscules seulement) ; la boucle `int("0x" + source[:2], 16)` consomme deux caractères à la fois, un dernier caractère seul donnant un octet de 0 à 15 ; `int()` lève `ValueError` sur un caractère invalide. Vérifié : `60016` produit `push1 0x1` puis `mod` (octet 0x06). |

Note contextuelle du document source (tolérances de la conversion numérique) : confirmée — `int("0x_1", 16)` et `int("0x1 ", 16)` valent 1, la conversion standard acceptant un tiret bas après le préfixe et des blancs finaux.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-02** : opcode connu ou `UNKNOWN` portant la valeur de l'octet | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/utils/opcode_dict.py` — `opcode_dict` | `if popped not in opcode_dict: op = "UNKNOWN"; param = popped`. |
| **FR-DEC-03** : jeu d'opcodes reconnu jusqu'à Cancun | `scobelix/utils/opcode_dict.py` — `opcode_dict` | Table octet → mnémonique couvrant exactement la liste du document (0x44 est nommé `prevrandao`, 0x5C–0x5F `tload`, `tstore`, `mcopy`, `push0`, 0x49–0x4A `blobhash`, `blobbasefee`). |
| **FR-DEC-04** : immédiat de `pushN` gros-boutiste, `push0` = 0, immédiat partiel sans erreur | `scobelix/loader.py` — `Loader.load_binary()` | `num_words = int(op[4:])` (0 pour `push0`), puis `param = param * 0x100 + stack.pop()` et `line += 1` par octet lu ; un `except Exception: break` arrête la lecture en fin de code sans erreur. |
| **FR-DEC-05** : positions en octets, destinations `jumpdest` enregistrées | `scobelix/loader.py` — `Loader.load_binary()` | Le compteur `line` progresse d'un par octet (instruction et immédiat) ; `if op == "jumpdest": self.jump_dests.append(line)`. |
| **FR-DEC-06** : immédiats > 10^15 convertis en chaîne imprimable, cas du message signé | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/utils/helpers.py` — `pretty_bignum()` | `if op.startswith("push") and param > 1000000000000000: param = pretty_bignum(param)` ; `pretty_bignum()` renvoie `'\x19Ethereum Signed Message:\n32'` pour la constante connue, sinon parcourt les octets, ignore les nuls, rend l'entier d'origine dès qu'un octet non nul n'est ni imprimable ni blanc, et sinon la chaîne entre apostrophes. |
| **FR-DEC-07** : désassemblage exposé et slots de proxy sur immédiats bruts | `scobelix/loader.py` — `Loader.load_binary()`, `Loader.disasm()` | La conversion n'est appliquée qu'aux entrées de `self.lines` (utilisées par la VM) ; `self.parsed_lines`, lu par `disasm()` et par `detect_proxy_slots()`, conserve les entiers bruts. |
| **FR-DEC-08** : format du désassemblage, mnémoniques d'origine | `scobelix/loader.py` — `Loader.disasm()` | `f"{hex(line_no)}, {op}, {hex(param) if param is not None else ''}"` sur `parsed_lines`, où `dup`/`swap` ne sont pas encore normalisés ; `UNKNOWN` porte l'octet et `push0` la valeur 0 comme `param`. |

## 3. Découverte des fonctions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-09** : passe légère depuis 0, bornée par les budgets de découverte et de nœuds | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.run()` | `loader.run(VM(loader, just_fdests=True))` puis `vm.run(0, timeout=LOADER_TIMEOUT)` ; le budget de nœuds s'applique par `should_quit()` de `VM.run()`. |
| **FR-DEC-10** : point d'entrée unique `_fallback` à la position 0 | `scobelix/loader.py` — `Loader.run()`, `Loader.add_func()` | `func_calls()` ne reconnaît que des nœuds `funccall`, jamais émis ; `func_list` est vide, donc `default` vaut `None` et `self.add_func(default or 0, name="_fallback")`. |
| **FR-DEC-11** : exception de découverte → `Loader issue.` et même point d'entrée | `scobelix/loader.py` — `Loader.run()` | `except Exception: logger.exception("Loader issue."); self.add_func(0, name="_fallback")`. |
| **FR-DEC-12** : cible > 1 sur `jumpdest` → octet suivant | `scobelix/decompiler.py` — `_decompile_with_loader()` | `if target > 1 and loader.lines[target][1] == "jumpdest": target += 1` ; jamais exercé puisque la seule cible est 0. |
| **FR-DEC-13** : nommage selon la résolution des signatures, `_fallback(?)` | `scobelix/loader.py` — `Loader.run()` ; `scobelix/utils/signatures.py` — `make_abi()`, `get_func_name()` | `make_abi(self.hash_targets)` puis `get_func_name(hash)` pour chaque entrée ; un identifiant sans `0x` donne `{"name": h}` et donc `_fallback(?)`. |

Note contextuelle du document source (mécanisme de découverte par sélecteur jamais alimenté) : confirmée — aucune occurrence de `funccall` en dehors du motif recherché dans `Loader.run()` ; la docstring de `_decompile_with_loader()` et le filtre `only_func_name` décrivent le comportement amont.

## 4. Exploration des chemins

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-14** : amorce `mem[0x40] = 0x60` en tête de trace | `scobelix/vm.py` — `VM.run()` | Trace initiale du nœud racine : `("setmem", ("range", 0x40, 32), 0x60)` suivie du saut vers le nœud de la fonction. |
| **FR-DEC-15** : exploration en largeur, identité position/hauteur/destinations | `scobelix/vm.py` — `Node.__init__()`, `VM.expand_trace()` | `self.jd = (start, len(stack), tuple(stack_obj.jump_dests(…)))` ; `expand_trace()` exécute à chaque itération tous les nœuds dont `trace is None`, niveau par niveau. |
| **FR-DEC-16** : destinations de saut dans la pile | `scobelix/stack.py` — `Stack.jump_dests()` | Retient tout entier appartenant à `loader.jump_dests` ou tel que `el > 2000 and el < 5000`. |
| **FR-DEC-17** : 20 × 200 itérations, arrêt sans nœud inexploré | `scobelix/vm.py` — `VM.run()` | Boucles `for j in range(20)` / `for i in range(200)` : `expand_trace()`, `replace_loops()`, puis `break` si `find_nodes(root, lambda n: n.trace is None)` est vide ; `continue_loops()` entre deux itérations externes. |
| **FR-DEC-18** : arrêt sur budget de temps ou de nœuds, en fin d'itération | `scobelix/vm.py` — `should_quit()` dans `VM.run()` | `should_quit()` n'est évaluée qu'après chaque itération interne et en fin d'itération externe : `node_count > MAX_NODE_COUNT` ou `timeout and (time.monotonic() - time_start > timeout)`. |
| **FR-DEC-19** : avertissement `VM stopped prematurely…`, trace partielle `undefined` | `scobelix/vm.py` — `VM.run()`, `Node.make_trace()` | `logger.warning("VM stopped prematurely. Node count %i, after %.2f seconds.", …)` puis `root.make_trace()`, qui rend `[("undefined", "decompilation didn't finish")]` pour tout nœud sans trace ; aucune exception n'est levée. |
| **FR-DEC-20** : progression toutes les 2 s au plus | `scobelix/vm.py` — `VM.run()` | `if now - last_progress >= 2` : `pct = min(int(node_count * 100 / MAX_NODE_COUNT), 100)`, barre de `int(pct / 5)` `#` sur 20 caractères, message `VM progress [%s] %s%% (%s nodes)`. |
| **FR-DEC-21** : évaluation concrète d'un saut conditionnel | `scobelix/vm.py` — `VM.handle_jumps()` ; `scobelix/core/arithmetic.py` — `eval_bool()` | `arithmetic.eval_bool(if_condition, condition, symbolic=False)` compare aussi la condition au prédicat connu du nœud (`known_true`) ; un résultat booléen ne poursuit que `n_true` ou `n_false`. |
| **FR-DEC-22** : condition indécidable → `if` à deux branches | `scobelix/vm.py` — `VM.handle_jumps()` | `trace.append(("if", if_condition, n_true, n_false))`, `n_true` partant de la cible, `n_false` de `self.loader.next_line(i)`. |
| **FR-DEC-23** : élagage permanent au-delà de 60 % des nœuds | `scobelix/vm.py` — `VM.handle_jumps()`, `VM.__init__()` | `if self.protocol_safe and node_count > int(MAX_NODE_COUNT * 0.6)` : la branche fausse devient un `Node` de trace `[("stop",)]` ; `protocol_safe=True` par défaut et aucun appelant ne le change. |

Note contextuelle du document source (branches élaguées sans marqueur) : confirmée — le nœud élagué ne porte qu'un `("stop",)` ordinaire, indiscernable d'un arrêt réel.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-24** : saut vers destination non entière ou invalide | `scobelix/vm.py` — `VM._run()` | Si la position n'est pas dans `lines` : `("undefined", "jump to a parameter computed at runtime", i)` pour un non-entier, `("invalid", "jumdest", i)` sinon ; hors `jumpdest` en mode non sûr : `("invalid", "jump")`. |
| **FR-DEC-25** : fin de code sans terminaison → `invalid` | `scobelix/vm.py` — `VM._run()` | `next_line()` renvoie `None` après la dernière instruction ; `lines[None]` lève `KeyError`, converti en `("invalid", "jumpdest")`. |
| **FR-DEC-26** : pile vide → exception, échec de la fonction ou repli de découverte | `scobelix/stack.py` — `Stack.pop()`, `Stack.dup()`, `Stack.swap()` | `list.pop()` ou l'indexation négative lèvent `IndexError`, non rattrapée dans `scobelix/vm.py` ; elle remonte au `except` de `_decompile_with_loader()` (échec) ou de `Loader.run()` (repli). |

## 5. Détection et repliement des boucles

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-27** : boucle = identité déjà présente chez un ancêtre, pile non vide de même hauteur | `scobelix/vm.py` — `VM.replace_loops()` | Condition `node.jd in node.history and node.jd[1] > 0 and len(node.history[node.jd].stack) == len(node.stack)` ; `history` est hérité du parent par `Node.set_prev()`. |
| **FR-DEC-28** : variables de boucle et leur identifiant | `scobelix/stack.py` — `fold_stacks()` | Pour chaque position différente : `temp_var_counter = len(first) - idx + depth * 1000`, valeur remplacée par `("var", temp_var_counter)`. |
| **FR-DEC-29** : nœuds `label` et `goto` | `scobelix/vm.py` — `VM.continue_loops()`, `Node.set_label()`, `Node.make_trace()` | `continue_loops()` transforme le nœud `loop` en `("goto", loop_dest, set_vars)` ou pose un label ; `make_trace()` insère `("label", self, begin_vars)` en tête du nœud étiqueté. |
| **FR-DEC-30** : accumulateur indépendant possiblement non suivi | `scobelix/vm.py` — `VM.replace_loops()` | Limite documentée par le long commentaire en tête de la méthode ; la comparaison n'a lieu qu'à la première revisite détectée. |

Note contextuelle du document source (test « échec attendu strict ») : confirmée par `tests/test_golden_fixtures.py` — `test_loop_accumulator_value_is_tracked()`, marqué `xfail(strict=True)`.

## 6. Sémantique symbolique des opcodes

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-31** : réduction modulo 2^256, évaluation concrète, division et modulo par zéro = 0 | `scobelix/stack.py` — `Stack.simplify()` ; `scobelix/core/arithmetic.py` — `eval()`, `div()`, `mod()` | Tout entier empilé passe par `exp & arithmetic.UINT_256_MAX` ; `eval()` applique la table `OPCODES` lorsque tous les opérandes sont entiers ; `div()`, `mod()`, `sdiv()`, `smod()`, `mulmod()` renvoient 0 pour un diviseur nul. |
| **FR-DEC-32** : normalisation symbolique | `scobelix/core/algebra.py` — `add_op()`, `mul_op()`, `sub_op()` ; `scobelix/stack.py` — `Stack._simplify()` | `sub_op()` renvoie `add_op(left, minus_op(right))` avec `minus_op()` = `mul_op(-1, …)` ; `_simplify()` convertit `and` avec un masque (`to_mask()`) en `mask_op()`, et `div`/`mul` par une puissance de deux en masque décalé. |
| **FR-DEC-33** : `addmod` représenté par `mulmod` | `scobelix/vm.py` — `VM.apply_stack()` | Branche `elif op in ["mulmod", "addmod"]: stack.append(("mulmod", …))` ; `Stack.simplify()` évalue ensuite `mulmod` concrètement. |

Note contextuelle du document source (`addmod(2, 3, 7)` vaut 6) : confirmée en bac à sable (bytecode `6007600360020860005260206000f3` décompilé en `const _fallback(?) = 6`).

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-34** : `shl`/`shr` concrets ou masques, `sar` signé ou approximé | `scobelix/vm.py` — `VM.apply_stack()` | `exp << off` / `exp >> off` si `all_concrete()`, sinon `mask_op(exp, shl=off)` / `mask_op(exp, offset=minus_op(off), shr=off)` ; `sar` concret recopie le bit de signe, symbolique il reprend la forme de `shr` (commentaire `FIXME` du code). |
| **FR-DEC-35** : `not`, `iszero`, comparaisons, simplifications | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/stack.py` — `Stack.cleanup()` | `("not", x)` / `("iszero", x)` et `arithmetic.eval((op, a, b))` pour les comparaisons ; `cleanup()` réduit `lt` et `iszero` d'entiers en `("bool", 0/1)` et les doubles `iszero`. |
| **FR-DEC-36** : `mstore`, `mload`, `mcopy` | `scobelix/vm.py` — `VM.apply_stack()` | `("setmem", ("range", memloc, 32), val)` ; `mload` crée `setvar _<N>` = `("mem", ("range", memloc, 32))` avec `self.counter` ; `mcopy` n'écrit que `if size != 0`. |
| **FR-DEC-37** : `mstore8` sur une plage de 8 octets | `scobelix/vm.py` — `VM.apply_stack()` | `("setmem", ("range", memloc, 8), val)`. |

Note contextuelle du document source (un seul octet écrit en réalité) : confirmée par ce même littéral `8` (longueur en octets de la plage) ; vérifié en bac à sable sur `60ff60005360206000f3`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-38** : `calldataload`, `calldatacopy`, `returndatacopy`, `extcodecopy` | `scobelix/vm.py` — `VM.apply_stack()` | `("cd", off)` ; écritures `call.data` / `ext_call.return_data` seulement `if data_len != 0` ; `extcodecopy` toujours écrit `("extcodecopy", addr, ("range", code_pos, data_len))`. |
| **FR-DEC-39** : `codecopy` concret ou `code.data` | `scobelix/vm.py` — `VM.apply_stack()` | Condition `call_pos + data_len < len(self.loader.binary)` avec positions entières ; sinon `("code.data", call_pos, data_len)`. |

Note contextuelle du document source (lecture décalée d'un octet) : confirmée par la boucle `for i in range(call_pos - 1, call_pos + data_len - 1)` ; vérifié en bac à sable (lecture de 0xf3 au lieu de 0xab).

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-40** : `codesize` et `pc` concrets | `scobelix/vm.py` — `VM.apply_stack()` | `stack.append(len(self.loader.binary))` et `stack.append(line[0])`. |
| **FR-DEC-41** : `sload`, `sstore`, `tload`, `tstore` | `scobelix/vm.py` — `VM.apply_stack()` | `("storage", 256, 0, sloc)`, `("store", 256, 0, sloc, val)`, `("tload", x)`, `("tstore", tloc, val)`. |
| **FR-DEC-42** : `sha3` → variable `_<N>` | `scobelix/vm.py` — `VM.apply_stack()` | `trace(("setvar", f"_{self.counter}", ("sha3", mem_load(p, n))))` puis empilement de la variable. |
| **FR-DEC-43** : `log0`–`log4` | `scobelix/vm.py` — `VM.apply_stack()` | `("log", mem_load(p, s)) + tuple(topics)`, les sujets étant dépilés dans l'ordre. |
| **FR-DEC-44** : `call`/`staticcall` ordinaires | `scobelix/vm.py` — `VM.handle_call()` | `wei = 0` pour `staticcall` ; `arg_len == 0` → `None, None`, `arg_len == 4` → sélecteur seul, sinon sélecteur et `mem_load(add_op(arg_start, 4), sub_op(arg_len, 4))` ; empile `ext_call.success` ; écriture de retour si `lt_op(0, ret_len)` est vrai ou incomparable (`CannotCompare`). |
| **FR-DEC-45** : `delegatecall` | `scobelix/vm.py` — `VM.apply_stack()` | Nœud `("delegatecall", gas, addr, fname, fparams)` ; `call_id = f"delegatecall_{self.counter}"` avec le compteur partagé ; écriture `delegate.return_data` si `ret_len != 0`. |
| **FR-DEC-46** : `callcode` | `scobelix/vm.py` — `VM.apply_stack()` | Nœud `("callcode", gas, addr, value, fname, fparams)` avec `fparams = 0` pour 4 octets ; empile `callcode.return_code` ; écriture `callcode.return_data` si `ret_len != 0`. |
| **FR-DEC-47** : `create` et `create2` | `scobelix/vm.py` — `VM.apply_stack()` | `("create", wei, code)` et `("create2", wei, code, salt)` ; atomes `create.new_address` / `create2.new_address`. |
| **FR-DEC-48** : précompilés | `scobelix/vm.py` — `VM.handle_call()` ; `scobelix/utils/helpers.py` — `precompiled`, `precompiled_var_names` | `addr == 4` → copie mémoire et `memcopy.success` ; `type(addr) == int and addr in precompiled` (clés 1, 2, 3, 5 à 8) → `("precompiled", var_name, nom, args)`, écriture de la zone de retour et `"<nom>.result"` ; toute autre adresse suit le cas ordinaire. |
| **FR-DEC-49** : atomes d'environnement, `selfbalance`, nœuds à opérande, `msize` | `scobelix/vm.py` — `VM.apply_stack()` | Liste d'atomes empilés par leur nom ; `selfbalance` → `("balance", "address")` ; `balance` retire un masque `("mask_shl", 160, 0, 0)` ; `msize` → `setvar _<N>` = `"msize"`. |

Note contextuelle du document source (`balance` sur adresse concrète) : confirmée — le test `addr[:4] == ("mask_shl", 160, 0, 0)` indexe un entier et lève `TypeError` ; vérifié en bac à sable (`push20` puis `balance` : la fonction figure dans `problems`).

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-50** : instructions terminales | `scobelix/vm.py` — `VM.handle_jumps()` | `return`/`revert` → `(op, 0)` si la taille vaut 0, sinon `(op, mem_load(p, n))` ; `("selfdestruct", addr)` ; `(op,)` pour `stop`/`invalid` ; `("invalid",)` pour `UNKNOWN`. |
| **FR-DEC-51** : contrôle de la variation de pile | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/utils/opcode_dict.py` — `stack_diffs` | `if stack.len() - previous_len != opcode_dict.stack_diffs[op]` : quatre `logger.error(…)` dont `opcode {op} not processed correctly, very the code`, l'`assert` étant commenté. |
| **FR-DEC-52** : lignes de diagnostic `--verbose`, retirées avec `--explain` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/decompiler.py` — `dec()` | `apply_stack()` (appelé pour les instructions qui ne sont ni sauts ni terminales) ajoute trois chaînes : pile, ligne vide, `[pos] op [param]` ; avec `--explain`, `dec()` les retire par `rewrite_trace(trace, lambda line: [] if type(line) == str else [line])`. Vérifié en bac à sable (lignes présentes dans `trace` de l'AST et affichées en commentaires ; fonction non reconnue comme constante). |

## 7. Structuration des boucles et des gardes

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-53** : conversion `label` → `while` | `scobelix/whiles.py` — `make()`, `to_while()` | `to_while()` parcourt la suite de la trace jusqu'au premier `if` non garde ; si `jd` n'est présent (via `get_jds()`) que dans une branche, retourne `path, corps, sortie, cond` (ou `is_zero(cond)`) ; `make()` émet `before` (variables remplacées par leurs valeurs initiales), `("while", cond, inside, repr(jd), vars)` puis `remaining` ; `add_path()` recopie `path` avant chaque `goto`, variables remplacées par les réaffectations. |
| **FR-DEC-54** : garde de rejet → `require` | `scobelix/whiles.py` — `to_while()`, `is_revert()` | `is_revert()` : branche d'une instruction `("return", 0)`, `revert` ou `invalid` ; `path.append(("require", is_zero(cond)))` ou `("require", cond)` puis poursuite dans l'autre branche. |

Note contextuelle du document source (retour sans données assimilé à un rejet) : confirmée par le test `line == ("return", 0)` de `is_revert()`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-55** : `goto` → `continue` | `scobelix/whiles.py` — `make()` | `("continue", repr(m.jd), m.setvars)`. |
| **FR-DEC-56** : label non convertible conservé | `scobelix/whiles.py` — `make()`, `to_while()` | `to_while()` renvoie `None` (trace épuisée ou `goto` dans les deux ou aucune branche) ; `make()` fait alors `res.append(line)`. |
| **FR-DEC-57** : suppression des `jumpdest` résiduels | `scobelix/whiles.py` — `make_whiles()` | `rewrite_trace(trace, lambda line: [] if opcode(line) == "jumpdest" else [line])` ; la VM n'émettant pas de tels nœuds, l'étape est en pratique sans effet. |
| **FR-DEC-58** : budget limité à la boucle de simplification | `scobelix/whiles.py` — `make_whiles()` | `make(trace)` est appelé sans budget ; seul `simplify_trace(trace, timeout=timeout)` le reçoit. |

## 8. Boucle de simplification à point fixe

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-59** : point fixe, 40 passes ou 20 au-delà de 2 000 lignes | `scobelix/simplify.py` — `simplify_trace()` | `max_passes = MAX_SIMPLIFY_PASSES_LARGE if len(trace) > LARGE_TRACE_THRESHOLD else 40` ; `while trace != old_trace and count < max_passes and not should_quit()`. |
| **FR-DEC-60** : dépassement du budget | `scobelix/simplify.py` — `should_quit()` dans `simplify_trace()` | `logger.warning("simplify_trace timed out.")` ; la boucle s'arrête, la trace courante passe au post-traitement final. |
| **FR-DEC-61** : progression toutes les 5 passes | `scobelix/simplify.py` — `simplify_trace()` | `if count % 5 == 0: logger.info("Simplify progress %s%% (pass %s/%s)", …)`. |
| **FR-DEC-62** : ordre des passes | `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/postprocess.py` — `cleanup_mul_1()` | Séquence `simplify_exp`, `cleanup_vars`, `cleanup_mems`, `split_setmem` + `split_store`, `cleanup_vars`, `simplify_exp`, `cleanup_mul_1`, `cleanup_msize`, `replace_bytes_or_string_length`, `cleanup_conds`, `loop_to_setmem`, `propagate_storage_in_loops` ; `cleanup_mul_1()` retire `mul 1`, ramène `("bool", entier)` à 1 ou 0 et supprime les masques redondants (stockage, `caller`, chaîne). |
| **FR-DEC-63** : simplification d'expressions mise en cache | `scobelix/simplify.py` — `simplify_exp()` ; `scobelix/utils/helpers.py` — `cached()` | `simplify_exp()` est décorée par `@cached` ; elle traite sommes, produits, masques, comparaisons à termes communs et `mod` par une puissance de deux (`mask_op(…, size=size)`). |
| **FR-DEC-64** : élimination des variables | `scobelix/simplify.py` — `cleanup_vars()`, `replace_var()` | Pour chaque `setvar`, `replace_var()` substitue la valeur dans la suite tant qu'aucune écriture ne l'invalide ; l'affectation n'est conservée que si la variable reste utilisée (`contains()` ou `required_after`). |
| **FR-DEC-65** : nettoyage de la mémoire, sauté au-delà de 2 000 lignes | `scobelix/simplify.py` — `cleanup_mems()`, `replace_mem()`, `MAX_MEM_CLEANUP_TRACE_LEN` | `if len(trace) > MAX_MEM_CLEANUP_TRACE_LEN: logger.debug("cleanup_mems skipped …")` ; sinon remplacement des lectures par la valeur écrite (`replace_mem()`) et suppression des écritures inutilisées (`trace_uses_mem()`). |
| **FR-DEC-66** : découpage des écritures | `scobelix/core/memloc.py` — `split_setmem()`, `split_store()`, `split_or()` | `split_or()` décompose une valeur `or` en champs ; `split_store()` ignore l'écriture d'un champ avec `("storage", s_size, s_off, idx)` lui-même, et remplace `store(idx, mask(storage(idx)))` par des écritures de 0 dans les autres parties de l'emplacement. |
| **FR-DEC-67** : nettoyage des conditions | `scobelix/simplify.py` — `cleanup_conds()` | `arithmetic.eval_bool(cond, symbolic=False)` : `if` décidable remplacé par la branche retenue ; `while` toujours vrai → condition `("bool", 1)` (ramenée à 1 par `cleanup_mul_1()`), toujours faux → supprimé. |
| **FR-DEC-68** : remplacement de `msize` | `scobelix/simplify.py` — `cleanup_msize()` | Parcourt la trace en maintenant `current_msize` = maximum des bornes droites des `setmem` et des boucles (`while_max_memidx()`), substitué à l'atome `msize`. |
| **FR-DEC-69** : boucles d'écriture mémoire → écriture unique | `scobelix/simplify.py` — `loop_to_setmem()`, `_loop_to_setmem()`, `loop_to_setmem_from_storage()` | Corps de deux instructions `setmem` 32 octets + `continue`, pas `diff in (32, -32)`, valeurs finales issues de `parse_counters()` ; valeur 0 ou `("mem", range)` ; variante stockage → mémoire dans `loop_to_setmem_from_storage()`. |
| **FR-DEC-70** : post-traitement final ordonné | `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/core/algebra.py` — `max_to_add()` ; `scobelix/rewriter.py` — `postprocess_exp()`, `postprocess_trace()`, `rewrite_string_stores()` | Après la boucle : `max_to_add`, deux `postprocess_exp` (tableaux dans `data`), `postprocess_trace`, `rewrite_string_stores` (fenêtre de 3 lignes), trois `cleanup_mems` + `cleanup_conds`, `fix_storages` (décalage négatif → 0) + `cleanup_conds`, `readability`, `cleanup_mul_1`. |
| **FR-DEC-71** : renommage lisible et `_msize` | `scobelix/simplify.py` — `readability()`, `replace_while_var()` ; `scobelix/prettify.py` — `prettify()` | Compteur (`parse_counters()`) renuméroté 0, autres variables à partir de 1 en sautant les index déjà présents ; `setmem` à adresse `add(…, max(…))` → `("setvar", "_msize", max)` ; `prettify()` affiche l'index via la liste `idx, s, t, u, v, w, x, y, z, a…h`, puis `var<N>`. |
| **FR-DEC-72** : rejet ramené dans la branche vraie | `scobelix/simplify.py` — `readability()` | `if len(if_false) == 1 and opcode(if_false[0]) == "revert"` → `("if", is_zero(cond), readability(if_false), readability(if_true))`. |

## 9. Heuristiques de lisibilité assumées non fidèles

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-73** : approximations appliquées sans signalement | `scobelix/rewriter.py` (docstring de module) ; `scobelix/simplify.py` — `simplify_exp()` | Le module se présente comme « blatantly mathematically incorrect » ; aucune des réécritures n'ajoute de marqueur à la trace. |
| **FR-DEC-74** : masque 246 → 251 bits | `scobelix/simplify.py` — `simplify_exp()` | `match(exp, ("mask_shl", 246, 5, 0, ":exp"))` → `("mask_shl", 251, 5, 0, …)`, commenté « mathematically incorrect ». |
| **FR-DEC-75** : `if` sur longueur modulo 32 → branche vraie | `scobelix/rewriter.py` — `postprocess_trace()` | Motifs `("iszero", ("storage", 5, 0, l))` et `("iszero", ("mask_shl", 5, 0, 0, l))` ; retourne `if_true` si un tableau de longueur `l` y figure. |
| **FR-DEC-76** : chaînes en stockage, cas courts masqués | `scobelix/rewriter.py` — `postprocess_trace()` | `("if", ("lt", 31, some_len), …)` → `[first] + deep_false` (écriture) ; motif de lecture `iszero(mask_shl(255, 1, 0, and(storage, …)))` avec `lt 31 length` imbriqué → `deep_true`. |
| **FR-DEC-77** : écriture de longueur + deux boucles → tableau en stockage | `scobelix/rewriter.py` — `rewrite_string_stores()` | Fenêtre de trois lignes (`store` de longueur, `while` de recopie `mem` → stockage, second `while`) remplacée par `("store", 256, 0, ("array", "", ("sha3", idx)), ("arr", src, …))`. |
| **FR-DEC-78** : signe d'une somme par variantes | `scobelix/core/algebra.py` — `add_ge_zero()` ; `scobelix/core/variants.py` — `variants()`, `possibilities()` | Chaque variable reçoit `MAX_number` (2^230 − 1) puis 0, sauf `mem[64]` → 96 et `calldatasize` → 6 ; `add_ge_zero()` renvoie vrai si toutes les variantes sont ≥ 0, faux si toutes < 0, `None` sinon (ou si une variante n'est pas concrète). |
| **FR-DEC-79** : constante négative au-delà de −8^22 | `scobelix/simplify.py` — `simplify_exp()` ; `scobelix/core/arithmetic.py` — `to_real_int()` | `if type(exp) == int and to_real_int(exp) > -(8**22): return to_real_int(exp)` ; `to_real_int()` ne change que les valeurs dont le bit 255 vaut 1. |
| **FR-DEC-80** : structure non traitable → assertion, échec de la fonction ou de l'emplacement | `scobelix/simplify.py` — `move_right()` ; `scobelix/sparser.py` — `_sparser_resilient()` | `assert exp in terms  # deep embedding unsupported` ; levée dans `dec()`, l'assertion fait échouer la fonction ; levée pendant la reconstruction du stockage, elle est traitée par l'isolement emplacement par emplacement. |

Note contextuelle du document source (branche vraie comparée à elle-même) : confirmée — dans `postprocess_trace()`, `false_arr = find_f_list(if_true, find_arr_l)` porte sur `if_true`.

## 10. Pliage des chemins pour l'affichage

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-81** : dépliage en chemins puis fusion | `scobelix/folder.py` — `fold()`, `as_paths()`, `meta_fold_paths()`, `fold_aux()` | `as_paths()` produit un chemin par combinaison de branches (condition ou `is_zero(cond)`) ; `meta_fold_paths()` fusionne préfixes et suffixes ; `fold_aux()` produit un `if` sans `else` quand la branche vraie se termine par une instruction de `TERMINATING`. |
| **FR-DEC-82** : instructions terminales | `scobelix/folder.py` — `TERMINATING` | Tuple `return`, `stop`, `selfdestruct`, `invalid`, `assert_fail`, `revert`, `continue`, `undefined` ; `assert_fail` n'étant jamais produit, la liste effective est celle du document. |
| **FR-DEC-83** : pliage réservé à la vue texte | `scobelix/contract.py` — `Contract.make_ast()` ; `scobelix/function.py` — `Function.serialize()` | Seul `make_ast()` appelle `folder.fold()` pour construire `func.ast`, utilisé par `Function._print()` ; `serialize()` exporte `self.trace`, que lit le générateur Solidity. |
| **FR-DEC-84** : échec du pliage → `folder failed in a function.` et trace d'origine | `scobelix/folder.py` — `fold()` | `except Exception: logger.exception(f"folder failed in a function."); return trace`. |

## 11. Représentation intermédiaire (référence)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-DEC-85** : formes d'instructions | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()`, `VM.handle_call()` ; `scobelix/whiles.py` — `make()`, `to_while()` | Les n-uplets `setmem`, `store`, `tstore`, `log`, `call`/`staticcall`/`delegatecall`/`callcode`, `create`/`create2`, `precompiled`, terminaisons et `undefined` sont émis par la VM ; `while`, `continue`, `require` et `label` résiduel par la structuration ; `setvar` par la VM (`_<N>`), la structuration (variables de boucle) et `readability()` (`_msize`). |
| **FR-DEC-86** : formes d'expressions | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/sparser.py` — `repl_stor()` ; `scobelix/contract.py` — `Contract.postprocess()` | Atomes, `mem`, `var`, `cd`, tranches (`ARRAY_OPCODES` de `scobelix/utils/helpers.py`), `storage` produits par la VM ; `stor` après `repl_stor()` ; `param` par le remplacement `replace_names` de `postprocess()` ; opérateurs issus de `scobelix/core/arithmetic.py` et `scobelix/core/algebra.py`. |
| **FR-DEC-87** : sémantique de `mask_shl` | `scobelix/core/algebra.py` — `mask_op()`, `apply_mask()` ; `OPCODES.md` | `apply_mask()` évalue `mask_shl(size, offset, shl, val)` en bits ; les identités du document reprennent celles de `OPCODES.md` à la racine du dépôt. |
| **FR-DEC-88** : plage `range` (début, longueur) en octets | `scobelix/vm.py` — `mem_load()` | `("mem", ("range", pos, size))`, taille en octets. |
| **FR-DEC-89** : atomes de résultat | `scobelix/vm.py` — `VM.handle_call()`, `VM.apply_stack()` | Chaînes `ext_call.success`, `memcopy.success`, `callcode.return_code`, `create.new_address`, `create2.new_address`, `"{}.result".format(…)` et variables `delegatecall_<N>.success`. |
| **FR-DEC-90** : sérialisation en listes, nœuds résiduels en texte | `scobelix/function.py` — `Function.serialize()` ; `scobelix/vm.py` — `Node.__str__()` | `json_safe()` convertit n-uplets en listes et tout objet non natif par `str()` ; `Node.__str__()` rend `Node({self.jd})` ; les identifiants de `while`/`continue` sont déjà des chaînes `repr(jd)` de cette forme. |

---

Navigation : [../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md) · [../README.md](../README.md)
