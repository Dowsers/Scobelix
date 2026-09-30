# Traçabilité d'architecture — Reconstruction Solidity (solgen) et validation par compilation

Ce document trace chaque exigence de [../specification-fonctionnelle/generation-solidity.md](../specification-fonctionnelle/generation-solidity.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble et entrée

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-01** : seule entrée l'AST JSON, AST nul ou vide = `{}` | `scobelix/solgen/emitter.py` — `generate_solidity()`, `SolidityEmitter.__init__()` | `SolidityEmitter(decompilation.json or {})` ; le constructeur ne lit que `stor_defs` et `functions`, `generate()` y ajoute `problems`, tous par `.get()` avec valeur par défaut. |
| **FR-SOL-02** : AST vide → contrat minimal, confiance et avertissements vides | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | Sans fonction ni définition, seules les lignes d'en-tête, `contract DecompiledContract {`, l'événement de repli et `}` sont produites ; `self.confidence` et `self.warnings` restent vides ; aucun avertissement n'est ajouté pour un AST vide. |
| **FR-SOL-03** : ni échec ni omission silencieuse sur construction inconnue | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._expr()` | Les branches finales de `_emit_stmt()` et `_expr()` produisent un marqueur `unresolved` plutôt qu'une exception. |

Note contextuelle du document source (échec sur masque à paramètre symbolique) : confirmée — dans `SolidityEmitter._expr()`, la comparaison `if off >= 0:` et le calcul `(1 << size)` supposent des entiers ; vérifié en bac à sable : le bytecode `6004356024351c60005260206000f3` produit `mask_shl(256, -_param2, -_param2, _param1)` et `generate_solidity()` lève `TypeError`, la commande `--solidity` sortant avec le code 1.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-04** : aucune prétention de fidélité sémantique | `scobelix/solgen/emitter.py` (docstring de module), `SolidityEmitter.generate()` | La docstring déclare « NOT a recompiler » ; l'en-tête généré affirme « This is an approximation, NOT verified/compiled original ». Exigence de posture, sans autre mécanisme. |

## 2. Structure du contrat produit

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-05** : sept lignes d'en-tête puis ligne vide | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | Sept `lines.append()` littéraux (commentaires, `SPDX-License-Identifier: UNKNOWN`, `pragma solidity ^0.8.0;`) suivis de `lines.append("")`. |
| **FR-SOL-06** : contrat `DecompiledContract`, événement de repli en premier membre | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | `contract DecompiledContract {` puis `event ScobelixUnresolvedEvent(string detail); // approximation: real event ABI not reconstructed`. |
| **FR-SOL-07** : événements connus émis, triés par nom | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_event_declarations()` | `sorted(self._used_events.items())`, alimenté par `_resolve_event()` pendant la traduction des fonctions (effectuée avant l'assemblage) ; format `f"{t}{' indexed' if i else ''} {n}"`. |
| **FR-SOL-08** : variables d'état depuis `stor_defs` | `scobelix/solgen/emitter.py` — `SolidityEmitter.__init__()`, `SolidityEmitter._emit_state_vars()`, `SolidityEmitter._sol_type_for_stor()`, `SolidityEmitter._collect_map_depths()` | `stor_by_loc[loc] = (name, kind)` (la dernière définition écrase) ; tri `key=lambda kv: str(kv[0])` ; mapping de profondeur `_map_depths.get(loc, 1)` calculée sur les nœuds `map` imbriqués des traces, `uint256[]` pour un tableau, `uint256` précédé de `// storage slot {loc}` sinon ; `lines.append("")` en fin de liste non vide. |
| **FR-SOL-09** : assainissement des identifiants | `scobelix/solgen/emitter.py` — `_safe_ident()` | `re.sub(r"[^A-Za-z0-9_]", "_", str(name))`, préfixe `v_` si vide ou commençant par un chiffre. |
| **FR-SOL-10** : variables synthétiques `stor_extra_<N>` | `scobelix/solgen/emitter.py` — `SolidityEmitter._synthetic_stor_var()`, `SolidityEmitter._declare_extra_stor_vars()` | `ident = f"stor_extra_{len(self._extra_stor_vars)}"` à la première rencontre d'une clé textuelle ; déclarations `uint256 internal …;` insérées après les variables d'état. |
| **FR-SOL-11** : ordre fonctions, commentaires d'échec, accolade, saut de ligne final | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | Ajout des blocs de fonctions, puis des commentaires `problems`, puis `}` et `""` ; `"\n".join(lines)` produit donc un saut de ligne final. |
| **FR-SOL-12** : en-tête de chaque fonction | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_function()`, `SolidityEmitter._unique_function_name()` | Ligne vide et commentaire `// reconstructed from function …` (nom entre accents graves) ; `hash_ == "_fallback"` → `fallback(bytes calldata) external payable returns (bytes memory)` ; sinon `function {fname}() external{payable} returns (bytes memory)`, `fname` tronqué au premier `(`, `"unnamed"` si vide, suffixé `_2`, `_3`… |
| **FR-SOL-13** : paramètres décodés en `uint256` depuis `msg.data` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_function()` | `for offset in sorted(int(o) for o in params.keys())` → `uint256 {nom} = uint256(bytes32(msg.data[{offset}:{offset + 32}]));`, le type inféré étant ignoré. |
| **FR-SOL-14** : `loopvar_<N>` déclarées une fois en tête | `scobelix/solgen/emitter.py` — `SolidityEmitter._collect_loopvars()`, `SolidityEmitter._emit_function()` | Parcours récursif de la trace : tout nœud `setvar`/`var` d'identifiant entier ; déclarations `uint256 loopvar_{idx};` triées avant le corps. |

## 3. Traduction des instructions et des expressions

### 3.1 Instructions

L'indentation (huit espaces puis quatre par niveau) provient de `pad = "    " * indent` dans `SolidityEmitter._emit_stmt()`, appelé avec `indent=2` pour le corps.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-15** : `if` / `else` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` | `if ({cond}) {` … `}` ; `if false_branch:` remplace la dernière ligne par `} else {` et ajoute la branche fausse. |
| **FR-SOL-16** : `while` et `continue` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._setvar_lines()` | Affectations `loopvar_N = …;` issues des `setvar` puis `while (…) {` ; `continue` : réaffectations puis `continue;`. |
| **FR-SOL-17** : `return` | `scobelix/solgen/emitter.py` — `SolidityEmitter._return_expr()`, `SolidityEmitter._as_call_result_ret()` | Variable `…_ret_N` du dernier appel si la valeur désigne des données de retour, sinon `abi.encode(<expr>)`. |
| **FR-SOL-18** : `revert` par ordre de priorité | `scobelix/solgen/emitter.py` — `SolidityEmitter._revert_stmt()`, `SolidityEmitter._extract_revert_string()` | `val == 0 or val is None` → `revert();` ; chaîne littérale dans un `mask_shl` de `data` → `revert("…")` échappé ; `data` d'au moins deux termes finissant par 17 → commentaire `panic(0x11)` ; sinon commentaire d'approximation. |
| **FR-SOL-19** : `invalid` et `stop` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` | `assert(false); // approximation: INVALID opcode` et `return "";`. |
| **FR-SOL-20** : écritures de stockage | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._resolve_storage()` | Branches `store` (indices 3 et 4) et `set` (indices 1 et 2) : `{cible} = {self._expr_as_uint256(val)};`. |
| **FR-SOL-21** : `label` et `setvar` isolés | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` | `// label {stmt[1]} (no-op)` et `{loopvar_N} = {expr};`. |
| **FR-SOL-22** : `selfdestruct` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` | Commentaire d'approximation puis `selfdestruct(payable(address(uint160(…))));` (`msg.sender` si le bénéficiaire manque). |
| **FR-SOL-23** : toute autre instruction → `unresolved` + rejet | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` | Branche finale : `self._unresolved_count += 1`, `warnings.append(f"unresolved statement opcode: {op!r}")`, `// unresolved: …` et `revert("scobelix: unsupported construct");`. `staticcall`, `create`, `create2`, `precompiled`, `setmem`, `tstore`, `require`, `undefined` et les chaînes du mode `--verbose` n'ont pas de branche dédiée. |
| **FR-SOL-24** : représentation tronquée à 80 caractères | `scobelix/solgen/emitter.py` — `_short_repr()` | `r = repr(obj)` ; `r[: limit - 3] + "..."` si plus long que 80 ; `r.replace("\n", " ")`. |

Note contextuelle du document source (instructions fréquentes traduites en rejet) : confirmée par la branche finale de `_emit_stmt()`, qui émet `revert("scobelix: unsupported construct")` pour chacune.

### 3.2 Événements

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-25** : reconnaissance des événements connus | `scobelix/solgen/emitter.py` — `SolidityEmitter._resolve_event()`, `SolidityEmitter._log_stmt()` ; `scobelix/solgen/event_signatures.py` — `KNOWN_EVENT_SIGNATURES` | Premier sujet entier recherché dans la table (topic0 = keccak-256 de la signature, calculé par `_topic0()`) ; refus si un type est un tableau, si `num_indexed != len(topics) - 1` ou si plus d'une donnée non indexée ; arguments reconstitués dans l'ordre de déclaration ; `emit {name}({args});`. |
| **FR-SOL-26** : conversion des arguments | `scobelix/solgen/emitter.py` — `SolidityEmitter._event_arg_expr()` | `address(uint160(…))`, `(… != 0)` ou `_expr_as_uint256()`. |
| **FR-SOL-27** : journal non reconnu | `scobelix/solgen/emitter.py` — `SolidityEmitter._log_stmt()` | Avertissement `log/event reconstruction is approximate (no ABI match)`, commentaire d'approximation et `emit ScobelixUnresolvedEvent("{_short_repr(stmt)}");`. |

Note contextuelle du document source (`AdminChanged` jamais reconnu) : confirmée — l'entrée `AdminChanged` de `_EVENTS` a `[False, False]` comme drapeaux d'indexation, soit deux données non indexées, cas refusé par `_resolve_event()`.

### 3.3 Appels externes

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-28** : traduction de `call`, `callcode`, `delegatecall` | `scobelix/solgen/emitter.py` — `SolidityEmitter._call_stmt()` | Compteur `self._call_counters[op]` (jamais remis à zéro entre fonctions) ; `sol_op = "delegatecall" if op in ("delegatecall", "codecall") else "call"` ; cible `address(uint160({_expr_as_uint256(stmt[2])}))` ; `msg.data` transmis tel quel. |
| **FR-SOL-29** : références au dernier appel | `scobelix/solgen/emitter.py` — `SolidityEmitter._as_call_result_ok()`, `SolidityEmitter._as_call_result_ret()` | Toute variable nommée finissant par `.success` ou `.return_data`, ou l'atome `ext_call.return_data`, est associée à `self._last_call_result`, mis à jour par `_call_stmt()`. |

Note contextuelle du document source (`ext_call.success` non traduit, garde toujours vraie) : confirmée — `ext_call.success` est une chaîne, non une variable `("var", …)`, et `SolidityEmitter._atom()` n'en traite pas le cas ; vérifié en bac à sable : un appel suivi d'une garde produit `if ((0 /* unresolved atom: 'ext_call.success' */ == 0)) { revert(); }` avec une confiance `high`.

### 3.4 Expressions

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-30** : entiers, négatifs repliés sur 2^256 | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | `wrapped = (1 << 256) + exp` et `f"{wrapped} /* {exp} */"` ; les booléens Python sont traités avant les entiers. |
| **FR-SOL-31** : opérateurs binaires coercés en `uint256` | `scobelix/solgen/emitter.py` — `SolidityEmitter._BINOPS`, `SolidityEmitter._expr()` | Table `_BINOPS` ; `if op in self._BINOPS and len(exp) == 3` → `({left} {sym} {right})` avec les deux opérandes passés par `_expr_as_uint256()` ; `add` à plus de deux termes joint par ` + `. |

Note contextuelle du document source (opérateurs signés sans commentaire) : confirmée — `sdiv`, `smod`, `slt`, `sgt`, `sle`, `sge` sont associés aux symboles non signés dans `_BINOPS`, sans avertissement.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-32** : tests de nullité et `not` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()`, `SolidityEmitter._produces_bool()` | `iszero` : `(!ok)` via `_as_call_result_ok()`, `(!expr)` si `_produces_bool()` (ensemble `_BOOL_PRODUCING_OPS`), sinon `(expr == 0)` ; `not` → `(~expr)`. |
| **FR-SOL-33** : paramètres, variables de boucle, autres variables | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | `param` → `_safe_ident()` ; `var` entier → `loopvar_N` ; autre `var` non associée à un appel → avertissement `unresolved named var: …` et `_synthetic_stor_var(f"var:{ident}")`. |
| **FR-SOL-34** : résolution des emplacements de stockage | `scobelix/solgen/emitter.py` — `SolidityEmitter._resolve_storage()`, `SolidityEmitter._storage_base_name()` | `loc` → nom déclaré ou variable synthétique (sans décompte) ; `map` → `{base}[{clé en uint256}]` récursif ; toute autre forme → décompte, avertissement `unresolved storage index shape: …` et variable synthétique ; `stor` en lecture passe par la même fonction. |
| **FR-SOL-35** : traduction des masques à paramètres entiers | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | Idiome du sélecteur (`size == 256`, décalages ±224, `cd` 0) → `uint32(bytes4(msg.sig))` ; `size == _ADDRESS_MASK_SIZE` (160) → `address(uint160(…))` ; `off >= 0` → `(val & mask)` puis `<<`/`>>` ; sinon avertissement `mask_shl(…) not exactly reconstructed` et commentaire `/* approximation: … */`. |
| **FR-SOL-36** : `shl`, `shr`, `sar` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | `({val} << {n})` ou `({val} >> {n})` ; avertissement `sar approximated as logical (unsigned) shift` pour `sar`. La VM représentant les décalages par des masques, ces nœuds n'apparaissent pas dans les traces produites par le système. |
| **FR-SOL-37** : `sha3` approximé | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | Avertissement `sha3 region reconstruction is approximate` ; `keccak256(msg.data[0:0])` suivi de `/* approximation: sha3(…) */` (deux opérandes) ou `/* approximation: <repr> */`. |
| **FR-SOL-38** : données d'appel, blob de données, booléens | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | Branches `cd`, `call.data`, `data` (`hex"" /* approximation: raw data blob */`) et `bool` (`true`/`false`). |
| **FR-SOL-39** : atomes | `scobelix/solgen/emitter.py` — `SolidityEmitter._atom()` | `calldatasize`, `caller`, `address`, `gas`/`gas_remaining`, `ext_call.return_data` (si un appel précède), chaîne entre apostrophes ; sinon `0 /* unresolved atom: … */`, sans décompte ni avertissement. |

Note contextuelle du document source (branche `tx.origin`/`block.*` inatteignable) : confirmée — dans `_expr()`, les tests `exp in ("origin",)`, `("timestamp",)`, `("number",)` suivent `if isinstance(exp, str): return self._atom(exp)` et ne sont jamais atteints par une chaîne. Vérifié en bac à sable par la génération sur un AST factice : les quatre atomes sont rendus `0 /* unresolved atom: … */`, la confiance restant `high`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-40** : conversions en contexte `uint256` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr_as_uint256()` | Masque de 160 bits → `uint256(uint160(…))` ; `bool` → `1`/`0` ; `caller` → `uint256(uint160(msg.sender))` ; `address` → `uint256(uint160(address(this)))`. |
| **FR-SOL-41** : expressions non traduites | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` | Branche finale : décompte, avertissement `unresolved expression opcode: …`, `0 /* unresolved: … */` ; valeur ni entière, ni chaîne, ni n-uplet (par exemple `None` ou un nombre à virgule) → `0 /* unresolved atom: … */` avec décompte. |
| **FR-SOL-42** : marqueurs `approximation:` et `unresolved:` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._expr()`, `SolidityEmitter._atom()` | Tous les replis décrits ci-dessus insèrent l'un de ces marqueurs littéraux ; `tests/test_solgen.py` vérifie la présence du marqueur `approximation` sur le bytecode de proxy de référence. |

## 4. Confiance, avertissements et fonctions en échec

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-43** : niveau de confiance par fonction | `scobelix/solgen/emitter.py` — `SolidityEmitter._confidence_for()`, `SolidityEmitter.generate()` | Compteurs `_unresolved_count` et `_total_node_count` remis à zéro par fonction (le second incrémenté par `_emit_stmt()` et `_expr()`) ; `total == 0` → `medium`, ratio nul → `high`, `< 0.1` → `medium`, sinon `low` ; clé `func.get("hash", "?")`. |
| **FR-SOL-44** : liste cumulée des avertissements | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | `self.warnings` est une liste unique alimentée par `append()` sur tout le contrat, retournée telle quelle dans `SolgenResult`. |

Note contextuelle du document source (seuls certains replis abaissent la confiance) : confirmée — `_unresolved_count` n'est incrémenté que dans la branche finale de `_emit_stmt()`, les formes d'emplacement non résolues de `_resolve_storage()`, la branche finale de `_expr()` et les valeurs non textuelles ; `_atom()`, les masques à décalage négatif, `sar`, `sha3`, les variables nommées et `_log_stmt()` ne l'incrémentent pas.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-45** : fonctions en échec → deux commentaires, sans confiance | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` | `for selector, fname in problems.items()` : `""`, `// decompilation failed for selector {selector} ({fname})`, `// @custom:scobelix-confidence none` ; les fonctions en échec ne figurant pas dans `functions`, `confidence` n'a pas d'entrée pour elles. |

Note contextuelle du document source (pas de fonction qui rejette) : confirmée — la boucle sur `problems` n'émet que ces deux commentaires ; le test `test_unresolvable_function_gets_explicit_stub_not_silently_dropped` de `tests/test_solgen.py` ne vérifie que la présence des chaînes, et la docstring de module comme le `README.md` racine parlent à tort d'un « explicit reverting stub ».

## 5. Validation par compilation

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-SOL-46** : compilateur explicite ou `PATH`, absence → `skipped` | `scobelix/solgen/validate.py` — `validate_solidity()` | `solc = solc_path or shutil.which("solc")` ; `None` → `ValidationResult(status="skipped", errors=[], warnings=["solc not found on PATH - validation skipped"])`. |
| **FR-SOL-47** : fichier `Decompiled.sol` temporaire, `--bin`, capture texte, délai | `scobelix/solgen/validate.py` — `validate_solidity()` | `tempfile.TemporaryDirectory()` ; `sol_path = Path(tmpdir) / "Decompiled.sol"` ; `subprocess.run([solc, "--bin", str(sol_path)], capture_output=True, text=True, timeout=timeout)` avec `timeout: int = 30`. |
| **FR-SOL-48** : délai dépassé ou lancement impossible → `skipped` | `scobelix/solgen/validate.py` — `validate_solidity()` | `except subprocess.TimeoutExpired` → `solc timed out after {timeout}s` ; `except OSError` → `solc invocation failed: {e}` ; `tests/test_solgen_validate.py` couvre le chemin inexistant. |
| **FR-SOL-49** : lignes `Error` / `Warning` | `scobelix/solgen/validate.py` — `validate_solidity()` | `result.stderr.splitlines()` filtrées par `line.strip().startswith("Error")` et `startswith("Warning")`. |
| **FR-SOL-50** : statuts `invalid` / `valid` | `scobelix/solgen/validate.py` — `validate_solidity()` | `if result.returncode != 0 or errors` → `invalid` avec `errors or [result.stderr]` ; sinon `valid`, `errors=[]` ; `warnings` dans les deux cas. |
| **FR-SOL-51** : `valid` n'atteste que la compilabilité | `scobelix/solgen/validate.py` — `validate_solidity()` (docstring) | La docstring précise que la validation « says nothing about whether the generated code is a *faithful* reconstruction » ; exigence d'interprétation, sans mécanisme propre. |

---

Navigation : [../specification-fonctionnelle/generation-solidity.md](../specification-fonctionnelle/generation-solidity.md) · [../README.md](../README.md)
