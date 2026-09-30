# Matrice de couverture des exigences

Cette matrice recense, en une seule vue, les 380 exigences fonctionnelles du répertoire `docs/` et leur point d'implémentation dans le code. Elle est dérivée mécaniquement des documents de traçabilité détaillés du présent répertoire — pour l'explication de chaque exigence (pas seulement sa localisation), se reporter au fichier correspondant.

## Synthèse

| Domaine | Préfixe | Exigences | Document de traçabilité |
|---|---|---|---|
| Architecture et interfaces d'appel de Scobelix | `FR-ARCH` | 71 | [architecture.md](architecture.md) |
| Reconstruction Solidity (solgen) et validation par compilation | `FR-SOL` | 51 | [generation-solidity.md](generation-solidity.md) |
| Intégration de Scobelix dans son environnement | `FR-INT` | 32 | [integration.md](integration.md) |
| Pipeline de décompilation : désassemblage, exécution symbolique, structuration et simplification | `FR-DEC` | 90 | [pipeline-decompilation.md](pipeline-decompilation.md) |
| Reconstruction des fonctions, des paramètres et de la structure du stockage | `FR-STOR` | 36 | [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) |
| Résolution des signatures 4 octets et régénération de la base locale | `FR-SIG` | 27 | [resolution-signatures.md](resolution-signatures.md) |
| Sorties produites par Scobelix | `FR-SOR` | 51 | [sorties.md](sorties.md) |
| Spécification de paramétrage des bases de signatures de Scobelix | `FR-PARAM` | 22 | [parametrage-signatures.md](parametrage-signatures.md) |
| **Total** | | **380** | |

**380/380 exigences couvertes** — chaque identifiant apparaît au moins une fois ci-dessous, vérifié mécaniquement (aucun manquant, aucun orphelin).

## Détail par domaine

### Architecture et interfaces d'appel de Scobelix (`FR-ARCH`)

Exigences détaillées dans [architecture.md](architecture.md), énoncés fonctionnels dans [../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-ARCH-01` | `scobelix/decompiler.py` — `decompile_bytecode()`, `decompile_address()` ; `scobelix/__main__.py` — `main()` |
| `FR-ARCH-02` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-03` | `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-ARCH-04` | `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-ARCH-05` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-06` | `scobelix/decompiler.py` — classe `Decompilation` |
| `FR-ARCH-07` | `scobelix/decompiler.py` — `decompile_bytecode()` ; `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-ARCH-08` | `scobelix/decompiler.py` — `decompile_address()` ; `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-ARCH-09` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-10` | `scobelix/solgen/emitter.py` — `generate_solidity()` |
| `FR-ARCH-11` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-ARCH-12` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-ARCH-13` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-14` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-ARCH-15` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-16` | `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-ARCH-17` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-ARCH-18` | `scobelix/function.py` — `Function.serialize()`, `Function._print()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-ARCH-19` | `scobelix/decompiler.py` — constantes `FUNCTION_TIMEOUT`, `VM_RUN_TIMEOUT`, `WHILES_TIMEOUT` ; `scobelix/loader.py` — `LOADER_TIMEOUT` ; `scobelix/vm.py` — `MAX_NODE_COUNT` |
| `FR-ARCH-20` | `scobelix/decompiler.py` — `dec()` dans `_decompile_with_loader()` |
| `FR-ARCH-21` | `scobelix/decompiler.py` — `dec()` ; `scobelix/vm.py` — `VM.run()`, `should_quit()` |
| `FR-ARCH-22` | `scobelix/whiles.py` — `make_whiles()` ; `scobelix/simplify.py` — `simplify_trace()` |
| `FR-ARCH-23` | `scobelix/loader.py` — `Loader.run()` |
| `FR-ARCH-24` | `scobelix/vm.py` — `should_quit()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/decompiler.py` — `dec()` |
| `FR-ARCH-25` | `scobelix/vm.py` — `MAX_NODE_COUNT`, `should_quit()`, `VM.handle_jumps()` |
| `FR-ARCH-26` | `scobelix/decompiler.py`, `scobelix/loader.py`, `scobelix/vm.py` (conversions `int()` au niveau module) ; `scobelix/solgen/__init__.py` |
| `FR-ARCH-27` | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-ARCH-28` | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `OUT_PATH` |
| `FR-ARCH-29` | `scobelix/simplify.py` — `LARGE_TRACE_THRESHOLD`, `MAX_SIMPLIFY_PASSES_LARGE`, `MAX_MEM_CLEANUP_TRACE_LEN`, `simplify_trace()` ; `scobelix/vm.py` — `VM.run()`, `VM.handle_jumps()` ; `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` ; `scobelix/utils/helpers.py` — `cache_dir()` |
| `FR-ARCH-30` | `pyproject.toml` — clé `python` de `[tool.poetry.dependencies]` |
| `FR-ARCH-31` | `scobelix/decompiler.py` — `dec()` ; `README.md` (section « Caveats ») |
| `FR-ARCH-32` | `pyproject.toml` — dépendance `web3` ; `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/solgen/event_signatures.py` — `_topic0()` ; `scobelix/tools/build_local_sigs.py` — `compute_selector()` |
| `FR-ARCH-33` | `scobelix/__main__.py` — `main()` ; `scobelix/utils/helpers.py` — `cache_dir()` |
| `FR-ARCH-34` | `pyproject.toml` ; `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-ARCH-35` | `scobelix/data/abi_dump.xz`, `scobelix/data/local_sigs.json` ; `scobelix/utils/supplement.py` — `check_supplements()`, `LOCAL_SIGS_BULK_PATH` |
| `FR-ARCH-36` | `scobelix/utils/helpers.py` — `cached()` ; `scobelix/stack.py` — `Stack.simplify()` ; `scobelix/core/algebra.py` — `mask_op()`, `ge_zero()` ; `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-ARCH-37` | `scobelix/sparser.py` — `used_locs`, `replace_names_in_assoc()`, `replace_names_in_assoc_bool()` ; `scobelix/loader.py` — `Loader.signatures` |
| `FR-ARCH-38` | `scobelix/vm.py` — `VM.__init__()` |
| `FR-ARCH-39` | `scobelix/loader.py` — `Loader.run()` ; `scobelix/folder.py` — `fold()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-ARCH-40` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-41` | `scobelix/loader.py` — `Loader.load_binary()`, `Loader.load_addr()` ; `scobelix/contract.py` — `Contract.make_asts()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-42` | `scobelix/decompiler.py` — classe `TimeoutInterrupt` |
| `FR-ARCH-43` | `pyproject.toml` — `[tool.poetry.scripts]` ; `scobelix/__main__.py` — `main()` |
| `FR-ARCH-44` | `scobelix/__main__.py` — `parse_args()` |
| `FR-ARCH-45` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-46` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-47` | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-48` | `scobelix/__main__.py` — `main()`, `parse_args()` |
| `FR-ARCH-49` | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-50` | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-51` | `scobelix/__main__.py` — `parse_args()`, `print_decompilation()` |
| `FR-ARCH-52` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-53` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-54` | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()` ; `scobelix/prettify.py` — `explain()`, `explain_text()` ; `scobelix/decompiler.py` — `dec()` |
| `FR-ARCH-55` | `scobelix/prettify.py` — `explain()`, `explain_text()` |
| `FR-ARCH-56` | `scobelix/__main__.py` — `parse_args()` |
| `FR-ARCH-57` | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-58` | `scobelix/decompiler.py` — `decompile_bytecode()`, `decompile_address()` |
| `FR-ARCH-59` | `scobelix/decompiler.py` — classe `Decompilation` |
| `FR-ARCH-60` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-61` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-62` | `scobelix/solgen/emitter.py` — `generate_solidity()`, classe `SolgenResult`, `SolidityEmitter.generate()` |
| `FR-ARCH-63` | `scobelix/solgen/validate.py` — `validate()`, `validate_solidity()`, classe `ValidationResult` |
| `FR-ARCH-64` | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-ARCH-65` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-66` | `scobelix/decompiler.py` — `dec()` |
| `FR-ARCH-67` | `scobelix/__main__.py` — `main()` ; `scobelix/matcher.py` |
| `FR-ARCH-68` | (aucun code) |
| `FR-ARCH-69` | `scobelix/tools/build_local_sigs.py` — `main()`, `ABI_ROOTS`, `OUT_PATH` |
| `FR-ARCH-70` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-ARCH-71` | `scobelix/tools/build_local_sigs.py` ; `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` |

### Reconstruction Solidity (solgen) et validation par compilation (`FR-SOL`)

Exigences détaillées dans [generation-solidity.md](generation-solidity.md), énoncés fonctionnels dans [../specification-fonctionnelle/generation-solidity.md](../specification-fonctionnelle/generation-solidity.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-SOL-01` | `scobelix/solgen/emitter.py` — `generate_solidity()`, `SolidityEmitter.__init__()` |
| `FR-SOL-02` | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-SOL-03` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._expr()` |
| `FR-SOL-04` | `scobelix/solgen/emitter.py` (docstring de module), `SolidityEmitter.generate()` |
| `FR-SOL-05` | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-SOL-06` | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-SOL-07` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_event_declarations()` |
| `FR-SOL-08` | `scobelix/solgen/emitter.py` — `SolidityEmitter.__init__()`, `SolidityEmitter._emit_state_vars()`, `SolidityEmitter._sol_type_for_stor()`, `SolidityEmitter._collect_map_depths()` |
| `FR-SOL-09` | `scobelix/solgen/emitter.py` — `_safe_ident()` |
| `FR-SOL-10` | `scobelix/solgen/emitter.py` — `SolidityEmitter._synthetic_stor_var()`, `SolidityEmitter._declare_extra_stor_vars()` |
| `FR-SOL-11` | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-SOL-12` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_function()`, `SolidityEmitter._unique_function_name()` |
| `FR-SOL-13` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_function()` |
| `FR-SOL-14` | `scobelix/solgen/emitter.py` — `SolidityEmitter._collect_loopvars()`, `SolidityEmitter._emit_function()` |
| `FR-SOL-15` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` |
| `FR-SOL-16` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._setvar_lines()` |
| `FR-SOL-17` | `scobelix/solgen/emitter.py` — `SolidityEmitter._return_expr()`, `SolidityEmitter._as_call_result_ret()` |
| `FR-SOL-18` | `scobelix/solgen/emitter.py` — `SolidityEmitter._revert_stmt()`, `SolidityEmitter._extract_revert_string()` |
| `FR-SOL-19` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` |
| `FR-SOL-20` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._resolve_storage()` |
| `FR-SOL-21` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` |
| `FR-SOL-22` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` |
| `FR-SOL-23` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()` |
| `FR-SOL-24` | `scobelix/solgen/emitter.py` — `_short_repr()` |
| `FR-SOL-25` | `scobelix/solgen/emitter.py` — `SolidityEmitter._resolve_event()`, `SolidityEmitter._log_stmt()` ; `scobelix/solgen/event_signatures.py` — `KNOWN_EVENT_SIGNATURES` |
| `FR-SOL-26` | `scobelix/solgen/emitter.py` — `SolidityEmitter._event_arg_expr()` |
| `FR-SOL-27` | `scobelix/solgen/emitter.py` — `SolidityEmitter._log_stmt()` |
| `FR-SOL-28` | `scobelix/solgen/emitter.py` — `SolidityEmitter._call_stmt()` |
| `FR-SOL-29` | `scobelix/solgen/emitter.py` — `SolidityEmitter._as_call_result_ok()`, `SolidityEmitter._as_call_result_ret()` |
| `FR-SOL-30` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-31` | `scobelix/solgen/emitter.py` — `SolidityEmitter._BINOPS`, `SolidityEmitter._expr()` |
| `FR-SOL-32` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()`, `SolidityEmitter._produces_bool()` |
| `FR-SOL-33` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-34` | `scobelix/solgen/emitter.py` — `SolidityEmitter._resolve_storage()`, `SolidityEmitter._storage_base_name()` |
| `FR-SOL-35` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-36` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-37` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-38` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-39` | `scobelix/solgen/emitter.py` — `SolidityEmitter._atom()` |
| `FR-SOL-40` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr_as_uint256()` |
| `FR-SOL-41` | `scobelix/solgen/emitter.py` — `SolidityEmitter._expr()` |
| `FR-SOL-42` | `scobelix/solgen/emitter.py` — `SolidityEmitter._emit_stmt()`, `SolidityEmitter._expr()`, `SolidityEmitter._atom()` |
| `FR-SOL-43` | `scobelix/solgen/emitter.py` — `SolidityEmitter._confidence_for()`, `SolidityEmitter.generate()` |
| `FR-SOL-44` | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-SOL-45` | `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-SOL-46` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-47` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-48` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-49` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-50` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-51` | `scobelix/solgen/validate.py` — `validate_solidity()` (docstring) |

### Intégration de Scobelix dans son environnement (`FR-INT`)

Exigences détaillées dans [integration.md](integration.md), énoncés fonctionnels dans [../specification-fonctionnelle/integration.md](../specification-fonctionnelle/integration.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-INT-01` | `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/__main__.py` — `print_decompilation()` |
| `FR-INT-02` | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-03` | `scobelix/loader.py` — `Loader.load_addr()`, `Loader.load_binary()` |
| `FR-INT-04` | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-05` | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-06` | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-07` | `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` |
| `FR-INT-08` | `tests/test_solgen.py` — `test_generated_solidity_actually_compiles()` ; `.github/workflows/ci.yml` — étape `Install solc 0.8.19` |
| `FR-INT-09` | `scobelix/utils/helpers.py` — `cache_dir()` ; `scobelix/utils/supplement.py` — `abi_path()` |
| `FR-INT-10` | `scobelix/utils/supplement.py` — `abi_path()`, `check_supplements()` |
| `FR-INT-11` | `scobelix/utils/supplement.py` — `LOCAL_SIGS_BULK_PATH`, `check_supplements()` ; `scobelix/tools/build_local_sigs.py` — `OUT_PATH` |
| `FR-INT-12` | `scobelix/__main__.py` — `main()` |
| `FR-INT-13` | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-INT-14` | `pyproject.toml` — `[build-system]`, clé `version` |
| `FR-INT-15` | `pyproject.toml` — `[tool.poetry.scripts]`, `[tool.poetry.dependencies]`, `[tool.poetry.group.dev.dependencies]` |
| `FR-INT-16` | `pyproject.toml` — clé `packages` |
| `FR-INT-17` | `pyproject.toml` — `[tool.pytest.ini_options]` |
| `FR-INT-18` | `.github/workflows/ci.yml` — étape `Install dependencies` ; `pyproject.toml` |
| `FR-INT-19` | `.github/workflows/ci.yml` — clé `on` ; `.github/workflows/bump-version.yml` — étape `Commit and push changes` |
| `FR-INT-20` | `.github/workflows/ci.yml` — job `test` |
| `FR-INT-21` | `.github/workflows/ci.yml` — étapes `Install dependencies`, `Install solc 0.8.19`, `Run tests` |
| `FR-INT-22` | `.github/workflows/ci.yml` — étape `Lint (report only - not a merge gate yet)` |
| `FR-INT-23` | `.github/workflows/bump-version.yml` — clé `on`, étape `Commit and push changes` |
| `FR-INT-24` | `.github/workflows/bump-version.yml` — étape `Bump version in pyproject.toml` |
| `FR-INT-25` | `.github/workflows/bump-version.yml` — étapes `Commit and push changes`, `Tag the new version` |
| `FR-INT-26` | `.github/workflows/bump-version.yml` — étape `Checkout repo` |
| `FR-INT-27` | `tests/test_golden_fixtures.py`, `tests/test_solgen.py`, `tests/test_sparser_resilience.py`, `tests/test_simplify.py`, `tests/test_proxy_detect.py`, `tests/test_solgen_validate.py`, `tests/test_event_signatures.py`, `tests/test_build_local_sigs.py`, `tests/test_main_combined_json.py` |
| `FR-INT-28` | `tests/test_solgen.py` — `test_generated_solidity_actually_compiles()` |
| `FR-INT-29` | `tests/fixtures/bytecode/`, `tests/fixtures/sources/` ; `tests/test_golden_fixtures.py` (docstring) |
| `FR-INT-30` | `tests/test_golden_fixtures.py` — `test_loop_accumulator_value_is_tracked()` |
| `FR-INT-31` | `scobelix/matcher.py` |
| `FR-INT-32` | `Jenkinsfile` (étapes `Fetch bytecode & decompile`, `Verify Vyper file`, bloc `post`) ; `decompile_link.sh` |

### Pipeline de décompilation : désassemblage, exécution symbolique, structuration et simplification (`FR-DEC`)

Exigences détaillées dans [pipeline-decompilation.md](pipeline-decompilation.md), énoncés fonctionnels dans [../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-DEC-01` | `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-DEC-02` | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/utils/opcode_dict.py` — `opcode_dict` |
| `FR-DEC-03` | `scobelix/utils/opcode_dict.py` — `opcode_dict` |
| `FR-DEC-04` | `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-DEC-05` | `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-DEC-06` | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/utils/helpers.py` — `pretty_bignum()` |
| `FR-DEC-07` | `scobelix/loader.py` — `Loader.load_binary()`, `Loader.disasm()` |
| `FR-DEC-08` | `scobelix/loader.py` — `Loader.disasm()` |
| `FR-DEC-09` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.run()` |
| `FR-DEC-10` | `scobelix/loader.py` — `Loader.run()`, `Loader.add_func()` |
| `FR-DEC-11` | `scobelix/loader.py` — `Loader.run()` |
| `FR-DEC-12` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-DEC-13` | `scobelix/loader.py` — `Loader.run()` ; `scobelix/utils/signatures.py` — `make_abi()`, `get_func_name()` |
| `FR-DEC-14` | `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-15` | `scobelix/vm.py` — `Node.__init__()`, `VM.expand_trace()` |
| `FR-DEC-16` | `scobelix/stack.py` — `Stack.jump_dests()` |
| `FR-DEC-17` | `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-18` | `scobelix/vm.py` — `should_quit()` dans `VM.run()` |
| `FR-DEC-19` | `scobelix/vm.py` — `VM.run()`, `Node.make_trace()` |
| `FR-DEC-20` | `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-21` | `scobelix/vm.py` — `VM.handle_jumps()` ; `scobelix/core/arithmetic.py` — `eval_bool()` |
| `FR-DEC-22` | `scobelix/vm.py` — `VM.handle_jumps()` |
| `FR-DEC-23` | `scobelix/vm.py` — `VM.handle_jumps()`, `VM.__init__()` |
| `FR-DEC-24` | `scobelix/vm.py` — `VM._run()` |
| `FR-DEC-25` | `scobelix/vm.py` — `VM._run()` |
| `FR-DEC-26` | `scobelix/stack.py` — `Stack.pop()`, `Stack.dup()`, `Stack.swap()` |
| `FR-DEC-27` | `scobelix/vm.py` — `VM.replace_loops()` |
| `FR-DEC-28` | `scobelix/stack.py` — `fold_stacks()` |
| `FR-DEC-29` | `scobelix/vm.py` — `VM.continue_loops()`, `Node.set_label()`, `Node.make_trace()` |
| `FR-DEC-30` | `scobelix/vm.py` — `VM.replace_loops()` |
| `FR-DEC-31` | `scobelix/stack.py` — `Stack.simplify()` ; `scobelix/core/arithmetic.py` — `eval()`, `div()`, `mod()` |
| `FR-DEC-32` | `scobelix/core/algebra.py` — `add_op()`, `mul_op()`, `sub_op()` ; `scobelix/stack.py` — `Stack._simplify()` |
| `FR-DEC-33` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-34` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-35` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/stack.py` — `Stack.cleanup()` |
| `FR-DEC-36` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-37` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-38` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-39` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-40` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-41` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-42` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-43` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-44` | `scobelix/vm.py` — `VM.handle_call()` |
| `FR-DEC-45` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-46` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-47` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-48` | `scobelix/vm.py` — `VM.handle_call()` ; `scobelix/utils/helpers.py` — `precompiled`, `precompiled_var_names` |
| `FR-DEC-49` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-50` | `scobelix/vm.py` — `VM.handle_jumps()` |
| `FR-DEC-51` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/utils/opcode_dict.py` — `stack_diffs` |
| `FR-DEC-52` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/decompiler.py` — `dec()` |
| `FR-DEC-53` | `scobelix/whiles.py` — `make()`, `to_while()` |
| `FR-DEC-54` | `scobelix/whiles.py` — `to_while()`, `is_revert()` |
| `FR-DEC-55` | `scobelix/whiles.py` — `make()` |
| `FR-DEC-56` | `scobelix/whiles.py` — `make()`, `to_while()` |
| `FR-DEC-57` | `scobelix/whiles.py` — `make_whiles()` |
| `FR-DEC-58` | `scobelix/whiles.py` — `make_whiles()` |
| `FR-DEC-59` | `scobelix/simplify.py` — `simplify_trace()` |
| `FR-DEC-60` | `scobelix/simplify.py` — `should_quit()` dans `simplify_trace()` |
| `FR-DEC-61` | `scobelix/simplify.py` — `simplify_trace()` |
| `FR-DEC-62` | `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/postprocess.py` — `cleanup_mul_1()` |
| `FR-DEC-63` | `scobelix/simplify.py` — `simplify_exp()` ; `scobelix/utils/helpers.py` — `cached()` |
| `FR-DEC-64` | `scobelix/simplify.py` — `cleanup_vars()`, `replace_var()` |
| `FR-DEC-65` | `scobelix/simplify.py` — `cleanup_mems()`, `replace_mem()`, `MAX_MEM_CLEANUP_TRACE_LEN` |
| `FR-DEC-66` | `scobelix/core/memloc.py` — `split_setmem()`, `split_store()`, `split_or()` |
| `FR-DEC-67` | `scobelix/simplify.py` — `cleanup_conds()` |
| `FR-DEC-68` | `scobelix/simplify.py` — `cleanup_msize()` |
| `FR-DEC-69` | `scobelix/simplify.py` — `loop_to_setmem()`, `_loop_to_setmem()`, `loop_to_setmem_from_storage()` |
| `FR-DEC-70` | `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/core/algebra.py` — `max_to_add()` ; `scobelix/rewriter.py` — `postprocess_exp()`, `postprocess_trace()`, `rewrite_string_stores()` |
| `FR-DEC-71` | `scobelix/simplify.py` — `readability()`, `replace_while_var()` ; `scobelix/prettify.py` — `prettify()` |
| `FR-DEC-72` | `scobelix/simplify.py` — `readability()` |
| `FR-DEC-73` | `scobelix/rewriter.py` (docstring de module) ; `scobelix/simplify.py` — `simplify_exp()` |
| `FR-DEC-74` | `scobelix/simplify.py` — `simplify_exp()` |
| `FR-DEC-75` | `scobelix/rewriter.py` — `postprocess_trace()` |
| `FR-DEC-76` | `scobelix/rewriter.py` — `postprocess_trace()` |
| `FR-DEC-77` | `scobelix/rewriter.py` — `rewrite_string_stores()` |
| `FR-DEC-78` | `scobelix/core/algebra.py` — `add_ge_zero()` ; `scobelix/core/variants.py` — `variants()`, `possibilities()` |
| `FR-DEC-79` | `scobelix/simplify.py` — `simplify_exp()` ; `scobelix/core/arithmetic.py` — `to_real_int()` |
| `FR-DEC-80` | `scobelix/simplify.py` — `move_right()` ; `scobelix/sparser.py` — `_sparser_resilient()` |
| `FR-DEC-81` | `scobelix/folder.py` — `fold()`, `as_paths()`, `meta_fold_paths()`, `fold_aux()` |
| `FR-DEC-82` | `scobelix/folder.py` — `TERMINATING` |
| `FR-DEC-83` | `scobelix/contract.py` — `Contract.make_ast()` ; `scobelix/function.py` — `Function.serialize()` |
| `FR-DEC-84` | `scobelix/folder.py` — `fold()` |
| `FR-DEC-85` | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()`, `VM.handle_call()` ; `scobelix/whiles.py` — `make()`, `to_while()` |
| `FR-DEC-86` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/sparser.py` — `repl_stor()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-DEC-87` | `scobelix/core/algebra.py` — `mask_op()`, `apply_mask()` ; `OPCODES.md` |
| `FR-DEC-88` | `scobelix/vm.py` — `mem_load()` |
| `FR-DEC-89` | `scobelix/vm.py` — `VM.handle_call()`, `VM.apply_stack()` |
| `FR-DEC-90` | `scobelix/function.py` — `Function.serialize()` ; `scobelix/vm.py` — `Node.__str__()` |

### Reconstruction des fonctions, des paramètres et de la structure du stockage (`FR-STOR`)

Exigences détaillées dans [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), énoncés fonctionnels dans [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-STOR-01` | `scobelix/function.py` — `Function.analyse()` |
| `FR-STOR-02` | `scobelix/function.py` — `Function.analyse()` |
| `FR-STOR-03` | `scobelix/function.py` — `Function.analyse()`, `Function._print()` |
| `FR-STOR-04` | `scobelix/function.py` — `Function.analyse()` |
| `FR-STOR-05` | `scobelix/function.py` — `Function.simplify_string_getter_from_storage()` |
| `FR-STOR-06` | `scobelix/function.py` — `Function.__init__()` |
| `FR-STOR-07` | `scobelix/function.py` — `Function.priority()`, `Function.ast_length()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-STOR-08` | `scobelix/function.py` — `Function.make_params()` |
| `FR-STOR-09` | `scobelix/function.py` — `Function.make_params()` |
| `FR-STOR-10` | `scobelix/function.py` — `Function.make_params()` ; `scobelix/core/masks.py` — `mask_to_type()` |
| `FR-STOR-11` | `scobelix/function.py` — `Function.make_params()` |
| `FR-STOR-12` | `scobelix/function.py` — `Function.make_params()` |
| `FR-STOR-13` | `scobelix/function.py` — `Function.make_names()` |
| `FR-STOR-14` | `scobelix/function.py` — `Function.cleanup_masks()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-STOR-15` | `scobelix/sparser.py` — `rewrite_functions()`, `find_stores()` |
| `FR-STOR-16` | `scobelix/sparser.py` — `rainbow_sha3()`, `sha3_loc_table` |
| `FR-STOR-17` | `scobelix/sparser.py` — `_sparser()` |
| `FR-STOR-18` | `scobelix/sparser.py` — `_sparser()` |
| `FR-STOR-19` | `scobelix/sparser.py` — `_sparser()` |
| `FR-STOR-20` | `scobelix/sparser.py` — `_sparser()`, `repl_stor()` |
| `FR-STOR-21` | `scobelix/sparser.py` — `rewrite_functions()` |
| `FR-STOR-22` | `scobelix/sparser.py` — `rewrite_functions()`, `get_type()` |
| `FR-STOR-23` | `scobelix/sparser.py` — `rewrite_functions()` |
| `FR-STOR-24` | `scobelix/sparser.py` — `rewrite_functions()` |
| `FR-STOR-25` | `scobelix/sparser.py` — `find_storage_names()`, `replace_names_in_assoc()` |
| `FR-STOR-26` | `scobelix/sparser.py` — `replace_names_in_assoc()`, `replace_names_in_assoc_bool()`, `used_locs` |
| `FR-STOR-27` | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-STOR-28` | `scobelix/sparser.py` — `_sparser_resilient()`, `_find_unresolvable_storage()` |
| `FR-STOR-29` | `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-STOR-30` | `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-STOR-31` | `scobelix/contract.py` — `Contract.make_asts()` |
| `FR-STOR-32` | `scobelix/contract.py` — `Contract.make_asts()` |
| `FR-STOR-33` | `scobelix/utils/proxy_detect.py` — `KNOWN_PROXY_SLOTS`, `detect_proxy_slots()` |
| `FR-STOR-34` | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-STOR-35` | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-STOR-36` | `scobelix/contract.py` — `Contract.postprocess()` |

### Résolution des signatures 4 octets et régénération de la base locale (`FR-SIG`)

Exigences détaillées dans [resolution-signatures.md](resolution-signatures.md), énoncés fonctionnels dans [../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-SIG-01` | `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-SIG-02` | `scobelix/utils/supplement.py` — `fetch_sig()`, `LOCAL_SIGS` |
| `FR-SIG-03` | `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-SIG-04` | `scobelix/utils/supplement.py` — `fetch_sig()` ; `scobelix/utils/helpers.py` — `cached()` ; `scobelix/loader.py` — `Loader.find_sig()` |
| `FR-SIG-05` | `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` |
| `FR-SIG-06` | `scobelix/utils/supplement.py` — `LOCAL_SIGS` |
| `FR-SIG-07` | `scobelix/utils/supplement.py` — `abi_path()`, `fetch_sig()` |
| `FR-SIG-08` | `scobelix/utils/supplement.py` — `check_supplements()`, `fetch_sig()` |
| `FR-SIG-09` | `scobelix/utils/supplement.py` — `check_supplements()` |
| `FR-SIG-10` | `scobelix/utils/supplement.py` — `check_supplements()` |
| `FR-SIG-11` | `scobelix/utils/signatures.py` — `make_abi()`, `fix_input_names()`, `get_func_name()`, `get_abi_name()` |
| `FR-SIG-12` | `scobelix/utils/signatures.py` — `make_abi()` ; `scobelix/function.py` — `Function.make_names()` |
| `FR-SIG-13` | `scobelix/utils/signatures.py` — `make_abi()`, `get_func_name()` |
| `FR-SIG-14` | `scobelix/prettify.py` — `try_fname()` ; `scobelix/loader.py` — `Loader.find_sig()` |
| `FR-SIG-15` | `scobelix/prettify.py` — `prettify()`, `pretty_num()` |
| `FR-SIG-16` | `scobelix/prettify.py` — `pretty_num()` ; `scobelix/loader.py` — `Loader.find_sig()` |
| `FR-SIG-17` | `scobelix/prettify.py` — `pretty_fname()`, `pretty_line()` |
| `FR-SIG-18` | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `main()` |
| `FR-SIG-19` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-20` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-21` | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `abi_functions()`, `walk_misc_signatures()`, `signature()` |
| `FR-SIG-22` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-23` | `scobelix/tools/build_local_sigs.py` — `compute_selector()` |
| `FR-SIG-24` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-25` | `scobelix/tools/build_local_sigs.py` — `OUT_PATH`, `main()` |
| `FR-SIG-26` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-27` | `scobelix/utils/supplement.py` — `LOCAL_SIGS_BULK_PATH`, `load_local_sigs_bulk()` |

### Sorties produites par Scobelix (`FR-SOR`)

Exigences détaillées dans [sorties.md](sorties.md), énoncés fonctionnels dans [../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-SOR-01` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-02` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-03` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-04` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-05` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-06` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/function.py` — `Function._print()` |
| `FR-SOR-07` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/prettify.py` — `pretty_type()` |
| `FR-SOR-08` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-09` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-10` | `scobelix/function.py` — `Function._print()` |
| `FR-SOR-11` | `scobelix/prettify.py` — `pprint_logic()` ; `scobelix/function.py` — `Function._print()` |
| `FR-SOR-12` | `scobelix/function.py` — `Function._print()` |
| `FR-SOR-13` | `scobelix/prettify.py` — `pprint_logic()` |
| `FR-SOR-14` | `scobelix/prettify.py` — `pprint_logic()`, `pretty_line()` |
| `FR-SOR-15` | `scobelix/prettify.py` — `prettify()`, `pretty_line()` |
| `FR-SOR-16` | `scobelix/prettify.py` — `pretty_line()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-SOR-17` | `scobelix/prettify.py` — `pretty_line()`, `pretty_memory()` |
| `FR-SOR-18` | `scobelix/prettify.py` — `PANIC_CODES`, `pretty_line()` |
| `FR-SOR-19` | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-20` | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-21` | `scobelix/prettify.py` — `pretty_line()`, `pretty_fname()` |
| `FR-SOR-22` | `scobelix/prettify.py` — `pretty_line()`, `pretty_gas()` |
| `FR-SOR-23` | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-24` | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-25` | `scobelix/prettify.py` — `prettify()` |
| `FR-SOR-26` | `scobelix/prettify.py` — `prettify()` |
| `FR-SOR-27` | `scobelix/prettify.py` — `prettify()` ; `scobelix/core/masks.py` — `mask_to_type()` |
| `FR-SOR-28` | `scobelix/prettify.py` — `prettify()` ; `scobelix/utils/signatures.py` — `get_param_name()` |
| `FR-SOR-29` | `scobelix/prettify.py` — `pretty_stor()` |
| `FR-SOR-30` | `scobelix/prettify.py` — `prettify()` ; `scobelix/postprocess.py` — `cleanup_mul_1()` |
| `FR-SOR-31` | `scobelix/prettify.py` — `prettify()`, `pretty_num()`, `try_fname()` |
| `FR-SOR-32` | `scobelix/utils/helpers.py` — classe `C`, `color()`, `clean_color()` ; `scobelix/prettify.py` — `prettify()`, `pretty_line()` |
| `FR-SOR-33` | `scobelix/contract.py` — `Contract.json()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-34` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-35` | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-SOR-36` | `scobelix/function.py` — `Function.serialize()` |
| `FR-SOR-37` | `scobelix/function.py` — `Function.serialize()` |
| `FR-SOR-38` | `scobelix/function.py` — `Function.serialize()` |
| `FR-SOR-39` | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-SOR-40` | `scobelix/decompiler.py` — classe `Decompilation`, `_decompile_with_loader()` |
| `FR-SOR-41` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-42` | `scobelix/__main__.py` — `print_decompilation()` ; `tests/test_main_combined_json.py` — `test_combined_json_output_is_valid_single_line_json()` |
| `FR-SOR-43` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-44` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-45` | `tests/test_main_combined_json.py` ; `scobelix/__main__.py` — `parse_args()` |
| `FR-SOR-46` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-47` | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-48` | `scobelix/__main__.py` — `main()` |
| `FR-SOR-49` | `scobelix/decompiler.py` — `_decompile_with_loader()`, `dec()` ; `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-SOR-50` | `scobelix/vm.py` — `VM.run()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-51` | `scobelix/__main__.py` — `main()` |

### Spécification de paramétrage des bases de signatures de Scobelix (`FR-PARAM`)

Exigences détaillées dans [parametrage-signatures.md](parametrage-signatures.md), énoncés fonctionnels dans [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md).

| Exigence | Fichier — Fonction/élément |
|---|---|
| `FR-PARAM-01` | `scobelix/tools/build_local_sigs.py` — `compute_selector()`, `signature()` ; `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-PARAM-02` | `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/utils/signatures.py` — `make_abi()` |
| `FR-PARAM-03` | `scobelix/utils/supplement.py` — `load_local_sigs_bulk()`, `fetch_sig()` |
| `FR-PARAM-04` | `scobelix/loader.py` — `Loader.find_sig()` |
| `FR-PARAM-05` | `scobelix/utils/signatures.py` — `fix_input_names()` ; `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-PARAM-06` | `scobelix/tools/build_local_sigs.py` — `main()` ; `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` |
| `FR-PARAM-07` | `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` |
| `FR-PARAM-08` | `scobelix/utils/supplement.py` — `check_supplements()` |
| `FR-PARAM-09` | `scobelix/utils/supplement.py` — `check_supplements()` |
| `FR-PARAM-10` | `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/utils/signatures.py` — `make_abi()` |
| `FR-PARAM-11` | `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-PARAM-12` | `scobelix/utils/supplement.py` — `check_supplements()` |
| `FR-PARAM-13` | `scobelix/utils/supplement.py` — `check_supplements()` |
| `FR-PARAM-14` | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-PARAM-15` | `scobelix/tools/build_local_sigs.py` — `load_abi()` |
| `FR-PARAM-16` | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `main()` |
| `FR-PARAM-17` | `scobelix/tools/build_local_sigs.py` — `abi_functions()`, `format_type()` |
| `FR-PARAM-18` | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `format_type()` |
| `FR-PARAM-19` | `scobelix/tools/build_local_sigs.py` — `abi_functions()` |
| `FR-PARAM-20` | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `signature()` |
| `FR-PARAM-21` | `scobelix/tools/build_local_sigs.py` — `parse_signature_string()`, `walk_misc_signatures()`, `main()` |
| `FR-PARAM-22` | `scobelix/utils/supplement.py` — `LOCAL_SIGS` |

---

Navigation : [README.md](README.md) · [../README.md](../README.md)
