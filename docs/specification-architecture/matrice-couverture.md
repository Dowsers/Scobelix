# Matrice de couverture des exigences

Cette matrice recense, en une seule vue, les 476 exigences fonctionnelles du répertoire `docs/`, réparties en 8 domaines d'un préfixe chacun, et leur point d'implémentation dans le code. Elle est dérivée mécaniquement des documents de traçabilité détaillés du présent répertoire : pour chaque exigence, l'objet abrégé et la colonne « Fichier — Fonction/élément » de sa ligne de traçabilité, sans retouche. Pour l'énoncé complet, se reporter au document fonctionnel ; pour l'explication du mécanisme (pas seulement sa localisation), au document de traçabilité correspondant.

## Synthèse

| Domaine | Préfixe | Exigences | Document de traçabilité |
|---|---|---|---|
| Architecture et interfaces d'appel de Scobelix | `FR-ARCH` | 77 | [architecture.md](architecture.md) |
| Reconstruction Solidity (solgen) et validation par compilation | `FR-SOL` | 73 | [generation-solidity.md](generation-solidity.md) |
| Intégration de Scobelix dans son environnement | `FR-INT` | 38 | [integration.md](integration.md) |
| Pipeline de décompilation : désassemblage, exécution symbolique, structuration et simplification | `FR-DEC` | 108 | [pipeline-decompilation.md](pipeline-decompilation.md) |
| Reconstruction des fonctions, des paramètres et de la structure du stockage | `FR-STOR` | 41 | [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md) |
| Résolution des signatures et régénération de la base locale | `FR-SIG` | 46 | [resolution-signatures.md](resolution-signatures.md) |
| Sorties produites par Scobelix | `FR-SOR` | 63 | [sorties.md](sorties.md) |
| Spécification de paramétrage des bases de signatures de Scobelix | `FR-PARAM` | 30 | [parametrage-signatures.md](parametrage-signatures.md) |
| **Total** | | **476** | |

**476/476 exigences couvertes** — chaque identifiant défini dans un document fonctionnel a sa ligne dans le document de traçabilité correspondant et ci-dessous, dans le même ordre ; vérifié mécaniquement (numérotation continue de 01 à N dans chaque préfixe, aucun manquant, aucun orphelin).

## Détail par domaine

### Architecture et interfaces d'appel de Scobelix (`FR-ARCH`)

Exigences détaillées dans [architecture.md](architecture.md), énoncés fonctionnels dans [../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-ARCH-01` | bibliothèque importable et commande, sans serveur | `scobelix/decompiler.py` — `decompile_bytecode()`, `decompile_address()` ; `scobelix/__main__.py` — `main()` |
| `FR-ARCH-02` | exécution synchrone, dans le processus et le fil de l'appelant, compilateur en processus fils | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/verify/solc.py` — `binary_version()`, `_standard_json_output()` ; `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-ARCH-03` | aucun accès réseau hors lecture du code d'une adresse et téléchargement autorisé du compilateur | `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/verify/solc.py` — `download_allowed()`, `download_solc()`, `available_releases()`, `_http_get()` ; `scobelix/utils/sigdb.py` |
| `FR-ARCH-04` | bytecode runtime, bloc de métadonnées lu comme donnée, création non distinguée | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/utils/metadata.py` — `parse_metadata()` |
| `FR-ARCH-05` | en-tête hérité `# Palkeoramix decompiler. ` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-06` | résultat en huit parties | `scobelix/decompiler.py` — classe `Decompilation` |
| `FR-ARCH-07` | décompilation d'un bytecode hexadécimal, entrée invalide refusée | `scobelix/decompiler.py` — `decompile_bytecode()` ; `scobelix/loader.py` — `parse_hex_code()`, `InvalidBytecode`, `Loader.load_binary()` |
| `FR-ARCH-08` | décompilation d'une adresse | `scobelix/decompiler.py` — `decompile_address()` ; `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-ARCH-09` | filtre par préfixe de nom, fonctions ignorées hors échecs | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.run()` |
| `FR-ARCH-10` | génération Solidity depuis la décompilation, mode dégradé sur l'AST | `scobelix/solgen/__init__.py` — `generate_solidity()` ; `scobelix/solgen/v2.py` — `generate()`, `Generator` |
| `FR-ARCH-11` | validation par un compilateur externe, statuts, pipeline IR | `scobelix/solgen/validate.py` — `validate_solidity()`, `ValidationResult` |
| `FR-ARCH-12` | capacité de vérification L0 à L4 | `scobelix/verify/core.py` — `verify()` ; `scobelix/verify/__init__.py` |
| `FR-ARCH-13` | outil satellite de régénération des signatures | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-ARCH-14` | bytecode vide ou réduit aux métadonnées, résultat « aucun code » | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-15` | ordre des étapes | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.load_binary()`, `Loader.run()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-ARCH-16` | décompilation indépendante, échec isolé et journalisé | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-17` | reconstruction du stockage une seule fois pour le contrat | `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-ARCH-18` | slots de proxy détectés sur le seul désassemblage brut | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-ARCH-19` | AST et texte dans la même passe, AST non plié, texte plié | `scobelix/function.py` — `Function.serialize()`, `Function._print()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-ARCH-20` | variables `PANORAMIX_*` lues une seule fois au chargement | `scobelix/decompiler.py` — constantes `FUNCTION_TIMEOUT`, `VM_RUN_TIMEOUT`, `WHILES_TIMEOUT` ; `scobelix/loader.py` — `LOADER_TIMEOUT` ; `scobelix/vm.py` — `MAX_NODE_COUNT` |
| `FR-ARCH-21` | budget par fonction (720 s) couvrant exécution symbolique, structuration et simplification | `scobelix/decompiler.py` — `dec()` dans `_decompile_with_loader()` |
| `FR-ARCH-22` | budget de l'exécution symbolique (600 s) | `scobelix/decompiler.py` — `dec()` ; `scobelix/vm.py` — `VM.run()` |
| `FR-ARCH-23` | arrêt de la simplification à la plus proche des deux échéances, fonction exacte et marquée | `scobelix/decompiler.py` — `simplification_deadline()`, `SIMPLIFY_RESERVE`, `dec()` ; `scobelix/whiles.py` — `make_whiles()` ; `scobelix/simplify.py` — `simplify_trace()`, `last_run_timed_out` |
| `FR-ARCH-24` | budget de la découverte (120 s) | `scobelix/loader.py` — `Loader.run()` |
| `FR-ARCH-25` | valeur nulle = pas de limite de temps, échéance de 75 % comprise | `scobelix/vm.py` — `VM.run()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/decompiler.py` — `dec()`, `simplification_deadline()` |
| `FR-ARCH-26` | nombre maximal de nœuds (500 000), seuil d'élagage, valeur nulle non illimitée | `scobelix/vm.py` — `MAX_NODE_COUNT`, `VM.run()`, `VM.handle_jumps()` |
| `FR-ARCH-27` | valeur non entière → erreur au chargement des capacités de décompilation seulement | `scobelix/decompiler.py`, `scobelix/loader.py`, `scobelix/vm.py` (conversions `int()` au niveau module) ; `scobelix/solgen/__init__.py` ; `scobelix/verify/__init__.py` |
| `FR-ARCH-28` | `WEB3_PROVIDER_URI` non interprétée par le système | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-ARCH-29` | `SCOBELIX_ABI_ROOTS`/`SCOBELIX_SIGS_OUT` lues par l'outil seul | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `OUT_PATH` |
| `FR-ARCH-30` | `SCOBELIX_SIGDB`, `SCOBELIX_SOLC_DIR`, `SCOBELIX_ALLOW_SOLC_DOWNLOAD` lues à l'usage | `scobelix/utils/sigdb.py` — `ENV_PATH`, `default_path()`, `_default_locations()`, `get_default()` ; `scobelix/verify/solc.py` — `DIR_ENV`, `DOWNLOAD_ENV`, `_candidate_paths()`, `_download_dir()`, `download_allowed()` |
| `FR-ARCH-31` | constantes non configurables | `scobelix/simplify.py` — `LARGE_TRACE_THRESHOLD`, `MAX_SIMPLIFY_PASSES_LARGE`, `MAX_MEM_CLEANUP_TRACE_LEN` ; `scobelix/vm.py` — `VM.run()`, `VM.handle_jumps()` ; `scobelix/decompiler.py` — `SIMPLIFY_RESERVE` ; `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/contract.py` ; `scobelix/solgen/v2.py` — `DEFAULT_TARGET` ; `scobelix/solgen/tiers.py` — `SearchBudget` ; `scobelix/verify/core.py` — `Budget` ; `scobelix/verify/solc.py` — `COMPILE_CACHE_BYTES` ; `scobelix/utils/sigdb.py` — `_file_name()` |
| `FR-ARCH-32` | Python ≥ 3.9 et < 4 | `pyproject.toml` — clé `python` de `[tool.poetry.dependencies]` |
| `FR-ARCH-33` | budget par signal, pas de Windows, fil principal | `scobelix/decompiler.py` — `dec()` ; `README.md` (section « Caveats ») |
| `FR-ARCH-34` | bibliothèque Ethereum 6.0.0-beta.8, usages limités ; keccak par eth-hash | `pyproject.toml` — dépendance `web3` ; `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/tools/build_local_sigs.py` — `compute_selector()` ; `scobelix/utils/sigdb.py` — `keccak256()` |
| `FR-ARCH-35` | journalisation colorée et répertoire de cache standard | `scobelix/__main__.py` — `main()` ; `scobelix/utils/helpers.py` — `cache_dir()` ; `scobelix/verify/solc.py` — `_download_dir()` |
| `FR-ARCH-36` | compilateur non déclaré, facultatif, cherché parmi les installations usuelles | `pyproject.toml` ; `scobelix/verify/solc.py` — `installed_solcs()`, `SolcNotFound` ; `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/storage.py` |
| `FR-ARCH-37` | option d'installation `verify` (pyrevm, py-evm) | `pyproject.toml` — `[tool.poetry.extras]`, dépendances `pyrevm` et `py-evm` ; `scobelix/verify/evm/__init__.py` — `available_backends()` |
| `FR-ARCH-38` | trois fichiers de données embarqués | `scobelix/data/abi_dump.xz`, `scobelix/data/local_sigs.json`, `scobelix/data/extra_sigs.json` ; `scobelix/utils/sigdb.py` — `DUMP_PATH`, `LOCAL_SIGS_PATH`, `EXTRA_SIGS_PATH` |
| `FR-ARCH-39` | caches de la décompilation jamais purgés, base ouverte une fois, caches bornés de la génération et de la vérification | `scobelix/utils/helpers.py` — `cached()` ; `scobelix/stack.py` — `Stack.simplify_cache` ; `scobelix/core/algebra.py` — `ge_zero_cache` ; `scobelix/loader.py` — `Loader.signatures` ; `scobelix/utils/sigdb.py` — `get_default()` ; `scobelix/solgen/sigs.py` ; `scobelix/verify/solc.py` — `COMPILE_CACHE_BYTES`, `_standard_json_output()` |
| `FR-ARCH-40` | décompilations successives partageant l'état, y compris les emplacements nommés | `scobelix/sparser.py` — `used_locs`, `replace_names_in_assoc()`, `replace_names_in_assoc_bool()` ; `scobelix/loader.py` — `Loader.signatures` |
| `FR-ARCH-41` | compteur de nœuds remis à zéro à chaque exécution symbolique | `scobelix/vm.py` — `VM.__init__()` |
| `FR-ARCH-42` | replis locaux journalisés | `scobelix/loader.py` — `Loader.run()` ; `scobelix/folder.py` — `fold()` ; `scobelix/contract.py` — `Contract.postprocess()` ; `scobelix/utils/sigdb.py` — `_open_default()` |
| `FR-ARCH-43` | AST non sérialisable → `{}` et `Failed json serialization.` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-44` | erreurs propagées sans reprise | `scobelix/loader.py` — `parse_hex_code()`, `Loader.load_binary()`, `Loader.load_addr()` ; `scobelix/contract.py` — `Contract.make_asts()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-45` | le budget par fonction ne peut être absorbé | `scobelix/decompiler.py` — classe `TimeoutInterrupt` |
| `FR-ARCH-46` | commande `scobelix` et mode module | `pyproject.toml` — `[tool.poetry.scripts]` ; `scobelix/__main__.py` — `main()` |
| `FR-ARCH-47` | un argument positionnel obligatoire, code 2 sinon | `scobelix/__main__.py` — `parse_args()` |
| `FR-ARCH-48` | nature de l'argument selon sa seule longueur | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-49` | `-` lit l'entrée standard, puis même règle de longueur | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-50` | liste séparée par des virgules, traitement successif, arrêt à la première erreur | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-51` | option `-v`, valeur numérique ou nom défini en majuscules par la journalisation standard (dont `BASIC_FORMAT`), erreur sinon | `scobelix/__main__.py` — `main()`, `parse_args()` |
| `FR-ARCH-52` | `--profile` écrit `scobelix.prof`, même en cas d'échec | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-53` | `--profile` sans effet sur une liste | `scobelix/__main__.py` — `main()` |
| `FR-ARCH-54` | `--function`, défaut vide = toutes | `scobelix/__main__.py` — `parse_args()`, `print_decompilation()` |
| `FR-ARCH-55` | quatre drapeaux de format, précédence stricte | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-56` | options de génération seulement avec `--solidity` | `scobelix/__main__.py` — `print_decompilation()`, `_generate_solidity()`, `_validate()` |
| `FR-ARCH-57` | valeurs des options de génération, refus en code 2 | `scobelix/__main__.py` — `parse_args()`, `_solc_version()`, `_seconds()`, `_generate_solidity()` |
| `FR-ARCH-58` | `--verbose`/`--explain` par présence littérale dans les arguments du processus | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()` ; `scobelix/prettify.py` — `explain()`, `explain_text()` ; `scobelix/decompiler.py` — `dec()` |
| `FR-ARCH-59` | `--explain` écrit sur la sortie standard avant la sortie principale | `scobelix/prettify.py` — `explain()`, `explain_text()` |
| `FR-ARCH-60` | options non déclarées et abréviations ambiguës refusées, abréviations univoques acceptées | `scobelix/__main__.py` — `parse_args()` |
| `FR-ARCH-61` | codes de sortie 0, 2 et 1 | `scobelix/__main__.py` — `main()`, `_print_verification()` |
| `FR-ARCH-62` | deux fonctions publiques de décompilation | `scobelix/decompiler.py` — `decompile_bytecode()`, `decompile_address()` |
| `FR-ARCH-63` | huit champs à valeurs vides par défaut | `scobelix/decompiler.py` — classe `Decompilation` |
| `FR-ARCH-64` | `json` sérialisable ou `{}`, clés `proxy_hints`, `metadata`, `dispatcher` identiques | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-65` | désassemblage, bytecode et fonctions exposés par l'API seulement | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-ARCH-66` | génération Solidity, paramètres nommés, résultat, erreurs de valeur | `scobelix/solgen/__init__.py` — `generate_solidity()` ; `scobelix/solgen/v2.py` — `SolgenResult`, `generate()`, `CONTRACT_NAME` |
| `FR-ARCH-67` | deux fonctions de validation, résultat à cinq champs | `scobelix/solgen/validate.py` — `validate()`, `validate_solidity()`, classe `ValidationResult` ; `scobelix/verify/solc.py` — `solc_for_source()` |
| `FR-ARCH-68` | fonction de vérification, machines et compilateurs disponibles | `scobelix/verify/core.py` — `verify()` ; `scobelix/verify/__init__.py` ; `scobelix/verify/evm/__init__.py` — `available_backends()` ; `scobelix/verify/solc.py` — `installed_solcs()` |
| `FR-ARCH-69` | détection des slots de proxy exposée | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-ARCH-70` | exceptions pour les erreurs de FR-ARCH-44, retour normal sinon | `scobelix/loader.py` — `InvalidBytecode` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-ARCH-71` | fil principal requis, sauf budget par fonction nul | `scobelix/decompiler.py` — `dec()` |
| `FR-ARCH-72` | aucune configuration de la journalisation par l'API | `scobelix/__main__.py` — `main()` ; `scobelix/matcher.py` |
| `FR-ARCH-73` | état partagé sans moyen de réinitialisation, hors base de signatures | `scobelix/utils/sigdb.py` — `set_default()` |
| `FR-ARCH-74` | interface publique de la base de signatures | `scobelix/utils/sigdb.py` — `lookup_function()`, `lookup_event()`, `lookup_error()`, `SigDB`, `SigDB.stats()`, `function_selector()`, `event_topic()`, `canonical_type()`, `canonical_signature()`, `default_path()`, `default_sources()`, `build()`, `ensure_built()`, `get_default()`, `set_default()` |
| `FR-ARCH-75` | module dédié, sans argument, piloté par deux variables lues au chargement | `scobelix/tools/build_local_sigs.py` — `main()`, `ABI_ROOTS`, `OUT_PATH` |
| `FR-ARCH-76` | variable absente ou vide → message d'aide, fin normale | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-ARCH-77` | jamais invoqué par le pipeline, effet par le fichier local, source de la base | `scobelix/tools/build_local_sigs.py` ; `scobelix/utils/sigdb.py` — `default_sources()`, `data_hash()`, `default_path()` |

### Reconstruction Solidity (solgen) et validation par compilation (`FR-SOL`)

Exigences détaillées dans [generation-solidity.md](generation-solidity.md), énoncés fonctionnels dans [../specification-fonctionnelle/generation-solidity.md](../specification-fonctionnelle/generation-solidity.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-SOL-01` | entrée complète, base de signatures vérifiée par haché | `scobelix/solgen/v2.py` — `_collect()`, `Generator._prepare()` ; `scobelix/solgen/sigs.py` — `function_candidates()`, `event_candidates()`, `error_candidates()`, `_from_entry()`, `_lookup()` |
| `FR-SOL-02` | mode dégradé JSON | `scobelix/solgen/v2.py` — `_collect()`, `_clean_metadata()`, `_clean_dispatcher()`, `Generator._prepare()` ; `scobelix/solgen/lift.py` — `lift_function()`, `_Lifter.json_slot()`, `_Lifter.e_stor()` |
| `FR-SOL-03` | bytecode absent | `scobelix/solgen/v2.py` — `Generator._prepare()` ; `scobelix/solgen/lift.py` — `_Lifter.bytes_()` |
| `FR-SOL-04` | contrat vide, points d'entrée absents | `scobelix/solgen/v2.py` — `_collect()`, `Generator._prepare()` ; `scobelix/solgen/contract.py` — `_header()` |
| `FR-SOL-05` | paramètres et refus | `scobelix/solgen/__init__.py` — `generate_solidity()` ; `scobelix/solgen/v2.py` — `Generator.__init__()`, `CONTRACT_NAME` ; `scobelix/solgen/pipeline.py` — `IDIOM_LEVELS` |
| `FR-SOL-06` | exactitude, rien d'omis | `scobelix/solgen/lift.py` — `_Lifter.unstructured()`, `_Lifter.st_undefined()`, `_Lifter.e_undefined()`, `_Lifter.st_continue()`, `_STATEMENTS`, `_EXPRESSIONS` ; `scobelix/solgen/render.py` — `_FunctionRenderer.s_Unstructured()`, `_FunctionRenderer.expr()`, `_FunctionRenderer.s_Continue()` |
| `FR-SOL-07` | échec d'une réécriture | `scobelix/solgen/pipeline.py` — `run_passes()`, `prepare()`, `finish()` |
| `FR-SOL-08` | contenu du résultat | `scobelix/solgen/v2.py` — `SolgenResult`, `SolgenResult.to_json()`, `_table()`, `_storage_layout()`, `_original()`, `record()` ; `scobelix/solgen/passes/storage.py` — `finish()` |
| `FR-SOL-09` | version visée | `scobelix/solgen/v2.py` — `choose_target()`, `DEFAULT_TARGET`, `_assemble()`, `Generator._run()` ; `scobelix/solgen/render.py` — `RenderContext.need()`, `CANCUN` |
| `FR-SOL-10` | SPDX, `pragma`, `abicoder v1` | `scobelix/solgen/contract.py` — `assemble()` ; `scobelix/solgen/v2.py` — `_original_abi_v2()` ; `scobelix/solgen/abi.py` — `uses_abi_v1()`, `uses_abi_v2()` ; `scobelix/solgen/render.py` — `_FunctionRenderer.x_Env()` |
| `FR-SOL-11` | commentaire d'en-tête | `scobelix/solgen/contract.py` — `_header()`, `_VERIFIED_LEGEND` |
| `FR-SOL-12` | ordre des éléments | `scobelix/solgen/contract.py` — `assemble()`, `_Structs` ; `scobelix/solgen/pipeline.py` — `DECLARATION_KINDS`, `PassContext.declare()` |
| `FR-SOL-13` | fonctions nommées | `scobelix/solgen/abi.py` — `analyse_entry()`, `_choose()`, `function_name_ok()`, `_param_name()`, `head_checks()`, `head_size()`, `validator()` ; `scobelix/solgen/contract.py` — `_signature()` |
| `FR-SOL-14` | emplacements, structures, enveloppe privée | `scobelix/solgen/contract.py` — `_signature()`, `_Structs.name()`, `assemble()` ; `scobelix/solgen/abi.py` — `WRAP_SLOTS` |
| `FR-SOL-15` | mutabilité, contrôle de valeur | `scobelix/solgen/abi.py` — `set_mutability()`, `mutability()`, `strip_callvalue_check()` ; `scobelix/solgen/v2.py` — `Generator._prepare()`, `_constant_getter_mutability()` |
| `FR-SOL-16` | fonctions routées non typées | `scobelix/solgen/contract.py` — `assemble()` ; `scobelix/solgen/abi.py` — `EntrySpec.routed` |
| `FR-SOL-17` | fonctions routées typées | `scobelix/solgen/contract.py` — `_routed_signature()`, `_route_call()`, `_routed_entry()`, `_param_types()`, `_fresh()`, `assemble()` ; `scobelix/solgen/render.py` — `_FunctionRenderer.s_Return()`, `_FunctionRenderer.s_Stop()` |
| `FR-SOL-18` | repli et réception | `scobelix/solgen/v2.py` — `_default_revert()`, `Generator._prepare()` ; `scobelix/solgen/contract.py` — `assemble()`, `_reads_calldata()` |
| `FR-SOL-19` | NatSpec | `scobelix/solgen/contract.py` — `_natspec()`, `_DECODER_NOTES`, `_FLAG_NOTES`, `DIFFERING` |
| `FR-SOL-20` | noms réservés, masquage | `scobelix/solgen/render.py` — `reserved_name()`, `_KEYWORDS`, `_BUILTINS`, `_CONTEXTUAL`, `_GENERATED_NAMES`, `_GENERATED_RE`, `_YUL_NAMES`, `_TYPE_NAME_RE` ; `scobelix/solgen/contract.py` — `_declared_names()` |
| `FR-SOL-21` | fonctions en échec | `scobelix/solgen/v2.py` — `_collect()`, `Generator._prepare()`, `Generator._run()`, `derive_confidence()` |
| `FR-SOL-22` | `unchecked` | `scobelix/solgen/render.py` — `_FunctionRenderer.render()`, `_FunctionRenderer._block()`, `_FunctionRenderer.guarded()`, `_FunctionRenderer.facts()`, `_FunctionRenderer._chain()`, `_FunctionRenderer._sub()` |
| `FR-SOL-23` | assistants à assemblage | `scobelix/solgen/render.py` — `_HELPERS`, `Helpers.use()`, `Helpers.sources()`, `_FunctionRenderer.x_Op()`, `_FunctionRenderer.x_Mask()`, `_FunctionRenderer.x_Field()`, `_FunctionRenderer.expr()` |
| `FR-SOL-24` | comparaisons, booléens, choix | `scobelix/solgen/render.py` — `_FunctionRenderer.x_Op()`, `_FunctionRenderer.signed()`, `_FunctionRenderer._cmp_operand()`, `_FunctionRenderer._iszero()`, `_FunctionRenderer.w()`, `_FunctionRenderer.b()`, `_FunctionRenderer._compare_addresses()`, `_FunctionRenderer.x_Ternary()`, `_may_halt()`, `max_literal()` |
| `FR-SOL-25` | constantes | `scobelix/solgen/render.py` — `literal()`, `time_literal()`, `_FunctionRenderer._add()`, `_is_timestamp()` |
| `FR-SOL-26` | environnement | `scobelix/solgen/render.py` — `_FunctionRenderer.x_Env()`, `_FunctionRenderer.x_Balance()`, `_FunctionRenderer.x_ExtCodeSize()`, `_FunctionRenderer.x_ExtCodeHash()`, `_FunctionRenderer.x_BlockHash()`, `_FunctionRenderer.x_BlobHash()` |
| `FR-SOL-27` | données d'appel | `scobelix/solgen/render.py` — `_FunctionRenderer.x_CalldataWord()`, `_FunctionRenderer.x_Param()`, `_FunctionRenderer._dynamic_param()` ; `scobelix/solgen/contract.py` — `_word_views()`, `_dynamic_views()` |
| `FR-SOL-28` | stockage par emplacement | `scobelix/solgen/render.py` — `_FunctionRenderer.x_Sload()`, `_FunctionRenderer.s_Sstore()`, `_FunctionRenderer.x_Field()`, `_FunctionRenderer.x_TLoad()`, `_FunctionRenderer.s_TStore()` |
| `FR-SOL-29` | mémoire émulée | `scobelix/solgen/render.py` — `_FunctionRenderer.__init__()`, `_FunctionRenderer.render()`, `_FunctionRenderer.s_Mstore()`, `_FunctionRenderer.x_MLoad()` |
| `FR-SOL-30` | suites d'octets | `scobelix/solgen/render.py` — `_FunctionRenderer.bytes_()`, `_FunctionRenderer.x_Keccak()`, `_FunctionRenderer.x_BytesWord()`, `_HELPERS` ; `scobelix/solgen/contract.py` — `assemble()` |
| `FR-SOL-31` | fins d'exécution | `scobelix/solgen/render.py` — `_FunctionRenderer.s_Return()`, `_FunctionRenderer.s_Stop()`, `_FunctionRenderer.s_Revert()`, `_FunctionRenderer.s_Invalid()`, `_FunctionRenderer.s_SelfDestruct()`, `_FunctionRenderer.s_Require()`, `_FunctionRenderer._tail()`, `string_literal()` ; `scobelix/solgen/lift.py` — `_Lifter.st_require()`, `_Lifter.require_branch()` |
| `FR-SOL-32` | journaux, appels, créations | `scobelix/solgen/render.py` — `_FunctionRenderer.s_Log()`, `_FunctionRenderer.s_ExtCall()`, `_FunctionRenderer._ext_call_text()`, `_FunctionRenderer.payload()`, `_FunctionRenderer.call_ok()`, `_FunctionRenderer.call_addr()`, `_FunctionRenderer.s_Create()`, `_FunctionRenderer.s_Precompile()` ; `scobelix/solgen/lift.py` — `_Lifter.call_out()` |
| `FR-SOL-33` | flot de contrôle | `scobelix/solgen/render.py` — `_FunctionRenderer.s_If()`, `_FunctionRenderer.s_While()`, `_FunctionRenderer.s_For()`, `_FunctionRenderer.s_Continue()`, `_FunctionRenderer.s_Break()`, `_FunctionRenderer.parallel()`, `_FunctionRenderer._go_var()`, `_FunctionRenderer._after_loop()`, `_depends()` ; `scobelix/solgen/lift.py` — `_Lifter.label()`, `_Lifter.st_while()`, `_Lifter.setvars()`, `_Lifter.local_name()` |
| `FR-SOL-34` | profondeur de pile | `scobelix/solgen/render.py` — `_FunctionRenderer.hoist_plan()`, `_FunctionRenderer._plan_operands()`, `_FunctionRenderer._emit_hoisted()`, `_FunctionRenderer._emit_memory()`, `_FunctionRenderer._hoisted()`, `_FunctionRenderer._cond_var()`, `_FunctionRenderer._loop_check()`, `_FunctionRenderer._frame()`, `_FunctionRenderer.__init__()`, `_STACK_BUDGET` ; `scobelix/solgen/stack.py` — `StackModel`, `StackModel.stmt_need()`, `StackModel.plan()`, `StackModel.plan_memory()`, `reorder_safe()`, `Index.order_safe()`, `WINDOW` |
| `FR-SOL-35` | commentaires et chaînes | `scobelix/solgen/render.py` — `comment_text()`, `string_literal()`, `_ESCAPES` |
| `FR-SOL-36` | ordre et interrupteurs des réécritures | `scobelix/solgen/pipeline.py` — `PASS_ORDER`, `available_passes()`, `PassContext.enabled()`, `PassContext.off_everywhere()`, `prepare()`, `run_passes()`, `finish()` ; `scobelix/solgen/passes/__init__.py` (contrat d'une réécriture) ; `scobelix/solgen/v2.py` — `Generator.regenerate()`, `Generator._run()` ; `scobelix/solgen/storage.py` — `exclude()` |
| `FR-SOL-37` | `abi`, prologue du décodeur | `scobelix/solgen/passes/abi.py` — `run()`, `_prologue()`, `_classify()`, `_removable()`, `_select()`, `_rebuild()`, `_name_params()` ; `scobelix/solgen/abi.py` — `head_checks()`, `validator()` |
| `FR-SOL-38` | `abi`, énumérations, emplacements, retours | `scobelix/solgen/passes/abi.py` — `_enum_name()`, `_enum_declaration()`, `_locations()`, `_refine_returns()`, `_column_type()`, `_standard_string()`, `finish()` |
| `FR-SOL-39` | `abi`, routes typées | `scobelix/solgen/passes/abi.py` — `_route()`, `_memory_strings()`, `run()` ; `scobelix/solgen/v2.py` — `Generator._run()` |
| `FR-SOL-40` | notes des décodeurs anciens | `scobelix/solgen/v2.py` — `_dispatch_flags()`, `_legacy_decoder_flags()`, `_indirect_calldata()` ; `scobelix/solgen/passes/abi.py` — `_allocates_elsewhere()`, `FLAG_MEMORY_START` ; `scobelix/solgen/contract.py` — `_DECODER_NOTES` |
| `FR-SOL-41` | inférence de la disposition du stockage | `scobelix/solgen/storage.py` — `analyse()`, `infer_layout()`, `parse_slot()`, `decompose_keccak()`, `check()`, `self_check()`, `name_types()`, `state_declarations()`, `type_declarations()`, `namespace_declarations()`, `Layout` ; `scobelix/solgen/passes/storage.py` — `prepare()`, `finish()`, `assign_names()` |
| `FR-SOL-42` | `storage`, accès réécrits | `scobelix/solgen/passes/storage.py` — `run()`, `_Rewriter`, `_Rewriter.read()`, `_Rewriter.store()`, `_Rewriter.key_fits()`, `_Rewriter.index_ok()`, `_Rewriter.whole_variables()`, `_Rewriter.split_constant()`, `cuts_a_variable()` ; `scobelix/solgen/storage.py` — `Layout.resolve()` |
| `FR-SOL-43` | `getters`, repli en accesseur | `scobelix/solgen/passes/getters.py` — `prepare()`, `run()`, `finish()`, `solc_getter()`, `getter_params()`, `constant_literal()` ; `scobelix/solgen/pipeline.py` — `PassContext.fold()` ; `scobelix/solgen/contract.py` — `assemble()` |
| `FR-SOL-44` | `reverts` | `scobelix/solgen/passes/reverts.py` — `run()`, `finish()`, `_Rewriter.block()`, `_Rewriter.require()`, `_Rewriter.named()`, `_Errors.candidates()`, `_Errors.resolve()`, `decode_arguments()`, `local_values()`, `with_locals()` ; `scobelix/solgen/sigs.py` — `error_candidates()` ; `scobelix/solgen/render.py` — `_FunctionRenderer.s_Require()`, `_FunctionRenderer.s_Revert()` |
| `FR-SOL-45` | `arith` | `scobelix/solgen/passes/arith.py` — `run()`, `expected_guards()`, `Normaliser`, `_Arith.absorb()`, `_Arith.use()`, `_Arith.bind()`, `_Arith.divisions()`, `_Arith.bounds()`, `_Arith.keep()` ; `scobelix/solgen/render.py` — `_FunctionRenderer.x_Typed()` |
| `FR-SOL-46` | `calls` | `scobelix/solgen/passes/calls.py` — `run()`, `finish()`, `_Rewriter.call()`, `_Rewriter.high_level()`, `_Rewriter.transfer()`, `_Rewriter.forward()`, `_Rewriter.builtin()`, `_Rewriter.low_level()`, `_Interfaces.name()` ; `scobelix/solgen/render.py` — `_FunctionRenderer.s_HighCall()`, `_FunctionRenderer.s_Transfer()`, `_FunctionRenderer.s_Forward()`, `_FunctionRenderer.s_Builtin()`, `_FunctionRenderer.s_ExtCall()` |
| `FR-SOL-47` | `events` | `scobelix/solgen/passes/events.py` — `run()`, `finish()`, `_Events.candidates()`, `_Events.named()`, `_Events.decode()`, `_Events.anonymous()`, `_Events.declaration()`, `data_arguments()` ; `scobelix/solgen/render.py` — `_FunctionRenderer.s_Emit()`, `_FunctionRenderer.s_Log()` |
| `FR-SOL-48` | `loops` | `scobelix/solgen/passes/loops.py` — `run()`, `_Loops.loop()`, `_Loops.breaks()`, `_Loops.implied()`, `sequence()`, `_Loops.induction()`, `_Loops.header_step()`, `_Loops.tail()` ; `scobelix/solgen/scopes.py` — `sites()` ; `scobelix/solgen/render.py` — `_FunctionRenderer._in_place()` |
| `FR-SOL-49` | `naming` | `scobelix/solgen/passes/naming.py` — `prepare()`, `run()`, `finish()`, `_Namer.locals()`, `_Namer.parameters()`, `state_names()`, `singular()`, `value_name()`, `cached_names()`, `contract_names()` ; `scobelix/solgen/passes/storage.py` — `assign_names()` |
| `FR-SOL-50` | `compound` | `scobelix/solgen/passes/compound.py` — `run()`, `_Compound.stmt()`, `_Compound.assign()`, `_Compound.typed_compound()`, `_Compound.evm_compound()`, `_Compound.expr()`, `_Compound.bool_return()` |
| `FR-SOL-51` | `modifiers` | `scobelix/solgen/passes/modifiers.py` — `prepare()`, `run()`, `finish()`, `first_check()`, `lifted_check()`, `check_name()` ; `scobelix/solgen/contract.py` — `_modifiers()` |
| `FR-SOL-52` | choix du compilateur, absence | `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/verify/solc.py` — `solc_for_source()` |
| `FR-SOL-53` | fichier temporaire, `--bin`, délai | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-54` | reprise via-IR | `scobelix/solgen/validate.py` — `validate_solidity()`, `VIA_IR_ONLY`, `ValidationResult` |
| `FR-SOL-55` | délai dépassé, lancement impossible | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-SOL-56` | lignes, statuts, version | `scobelix/solgen/validate.py` — `validate_solidity()`, `ValidationResult` |
| `FR-SOL-57` | validation d'un résultat | `scobelix/solgen/validate.py` — `validate()` |
| `FR-SOL-58` | `valid` n'atteste que la compilation | `scobelix/solgen/validate.py` — `validate_solidity()` (docstring) |
| `FR-SOL-59` | niveaux par fonction | `scobelix/solgen/v2.py` — `Generator._run()`, `Generator.full_passes()` ; `scobelix/solgen/contract.py` — `_render()` ; `scobelix/solgen/render.py` — `exact_machinery()`, `_MACHINERY_RE` |
| `FR-SOL-60` | gardes statiques, indicateurs | `scobelix/solgen/v2.py` — `RISK_FLAGS`, `risk_flags()`, `Generator._prepare()`, `Generator.regenerate()`, `_GUARD_ROUNDS`, `Generator._run()`, `_dispatch_flags()` ; `scobelix/solgen/lift.py` (docstring : indicateurs du relèvement) ; `scobelix/solgen/abi.py` — `analyse_entry()` |
| `FR-SOL-61` | limite de temps du décompilateur | `scobelix/solgen/v2.py` — `_FnInput`, `_collect()`, `Generator._prepare()`, `Generator._run()` ; `scobelix/solgen/contract.py` — `FLAG_TIME_LIMITED`, `_FLAG_NOTES`, `_render()` |
| `FR-SOL-62` | verdict et confiance | `scobelix/solgen/v2.py` — `derive_confidence()`, `_table()`, `record()` ; `scobelix/solgen/contract.py` — `DIFFERING`, `Unit` |
| `FR-SOL-63` | avertissements | `scobelix/solgen/v2.py` — `Generator._prepare()`, `Generator._run()`, `_shown()` |
| `FR-SOL-64` | déterminisme | `scobelix/solgen/contract.py` — `assemble()` ; `scobelix/solgen/v2.py` — `_table()` ; `scobelix/solgen/tiers.py` (docstring) |
| `FR-SOL-65` | règle du résultat | `scobelix/solgen/tiers.py` — `search()`, `_Loop.run()`, `_Loop._finish()`, `OK_VERDICTS` ; `scobelix/solgen/v2.py` — `generate()`, `Generator.search()`, `record()` |
| `FR-SOL-66` | vérification impossible | `scobelix/solgen/tiers.py` — `search()`, `_unverified()`, `_exact_warning()`, `ALL_OFF`, `_Loop._finish()`, `_Loop._carried()` ; `scobelix/solgen/v2.py` — `_check()` |
| `FR-SOL-67` | réparation L0 | `scobelix/solgen/tiers.py` — `_Loop._repair_l0()`, `_Loop.L0_ATTEMPTS`, `locate_errors()`, `_minimise()`, `_ddmin()`, `_Loop._l0_round()`, `_Loop._compile()`, `_Loop._warnings()` ; `scobelix/solgen/contract.py` — `entry_spans()`, `router_spans()` ; `scobelix/solgen/v2.py` — `_level_warnings()` |
| `FR-SOL-68` | réparation L2 | `scobelix/solgen/tiers.py` — `_Loop._settle()`, `_Loop.L2_ATTEMPTS`, `layout_rows()`, `_Loop._l2_level()`, `_Loop._warnings()` ; `scobelix/solgen/storage.py` — `exclude()` |
| `FR-SOL-69` | recherche L3 | `scobelix/solgen/tiers.py` — `_Loop.run()`, `_Loop._search()`, `_Loop._l3_round()`, `_Loop._candidate()`, `_Loop._execute()`, `_Loop._fingerprints()`, `_Loop._state()`, `_Loop._drop()`, `_sequence_only()`, `_Loop._warnings()` |
| `FR-SOL-70` | L4 | `scobelix/solgen/tiers.py` — `_Loop._l4_level()`, `SearchBudget` |
| `FR-SOL-71` | budget | `scobelix/solgen/tiers.py` — `SearchBudget`, `SearchBudget.of()`, `_verify_budget()`, `_Loop._remaining()`, `_Loop._out_of()`, `_Loop._run_limit()`, `_Loop._why_not()`, `_Loop._demote()`, `_Loop._carried()`, `_Loop._compile()` |
| `FR-SOL-72` | texte vérifié | `scobelix/solgen/v2.py` — `summary_lines()`, `record()`, `short_counterexample()`, `_cut()` ; `scobelix/solgen/tiers.py` — `_Loop._lines()` ; `scobelix/solgen/contract.py` — `_header()`, `_VERIFIED_LEGEND`, `_natspec()` |
| `FR-SOL-73` | rapport de vérification | `scobelix/solgen/tiers.py` — `Verification`, `Verification.passed`, `Verification.to_json()`, `_Loop._summary()`, `_Loop._finish()` ; `scobelix/solgen/v2.py` — `_verify()`, `_level_warnings()`, `SolgenResult.verification_json()` |

### Intégration de Scobelix dans son environnement (`FR-INT`)

Exigences détaillées dans [integration.md](integration.md), énoncés fonctionnels dans [../specification-fonctionnelle/integration.md](../specification-fonctionnelle/integration.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-INT-01` | lecture de code déclenchée seulement par la décompilation d'une adresse | `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/__main__.py` — `print_decompilation()` |
| `FR-INT-02` | adresse alphanumérique, minuscules, checksum, avant tout accès | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-03` | code au dernier bloc, décompilé comme un bytecode, compte sans code → « aucun code » | `scobelix/loader.py` — `Loader.load_addr()`, `Loader.load_binary()` |
| `FR-INT-04` | choix du nœud par la bibliothèque | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-05` | ni reprise ni délai propre | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-06` | point d'accès JSON-RPC répondant à la lecture du code | `scobelix/loader.py` — `Loader.load_addr()` |
| `FR-INT-07` | version publiée identifiée par `--version`, `--standard-json`, `--bin`, `--via-ir`, code de sortie, diagnostics, pragma | `scobelix/verify/solc.py` — `binary_version()`, `parse_version_output()`, `_standard_json_output()` ; `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/contract.py` — `assemble()` |
| `FR-INT-08` | ordre de recherche, identification par `--version`, scripts écartés | `scobelix/verify/solc.py` — `_candidate_paths()`, `installed_solcs()`, `binary_version()`, `SEARCH_PATTERNS` |
| `FR-INT-09` | choix de la version, échec explicite | `scobelix/verify/solc.py` — `find_solc()`, `solc_for_source()`, `select_version()`, `versions_matching()` ; `scobelix/verify/core.py` — `verify()` ; `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-INT-10` | téléchargement officiel, liste, SHA-256, version, renommage atomique, `User-Agent` | `scobelix/verify/solc.py` — `download_allowed()`, `download_solc()`, `_release_list()`, `_platform_dir()`, `_http_get()`, `_download_dir()`, `BINARIES_URL`, `USER_AGENT` |
| `FR-INT-11` | pyrevm et py-evm facultatives, rôles, disponibilité, Cancun | `scobelix/verify/evm/__init__.py` — `available_backends()`, `make_world()`, `BACKENDS` ; `scobelix/verify/core.py` — `_backends()` |
| `FR-INT-12` | sans machine ou sans compilateur, code produit, forme exacte, code 0 | `scobelix/verify/core.py` — `verify()` ; `scobelix/solgen/tiers.py` — `search()`, `_exact_warning()` ; `scobelix/__main__.py` — `_print_verification()` |
| `FR-INT-13` | base dans le cache utilisateur, nom à empreinte, construction unique sous verrou, lecture seule | `scobelix/utils/helpers.py` — `cache_dir()` ; `scobelix/utils/sigdb.py` — `default_path()`, `_file_name()`, `data_hash()`, `ensure_built()`, `_exclusive_lock()`, `build()`, `_connect_ro()` |
| `FR-INT-14` | `SCOBELIX_SIGDB`, fichier étranger jamais remplacé, repli privé, volume | `scobelix/utils/sigdb.py` — `ENV_PATH`, `_default_locations()`, `_check_replaceable()`, `_private_temp_dir()`, `_open_default()` |
| `FR-INT-15` | données lues dans le paquet, écriture par l'outil seulement | `scobelix/utils/sigdb.py` — `DATA_DIR`, `DUMP_PATH`, `LOCAL_SIGS_PATH`, `EXTRA_SIGS_PATH` ; `scobelix/tools/build_local_sigs.py` — `OUT_PATH` |
| `FR-INT-16` | seul `scobelix.prof` écrit dans le répertoire courant | `scobelix/__main__.py` — `main()` |
| `FR-INT-17` | répertoire temporaire propre à chaque validation, supprimé | `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-INT-18` | écritures hors du répertoire courant limitées | `scobelix/utils/sigdb.py` — `build()`, `ensure_built()` ; `scobelix/verify/solc.py` — `download_solc()`, `_standard_json_output()` ; `scobelix/solgen/validate.py` — `validate_solidity()` |
| `FR-INT-19` | paquet construit par poetry-core ≥ 1.2.0, version unique `X.Y.Z` | `pyproject.toml` — `[build-system]`, clé `version` |
| `FR-INT-20` | script console, contrainte d'interpréteur, dépendances, option `verify` | `pyproject.toml` — `[tool.poetry.scripts]`, `[tool.poetry.dependencies]`, `[tool.poetry.extras]`, `[tool.poetry.group.dev.dependencies]` |
| `FR-INT-21` | trois fichiers de données inclus dans le paquet | `pyproject.toml` — clé `packages` |
| `FR-INT-22` | répertoire de tests, greffon désactivé, marqueur `slow` exclu par défaut | `pyproject.toml` — `[tool.pytest.ini_options]` |
| `FR-INT-23` | setuptools < 81 requis par la bibliothèque Ethereum seule, non déclaré | `.github/workflows/ci.yml` — étape `Install dependencies` ; `pyproject.toml` ; `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/tools/build_local_sigs.py` |
| `FR-INT-24` | déclenchement sur envoi et demande de fusion vers la branche de travail ou `master`, sauf commit de tête marqué `[skip ci]` | `.github/workflows/ci.yml` — clé `on` ; `.github/workflows/bump-version.yml` — étape `Commit and push changes` |
| `FR-INT-25` | Ubuntu, Python 3.9 / 3.10 / 3.11, sans arrêt global | `.github/workflows/ci.yml` — job `test` |
| `FR-INT-26` | étapes dans l'ordre | `.github/workflows/ci.yml` — étapes `Install dependencies`, `Install the solc releases the tests compile with`, `Build the signature database`, `Run tests`, `Run slow tests`, `Lint (report only - not a merge gate yet)` |
| `FR-INT-27` | vérificateur de style informatif | `.github/workflows/ci.yml` — étape `Lint (report only - not a merge gate yet)` |
| `FR-INT-28` | versionnage sur envoi vers la branche de travail, non relancé grâce à `[skip ci]` | `.github/workflows/bump-version.yml` — clé `on`, étape `Commit and push changes` |
| `FR-INT-29` | version = max(manifeste, dernière étiquette) + correctif, ligne unique réécrite | `.github/workflows/bump-version.yml` — étape `Bump version in pyproject.toml` |
| `FR-INT-30` | commit si changement, auteur déclaré robot, envoi de la branche, étiquette | `.github/workflows/bump-version.yml` — étapes `Commit and push changes`, `Tag the new version` |
| `FR-INT-31` | jeton dédié, historique complet | `.github/workflows/bump-version.yml` — étape `Checkout repo` |
| `FR-INT-32` | suite pytest et couverture | `tests/` (modules `test_*.py` du moteur, dont `test_golden_fixtures.py`, `test_dispatcher.py`, `test_metadata.py`, `test_memory_seed.py`, `test_vm_semantics.py`, `test_simplify.py`, `test_simplify_fuzz.py`, `test_simplify_time_limit.py`, `test_hash_seed.py`, `test_storage_defs.py`, `test_param_inference.py`, `test_function_traits.py`, `test_proxy_detect.py`, `test_sigdb.py`, `test_loader_input.py`, `test_main_combined_json.py`, `test_solgen_validate.py`, `test_fixtures_build.py`) ; `tests/solgen/` ; `tests/verify/` |
| `FR-INT-33` | tests de compilation ignorés sans la version exacte, échec sur refus du compilateur, tests d'exécution ignorés sans machine | `tests/solgen/conftest.py` — `installed()`, `solc_or_skip()`, `compile_or_fail()`, `backend_or_skip()` ; `tests/verify/verify_helpers.py` — `solc_path()`, `requires_solc`, `requires_backend` ; `tests/test_solgen_validate.py` |
| `FR-INT-34` | bytecodes de référence, registre, reconstruction à l'octet | `tests/fixtures/build_fixtures.py` — `compile_fixture()`, `main()` ; `tests/fixtures/fixtures.json` ; `tests/fixtures/bytecode/`, `tests/fixtures/sources/` ; `tests/test_fixtures_build.py` — `test_every_bytecode_fixture_is_registered()`, `test_fixture_rebuilds_byte_identical()` |
| `FR-INT-35` | marqueur `slow`, exclu par défaut, `-m slow` | `pyproject.toml` — `[tool.pytest.ini_options]` ; `tests/solgen/conftest.py` — `BUILD_VARIANTS`, `LONG_DIFFERENTIAL`, `fixture_params()`, `differential_fixtures()` |
| `FR-INT-36` | échec attendu strict pour une limite documentée | `tests/solgen/test_storage_fixtures.py` — `_L2_AMBIGUOUS`, `test_l2_touched_variables_at_their_positions()` |
| `FR-INT-37` | exemples exécutables du filtrage par motifs hors suite | `scobelix/matcher.py` |
| `FR-INT-38` | pipeline Jenkins et script shell hérités, hors contrat | `Jenkinsfile` (étapes `Fetch bytecode & decompile`, `Verify Vyper file`, bloc `post`) ; `decompile_link.sh` |

### Pipeline de décompilation : désassemblage, exécution symbolique, structuration et simplification (`FR-DEC`)

Exigences détaillées dans [pipeline-decompilation.md](pipeline-decompilation.md), énoncés fonctionnels dans [../specification-fonctionnelle/pipeline-decompilation.md](../specification-fonctionnelle/pipeline-decompilation.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-DEC-01` | trace exacte et trace d'affichage | `scobelix/simplify.py` — `simplify_trace()`, `_simplify_trace()` ; `scobelix/whiles.py` — `make_whiles()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/function.py` — `Function.__init__()` |
| `FR-DEC-02` | indépendance vis-à-vis de `PYTHONHASHSEED` | `scobelix/core/variants.py` — `extract_variables()`, `possibilities()`, `replace_dict()` ; `scobelix/sparser.py` — `find_stores()` ; `scobelix/contract.py` — `Contract.make_asts()` ; `scobelix/core/algebra.py` — `_max_op()` |
| `FR-DEC-03` | chaîne hexadécimale ou octets, préfixe `0x`/`0X`, blancs ignorés, code vide | `scobelix/loader.py` — `parse_hex_code()`, `Loader.load_binary()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-DEC-04` | refus d'une entrée invalide avec la raison | `scobelix/loader.py` — `InvalidBytecode`, `parse_hex_code()` |
| `FR-DEC-05` | terminaison de métadonnées exclue du désassemblage, bytecode complet conservé | `scobelix/utils/metadata.py` — `parse_metadata()`, `_cbor_decode()` ; `scobelix/loader.py` — `Loader.load_binary()`, `Loader.bytecode` ; `scobelix/decompiler.py` — `Decompilation` |
| `FR-DEC-06` | opcode connu ou `UNKNOWN` | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/utils/opcode_dict.py` — `opcode_dict` |
| `FR-DEC-07` | jeu d'opcodes jusqu'à Cancun | `scobelix/utils/opcode_dict.py` — `opcode_dict` |
| `FR-DEC-08` | immédiat lu dans le bytecode complet, complété par des zéros | `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-DEC-09` | positions, `jumpdest`, `jumpdest` de la terminaison | `scobelix/loader.py` — `Loader.load_binary()`, `Loader.trailer_jump_dests` |
| `FR-DEC-10` | immédiats entiers dans la trace | `scobelix/loader.py` — `Loader.load_binary()` ; `scobelix/prettify.py` — `pretty_num()` |
| `FR-DEC-11` | format du désassemblage, code avant la terminaison | `scobelix/loader.py` — `Loader.disasm()` |
| `FR-DEC-12` | passe légère et points d'entrée | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.run()`, `LOADER_TIMEOUT` ; `scobelix/vm.py` — `VM.handle_jumps()` |
| `FR-DEC-13` | formes du sélecteur et des tests | `scobelix/dispatcher.py` — `is_selector_expr()`, `selector_test()` ; `scobelix/vm.py` — `VM.handle_jumps()` |
| `FR-DEC-14` | comparaisons de recherche dichotomique | `scobelix/dispatcher.py` — `is_selector_range_test()`, `_Walker.walk()` |
| `FR-DEC-15` | frontière du dispatcher, sortie irrégulière | `scobelix/dispatcher.py` — `_Walker.walk()`, `callvalue_test()`, `is_plain_revert()`, `Dispatcher.regular` |
| `FR-DEC-16` | classement des sorties | `scobelix/dispatcher.py` — `_Walker.exit()`, `_Walker.cds_branch()`, `calldatasize_test()`, `_intersect()` |
| `FR-DEC-17` | choix des fonctions de repli et de réception | `scobelix/dispatcher.py` — `analyse()`, `canonical()`, `Exit.code` |
| `FR-DEC-18` | sorties incohérentes → code entier | `scobelix/dispatcher.py` — `analyse()` ; `scobelix/loader.py` — `Loader.run()` |
| `FR-DEC-19` | sélecteurs dupliqués | `scobelix/dispatcher.py` — `analyse()` |
| `FR-DEC-20` | marquage par le test de valeur remonté | `scobelix/dispatcher.py` — `_Walker.walk()`, `analyse()` (`guarded()`), `Dispatcher.callvalue_guarded_keys()` ; `scobelix/loader.py` — `Loader.callvalue_guarded_functions()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-DEC-21` | pas de dispatch → fonction de repli unique | `scobelix/dispatcher.py` — `analyse()`, `routes_selectors()`, `no_dispatch_summary()`, `is_plain_revert()` ; `scobelix/loader.py` — `Loader.run()` |
| `FR-DEC-22` | exception de découverte → `Loader issue.` | `scobelix/loader.py` — `Loader.run()` |
| `FR-DEC-23` | clés et point de départ | `scobelix/loader.py` — `Loader.add_func()` ; `scobelix/dispatcher.py` — `Entry.key`, `FALLBACK`, `RECEIVE` ; `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-24` | mémoire au point de départ | `scobelix/dispatcher.py` — `_Walker.walk()`, `memory_seed()` ; `scobelix/loader.py` — `Loader.add_func()`, `Loader.memory_seed()` ; `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-25` | résumé du dispatcher et nommage | `scobelix/dispatcher.py` — `Dispatcher.to_dict()`, `no_dispatch_summary()` ; `scobelix/loader.py` — `Loader.run()` ; `scobelix/utils/signatures.py` — `make_abi()`, `get_func_name()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-DEC-26` | exploration en largeur, identité position/hauteur/destinations | `scobelix/vm.py` — `Node.__init__()`, `VM.expand_trace()` |
| `FR-DEC-27` | destinations de saut dans la pile | `scobelix/stack.py` — `Stack.jump_dests()` |
| `FR-DEC-28` | 20 × 200 itérations | `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-29` | arrêt sur budget de temps ou de nœuds, en fin d'itération | `scobelix/vm.py` — `should_quit()` dans `VM.run()`, `MAX_NODE_COUNT` |
| `FR-DEC-30` | avertissement et nœuds `decompilation didn't finish` | `scobelix/vm.py` — `VM.run()`, `Node.make_trace()` |
| `FR-DEC-31` | progression toutes les 2 s au plus | `scobelix/vm.py` — `VM.run()` |
| `FR-DEC-32` | évaluation concrète d'un saut conditionnel | `scobelix/vm.py` — `VM.handle_jumps()` ; `scobelix/core/arithmetic.py` — `eval_bool()` |
| `FR-DEC-33` | condition indécidable → `if` | `scobelix/vm.py` — `VM.handle_jumps()` |
| `FR-DEC-34` | élagage → `undefined` `branch pruned` | `scobelix/vm.py` — `VM.handle_jumps()`, `VM.__init__()` |
| `FR-DEC-35` | sauts calculés, hors code ou vers un non-`jumpdest` | `scobelix/vm.py` — `VM._run()` |
| `FR-DEC-36` | chemin qui sort du code désassemblé | `scobelix/vm.py` — `VM._run()`, `VM._past_code()` ; `scobelix/loader.py` — `Loader.runs_into_trailer()` |
| `FR-DEC-37` | pile vide → `undefined` `stack underflow` | `scobelix/stack.py` — `StackUnderflow`, `Stack.pop()`, `Stack.dup()`, `Stack.swap()` ; `scobelix/vm.py` — `VM._run()` |
| `FR-DEC-38` | instruction non modélisée → `undefined` | `scobelix/vm.py` — `VM.apply_stack()`, `VM._run()` ; `scobelix/utils/opcode_dict.py` — `stack_diffs` |
| `FR-DEC-39` | boucle = identité déjà présente chez un ancêtre, pile non vide de même hauteur | `scobelix/vm.py` — `VM.replace_loops()` |
| `FR-DEC-40` | identifiants des variables de boucle | `scobelix/stack.py` — `fold_stacks()` ; `scobelix/vm.py` — `loop_var_depth()` |
| `FR-DEC-41` | nœuds `label` et `goto` | `scobelix/vm.py` — `VM.continue_loops()`, `Node.set_label()`, `Node.make_trace()` |
| `FR-DEC-42` | élargissement des variables de boucle | `scobelix/vm.py` — `VM.continue_loops()` |
| `FR-DEC-43` | réduction modulo 2^256, évaluation concrète, division par zéro | `scobelix/stack.py` — `Stack.simplify()` ; `scobelix/core/arithmetic.py` — `eval()`, `addmod()`, `mulmod()` |
| `FR-DEC-44` | normalisation symbolique | `scobelix/core/algebra.py` — `add_op()`, `mul_op()`, `sub_op()`, `_word()` ; `scobelix/stack.py` — `Stack._simplify()` |
| `FR-DEC-45` | nœuds `addmod` et `mulmod` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/core/arithmetic.py` — `addmod()`, `mulmod()` |
| `FR-DEC-46` | décalages et `byte` | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/core/arithmetic.py` — `shl()`, `shr()`, `sar()`, `byte_op()` |
| `FR-DEC-47` | `not`, `iszero`, comparaisons | `scobelix/vm.py` — `VM.apply_stack()` ; `scobelix/stack.py` — `Stack.cleanup()` |
| `FR-DEC-48` | `mstore`, `mload`, `mcopy` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-49` | `mstore8` sur un octet | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-50` | `calldataload`, `calldatacopy`, `returndatacopy`, `extcodecopy` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-51` | `codecopy` | `scobelix/vm.py` — `VM.apply_stack()`, `MAX_CONCRETE_CODECOPY` |
| `FR-DEC-52` | limite de conversion des entiers relevée | `scobelix/vm.py` — niveau module ; `scobelix/utils/helpers.py` — `allow_int_digits()` |
| `FR-DEC-53` | `codesize` et `pc` concrets | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-54` | `sha3` → variable `_<N>` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-55` | `log0`–`log4` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-56` | `sload`, `sstore`, `tload`, `tstore` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-57` | instantanés des lectures d'état | `scobelix/vm.py` — `VM.snapshot()`, `VM.apply_stack()`, `VM.handle_call()` ; `scobelix/simplify.py` — `cleanup_vars()`, `replace_var()` |
| `FR-DEC-58` | états changés par une ligne | `scobelix/core/effects.py` — `_LINE_EFFECTS`, `changes()`, `trace_changes()`, `kinds()`, `_HEADS`, `RESULT_ATOMS`, `clobbers()` |
| `FR-DEC-59` | écritures et lectures de stockage disjointes | `scobelix/core/effects.py` — `clobbers()`, `_store_fields()`, `storage_slots()`, `_disjoint_fields()`, `disjoint_slots()`, `_hash_based()` |
| `FR-DEC-60` | atomes d'environnement, soldes, code, `blockhash`, `msize` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-61` | `call` et `staticcall` | `scobelix/vm.py` — `VM.handle_call()`, `call_payload()` |
| `FR-DEC-62` | zone de retour min(L, `returndatasize`), copie entière sous contrôle | `scobelix/call_output.py` — `output_write()`, `resolve_call_outputs()`, `_sink()`, `_size_at_least()` ; `scobelix/vm.py` — `VM.handle_call()`, `VM.apply_stack()` ; `scobelix/simplify.py` — `_simplify_trace()` |
| `FR-DEC-63` | `delegatecall` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-64` | `callcode` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-65` | `create` et `create2` | `scobelix/vm.py` — `VM.apply_stack()` |
| `FR-DEC-66` | précompilés | `scobelix/vm.py` — `VM.handle_call()` ; `scobelix/utils/helpers.py` — `precompiled`, `precompiled_var_names` ; `scobelix/core/algebra.py` — `safe_le_op()` |
| `FR-DEC-67` | instructions terminales | `scobelix/vm.py` — `VM.handle_jumps()` |
| `FR-DEC-68` | lignes de diagnostic `--verbose` et `--explain` | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` (`dec()`) |
| `FR-DEC-69` | conversion `label` → `while` | `scobelix/whiles.py` — `make()`, `to_while()`, `replace_vars()` |
| `FR-DEC-70` | garde de rejet → `require` portant la ligne | `scobelix/whiles.py` — `to_while()`, `is_revert()` |
| `FR-DEC-71` | `goto` → `continue` | `scobelix/whiles.py` — `make()` |
| `FR-DEC-72` | label non convertible conservé | `scobelix/whiles.py` — `make()`, `to_while()` |
| `FR-DEC-73` | suppression des `jumpdest` résiduels | `scobelix/whiles.py` — `make_whiles()` |
| `FR-DEC-74` | structuration sans borne propre | `scobelix/whiles.py` — `make_whiles()` ; `scobelix/decompiler.py` — `FUNCTION_TIMEOUT`, `dec()` |
| `FR-DEC-75` | point fixe, 40 passes ou 20 au-delà de 2 000 lignes | `scobelix/simplify.py` — `_simplify_trace()`, `LARGE_TRACE_THRESHOLD`, `MAX_SIMPLIFY_PASSES_LARGE` |
| `FR-DEC-76` | limite de temps de la simplification | `scobelix/simplify.py` — `simplify_trace()`, `_out_of_time()`, `_deadline`, `cleanup_mems()`, `replace_mem()`, `cleanup_vars()` ; `scobelix/decompiler.py` — `simplification_deadline()`, `SIMPLIFY_RESERVE`, `WHILES_TIMEOUT` |
| `FR-DEC-77` | fonction marquée `time_limited` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/function.py` — `Function.time_limited`, `Function.serialize()` |
| `FR-DEC-78` | progression toutes les 5 passes | `scobelix/simplify.py` — `_simplify_trace()` |
| `FR-DEC-79` | ordre des passes | `scobelix/simplify.py` — `_simplify_trace()` ; `scobelix/postprocess.py` — `cleanup_mul_1()` |
| `FR-DEC-80` | simplification d'expressions mise en cache | `scobelix/simplify.py` — `simplify_exp()`, `_simplify_exp()` ; `scobelix/utils/helpers.py` — `cached()` |
| `FR-DEC-81` | élimination des variables | `scobelix/simplify.py` — `cleanup_vars()`, `replace_var()`, `_kept_in_memory()`, `_rebinds()`, `affects()` |
| `FR-DEC-82` | nettoyage de la mémoire, sauté au-delà de 2 000 lignes | `scobelix/simplify.py` — `cleanup_mems()`, `replace_mem()`, `trace_uses_mem()`, `MAX_MEM_CLEANUP_TRACE_LEN` |
| `FR-DEC-83` | découpage des écritures en champs, ordre des écritures | `scobelix/core/memloc.py` — `split_setmem()`, `split_store()`, `split_or()`, `order_field_stores()`, `slot_reads()`, `may_alias()` |
| `FR-DEC-84` | instantanés réduits aux champs utilisés | `scobelix/simplify.py` — `narrow_snapshots()`, `_fields_used()` |
| `FR-DEC-85` | nettoyage des conditions | `scobelix/simplify.py` — `cleanup_conds()` |
| `FR-DEC-86` | remplacement de `msize` | `scobelix/simplify.py` — `cleanup_msize()` |
| `FR-DEC-87` | boucles d'écriture mémoire, formes closes exactes, index de stockage | `scobelix/simplify.py` — `loop_to_setmem()`, `_loop_to_setmem()`, `loop_to_setmem_from_storage()`, `parse_counters()`, `_linear_step()`, `_loop_invariant()`, `propagate_storage_in_loops()`, `propagate_storage_in_loop()` |
| `FR-DEC-88` | post-traitement final, trace exacte et trace d'affichage | `scobelix/simplify.py` — `_simplify_trace()`, `_final_cleanup()`, `_shown_field()` ; `scobelix/core/algebra.py` — `max_to_add()` ; `scobelix/rewriter.py` — `postprocess_exp()`, `postprocess_trace()`, `rewrite_string_stores()` |
| `FR-DEC-89` | renommage lisible et `_msize` | `scobelix/simplify.py` — `readability()`, `replace_while_var()` ; `scobelix/prettify.py` — `prettify()` |
| `FR-DEC-90` | rejet ramené dans la branche vraie | `scobelix/simplify.py` — `readability()` |
| `FR-DEC-91` | heuristiques sans signalement, trace d'affichage seulement | `scobelix/simplify.py` — `_simplify_trace()` ; `scobelix/rewriter.py` (docstring de module) |
| `FR-DEC-92` | `if` sur longueur modulo 32 → branche vraie | `scobelix/rewriter.py` — `postprocess_trace()` |
| `FR-DEC-93` | chaînes en stockage, cas courts masqués | `scobelix/rewriter.py` — `postprocess_trace()` |
| `FR-DEC-94` | écriture de longueur + deux boucles → tableau en stockage | `scobelix/rewriter.py` — `rewrite_string_stores()` |
| `FR-DEC-95` | signe d'une somme par variantes | `scobelix/core/algebra.py` — `add_ge_zero()`, `ge_zero()` ; `scobelix/core/variants.py` — `variants()`, `candidate_values()`, `possibilities()`, `replace_dict()` |
| `FR-DEC-96` | dépliage en chemins puis fusion | `scobelix/folder.py` — `fold()`, `as_paths()`, `meta_fold_paths()`, `fold_aux()` |
| `FR-DEC-97` | instructions terminales | `scobelix/folder.py` — `TERMINATING` |
| `FR-DEC-98` | pliage réservé à la vue texte | `scobelix/contract.py` — `Contract.make_ast()` ; `scobelix/function.py` — `Function.serialize()`, `Function.orig_trace` |
| `FR-DEC-99` | échec du pliage → `folder failed in a function.` | `scobelix/folder.py` — `fold()` |
| `FR-DEC-100` | formes d'instructions et messages `undefined` | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()`, `VM.handle_call()`, `VM._run()`, `VM._past_code()`, `Node.make_trace()` ; `scobelix/whiles.py` — `make()`, `to_while()` ; `scobelix/simplify.py` — `narrow_snapshots()`, `readability()` |
| `FR-DEC-101` | formes d'expressions | `scobelix/vm.py` — `VM.apply_stack()`, `mem_load()` ; `scobelix/call_output.py` — `output_write()` ; `scobelix/sparser.py` — `repl_stor()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-DEC-102` | largeur exacte des suites d'octets | `scobelix/core/memloc.py` — `self_width()`, `part_width()`, `with_width()`, `slice_exp()` ; `scobelix/simplify.py` — `simplify_blob()`, `simplify_part()`, `_merge_parts()`, `_is_zero_blob()` |
| `FR-DEC-103` | sémantique de `mask_shl` | `scobelix/core/algebra.py` — `mask_op()`, `apply_mask()` ; `OPCODES.md` |
| `FR-DEC-104` | plage `range` (début, longueur) en octets | `scobelix/vm.py` — `mem_load()` ; `scobelix/call_output.py` — `output_write()` |
| `FR-DEC-105` | atomes et variables de résultat | `scobelix/vm.py` — `VM.handle_call()`, `VM.apply_stack()` ; `scobelix/core/effects.py` — `RESULT_ATOMS`, `_RESULT_VARS` |
| `FR-DEC-106` | sens d'une valeur dépendant du temps | `scobelix/core/effects.py` (docstring de module) ; `scobelix/vm.py` — `VM.snapshot()` ; `scobelix/simplify.py` — `cleanup_vars()`, `trace_affects()` |
| `FR-DEC-107` | convention des entiers | `scobelix/stack.py` — `Stack.simplify()` ; `scobelix/simplify.py` — `_simplify_exp()` ; `scobelix/core/arithmetic.py` — `to_real_int()` ; `scobelix/core/algebra.py` — `_word()` |
| `FR-DEC-108` | sérialisation en listes, nœuds résiduels en texte | `scobelix/function.py` — `Function.serialize()` ; `scobelix/vm.py` — `Node.__str__()` |

### Reconstruction des fonctions, des paramètres et de la structure du stockage (`FR-STOR`)

Exigences détaillées dans [reconstruction-fonctions-stockage.md](reconstruction-fonctions-stockage.md), énoncés fonctionnels dans [../specification-fonctionnelle/reconstruction-fonctions-stockage.md](../specification-fonctionnelle/reconstruction-fonctions-stockage.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-STOR-01` | non payable par test de `callvalue` en tête, ou par test remonté du dispatcher | `scobelix/function.py` — `Function.analyse()`, `_memory_seed_length()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-STOR-02` | lecture seule par recherche textuelle | `scobelix/function.py` — `Function.analyse()`, `STATE_CHANGING_OPS` |
| `FR-STOR-03` | constante | `scobelix/function.py` — `Function.analyse()`, `is_constant()`, `PURE_OPS` |
| `FR-STOR-04` | getter | `scobelix/function.py` — `Function.analyse()` |
| `FR-STOR-05` | getter de chaîne, copie repliée dans la trace d'affichage | `scobelix/function.py` — `Function.find_string_getter()`, `fold_string_copies()`, `STRING_COPY_RETURN` |
| `FR-STOR-06` | fonction régulière | `scobelix/function.py` — `Function.__init__()` |
| `FR-STOR-07` | ordre d'affichage | `scobelix/function.py` — `Function.priority()`, `Function.ast_length()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-STOR-08` | signature connue → décalages 4 + 32k | `scobelix/function.py` — `Function.make_params()` |
| `FR-STOR-09` | inférence sur la trace exacte, sources par ordre de force | `scobelix/function.py` — `Function.make_params()`, `infer_params()` |
| `FR-STOR-10` | contrôles du décodeur = gardes de rejet sans données en tête | `scobelix/function.py` — `_prologue_conditions()`, `_revert_condition()`, `BARE_REVERT` |
| `FR-STOR-11` | nombre de mots de tête, mots non lus en `uint256` | `scobelix/function.py` — `infer_params()`, `MAX_HEAD_WORDS` |
| `FR-STOR-12` | contrôles de validation de type | `scobelix/function.py` — `_validator()`, `_cleaned_type()`, `_uint_type()`, `_indexes_storage()` |
| `FR-STOR-13` | paramètres dynamiques par les bornes du décodeur | `scobelix/function.py` — `_dynamic_check()`, `WORD_MAX` |
| `FR-STOR-14` | indices à l'usage | `scobelix/function.py` — `infer_params()` (`f()`, `narrower()`) |
| `FR-STOR-15` | décalage non aligné → avertissement et aucun paramètre | `scobelix/function.py` — `infer_params()` |
| `FR-STOR-16` | ordre de choix du type | `scobelix/function.py` — `infer_params()`, `has_validators()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/core/masks.py` — `mask_to_type()` |
| `FR-STOR-17` | noms `_param1`, `_param2`… | `scobelix/function.py` — `infer_params()` |
| `FR-STOR-18` | nom complété pour un sélecteur non résolu | `scobelix/function.py` — `Function.make_names()` |
| `FR-STOR-19` | masques redondants retirés, lectures remplacées par `param` | `scobelix/function.py` — `Function.cleanup_masks()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-STOR-20` | collecte de tous les accès, ordre de première apparition, reconstruction unique | `scobelix/sparser.py` — `rewrite_functions()`, `find_stores()`, `_find_stores()` |
| `FR-STOR-21` | constantes proches d'un haché keccak, table des mappings | `scobelix/sparser.py` — `rainbow_sha3()`, `_keccak_slots()`, `KECCAK_SLOTS`, `KECCAK_SPAN`, `sha3_loc_table`, `sha3_loc_values` |
| `FR-STOR-22` | `loc`, `map`, `array` et leurs imbrications | `scobelix/sparser.py` — `_sparser()` |
| `FR-STOR-23` | constante ajoutée → champ décalé de 256 × N bits | `scobelix/sparser.py` — `_sparser()` |
| `FR-STOR-24` | emplacement constant aussi base d'un tableau → `length` | `scobelix/sparser.py` — `_sparser()` |
| `FR-STOR-25` | forme `stor`, réécriture des traces, accès non résolus | `scobelix/sparser.py` — `_sparser()`, `repl_stor()` |
| `FR-STOR-26` | regroupement par emplacement, aucune définition sans base entière | `scobelix/sparser.py` — `rewrite_functions()`, `get_loc()` |
| `FR-STOR-27` | au plus une définition pour un emplacement non simple, type d'élément | `scobelix/sparser.py` — `rewrite_functions()`, `get_type()` |
| `FR-STOR-28` | emplacement à accès simples → une définition masquée par champ | `scobelix/sparser.py` — `rewrite_functions()` |
| `FR-STOR-29` | définitions triées par emplacement | `scobelix/sparser.py` — `rewrite_functions()` |
| `FR-STOR-30` | nom tiré du getter | `scobelix/sparser.py` — `find_storage_names()`, `_name_composite()` |
| `FR-STOR-31` | portée du nommage, getters de longueur et booléens, remise à zéro par contrat | `scobelix/sparser.py` — `replace_names_in_assoc()`, `replace_names_in_assoc_bool()`, `_name_composite()`, `used_locs`, `rewrite_functions()` |
| `FR-STOR-32` | noms `stor<N>` et `stor<HEX>` | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-STOR-33` | exclusion un par un, avertissement | `scobelix/sparser.py` — `_sparser_resilient()`, `_find_unresolvable_storage()` |
| `FR-STOR-34` | échec global → `{}`, traces non renommées | `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-STOR-35` | écritures en affectations, emplacements restants nommés | `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-STOR-36` | conversion ou champ supprimés si uniformes dans toutes les fonctions | `scobelix/contract.py` — `Contract.make_asts()` |
| `FR-STOR-37` | même nom pour deux emplacements → erreur journalisée | `scobelix/contract.py` — `Contract.make_asts()` |
| `FR-STOR-38` | quatre constantes, immédiats entiers bruts | `scobelix/utils/proxy_detect.py` — `KNOWN_PROXY_SLOTS`, `detect_proxy_slots()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-STOR-39` | dédoublonnage et contenu de l'indice | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-STOR-40` | purement indicatif | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-STOR-41` | constantes, noms entièrement en majuscules en dernier | `scobelix/contract.py` — `Contract.postprocess()` |

### Résolution des signatures et régénération de la base locale (`FR-SIG`)

Exigences détaillées dans [resolution-signatures.md](resolution-signatures.md), énoncés fonctionnels dans [../specification-fonctionnelle/resolution-signatures.md](../specification-fonctionnelle/resolution-signatures.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-SIG-01` | quatre sources locales par confiance décroissante, source absente signalée | `scobelix/utils/sigdb.py` — `default_sources()`, `_SOURCE_PRIORITY`, `_fill()` ; `scobelix/utils/supplement.py` — `LOCAL_SIGS` |
| `FR-SIG-02` | vérification keccak de chaque entrée | `scobelix/utils/sigdb.py` — `_make_entry()`, `keccak256()`, `_read_curated()`, `_read_dump()`, `_read_selector_table()` |
| `FR-SIG-03` | rejets comptés par source et par motif | `scobelix/utils/sigdb.py` — `_make_entry()`, `_parse_params()`, `_key_int()`, `_fill()`, `build()` |
| `FR-SIG-04` | espaces de noms, signatures non typées, topic0 complet, bibliothèques | `scobelix/utils/sigdb.py` — `_make_entry()`, `_read_dump()`, `_row()`, `_SCHEMA_SQL` |
| `FR-SIG-05` | candidats, fusion et classement | `scobelix/utils/sigdb.py` — `_merge()`, `_fill()` |
| `FR-SIG-06` | noms de paramètres et noms génériques | `scobelix/utils/sigdb.py` — `_representative()`, `_NAMES_PRIORITY`, `_is_generic()`, `_GENERIC_NAME`, `_row()` |
| `FR-SIG-07` | types de retour et mutabilité | `scobelix/utils/sigdb.py` — `_mutability()`, `_make_entry()`, `_representative()` |
| `FR-SIG-08` | table interne partie du système | `scobelix/utils/supplement.py` — `LOCAL_SIGS` |
| `FR-SIG-09` | fichier `sigdb-<schéma>-<empreinte>.sqlite`, construit à la première recherche | `scobelix/utils/sigdb.py` — `SCHEMA_VERSION`, `data_hash()`, `_file_name()`, `default_path()`, `_default_locations()`, `get_default()` ; `scobelix/utils/helpers.py` — `cache_dir()` |
| `FR-SIG-10` | journalisation INFO de la construction | `scobelix/utils/sigdb.py` — `_open_default()`, `build()` |
| `FR-SIG-11` | construction atomique sous verrou, fichiers temporaires périmés | `scobelix/utils/sigdb.py` — `build()`, `ensure_built()`, `_exclusive_lock()`, `_remove_stale_temporaries()` |
| `FR-SIG-12` | base complète, métadonnées | `scobelix/utils/sigdb.py` — `_is_complete()`, `build()`, `SigDB.stats()` |
| `FR-SIG-13` | lecture seule immuable, connexion par processus, mémoire des recherches | `scobelix/utils/sigdb.py` — `_connect_ro()`, `SigDB._query()`, `SigDB._cached()` |
| `FR-SIG-14` | `SCOBELIX_SIGDB` | `scobelix/utils/sigdb.py` — `ENV_PATH`, `default_path()`, `_default_locations()`, `ensure_built()` |
| `FR-SIG-15` | refus de remplacer ce qui n'est pas une base de signatures | `scobelix/utils/sigdb.py` — `ensure_built()`, `_check_replaceable()`, `_has_meta_table()`, `_SQLITE_HEADER` |
| `FR-SIG-16` | repli sur un répertoire temporaire privé | `scobelix/utils/sigdb.py` — `_default_locations()`, `_private_temp_dir()` |
| `FR-SIG-17` | erreur d'environnement, emplacement suivant | `scobelix/utils/sigdb.py` — `_open_default()` |
| `FR-SIG-18` | erreur des données, sans autre emplacement | `scobelix/utils/sigdb.py` — `_open_default()`, `build()` |
| `FR-SIG-19` | base indisponible, aucun candidat, décompilation sans noms | `scobelix/utils/sigdb.py` — `get_default()`, `lookup_function()`, `lookup_event()`, `lookup_error()` ; `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-SIG-20` | formes et largeur des clés | `scobelix/utils/sigdb.py` — `_key_int()` ; `scobelix/utils/supplement.py` — `fetch_sig()` ; `scobelix/utils/signatures.py` — `find_sig_name()` |
| `FR-SIG-21` | recherche de fonction cloisonnée | `scobelix/utils/sigdb.py` — `SigDB.lookup_function()` |
| `FR-SIG-22` | recherche d'erreur et signatures d'autres natures | `scobelix/utils/sigdb.py` — `SigDB.lookup_error()`, `SigDB._event_prefix_rows()` |
| `FR-SIG-23` | recherche d'événement par topic0 complet | `scobelix/utils/sigdb.py` — `SigDB.lookup_event()` |
| `FR-SIG-24` | filtre par types | `scobelix/utils/sigdb.py` — `SigDB._filter_types()`, `_canonical_type_string()`, `signature_types()` |
| `FR-SIG-25` | contenu des candidats, copies indépendantes | `scobelix/utils/sigdb.py` — `SigDB._candidate()`, `_decode_inputs()`, `_hex()` |
| `FR-SIG-26` | sélecteur résolu → nom affiché et nom ABI | `scobelix/loader.py` — `Loader.add_func()`, `Loader.run()` ; `scobelix/utils/signatures.py` — `make_abi()`, `fix_input_names()`, `get_func_name()`, `get_abi_name()` ; `scobelix/utils/supplement.py` — `fetch_sig()` |
| `FR-SIG-27` | sélecteur sans candidat → `unknown<sélecteur>` | `scobelix/utils/signatures.py` — `make_abi()` ; `scobelix/function.py` — `Function.make_names()` |
| `FR-SIG-28` | `_fallback` et `_receive` suivis de `(?)` | `scobelix/dispatcher.py` — `FALLBACK`, `RECEIVE` ; `scobelix/loader.py` — `Loader.run()` ; `scobelix/utils/signatures.py` — `make_abi()`, `get_func_name()` |
| `FR-SIG-29` | recherche limitée aux positions de sélecteur, format du nom | `scobelix/prettify.py` — `try_fname()`, `pretty_num()` ; `scobelix/utils/signatures.py` — `find_sig_name()` |
| `FR-SIG-30` | comparaisons avec le sélecteur des données d'appel | `scobelix/prettify.py` — `pretty_selector_operand()`, `is_selector_exp()`, `prettify()` ; `scobelix/dispatcher.py` — `is_selector_expr()` |
| `FR-SIG-31` | têtes de mots et données de retour sur 4 octets | `scobelix/prettify.py` — `pretty_selector_operand()`, `is_word_head_exp()` |
| `FR-SIG-32` | sélecteur d'un appel externe | `scobelix/prettify.py` — `pretty_line()`, `split_payload()`, `pretty_fname()`, `try_fname()` |
| `FR-SIG-33` | données de rejet | `scobelix/prettify.py` — `pretty_line()`, `payload_selector()`, `pretty_memory()`, `try_fname()` ; `scobelix/utils/signatures.py` — `find_sig_name()` |
| `FR-SIG-34` | écritures en mémoire et têtes de blocs | `scobelix/prettify.py` — `prettify()`, `selector_value()`, `pretty_memory()`, `payload_selector()` |
| `FR-SIG-35` | topic0 d'un journal | `scobelix/prettify.py` — `pretty_line()`, `pretty_fname()` ; `scobelix/utils/signatures.py` — `find_sig_name()` |
| `FR-SIG-36` | aucun répertoire à parcourir → message, aucune écriture | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `main()` |
| `FR-SIG-37` | parcours récursif des répertoires de `SCOBELIX_ABI_ROOTS` | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `main()` |
| `FR-SIG-38` | répertoire inexistant → avertissement sur la sortie standard | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-39` | dédoublonnage par chemin résolu, ordre lexicographique | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-40` | extraction des signatures, silence sur les non-conformités | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `abi_functions()`, `walk_misc_signatures()`, `signature()` |
| `FR-SIG-41` | première occurrence d'une signature, noms `param<k>` à défaut | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-42` | sélecteur calculé localement | `scobelix/tools/build_local_sigs.py` — `compute_selector()` |
| `FR-SIG-43` | première signature par sélecteur, collisions comptées | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-44` | écriture complète à `SCOBELIX_SIGS_OUT`, répertoires créés | `scobelix/tools/build_local_sigs.py` — `OUT_PATH`, `main()` |
| `FR-SIG-45` | message récapitulatif | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-SIG-46` | fichier régénéré pris en compte par la base suivante | `scobelix/utils/sigdb.py` — `LOCAL_SIGS_PATH`, `default_sources()`, `data_hash()` ; `scobelix/tools/build_local_sigs.py` — `OUT_PATH` |

### Sorties produites par Scobelix (`FR-SOR`)

Exigences détaillées dans [sorties.md](sorties.md), énoncés fonctionnels dans [../specification-fonctionnelle/sorties.md](../specification-fonctionnelle/sorties.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-SOR-01` | une sortie principale par entrée sur la sortie standard, sortie d'erreur pour journal, vérification, validation et entrée invalide | `scobelix/__main__.py` — `print_decompilation()`, `_print_verification()`, `main()` |
| `FR-SOR-02` | cohérence texte / AST / payload | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-03` | première ligne `# Palkeoramix decompiler. ` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-04` | bloc des slots de proxy | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-05` | bloc des fonctions en échec | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-06` | ligne vide, constantes, stockage, getters, fonctions régulières | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/function.py` — `Function._print()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-SOR-07` | bloc de stockage et syntaxe des types | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/prettify.py` — `pretty_type()` |
| `FR-SOR-08` | séparateur `Regular functions` | `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-09` | commentaire d'une fonction dont la simplification a été arrêtée | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/function.py` — `Function.time_limited` |
| `FR-SOR-10` | bytecode vide ou réduit aux métadonnées → `# No code found for this contract.` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.load_binary()` |
| `FR-SOR-11` | `def <nom>[ payable]: <commentaire>` | `scobelix/function.py` — `Function._print()` |
| `FR-SOR-12` | indentation 2 puis +4, corps vide `  stop`, `stop` final masqué | `scobelix/prettify.py` — `pprint_logic()` ; `scobelix/function.py` — `Function._print()` |
| `FR-SOR-13` | corps rendu depuis la vue pliée | `scobelix/function.py` — `Function._print()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-SOR-14` | `require`, et `if` pour un échec qui n'est pas un rejet nu | `scobelix/prettify.py` — `pprint_logic()` |
| `FR-SOR-15` | `if`/`else`, `while`, `continue`, affectation parallèle | `scobelix/prettify.py` — `pprint_logic()`, `pretty_line()` |
| `FR-SOR-16` | affectations, écritures mémoire, stockage transitoire | `scobelix/prettify.py` — `prettify()`, `pretty_line()` |
| `FR-SOR-17` | écritures de stockage et formes abrégées | `scobelix/prettify.py` — `pretty_line()` ; `scobelix/contract.py` — `Contract.make_ast()` |
| `FR-SOR-18` | `return` / `revert with`, `return` et `revert` seuls, mémoire non résolue, erreur nommée | `scobelix/prettify.py` — `pretty_line()`, `pretty_memory()`, `try_fname()`, `payload_selector()` |
| `FR-SOR-19` | `Panic(<code>)` et libellés | `scobelix/prettify.py` — `PANIC_SELECTOR`, `PANIC_CODES`, `pretty_line()` |
| `FR-SOR-20` | découpage des longs retours | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-21` | décompilation interrompue | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-22` | journaux d'événements | `scobelix/prettify.py` — `pretty_line()`, `pretty_fname()` |
| `FR-SOR-23` | appels externes | `scobelix/prettify.py` — `pretty_line()`, `pretty_gas()`, `split_payload()` |
| `FR-SOR-24` | `selfdestruct`, précompilé, créations | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-25` | lignes `--verbose` et label résiduel | `scobelix/prettify.py` — `pretty_line()` |
| `FR-SOR-26` | valeurs d'environnement | `scobelix/prettify.py` — `prettify()` |
| `FR-SOR-27` | opérateurs infixes, primes pour le signé, `2^256 - n`, formes d'appel | `scobelix/prettify.py` — `prettify()` |
| `FR-SOR-28` | masques et conversions de type, `Mask(…)`, `ceil32`/`floor32`, `int<N>` | `scobelix/prettify.py` — `prettify()` ; `scobelix/core/masks.py` — `mask_to_type()` |
| `FR-SOR-29` | accès aux données | `scobelix/prettify.py` — `prettify()` ; `scobelix/utils/signatures.py` — `get_param_name()` |
| `FR-SOR-30` | accès au stockage | `scobelix/prettify.py` — `pretty_stor()` |
| `FR-SOR-31` | noms lisibles, `True`/`False` résiduels | `scobelix/prettify.py` — `prettify()` ; `scobelix/postprocess.py` — `cleanup_mul_1()` |
| `FR-SOR-32` | mise en forme des entiers par règles ordonnées | `scobelix/prettify.py` — `prettify()`, `pretty_num()` ; `scobelix/utils/helpers.py` — `pretty_bignum()` |
| `FR-SOR-33` | positions de sélecteur nommées ou `0x%08x`, parties d'octets de largeur visible | `scobelix/prettify.py` — `pretty_selector_operand()`, `try_fname()`, `is_selector_exp()`, `is_word_head_exp()`, `prettify()` |
| `FR-SOR-34` | séquences ANSI toujours présentes | `scobelix/utils/helpers.py` — classe `C`, `color()`, `clean_color()` ; `scobelix/prettify.py` — `prettify()`, `pretty_line()` |
| `FR-SOR-35` | six clés dans l'ordre | `scobelix/contract.py` — `Contract.json()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-36` | `problems` identifiant → nom | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.run()` |
| `FR-SOR-37` | `stor_defs` liste de quadruplets, `{}` en cas d'échec | `scobelix/sparser.py` — `rewrite_functions()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-SOR-38` | objet fonction, clés et ordre, `time_limited` facultatif | `scobelix/function.py` — `Function.serialize()` |
| `FR-SOR-39` | `trace` de la vue d'affichage, non pliée, listes et textes | `scobelix/function.py` — `Function.__init__()`, `Function.serialize()` ; `scobelix/whiles.py` — `make_whiles()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/contract.py` — `Contract.postprocess()` |
| `FR-SOR-40` | `params` à clés décimales | `scobelix/function.py` — `Function.serialize()` |
| `FR-SOR-41` | `proxy_hints` | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` |
| `FR-SOR-42` | `metadata` | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/utils/metadata.py` — `parse_metadata()`, `Metadata.to_dict()` |
| `FR-SOR-43` | `dispatcher` | `scobelix/loader.py` — `Loader.run()` ; `scobelix/dispatcher.py` — `Dispatcher.to_dict()`, `no_dispatch_summary()` |
| `FR-SOR-44` | AST `{}` pour un bytecode vide ou un échec de sérialisation | `scobelix/decompiler.py` — classe `Decompilation`, `_decompile_with_loader()` |
| `FR-SOR-45` | `--json` indenté de deux espaces | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-46` | objet sur une ligne, séparateurs par défaut, saut de ligne final | `scobelix/__main__.py` — `print_decompilation()` ; `tests/test_main_combined_json.py` |
| `FR-SOR-47` | `text` et `json` toujours présents, dans cet ordre | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-48` | clés Solidity, vérification et validation | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-49` | `solgen_functions` | `scobelix/solgen/v2.py` — `SolgenResult.functions_json()` |
| `FR-SOR-50` | `solgen_verification`, objet de repli | `scobelix/__main__.py` — `_verification_json()`, `_verification_warnings()` ; `scobelix/solgen/v2.py` — `SolgenResult.verification_json()` ; `scobelix/solgen/tiers.py` — `Verification.to_json()` |
| `FR-SOR-51` | contrat d'intégration générique | `tests/test_main_combined_json.py` ; `scobelix/__main__.py` — `parse_args()` |
| `FR-SOR-52` | code généré imprimé, saut de ligne supplémentaire | `scobelix/__main__.py` — `print_decompilation()` |
| `FR-SOR-53` | résumé de vérification sur la sortie d'erreur | `scobelix/__main__.py` — `_print_verification()`, `_verification_warnings()` ; `scobelix/solgen/tiers.py` — `Verification` |
| `FR-SOR-54` | statut, ligne IR et erreurs sur la sortie d'erreur | `scobelix/__main__.py` — `print_decompilation()` ; `scobelix/solgen/validate.py` — `validate_solidity()`, `VIA_IR_ONLY` |
| `FR-SOR-55` | clés du rapport, niveaux et statuts, `passed` | `scobelix/verify/report.py` — `VerificationReport.to_json()`, `VerificationReport.passed`, `LevelResult.to_dict()` ; `scobelix/verify/core.py` — `verify()` ; `scobelix/solgen/tiers.py` — `Verification.passed` |
| `FR-SOR-56` | entrées par fonction et verdicts | `scobelix/verify/report.py` — `FunctionReport.to_dict()`, `Verdict`, `derive_verdict()` |
| `FR-SOR-57` | `INCONCLUSIVE` d'environnement et de gas, statut de L3 | `scobelix/verify/report.py` — `derive_verdict()` ; `scobelix/verify/core.py` — `_level3()` ; `scobelix/verify/equiv.py` — `Differ._record()` |
| `FR-SOR-58` | contre-exemple | `scobelix/verify/report.py` — `counterexample_to_dict()`, `_call_to_dict()`, `_pre_to_dict()`, `_result_to_dict()` |
| `FR-SOR-59` | format de journal | `scobelix/__main__.py` — `main()` |
| `FR-SOR-60` | messages INFO minimaux | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/utils/sigdb.py` — `_open_default()`, `build()` |
| `FR-SOR-61` | avertissements et erreur d'échec de fonction | `scobelix/vm.py` — `VM.run()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/sparser.py` — `_sparser_resilient()` ; `scobelix/utils/sigdb.py` — `_open_default()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` |
| `FR-SOR-62` | message d'entrée invalide | `scobelix/__main__.py` — `main()` ; `scobelix/loader.py` — `parse_hex_code()`, `InvalidBytecode` |
| `FR-SOR-63` | profil au format pstats | `scobelix/__main__.py` — `main()` |

### Spécification de paramétrage des bases de signatures de Scobelix (`FR-PARAM`)

Exigences détaillées dans [parametrage-signatures.md](parametrage-signatures.md), énoncés fonctionnels dans [../specification-parametrage/parametrage-signatures.md](../specification-parametrage/parametrage-signatures.md).

| Exigence | Objet | Fichier — Fonction/élément |
|---|---|---|
| `FR-PARAM-01` | sélecteur, topic0 et forme des clés | `scobelix/utils/sigdb.py` — `function_selector()`, `event_topic()`, `_key_int()` ; `scobelix/tools/build_local_sigs.py` — `compute_selector()` |
| `FR-PARAM-02` | signature canonique, types acceptés et alias | `scobelix/utils/sigdb.py` — `_IDENTIFIER`, `_canonical_elementary()`, `_ELEMENTARY_ALIASES`, `_type_info()`, `_split_types()`, `_parse_params()`, `canonical_signature()` |
| `FR-PARAM-03` | schéma d'une entrée | `scobelix/utils/sigdb.py` — `_make_entry()`, `_parse_params()` |
| `FR-PARAM-04` | objet JSON de sélecteurs vers entrées de fonctions | `scobelix/utils/sigdb.py` — `_read_selector_json()`, `_read_selector_table()`, `_make_entry()` |
| `FR-PARAM-05` | noms vides ou synthétiques | `scobelix/utils/sigdb.py` — `_is_generic()`, `_representative()`, `_NAMES_PRIORITY` ; `scobelix/utils/signatures.py` — `fix_input_names()` ; `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-PARAM-06` | forme produite par l'outil, lecture tolérante | `scobelix/tools/build_local_sigs.py` — `main()` ; `scobelix/utils/sigdb.py` — `_read_selector_json()` |
| `FR-PARAM-07` | document JSON valide dans son ensemble, fichier facultatif | `scobelix/utils/sigdb.py` — `_fill()`, `_read_selector_json()`, `_open_default()` |
| `FR-PARAM-08` | clé égale au sélecteur de la signature canonique | `scobelix/utils/sigdb.py` — `_make_entry()` |
| `FR-PARAM-09` | objet JSON à clé `abi` | `scobelix/utils/sigdb.py` — `_read_curated()`, `data_hash()`, `_fill()` |
| `FR-PARAM-10` | nature de chaque entrée | `scobelix/utils/sigdb.py` — `_read_curated()`, `_fill()` |
| `FR-PARAM-11` | types de retour, mutabilité, drapeaux d'événement | `scobelix/utils/sigdb.py` — `_mutability()`, `_make_entry()`, `_parse_params()` |
| `FR-PARAM-12` | types ABI exigés pour un événement ou une erreur | `scobelix/utils/sigdb.py` — `_make_entry()` |
| `FR-PARAM-13` | archive xz de JSON Lines en UTF-8 | `scobelix/utils/sigdb.py` — `_read_dump()` |
| `FR-PARAM-14` | clés `selector` et `abi`, nature, événements sous le préfixe du topic0 | `scobelix/utils/sigdb.py` — `_read_dump()`, `_make_entry()` |
| `FR-PARAM-15` | `inputs` facultatif, champs exploités | `scobelix/utils/sigdb.py` — `_make_entry()` |
| `FR-PARAM-16` | ligne invalide ignorée et comptée | `scobelix/utils/sigdb.py` — `_fill()` |
| `FR-PARAM-17` | substituts, noms invalides, hachés faux ignorés | `scobelix/utils/sigdb.py` — `_read_dump()`, `_make_entry()` |
| `FR-PARAM-18` | unicité des clés valides par espace de noms | `scobelix/utils/sigdb.py` — `_fill()`, `_row()`, `_SCHEMA_SQL` |
| `FR-PARAM-19` | archive complète et lisible | `scobelix/utils/sigdb.py` — `_read_dump()`, `_fill()` |
| `FR-PARAM-20` | nom `abi*.json`, à toute profondeur | `scobelix/tools/build_local_sigs.py` — `main()` |
| `FR-PARAM-21` | JSON lu en UTF-8, octets invalides ignorés, fichier invalide ignoré | `scobelix/tools/build_local_sigs.py` — `load_abi()` |
| `FR-PARAM-22` | quatre formes de contenu | `scobelix/tools/build_local_sigs.py` — `load_abi()`, `main()` |
| `FR-PARAM-23` | entrées `function` nommées, `inputs` facultatif, `type` et `components` | `scobelix/tools/build_local_sigs.py` — `abi_functions()`, `format_type()` |
| `FR-PARAM-24` | types acceptés par l'outil, suffixes de tableau, tuples aplatis | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `format_type()` |
| `FR-PARAM-25` | un type non accepté → fonction ignorée | `scobelix/tools/build_local_sigs.py` — `abi_functions()` |
| `FR-PARAM-26` | types canoniques recommandés, rejet à la construction | `scobelix/tools/build_local_sigs.py` — `is_supported_type()`, `signature()`, `compute_selector()` ; `scobelix/utils/sigdb.py` — `_make_entry()` |
| `FR-PARAM-27` | signatures reconnues dans les chaînes de la forme (d) | `scobelix/tools/build_local_sigs.py` — `parse_signature_string()`, `walk_misc_signatures()`, `main()` |
| `FR-PARAM-28` | base fournie construite, schéma et marque d'achèvement | `scobelix/utils/sigdb.py` — `ensure_built()`, `_is_complete()`, `_check_replaceable()`, `SigDB` |
| `FR-PARAM-29` | aucun autre fichier à cet emplacement | `scobelix/utils/sigdb.py` — `_check_replaceable()`, `_has_meta_table()`, `_open_default()` |
| `FR-PARAM-30` | même schéma que le fichier local, partie du système | `scobelix/utils/supplement.py` — `LOCAL_SIGS` ; `scobelix/utils/sigdb.py` — `default_sources()`, `_read_selector_table()` |

Navigation : [README.md](README.md) · [../README.md](../README.md)
