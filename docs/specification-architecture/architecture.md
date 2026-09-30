# Traçabilité d'architecture — Architecture et interfaces d'appel de Scobelix

Ce document trace chaque exigence de [../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md) vers son implémentation dans le code du dépôt Scobelix : fichier, fonction, et explication concise du mécanisme effectif. Les sections suivent l'ordre du document source ; les chemins sont relatifs à la racine du dépôt. Quand une exigence ne correspond à aucun code précis, cela est dit explicitement.

## 1. Vue d'ensemble et nature du système

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-01** : bibliothèque importable et commande, sans serveur | `scobelix/decompiler.py` — `decompile_bytecode()`, `decompile_address()` ; `scobelix/__main__.py` — `main()` | Les capacités sont de simples fonctions Python ; la commande n'est qu'un analyseur d'arguments qui les appelle. Aucun module du paquet n'ouvre de socket d'écoute, ne définit de route ni n'utilise de base de données ou de file de messages. |
| **FR-ARCH-02** : exécution synchrone, dans le processus et le fil de l'appelant | `scobelix/decompiler.py` — `_decompile_with_loader()` | Enchaîne toutes les étapes séquentiellement dans l'appel et ne retourne l'objet `Decompilation` qu'après le rendu du texte ; aucun fil ni processus n'est créé (le budget par fonction s'appuie sur un signal, pas sur un processus fils). |
| **FR-ARCH-03** : aucun accès réseau hors lecture du code d'une adresse | `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/utils/supplement.py` — `fetch_sig()` | `load_addr()` est le seul endroit qui importe la couche web3 et appelle `w3.eth.get_code()` ; `fetch_sig()` ne consulte que la table `LOCAL_SIGS`, le cache disque et `local_sigs.json`. |
| **FR-ARCH-04** : bytecode runtime seulement, bytecode de création non distingué | `scobelix/loader.py` — `Loader.load_binary()` | Convertit la chaîne hexadécimale en octets puis en lignes désassemblées sans aucune analyse de structure : un bytecode de création est désassemblé et exécuté depuis la position 0 comme n'importe quel code. |
| **FR-ARCH-05** : en-tête hérité `# Palkeoramix decompiler. ` | `scobelix/decompiler.py` — `_decompile_with_loader()` | Première instruction du bloc `redirect_stdout` : `print(C.gray + "# Palkeoramix decompiler. " + C.end)`. |
| **FR-ARCH-06** : résultat en quatre parties | `scobelix/decompiler.py` — classe `Decompilation` | Dataclass à quatre champs `text`, `asm`, `json`, `proxy_hints`, tous remplis par `_decompile_with_loader()` dans le même appel. |

## 2. Capacités (points d'entrée fonctionnels)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-07** : décompilation d'un bytecode hexadécimal | `scobelix/decompiler.py` — `decompile_bytecode()` ; `scobelix/loader.py` — `Loader.load_binary()` | `load_binary()` retire un préfixe `0x` éventuel (`source[:2] == "0x"`) avant le découpage en octets ; le résultat est produit par `_decompile_with_loader()`. |
| **FR-ARCH-08** : décompilation d'une adresse | `scobelix/decompiler.py` — `decompile_address()` ; `scobelix/loader.py` — `Loader.load_addr()` | `load_addr()` récupère le code puis appelle `self.load_binary(code)` ; la suite est strictement la même fonction `_decompile_with_loader()`. |
| **FR-ARCH-09** : filtre par préfixe de nom, fonctions ignorées hors échecs | `scobelix/decompiler.py` — `_decompile_with_loader()` | Dans la boucle sur `loader.func_list`, `if only_func_name is not None and not fname.startswith(only_func_name): continue` saute la fonction avant le bloc `try`, donc sans l'ajouter à `problems`. |

Note contextuelle du document source (fonction de repli unique, filtre presque toujours inopérant) : confirmée par `scobelix/loader.py` — `Loader.run()`, qui ne retient que des nœuds `funccall` qu'aucune partie de `scobelix/vm.py` n'émet ; seule la fonction `_fallback` est ajoutée, et son nom affiché est `_fallback(?)`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-10** : génération Solidity à partir du seul AST | `scobelix/solgen/emitter.py` — `generate_solidity()` | Construit `SolidityEmitter(decompilation.json or {})` : aucun autre champ du résultat n'est lu. |
| **FR-ARCH-11** : validation par un compilateur externe, statuts `valid`/`invalid`/`skipped` | `scobelix/solgen/validate.py` — `validate_solidity()` | Retourne un `ValidationResult` dont le champ `status` ne prend que ces trois valeurs littérales. |
| **FR-ARCH-12** : outil satellite de régénération des signatures | `scobelix/tools/build_local_sigs.py` — `main()` | Module autonome exécuté par `python -m` ; il n'est importé par aucun autre module du paquet. |
| **FR-ARCH-13** : bytecode vide, résultat « aucun code » sans erreur | `scobelix/decompiler.py` — `_decompile_with_loader()` | Après la passe légère, `if len(loader.lines) == 0: return Decompilation(text=C.gray + "# No code found for this contract." + C.end)` : les trois autres champs gardent leurs valeurs par défaut (`[]`, `{}`, `[]`). Vérifié en bac à sable avec `""` et `"0x"`. |

## 3. Pipeline de décompilation (vue d'ensemble)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-14** : ordre des étapes | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/contract.py` — `Contract.postprocess()` | `load_binary()` (désassemblage) → `loader.run(VM(loader, just_fdests=True))` → par fonction `VM(loader).run()`, `make_whiles()` puis `Function(hash, trace)` (caractérisation) → `Contract.postprocess()` : `sparser.rewrite_functions()`, remplacement `cd` → `param`, liste des constantes, `make_asts()` → `detect_proxy_slots()` → `contract.json()` → rendu texte. |
| **FR-ARCH-15** : décompilation indépendante, échec isolé et journalisé | `scobelix/decompiler.py` — `_decompile_with_loader()` | Le corps de chaque fonction est dans `try … except (Exception, TimeoutInterrupt)` qui fait `problems[hash] = fname` et `logger.exception("Problem with %s%s", …)`, puis la boucle continue ; `Contract(problems=…, functions=…)` est construit ensuite quoi qu'il arrive. |
| **FR-ARCH-16** : reconstruction du stockage une seule fois pour le contrat | `scobelix/contract.py` — `Contract.postprocess()` | Un unique appel `sparser.rewrite_functions(self.functions)` reçoit la liste de toutes les fonctions décompilées. |
| **FR-ARCH-17** : slots de proxy détectés sur le seul désassemblage brut | `scobelix/decompiler.py` — `_decompile_with_loader()` ; `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | `detect_proxy_slots(loader.parsed_lines)` ne reçoit que les triplets bruts produits par `load_binary()`, indépendamment des traces. |
| **FR-ARCH-18** : AST et texte dans la même passe, AST non plié, texte plié | `scobelix/function.py` — `Function.serialize()`, `Function._print()` ; `scobelix/contract.py` — `Contract.make_ast()` | `serialize()` sérialise `self.trace` (non plié) ; `_print()` rend `self.ast`, que `make_ast()` calcule à partir de `folder.fold(trace)`. Les deux sont appelés sur les mêmes objets `Function` dans `_decompile_with_loader()`. |

## 4. Configuration

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-19** : variables lues une seule fois au chargement | `scobelix/decompiler.py` — constantes `FUNCTION_TIMEOUT`, `VM_RUN_TIMEOUT`, `WHILES_TIMEOUT` ; `scobelix/loader.py` — `LOADER_TIMEOUT` ; `scobelix/vm.py` — `MAX_NODE_COUNT` | Les cinq valeurs sont calculées par `int(os.environ.get(…))` au niveau module, lors du premier import ; aucun code ne relit l'environnement ensuite. |
| **FR-ARCH-20** : budget par fonction (720 s) couvrant exécution symbolique, structuration et simplification | `scobelix/decompiler.py` — `dec()` dans `_decompile_with_loader()` | `@timeout_decorator.timeout(FUNCTION_TIMEOUT, timeout_exception=TimeoutInterrupt)` décore la fonction imbriquée qui appelle `VM(loader).run()` puis `make_whiles()` ; le défaut vaut `60 * 12`. La construction de l'objet `Function` est hors de ce budget. |
| **FR-ARCH-21** : budget de l'exécution symbolique (600 s) | `scobelix/decompiler.py` — `dec()` ; `scobelix/vm.py` — `VM.run()`, `should_quit()` | `VM(loader).run(target, stack=stack, timeout=VM_RUN_TIMEOUT)` ; `should_quit()` compare `time.monotonic() - time_start` au budget. |
| **FR-ARCH-22** : budget de la boucle de simplification (600 s) | `scobelix/whiles.py` — `make_whiles()` ; `scobelix/simplify.py` — `simplify_trace()` | `make_whiles(trace, timeout=WHILES_TIMEOUT)` transmet le budget à `simplify_trace()`, seule étape qui le consulte (`should_quit()` local). |
| **FR-ARCH-23** : budget de la découverte (120 s) | `scobelix/loader.py` — `Loader.run()` | `vm.run(0, timeout=LOADER_TIMEOUT)`. |
| **FR-ARCH-24** : valeur nulle = pas de limite de temps | `scobelix/vm.py` — `should_quit()` ; `scobelix/simplify.py` — `simplify_trace()` ; `scobelix/decompiler.py` — `dec()` | Les deux `should_quit()` évaluent `timeout and (…)`, faux pour 0 ; pour le budget par fonction, la bibliothèque `timeout_decorator` n'arme aucune alarme lorsque le nombre de secondes est nul (comportement de la dépendance, constaté dans sa source installée). |
| **FR-ARCH-25** : nombre maximal de nœuds (500 000), seuil d'élagage, valeur nulle non illimitée | `scobelix/vm.py` — `MAX_NODE_COUNT`, `should_quit()`, `VM.handle_jumps()` | `should_quit()` teste `node_count > MAX_NODE_COUNT`, vrai dès le premier nœud si la valeur est 0 ; l'élagage teste `node_count > int(MAX_NODE_COUNT * 0.6)`. Vérifié en bac à sable : avec `PANORAMIX_MAX_NODE_COUNT=0`, l'exploration s'arrête après 5 nœuds avec l'avertissement `VM stopped prematurely`. |
| **FR-ARCH-26** : valeur non entière → erreur au chargement des capacités de décompilation | `scobelix/decompiler.py`, `scobelix/loader.py`, `scobelix/vm.py` (conversions `int()` au niveau module) ; `scobelix/solgen/__init__.py` | `int()` lève `ValueError` à l'import de `scobelix.decompiler` (que la commande importe dès son chargement) ; `scobelix/solgen/__init__.py` n'importe que `emitter` et `validate`, qui n'importent pas le décompilateur. Vérifié : `import scobelix.solgen` réussit avec `PANORAMIX_MAX_NODE_COUNT=abc`, `import scobelix.decompiler` échoue. |
| **FR-ARCH-27** : `WEB3_PROVIDER_URI` non interprétée par le système | `scobelix/loader.py` — `Loader.load_addr()` | Aucun module du dépôt ne lit cette variable ; `load_addr()` utilise l'instance `w3` de `web3.auto`, dont le fournisseur automatique la lit (voir la traçabilité de FR-INT-04 dans [integration.md](integration.md)). |
| **FR-ARCH-28** : `SCOBELIX_ABI_ROOTS`/`SCOBELIX_SIGS_OUT` lues par l'outil seul | `scobelix/tools/build_local_sigs.py` — `ABI_ROOTS`, `OUT_PATH` | Seul ce module lit ces variables ; il n'est importé par aucun autre module du paquet. |
| **FR-ARCH-29** : constantes non configurables | `scobelix/simplify.py` — `LARGE_TRACE_THRESHOLD`, `MAX_SIMPLIFY_PASSES_LARGE`, `MAX_MEM_CLEANUP_TRACE_LEN`, `simplify_trace()` ; `scobelix/vm.py` — `VM.run()`, `VM.handle_jumps()` ; `scobelix/solgen/validate.py` — `validate_solidity()` ; `scobelix/solgen/emitter.py` — `SolidityEmitter.generate()` ; `scobelix/utils/helpers.py` — `cache_dir()` | Valeurs en dur : 2000/20/2000 et le littéral 40 de `simplify_trace()` ; boucles `range(20)` × `range(200)` de `VM.run()` ; facteur `0.6` de l'élagage ; `timeout: int = 30` ; ligne `pragma solidity ^0.8.0;` ; `user_cache_dir("scobelix", "scobelix")`. Aucune n'est lue dans l'environnement. |

Note contextuelle du document source (coexistence des préfixes `PANORAMIX_` et `SCOBELIX_`) : confirmée par les noms de variables lus dans `scobelix/decompiler.py`, `scobelix/loader.py`, `scobelix/vm.py` et `scobelix/tools/build_local_sigs.py`.

## 5. Dépendances fonctionnelles

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-30** : Python ≥ 3.9 et < 4 | `pyproject.toml` — clé `python` de `[tool.poetry.dependencies]` | Contrainte déclarée `">=3.9,<4"`. |
| **FR-ARCH-31** : budget par signal, pas de Windows, fil principal | `scobelix/decompiler.py` — `dec()` ; `README.md` (section « Caveats ») | `timeout_decorator.timeout` est utilisé avec son mode par défaut à signaux (`SIGALRM`, `setitimer`), indisponible sous Windows et hors du fil principal ; le README racine indique que Windows n'est pas supporté. |
| **FR-ARCH-32** : bibliothèque Ethereum 6.0.0-beta.8, usages | `pyproject.toml` — dépendance `web3` ; `scobelix/loader.py` — `Loader.load_addr()` ; `scobelix/solgen/event_signatures.py` — `_topic0()` ; `scobelix/tools/build_local_sigs.py` — `compute_selector()` | `web3` est importé paresseusement dans `load_addr()` (code et adresse checksum), au niveau module dans `event_signatures.py` (keccak des événements, donc dès le chargement du générateur) et dans l'outil (keccak des sélecteurs) ; aucun module du chemin de décompilation d'un bytecode ne l'importe (la table arc-en-ciel et les slots de proxy sont des constantes en dur). |
| **FR-ARCH-33** : journalisation colorée et répertoire de cache standard | `scobelix/__main__.py` — `main()` ; `scobelix/utils/helpers.py` — `cache_dir()` | `coloredlogs.install(…)` n'est appelé que par la commande ; `cache_dir()` utilise `appdirs.user_cache_dir`. |
| **FR-ARCH-34** : compilateur non déclaré, facultatif | `pyproject.toml` ; `scobelix/solgen/validate.py` — `validate_solidity()` | Aucune dépendance solc déclarée ; `validate_solidity()` le cherche par `shutil.which("solc")` et retourne `skipped` en son absence. |
| **FR-ARCH-35** : deux fichiers de données embarqués | `scobelix/data/abi_dump.xz`, `scobelix/data/local_sigs.json` ; `scobelix/utils/supplement.py` — `check_supplements()`, `LOCAL_SIGS_BULK_PATH` | Fichiers situés dans l'arborescence du paquet (23 903 728 octets pour le dump, 557 clés pour le fichier local à la date de rédaction), lus par chemin relatif au module. |

Note contextuelle du document source (client HTTP déclaré mais inutilisé ; bibliothèque de délais en mode signaux) : confirmée — `requests` figure dans `pyproject.toml` mais aucun module de `scobelix/` ne l'importe ; `timeout_decorator` est importé par `scobelix/decompiler.py`.

## 6. État partagé, caches et robustesse

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-36** : caches en mémoire jamais purgés | `scobelix/utils/helpers.py` — `cached()` ; `scobelix/stack.py` — `Stack.simplify()` ; `scobelix/core/algebra.py` — `mask_op()`, `ge_zero()` ; `scobelix/loader.py` — `Loader.find_sig()` ; `scobelix/utils/supplement.py` — `fetch_sig()` | Le décorateur `cached()` conserve un dictionnaire par fonction décorée (`simplify_exp`, `cleanup_vars`, `add_op`, `lt_op`, `to_mask`, `fetch_sig`…) ; `Stack.simplify_cache`, `mask_dict`, `ge_zero_cache` et `cache_sigs` sont des dictionnaires de niveau module ou de classe ; aucun code ne les vide. |
| **FR-ARCH-37** : décompilations successives partageant l'état, y compris les emplacements nommés | `scobelix/sparser.py` — `used_locs`, `replace_names_in_assoc()`, `replace_names_in_assoc_bool()` ; `scobelix/loader.py` — `Loader.signatures` | `used_locs` est un ensemble de niveau module alimenté à chaque reconstruction et consulté par `replace_names_in_assoc_bool()` ; `Loader.signatures` est un attribut de classe partagé par toutes les instances. |
| **FR-ARCH-38** : compteur de nœuds remis à zéro à chaque exécution symbolique | `scobelix/vm.py` — `VM.__init__()` | `global node_count; node_count = 0` dans le constructeur ; un nouvel objet `VM` est créé pour la passe légère et pour chaque fonction. |
| **FR-ARCH-39** : replis locaux journalisés | `scobelix/loader.py` — `Loader.run()` ; `scobelix/folder.py` — `fold()` ; `scobelix/contract.py` — `Contract.postprocess()` | Blocs `except Exception` qui journalisent (`Loader issue.`, `folder failed in a function.`, `Storage postprocessing failed. This is very bad!`) et substituent respectivement la fonction de repli, la trace d'origine et `stor_defs = {}`. |
| **FR-ARCH-40** : AST non sérialisable → `{}` et `Failed json serialization.` | `scobelix/decompiler.py` — `_decompile_with_loader()` | `json.dump(decompilation.json, f)` vers `os.devnull` dans un `try` ; `except Exception: logger.exception("Failed json serialization."); decompilation.json = {}` ; le rendu du texte suit. |
| **FR-ARCH-41** : erreurs propagées sans reprise | `scobelix/loader.py` — `Loader.load_binary()`, `Loader.load_addr()` ; `scobelix/contract.py` — `Contract.make_asts()` ; `scobelix/decompiler.py` — `_decompile_with_loader()` | `int("0x" + …, 16)` lève `ValueError` sur un caractère non hexadécimal ; `assert address.isalnum()` et `w3.eth.get_code()` ne sont protégés par aucun `try` ; `make_asts()` (hors `folder.fold()`) et le bloc `redirect_stdout` du rendu non plus. |
| **FR-ARCH-42** : le budget par fonction ne peut être absorbé | `scobelix/decompiler.py` — classe `TimeoutInterrupt` | Dérive de `BaseException` et échappe donc aux nombreux `except Exception` du moteur ; le dépôt ne contient aucun `except:` nu ni `except BaseException`, seul le `except (Exception, TimeoutInterrupt)` de la boucle principale l'intercepte. |

Note contextuelle du document source (auto-vérifications au chargement, en partie converties en tests) : confirmée par les instructions `assert` de niveau module de `scobelix/utils/helpers.py`, `scobelix/core/masks.py`, `scobelix/core/memloc.py`, `scobelix/core/algebra.py` et `scobelix/folder.py`, et par la docstring de `tests/test_simplify.py`, qui indique que les anciennes assertions de `simplify.py` y ont été déplacées.

## 7. Interface en ligne de commande

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-43** : commande `scobelix` et mode module | `pyproject.toml` — `[tool.poetry.scripts]` ; `scobelix/__main__.py` — `main()` | Le script `scobelix = "scobelix.__main__:main"` et le bloc `if __name__ == "__main__": main()` exécutent la même fonction ; l'analyseur `argparse` prend son nom de programme dans `sys.argv[0]` (`__main__.py` en mode module). |
| **FR-ARCH-44** : un argument positionnel obligatoire, code 2 sinon | `scobelix/__main__.py` — `parse_args()` | Argument positionnel `address_or_bytecode` sans `nargs` ; `argparse` écrit l'usage sur la sortie d'erreur et sort avec le code 2. |
| **FR-ARCH-45** : nature de l'argument selon sa seule longueur | `scobelix/__main__.py` — `print_decompilation()` | `if len(this_addr) == 42: decompile_address(…)` sinon `decompile_bytecode(…)`. |

Note contextuelle du document source (règle de longueur sans contrôle du contenu) : confirmée par le même test `len(this_addr) == 42`, seul critère employé.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-46** : `-` lit l'entrée standard, puis même règle de longueur | `scobelix/__main__.py` — `print_decompilation()` | `if this_addr == "-": this_addr = sys.stdin.read().strip()` précède le test de longueur. |
| **FR-ARCH-47** : liste séparée par des virgules, traitement successif, arrêt à la première erreur | `scobelix/__main__.py` — `main()` | `for addr in args.address_or_bytecode.split(","): print_decompilation(addr, args)` sans `strip()` ni `try` : une exception interrompt la boucle ; les impressions précédentes ont déjà eu lieu. Vérifié en bac à sable avec `00,zz`. |
| **FR-ARCH-48** : option `-v`, valeur numérique ou nom défini en majuscules par la journalisation standard (dont `BASIC_FORMAT`), erreur sinon | `scobelix/__main__.py` — `main()`, `parse_args()` | `args.v.isnumeric()` → `coloredlogs.install(level=int(args.v), milliseconds=True)` ; sinon `hasattr(logging, args.v.upper())` → niveau `getattr(logging, args.v.upper())` ; sinon `raise ValueError("Logging should be DEBUG/INFO/WARNING/ERROR.")`, non rattrapée (code 1), avant tout traitement. Défaut `str(logging.INFO)` dans `parse_args()`. L'acceptation d'un nom repose sur la seule existence de l'attribut du module `logging` : sous Python 3.12, les noms qui passent sont `BASIC_FORMAT`, `CRITICAL`, `DEBUG`, `ERROR`, `FATAL`, `INFO`, `NOTSET`, `WARN`, `WARNING` et `_STYLES`. Vérifié en bac à sable : `-v basic_format` produit la décompilation avec le code 0. |

Note contextuelle du document source (résidus `BASIC_FORMAT`, `_STYLES` et chiffres Unicode) : confirmée en bac à sable. `getattr(logging, "BASIC_FORMAT")` est une chaîne de format absente des niveaux connus de `coloredlogs`, qui retient alors son `DEFAULT_LOG_LEVEL` (20, INFO), d'où le code 0. `-v _styles` transmet un dictionnaire et échoue sur `TypeError: Level not an integer or a valid string`, avec le code 1. `str.isnumeric()` est vrai pour `٣` (converti en 3 par `int()`, code 0) et pour `²` (`ValueError: invalid literal for int() with base 10: '²'`, code 1).

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-49** : `--profile` écrit `scobelix.prof`, même en cas d'échec | `scobelix/__main__.py` — `main()` | `with cProfile.Profile() as profile: try: print_decompilation(…) finally: profile.dump_stats("scobelix.prof")` ; chemin relatif, donc répertoire courant. Vérifié en bac à sable avec un bytecode invalide. |
| **FR-ARCH-50** : `--profile` sans effet sur une liste | `scobelix/__main__.py` — `main()` | La branche `if "," in args.address_or_bytecode` est testée avant `elif args.profile`. |
| **FR-ARCH-51** : `--function`, défaut vide = toutes | `scobelix/__main__.py` — `parse_args()`, `print_decompilation()` | `default=""` puis `function_name = args.function or None`. |
| **FR-ARCH-52** : quatre drapeaux, précédence stricte | `scobelix/__main__.py` — `print_decompilation()` | Chaîne `if args.combined_json` / `elif args.solidity` / `elif args.json` / `else` : une seule impression principale par appel. |
| **FR-ARCH-53** : `--validate-solidity` seulement avec `--solidity` | `scobelix/__main__.py` — `print_decompilation()` | `validate()` n'est appelé qu'à l'intérieur des blocs `if args.solidity` (mode combiné) et `elif args.solidity` ; dans les autres branches le drapeau n'est pas consulté. |
| **FR-ARCH-54** : `--verbose`/`--explain` par présence littérale dans les arguments du processus | `scobelix/vm.py` — `VM.apply_stack()`, `VM.handle_jumps()` ; `scobelix/prettify.py` — `explain()`, `explain_text()` ; `scobelix/decompiler.py` — `dec()` | Tous testent `"--verbose" in sys.argv` ou `"--explain" in sys.argv` ; les attributs `args.verbose`/`args.explain` produits par `parse_args()` ne sont jamais lus, d'où l'inefficacité d'une abréviation acceptée par `argparse` (vérifié avec `--expl`). |
| **FR-ARCH-55** : `--explain` écrit sur la sortie standard avant la sortie principale | `scobelix/prettify.py` — `explain()`, `explain_text()` | `print()` direct sur la sortie standard, appelé pendant l'exécution symbolique, la structuration et la caractérisation, donc hors du bloc `redirect_stdout` qui ne capture que le rendu du texte ; la sortie principale n'est imprimée qu'ensuite par `print_decompilation()`. |
| **FR-ARCH-56** : options non déclarées refusées, abréviations acceptées | `scobelix/__main__.py` — `parse_args()` | `argparse.ArgumentParser` avec `allow_abbrev` à sa valeur par défaut (vrai) : `--sol` est accepté, `--repr` est refusé (code 2), vérifié en bac à sable. |

Note contextuelle du document source (branches `--repr` et `--returns` inatteignables) : confirmée par les tests `"--repr" in sys.argv` et `"--returns" in sys.argv` de `scobelix/decompiler.py` — `_decompile_with_loader()`, options absentes de `parse_args()`.

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-57** : code 0 si sortie produite, 1 et trace sur exception | `scobelix/__main__.py` — `main()` | `main()` retourne `None` (code 0 via le script console) ; aucune exception n'y est rattrapée, l'interpréteur imprime la trace et sort avec le code 1. Les échecs de fonctions ne lèvent rien (FR-ARCH-15). |

## 8. Interface de programmation Python

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-58** : deux fonctions publiques de décompilation | `scobelix/decompiler.py` — `decompile_bytecode()`, `decompile_address()` | Signatures `(code: str, only_func_name=None)` et `(address: str, only_func_name=None)`, retour annoté `Decompilation`. |
| **FR-ARCH-59** : quatre champs à valeurs vides par défaut | `scobelix/decompiler.py` — classe `Decompilation` | `text: str = ""`, `asm` et `proxy_hints` en `default_factory=list`, `json` en `default_factory=dict`. |
| **FR-ARCH-60** : `json` sérialisable ou `{}`, clé `proxy_hints` identique | `scobelix/decompiler.py` — `_decompile_with_loader()` | `decompilation.json["proxy_hints"] = decompilation.proxy_hints` (même objet liste) puis `json.dump()` de contrôle ; en cas d'échec, `{}`. |
| **FR-ARCH-61** : désassemblage exposé par l'API seulement | `scobelix/__main__.py` — `print_decompilation()` | Aucune des quatre branches d'impression n'utilise `decompilation.asm`. |
| **FR-ARCH-62** : génération Solidity, résultat à trois champs | `scobelix/solgen/emitter.py` — `generate_solidity()`, classe `SolgenResult`, `SolidityEmitter.generate()` | `generate_solidity()` n'accède qu'à l'attribut `json` de son argument (le test `test_unresolvable_function_gets_explicit_stub_not_silently_dropped` de `tests/test_solgen.py` lui passe un objet factice) ; `confidence[func.get("hash", "?")]` reçoit `high`/`medium`/`low`. |
| **FR-ARCH-63** : deux fonctions de validation, résultat à trois champs | `scobelix/solgen/validate.py` — `validate()`, `validate_solidity()`, classe `ValidationResult` | `validate(solgen_result)` appelle `validate_solidity(solgen_result.solidity)` avec les défauts `solc_path=None` (recherche dans le `PATH`) et `timeout=30`. |
| **FR-ARCH-64** : détection des slots de proxy exposée | `scobelix/utils/proxy_detect.py` — `detect_proxy_slots()` | Accepte tout itérable de triplets `(line_no, op, param)` et retourne la liste de dictionnaires d'indices. |
| **FR-ARCH-65** : exceptions pour les erreurs de FR-ARCH-41, retour normal sinon | `scobelix/decompiler.py` — `_decompile_with_loader()` | Mêmes mécanismes que FR-ARCH-41 et FR-ARCH-15 : les échecs de fonctions sont consignés dans `problems`, repris dans l'AST par `Contract.json()`. |
| **FR-ARCH-66** : fil principal requis, sauf budget par fonction nul | `scobelix/decompiler.py` — `dec()` | Hors du fil principal, `signal.signal()` appelé par `timeout_decorator` lève `ValueError`, rattrapée par la boucle principale : chaque fonction part dans `problems`. Avec un budget nul, aucun signal n'est armé. Vérifié en bac à sable : `problems == {'_fallback': '_fallback(?)'}` depuis un fil secondaire, `{}` avec `PANORAMIX_FUNCTION_TIMEOUT=0`. |
| **FR-ARCH-67** : aucune configuration de la journalisation par l'API | `scobelix/__main__.py` — `main()` ; `scobelix/matcher.py` | Seul `main()` appelle `coloredlogs.install()` ; l'unique `logging.basicConfig()` du paquet, dans `scobelix/matcher.py`, est placé sous `if __name__ == "__main__":`. Les modules se contentent de `logging.getLogger(__name__)`. |
| **FR-ARCH-68** : état partagé sans moyen de réinitialisation | (aucun code) | Aucune fonction publique ne vide les caches ni `used_locs` : l'exigence traduit une absence de mécanisme. |

## 9. Outil de régénération des signatures (invocation)

| Exigence | Fichier — Fonction/élément | Explication |
|---|---|---|
| **FR-ARCH-69** : module dédié, sans argument, piloté par deux variables lues au chargement | `scobelix/tools/build_local_sigs.py` — `main()`, `ABI_ROOTS`, `OUT_PATH` | Exécuté par `if __name__ == "__main__": main()` ; `main()` ne consulte jamais `sys.argv` ; `ABI_ROOTS` et `OUT_PATH` sont calculés au niveau module. |
| **FR-ARCH-70** : variable absente ou vide → message d'aide, fin normale | `scobelix/tools/build_local_sigs.py` — `main()` | `if not ABI_ROOTS: print("SCOBELIX_ABI_ROOTS is not set - nothing to scan. …") ; return`, sans écriture. |
| **FR-ARCH-71** : jamais invoqué par le pipeline | `scobelix/tools/build_local_sigs.py` ; `scobelix/utils/supplement.py` — `load_local_sigs_bulk()` | Aucun module du paquet n'importe `scobelix.tools` ; le résultat n'agit que via le fichier `local_sigs.json` lu par `load_local_sigs_bulk()`. |

---

Navigation : [../specification-fonctionnelle/architecture.md](../specification-fonctionnelle/architecture.md) · [../README.md](../README.md)
