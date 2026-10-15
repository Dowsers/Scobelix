"""scobelix.verify.solc: finding, downloading and running solc."""

import hashlib
import json
import os

import pytest
from verify_helpers import SOLC, fixture_source, requires_solc, solc_path

from scobelix.solgen.validate import validate_solidity
from scobelix.verify import solc

SHIM = (
    "#!/bin/sh\n"
    "echo 'solc, the solidity compiler commandline interface'\n"
    "echo 'Version: 0.8.19+commit.7dd6d404.Linux.g++'\n"
)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """No solc anywhere: empty HOME, empty PATH, no override dir."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    monkeypatch.delenv(solc.DIR_ENV, raising=False)
    monkeypatch.delenv(solc.DOWNLOAD_ENV, raising=False)
    (tmp_path / "bin").mkdir()
    return tmp_path


def _write_exec(path, text):
    path.write_text(text)
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------- discovery


def test_version_output_parsing_keeps_releases_only():
    assert solc.parse_version_output("Version: 0.8.19+commit.7dd6d404.Linux.g++") == "0.8.19"
    assert (
        solc.parse_version_output("solc\nVersion: 0.4.26+commit.4563c3fc.Linux.g++\n") == "0.4.26"
    )
    assert solc.parse_version_output("Version: 0.8.20-nightly.2023.1.1+commit.abc") is None
    assert solc.parse_version_output("") is None


def test_shell_shim_is_never_a_solc(isolated):
    shim = _write_exec(isolated / "bin" / "solc", SHIM)
    assert solc.binary_version(str(shim)) is None
    assert solc.installed_solcs() == {}
    with pytest.raises(solc.SolcNotFound, match="not installed"):
        solc.find_solc("0.8.19")


def test_validate_skips_when_only_a_shim_is_on_path(isolated):
    _write_exec(isolated / "bin" / "solc", SHIM)
    r = validate_solidity("pragma solidity ^0.8.0; contract C {}")
    assert r.status == "skipped"
    assert r.errors == []
    assert "no installed solc" in r.warnings[0]


@requires_solc
def test_override_dir_is_searched(isolated, monkeypatch):
    d = isolated / "solcs"
    d.mkdir()
    os.symlink(solc_path(), d / "solc-custom")
    monkeypatch.setenv(solc.DIR_ENV, str(d))
    found = solc.installed_solcs()
    assert list(found) == [SOLC]
    assert solc.find_solc(SOLC) == os.path.realpath(solc_path())


@requires_solc
def test_installed_versions_are_sorted_and_verified():
    found = solc.installed_solcs()
    versions = list(found)
    assert versions == sorted(versions, key=solc.version_key)
    assert all(solc.binary_version(p) == v for v, p in found.items())


def test_versions_are_normalised(isolated):
    for text in ("0.8.19", "v0.8.19", "0.8.19+commit.7dd6d404", " 0.8.19+commit.7dd6d4.Linux.g++"):
        assert solc.normalize_version(text) == "0.8.19"
    for bad in ("0.8", "latest", "0.8.20-nightly.2023.1.1"):
        with pytest.raises(ValueError):
            solc.normalize_version(bad)
    with pytest.raises(solc.SolcNotFound, match="not a solc release version"):
        solc.find_solc("latest")


def test_download_needs_an_opt_in(isolated, monkeypatch):
    assert solc.download_allowed() is False
    assert solc.download_allowed(True) is True
    monkeypatch.setenv(solc.DOWNLOAD_ENV, "1")
    assert solc.download_allowed() is True
    assert solc.download_allowed(False) is False
    monkeypatch.setenv(solc.DOWNLOAD_ENV, "no")
    with pytest.raises(solc.SolcNotFound, match=solc.DOWNLOAD_ENV):
        solc.find_solc("0.8.19")


# ---------------------------------------------------------------- downloads (offline)


@pytest.fixture
def fake_release_server(monkeypatch):
    """binaries.soliditylang.org stand-in serving a real local solc as the 0.8.19 release."""
    blob = open(solc_path(), "rb").read() if solc_path() else b""
    fname = "solc-linux-amd64-v0.8.19+commit.7dd6d404"
    listing = {
        "builds": [
            {"path": fname, "version": "0.8.19", "sha256": "0x" + hashlib.sha256(blob).hexdigest()}
        ],
        "releases": {"0.8.19": fname},
    }
    seen = []

    def get(url, timeout):
        seen.append(url)
        if url.endswith("list.json"):
            return json.dumps(listing).encode()
        if url.endswith(fname):
            return blob
        raise OSError(f"404 {url}")

    monkeypatch.setattr(solc, "_http_get", get)
    monkeypatch.setattr(solc, "_platform_dir", lambda: "linux-amd64")
    return listing, seen


@requires_solc
def test_download_checks_sha256_and_version(isolated, fake_release_server):
    _listing, seen = fake_release_server
    path = solc.download_solc("0.8.19", dest=isolated / "dl")
    assert path == str(isolated / "dl" / "solc-0.8.19")
    assert solc.binary_version(path) == "0.8.19"
    assert seen[0].endswith("/linux-amd64/list.json")
    # no temporary file left
    assert [p.name for p in (isolated / "dl").iterdir()] == ["solc-0.8.19"]


@requires_solc
def test_download_rejects_a_bad_checksum(isolated, fake_release_server):
    listing, _ = fake_release_server
    listing["builds"][0]["sha256"] = "0x" + "00" * 32
    with pytest.raises(solc.SolcNotFound, match="sha256 mismatch"):
        solc.download_solc("0.8.19", dest=isolated / "dl")
    assert not (isolated / "dl" / "solc-0.8.19").exists()


@requires_solc
def test_download_rejects_unknown_releases(isolated, fake_release_server):
    with pytest.raises(solc.SolcNotFound, match="not an official release"):
        solc.download_solc("0.8.99", dest=isolated / "dl")


@requires_solc
def test_find_solc_downloads_into_the_override_dir(isolated, fake_release_server, monkeypatch):
    monkeypatch.setenv(solc.DIR_ENV, str(isolated / "override"))
    path = solc.find_solc("0.8.19", allow_download=True)
    assert path == str(isolated / "override" / "solc-0.8.19")
    assert solc.installed_solcs() == {"0.8.19": path}


def test_requests_carry_an_explicit_user_agent(monkeypatch):
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    def urlopen(req, timeout):
        seen["ua"] = req.get_header("User-agent")
        return Response()

    monkeypatch.setattr(solc.urllib.request, "urlopen", urlopen)
    assert solc._http_get("https://binaries.soliditylang.org/linux-amd64/list.json", 5) == b"{}"
    assert seen["ua"] == solc.USER_AGENT and not seen["ua"].startswith("Python-urllib")


# ---------------------------------------------------------------- pragmas


@pytest.mark.parametrize(
    "version, constraint, ok",
    [
        ("0.8.19", "^0.8.0", True),
        ("0.9.0", "^0.8.0", False),
        ("0.4.26", "^0.4.24", True),
        ("0.5.0", "^0.4.24", False),
        ("0.0.3", "^0.0.3", True),
        ("0.0.4", "^0.0.3", False),
        ("0.7.6", "~0.7.0", True),
        ("0.8.0", "~0.7.0", False),
        ("0.8.19", "0.8.19", True),
        ("0.8.20", "=0.8.19", False),
        ("0.8.5", "0.8", True),
        ("0.8.5", "0.8.x", True),
        ("0.7.6", "0.8.*", False),
        ("0.8.19", ">0.8.18", True),
        ("0.8.18", ">0.8.18", False),
        ("0.9.0", ">0.8", True),
        ("0.8.99", ">0.8", False),
        ("0.8.31", "<=0.8", True),
        ("0.9.0", "<=0.8", False),
        ("0.8.31", ">=0.6.0 <0.9.0", True),
        ("0.5.17", ">=0.6.0 <0.9.0", False),
        ("0.8.1", ">= 0.8.0", True),
        ("0.7.6", "^0.8.0 || ^0.7.0", True),
        ("0.6.12", "^0.8.0 || ^0.7.0", False),
        ("0.8.0", "0.6.0 - 0.8.0", True),
        ("0.8.1", "0.6.0 - 0.8.0", False),
        ("1.2.3", "*", True),
    ],
)
def test_version_satisfies(version, constraint, ok):
    assert solc.version_satisfies(version, constraint) is ok


def test_bad_constraints_raise():
    with pytest.raises(ValueError):
        solc.version_satisfies("0.8.19", "^banana")


def test_pragmas_in_comments_and_strings_are_ignored():
    src = (
        "// pragma solidity ^0.4.0;\n"
        "/* pragma solidity 0.5.0; */\n"
        'string constant s = "pragma solidity 0.6.0;";\n'
        "pragma solidity >=0.8.0 <0.9.0;\n"
    )
    assert solc.pragma_constraints(src) == [">=0.8.0 <0.9.0"]
    assert solc.pragma_constraints(
        {"a.sol": "pragma solidity ^0.8.0;", "b.sol": "pragma solidity >=0.8.10;"}
    ) == [
        "^0.8.0",
        ">=0.8.10",
    ]


def test_select_version_prefers_the_given_version_then_the_newest():
    pool = ["0.4.26", "0.7.6", "0.8.19", "0.8.31"]
    assert solc.select_version("pragma solidity ^0.8.0;", candidates=pool) == "0.8.31"
    assert (
        solc.select_version("pragma solidity ^0.8.0;", preferred="0.8.19", candidates=pool)
        == "0.8.19"
    )
    assert (
        solc.select_version("pragma solidity ^0.8.0;", preferred="0.7.6", candidates=pool)
        == "0.8.31"
    )
    assert solc.select_version("contract C {}", candidates=pool) == "0.8.31"
    assert solc.select_version("pragma solidity ^0.9.0;", candidates=pool) is None
    assert solc.versions_matching(["^0.4.0 || ^0.7.0"], pool) == ["0.4.26", "0.7.6"]


# ---------------------------------------------------------------- compilation


@requires_solc
def test_compile_standard_json_returns_full_artifacts():
    comp = solc.compile_standard_json(fixture_source("token/Recon.sol"), version=SOLC)
    art = comp.artifact("Recon")
    assert comp.version == SOLC and comp.settings == solc.Settings()
    assert art.name == "Contract.sol:Recon" and art.contract_name == "Recon"
    assert art.method_ids == {
        "balanceOf(address)": "70a08231",
        "totalSupply()": "18160ddd",
        "transfer(address,uint256)": "a9059cbb",
    }
    assert art.selectors[0xA9059CBB] == "transfer(address,uint256)"
    assert [v["label"] for v in art.storage_layout["storage"]] == ["balanceOf", "totalSupply"]
    assert art.runtime and art.creation and art.immutable_refs == {} and art.link_refs == {}
    assert {i["name"] for i in art.abi if i["type"] == "function"} == {
        "balanceOf",
        "totalSupply",
        "transfer",
    }


@requires_solc
def test_compile_outputs_are_cached_per_binary_and_input(monkeypatch):
    runs = []
    real_run = solc.subprocess.run

    def counting(cmd, *a, **k):
        if "--standard-json" in cmd:
            runs.append(cmd[0])
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(solc.subprocess, "run", counting)
    solc.clear_compile_cache()
    src = "pragma solidity 0.8.19; contract C { function f() external pure returns (uint8) {} }"
    first = solc.compile_standard_json(src, version="v" + SOLC).artifact("C")
    again = solc.compile_standard_json(src, version=SOLC).artifact("C")
    assert first.runtime == again.runtime and len(runs) == 1
    solc.compile_standard_json(src, solc.Settings(optimize=False), version=SOLC)
    assert len(runs) == 2  # other settings: another input
    # errors come from the cached output as well
    with pytest.raises(solc.CompilationError):
        solc.compile_standard_json("contract D { function f() {} }", version=SOLC)
    with pytest.raises(solc.CompilationError):
        solc.compile_standard_json("contract D { function f() {} }", version=SOLC)
    assert len(runs) == 3
    # bounded: an output larger than the budget is not kept
    monkeypatch.setattr(solc, "COMPILE_CACHE_BYTES", 10)
    solc.clear_compile_cache()
    solc.compile_standard_json(src, version=SOLC)
    solc.compile_standard_json(src, version=SOLC)
    assert len(runs) == 5 and not solc._compile_cache


@requires_solc
def test_compilation_errors_carry_solc_messages():
    with pytest.raises(solc.CompilationError) as e:
        solc.compile_standard_json(
            "pragma solidity ^0.8.0; contract C { function f() { } }", version=SOLC
        )
    assert e.value.version == SOLC
    assert e.value.messages and "Error" in e.value.messages[0]
    assert not e.value.stack_too_deep
    assert solc.CompilationError(
        [{"message": "Stack too deep, try removing local variables."}]
    ).stack_too_deep


@requires_solc
def test_the_version_comes_from_the_pragma_when_not_given():
    comp = solc.compile_standard_json(f"pragma solidity {SOLC}; contract C {{}}")
    assert comp.version == SOLC


@requires_solc
def test_immutable_names_come_from_the_ast():
    art = solc.compile_standard_json(fixture_source("misc/Immutables.sol"), version=SOLC).artifact(
        "Imm"
    )
    assert sorted(art.immutable_names.values()) == ["cap", "owner"]
    assert set(art.immutable_names) == set(art.immutable_refs)


@requires_solc
def test_artifact_lookup():
    comp = solc.compile_standard_json(
        {
            "A.sol": fixture_source("misc/Immutables.sol"),
            "B.sol": "pragma solidity 0.8.19; contract Imm {}",
        },
        version=SOLC,
    )
    assert comp.artifact("A.sol:Imm").name == "A.sol:Imm"
    with pytest.raises(KeyError, match="ambiguous"):
        comp.artifact("Imm")
    with pytest.raises(KeyError, match="not found"):
        comp.artifact("Nope")
    with pytest.raises(KeyError, match="several"):
        comp.artifact()


def test_link_placeholders_are_zero_filled():
    # solc >= 0.5: "__$" + 34 hex digits + "$__"
    new_style = "73" + "__$" + "ab" * 17 + "$__" + "5af4"
    # 0.4: the name padded to 36
    old_style = "73" + "__" + "Lib.sol:Lib".ljust(36, "_") + "__" + "5af4"
    for obj in (new_style, old_style):
        assert solc._unhex(obj) == bytes.fromhex("73" + "00" * 20 + "5af4")


def test_settings_follow_the_compiler_version():
    old = solc.Settings().to_json("0.4.26")
    outputs = old["outputSelection"]["*"]["*"]
    assert (
        "storageLayout" not in outputs and "evm.deployedBytecode.immutableReferences" not in outputs
    )
    new = solc.Settings(
        via_ir=True, evm_version="cancun", metadata_hash="none", append_cbor=False
    ).to_json("0.8.19", ast=True)
    assert new["viaIR"] is True and new["evmVersion"] == "cancun"
    assert new["metadata"] == {"bytecodeHash": "none", "appendCBOR": False}
    assert new["outputSelection"]["*"][""] == ["ast"]
    assert "storageLayout" in new["outputSelection"]["*"]["*"]
    assert solc.Settings().label == "opt200"
    assert solc.Settings(optimize=False).label == "noopt"
    assert solc.Settings(True, 1, True, "paris").label == "viaIR-opt1-paris"


def test_optimizer_variants_and_execution_evm_version():
    assert len(solc.optimizer_variants("0.8.12")) == 6
    variants = solc.optimizer_variants("0.8.13")
    assert (
        len(variants) == 9
        and variants[0] == solc.Settings()
        and sum(v.via_ir for v in variants) == 3
    )
    assert solc.execution_evm_version("0.8.31") == "cancun"
    assert solc.execution_evm_version("0.8.19") is None
