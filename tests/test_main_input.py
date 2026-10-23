"""
How the command tells an address from a bytecode: an argument of exactly 42
characters is an address unless --bytecode says otherwise; what `-` reads
from the standard input is always bytecode (a 20-byte runtime code has the
length of an address), with a warning when it looks like an address.
"""

import io
import logging

import pytest

import scobelix.__main__ as cli
from scobelix.decompiler import Decompilation

ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"  # 42 characters
TWENTY_BYTES = "0x" + "60" * 20  # a 20-byte bytecode: 42 characters too
RETURN_42 = "602a60005260206000f3"


@pytest.fixture
def spies(monkeypatch):
    """decompile_address / decompile_bytecode replaced by recorders."""
    seen = {"address": [], "bytecode": []}

    def address(value, only_func_name=None, *, time_budget=None):
        seen["address"].append(value)
        return Decompilation(text="by address")

    def bytecode(value, only_func_name=None, *, time_budget=None):
        seen["bytecode"].append(value)
        return Decompilation(text="by bytecode")

    monkeypatch.setattr(cli, "decompile_address", address)
    monkeypatch.setattr(cli, "decompile_bytecode", bytecode)
    monkeypatch.delenv("SCOBELIX_TIME_BUDGET", raising=False)
    return seen


def _run(capsys, *argv):
    args = cli.parse_args(list(argv))
    cli.print_decompilation(args.address_or_bytecode, args)
    return capsys.readouterr().out


def test_an_argument_of_42_characters_is_an_address(spies, capsys):
    assert _run(capsys, ADDRESS) == "by address\n"
    assert _run(capsys, TWENTY_BYTES) == "by address\n"
    assert spies["address"] == [ADDRESS, TWENTY_BYTES] and spies["bytecode"] == []


def test_any_other_length_is_bytecode(spies, capsys):
    assert _run(capsys, RETURN_42) == "by bytecode\n"
    assert spies["bytecode"] == [RETURN_42] and spies["address"] == []


def test_bytecode_forces_the_bytecode_mode(spies, capsys):
    assert cli.parse_args([RETURN_42]).bytecode is False
    assert _run(capsys, "--bytecode", TWENTY_BYTES) == "by bytecode\n"
    assert _run(capsys, "--bytecode", RETURN_42) == "by bytecode\n"
    assert spies["bytecode"] == [TWENTY_BYTES, RETURN_42] and spies["address"] == []


def test_the_standard_input_is_always_bytecode(spies, capsys, monkeypatch, caplog):
    monkeypatch.setattr("sys.stdin", io.StringIO(f" {TWENTY_BYTES}\n"))
    with caplog.at_level(logging.WARNING, logger="scobelix.__main__"):
        assert _run(capsys, "-") == "by bytecode\n"
    assert spies["bytecode"] == [TWENTY_BYTES] and spies["address"] == []
    # it has the length of an address: the reader is told how to pass one
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "bytecode" in warnings[0] and "argument" in warnings[0]


def test_the_standard_input_warns_only_for_an_address_shape(spies, capsys, monkeypatch, caplog):
    monkeypatch.setattr("sys.stdin", io.StringIO(RETURN_42 + "\n"))
    with caplog.at_level(logging.WARNING, logger="scobelix.__main__"):
        assert _run(capsys, "-") == "by bytecode\n"
    assert spies["bytecode"] == [RETURN_42]
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]
    monkeypatch.setattr("sys.stdin", io.StringIO("0x" + "zz" * 20))  # 42 characters, not an address
    with caplog.at_level(logging.WARNING, logger="scobelix.__main__"):
        _run(capsys, "-")
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]
