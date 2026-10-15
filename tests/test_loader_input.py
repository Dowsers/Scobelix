"""
The code to decompile must be hexadecimal bytes.

A character that is not a hex digit used to escape as a bare ValueError of
int() (a traceback from the command line), and an odd number of digits was
read as if the last nibble were a whole byte. Both are now refused with
the reason (InvalidBytecode, a ValueError); the command line prints it and
exits with status 2, as for its other usage errors.
"""

import logging
import sys

import pytest

from scobelix.decompiler import decompile_bytecode
from scobelix.loader import InvalidBytecode, Loader, parse_hex_code


@pytest.fixture(autouse=True)
def _restore_root_logger():
    # main() installs a log handler on the root logger, as a command line
    # does; without this, the log lines of every later test of the session
    # would reach that test's captured stderr.
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.mark.parametrize(
    "source, expected",
    [
        ("6001", b"\x60\x01"),
        ("0x6001", b"\x60\x01"),
        ("0X60AB", b"\x60\xab"),
        (" 6001\n", b"\x60\x01"),
        ("", b""),
        ("0x", b""),
    ],
)
def test_hex_code_is_parsed(source, expected):
    assert parse_hex_code(source) == expected


@pytest.mark.parametrize(
    "source, reason",
    [
        ("0xzz12", "not hexadecimal: 'z' at position 2"),
        ("60016g", "not hexadecimal: 'g' at position 5"),
        ("60 01", "not hexadecimal: ' ' at position 2"),
        ("0x_1", "not hexadecimal: '_' at position 2"),
        ("6001600", "odd number of hex digits (7)"),
        ("0x6", "odd number of hex digits (1)"),
    ],
)
def test_bad_hex_code_is_refused_with_the_reason(source, reason):
    with pytest.raises(InvalidBytecode) as e:
        parse_hex_code(source)
    assert reason in str(e.value)
    with pytest.raises(ValueError):
        Loader().load_binary(source)


def test_decompile_bytecode_refuses_bad_hex():
    with pytest.raises(InvalidBytecode):
        decompile_bytecode("0xzz12")
    with pytest.raises(InvalidBytecode):
        decompile_bytecode("6001600")


@pytest.mark.parametrize("source", ["0xzz12", "6001600"])
def test_command_line_reports_bad_hex_without_traceback(monkeypatch, capsys, source):
    from scobelix import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["scobelix", source])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "invalid bytecode" in err
    assert "Traceback" not in err


def test_command_line_still_decompiles_good_hex(monkeypatch, capsys):
    from scobelix import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["scobelix", "0x602a60005260206000f3"])
    cli.main()
    assert "42" in capsys.readouterr().out
