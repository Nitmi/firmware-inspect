from __future__ import annotations

import json
from importlib.resources import files

import pytest
from fixtures import elf_image
from jsonschema import Draft202012Validator

from firmware_inspect.cli import main
from firmware_inspect.core import compare, inspect


def validator():
    schema = json.loads(files("firmware_inspect").joinpath("report.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize("bits", [32, 64])
def test_elf_inspection_and_diff_schema(tmp_path, bits):
    old, new = tmp_path / "a.elf", tmp_path / "b.elf"
    old.write_bytes(elf_image(bits=bits))
    new.write_bytes(elf_image(bits=bits, bss_size=16))
    before, after = inspect(old), inspect(new)
    check = validator()
    check.validate(before)
    check.validate(after)
    check.validate(compare(before, after))
    check.validate(compare(after, before))  # Negative section deltas are valid.


def test_bin_hex_and_error_schema(tmp_path, capsys):
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"1234")
    hexadecimal = tmp_path / "app.hex"
    hexadecimal.write_text(":040000006162636472\n:00000001FF\n")
    check = validator()
    check.validate(inspect(binary, base_address=0))
    check.validate(inspect(hexadecimal))
    check.validate(compare(inspect(binary, base_address=0), inspect(binary, base_address=0)))
    assert main(["inspect", str(tmp_path / "absent"), "--json"]) == 1
    check.validate(json.loads(capsys.readouterr().out))


def test_schema_rejects_hardware_access_and_unknown_fields(tmp_path):
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"1234")
    report = inspect(binary, base_address=0)
    report["hardware_access"] = True
    assert not validator().is_valid(report)
    report["hardware_access"] = False
    report["unexpected"] = "not part of contract"
    assert not validator().is_valid(report)


def test_schema_does_not_mix_success_and_error_contracts(tmp_path):
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"1234")
    report = inspect(binary, base_address=0)
    report["error"] = {"code": "FORMAT_INVALID", "message": "bad", "retryable": False}
    assert not validator().is_valid(report)
