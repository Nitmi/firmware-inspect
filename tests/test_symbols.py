from __future__ import annotations

import hashlib
import json
import struct

import pytest
from fixtures import elf_image
from test_schema import validator

from firmware_inspect import symbols
from firmware_inspect.cli import main
from firmware_inspect.core import InspectionError, inspect
from firmware_inspect.symbols import lookup


def save(tmp_path, **options):
    path = tmp_path / "symbols.elf"
    path.write_bytes(elf_image(**options))
    return path


@pytest.mark.parametrize("bits,endian", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_exact_case_sensitive_lookup_and_schema(tmp_path, bits, endian):
    path = save(tmp_path, bits=bits, endian=endian)
    result = lookup(path, ["counter", "main", "MAIN", "ma*"])
    assert result["source"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["architecture"]["bits"] == bits
    assert [row["name"] for row in result["queries"]] == ["counter", "main", "MAIN", "ma*"]
    assert [row["status"] for row in result["queries"]] == [
        "unique",
        "unique",
        "not_found",
        "not_found",
    ]
    counter = result["queries"][0]
    assert counter["value"] == 0x20000000
    assert counter["matches"][0]["section"]["name"] == ".data"
    assert counter["matches"][0]["table_name"] == ".symtab"
    assert result["symbol_entries_scanned"] == 4 and result["complete"]
    validator().validate(result)


def test_small_and_zero_sized_symbols_are_not_largest_list_dependent(tmp_path):
    path = save(
        tmp_path,
        symbol_entries=[
            ("large", 0, 4, 0x12, 1),
            ("zero", 1, 0, 0x12, 1),
            ("_SEGGER_RTT", 0x20000004, 8, 0x11, 3),
        ],
    )
    assert "zero" not in {
        row["name"] for row in inspect(path, symbol_limit=1)["symbols"]["largest"]
    }
    result = lookup(path, ["zero", "_SEGGER_RTT"])
    assert result["queries"][0]["status"] == "unique"
    assert result["queries"][0]["value"] == 1  # Preserve ABI bits; do not adjust values.
    rtt = result["queries"][1]
    assert rtt["status"] == "unique" and rtt["value"] == 0x20000004
    assert rtt["matches"][0]["section"]["file_backed"] is False


def test_equivalent_entries_from_two_tables_are_preserved(tmp_path):
    result = lookup(save(tmp_path, duplicate_symbol_table=True), ["counter"])
    query = result["queries"][0]
    assert query["status"] == "unique" and query["definition_count"] == 1
    assert query["matched_entries"] == 2
    assert {row["table_name"] for row in query["matches"]} == {".symtab", ".dynsym"}
    assert result["symbol_tables_scanned"] == 2 and result["symbol_entries_scanned"] == 8
    validator().validate(result)


@pytest.mark.parametrize(
    "entries",
    [
        [("same", 0, 1, 0x12, 1), ("same", 1, 1, 0x12, 1)],
        [("same", 0, 1, 0x12, 1), ("same", 0, 1, 0x22, 1)],
        [("same", 0, 1, 0x12, 1), ("same", 0, 1, 0x11, 1)],
    ],
)
def test_conflicting_values_binding_or_type_are_ambiguous(tmp_path, entries):
    query = lookup(save(tmp_path, symbol_entries=entries), ["same"])["queries"][0]
    assert query["status"] == "ambiguous"
    assert query["definition_count"] == 2 and query["value"] is None
    validator().validate(lookup(tmp_path / "symbols.elf", ["same"]))


def test_undefined_common_absolute_and_tls_values_keep_semantics(tmp_path):
    path = save(
        tmp_path,
        elf_type=3,
        symbol_entries=[
            ("undef", 0, 0, 0x12, 0),
            ("common", 4, 8, 0x11, 0xFFF2),
            ("absolute", 123, 0, 0x10, 0xFFF1),
            ("tls", 0, 4, 0x16, 2),
        ],
    )
    result = lookup(path, ["undef", "common", "absolute", "tls", "missing"])
    rows = result["queries"]
    assert [row["status"] for row in rows] == [
        "undefined_only",
        "no_definition",
        "unique",
        "unique",
        "not_found",
    ]
    assert [row["value"] for row in rows] == [None, None, 123, 0, None]
    assert [row["matches"][0]["value_kind"] for row in rows[:4]] == [
        "undefined_value",
        "common_alignment",
        "absolute_value",
        "tls_offset",
    ]
    assert result["value_semantics"] == "elf_st_value"
    assert all("address" not in row for row in rows)
    validator().validate(result)


@pytest.mark.parametrize("section_index", [0xFF00, 0xFFFF])
def test_special_indexes_are_unresolved_and_not_ordinary_sections(tmp_path, section_index):
    path = save(tmp_path, symbol_entries=[("special", 123, 4, 0x11, section_index)])
    assert inspect(path)["symbols"]["defined_function_object_entries"] == 0
    result = lookup(path, ["special"])
    query = result["queries"][0]
    assert query["status"] == "no_definition" and query["value"] is None
    match = query["matches"][0]
    assert match["definition"] == "reserved" and match["section"] is None
    assert match["value"] == 123 and match["value_kind"] == "special_value"
    validator().validate(result)


def test_defined_and_undefined_entries_do_not_conflict(tmp_path):
    query = lookup(
        save(
            tmp_path,
            symbol_entries=[
                ("name", 0, 0, 0x12, 0),
                ("name", 2, 0, 0x12, 1),
            ],
        ),
        ["name"],
    )["queries"][0]
    assert query["status"] == "unique" and query["matched_entries"] == 2
    assert query["value"] == 2


def test_stripped_elf_has_complete_not_found_result(tmp_path):
    image = bytearray(elf_image(note_program=True))
    struct.pack_into("<I", image, 32, 0)
    struct.pack_into("<HH", image, 48, 0, 0)
    path = tmp_path / "stripped.elf"
    path.write_bytes(image)
    report = lookup(path, ["_SEGGER_RTT"])
    assert report["complete"] and report["symbol_tables_scanned"] == 0
    assert report["queries"][0]["status"] == "not_found"
    validator().validate(report)


@pytest.mark.parametrize(
    "names",
    [
        [],
        "main",
        [""],
        [None],
        ["a\n"],
        ["x"] * 2,
        ["x" * 1025],
        [str(index) for index in range(33)],
    ],
)
def test_invalid_queries_are_rejected_before_file_access(tmp_path, monkeypatch, names):
    def forbidden(*args):
        raise AssertionError("invalid options must not read the input")

    monkeypatch.setattr(symbols, "_snapshot", forbidden)
    with pytest.raises(InspectionError) as error:
        lookup(tmp_path / "absent", names)
    assert error.value.code == "OPTIONS_INVALID"


def test_match_limit_refuses_incomplete_partial_resolution(tmp_path):
    path = save(tmp_path, symbol_entries=[("many", 0, 0, 0x12, 1)] * 257)
    with pytest.raises(InspectionError) as error:
        lookup(path, ["many"])
    assert error.value.code == "LIMIT_EXCEEDED"


def test_snapshot_is_not_reread_and_no_subprocess_or_source_write(tmp_path, monkeypatch):
    path = save(tmp_path)
    snapshot = path.read_bytes()
    snapshot_reader = symbols._snapshot

    def changed_after_snapshot(source):
        resolved, data = snapshot_reader(source)
        source.write_bytes(elf_image(symbol_entries=[("counter", 9, 0, 0x11, 2)]))
        return resolved, data

    monkeypatch.setattr(symbols, "_snapshot", changed_after_snapshot)
    result = lookup(path, ["counter"])
    assert result["queries"][0]["value"] == 0x20000000
    assert result["source"]["sha256"] == hashlib.sha256(snapshot).hexdigest()
    assert path.read_bytes() != snapshot
    monkeypatch.setattr(symbols, "_snapshot", snapshot_reader)
    before = path.read_bytes(), path.stat().st_mtime_ns

    def forbidden(*args, **kwargs):
        raise AssertionError("inspection must not execute a process")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    lookup(path, ["counter"])
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize(
    "image",
    [
        b"not ELF",
        b"\x7fELFbroken",
        elf_image(elf_type=1),
        elf_image(symbol_entries=[("bad", 0, 0, 0x10, 400)]),
    ],
)
def test_unsupported_or_malformed_inputs_are_structured_errors(tmp_path, image, capsys):
    path = tmp_path / "bad.elf"
    path.write_bytes(image)
    assert main(["symbols", str(path), "--name", "bad", "--json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["error"]["retryable"] is False and not captured.err
    validator().validate(report)


def test_cli_missing_name_is_a_successful_query_not_fake_definition(tmp_path, capsys):
    path = save(tmp_path)
    assert main(["symbols", str(path), "--name", "missing", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["queries"][0]["status"] == "not_found"
    validator().validate(report)
    assert main(["symbols", str(path), "--name", "counter"]) == 0
    output = capsys.readouterr()
    assert "st_value=0x20000000" in output.out
    assert "runtime addresses" in output.err


def test_schema_does_not_accept_fabricated_unique_value(tmp_path):
    report = lookup(save(tmp_path), ["missing"])
    report["queries"][0]["value"] = 0x20000000
    assert not validator().is_valid(report)
