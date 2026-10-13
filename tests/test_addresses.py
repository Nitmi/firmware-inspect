from __future__ import annotations

import hashlib
import json
import struct

import pytest
from address_fixtures import address_elf, dwarf_sections, leb, line_program
from fixtures import elf_image
from test_schema import validator

from firmware_inspect import addresses
from firmware_inspect.addresses import lookup
from firmware_inspect.cli import main
from firmware_inspect.core import InspectionError


def save(tmp_path, image=None, **options):
    path = tmp_path / "addresses.elf"
    path.write_bytes(address_elf(**options) if image is None else image)
    return path


@pytest.mark.parametrize("version", [2, 3, 4, 5])
@pytest.mark.parametrize("bits,endian", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_in_file_lines_and_function_ranges(tmp_path, version, bits, endian):
    path = save(tmp_path, version=version, bits=bits, endian=endian)
    report = lookup(path, [0, 3, 4, 7, 8, 15, 16])
    validator().validate(report)
    assert report["source"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert [row["line_status"] for row in report["address_queries"]] == ["unique"] * 4 + [
        "not_found"
    ] * 3
    assert [row["lines"][0]["line"] for row in report["address_queries"][:4]] == [10, 10, 20, 20]
    assert report["address_queries"][0]["lines"][0]["file_name"] == "app.c"
    assert report["address_queries"][0]["lines"][0]["directory"] == "src"
    assert report["address_queries"][0]["lines"][0]["compilation_directory"] == "/build"
    assert report["address_queries"][5]["function_status"] == "unique"
    assert report["address_queries"][6]["function_status"] == "not_found"
    assert report["debug_lines"]["compile_units_scanned"] == 1


def test_sequence_gaps_and_duplicate_addresses_do_not_extend_previous_lines(tmp_path):
    rows = ((0, 10), (0, 11), (2, None), (8, 30), (10, None))
    path = save(tmp_path, programs=[(line_program(rows), b"/build")])
    result = lookup(path, [0, 1, 2, 7, 8, 10])["address_queries"]
    assert result[0]["lines"][0]["line"] == 11
    assert [row["line_status"] for row in result] == [
        "unique",
        "unique",
        "not_found",
        "not_found",
        "unique",
        "not_found",
    ]


def test_overlapping_function_definitions_are_not_resolved_by_order(tmp_path):
    path = save(tmp_path, symbol_entries=[("outer", 0, 16, 0x12, 1), ("inner", 4, 4, 0x12, 1)])
    rows = lookup(path, [4, 8])["address_queries"]
    assert rows[0]["function_status"] == "ambiguous"
    assert [row["name"] for row in rows[0]["functions"]] == ["outer", "inner"]
    assert rows[1]["function_status"] == "unique"


def test_duplicate_tables_preserve_entries_without_false_ambiguity(tmp_path):
    report = lookup(save(tmp_path, duplicate_symbol_table=True), [0])
    query = report["address_queries"][0]
    assert query["function_status"] == "unique" and len(query["functions"]) == 2
    validator().validate(report)


def test_zero_size_and_non_function_values_are_not_guessed(tmp_path):
    path = save(
        tmp_path,
        symbol_entries=[
            ("zero", 4, 0, 0x12, 1),
            ("object", 0, 16, 0x11, 1),
            ("absolute", 4, 8, 0x12, 0xFFF1),
        ],
    )
    report = lookup(path, [4, 5])
    match = report["address_queries"][0]["functions"][0]
    assert match["name"] == "zero" and match["match_kind"] == "exact_start_only"
    assert match["range_end_exclusive"] is None
    assert report["address_queries"][1]["function_status"] == "not_found"
    validator().validate(report)


def test_thumb_normalization_keeps_inputs_values_and_does_not_adjust_lr(tmp_path):
    path = save(tmp_path, symbol_entries=[("thumb", 1, 16, 0x12, 1)])
    raw = lookup(path, [1, 3])["address_queries"]
    adjusted = lookup(path, [1, 3], address_mode="arm-thumb")["address_queries"]
    assert [row["lookup_address"] for row in raw] == [1, 3]
    assert [row["address"] for row in adjusted] == [1, 3]
    assert [row["lookup_address"] for row in adjusted] == [0, 2]
    function = adjusted[0]["functions"][0]
    assert function["raw_value"] == 1 and function["range_start"] == 0
    assert function["value_normalization"] == "arm_thumb_bit"
    assert adjusted[1]["functions"][0]["offset_bytes"] == 2
    with pytest.raises(InspectionError, match="ELF32 EM_ARM"):
        lookup(save(tmp_path, bits=64), [1], address_mode="arm-thumb")


def test_dwarf_overlap_is_preserved_and_equivalent_locations_remain_unique(tmp_path):
    one = line_program()
    different = line_program(((0, 30), (8, None)))
    result = lookup(save(tmp_path, programs=[(one, b"/build"), (different, b"/other")]), [0])
    assert result["address_queries"][0]["line_status"] == "ambiguous"
    assert len(result["address_queries"][0]["lines"]) == 2
    result = lookup(save(tmp_path, programs=[(one, b"/build"), (one, b"/build")]), [0])
    assert result["address_queries"][0]["line_status"] == "unique"
    assert len(result["address_queries"][0]["lines"]) == 2


def test_stripped_or_line_free_elf_and_disabled_lines(tmp_path):
    report = lookup(save(tmp_path, image=elf_image()), [0])
    assert report["debug_lines"]["status"] == "absent"
    report = lookup(save(tmp_path), [0], lines=False)
    assert report["debug_lines"]["status"] == "disabled"
    assert report["address_queries"][0]["functions"]
    assert not report["address_queries"][0]["lines"]
    image = bytearray(elf_image())
    struct.pack_into("<I", image, 32, 0)
    struct.pack_into("<HH", image, 48, 0, 0)
    report = lookup(save(tmp_path, image=image), [0])
    assert report["address_queries"][0]["function_status"] == "not_found"
    validator().validate(report)


@pytest.mark.parametrize(
    "values", [[], "1", [True], [None], [-1], [1 << 64], [1, 1], list(range(33))]
)
def test_invalid_addresses_do_not_read_input(tmp_path, monkeypatch, values):
    def forbidden(*args):
        raise AssertionError("must not read")

    monkeypatch.setattr(addresses, "_snapshot", forbidden)
    with pytest.raises(InspectionError) as error:
        lookup(tmp_path / "absent", values)
    assert error.value.code == "OPTIONS_INVALID"


@pytest.mark.parametrize(
    "program", [line_program(((4, 10), (2, 20), (8, None))), line_program(((0, 10), (8, 20)))]
)
def test_invalid_or_unterminated_sequences_fail_closed(tmp_path, program):
    with pytest.raises(InspectionError) as error:
        lookup(save(tmp_path, programs=[(program, b"/build")]), [0])
    assert error.value.code == "FORMAT_INVALID"


def test_bounds_reject_before_eager_line_decoding(tmp_path, monkeypatch):
    path = save(tmp_path)

    def forbidden(*args):
        raise AssertionError("must not decode an oversized unit")

    monkeypatch.setattr(addresses, "MAX_LINE_UNIT_BYTES", 10)
    monkeypatch.setattr("elftools.dwarf.lineprogram.LineProgram.get_entries", forbidden)
    with pytest.raises(InspectionError) as error:
        lookup(path, [0])
    assert error.value.code == "LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    "limit",
    [
        "MAX_DEBUG_BYTES",
        "MAX_LINE_BYTES",
        "MAX_COMPILE_UNITS",
        "MAX_LINE_ENTRIES",
        "MAX_LINE_MATCHES",
        "MAX_FUNCTION_MATCHES",
    ],
)
def test_limits_refuse_partial_reports(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(addresses, limit, 0)
    with pytest.raises(InspectionError) as error:
        lookup(save(tmp_path), [0])
    assert error.value.code == "LIMIT_EXCEEDED"


def test_truncated_units_and_cross_unit_opcode_reads_fail(tmp_path):
    program = bytearray(line_program())
    struct.pack_into("<I", program, 0, 100000)
    with pytest.raises(InspectionError) as error:
        lookup(save(tmp_path, programs=[(bytes(program), b"/build")]), [0])
    assert error.value.code == "FORMAT_INVALID"
    # Remove final end_sequence byte; a following valid unit must not satisfy it.
    original = line_program()
    cut = bytearray(original[:-1])
    struct.pack_into("<I", cut, 0, len(cut) - 4)
    with pytest.raises(InspectionError) as error:
        lookup(save(tmp_path, programs=[(bytes(cut), b"/one"), (original, b"/two")]), [0])
    assert error.value.code == "FORMAT_INVALID"


def test_function_outside_section_and_width_are_rejected(tmp_path):
    with pytest.raises(InspectionError, match="outside its section"):
        lookup(save(tmp_path, symbol_entries=[("bad", 0, 17, 0x12, 1)]), [0])
    with pytest.raises(InspectionError, match="address width"):
        lookup(save(tmp_path), [1 << 32])


def test_snapshot_binding_no_external_debug_source_or_subprocess(tmp_path, monkeypatch):
    path = save(tmp_path)
    snapshot = path.read_bytes()
    reader = addresses._snapshot

    def replace_after_read(source):
        resolved, data = reader(source)
        source.write_bytes(elf_image())
        return resolved, data

    monkeypatch.setattr(addresses, "_snapshot", replace_after_read)

    def forbidden(*args, **kwargs):
        raise AssertionError("no external file or process")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("elftools.elf.elffile.ELFFile.get_supplementary_dwarfinfo", forbidden)
    result = lookup(path, [0])
    assert result["source"]["sha256"] == hashlib.sha256(snapshot).hexdigest()
    assert result["address_queries"][0]["lines"][0]["line"] == 10
    monkeypatch.setattr(addresses, "_snapshot", reader)
    before = path.read_bytes(), path.stat().st_mtime_ns
    lookup(path, [0])
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_compressed_dwarf_and_invalid_file_index_fail_without_guessing(tmp_path):
    debug = dwarf_sections()
    debug[".zdebug_info"] = b"compressed"
    path = save(tmp_path, image=elf_image(text=b"\0" * 16, debug_sections=debug))
    with pytest.raises(InspectionError) as error:
        lookup(path, [0])
    assert error.value.code == "FORMAT_UNSUPPORTED"
    program = line_program().replace(b"\x04\x01\0\x05\x02", b"\x04\x09\0\x05\x02")
    with pytest.raises(InspectionError) as error:
        lookup(save(tmp_path, programs=[(program, b"/build")]), [0])
    assert error.value.code == "FORMAT_INVALID"


@pytest.mark.parametrize("form,section", [(0x0E, ".debug_str"), (0x1F, ".debug_line_str")])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_dwarf5_paths_from_in_file_string_tables(tmp_path, form, section, endian):
    program = line_program(version=5, endian=endian, path_form=form)
    debug = dwarf_sections(programs=[(program, b"/build")], version=5, endian=endian)
    debug[section] = b"src\0app.c\0"
    image = elf_image(text=b"\0" * 16, endian=endian, debug_sections=debug)
    report = lookup(save(tmp_path, image=image), [0])
    location = report["address_queries"][0]["lines"][0]
    assert location["file_name"] == "app.c" and location["directory"] == "src"
    validator().validate(report)


def test_duplicate_debug_sections_are_rejected(tmp_path):
    debug = dwarf_sections()
    debug[".extra_line"] = line_program(((0, 30), (8, None)))
    image = elf_image(text=b"\0" * 16, debug_sections=debug)
    image = image.replace(b".extra_line\0", b".debug_line\0")
    with pytest.raises(InspectionError, match="duplicate DWARF"):
        lookup(save(tmp_path, image=image), [0])


def test_line_zero_and_disabled_malformed_debug_are_explicit(tmp_path):
    path = save(tmp_path, programs=[(line_program(((0, 10), (4, 0), (8, None))), b"/build")])
    rows = lookup(path, [0, 4])["address_queries"]
    assert rows[0]["line_status"] == "unique" and rows[1]["line_status"] == "not_found"
    malformed = save(tmp_path, programs=[(line_program()[:-1], b"/build")])
    report = lookup(malformed, [0], lines=False)
    assert report["debug_lines"]["status"] == "disabled"
    assert report["address_queries"][0]["function_status"] == "unique"


def test_forward_defined_file_does_not_validate_an_earlier_row(tmp_path):
    original = line_program(((0, 10), (8, None)))
    # Header decoding appends DW_LNE_define_file entries eagerly. A file defined
    # after a row must not make that earlier row's file register valid.
    define = b"\x03later.c\0\x01\x00\x00"
    program = original[:-3] + b"\0" + leb(len(define)) + define + original[-3:]
    program = program.replace(b"\x04\x01\0\x05\x02", b"\x04\x02\0\x05\x02")
    program = struct.pack("<I", len(program) - 4) + program[4:]
    with pytest.raises(InspectionError, match="file register"):
        lookup(save(tmp_path, programs=[(program, b"/build")]), [0])


def test_cli_contract_text_and_non_elf_failure(tmp_path, capsys):
    path = save(tmp_path)
    assert (
        main(["addresses", str(path), "--address", "0x1", "--address-mode", "arm-thumb", "--json"])
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    validator().validate(report)
    assert report["address_queries"][0]["lookup_address"] == 0
    assert main(["addresses", str(path), "--address", "0"]) == 0
    captured = capsys.readouterr()
    assert '"main"+0x0' in captured.out and '"app.c":10:0' in captured.out
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"raw")
    assert main(["addresses", str(binary), "--address", "0", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["error"]["code"] == "FORMAT_UNSUPPORTED"
    validator().validate(report)
    report = lookup(path, [0])
    report["address_queries"][0]["line_status"] = "not_found"
    assert not validator().is_valid(report)
