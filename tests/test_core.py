from __future__ import annotations

import hashlib
import io
import struct
from pathlib import Path

import pytest
from fixtures import elf_image
from intelhex import IntelHex, Record

from firmware_inspect import core
from firmware_inspect.core import InspectionError, compare, inspect


def save(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def hex_image() -> bytes:
    image = IntelHex()
    image.puts(0, b"abcd")
    image.puts(0x10001000, b"UICR")
    image.start_addr = {"EIP": 0}
    output = io.StringIO()
    image.write_hex_file(output)
    return output.getvalue().encode("ascii")


def test_bin_explicit_base_and_snapshot_hash(tmp_path):
    data = b"firmware"
    report = inspect(save(tmp_path, "app.bin", data), base_address=0x10000)
    assert report["source"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert report["programmed_ranges"] == [
        {
            "start": 0x10000,
            "end_exclusive": 0x10008,
            "length_bytes": 8,
        }
    ]
    assert report["summary"]["section_usage"] is None
    assert report["load_segments"][0]["run_address"] is None
    assert report["hardware_access"] is report["executables_started"] is False
    assert report["flash_authorized"] is False


@pytest.mark.parametrize(
    "options,code",
    [
        ({}, "OPTIONS_INVALID"),
        ({"base_address": -1}, "OPTIONS_INVALID"),
        ({"base_address": True}, "OPTIONS_INVALID"),
        ({"base_address": 1 << 64}, "OPTIONS_INVALID"),
        ({"base_address": (1 << 64) - 1}, "FORMAT_INVALID"),
        ({"format": "bad"}, "OPTIONS_INVALID"),
        ({"symbol_limit": 201}, "OPTIONS_INVALID"),
        ({"symbol_limit": True}, "OPTIONS_INVALID"),
    ],
)
def test_invalid_options(tmp_path, options, code):
    with pytest.raises(InspectionError) as error:
        inspect(save(tmp_path, "app.bin", b"12"), **options)
    assert error.value.code == code


def test_unknown_format_not_guessed(tmp_path):
    path = save(tmp_path, "app.dat", b":no guess")
    with pytest.raises(InspectionError, match="cannot infer"):
        inspect(path)
    assert inspect(path, format="bin", base_address=0)["format"] == "bin"


def test_missing_empty_directory_and_size_limit(tmp_path, monkeypatch):
    for path in (tmp_path / "absent", save(tmp_path, "empty.bin", b""), tmp_path):
        with pytest.raises(InspectionError):
            inspect(path, format="bin", base_address=0)
    monkeypatch.setattr(core, "MAX_FILE_BYTES", 3)
    with pytest.raises(InspectionError) as error:
        inspect(save(tmp_path, "large.bin", b"four"), base_address=0)
    assert error.value.code == "LIMIT_EXCEEDED"


def test_sparse_hex_and_high_addresses_are_retained(tmp_path):
    report = inspect(save(tmp_path, "whole.hex", hex_image()))
    assert report["summary"]["program_address_bytes"] == 8
    assert report["source"]["size_bytes"] > 8
    assert [item["start"] for item in report["programmed_ranges"]] == [0, 0x10001000]
    assert report["load_segments"][1]["sha256"] == hashlib.sha256(b"UICR").hexdigest()
    assert report["hex_start_address"] == {"EIP": 0}
    assert report["entry_point"] is None
    with pytest.raises(InspectionError, match="only valid for BIN"):
        inspect(tmp_path / "whole.hex", base_address=0)


@pytest.mark.parametrize(
    "data",
    [
        b":040000006162636471\n:00000001FF\n",  # Wrong checksum.
        b":040000006162636472\n:040000006162636472\n:00000001FF\n",  # Overlap.
        b":040000006162636472\n",  # Missing EOF.
        b":00000001FF\n:040000006162636472\n",  # Trailing record after EOF.
        b":00000001FF\n",  # No payload.
        b":00000001FF\n:00000001FF\n",  # Two EOF records.
        b":00000101FE\n:040000006162636472\n:00000001FF\n",  # Noncanonical early EOF.
        b"\xff\n:00000001FF\n",  # Non-ASCII.
        b":" + b"0" * 522 + b"\n:00000001FF\n",  # Oversized record.
    ],
)
def test_hex_invalid_inputs_fail(tmp_path, data):
    with pytest.raises(InspectionError) as error:
        inspect(save(tmp_path, "bad.hex", data))
    assert error.value.code == "FORMAT_INVALID"


@pytest.mark.parametrize("bits,endian", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_elf_addresses_bss_build_ids_and_symbols(tmp_path, bits, endian):
    report = inspect(save(tmp_path, "app.elf", elf_image(bits=bits, endian=endian)))
    assert report["architecture"]["bits"] == bits
    assert report["architecture"]["endianness"] == ("little" if endian == "<" else "big")
    assert report["build_ids"] == ["01020304"]
    assert report["load_segments"][1]["load_address"] == 0x1000
    assert report["load_segments"][1]["run_address"] == 0x20000000
    assert report["load_segments"][1]["file_size_bytes"] == 4
    assert report["load_segments"][1]["memory_size_bytes"] == 12
    assert report["summary"]["program_address_bytes"] == 8
    assert report["summary"]["section_usage"] == {
        "allocated_bytes_sum": 16,
        "file_backed_bytes_sum": 8,
        "zero_fill_bytes_sum": 8,
        "writable_bytes_sum": 12,
        "readonly_bytes_sum": 4,
        "executable_bytes_sum": 4,
    }
    assert report["symbols"]["defined_function_object_entries"] == 2
    assert {item["name"] for item in report["symbols"]["largest"]} == {"main", "counter"}
    assert next(item for item in report["sections"] if item["name"] == ".bss")["sha256"] is None


def test_elf_symbol_output_limit(tmp_path):
    path = save(tmp_path, "app.elf", elf_image())
    report = inspect(path, symbol_limit=1)
    assert report["symbols"]["truncated"] is True
    assert len(report["symbols"]["largest"]) == 1
    assert inspect(path, symbol_limit=0)["symbols"]["largest"] == []


def test_malformed_and_relocatable_elf_rejected(tmp_path):
    for data in (b"\x7fELFbroken", elf_image(elf_type=1), elf_image()[:-20]):
        with pytest.raises(InspectionError):
            inspect(save(tmp_path, "bad.elf", data))


def test_elf_segment_bounds_and_no_load_segments(tmp_path):
    image = bytearray(elf_image())
    struct.pack_into("<I", image, 52 + 16, 1 << 20)  # p_filesz outside file and memory.
    with pytest.raises(InspectionError, match="outside file or memory"):
        inspect(save(tmp_path, "overflow.elf", image))
    image = bytearray(elf_image())
    struct.pack_into("<I", image, 52, 0)
    struct.pack_into("<I", image, 84, 0)
    with pytest.raises(InspectionError, match="no PT_LOAD"):
        inspect(save(tmp_path, "unloadable.elf", image))


def test_elf_and_hex_structural_limits(tmp_path, monkeypatch):
    path = save(tmp_path, "app.elf", elf_image())
    with monkeypatch.context() as patch:
        patch.setattr(core, "MAX_SECTIONS", 1)
        with pytest.raises(InspectionError) as error:
            inspect(path)
        assert error.value.code == "LIMIT_EXCEEDED"
    with monkeypatch.context() as patch:
        patch.setattr(core, "MAX_SYMBOLS", 1)
        with pytest.raises(InspectionError) as error:
            inspect(path)
        assert error.value.code == "LIMIT_EXCEEDED"
    with monkeypatch.context() as patch:
        patch.setattr(core, "MAX_HEX_BYTES", 3)
        with pytest.raises(InspectionError) as error:
            inspect(save(tmp_path, "whole.hex", hex_image()))
        assert error.value.code == "LIMIT_EXCEEDED"


def test_overlapping_load_ranges_warn_without_double_count(tmp_path):
    image = bytearray(elf_image())
    struct.pack_into("<I", image, 84 + 12, 2)  # Second p_paddr overlaps first.
    report = inspect(save(tmp_path, "overlay.elf", image))
    assert report["summary"]["program_address_bytes"] == 6
    assert report["summary"]["load_file_bytes_sum"] == 8
    assert any("overlapping" in warning for warning in report["warnings"])


def test_diff_identical_and_bss_changes(tmp_path):
    before = inspect(save(tmp_path, "a.elf", elf_image()))
    identical = compare(before, before)
    assert identical["identical"] is True
    assert identical["section_changes"] == []
    after = inspect(save(tmp_path, "b.elf", elf_image(bss_size=16)))
    diff = compare(before, after)
    assert diff["identical"] is False
    assert diff["layout_changed"] is True
    assert diff["program_address_delta_bytes"] == 0
    assert diff["section_usage_delta"]["zero_fill_bytes_sum"] == 8
    change = next(item for item in diff["section_changes"] if item["name"] == ".bss")
    assert change["size_delta_bytes"] == 8


def test_diff_same_size_payload_change(tmp_path):
    before = inspect(save(tmp_path, "a.elf", elf_image()))
    after = inspect(save(tmp_path, "b.elf", elf_image(text=b"\xff" * 4)))
    diff = compare(before, after)
    assert diff["layout_changed"] is False
    assert diff["file_size_delta_bytes"] == 0
    assert [item["name"] for item in diff["section_changes"]] == [".text"]


def test_diff_incompatible_inputs(tmp_path):
    elf = inspect(save(tmp_path, "a.elf", elf_image()))
    wide = inspect(save(tmp_path, "b.elf", elf_image(bits=64)))
    binary = inspect(save(tmp_path, "app.bin", b"bin"), base_address=0)
    for other in (wide, binary):
        with pytest.raises(InspectionError) as error:
            compare(elf, other)
        assert error.value.code == "INPUT_INCOMPATIBLE"


def test_duplicate_section_names_not_overwritten(tmp_path):
    report = inspect(save(tmp_path, "app.elf", elf_image()))
    sections = [
        {**report["sections"][1], "name": ".repeated"},
        {**report["sections"][2], "name": ".repeated"},
    ]
    indexed = core._section_index(sections)
    assert len(indexed) == 2
    assert indexed[(".repeated", 0)]["sha256"] != indexed[(".repeated", 1)]["sha256"]


def test_build_id_from_program_notes_without_section_table(tmp_path):
    data = bytearray(elf_image(note_program=True))
    struct.pack_into("<I", data, 32, 0)  # e_shoff.
    struct.pack_into("<HH", data, 48, 0, 0)  # e_shnum / e_shstrndx.
    report = inspect(save(tmp_path, "stripped.elf", data))
    assert report["build_ids"] == ["01020304"]
    assert report["sections"] == []
    assert report["symbols"]["defined_function_object_entries"] == 0


def test_duplicate_build_id_notes_and_note_budget(tmp_path, monkeypatch):
    path = save(tmp_path, "app.elf", elf_image(note_program=True))
    assert inspect(path)["build_ids"] == ["01020304"]
    monkeypatch.setattr(core, "MAX_NOTES", 1)
    with pytest.raises(InspectionError) as error:
        inspect(path)
    assert error.value.code == "LIMIT_EXCEEDED"


def test_bin_and_hex_diff_include_payload_changes(tmp_path):
    first = inspect(save(tmp_path, "a.bin", b"abcd"), base_address=0)
    second = inspect(save(tmp_path, "b.bin", b"ABCD"), base_address=0)
    report = compare(first, second)
    assert report["layout_changed"] is False
    assert report["load_segment_changes"][0]["change"] == "changed"
    assert report["load_segment_changes"][0]["load_address"] == 0
    assert report["section_changes"] == []


def test_same_bin_at_different_bases_is_not_identical(tmp_path):
    path = save(tmp_path, "app.bin", b"abcd")
    report = compare(inspect(path, base_address=0), inspect(path, base_address=4))
    assert report["source_identical"] is True
    assert report["identical"] is False
    assert report["layout_changed"] is True
    assert {item["change"] for item in report["load_segment_changes"]} == {"added", "removed"}


def test_inspection_never_mutates_firmware(tmp_path):
    path = save(tmp_path, "app.elf", elf_image())
    before_bytes, before_stat = path.read_bytes(), path.stat()
    inspect(path)
    compare(inspect(path), inspect(path))
    assert path.read_bytes() == before_bytes
    assert path.stat().st_mtime_ns == before_stat.st_mtime_ns


def test_hex_range_overflow_is_not_wrapped(tmp_path):
    text = "\n".join(
        [
            Record.extended_linear_address(0xFFFF),
            Record.data(0xFFFF, [0x31, 0x32]),
            Record.eof(),
            "",
        ]
    )
    with pytest.raises(InspectionError):
        inspect(save(tmp_path, "overflow.hex", text.encode()))


def test_note_segment_cannot_read_outside_input(tmp_path):
    data = bytearray(elf_image(note_program=True))
    struct.pack_into("<I", data, 52 + 2 * 32 + 4, len(data) + 100)
    with pytest.raises(InspectionError, match="note segment extends beyond file"):
        inspect(save(tmp_path, "invalid-notes.elf", data))
