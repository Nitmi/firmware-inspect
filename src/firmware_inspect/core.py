from __future__ import annotations

import hashlib
import io
import stat
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.segments import NoteSegment
from intelhex import IntelHex

from . import __version__

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 4096
MAX_SEGMENTS = 4096
MAX_SYMBOLS = 200_000
MAX_HEX_BYTES = 8 * 1024 * 1024
MAX_NOTES = 4096
INSPECTION_SCHEMA = "embedded-firmware-inspect.inspection.v1"
DIFF_SCHEMA = "embedded-firmware-inspect.diff.v1"


class InspectionError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot(path: Path) -> tuple[Path, bytes]:
    try:
        resolved = path.resolve(strict=True)
        if not stat.S_ISREG(resolved.stat().st_mode):
            raise InspectionError("INPUT_INVALID", "input must be a regular file")
        with resolved.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except InspectionError:
        raise
    except (OSError, ValueError, RuntimeError) as error:
        raise InspectionError("INPUT_UNAVAILABLE", f"cannot read {path}: {error}") from error
    if len(data) > MAX_FILE_BYTES:
        raise InspectionError("LIMIT_EXCEEDED", f"input exceeds {MAX_FILE_BYTES} bytes")
    if not data:
        raise InspectionError("INPUT_INVALID", "firmware file is empty")
    return resolved, data


def _range(start: int, length: int, bits: int = 64) -> dict[str, int]:
    if start < 0 or length < 0 or start >= 1 << bits or start + length > 1 << bits:
        raise InspectionError("FORMAT_INVALID", f"address range exceeds unsigned {bits}-bit space")
    return {"start": start, "end_exclusive": start + length, "length_bytes": length}


def _union(ranges: list[dict[str, int]]) -> list[dict[str, int]]:
    merged: list[dict[str, int]] = []
    for item in sorted(ranges, key=lambda item: (item["start"], item["end_exclusive"])):
        if not item["length_bytes"]:
            continue
        if merged and item["start"] <= merged[-1]["end_exclusive"]:
            merged[-1]["end_exclusive"] = max(merged[-1]["end_exclusive"], item["end_exclusive"])
            merged[-1]["length_bytes"] = merged[-1]["end_exclusive"] - merged[-1]["start"]
        else:
            merged.append(dict(item))
    return merged


def _base_report(operation: str, schema: str) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "ok": True,
        "operation": operation,
        "tool": {"name": "firmware-inspect", "version": __version__},
        "scope": "host_only_firmware_analysis",
        "hardware_access": False,
        "executables_started": False,
        "flash_authorized": False,
        "warnings": [],
    }


def inspect(
    path: Path,
    *,
    format: str = "auto",
    base_address: int | None = None,
    symbol_limit: int = 20,
) -> dict[str, Any]:
    if format not in {"auto", "elf", "hex", "bin"}:
        raise InspectionError("OPTIONS_INVALID", "format must be auto, elf, hex, or bin")
    if type(symbol_limit) is not int or not 0 <= symbol_limit <= 200:
        raise InspectionError("OPTIONS_INVALID", "symbol limit must be between 0 and 200")
    if base_address is not None and (
        type(base_address) is not int or not 0 <= base_address < 1 << 64
    ):
        raise InspectionError("OPTIONS_INVALID", "base address must be an unsigned 64-bit integer")
    resolved, data = _snapshot(path)
    if format == "auto":
        if data.startswith(b"\x7fELF"):
            format = "elf"
        elif resolved.suffix.lower() in {".hex", ".ihex"}:
            format = "hex"
        elif resolved.suffix.lower() == ".bin":
            format = "bin"
        else:
            raise InspectionError("FORMAT_UNKNOWN", "cannot infer format; supply --format")
    if format == "bin" and base_address is None:
        raise InspectionError("OPTIONS_INVALID", "BIN requires an explicit --base-address")
    if format != "bin" and base_address is not None:
        raise InspectionError("OPTIONS_INVALID", "base address is only valid for BIN")
    report = _base_report("inspect", INSPECTION_SCHEMA)
    report.update(
        {
            "source": {"path": str(resolved), "size_bytes": len(data), "sha256": sha256(data)},
            "format": format,
            "address_unit": "byte",
            "range_convention": "half_open",
        }
    )
    try:
        if format == "elf":
            report.update(_elf(data, symbol_limit))
        elif format == "hex":
            report.update(_hex(data))
        else:
            report.update(_bin(data, base_address))
    except InspectionError:
        raise
    except Exception as error:
        # Parser exceptions must stay inside the machine-readable CLI contract.
        raise InspectionError("FORMAT_INVALID", f"invalid {format.upper()}: {error}") from error
    ranges = _union(
        [
            _range(segment["load_address"], segment["file_size_bytes"])
            for segment in report["load_segments"]
        ]
    )
    report["programmed_ranges"] = ranges
    report["summary"]["program_address_bytes"] = sum(item["length_bytes"] for item in ranges)
    report["summary"]["load_file_bytes_sum"] = sum(
        item["file_size_bytes"] for item in report["load_segments"]
    )
    if report["summary"]["program_address_bytes"] < report["summary"]["load_file_bytes_sum"]:
        report["warnings"].append(
            "overlapping file-backed load addresses; no flash layout inferred"
        )
    return report


def _bin(data: bytes, base_address: int) -> dict[str, Any]:
    _range(base_address, len(data))
    return {
        "architecture": None,
        "entry_point": None,
        "build_ids": [],
        "sections": [],
        "symbols": None,
        "load_segments": [
            {
                "index": 0,
                "load_address": base_address,
                "run_address": None,
                "source_offset": 0,
                "file_size_bytes": len(data),
                "memory_size_bytes": None,
                "sha256": sha256(data),
            }
        ],
        "summary": {"section_usage": None},
    }


def _hex(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_HEX_BYTES:
        raise InspectionError("LIMIT_EXCEEDED", f"Intel HEX exceeds {MAX_HEX_BYTES} source bytes")
    text = data.decode("ascii")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if (
        not lines
        or lines[-1].upper() != ":00000001FF"
        or any(line.upper() == ":00000001FF" for line in lines[:-1])
    ):
        raise InspectionError("FORMAT_INVALID", "Intel HEX requires one final EOF record")
    if any(len(line) > 521 for line in lines):
        raise InspectionError("FORMAT_INVALID", "Intel HEX record exceeds maximum record size")
    stream = io.StringIO(text)
    image = IntelHex(stream)
    if stream.read().strip():
        raise InspectionError("FORMAT_INVALID", "Intel HEX has records after parser EOF")
    ranges = image.segments()
    if not ranges:
        raise InspectionError("FORMAT_INVALID", "Intel HEX has no data records")
    if len(ranges) > MAX_SEGMENTS:
        raise InspectionError("LIMIT_EXCEEDED", "Intel HEX has too many sparse segments")
    segments = []
    for index, (start, end) in enumerate(ranges):
        _range(start, end - start, 32)
        payload = image.tobinstr(start=start, end=end - 1)
        segments.append(
            {
                "index": index,
                "load_address": start,
                "run_address": None,
                "source_offset": None,
                "file_size_bytes": len(payload),
                "memory_size_bytes": None,
                "sha256": sha256(payload),
            }
        )
    return {
        "architecture": None,
        "entry_point": None,
        "hex_start_address": image.start_addr,
        "build_ids": [],
        "sections": [],
        "symbols": None,
        "load_segments": segments,
        "summary": {"section_usage": None},
    }


def _elf(data: bytes, symbol_limit: int) -> dict[str, Any]:
    elf = ELFFile(io.BytesIO(data))
    if elf.header["e_type"] not in {"ET_EXEC", "ET_DYN"}:
        raise InspectionError("FORMAT_UNSUPPORTED", "ELF must be executable or shared/PIE")
    if elf.num_sections() > MAX_SECTIONS or elf.num_segments() > MAX_SEGMENTS:
        raise InspectionError("LIMIT_EXCEEDED", "ELF has too many sections or segments")
    segments, build_ids = [], []
    load_file_bytes, note_file_bytes, note_count = 0, 0, 0
    for index, segment in enumerate(elf.iter_segments()):
        if isinstance(segment, NoteSegment):
            if segment["p_offset"] + segment["p_filesz"] > len(data):
                raise InspectionError("FORMAT_INVALID", "ELF note segment extends beyond file")
            note_file_bytes += segment["p_filesz"]
            if note_file_bytes > 2 * MAX_FILE_BYTES:
                raise InspectionError("LIMIT_EXCEEDED", "ELF aggregate note payload exceeds limit")
            ids, note_count = _build_ids(segment, note_count)
            build_ids.extend(ids)
        if segment["p_type"] != "PT_LOAD":
            continue
        size, memory_size, offset = segment["p_filesz"], segment["p_memsz"], segment["p_offset"]
        if size > memory_size or offset + size > len(data):
            raise InspectionError("FORMAT_INVALID", "ELF load segment is outside file or memory")
        load_file_bytes += size
        if load_file_bytes > 2 * MAX_FILE_BYTES:
            raise InspectionError("LIMIT_EXCEEDED", "ELF aggregate load payload exceeds limit")
        _range(segment["p_paddr"], size, elf.elfclass)
        _range(segment["p_vaddr"], memory_size, elf.elfclass)
        segments.append(
            {
                "index": index,
                "load_address": segment["p_paddr"],
                "run_address": segment["p_vaddr"],
                "source_offset": offset,
                "file_size_bytes": size,
                "memory_size_bytes": memory_size,
                "sha256": sha256(data[offset : offset + size]),
            }
        )
    if not segments:
        raise InspectionError("FORMAT_INVALID", "ELF has no PT_LOAD segments")
    sections, symbols = [], []
    symbol_count, table_entries, section_file_bytes = 0, 0, 0
    usage = {
        "allocated_bytes_sum": 0,
        "file_backed_bytes_sum": 0,
        "zero_fill_bytes_sum": 0,
        "writable_bytes_sum": 0,
        "readonly_bytes_sum": 0,
        "executable_bytes_sum": 0,
    }
    for index, section in enumerate(elf.iter_sections()):
        size, flags, kind = section["sh_size"], section["sh_flags"], section["sh_type"]
        if kind != "SHT_NOBITS" and section["sh_offset"] + size > len(data):
            raise InspectionError("FORMAT_INVALID", "ELF section extends beyond file")
        if kind != "SHT_NOBITS":
            section_file_bytes += size
            if section_file_bytes > 2 * MAX_FILE_BYTES:
                raise InspectionError("LIMIT_EXCEEDED", "ELF aggregate section bytes exceed limit")
        if len(section.name) > 1024:
            raise InspectionError("LIMIT_EXCEEDED", "ELF section name exceeds limit")
        allocated, writable, executable = bool(flags & 2), bool(flags & 1), bool(flags & 4)
        if allocated:
            _range(section["sh_addr"], size, elf.elfclass)
            usage["allocated_bytes_sum"] += size
            usage["zero_fill_bytes_sum" if kind == "SHT_NOBITS" else "file_backed_bytes_sum"] += (
                size
            )
            usage["writable_bytes_sum" if writable else "readonly_bytes_sum"] += size
            if executable:
                usage["executable_bytes_sum"] += size
        sections.append(
            {
                "index": index,
                "name": section.name,
                "type": kind,
                "address": section["sh_addr"],
                "size_bytes": size,
                "allocated": allocated,
                "writable": writable,
                "executable": executable,
                "file_backed": kind != "SHT_NOBITS",
                "sha256": None
                if kind == "SHT_NOBITS"
                else sha256(data[section["sh_offset"] : section["sh_offset"] + size]),
            }
        )
        if isinstance(section, NoteSection):
            ids, note_count = _build_ids(section, note_count)
            build_ids.extend(ids)
        if isinstance(section, SymbolTableSection):
            table_entries += section.num_symbols()
            if table_entries > MAX_SYMBOLS:
                raise InspectionError("LIMIT_EXCEEDED", "ELF has too many symbol entries")
            for symbol in section.iter_symbols():
                kind = symbol["st_info"]["type"]
                if (
                    kind not in {"STT_FUNC", "STT_OBJECT"}
                    or not isinstance(symbol["st_shndx"], int)
                    or symbol["st_shndx"] == 0
                    or not symbol.name
                ):
                    continue
                if symbol["st_shndx"] >= elf.num_sections():
                    raise InspectionError("FORMAT_INVALID", "ELF symbol has invalid section index")
                if len(symbol.name) > 1024:
                    raise InspectionError("LIMIT_EXCEEDED", "ELF symbol name exceeds limit")
                symbol_count += 1
                symbols.append(
                    {
                        "name": symbol.name,
                        "type": kind,
                        "address": symbol["st_value"],
                        "size_bytes": symbol["st_size"],
                        "section_index": symbol["st_shndx"],
                        "table_index": index,
                    }
                )
    symbols.sort(key=lambda item: (-item["size_bytes"], item["name"], item["address"]))
    return {
        "architecture": {
            "machine": elf.header["e_machine"],
            "bits": elf.elfclass,
            "endianness": "little" if elf.little_endian else "big",
            "elf_type": elf.header["e_type"],
        },
        "entry_point": elf.header["e_entry"],
        "build_ids": sorted(set(build_ids)),
        "sections": sections,
        "load_segments": segments,
        "symbols": {
            "defined_function_object_entries": symbol_count,
            "limit": symbol_limit,
            "truncated": symbol_count > symbol_limit,
            "largest": symbols[:symbol_limit],
        },
        "summary": {"section_usage": usage},
        "warnings": [
            "section usage is a sum, not physical RAM/Flash capacity or erase layout",
            "ELF PT_LOAD physical addresses are linker-declared, not validated flash destinations",
        ],
    }


def _build_ids(container: NoteSection | NoteSegment, count: int) -> tuple[list[str], int]:
    ids = []
    for note in container.iter_notes():
        count += 1
        if count > MAX_NOTES:
            raise InspectionError("LIMIT_EXCEEDED", "ELF has too many note entries")
        if note["n_type"] == "NT_GNU_BUILD_ID" and note["n_name"] == "GNU":
            value = note["n_desc"]
            value = value.hex() if isinstance(value, bytes) else value
            if not isinstance(value, str) or len(value) > 8192:
                raise InspectionError("LIMIT_EXCEEDED", "ELF Build ID exceeds limit")
            ids.append(value)
    return ids, count


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before["format"] != after["format"] or before["architecture"] != after["architecture"]:
        raise InspectionError(
            "INPUT_INCOMPATIBLE", "diff requires matching format and architecture"
        )
    report = _base_report("diff", DIFF_SCHEMA)
    report.update(
        {
            "format": before["format"],
            "architecture": before["architecture"],
            "before": before["source"],
            "after": after["source"],
            "source_identical": before["source"]["sha256"] == after["source"]["sha256"],
            "identical": before["source"]["sha256"] == after["source"]["sha256"]
            and before["programmed_ranges"] == after["programmed_ranges"],
            "file_size_delta_bytes": after["source"]["size_bytes"] - before["source"]["size_bytes"],
            "program_address_delta_bytes": (
                after["summary"]["program_address_bytes"]
                - before["summary"]["program_address_bytes"]
            ),
            "entry_point_changed": before["entry_point"] != after["entry_point"],
            "build_ids": {"before": before["build_ids"], "after": after["build_ids"]},
            "layout_changed": before["programmed_ranges"] != after["programmed_ranges"]
            or _allocated_layout(before["sections"]) != _allocated_layout(after["sections"])
            or _segment_layout(before["load_segments"]) != _segment_layout(after["load_segments"]),
            "programmed_ranges": {
                "before": before["programmed_ranges"],
                "after": after["programmed_ranges"],
            },
            "section_usage_delta": None,
            "section_changes": [],
            "load_segment_changes": [],
        }
    )
    if before["format"] == "elf":
        old_usage, new_usage = before["summary"]["section_usage"], after["summary"]["section_usage"]
        report["section_usage_delta"] = {key: new_usage[key] - old_usage[key] for key in old_usage}
        old, new = _section_index(before["sections"]), _section_index(after["sections"])
        for name, occurrence in sorted(old.keys() | new.keys()):
            left, right = old.get((name, occurrence)), new.get((name, occurrence))
            if left == right:
                continue
            report["section_changes"].append(
                {
                    "name": name,
                    "occurrence": occurrence,
                    "change": "added"
                    if left is None
                    else "removed"
                    if right is None
                    else "changed",
                    "before": left,
                    "after": right,
                    "size_delta_bytes": (right["size_bytes"] if right else 0)
                    - (left["size_bytes"] if left else 0),
                }
            )
    old_segments = _segment_index(before["load_segments"])
    new_segments = _segment_index(after["load_segments"])
    for key in sorted(old_segments.keys() | new_segments.keys(), key=_segment_key):
        left, right = old_segments.get(key), new_segments.get(key)
        if left == right:
            continue
        load_address, run_address, occurrence = key
        report["load_segment_changes"].append(
            {
                "load_address": load_address,
                "run_address": run_address,
                "occurrence": occurrence,
                "change": "added" if left is None else "removed" if right is None else "changed",
                "before": left,
                "after": right,
            }
        )
    report["warnings"] = sorted(set(before["warnings"] + after["warnings"]))
    return report


def _allocated_layout(sections: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return sorted(
        (
            item["name"],
            item["address"],
            item["size_bytes"],
            item["type"],
            item["writable"],
            item["executable"],
        )
        for item in sections
        if item["allocated"]
    )


def _segment_layout(segments: list[dict[str, Any]]) -> list[tuple[int, ...]]:
    return sorted(
        (
            item["load_address"],
            item["run_address"] if item["run_address"] is not None else -1,
            item["file_size_bytes"],
            item["memory_size_bytes"] or 0,
        )
        for item in segments
    )


def _segment_key(key: tuple[int, int | None, int]) -> tuple[int, int, int]:
    return key[0], key[1] if key[1] is not None else -1, key[2]


def _segment_index(segments: list[dict[str, Any]]) -> dict[tuple[int, int | None, int], Any]:
    result = {}
    counts: dict[tuple[int, int | None], int] = {}
    for segment in segments:
        address = (segment["load_address"], segment["run_address"])
        occurrence = counts.get(address, 0)
        counts[address] = occurrence + 1
        result[(*address, occurrence)] = {
            key: value for key, value in segment.items() if key not in {"index", "source_offset"}
        }
    return result


def _section_index(sections: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    result = {}
    counts: dict[str, int] = {}
    for section in sections:
        name = section["name"]
        ordinal = counts.get(name, 0)
        counts[name] = ordinal + 1
        result[(name, ordinal)] = {key: value for key, value in section.items() if key != "index"}
    return result
