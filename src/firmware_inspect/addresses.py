from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .core import MAX_SYMBOLS, InspectionError, _base_report, _elf, _snapshot, sha256

ADDRESSES_SCHEMA = "embedded-firmware-inspect.addresses.v1"
MAX_ADDRESSES = 32
MAX_FUNCTION_MATCHES = 256
MAX_LINE_MATCHES = 128
MAX_DEBUG_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
# pyelftools decodes a whole line program eagerly. Bound encoded bytes before
# parsing, not just the number of rows after they have already been allocated.
MAX_LINE_UNIT_BYTES = 128 * 1024
MAX_LINE_ENTRIES = 200_000
MAX_COMPILE_UNITS = 1024


class _UnitStream(io.BytesIO):
    """Keep pyelftools reads/seeks inside one declared DWARF unit."""

    def __init__(self, data: bytes, start: int, end: int):
        super().__init__(data)
        self.start, self.end = start, end
        self.seek(start)

    def seek(self, offset: int, whence: int = 0) -> int:
        target = (
            offset if whence == 0 else self.tell() + offset if whence == 1 else self.end + offset
        )
        if not self.start <= target <= self.end:
            raise InspectionError("FORMAT_INVALID", "DWARF access extends outside its unit")
        return super().seek(target)

    def read(self, size: int = -1) -> bytes:
        remaining = self.end - self.tell()
        if size > remaining:
            raise InspectionError("FORMAT_INVALID", "DWARF read extends outside its unit")
        return super().read(remaining if size < 0 else size)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, bytes)):
        raise InspectionError("FORMAT_UNSUPPORTED", "external/indexed DWARF string is unresolved")
    if len(value) > 4096:
        raise InspectionError("LIMIT_EXCEEDED", "DWARF source path exceeds 4096 bytes/characters")
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def _status(matches: list[dict], fields: tuple[str, ...]) -> str:
    count = len({tuple(row[field] for field in fields) for row in matches})
    return "unique" if count == 1 else "ambiguous" if count else "not_found"


def _functions(elf: ELFFile, sections: list[dict], queries: list[dict]) -> dict:
    table_count = entry_count = match_count = 0
    for table_index, table in enumerate(elf.iter_sections()):
        if not isinstance(table, SymbolTableSection):
            continue
        expected_size = elf.structs.Elf_Sym.sizeof()
        if table["sh_entsize"] != expected_size or table["sh_size"] % expected_size:
            raise InspectionError("FORMAT_INVALID", "ELF symbol table has invalid entry sizes")
        table_count += 1
        entry_count += table.num_symbols()
        if entry_count > MAX_SYMBOLS:
            raise InspectionError("LIMIT_EXCEEDED", "ELF has too many symbol entries")
        for index, symbol in enumerate(table.iter_symbols()):
            section_index = symbol["st_shndx"]
            if len(symbol.name) > 1024:
                raise InspectionError("LIMIT_EXCEEDED", "ELF symbol name exceeds limit")
            if (
                symbol["st_info"]["type"] != "STT_FUNC"
                or not symbol.name
                or not isinstance(section_index, int)
                or not 0 < section_index < SHN_INDICES.SHN_LORESERVE
            ):
                continue
            if section_index >= len(sections):
                raise InspectionError("FORMAT_INVALID", "ELF symbol has invalid section index")
            section = sections[section_index]
            if not section["allocated"] or not section["executable"]:
                continue
            value, size = symbol["st_value"], symbol["st_size"]
            thumb_value = (
                elf.header["e_machine"] == "EM_ARM" and elf.elfclass == 32 and bool(value & 1)
            )
            start = value & ~1 if thumb_value else value
            end = start + size
            section_end = section["address"] + section["size_bytes"]
            if not section["address"] <= start < section_end or end > section_end:
                raise InspectionError("FORMAT_INVALID", "ELF function extends outside its section")
            for query in queries:
                address = query["lookup_address"]
                if not (start <= address < end if size else address == start):
                    continue
                match_count += 1
                if match_count > MAX_FUNCTION_MATCHES:
                    raise InspectionError(
                        "LIMIT_EXCEEDED", "address queries exceed 256 function matches"
                    )
                query["functions"].append(
                    {
                        "name": symbol.name,
                        "table_index": table_index,
                        "table_name": table.name,
                        "symbol_index": index,
                        "section_index": section_index,
                        "binding": symbol["st_info"]["bind"],
                        "visibility": symbol["st_other"]["visibility"],
                        "raw_value": value,
                        "range_start": start,
                        "range_end_exclusive": end if size else None,
                        "size_bytes": size,
                        "offset_bytes": address - start,
                        "value_normalization": "arm_thumb_bit" if thumb_value else "none",
                        "match_kind": "declared_range" if size else "exact_start_only",
                    }
                )
    for query in queries:
        query["function_status"] = _status(
            query["functions"],
            (
                "name",
                "section_index",
                "binding",
                "visibility",
                "raw_value",
                "size_bytes",
            ),
        )
    return {"symbol_tables_scanned": table_count, "symbol_entries_scanned": entry_count}


def _line_unit_end(data: bytes, offset: int, byteorder: str) -> int:
    if not 0 <= offset <= len(data) - 4:
        raise InspectionError("FORMAT_INVALID", "DWARF line offset is outside the section")
    length = int.from_bytes(data[offset : offset + 4], byteorder)
    prefix = 4
    if length == 0xFFFFFFFF:
        if offset + 12 > len(data):
            raise InspectionError("FORMAT_INVALID", "DWARF64 line length is truncated")
        length = int.from_bytes(data[offset + 4 : offset + 12], byteorder)
        prefix = 12
    elif length >= 0xFFFFFFF0:
        raise InspectionError("FORMAT_INVALID", "DWARF line length is reserved")
    end = offset + prefix + length
    if end > len(data) or length < 2:
        raise InspectionError("FORMAT_INVALID", "DWARF line unit is truncated")
    if end - offset > MAX_LINE_UNIT_BYTES:
        raise InspectionError("LIMIT_EXCEEDED", "DWARF line unit exceeds 128 KiB encoded bytes")
    return end


def _location(program: Any, state: Any, compilation_directory: Any) -> dict:
    version = program.header["version"]
    files, directories = program.header["file_entry"], program.header["include_directory"]
    index = state.file - (1 if version < 5 else 0)
    if not 0 <= index < len(files):
        raise InspectionError("FORMAT_INVALID", "DWARF line file index is invalid")
    entry = files[index]
    directory_index = entry.dir_index
    if directory_index is None:
        directory = None
    elif version < 5 and directory_index == 0:
        directory = compilation_directory
    else:
        directory_index -= 1 if version < 5 else 0
        if not 0 <= directory_index < len(directories):
            raise InspectionError("FORMAT_INVALID", "DWARF line directory index is invalid")
        directory = directories[directory_index]
    return {
        "file_name": _text(entry.name),
        "directory": _text(directory),
        "compilation_directory": _text(compilation_directory),
        "line": state.line,
        "column": state.column,
        "discriminator": state.discriminator,
        "is_statement": bool(state.is_stmt),
    }


def _lines(elf: ELFFile, queries: list[dict], enabled: bool) -> dict:
    counts = {"compile_units_scanned": 0, "line_programs_scanned": 0, "line_entries_scanned": 0}
    line_section = elf.get_section_by_name(".debug_line")
    if enabled and elf.get_section_by_name(".zdebug_line") is not None:
        raise InspectionError("FORMAT_UNSUPPORTED", "compressed DWARF is unsupported")
    if not enabled or line_section is None or not elf.has_dwarf_info(strict=True):
        return {"status": "disabled" if not enabled else "absent", **counts}
    debug_bytes = 0
    debug_names = set()
    for section in elf.iter_sections():
        if section.name.startswith((".debug_", ".zdebug_")) or section.name in (
            ".eh_frame",
            ".gnu_debugaltlink",
        ):
            if section.name in debug_names:
                raise InspectionError("FORMAT_INVALID", "ELF has duplicate DWARF section names")
            debug_names.add(section.name)
            if section.name.startswith(".zdebug_") or section["sh_flags"] & 0x800:
                raise InspectionError("FORMAT_UNSUPPORTED", "compressed DWARF is unsupported")
            debug_bytes += section["sh_size"]
    if debug_bytes > MAX_DEBUG_BYTES or line_section["sh_size"] > MAX_LINE_BYTES:
        raise InspectionError("LIMIT_EXCEEDED", "DWARF sections or encoded line bytes exceed limit")
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False, follow_links=False)
    info_descriptor, line_descriptor = dwarf.debug_info_sec, dwarf.debug_line_sec
    info_data, line_data = info_descriptor.stream.getvalue(), line_descriptor.stream.getvalue()
    match_count = 0
    for cu in dwarf.iter_CUs():
        counts["compile_units_scanned"] += 1
        if counts["compile_units_scanned"] > MAX_COMPILE_UNITS:
            raise InspectionError("LIMIT_EXCEEDED", "DWARF has too many compilation units")
        if cu["address_size"] != elf.elfclass // 8:
            raise InspectionError("FORMAT_UNSUPPORTED", "DWARF address size differs from ELF")
        cu_end = cu.cu_offset + cu["unit_length"] + cu.structs.initial_length_field_size()
        if cu_end > len(info_data):
            raise InspectionError("FORMAT_INVALID", "DWARF compilation unit is truncated")
        dwarf.debug_info_sec = info_descriptor._replace(
            stream=_UnitStream(info_data, cu.cu_offset, cu_end)
        )
        try:
            top = cu.get_top_DIE()
        finally:
            dwarf.debug_info_sec = info_descriptor
        attribute = top.attributes.get("DW_AT_stmt_list")
        if attribute is None:
            continue
        offset = attribute.value
        end = _line_unit_end(line_data, offset, "little" if elf.little_endian else "big")
        dwarf.debug_line_sec = line_descriptor._replace(stream=_UnitStream(line_data, offset, end))
        try:
            program = dwarf.line_program_for_CU(cu)
        finally:
            dwarf.debug_line_sec = line_descriptor
        if program.program_end_offset != end or program.program_start_offset > end:
            raise InspectionError("FORMAT_INVALID", "DWARF line program boundary differs")
        header = program.header
        if (
            header["version"] not in (2, 3, 4, 5)
            or header.get("maximum_operations_per_instruction", 1) != 1
            or (header.get("segment_selector_size") or 0) != 0
            or (header.get("address_size") or cu["address_size"]) != cu["address_size"]
        ):
            raise InspectionError(
                "FORMAT_UNSUPPORTED", "DWARF line version/VLIW/segments unsupported"
            )
        if header["line_range"] == 0 or header["minimum_instruction_length"] == 0:
            raise InspectionError("FORMAT_INVALID", "DWARF line header has zero step/range")
        for field in ("directory_entry_format", "file_name_entry_format"):
            if any(
                row.form
                not in (
                    "DW_FORM_string",
                    "DW_FORM_strp",
                    "DW_FORM_line_strp",
                    "DW_FORM_data1",
                    "DW_FORM_data2",
                    "DW_FORM_data4",
                    "DW_FORM_data8",
                    "DW_FORM_udata",
                    "DW_FORM_data16",
                )
                for row in header.get(field, ()) or ()
            ):
                raise InspectionError(
                    "FORMAT_UNSUPPORTED", "external/indexed DWARF paths unsupported"
                )
        counts["line_programs_scanned"] += 1
        known_files = len(header["file_entry"])
        entries = program.get_entries()
        counts["line_entries_scanned"] += len(entries)
        if counts["line_entries_scanned"] > MAX_LINE_ENTRIES:
            raise InspectionError("LIMIT_EXCEEDED", "DWARF has too many decoded line entries")
        compilation_directory = top.attributes.get("DW_AT_comp_dir")
        compilation_directory = compilation_directory.value if compilation_directory else None
        previous = None
        for index, entry in enumerate(entries):
            if entry.is_extended and entry.command == 3:  # DW_LNE_define_file
                known_files += 1
            state = entry.state
            if state is None:
                continue
            address_limit = (1 << elf.elfclass) - (0 if state.end_sequence else 1)
            if not 0 <= state.address <= address_limit:
                raise InspectionError(
                    "FORMAT_INVALID", "DWARF line address exceeds ELF address width"
                )
            if not state.end_sequence and (
                state.line < 0
                or not 0 <= state.file - (1 if header["version"] < 5 else 0) < known_files
            ):
                raise InspectionError("FORMAT_INVALID", "DWARF line/file register is invalid")
            if previous is not None:
                old_index, old = previous
                if state.address < old.address:
                    raise InspectionError(
                        "FORMAT_INVALID", "DWARF line addresses decrease within a sequence"
                    )
                if old.address < state.address and old.line > 0:
                    for query in queries:
                        if old.address <= query["lookup_address"] < state.address:
                            match_count += 1
                            if match_count > MAX_LINE_MATCHES:
                                raise InspectionError(
                                    "LIMIT_EXCEEDED", "address queries exceed 128 line matches"
                                )
                            query["lines"].append(
                                {
                                    **_location(program, old, compilation_directory),
                                    "cu_offset": cu.cu_offset,
                                    "line_program_offset": offset,
                                    "entry_index": old_index,
                                    "dwarf_version": header["version"],
                                    "range_start": old.address,
                                    "range_end_exclusive": state.address,
                                }
                            )
            previous = None if state.end_sequence else (index, state)
        if previous is not None:
            raise InspectionError("FORMAT_INVALID", "DWARF line sequence lacks end_sequence")
    for query in queries:
        query["line_status"] = _status(
            query["lines"],
            (
                "file_name",
                "directory",
                "compilation_directory",
                "line",
                "column",
                "discriminator",
            ),
        )
    return {"status": "scanned", **counts}


def lookup(
    path: Path,
    addresses: list[int] | tuple[int, ...],
    *,
    address_mode: str = "raw",
    lines: bool = True,
) -> dict[str, Any]:
    """Resolve declared code ranges and in-file DWARF lines without runtime guesses."""
    if (
        not isinstance(addresses, (list, tuple))
        or not 1 <= len(addresses) <= MAX_ADDRESSES
        or any(type(value) is not int or not 0 <= value < 1 << 64 for value in addresses)
        or len(set(addresses)) != len(addresses)
        or address_mode not in ("raw", "arm-thumb")
        or type(lines) is not bool
    ):
        raise InspectionError(
            "OPTIONS_INVALID", "supply 1..32 distinct unsigned addresses and a valid mode"
        )
    resolved, data = _snapshot(path)
    if not data.startswith(b"\x7fELF"):
        raise InspectionError("FORMAT_UNSUPPORTED", "address lookup requires an ELF file")
    try:
        layout = _elf(data, 0)
        elf = ELFFile(io.BytesIO(data))
        thumb = address_mode == "arm-thumb"
        if thumb and (elf.header["e_machine"] != "EM_ARM" or elf.elfclass != 32):
            raise InspectionError(
                "OPTIONS_INVALID", "arm-thumb mode requires an ELF32 EM_ARM image"
            )
        if any(value >= 1 << elf.elfclass for value in addresses):
            raise InspectionError("OPTIONS_INVALID", "query address exceeds ELF address width")
        queries = [
            {
                "address": value,
                "lookup_address": value & ~1 if thumb else value,
                "function_status": "not_found",
                "functions": [],
                "line_status": "not_found",
                "lines": [],
            }
            for value in addresses
        ]
        counts = _functions(elf, layout["sections"], queries)
        debug = _lines(elf, queries, lines)
    except InspectionError:
        raise
    except Exception as error:
        raise InspectionError("FORMAT_INVALID", f"invalid ELF/DWARF: {error}") from error
    report = _base_report("addresses", ADDRESSES_SCHEMA)
    report.update(
        {
            "source": {"path": str(resolved), "size_bytes": len(data), "sha256": sha256(data)},
            "format": "elf",
            "architecture": layout["architecture"],
            "address_unit": "byte",
            "range_convention": "half_open",
            "address_mode": address_mode,
            "complete": True,
            "address_queries": queries,
            "debug_lines": debug,
            **counts,
            "warnings": [
                "Offline address matches do not prove running firmware or a call stack",
                "No return-address subtraction, relocation, nearest-symbol inference "
                "or inline-stack reconstruction is performed",
                "Source paths are DWARF metadata; source files and external debug files "
                "are not opened",
                "Function and source-line matches are independent declarations; "
                "optimized or discarded code may leave stale DWARF locations",
            ],
        }
    )
    return report
