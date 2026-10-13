from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .core import MAX_SYMBOLS, InspectionError, _base_report, _elf, _snapshot, sha256

SYMBOLS_SCHEMA = "embedded-firmware-inspect.symbols.v1"
MAX_QUERY_NAMES = 32
MAX_MATCHES = 256


def lookup(path: Path, names: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """Query exact names from the same bounded ELF snapshot that is hashed."""
    if not isinstance(names, (list, tuple)) or not 1 <= len(names) <= MAX_QUERY_NAMES:
        raise InspectionError("OPTIONS_INVALID", "supply between 1 and 32 exact symbol names")
    if any(not isinstance(name, str) or not 1 <= len(name) <= 1024 for name in names):
        raise InspectionError("OPTIONS_INVALID", "symbol names must contain 1..1024 characters")
    if any(not name.isprintable() for name in names) or len(set(names)) != len(names):
        raise InspectionError("OPTIONS_INVALID", "symbol names must be printable and distinct")
    resolved, data = _snapshot(path)
    if not data.startswith(b"\x7fELF"):
        raise InspectionError("FORMAT_UNSUPPORTED", "symbol lookup requires an ELF file")
    try:
        layout = _elf(data, 0)
        elf = ELFFile(io.BytesIO(data))
        matches: dict[str, list[dict[str, Any]]] = {name: [] for name in names}
        table_entries = match_count = table_count = 0
        for table_index, table in enumerate(elf.iter_sections()):
            if not isinstance(table, SymbolTableSection):
                continue
            if table["sh_entsize"] != elf.structs.Elf_Sym.sizeof() or (
                table["sh_size"] % table["sh_entsize"]
            ):
                raise InspectionError("FORMAT_INVALID", "ELF symbol table has invalid entry sizes")
            table_count += 1
            table_entries += table.num_symbols()
            if table_entries > MAX_SYMBOLS:
                raise InspectionError("LIMIT_EXCEEDED", "ELF has too many symbol entries")
            for symbol_index, symbol in enumerate(table.iter_symbols()):
                name = symbol.name
                if len(name) > 1024:
                    raise InspectionError("LIMIT_EXCEEDED", "ELF symbol name exceeds limit")
                if name not in matches:
                    continue
                match_count += 1
                if match_count > MAX_MATCHES:
                    raise InspectionError(
                        "LIMIT_EXCEEDED", "exact symbol matches exceed 256 entries"
                    )
                index = symbol["st_shndx"]
                section = None
                if isinstance(index, int):
                    if index == 0:
                        definition = "undefined"
                    elif index >= SHN_INDICES.SHN_LORESERVE:
                        definition = "reserved"
                    elif not 0 < index < len(layout["sections"]):
                        raise InspectionError(
                            "FORMAT_INVALID", "ELF symbol has invalid section index"
                        )
                    else:
                        definition = "section"
                        section = layout["sections"][index]
                else:
                    definition = {
                        "SHN_UNDEF": "undefined",
                        "SHN_ABS": "absolute",
                        "SHN_COMMON": "common",
                    }.get(index, "reserved")
                matches[name].append(
                    {
                        "table_index": table_index,
                        "table_name": table.name,
                        "symbol_index": symbol_index,
                        "type": symbol["st_info"]["type"],
                        "binding": symbol["st_info"]["bind"],
                        "visibility": symbol["st_other"]["visibility"],
                        "value": symbol["st_value"],
                        "size_bytes": symbol["st_size"],
                        "definition": definition,
                        "section_index": index,
                        "section": section,
                        "value_kind": "tls_offset"
                        if symbol["st_info"]["type"] == "STT_TLS"
                        else {
                            "section": "linker_virtual_value",
                            "absolute": "absolute_value",
                            "common": "common_alignment",
                            "undefined": "undefined_value",
                            "reserved": "special_value",
                        }[definition],
                    }
                )
        queries = []
        for name, entries in matches.items():
            definitions = {
                (
                    row["definition"],
                    row["section_index"],
                    row["value"],
                    row["size_bytes"],
                    row["type"],
                    row["binding"],
                    row["visibility"],
                )
                for row in entries
                if row["definition"] in {"section", "absolute"}
            }
            status = (
                "unique"
                if len(definitions) == 1
                else "ambiguous"
                if definitions
                else "not_found"
                if not entries
                else "undefined_only"
                if all(row["definition"] == "undefined" for row in entries)
                else "no_definition"
            )
            queries.append(
                {
                    "name": name,
                    "status": status,
                    "matched_entries": len(entries),
                    "definition_count": len(definitions),
                    "value": next(iter(definitions))[2] if status == "unique" else None,
                    "matches": entries,
                }
            )
    except InspectionError:
        raise
    except Exception as error:
        raise InspectionError("FORMAT_INVALID", f"invalid ELF: {error}") from error
    report = _base_report("symbols", SYMBOLS_SCHEMA)
    report.update(
        {
            "source": {"path": str(resolved), "size_bytes": len(data), "sha256": sha256(data)},
            "format": "elf",
            "architecture": layout["architecture"],
            "value_semantics": "elf_st_value",
            "complete": True,
            "symbol_tables_scanned": table_count,
            "symbol_entries_scanned": table_entries,
            "queries": queries,
            "warnings": [
                "ELF symbol values do not prove runtime addresses or running firmware identity"
            ],
        }
    )
    return report
