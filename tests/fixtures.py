from __future__ import annotations

import struct


def elf_image(
    *,
    bits: int = 32,
    endian: str = "<",
    bss_size: int = 8,
    text: bytes = b"\x00\xbf\x00\xbf",
    elf_type: int = 2,
    note_program: bool = False,
    symbol_entries: list[tuple[str, int, int, int, int]] | None = None,
    duplicate_symbol_table: bool = False,
) -> bytes:
    """Small executable fixture with distinct .data load and runtime addresses."""
    wide = bits == 64
    header_size, program_size, section_size = (64, 56, 64) if wide else (52, 32, 40)
    names = [
        "",
        ".text",
        ".data",
        ".bss",
        ".note.gnu.build-id",
        ".symtab",
        ".strtab",
        ".shstrtab",
        ".debug_info",
    ]
    if duplicate_symbol_table:
        names.append(".dynsym")
    name_table = b"\0"
    name_offsets = {"": 0}
    for name in names[1:]:
        name_offsets[name] = len(name_table)
        name_table += name.encode() + b"\0"
    strings = b"\0"
    symbol_format = endian + ("IBBHQQ" if wide else "IIIBBH")

    def symbol(name: int, address: int, size: int, info: int, section: int) -> bytes:
        values = (
            (name, info, 0, section, address, size)
            if wide
            else (name, address, size, info, 0, section)
        )
        return struct.pack(symbol_format, *values)

    entries = (
        symbol_entries
        if symbol_entries is not None
        else [
            ("main", 0, len(text), 0x12, 1),
            ("counter", 0x20000000, 4, 0x11, 2),
            ("undefined", 0, 0, 0x12, 0),
        ]
    )
    symbols = symbol(0, 0, 0, 0, 0)
    for name, address, size, info, section in entries:
        symbols += symbol(len(strings), address, size, info, section)
        strings += name.encode("utf-8") + b"\0"
    note = struct.pack(endian + "III", 4, 4, 3) + b"GNU\0" + b"\x01\x02\x03\x04"
    payloads = [
        b"",
        text,
        b"\x12\x34\x56\x78",
        b"",
        note,
        symbols,
        strings,
        name_table,
        b"debug-info",
    ]
    if duplicate_symbol_table:
        payloads.append(symbols)
    program_count = 3 if note_program else 2
    body = bytearray(b"\0" * (header_size + program_count * program_size))
    offsets = []
    for payload in payloads:
        body.extend(b"\0" * (-len(body) % 4))
        offsets.append(len(body))
        body.extend(payload)
    body.extend(b"\0" * (-len(body) % 8))
    section_offset = len(body)
    for index in range(len(names)):
        kind = (
            11
            if index == 9
            else 8
            if index == 3
            else 7
            if index == 4
            else 2
            if index == 5
            else (3 if index in {6, 7} else 0 if index == 0 else 1)
        )
        flags = 6 if index == 1 else 3 if index in {2, 3} else 0
        address = 0x20000000 if index == 2 else 0x20000004 if index == 3 else 0
        size = bss_size if index == 3 else len(payloads[index])
        link, info = (6, 1) if index in {5, 9} else (0, 0)
        entry_size = struct.calcsize(symbol_format) if index in {5, 9} else 0
        fields = (
            name_offsets[names[index]],
            kind,
            flags,
            address,
            offsets[index],
            size,
            link,
            info,
            4 if index else 0,
            entry_size,
        )
        body.extend(struct.pack(endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), *fields))
    identity = b"\x7fELF" + bytes((2 if wide else 1, 1 if endian == "<" else 2, 1, 0, 0))
    identity += b"\0" * 7
    fields = (
        elf_type,
        183 if wide else 40,
        1,
        0,
        header_size,
        section_offset,
        0,
        header_size,
        program_size,
        program_count,
        section_size,
        len(names),
        7,
    )
    header = identity + struct.pack(
        endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), *fields
    )
    body[:header_size] = header
    for index, (section, physical, virtual, memory) in enumerate(
        (
            (1, 0, 0, len(text)),
            (2, 0x1000, 0x20000000, 4 + bss_size),
        )
    ):
        values = (
            (
                1,
                5 if index == 0 else 6,
                offsets[section],
                virtual,
                physical,
                len(payloads[section]),
                memory,
                4,
            )
            if wide
            else (
                1,
                offsets[section],
                virtual,
                physical,
                len(payloads[section]),
                memory,
                5 if index == 0 else 6,
                4,
            )
        )
        program = struct.pack(endian + ("IIQQQQQQ" if wide else "IIIIIIII"), *values)
        start = header_size + index * program_size
        body[start : start + program_size] = program
    if note_program:
        values = (
            (4, 0, offsets[4], 0, 0, len(note), len(note), 4)
            if wide
            else (4, offsets[4], 0, 0, len(note), len(note), 0, 4)
        )
        start = header_size + 2 * program_size
        body[start : start + program_size] = struct.pack(
            endian + ("IIQQQQQQ" if wide else "IIIIIIII"), *values
        )
    return bytes(body)
