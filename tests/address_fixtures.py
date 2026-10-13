"""Small, generated DWARF units; no compiler or fixture executable is run."""

from __future__ import annotations

import struct

from fixtures import elf_image


def leb(value: int, *, signed: bool = False) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (
            (value == 0 and not byte & 0x40 or value == -1 and byte & 0x40)
            if signed
            else value == 0
        )
        result.append(byte if done else byte | 0x80)
        if done:
            return bytes(result)


def line_program(
    rows=((0, 10), (4, 20), (8, None)), *, version=4, bits=32, endian="<", path_form=8
):
    file_index = 0 if version == 5 else 1
    header = bytes([1]) + (bytes([1]) if version >= 4 else b"")
    header += bytes([1, 251, 14, 13]) + bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    if version == 5:
        directory = b"src\0" if path_form == 8 else struct.pack(endian + "I", 0)
        file_name = b"app.c\0" if path_form == 8 else struct.pack(endian + "I", 4)
        header += b"\x01\x01" + leb(path_form) + b"\x01" + directory
        header += b"\x02\x01" + leb(path_form) + b"\x02\x0f\x01" + file_name + b"\x00"
    else:
        header += b"src\0\0app.c\0\x01\x00\x00\0"
    program = b"\x04" + leb(file_index)
    line = 1
    for address, new_line in rows:
        # Explicit set_address also permits malformed descending-sequence tests.
        program += b"\0" + leb(1 + bits // 8) + b"\x02"
        program += struct.pack(endian + ("Q" if bits == 64 else "I"), address)
        if new_line is None:
            program += b"\0\x01\x01"
            line = 1
        else:
            program += b"\x03" + leb(new_line - line, signed=True) + b"\x01"
            line = new_line
    prefix = struct.pack(endian + "H", version)
    if version == 5:
        prefix += bytes([bits // 8, 0])
    body = prefix + struct.pack(endian + "I", len(header)) + header + program
    return struct.pack(endian + "I", len(body)) + body


def dwarf_sections(*, programs=None, version=4, bits=32, endian="<"):
    programs = (
        programs
        if programs is not None
        else [(line_program(version=version, bits=bits, endian=endian), b"/build")]
    )
    form = 0x17 if version >= 4 else 6
    abbrev = b"\x01\x11\x00\x10" + bytes([form]) + b"\x1b\x08\0\0\0"
    info, lines = b"", b""
    for program, directory in programs:
        header = struct.pack(endian + "H", version)
        header += (
            bytes([1, bits // 8]) + struct.pack(endian + "I", 0)
            if version == 5
            else struct.pack(endian + "I", 0) + bytes([bits // 8])
        )
        body = header + b"\x01" + struct.pack(endian + "I", len(lines)) + directory + b"\0"
        info += struct.pack(endian + "I", len(body)) + body
        lines += program
    return {".debug_info": info, ".debug_abbrev": abbrev, ".debug_line": lines}


def address_elf(*, version=4, bits=32, endian="<", programs=None, **options):
    return elf_image(
        bits=bits,
        endian=endian,
        text=b"\x00" * 16,
        debug_sections=dwarf_sections(programs=programs, version=version, bits=bits, endian=endian),
        **options,
    )
