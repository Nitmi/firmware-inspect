from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .addresses import lookup as lookup_addresses
from .core import InspectionError, compare, inspect
from .symbols import lookup


def _address(value: str) -> int:
    try:
        address = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected decimal or 0x-prefixed address") from error
    if not 0 <= address < 1 << 64:
        raise argparse.ArgumentTypeError("address must fit unsigned 64 bits")
    return address


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="firmware-inspect", description="Analyze firmware offline.")
    root.add_argument("--version", action="version", version=f"firmware-inspect {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    single = commands.add_parser("inspect", help="inspect ELF, Intel HEX, or explicitly based BIN")
    single.add_argument("firmware", type=Path)
    diff = commands.add_parser("diff", help="compare two firmware builds without hardware access")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    for command in (single, diff):
        command.add_argument("--format", choices=("auto", "elf", "hex", "bin"), default="auto")
        command.add_argument("--base-address", type=_address)
        command.add_argument("--json", action="store_true")
    single.add_argument("--symbol-limit", type=int, default=20, help="largest symbols, 0..200")
    symbols = commands.add_parser(
        "symbols", help="query exact ELF symbol names, preserving ambiguity"
    )
    symbols.add_argument("firmware", type=Path)
    symbols.add_argument(
        "--name", action="append", required=True, help="exact name; repeat up to 32 times"
    )
    symbols.add_argument("--json", action="store_true")
    addresses = commands.add_parser(
        "addresses", help="locate code addresses in ELF functions/DWARF lines"
    )
    addresses.add_argument("firmware", type=Path)
    addresses.add_argument(
        "--address",
        type=_address,
        action="append",
        required=True,
        help="linker virtual code address; repeat up to 32 times",
    )
    addresses.add_argument(
        "--address-mode",
        choices=("raw", "arm-thumb"),
        default="raw",
        help="raw values, or explicit ARM32 Thumb-bit normalization",
    )
    addresses.add_argument("--no-lines", action="store_true", help="query function symbols only")
    addresses.add_argument("--json", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "addresses":
            report = lookup_addresses(
                args.firmware, args.address, address_mode=args.address_mode, lines=not args.no_lines
            )
        elif args.command == "symbols":
            report = lookup(args.firmware, args.name)
        else:
            options = {"format": args.format, "base_address": args.base_address}
            if args.command == "inspect":
                report = inspect(args.firmware, symbol_limit=args.symbol_limit, **options)
            else:
                report = compare(inspect(args.before, **options), inspect(args.after, **options))
    except InspectionError as error:
        report = {
            "schema_version": "embedded-firmware-inspect.error.v1",
            "ok": False,
            "operation": args.command,
            "scope": "host_only_firmware_analysis",
            "hardware_access": False,
            "executables_started": False,
            "flash_authorized": False,
            "error": {"code": error.code, "message": str(error), "retryable": False},
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif not report["ok"]:
        print(f"{report['error']['code']}: {report['error']['message']}", file=sys.stderr)
    elif args.command == "addresses":
        print(f"ELF: {json.dumps(report['source']['path'])}")
        print(f"SHA-256: {report['source']['sha256']}")
        for query in report["address_queries"]:
            print(
                f"  0x{query['address']:X} -> 0x{query['lookup_address']:X}: "
                f"functions={query['function_status']}, lines={query['line_status']}"
            )
            for function in query["functions"]:
                print(
                    f"    {json.dumps(function['name'])}+0x{function['offset_bytes']:X} "
                    f"({function['match_kind']})"
                )
            for location in query["lines"]:
                print(
                    f"    {json.dumps(location['file_name'])}:"
                    f"{location['line']}:{location['column']}"
                )
        for warning in report["warnings"]:
            print(f"Warning: {warning}", file=sys.stderr)
    elif args.command == "symbols":
        print(f"ELF: {json.dumps(report['source']['path'])}")
        print(f"SHA-256: {report['source']['sha256']}")
        for query in report["queries"]:
            value = f"; st_value=0x{query['value']:X}" if query["value"] is not None else ""
            print(f"  {json.dumps(query['name'])}: {query['status']}{value}")
        for warning in report["warnings"]:
            print(f"Warning: {warning}", file=sys.stderr)
    elif args.command == "inspect":
        print(f"{report['format'].upper()}: {report['source']['path']}")
        print(f"SHA-256: {report['source']['sha256']}")
        print(f"Source bytes: {report['source']['size_bytes']}")
        print(f"File-backed address bytes: {report['summary']['program_address_bytes']}")
        for region in report["programmed_ranges"]:
            print(f"  0x{region['start']:X}..0x{region['end_exclusive']:X} (exclusive)")
        if report["summary"]["section_usage"]:
            print(
                f"Section usage: {json.dumps(report['summary']['section_usage'], sort_keys=True)}"
            )
        for warning in report["warnings"]:
            print(f"Warning: {warning}", file=sys.stderr)
    else:
        print(f"Identical: {report['identical']}; layout changed: {report['layout_changed']}")
        print(f"Source delta: {report['file_size_delta_bytes']:+d} bytes")
        print(f"Address bytes delta: {report['program_address_delta_bytes']:+d}")
        for change in report["load_segment_changes"]:
            print(f"  Load 0x{change['load_address']:X}: {change['change']}")
        for change in report["section_changes"]:
            print(f"  {change['name']}: {change['change']}, {change['size_delta_bytes']:+d} bytes")
    return 0 if report["ok"] else 1
