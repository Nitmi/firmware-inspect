#!/usr/bin/env python3
"""Exercise a standalone executable using only generated offline fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path

from intelhex import IntelHex, Record
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from firmware_inspect import __version__

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from fixtures import elf_image  # noqa: E402


class SmokeError(ValueError):
    pass


def run(executable: Path, arguments: list[str], cwd: Path, expected_exit: int = 0) -> str:
    result = subprocess.run(
        [str(executable), *arguments],
        cwd=cwd,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    if result.returncode != expected_exit or result.stderr:
        raise SmokeError(
            f"standalone command failed: {arguments}; exit={result.returncode}; "
            f"stderr={result.stderr}"
        )
    return result.stdout


def smoke(executable: Path, work_dir: Path) -> dict:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if version != __version__:
        raise SmokeError("project and runtime versions differ")
    if executable.is_symlink() or not executable.is_file():
        raise SmokeError("executable must be an exact regular file")
    executable = executable.resolve()
    work_dir.mkdir(parents=True, exist_ok=False)
    if run(executable, ["--version"], work_dir).strip() != f"firmware-inspect {__version__}":
        raise SmokeError("standalone version differs")
    files = {
        "before.elf": elf_image(),
        "after.elf": elf_image(bss_size=16),
        "app.bin": b"abcd",
        "bad.hex": b":00000001FF\n:040000006162636472\n",
        "overflow.hex": (
            "\n".join(
                [
                    Record.extended_linear_address(0xFFFF),
                    Record.data(0xFFFF, [0x31, 0x32]),
                    Record.eof(),
                    "",
                ]
            )
        ).encode("ascii"),
    }
    for name, data in files.items():
        (work_dir / name).write_bytes(data)
    image = IntelHex()
    image.puts(0, b"abcd")
    image.puts(0x10001000, b"UICR")
    image.write_hex_file(str(work_dir / "sparse.hex"))
    files["sparse.hex"] = (work_dir / "sparse.hex").read_bytes()
    schema = json.loads((ROOT / "src/firmware_inspect/report.schema.json").read_text())
    validator = Draft202012Validator(schema)

    def report(arguments: list[str], expected_exit: int = 0) -> dict:
        value = json.loads(run(executable, [*arguments, "--json"], work_dir, expected_exit))
        validator.validate(value)
        if any(
            value[key] is not False
            for key in (
                "hardware_access",
                "executables_started",
                "flash_authorized",
            )
        ):
            raise SmokeError("standalone report changed analysis scope")
        return value

    elf = report(["inspect", "before.elf"])
    binary = report(["inspect", "app.bin", "--base-address", "0x10000"])
    hexadecimal = report(["inspect", "sparse.hex"])
    delta = report(["diff", "before.elf", "after.elf"])
    missing_base = report(["inspect", "app.bin"], 1)
    invalid_hex = report(["inspect", "bad.hex"], 1)
    overflow_hex = report(["inspect", "overflow.hex"], 1)
    if (
        elf["build_ids"] != ["01020304"]
        or elf["summary"]["section_usage"]["zero_fill_bytes_sum"] != 8
        or binary["programmed_ranges"][0]["start"] != 0x10000
        or hexadecimal["summary"]["program_address_bytes"] != 8
        or [item["start"] for item in hexadecimal["programmed_ranges"]] != [0, 0x10001000]
        or delta["section_usage_delta"]["zero_fill_bytes_sum"] != 8
        or delta["layout_changed"] is not True
        or missing_base["error"]["code"] != "OPTIONS_INVALID"
        or invalid_hex["error"]["code"] != "FORMAT_INVALID"
        or overflow_hex["error"]["code"] != "FORMAT_INVALID"
    ):
        raise SmokeError("standalone semantic checks differ")
    if any((work_dir / name).read_bytes() != data for name, data in files.items()):
        raise SmokeError("standalone changed an input fixture")
    return {
        "schema_version": "embedded-firmware-inspect.binary-smoke.v1",
        "ok": True,
        "version": __version__,
        "checks_passed": 8,
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "hardware_access": False,
        "work_directory": str(work_dir.resolve()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = smoke(args.executable, args.work_dir)
    except (OSError, ValueError, ValidationError, subprocess.SubprocessError) as error:
        result = {"ok": False, "error": str(error), "hardware_access": False}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
