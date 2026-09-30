#!/usr/bin/env python3
"""Build and verify a reproducible standalone Windows firmware-inspect archive."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

COMMAND = "firmware-inspect"
PROJECT = "embedded-firmware-inspect"
TARGET = "windows-x86_64"
SCHEMA = "embedded-firmware-inspect.binary-release.v1"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 48 * 1024 * 1024
MAX_MANIFEST = 16 * 1024
MAX_CHECKSUM = 256
MAX_LICENSE = 512 * 1024
LICENSE_FILES = ("LICENSE", "THIRD-PARTY-NOTICES.txt")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
REVISION = re.compile(r"[0-9a-f]{40}")
HASH = re.compile(r"[0-9a-f]{64}")
BUILD_PYTHON = "3.13.13"
BUILD_PYINSTALLER = "6.22.2"
BUILD_PATH_POLICY = "python-root-system32-only"


class ReleaseError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def project_version(root: Path) -> str:
    document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = document.get("project", {}).get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ReleaseError("project version must be stable major.minor.patch")
    return version


def builder_identity() -> dict[str, str]:
    python_version = platform.python_version()
    try:
        pyinstaller_version = importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError as error:
        raise ReleaseError("PyInstaller is not installed in the build environment") from error
    if python_version != BUILD_PYTHON or pyinstaller_version != BUILD_PYINSTALLER:
        raise ReleaseError(
            "release builder must use "
            f"CPython {BUILD_PYTHON} and PyInstaller {BUILD_PYINSTALLER}; "
            f"got CPython {python_version} and PyInstaller {pyinstaller_version}"
        )
    return {
        "python": python_version,
        "pyinstaller": pyinstaller_version,
        "dependency_path": BUILD_PATH_POLICY,
    }


def build_environment() -> dict[str, str]:
    system_root_value = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    if not system_root_value:
        raise ReleaseError("Windows system root is unavailable")
    python_root = Path(sys.base_prefix).resolve()
    system_root = Path(system_root_value).resolve()
    environment = dict(os.environ)
    environment.update(
        {
            "PATH": os.pathsep.join(
                (str(python_root), str(python_root / "Scripts"), str(system_root / "System32"))
            ),
            "PYTHONHASHSEED": "1",
            "SOURCE_DATE_EPOCH": "315532800",
        }
    )
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    return environment


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if result.returncode:
        raise ReleaseError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def clean_revision(root: Path) -> str:
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ReleaseError("commit source changes before building")
    revision = git(root, "rev-parse", "HEAD")
    if not REVISION.fullmatch(revision):
        raise ReleaseError("invalid source revision")
    return revision


def check_tag(root: Path, tag: str) -> dict[str, str]:
    version = project_version(root)
    if tag != f"v{version}":
        raise ReleaseError(f"release tag must be exactly v{version}")
    revision = clean_revision(root)
    tagged = git(root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if tagged != revision:
        raise ReleaseError("release tag does not resolve to the checked-out commit")
    return {"version": version, "tag": tag, "source_revision": revision}


def notice_text(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(MAX_LICENSE + 1)
    if not 0 < len(data) <= MAX_LICENSE:
        raise ReleaseError("license material is empty or oversized")
    return data.decode("utf-8").replace("\r\n", "\n").rstrip() + "\n"


def license_materials(root: Path) -> dict[str, bytes]:
    notices = [
        "Third-party notices for the standalone Windows firmware-inspect release.\n"
        "Upstream libraries and CPython are embedded without source modifications.\n"
        "Only the combined executable is distributed; build tools are not shipped.\n"
    ]
    sources = [
        (
            f"CPython {BUILD_PYTHON} (Windows runtime)",
            Path(sys.base_prefix) / "LICENSE.txt",
        ),
        (
            "Construct vendored by pyelftools 0.33",
            root / "docs" / "licenses" / "pyelftools-construct.txt",
        ),
    ]
    for name, version, relative in (
        ("pyelftools", "0.33", "pyelftools-0.33.dist-info/licenses/LICENSE"),
        ("intelhex", "2.3.0", "intelhex-2.3.0.dist-info/LICENSE.txt"),
        (
            "pyinstaller",
            BUILD_PYINSTALLER,
            f"pyinstaller-{BUILD_PYINSTALLER}.dist-info/licenses/COPYING.txt",
        ),
        (
            "pyinstaller-hooks-contrib",
            "2026.7",
            "pyinstaller_hooks_contrib-2026.7.dist-info/licenses/LICENSE",
        ),
    ):
        distribution = importlib.metadata.distribution(name)
        if distribution.version != version:
            raise ReleaseError(f"license source version differs: {name}")
        sources.append((f"{name} {version}", Path(distribution.locate_file(relative))))
    for label, path in sources:
        notices.append(f"\n{'=' * 72}\n{label}\n{'=' * 72}\n\n{notice_text(path)}")
    return {
        "LICENSE": notice_text(root / "LICENSE").encode("utf-8"),
        "THIRD-PARTY-NOTICES.txt": "".join(notices).encode("utf-8"),
    }


def archive_bytes(
    version: str,
    revision: str,
    executable: bytes,
    builder: dict[str, str] | None = None,
    *,
    licenses: dict[str, bytes],
) -> bytes:
    if not VERSION.fullmatch(version) or not REVISION.fullmatch(revision):
        raise ReleaseError("invalid release identity")
    if not executable or len(executable) > MAX_BINARY:
        raise ReleaseError("standalone executable is empty or oversized")
    if set(licenses) != set(LICENSE_FILES) or any(
        not isinstance(data, bytes) or not 0 < len(data) <= MAX_LICENSE
        for data in licenses.values()
    ):
        raise ReleaseError("license materials differ or are empty/oversized")
    prefix = f"{PROJECT}-{version}-{TARGET}"
    builder = builder or {
        "python": BUILD_PYTHON,
        "pyinstaller": BUILD_PYINSTALLER,
        "dependency_path": BUILD_PATH_POLICY,
    }
    if builder != {
        "python": BUILD_PYTHON,
        "pyinstaller": BUILD_PYINSTALLER,
        "dependency_path": BUILD_PATH_POLICY,
    }:
        raise ReleaseError("release builder identity differs")
    manifest = json_bytes(
        {
            "schema_version": SCHEMA,
            "name": PROJECT,
            "command": COMMAND,
            "version": version,
            "target": TARGET,
            "source_revision": revision,
            "builder": builder,
            "executable": f"{COMMAND}.exe",
            "executable_sha256": digest(executable),
            "executable_size": len(executable),
            "scope": "host_only_firmware_analysis",
            "licenses": {
                name: {"sha256": digest(licenses[name]), "size": len(licenses[name])}
                for name in LICENSE_FILES
            },
        }
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data, mode in (
            (f"{prefix}/{COMMAND}.exe", executable, 0o755),
            (f"{prefix}/release-manifest.json", manifest, 0o644),
            *((f"{prefix}/{name}", licenses[name], 0o644) for name in LICENSE_FILES),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, data)
    data = output.getvalue()
    if len(data) > MAX_ARCHIVE:
        raise ReleaseError("standalone archive is oversized")
    return data


def build(root: Path, output_dir: Path, work_dir: Path) -> dict[str, object]:
    if platform.system() != "Windows" or platform.machine().upper() not in {"AMD64", "X86_64"}:
        raise ReleaseError("standalone release build requires Windows x86_64")
    builder = builder_identity()
    revision = clean_revision(root)
    version = project_version(root)
    licenses = license_materials(root)
    if output_dir.exists() or work_dir.exists():
        raise ReleaseError("build output or work directory already exists")
    output_dir.mkdir(parents=True)
    work_dir.mkdir(parents=True)
    environment = build_environment()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--clean",
            "--noconfirm",
            "--name",
            COMMAND,
            "--collect-data",
            "firmware_inspect",
            "--paths",
            str(root / "src"),
            "--distpath",
            str(work_dir / "dist"),
            "--workpath",
            str(work_dir / "build"),
            "--specpath",
            str(work_dir),
            str(root / "src" / "firmware_inspect" / "__main__.py"),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    if result.returncode:
        raise ReleaseError(result.stderr.strip() or "PyInstaller failed")
    executable_path = work_dir / "dist" / f"{COMMAND}.exe"
    if executable_path.is_symlink() or not executable_path.is_file():
        raise ReleaseError(f"PyInstaller did not create {COMMAND}.exe")
    executable = executable_path.read_bytes()
    payload = archive_bytes(version, revision, executable, builder, licenses=licenses)
    archive = output_dir / f"{PROJECT}-{version}-{TARGET}.zip"
    checksum = archive.with_suffix(".zip.sha256")
    archive.write_bytes(payload)
    checksum.write_text(f"{digest(payload)}  {archive.name}\n", encoding="ascii")
    return {
        "archive": str(archive.resolve()),
        "checksum": str(checksum.resolve()),
        "sha256": digest(payload),
        "executable_sha256": digest(executable),
        "version": version,
        "target": TARGET,
        "source_revision": revision,
        "builder": builder,
        "hardware_access": False,
    }


def verify(archive_path: Path, checksum_path: Path) -> dict[str, object]:
    for label, path in (("archive", archive_path), ("checksum", checksum_path)):
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"{label} is not a regular file")
    if checksum_path.stat().st_size > MAX_CHECKSUM:
        raise ReleaseError("checksum is oversized")
    with archive_path.open("rb") as stream:
        data = stream.read(MAX_ARCHIVE + 1)
    if not data or len(data) > MAX_ARCHIVE:
        raise ReleaseError("archive is empty or oversized")
    checksum = checksum_path.read_text(encoding="ascii")
    match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\r\n]+)\r?\n?", checksum)
    if not match or match[2] != archive_path.name or match[1] != digest(data):
        raise ReleaseError("archive checksum differs")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) != 4 or len({entry.filename.casefold() for entry in entries}) != 4:
                raise ReleaseError("archive inventory differs")
            manifests = [
                entry for entry in entries if entry.filename.endswith("/release-manifest.json")
            ]
            binaries = [entry for entry in entries if entry.filename.endswith(f"/{COMMAND}.exe")]
            if len(manifests) != 1 or len(binaries) != 1:
                raise ReleaseError("archive payload differs")
            for entry in entries:
                mode = entry.external_attr >> 16
                if (
                    entry.is_dir()
                    or stat.S_IFMT(mode) != stat.S_IFREG
                    or entry.compress_type != zipfile.ZIP_STORED
                ):
                    raise ReleaseError("archive member is not a regular file")
            if manifests[0].file_size > MAX_MANIFEST:
                raise ReleaseError("release manifest is oversized")
            if not 0 < binaries[0].file_size <= MAX_BINARY:
                raise ReleaseError("standalone executable size is invalid")
            license_entries = {}
            for name in LICENSE_FILES:
                matches = [entry for entry in entries if entry.filename.endswith(f"/{name}")]
                if len(matches) != 1 or not 0 < matches[0].file_size <= MAX_LICENSE:
                    raise ReleaseError("archive license materials differ")
                license_entries[name] = matches[0]
            manifest = json.loads(archive.read(manifests[0]), object_pairs_hook=unique_object)
            executable = archive.read(binaries[0])
            licenses = {name: archive.read(entry) for name, entry in license_entries.items()}
    except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("invalid standalone archive") from error
    expected_fields = {
        "schema_version",
        "name",
        "command",
        "version",
        "target",
        "source_revision",
        "builder",
        "executable",
        "executable_sha256",
        "executable_size",
        "scope",
        "licenses",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise ReleaseError("release manifest fields differ")
    prefix = f"{PROJECT}-{manifest.get('version')}-{TARGET}"
    if (
        manifest["schema_version"] != SCHEMA
        or manifest["name"] != PROJECT
        or manifest["command"] != COMMAND
        or manifest["target"] != TARGET
        or manifest["executable"] != f"{COMMAND}.exe"
        or manifest["scope"] != "host_only_firmware_analysis"
        or not isinstance(manifest["version"], str)
        or not VERSION.fullmatch(manifest["version"])
        or not isinstance(manifest["source_revision"], str)
        or not REVISION.fullmatch(manifest["source_revision"])
        or manifest["builder"]
        != {
            "python": BUILD_PYTHON,
            "pyinstaller": BUILD_PYINSTALLER,
            "dependency_path": BUILD_PATH_POLICY,
        }
        or not isinstance(manifest["executable_sha256"], str)
        or not HASH.fullmatch(manifest["executable_sha256"])
        or manifest["executable_sha256"] != digest(executable)
        or not isinstance(manifest["executable_size"], int)
        or isinstance(manifest["executable_size"], bool)
        or manifest["executable_size"] != len(executable)
        or not 0 < len(executable) <= MAX_BINARY
        or manifests[0].filename != f"{prefix}/release-manifest.json"
        or binaries[0].filename != f"{prefix}/{COMMAND}.exe"
    ):
        raise ReleaseError("release manifest values differ")
    if not isinstance(manifest["licenses"], dict) or set(manifest["licenses"]) != set(
        LICENSE_FILES
    ):
        raise ReleaseError("release license manifest differs")
    for name, data in licenses.items():
        binding = manifest["licenses"][name]
        if (
            not isinstance(binding, dict)
            or set(binding) != {"sha256", "size"}
            or binding["sha256"] != digest(data)
            or type(binding["size"]) is not int
            or binding["size"] != len(data)
            or license_entries[name].filename != f"{prefix}/{name}"
        ):
            raise ReleaseError("release license manifest differs")
    return {
        "archive": str(archive_path.resolve()),
        "archive_sha256": digest(data),
        **manifest,
        "integrity_verified": True,
        "publisher_authenticity_verified": False,
        "hardware_access": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    builder = commands.add_parser("build")
    builder.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    builder.add_argument("--output-dir", type=Path, required=True)
    builder.add_argument("--work-dir", type=Path, required=True)
    verifier = commands.add_parser("verify")
    verifier.add_argument("archive", type=Path)
    verifier.add_argument("--checksum", type=Path, required=True)
    tag = commands.add_parser("check-tag")
    tag.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    tag.add_argument("--tag", required=True)
    for command in commands.choices.values():
        command.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.operation == "build":
            data = build(args.source.resolve(), args.output_dir.resolve(), args.work_dir.resolve())
        elif args.operation == "verify":
            data = verify(args.archive.resolve(), args.checksum.resolve())
        else:
            data = check_tag(args.source.resolve(), args.tag)
        report = {"schema_version": SCHEMA, "ok": True, "operation": args.operation, "data": data}
    except (OSError, ReleaseError, subprocess.SubprocessError, UnicodeError) as error:
        report = {
            "schema_version": SCHEMA,
            "ok": False,
            "operation": args.operation,
            "error": str(error),
        }
    if args.json or report["ok"]:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["error"], file=sys.stderr)
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
