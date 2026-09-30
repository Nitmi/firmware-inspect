from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path
from unittest import mock

import pytest

from scripts import package_binary

LICENSES = {"LICENSE": b"project license", "THIRD-PARTY-NOTICES.txt": b"upstream notices"}


def write_release(tmp_path: Path, payload: bytes) -> tuple[Path, Path]:
    archive = tmp_path / "embedded-firmware-inspect-0.1.0-windows-x86_64.zip"
    checksum = archive.with_suffix(".zip.sha256")
    archive.write_bytes(payload)
    checksum.write_text(f"{package_binary.digest(payload)}  {archive.name}\n", encoding="ascii")
    return archive, checksum


def rewrite_zip(payload: bytes, transform) -> bytes:
    output = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(payload)) as source,
        zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as target,
    ):
        for entry in source.infolist():
            data = transform(entry.filename, source.read(entry))
            copied = zipfile.ZipInfo(entry.filename, date_time=entry.date_time)
            copied.create_system = entry.create_system
            copied.external_attr = entry.external_attr
            target.writestr(copied, data)
    return output.getvalue()


def test_archive_verify_binds_executable_and_source(tmp_path: Path) -> None:
    payload = package_binary.archive_bytes("0.1.0", "a" * 40, b"standalone", licenses=LICENSES)
    archive, checksum = write_release(tmp_path, payload)

    report = package_binary.verify(archive, checksum)
    assert report["version"] == "0.1.0"
    assert report["source_revision"] == "a" * 40
    assert report["builder"] == {
        "python": "3.13.13",
        "pyinstaller": "6.22.2",
        "dependency_path": "python-root-system32-only",
    }
    assert report["executable_sha256"] == package_binary.digest(b"standalone")
    assert report["archive_sha256"] == package_binary.digest(payload)
    assert report["hardware_access"] is False
    assert report["licenses"]["LICENSE"]["sha256"] == package_binary.digest(LICENSES["LICENSE"])
    assert payload == package_binary.archive_bytes(
        "0.1.0", "a" * 40, b"standalone", licenses=LICENSES
    )


def test_modified_executable_is_rejected_even_with_new_archive_checksum(tmp_path: Path) -> None:
    payload = package_binary.archive_bytes("0.1.0", "a" * 40, b"standalone", licenses=LICENSES)
    modified = rewrite_zip(
        payload,
        lambda name, data: b"changed" if name.endswith("firmware-inspect.exe") else data,
    )
    archive, checksum = write_release(tmp_path, modified)

    with pytest.raises(package_binary.ReleaseError, match="manifest values differ"):
        package_binary.verify(archive, checksum)


def test_duplicate_manifest_field_is_rejected(tmp_path: Path) -> None:
    payload = package_binary.archive_bytes("0.1.0", "a" * 40, b"standalone", licenses=LICENSES)
    modified = rewrite_zip(
        payload,
        lambda name, data: (
            data.replace(b"{", b'{"version":"0.1.0",', 1)
            if name.endswith("release-manifest.json")
            else data
        ),
    )
    archive, checksum = write_release(tmp_path, modified)

    with pytest.raises(package_binary.ReleaseError, match="duplicate JSON field"):
        package_binary.verify(archive, checksum)


def test_non_regular_archive_member_is_rejected(tmp_path: Path) -> None:
    payload = package_binary.archive_bytes("0.1.0", "a" * 40, b"standalone", licenses=LICENSES)
    source = zipfile.ZipFile(io.BytesIO(payload))
    output = io.BytesIO()
    with source, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as target:
        for entry in source.infolist():
            copied = zipfile.ZipInfo(entry.filename, date_time=entry.date_time)
            copied.create_system = 3
            copied.external_attr = (
                (stat.S_IFLNK | 0o777) << 16
                if entry.filename.endswith("firmware-inspect.exe")
                else entry.external_attr
            )
            target.writestr(copied, source.read(entry))
    archive, checksum = write_release(tmp_path, output.getvalue())

    with pytest.raises(package_binary.ReleaseError, match="not a regular file"):
        package_binary.verify(archive, checksum)


def test_modified_license_is_rejected_even_with_new_archive_checksum(tmp_path: Path) -> None:
    payload = package_binary.archive_bytes("0.1.0", "a" * 40, b"standalone", licenses=LICENSES)
    modified = rewrite_zip(
        payload,
        lambda name, data: b"changed" if name.endswith("THIRD-PARTY-NOTICES.txt") else data,
    )
    archive, checksum = write_release(tmp_path, modified)
    with pytest.raises(package_binary.ReleaseError, match="license manifest differs"):
        package_binary.verify(archive, checksum)


@pytest.mark.parametrize(
    "licenses",
    [{}, {**LICENSES, "LICENSE": b""}, {**LICENSES, "extra": b"unexpected"}],
)
def test_archive_requires_exact_nonempty_license_materials(licenses: dict[str, bytes]) -> None:
    with pytest.raises(package_binary.ReleaseError, match="license materials differ"):
        package_binary.archive_bytes("0.1.0", "a" * 40, b"standalone", licenses=licenses)


def test_license_materials_require_locked_dependencies(tmp_path: Path) -> None:
    with (
        mock.patch.object(package_binary.importlib.metadata, "distribution") as distribution,
        pytest.raises(package_binary.ReleaseError, match="license source version differs"),
    ):
        distribution.return_value.version = "unexpected"
        package_binary.license_materials(tmp_path)


def test_tag_must_bind_version_and_current_commit(tmp_path: Path) -> None:
    with (
        mock.patch.object(package_binary, "project_version", return_value="0.1.0"),
        mock.patch.object(package_binary, "clean_revision", return_value="a" * 40),
        mock.patch.object(package_binary, "git", return_value="a" * 40),
    ):
        report = package_binary.check_tag(tmp_path, "v0.1.0")
        assert report["source_revision"] == "a" * 40
        with pytest.raises(package_binary.ReleaseError, match="exactly v0.1.0"):
            package_binary.check_tag(tmp_path, "v0.1")

    with (
        mock.patch.object(package_binary, "project_version", return_value="0.1.0"),
        mock.patch.object(package_binary, "clean_revision", return_value="a" * 40),
        mock.patch.object(package_binary, "git", return_value="b" * 40),
        pytest.raises(package_binary.ReleaseError, match="checked-out commit"),
    ):
        package_binary.check_tag(tmp_path, "v0.1.0")


def test_project_version_comes_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "example"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    assert package_binary.project_version(tmp_path) == "1.2.3"


def test_builder_identity_rejects_unpinned_python() -> None:
    with (
        mock.patch.object(package_binary.platform, "python_version", return_value="3.13.12"),
        mock.patch.object(package_binary.importlib.metadata, "version", return_value="6.22.2"),
        pytest.raises(package_binary.ReleaseError, match="release builder must use"),
    ):
        package_binary.builder_identity()


def test_build_environment_excludes_ambient_dependency_paths(tmp_path: Path) -> None:
    python_root = tmp_path / "python"
    windows_root = tmp_path / "windows"
    with (
        mock.patch.object(package_binary.sys, "base_prefix", str(python_root)),
        mock.patch.dict(
            package_binary.os.environ,
            {
                "PATH": str(tmp_path / "unrelated-jdk"),
                "SYSTEMROOT": str(windows_root),
                "PYTHONHOME": "unsafe-home",
                "PYTHONPATH": "unsafe-path",
            },
            clear=False,
        ),
    ):
        environment = package_binary.build_environment()
    assert environment["PATH"].split(package_binary.os.pathsep) == [
        str(python_root.resolve()),
        str((python_root / "Scripts").resolve()),
        str((windows_root / "System32").resolve()),
    ]
    assert "unrelated-jdk" not in environment["PATH"]
    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment
