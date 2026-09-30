from __future__ import annotations

import json
import os
import subprocess
import sys

from fixtures import elf_image

from firmware_inspect.cli import main


def test_cli_json_and_human_output(tmp_path, capsys):
    path = tmp_path / "app.elf"
    path.write_bytes(elf_image())
    assert main(["inspect", str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == "embedded-firmware-inspect.inspection.v1"
    assert main(["inspect", str(path)]) == 0
    output = capsys.readouterr()
    assert "ELF:" in output.out and "Section usage:" in output.out
    assert "Warning:" in output.err


def test_cli_json_failure_no_traceback(tmp_path, capsys):
    assert main(["inspect", str(tmp_path / "absent"), "--json"]) == 1
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["error"]["code"] == "INPUT_UNAVAILABLE"
    assert report["error"]["retryable"] is False
    assert not output.err


def test_cli_diff(tmp_path, capsys):
    first, second = tmp_path / "a.elf", tmp_path / "b.elf"
    first.write_bytes(elf_image())
    second.write_bytes(elf_image(bss_size=16))
    assert main(["diff", str(first), str(second), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "embedded-firmware-inspect.diff.v1"
    assert report["section_usage_delta"]["zero_fill_bytes_sum"] == 8


def test_module_entrypoint_runs_from_other_directory(tmp_path):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-m", "firmware_inspect", "--version"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "firmware-inspect 0.1.0"
    assert result.stderr == ""
