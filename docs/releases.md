# Standalone releases

Standalone releases are official only after their immutable tag, successful CI,
attested artifact, and published GitHub Release have all been verified. Local
builds and workflow artifacts alone are not published releases. The packaging helper was adapted
from Nitmi's MIT-licensed board-registry release implementation.

## Build

Windows x86_64 builds use uv-managed CPython 3.13.13 and PyInstaller 6.22.2.
The build subprocess searches only the Python runtime root, its Scripts
directory, and Windows System32, not ambient JDK or developer-tool directories.
Inspection remains file-only; only release/test helpers launch build and smoke
processes.

Commit the source before building. From this checkout:

```powershell
$env:UV_PYTHON_PREFERENCE = 'only-managed'
uv sync --locked --python 3.13.13 --extra binary --extra dev
uv run --locked --extra binary python scripts/package_binary.py build `
  --output-dir C:\work\release-a --work-dir C:\work\build-a --json
uv run --locked --extra binary python scripts/package_binary.py build `
  --output-dir C:\work\release-b --work-dir C:\work\build-b --json
```

Each output/work directory must be new. Compare both ZIP SHA-256 hashes.
The manifest binds the package version, source commit, target, builder identity,
executable size and executable SHA-256. The ZIP also includes the project
`LICENSE` and `THIRD-PARTY-NOTICES.txt`, each bound by size and SHA-256 in the
manifest. Notices come from the pinned Windows runtime and installed libraries,
including pyelftools' vendored Construct license. ZIP timestamps and metadata
are fixed.
`verify` validates integrity without running the executable or authenticating
its publisher:

```powershell
uv run --locked --extra binary python scripts/package_binary.py verify `
  C:\work\release-a\embedded-firmware-inspect-0.2.0-windows-x86_64.zip `
  --checksum C:\work\release-a\embedded-firmware-inspect-0.2.0-windows-x86_64.zip.sha256 --json
```

After extraction, `scripts/smoke_binary.py` runs the exact EXE against generated
ELF/HEX/BIN inputs, checks Build IDs, BSS, sparse/high addresses, diff results,
exact symbol lookup (defined, undefined and absent names), and failure behavior.
It validates native JSON against the report contract shipped by this source version.
It does not read user firmware or access hardware.

## Provenance and publication

`binary-release.yml` runs only on version-tag pushes. It binds `v<version>` to
the checked-out source commit, tests the code, builds twice, compares hashes,
smoke-checks the standalone, and emits GitHub attestation. It does not create
the GitHub Release or publish to PyPI automatically.

The published [v0.2.0 Release](https://github.com/Nitmi/firmware-inspect/releases/tag/v0.2.0)
binds source commit `575b1cca7a21c17c16e0b3affabc5b1c7d0e1e87`.
Verify its downloaded ZIP before extracting or executing it:

```powershell
gh attestation verify embedded-firmware-inspect-0.2.0-windows-x86_64.zip `
  --repo Nitmi/firmware-inspect --source-ref refs/tags/v0.2.0 `
  --source-digest 575b1cca7a21c17c16e0b3affabc5b1c7d0e1e87 `
  --signer-digest 575b1cca7a21c17c16e0b3affabc5b1c7d0e1e87 `
  --cert-identity https://github.com/Nitmi/firmware-inspect/.github/workflows/binary-release.yml@refs/tags/v0.2.0 `
  --deny-self-hosted-runners
```

For strict acceptance also require the expected source and signer commit digest
and compare the asset, checksum, manifest and executable hashes. A sidecar
checksum alone is not proof of publisher authenticity. Install into a versioned
directory; do not change PATH or an existing workstation lock implicitly.

Toolkit's trusted catalog will only pin this optional component after official
release assets and provenance have been verified. Source checkout support must
not be confused with availability in an already installed Toolkit release.
