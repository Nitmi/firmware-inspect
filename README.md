# Firmware Inspect

Offline firmware analysis for people, agents, and CI. Inspect an ELF, Intel HEX,
or BIN before asking a hardware tool to program it; compare builds without
attaching to a target or running a toolchain.

This repository is the next host-only component of Embedded Agent Toolkit.
Version 0.1.0 is a local development version, not yet a published release or an
automatically selected Toolkit component.

## Install and use

Python 3.11+ is required. From this checkout:

```powershell
uv sync --locked
uv run firmware-inspect inspect C:\project\build\app.elf --json
uv run firmware-inspect inspect C:\project\build\whole.hex --json
uv run firmware-inspect inspect C:\project\build\app.bin --base-address 0x10000 --json
uv run firmware-inspect diff C:\build-A\app.elf C:\build-B\app.elf --json
```

Alternatively install this directory with `pip install .` or `uv tool install .`.
An installed wheel exposes `firmware-inspect` and `python -m firmware_inspect`.
All runtime dependencies are pinned in `pyproject.toml`; development dependencies
are resolved in `uv.lock`.

## Inspection

- Hashes and parses the same bounded byte snapshot; the source includes its
  canonical path, size and SHA-256.
- ELF32/ELF64, both byte orders: architecture, entry point, GNU Build IDs,
  PT_LOAD physical/load and virtual/run addresses, segment hashes, sections,
  section hashes, and the largest defined function/object symbol entries.
- Intel HEX: checksum and record validation, sparse contiguous address ranges,
  per-range hashes, and raw start-address metadata. Gaps are not padded or
  counted as programmed bytes. High-address records, including UICR, are retained.
- BIN: one explicitly based range; no architecture or entry point is guessed.
- All addresses are integers in byte units, with half-open ranges. HEX addresses
  must fit 32 bits; ELF follows its address width; BIN must fit 64 bits.

Auto format selection recognizes ELF magic or `.hex`/`.ihex`/`.bin` suffixes.
Ambiguous inputs require `--format elf|hex|bin`. BIN always requires
`--base-address`; it is rejected for other formats. `--symbol-limit 0..200`
controls the largest symbol list (default 20). Counts refer to entries, so
duplicates across ELF symbol tables are counted rather than silently deduplicated.

The `summary.section_usage` fields are explicitly named sums: allocated,
file-backed, zero-fill, writable, read-only, and executable section bytes.
Writable `.data` has both a file-backed load and a runtime allocation. NOBITS
sections such as `.bss` have runtime size but no source payload. Debug sections
are listed but do not count toward allocated-section usage. These sums are not
board-specific RAM/Flash consumption or percentage capacity; overlays, aliases,
alignment, and linker mapping require board/linker context.

`programmed_ranges` is the union of file-backed load-address intervals,
not a Flash Plan. ELF `p_paddr` values are linker declarations; ELF PIE images
may need relocation. Overlapping load ranges are reported with a warning.
No target compatibility, erase region, firmware signature authenticity, or
connected-board firmware identity is inferred. SHA-256 and Build ID identify
file contents; a Build ID is not a signature.

## Build comparison

`diff` requires matching format and ELF architecture/type. It reports both source
identities, file-size and address-byte deltas, entry-point and Build ID changes,
load/runtime layout changes, section-usage deltas, and added/removed/changed
load segments and sections. Payload hashes detect same-size content changes in
all three formats. Duplicate section
names are matched by occurrence, not overwritten in a name-keyed dictionary.
It does not pretend to be a symbol ABI comparison or an instruction-level diff.

`source_identical` means equal input hashes; `identical` additionally requires
equal load-address ranges. The CLI uses the same BIN base for both inputs.

## Structured contract

`--json` writes one JSON object to stdout; successful operations exit 0 and
inspection failures exit 1. Invalid CLI syntax exits 2 through argparse.
Reports use `embedded-firmware-inspect.inspection.v1`,
`embedded-firmware-inspect.diff.v1`, or `embedded-firmware-inspect.error.v1`.
Reports always state `scope=host_only_firmware_analysis`, `hardware_access=false`,
`executables_started=false`, and `flash_authorized=false`.

There are no device operations, subprocesses, automatic retries, or report-file
writes. Redirect stdout explicitly when a saved artifact is needed. Relative
input paths are resolved only within the invoking user's filesystem context.
Limits are 64 MiB per source, 8 MiB for HEX text, 4096 ELF sections/segments or
HEX ranges, 200,000 symbol entries, and 1024 characters per ELF name. Aggregate
ELF section and load-segment payload hashing are each limited to 128 MiB;
note entries to 4096 and individual Build ID text to 8192 characters.

## Agent integration

The self-contained [firmware-inspect Skill](skills/firmware-inspect/SKILL.md)
routes firmware identity, layout, footprint and build-comparison requests to
the structured CLI. It is shipped in the source distribution, not installed
into an Agent host by the Python installer. No component MCP server is needed
for bounded, file-only inspection. Toolkit catalog registration and binary
distribution are separate release work; the existing workstation lock remains
unchanged.

Parsing uses [pyelftools](https://github.com/eliben/pyelftools) and
[IntelHex](https://github.com/python-intelhex/intelhex). No replacement ELF or
HEX parser, flasher, MCP server, or hardware driver is implemented here.

## Development

```powershell
uv sync --locked --extra dev
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
uv build
git diff --check
```

Hardware is never required for the tests. Format fixtures cover load/run address
differences, BSS, sparse HEX, GNU Build IDs, symbols, malformed inputs and bounds.
