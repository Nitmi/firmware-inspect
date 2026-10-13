# Firmware Inspect

Offline firmware analysis for people, agents, and CI. Inspect an ELF, Intel HEX,
or BIN before asking a hardware tool to program it; compare builds without
attaching to a target or running a toolchain.

This repository provides a host-only component for Embedded Agent Toolkit.
Toolkit catalog registration and automatic selection are separate from this
component's releases; an existing workstation lock is never changed implicitly.

Release [0.2.0](https://github.com/Nitmi/firmware-inspect/releases/tag/v0.2.0)
adds exact ELF symbol queries. Hosts using `0.1.0` need to select `0.2.0` or newer
before calling `symbols`; publishing this component does not change a host's lock.

The local `0.3.0` candidate adds code-address lookup with function ranges and
in-file DWARF source lines. It is not yet a published release. Use this checkout
or an explicitly selected candidate when calling `addresses`; the official
`0.2.0` executable and existing Toolkit locks do not expose this command.

Windows standalone packages are built with a tag-bound provenance workflow;
see [standalone releases](docs/releases.md). Runtime inspection never invokes
these build helpers. Only published assets whose integrity and GitHub attestation
have been verified should be treated as official releases.

## Install and use

### Standalone Windows executable

Published Windows x86_64 packages are available from
[GitHub Releases](https://github.com/Nitmi/firmware-inspect/releases).
Verify the ZIP checksum and GitHub attestation using the
[release instructions](docs/releases.md), then extract the complete package
into a new versioned directory. Keep its license and third-party notices with
the executable. This distribution does not require a system Python installation.

Invoke the exact extracted executable; no PATH changes or administrator rights
are required for ordinary file inspection:

```powershell
$package = 'C:\tools\firmware-inspect\0.2.0\embedded-firmware-inspect-0.2.0-windows-x86_64'
$inspector = Join-Path $package 'firmware-inspect.exe'
& $inspector inspect C:\project\build\app.elf --json
& $inspector diff C:\build-A\app.elf C:\build-B\app.elf --json
& $inspector symbols C:\project\build\app.elf --name _SEGGER_RTT --json
```

### Python source installation

Python 3.11+ is required for source/wheel installations. From this checkout:

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

## Exact ELF symbols

```powershell
uv run --locked firmware-inspect symbols C:\project\build\app.elf `
  --name _SEGGER_RTT --name main --json
```

This scans all regular/dynamic symbol tables, independently of `inspect`'s
largest-symbol limit. Supply 1..32 distinct exact names. Matching is
case-sensitive, with no glob, demangling or substring rules. The source path,
size and SHA-256 bind the same bounded snapshot that is parsed.

Each query reports `unique`, `ambiguous`, `not_found`, `undefined_only`, or
`no_definition`, with every matching entry's table/index, type, binding,
visibility, section, raw value and size. Equivalent definition metadata across
tables counts once for uniqueness, while all original entries remain visible.
Conflicting definitions are not resolved by address order or global/weak
precedence. A zero-sized definition is retained without inventing its extent.
Missing/stripped symbols are a completed query, not an error or a guessed value.
More than 256 matching entries fails without returning a partial resolution.

`value` means ELF `st_value`, not a validated target address. TLS values are
offsets, common entries encode alignment, and ET_DYN/PIE needs relocation context;
see the [ELF symbol-table specification](https://gabi.xinuos.com/elf/05-symtab.html).
Architecture-specific bits are preserved. Section-defined and absolute
definitions can be unique without proving live memory, board or running-firmware
identity. Special/extended section indexes are retained as unresolved, not
guessed. This query supports linked ET_EXEC/ET_DYN files like inspection;
relocatable ET_REL objects remain unsupported.

For `_SEGGER_RTT`, review a unique section-defined object, its allocated writable
section and declared size, and pass the exact build hash and value to the
debugger's native plan with its target RAM checks. The query itself never scans
RAM, attaches, reads a target or asserts block initialization.

## Code addresses and source lines

```powershell
uv run --locked firmware-inspect addresses C:\project\build\app.elf `
  --address 0x101 --address 0x120 --address-mode arm-thumb --json
```

Supply 1..32 distinct unsigned byte addresses from the exact build's linked ELF.
The default `raw` mode keeps query addresses unchanged. Explicit `arm-thumb`
mode requires ELF32 EM_ARM and clears only query bit 0, retaining both the input
and lookup addresses. Neither mode subtracts from LR, relocates a PIE image,
unwinds a stack, or chooses a nearest symbol. ARM Thumb function symbols retain
their original `st_value`, with a separately reported code range and ABI bit
normalization. `symbols` continues to expose raw values unchanged.

Each address has independent `function_status` and `line_status`, with every
match retained. Function ranges use declared `STT_FUNC` sizes in allocated
executable sections; zero-sized functions match only their exact start. Lines
use DWARF 2–5 sequences with half-open intervals and explicit sequence ends.
Missing metadata returns `not_found`; conflicting declarations return
`ambiguous`. A completed query can have no function or line match.

Source paths are compiler metadata, kept as file, directory and compilation
directory fields. They are not opened, rebased or verified against a checkout.
Function symbols and line tables can disagree after optimization or discarded
code; a unique line match is a unique metadata location, not a verified function
body or root cause. External/split and compressed debug data are unsupported.
Use `--no-lines` for function-only lookup. See the [address query contract](docs/addresses.md)
for limits and how to interpret PC/LR evidence.

## Structured contract

`--json` writes one JSON object to stdout; successful operations exit 0 and
inspection failures exit 1. Invalid CLI syntax exits 2 through argparse.
Reports use `embedded-firmware-inspect.inspection.v1`,
`embedded-firmware-inspect.diff.v1`, `embedded-firmware-inspect.symbols.v1`,
`embedded-firmware-inspect.addresses.v1`,
or `embedded-firmware-inspect.error.v1`.
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
routes firmware identity, layout, footprint, symbol/address and build-comparison requests to
the structured CLI. It is shipped in the source distribution, not installed
into an Agent host by the Python installer. No component MCP server is needed
for bounded, file-only inspection. Toolkit catalog integration and activation
are separate release work; the existing workstation lock remains
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
Address fixtures cover DWARF 2–5, both ELF widths/byte orders, sequence gaps,
overlaps, Thumb values, in-file string tables and bounded malformed units.
