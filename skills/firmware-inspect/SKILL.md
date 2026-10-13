---
name: firmware-inspect
description: Inspect local ELF, Intel HEX, or BIN firmware identity and layout, query exact ELF symbols, resolve PC/LR code addresses to functions and in-file DWARF lines, or compare builds using firmware-inspect. Use for offline build and crash-log analysis, not live target access or flashing.
---

# Firmware Inspect

Use the installed `firmware-inspect` CLI for file-only firmware analysis. In a
source checkout, use `uv run --locked firmware-inspect` instead. This operation
does not access hardware or require a hardware confirmation.

```powershell
firmware-inspect inspect C:\project\build\app.elf --json
firmware-inspect inspect C:\project\build\whole.hex --json
firmware-inspect inspect C:\project\build\app.bin --base-address 0x10000 --json
firmware-inspect diff C:\build-A\app.elf C:\build-B\app.elf --json
firmware-inspect symbols C:\project\build\app.elf --name _SEGGER_RTT --json
firmware-inspect addresses C:\project\build\app.elf --address 0x101 --address-mode arm-thumb --json
```

BIN needs a base address from the user's project/linker context; do not invent
one. Auto format detection uses ELF magic or HEX/BIN suffixes. Use `--format`
only when the format is known. ELF output includes at most 20 largest defined
function/object symbol entries by default; `--symbol-limit 0..200` changes this.
For an exact variable/function or linker-symbol request, use `symbols` in 0.2.0+
instead of searching the size-limited inspection list. Repeat `--name` for up to
32 distinct, case-sensitive names; no glob, demangling or substring matching.
Read every query's `status`: `unique` identifies one set of equivalent definition
metadata, `ambiguous` retains conflicting definitions, and `not_found`,
`undefined_only` or `no_definition` supplies no selected value. A successful CLI
exit means the query completed, not that every requested symbol resolved.

`value` is raw ELF `st_value`; preserve `matches[].value_kind`, symbol type and
section. TLS values are offsets, common values are alignment, and ELF PIE values
need relocation context. Do not reinterpret them as target memory addresses or
clear ABI bits. For an RTT block, check a unique section-defined object, its
allocated writable section, declared size, exact ELF hash and the target RAM
map through the debugger's native plan before using the value. This file query
does not prove that the block is initialized or that this firmware is running.

For PC/LR or code-address requests, `addresses` requires 0.3.0+; use the exact
build's linked ELF and preserve its hash. Repeat `--address` for 1..32 distinct
unsigned byte addresses. Default `raw` preserves inputs; explicit `arm-thumb`
requires ELF32 EM_ARM and clears query bit 0 while retaining the input value.
Function matches retain raw symbol values and report any Thumb-bit range
normalization separately. Do not silently subtract from LR or infer relocation.
Read `function_status` and `line_status` independently; both can be `unique`,
`ambiguous` or `not_found`. Keep all conflicting matches. Zero-sized functions
match only their exact start, and sequence gaps supply no source line. DWARF
paths are unverified metadata and are never opened. Optimization/discarded code
can leave a line location unrelated to the matching function; this does not
establish a call stack or running identity. Use `--no-lines` for function-only
lookup. Read [the address guide](../../docs/addresses.md) when source lines,
missing debug data or return-address interpretation matter.

Interpret the report precisely:

- `source.sha256` is the identity of the parsed file snapshot. Build IDs are
  linker metadata, not signature verification or proof of firmware running on a board.
- `load_segments.load_address` is ELF physical load address or HEX/BIN data
  address; `run_address` is ELF virtual runtime address. `programmed_ranges`
  retains sparse HEX data, including high addresses such as UICR. It is not an
  erase plan or evidence that every interval is ordinary code Flash.
- `summary.section_usage` is an allocated-section sum, not physical RAM/Flash
  percentage. NOBITS/BSS is zero-fill runtime storage, not file payload; writable
  initialized data consumes file-backed load bytes and runtime storage.
- `diff` gives load-segment/section hashes, layout changes and size deltas.
  Same-size content changes still matter. A successful comparison means the
  files were analyzed; it does not mean the newer firmware meets a project's
  budget or correctness criteria. Apply budgets explicitly requested by the user.

Keep raw JSON and source hashes when the task needs an evidence artifact.
Exit 1 carries a structured non-retryable error; CLI argument errors exit 2.
Do not bypass failures by guessing addresses, extracting partial files, or
silently substituting a different build. Inspection grants no flash authority;
subsequent hardware tasks continue through their native component workflows.
