---
name: firmware-inspect
description: Inspect local ELF, Intel HEX, or BIN firmware identity and memory layout, or compare two builds using the offline firmware-inspect CLI. Use for pre-flash artifact analysis and footprint regressions, not for live target inspection or flashing.
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
```

BIN needs a base address from the user's project/linker context; do not invent
one. Auto format detection uses ELF magic or HEX/BIN suffixes. Use `--format`
only when the format is known. ELF output includes at most 20 largest defined
function/object symbol entries by default; `--symbol-limit 0..200` changes this.

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
