# Offline code-address queries

`addresses` is available in 0.3.0 and newer. It reads the specified
linked ELF once, hashes that bounded snapshot and parses it with pyelftools.
It does not read target memory, collect registers, invoke a toolchain, open
source files or load external debug files.

```powershell
uv run --locked firmware-inspect addresses C:\build\app.elf `
  --address 0x101 --address 0x120 --address-mode arm-thumb --json
```

## Select the address context

Use the ELF that produced the observed firmware, with its expected SHA-256.
This query proves only file identity and the declarations in that file; matching
the running firmware remains a separate debugger/serial/RTT evidence task.

Addresses are unsigned byte integers, decimal or `0x` in the CLI. Supply 1..32
distinct values within the ELF address width. ET_EXEC and ET_DYN are supported;
ET_REL objects are not. An ET_DYN address must already be in the ELF's link-time
context. No load bias is applied.

`raw` keeps each input as `lookup_address`. Explicit `arm-thumb` clears query
bit 0 and requires ELF32 EM_ARM. The original `address` remains visible. An ARM32
function's odd `st_value` declares Thumb code, so its code range starts at
`raw_value & ~1` in either query mode; `value_normalization=arm_thumb_bit`
records this. Exact-name `symbols` queries continue to preserve raw values.

LR is usually a return location, which may map to the instruction after a call.
Neither mode guesses call-instruction width or subtracts from LR. If an analyst
needs an adjusted address, supply it explicitly as another query and record why.
No registers are fetched and no stack unwind or inline-call stack is produced.

## Read independent results

Each `address_queries` row contains `functions` and `lines`. Each has its own
status: `unique`, `ambiguous` or `not_found`. CLI exit 0 and `complete=true`
mean the query completed, even if either result is missing or ambiguous.

Functions are named, section-defined `STT_FUNC` symbols in allocated executable
sections. Nonzero sizes define half-open code ranges; a zero size gives only
`exact_start_only` with no inferred endpoint. Tables, symbol/section indexes,
binding, visibility, raw value, size and offset remain in each match. Equivalent
metadata across tables has `unique` status while all entries remain visible;
aliases, overlaps and conflicting definitions are not resolved by precedence.

Source lines come from in-file DWARF 2–5 line programs. A row covers its address
up to the next row or sequence end, excluding that upper bound. Empty intervals,
line number 0 and gaps between sequences supply no source location. A different
matching file/directory/compilation directory, line, column or discriminator
makes the result ambiguous. CU, line-program and row offsets remain in the
report to inspect the original declaration.

Function symbols and DWARF line tables are independent metadata. Optimization,
assembly routines and discarded sections can leave line tables that do not
describe a matching function. For example, a saved DK test ELF has an exact
zero-sized `Reset` symbol and a compiler-builtins line declaration at the same
address. The query retains both without claiming that the builtins file is
`Reset`'s source. A unique line location is not verified against source contents
and does not prove a crash cause.

`file_name`, `directory` and `compilation_directory` stay separate. No path is
rebased, traversed, opened or checked against a checkout. In-file `.debug_str`
and `.debug_line_str` are supported; external/split or indexed supplementary
string references are not followed. Missing `.debug_info`/`.debug_line` reports
`debug_lines.status=absent`. `--no-lines` reports `disabled` and skips DWARF
decoding. Compressed DWARF, VLIW/multi-operation line programs and segmented
addresses are unsupported in this version.

## Bounds and failures

The existing 64 MiB snapshot, ELF section/segment and symbol limits apply.
Address queries retain at most 256 total function matches and 128 total line
matches. DWARF sections read by pyelftools total at most 16 MiB, `.debug_line`
at most 2 MiB, with at most 1024 compilation units and 200,000 decoded line
entries. Each line unit is limited to 128 KiB encoded bytes before eager
decoding. Reads and seeks for CU DIEs and line programs stay inside their
declared units. Individual source metadata strings are at most 4096 bytes or
characters. Duplicate DWARF section names are rejected.

Malformed declarations or exceeded bounds return a structured error, never a
partial successful result. JSON reports use
`embedded-firmware-inspect.addresses.v1`; errors retain
`embedded-firmware-inspect.error.v1`. Runtime analysis remains
`scope=host_only_firmware_analysis`, with `hardware_access=false`,
`executables_started=false` and `flash_authorized=false`. Exit 1 is a structured
analysis error; invalid CLI syntax exits 2.

Parsing and ABI references:

- [pyelftools address-to-line example](https://github.com/eliben/pyelftools/blob/main/examples/dwarf_decode_address.py)
- [DWARF 5 specification](https://dwarfstd.org/doc/DWARF5.pdf)
- [Arm ELF32 ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst)
