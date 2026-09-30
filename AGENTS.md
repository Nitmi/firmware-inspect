# Repository Guidance

- This tool is offline and host-only. Never enumerate or access hardware, run
  toolchains or subprocesses, or interpret inspection as permission to flash.
- Use pyelftools and IntelHex for format parsing; do not implement replacement
  ELF or Intel HEX parsers.
- Hash and parse the same bounded byte snapshot. Addresses are bytes; ranges
  are half-open. Do not infer board identity, erase layout, or physical memory
  capacity from a firmware file.
- Keep structured CLI results versioned and failures machine-readable.
- Run pytest, Ruff, wheel smoke tests, and git diff --check before committing.
