# Changelog

## 0.1.0

- Offline ELF, Intel HEX, and explicitly based BIN inspection with bounded
  parsing, SHA-256 identity, sparse address ranges, ELF sections and symbols,
  GNU Build IDs, and load/runtime layout.
- Build comparison that detects payload changes even when size and layout match.
- Versioned JSON reports and a file-only agent Skill; no hardware access,
  flashing authorization, toolchain invocation, or MCP server.
- Standalone Windows x86_64 distribution with license notices, deterministic
  dual builds, strict archive integrity verification, and tag-bound provenance.
- Source CI on Windows/Linux with Python 3.11/3.13. No PyPI publication is
  performed by this release workflow.
