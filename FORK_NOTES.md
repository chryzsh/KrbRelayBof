# KrbRelayBof Fork

- **Upstream:** https://github.com/antroguy/KrbRelayBof
- **Purpose:** Fix a crash that occurs in COFF loaders that do not apply relocations in the .rdata section (OC2 and others).

## Branches

- `main` tracks upstream.
- `fix/jump-table-crash` fixes the .rdata jump table crash.

## Changes

GCC compiles the `stage_name()` switch into two jump tables in the `.rdata` section, with `IMAGE_REL_AMD64_REL32` relocations that point back to `.text`. OC2's COFF loader does not apply relocations in `.rdata`, so the table entries contain unresolved values. When the relay fails and `go()` calls `stage_name()` to report the error, the indirect jump lands at an invalid address and kills the agent process.

The fix replaces the switch with an if-else chain that produces no jump table. The Makefile now includes `-fno-jump-tables` to prevent GCC from introducing new tables in future edits.
