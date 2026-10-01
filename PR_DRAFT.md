## Issue

When I ran this BOF through OC2's `exec_bof`, the relay attempt crashed the agent process (dllhost.exe) with an access violation (`0xc0000005`). The WER fault module was `StackHash_b4ee` at `PCH_71_FROM_unknown+0x0`, pointing to dynamically loaded code rather than any system DLL.

```
Sig[6].Value=c0000005
Sig[7].Value=PCH_71_FROM_unknown+0x0000000000000000
```

I dug into the compiled `.o` file and found that GCC compiles the `stage_name()` switch statement into two jump tables in the `.rdata` section. These tables contain `IMAGE_REL_AMD64_REL32` relocations that point back into `.text`:

```
RELOCATION RECORDS FOR [.rdata]:
OFFSET           TYPE              VALUE
0000000000000484 IMAGE_REL_AMD64_REL32  .text
0000000000000488 IMAGE_REL_AMD64_REL32  .text
...
(64 entries total)
```

OC2's COFF loader does not apply relocations in the `.rdata` section. It handles `.text` relocations fine, which is why every other BOF I tested worked. KrbRelayBof is the only BOF I have that triggers this. GCC generated jump tables here because the switch has sparse case values (1 through 623).

With the relocations unapplied, the table entries contain the original compile-time addends (small values like 4, 8, 12). The jump table code computes `target = table_base + entry_value`, which lands inside `.rdata` itself instead of the intended case label in `.text`. That produces the access violation.

The crash happens whenever the relay fails and `go()` calls `stage_name()` to report the failure stage. The vectored exception handler does not cover the main Beacon thread (only the worker thread), so the unhandled exception terminates the process.

## Fix

I replaced the `stage_name()` switch with an if-else chain. GCC does not generate a jump table for a chain of comparisons, so the `.rdata` section no longer has any relocations.

Before (64 REL32 relocations in `.rdata`):
```
$ objdump -r krbrelay.x64.o | grep -c 'RELOCATION RECORDS FOR \[.rdata\]' -A999 | grep .text
64
```

After (no `.rdata` relocations):
```
$ objdump -r krbrelay.x64.o | grep 'RELOCATION RECORDS FOR \[.rdata\]'
(no output)
```

I also added `-fno-jump-tables` to the Makefile `CFLAGS`. That flag tells GCC not to generate jump tables anywhere in the file, so future edits to other switch statements cannot bring the problem back.

The `.text` section grew by 16 bytes (comparison chains are marginally larger than table lookups). The `.rdata` section shrank by 256 bytes (the table entries are gone). All 48 DLL imports are unchanged. Behavior is identical to the original.
