# Race probe findings (mayyhem DC)

## What this tests

`race_probe.py` replicates the relay write-before-bind race as an ordinary
Kerberos client. It mints a no-integrity Kerberos context with impacket. It
reuses the relay PDU builders. It pipelines N modify PDUs against a single-leg
SASL bind in one TCP segment, then reads each operation result code. result=1
means the write was processed before the bind committed. Any other code means
the write was processed after the bind committed.

Run it as a low-privilege user against the lab DC (creds come from the
environment, KRBUSER and KRBPASS):

```
python race_probe.py --order mb --count 2
```

## Results against dc.mayyhem.com (Server 2022, 20348.5622)

- Race, writes then bind, one segment. Every write returns result=1. This holds
  at padding counts 2, 8, 32, 64, 128, and 512, across repeated runs. No write
  ever lands after the bind. The race does not win on this DC at any padding.
- No-integrity context, bind then write. The write is processed after the bind.
  It returns a normal post-bind code, a value or access error, not result=1 and
  not a reset. So when the context carries no integrity, this DC accepts an
  unsigned post-bind write.

## Conclusion

The blocker on this DC is the context integrity flag, not the race. This DC
processes one connection's pipelined requests in byte order. A write placed
before the bind is always processed first. It fails with result=1. Padding
cannot move a write after the bind, because the bind is last in the stream. The
author's DCs must process one connection concurrently. That is what lets a
padded write land after the bind there.

When the Kerberos context carries no integrity and the write follows the bind,
the write does land on this DC. That is the direct-kerberos post-bind path, not
the race. So the path that works here is a level-2 (no integrity) context plus a
normal bind-then-write. The open problem moves to getting a level-2 context on
the victim. AxInstSv gives level 2 on Windows 11. On a Server 2022 victim the
coerced context came back at packet integrity (level 5). See the
`exp/direct-kerberos` branch.
