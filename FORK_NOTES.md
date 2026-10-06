# KrbRelayBof Fork

## Upstream

- Repo: https://github.com/antroguy/KrbRelayBof
- Remote: `upstream`

## Purpose

Fork for testing, extending, and fixing the KrbRelayBof Kerberos COM relay.
Changes fall into three areas: auth-type variants (Negotiate vs Kerberos),
relay bridge plumbing (direct connections without rportfwd_local), and
diagnostic tooling (fingerprint scripts, survey BOFs).

## Branches

### `main`
Tracks upstream. No local changes.

### `exp/direct-kerberos`
Forces Kerberos (auth type 16) at four sites in the BOF: the OBJREF
security binding, the persistent SOLE_AUTHENTICATION_SERVICE, the
CoInitializeSecurity call, and RpcServerRegisterAuthInfoW. Also adds
diagnostic output and the optional-CLSID CNA parameter. Pushed.

### `exp/negotiate`
Parallel to exp/direct-kerberos but uses Negotiate (auth type 9) instead
of Kerberos. Contains three additional fixes:

1. **Configurable relay_host in the CNA.** The dev's main hardcodes
   `127.0.0.1` as the relay host, which requires `rportfwd_local` (a
   Cobalt Strike feature not available in all setups). The CNA now accepts
   an optional `relay_host` argument so the BOF can connect directly to a
   remote relay.

2. **rportfwd deadlock fix.** `beacon_inline_execute` runs the BOF on the
   beacon thread. The BOF sends data through an rportfwd socket and then
   blocks on `recv()`. The beacon cannot forward the rportfwd data through
   the C2 channel because the BOF holds the thread. The BOF waits for a
   response that the beacon cannot deliver. The 30-second
   `BRIDGE_IO_TIMEOUT_MS` recv timeout expires, the thread unblocks, and
   the beacon processes the buffered data. The relay sees the connection
   arrive too late. Even with sleep 0 this deadlock occurs because the
   inline BOF never yields the thread. The configurable relay_host
   bypasses this: a direct TCP socket does not need the beacon thread.

3. **Sleep/Aggressor null-equality bug.** Two CNA disambiguation approaches
   failed before the working one:
   - `hasmatch '{.*}'` silently fails because `{` is a regex quantifier
     character in Sleep's Java regex engine.
   - `indexOf($5, "{") == 0` misidentifies every input as a CLSID.
     If the substring is not found, Sleep's `indexOf` returns `$null`.
     `$null == 0` evaluates to true because of Sleep's type coercion.
   - Working fix: `substr($5, 0, 1) eq "{"` performs a string comparison
     that is not affected by null coercion.

Also adds `standalone/krbrelay-neg.c`, the Negotiate standalone source
alongside the original type-16 `krbrelay.c`. Pushed.

### `exp/ntlm-downgrade`
NTLM downgrade experiment. Pushed.

### `exp/race-probe`
Race-condition probe experiment. Pushed.

### `fix/jump-table-crash`
Jump table crash fix. Pushed.

### `standalone-exe`
Standalone exe variant with lab findings writeup. Pushed.
