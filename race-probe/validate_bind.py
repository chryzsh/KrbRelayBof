#!/usr/bin/env python3
"""Validation: confirm a Kerberos LDAP bind as a low-priv user works against the
lab DC from this host, before building the pipelining race probe.

Creds come from the environment so they are never written to disk:
  KRBUSER, KRBPASS, KRBDOMAIN (default mayyhem.com)
  DCIP (default 10.112.0.70), DCHOST (default dc.mayyhem.com)
"""
import os
import sys

from impacket.ldap import ldap

user = os.environ["KRBUSER"]
password = os.environ["KRBPASS"]
domain = os.environ.get("KRBDOMAIN", "mayyhem.com")
dcip = os.environ.get("DCIP", "10.112.0.70")
dchost = os.environ.get("DCHOST", "dc.mayyhem.com")
base_dn = "DC=" + ",DC=".join(domain.split("."))

print(f"[*] target ldap://{dchost} ({dcip}) base {base_dn} as {domain}\\{user}")
conn = ldap.LDAPConnection(f"ldap://{dchost}", base_dn, dcip)
conn.kerberosLogin(user, password, domain, kdcHost=dcip)
print("[+] Kerberos LDAP bind succeeded")

resp = conn.search(
    searchFilter=f"(sAMAccountName={user})",
    attributes=["distinguishedName"],
)
for item in resp:
    try:
        for attr in item["attributes"]:
            if str(attr["type"]) == "distinguishedName":
                print("[+] whoami DN:", str(attr["vals"][0]))
    except Exception:
        pass
print("[+] done")
