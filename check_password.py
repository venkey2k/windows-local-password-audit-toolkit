#!/usr/bin/env python3
"""Verify whether a candidate password matches the current Windows account.

Two modes:

  offline : if an NTLM hash is supplied (--hash or passstore.txt), the
            candidate is hashed locally and compared. No logon call at all,
            so there is zero lockout risk.
  online  : otherwise a single LogonUser() check is made (default 1 attempt).
            The script refuses to run near the account's lockout threshold.

Passwords are read hidden and never written to disk or printed.
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import os
import re
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

MASK = 0xFFFFFFFF


# --------------------------------------------------------------------------- MD4
def _rotl(x: int, n: int) -> int:
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | ((~x & MASK) & z)


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def md4(data: bytes) -> bytes:
    msg = bytearray(data)
    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bitlen.to_bytes(8, "little")

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def step(fn, target, x, y, z, k, s, const=0):
        return _rotl(target + fn(x, y, z) + k + const, s)

    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + i * 4: off + i * 4 + 4], "little") for i in range(16)]
        aa, bb, cc, dd = a, b, c, d

        order1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        for i in range(0, 16, 4):
            a = step(_f, a, b, c, d, x[order1[i]], 3)
            d = step(_f, d, a, b, c, x[order1[i + 1]], 7)
            c = step(_f, c, d, a, b, x[order1[i + 2]], 11)
            b = step(_f, b, c, d, a, x[order1[i + 3]], 19)

        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(0, 16, 4):
            a = step(_g, a, b, c, d, x[order2[i]], 3, 0x5A827999)
            d = step(_g, d, a, b, c, x[order2[i + 1]], 5, 0x5A827999)
            c = step(_g, c, d, a, b, x[order2[i + 2]], 9, 0x5A827999)
            b = step(_g, b, c, d, a, x[order2[i + 3]], 13, 0x5A827999)

        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(0, 16, 4):
            a = step(_h, a, b, c, d, x[order3[i]], 3, 0x6ED9EBA1)
            d = step(_h, d, a, b, c, x[order3[i + 1]], 9, 0x6ED9EBA1)
            c = step(_h, c, d, a, b, x[order3[i + 2]], 11, 0x6ED9EBA1)
            b = step(_h, b, c, d, a, x[order3[i + 3]], 15, 0x6ED9EBA1)

        a = (a + aa) & MASK
        b = (b + bb) & MASK
        c = (c + cc) & MASK
        d = (d + dd) & MASK

    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def ntlm_hash(password: str) -> str:
    return md4(password.encode("utf-16-le")).hex()


def self_test() -> bool:
    vectors = {
        b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
        b"a": "bde52cb31de33e46245e05fbdbd6fb24",
        b"abc": "a448017aaf21d8525fc10ae87aa6729d",
        b"message digest": "d9130a8164549fe818874806e1c7014b",
        b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
    }
    return (
        all(md4(k).hex() == v for k, v in vectors.items())
        and ntlm_hash("password") == "8846f7eaee8fb117ad06bdd830b7586c"
    )


# ------------------------------------------------------------------ credential check
LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0


def _setup_winapi():
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.LogonUserW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.LogonUserW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return advapi32, kernel32


def check_online(user: str, domain: str, password: str) -> tuple[bool, str]:
    advapi32, kernel32 = _setup_winapi()
    token = wintypes.HANDLE()
    ok = advapi32.LogonUserW(
        user, domain, password,
        LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(token),
    )
    if ok:
        kernel32.CloseHandle(token)
        return True, "ok"
    err = ctypes.get_last_error()
    return False, f"win32 error {err}: {ctypes.FormatError(err)}"


def lockout_threshold() -> int:
    try:
        out = subprocess.run(
            ["net", "accounts"], capture_output=True, text=True, timeout=15
        ).stdout
    except Exception:
        return 0
    m = re.search(r"Lockout threshold:\s+(\d+)", out)
    return int(m.group(1)) if m else 0


def load_store(path: Path) -> str | None:
    if not path.is_file():
        return None
    m = re.search(r"\b([0-9a-fA-F]{32})\b", path.read_text(encoding="utf-8", errors="ignore"))
    return m.group(1).lower() if m else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Check a candidate password against this Windows account.")
    ap.add_argument("--hash", help="NTLM hash (32 hex chars) for a fully offline compare")
    ap.add_argument("--store", default="passstore.txt", help="file holding an NTLM hash for offline compare")
    ap.add_argument("--attempts", type=int, default=1, help="max online attempts (default 1)")
    ap.add_argument("--hidden", action="store_true", help="hide typing (default: visible in offline mode)")
    ap.add_argument("--selftest", action="store_true", help="run MD4 self-tests and exit")
    args = ap.parse_args()

    if args.selftest:
        ok = self_test()
        print("MD4 self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1

    if not self_test():
        print("Internal MD4 self-test failed; refusing to run.", file=sys.stderr)
        return 1

    target = args.hash or load_store(Path(args.store))
    mode = "OFFLINE (hash compare, no logon)" if target else "ONLINE (single credential check)"
    print(f"Mode    : {mode}")
    print(f"Account : {os.environ.get('COMPUTERNAME')}\\{os.environ.get('USERNAME')}")

    threshold = 0
    if not target:
        threshold = lockout_threshold()
        print(f"Lockout : {'never' if threshold == 0 else f'{threshold} tries / 10 min'}")
    print()

    if target:
        reader = getpass.getpass if args.hidden else input
        print("Offline mode: unlimited candidates, no lockout, no logon. Typing is visible unless --hidden. Blank line quits.\n")
        n = 0
        while True:
            try:
                pw = reader("Candidate (blank = quit): ")
            except (EOFError, KeyboardInterrupt):
                break
            if not pw:
                break
            n += 1
            if ntlm_hash(pw) == target.lower():
                print(f"\n>>> MATCHED - candidate #{n} is your current password.\n")
                return 0
            print(f">>> not a match (#{n})")
        print(f"\nNo match in {n} candidate(s).")
        return 2

    fails = 0
    for i in range(max(1, args.attempts)):
        pw = getpass.getpass("Password to test (hidden): ")
        ok, detail = check_online(os.environ.get("USERNAME", ""), os.environ.get("COMPUTERNAME", ""), pw)
        pw = ""
        if ok:
            print("\n>>> MATCHED - that is your current password.")
            return 0
        fails += 1
        print(f"\n>>> NOT MATCHED ({detail})")
        if threshold and fails >= threshold - 3:
            print("Too close to the lockout threshold. Stopping.")
            break

    left = "unknown" if not threshold else max(0, threshold - fails)
    print(f"\nNo match. Nothing was changed. Safe attempts left: {left}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
