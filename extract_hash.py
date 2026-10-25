#!/usr/bin/env python3
"""Turn the one-time SAM blob export into a local NTLM hash store.

Input : %USERPROFILE%\\sam_dump.json   (written by dump_sam.ps1)
Output: passstore.txt                  (hex NTLM hash, used by check_password.py)

Nothing here authenticates anywhere. It is pure local decryption of data
that already lives on this machine.

Format reference: pypykatz (Tamas Jos) registry/sam. Structures used:
  DOMAIN_ACCOUNT_F key_0          @ 0x68  (rev==2 -> SAM_KEY_DATA_AES)
  SAM_KEY_DATA_AES                rev,len,chk_len,data_len,salt,data
  USER_ACCOUNT_V                  NT hash offset @ 0xA8, data area @ 0xCC
  SAM_HASH_AES                    pekID,rev,offset,salt,data
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES, ARC4, DES

TRANSFORMS = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
DIGITS = b"0123456789012345678901234567890123456789\0"
NTPASSWORD = b"NTPASSWORD\0"
LMPASSWORD = b"LMPASSWORD\0"
SAM_DATA_START = 0xCC
NT_OFF_OFFSET, NT_LEN_OFFSET = 0xA8, 0xAC
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


class ExtractError(RuntimeError):
    pass


def permute_bootkey(classes: dict[str, str]) -> bytes:
    blob = "".join(classes[k] for k in ("JD", "Skew1", "GBG", "Data"))
    blob = "".join(c for c in blob if c in "0123456789abcdefABCDEF")
    raw = bytes.fromhex(blob)
    if len(raw) != 16:
        raise ExtractError(f"bootkey material is {len(raw)} bytes, expected 16")
    return bytes(raw[t] for t in TRANSFORMS)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ExtractError(f"AES payload length {len(data)} is not a block multiple")
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def hashed_bootkey(f_bytes: bytes, bootkey: bytes) -> tuple[bytes, str]:
    revision = struct.unpack_from("<I", f_bytes, 0x68)[0]

    if revision == 2:  # AES (Vista+ newer builds / Win10-11)
        data_len = struct.unpack_from("<I", f_bytes, 0x74)[0]
        salt = f_bytes[0x78:0x88]
        data = f_bytes[0x88:0x88 + data_len]
        hb = _aes_cbc_decrypt(bootkey, salt, data)
        return hb, "aes"

    if revision == 1:  # legacy RC4
        salt = f_bytes[0x78:0x88]
        key = f_bytes[0x88:0x98]
        checksum = f_bytes[0x98:0xA8]
        rc4_key = hashlib.md5(salt + QWERTY + bootkey + DIGITS).digest()
        hb = ARC4.new(rc4_key).encrypt(key + checksum)
        expect = hashlib.md5(hb[:16] + DIGITS + hb[:16] + QWERTY).digest()
        if expect != hb[16:]:
            raise ExtractError("hashed bootkey checksum mismatch")
        return hb, "rc4"

    raise ExtractError(f"unsupported DOMAIN_ACCOUNT_F revision {revision}")


def expand_des_key(k7: bytes) -> bytes:
    return bytes([
        k7[0] & 0xFE,
        ((k7[0] << 7) | (k7[1] >> 1)) & 0xFE,
        ((k7[1] << 6) | (k7[2] >> 2)) & 0xFE,
        ((k7[2] << 5) | (k7[3] >> 3)) & 0xFE,
        ((k7[3] << 4) | (k7[4] >> 4)) & 0xFE,
        ((k7[4] << 3) | (k7[5] >> 5)) & 0xFE,
        ((k7[5] << 2) | (k7[6] >> 6)) & 0xFE,
        (k7[6] << 1) & 0xFE,
    ])


def rid_to_keys(rid: int) -> tuple[bytes, bytes]:
    k = rid.to_bytes(4, "little")
    key1 = bytes([k[0], k[1], k[2], k[3], k[0], k[1], k[2]])
    key2 = bytes([k[3], k[0], k[1], k[2], k[3], k[0], k[1]])
    return expand_des_key(key1), expand_des_key(key2)


def decrypt_user_hash(rid: int, blob: bytes, hb: bytes, mode: str) -> bytes:
    revision = blob[2]
    if revision == 1:  # legacy SAM_HASH: pek(2) rev(2) hash(16)
        enc = blob[4:20]
        rc4_key = hashlib.md5(hb[:16] + rid.to_bytes(4, "little") + NTPASSWORD).digest()
        key = ARC4.new(rc4_key).encrypt(enc)
    else:              # SAM_HASH_AES: pek(2) rev(2) off(4) salt(16) data(16)
        salt = blob[8:24]
        data = blob[24:]
        key = _aes_cbc_decrypt(hb[:16], salt, data)[:16]

    k1, k2 = rid_to_keys(rid)
    return DES.new(k1, DES.MODE_ECB).decrypt(key[:8]) + DES.new(k2, DES.MODE_ECB).decrypt(key[8:16])


def username_from_v(v: bytes) -> str | None:
    off, length = struct.unpack_from("<II", v, 0x0C)
    if not length:
        return None
    start = SAM_DATA_START + off
    raw = v[start:start + length]
    return raw.decode("utf-16-le", errors="ignore")


def extract(dump: dict, wanted: str | None) -> tuple[str, int, str, str]:
    bootkey = permute_bootkey(dump["classes"])
    f_bytes = base64.b64decode(dump["F"])
    hb, mode = hashed_bootkey(f_bytes, bootkey)

    found = []
    for entry in dump["users"]:
        v = base64.b64decode(entry["V"])
        rid = int(entry["rid"], 16)
        name = username_from_v(v)
        off, length = struct.unpack_from("<II", v, NT_OFF_OFFSET)
        if not length:
            nt = EMPTY_NT
        else:
            blob = v[SAM_DATA_START + off: SAM_DATA_START + off + length]
            if len(blob) <= 24:
                nt = EMPTY_NT          # header only: no hash stored
            else:
                nt = decrypt_user_hash(rid, blob, hb, mode).hex().lower()
        found.append((name or f"RID-{rid}", rid, entry["rid"], nt))

    if not found:
        raise ExtractError("no user hash records found in dump")

    if wanted:
        matches = [f for f in found if f[0].lower() == wanted.lower()]
        if not matches:
            names = ", ".join(sorted({f[0] for f in found}))
            raise ExtractError(f"user '{wanted}' not found. Available: {names}")
        row = matches[0]
    else:
        row = sorted(found, key=lambda r: r[1])[-1]
    return row[0], row[1], row[2], row[3]


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert sam_dump.json into a local NTLM hash store.")
    ap.add_argument("--dump", default=str(Path(__file__).resolve().parent / "sam_dump.json"))
    ap.add_argument("--user", default=os.environ.get("USERNAME"))
    ap.add_argument("--store", default=str(Path(__file__).resolve().parent / "passstore.txt"))
    ap.add_argument("--show", action="store_true", help="print the hash as well as storing it")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    path = Path(args.dump)
    if not path.is_file():
        print(f"Dump not found: {path}\nRun dump_sam.ps1 from an elevated PowerShell first.", file=sys.stderr)
        return 1

    dump = json.loads(path.read_text(encoding="utf-8-sig"))
    name, rid, rid_hex, nt = extract(dump, args.user)

    Path(args.store).write_text(nt + "\n", encoding="ascii")
    print(f"User       : {name} (RID {rid}, 0x{rid_hex})")
    print(f"NT hash    : {nt}" if args.show else "NT hash    : stored (use --show to print)")
    if nt == EMPTY_NT:
        print("Note       : this is the EMPTY-password hash - the account has no password set.")
    print(f"Saved to   : {Path(args.store).resolve()}")
    print(f"Compare    : python check_password.py --store {Path(args.store).name}")
    return 0


# --------------------------------------------------------------------- self-test
def _build_fake_dump(nt_hex: str) -> tuple[dict, bytes]:
    bootkey = bytes(range(16))
    obf = bytearray(16)
    for i, t in enumerate(TRANSFORMS):
        obf[t] = bootkey[i]
    classes = {
        "JD": obf[0:4].hex(), "Skew1": obf[4:8].hex(),
        "GBG": obf[8:12].hex(), "Data": obf[12:16].hex(),
    }

    hb = bytes((i * 7 + 3) & 0xFF for i in range(48))
    salt_f = bytes(range(0x40, 0x50))
    enc_f = AES.new(bootkey, AES.MODE_CBC, salt_f).encrypt(hb)
    f_bytes = bytearray(0x88 + len(enc_f))
    struct.pack_into("<I", f_bytes, 0x68, 2)
    struct.pack_into("<I", f_bytes, 0x6C, 0x30)
    struct.pack_into("<I", f_bytes, 0x70, 0x10)
    struct.pack_into("<I", f_bytes, 0x74, len(enc_f))
    f_bytes[0x78:0x88] = salt_f
    f_bytes[0x88:0x88 + len(enc_f)] = enc_f

    rid = 0x3E9
    nt = bytes.fromhex(nt_hex)
    k1, k2 = rid_to_keys(rid)
    material = DES.new(k1, DES.MODE_ECB).encrypt(nt[:8]) + DES.new(k2, DES.MODE_ECB).encrypt(nt[8:])
    salt_u = bytes(range(0x10, 0x20))
    enc_u = AES.new(hb[:16], AES.MODE_CBC, salt_u).encrypt(material)
    blob = b"\x02\x00" + b"\x02\x00" + struct.pack("<I", 0) + salt_u + enc_u

    name = "Tester".encode("utf-16-le")
    v = bytearray(SAM_DATA_START + len(blob) + len(name))
    struct.pack_into("<II", v, 0x0C, len(blob), len(name))
    v[SAM_DATA_START + len(blob):] = name
    struct.pack_into("<II", v, NT_OFF_OFFSET, 0, len(blob))
    v[SAM_DATA_START:SAM_DATA_START + len(blob)] = blob

    dump = {
        "classes": classes,
        "F": base64.b64encode(bytes(f_bytes)).decode(),
        "users": [{"rid": f"{rid:08X}", "V": base64.b64encode(bytes(v)).decode()}],
    }
    return dump, bootkey


def selftest() -> int:
    target = "8846f7eaee8fb117ad06bdd830b7586c"
    dump, _ = _build_fake_dump(target)
    name, rid, _, got = extract(dump, "Tester")
    ok = got == target and name == "Tester" and rid == 0x3E9
    print("round-trip self-test:", "PASS" if ok else f"FAIL (got {got})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
