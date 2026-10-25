# Windows Local Password Audit / Recovery Toolkit

Small, offline toolkit to recover or audit a **local** Windows account password on a
machine you own or are explicitly authorized to service.

It reads the local SAM (read-only), extracts the NTLM hash, and tests candidate
passwords against it locally. Nothing is sent anywhere.

> **Authorized use only.** Running this on a device without the owner's permission is
> unauthorized access (e.g. IT Act 2000 s.66, CFAA). NTLM hashes cannot be "decrypted" —
> only guessed, so results depend entirely on the candidate list.

---

## Files

| File | What it does |
|---|---|
| `dump_sam.ps1` | Elevated one-shot export of the SAM/LSA registry blobs. Tries the current admin session, then a temporary SYSTEM scheduled task. Writes `sam_dump.json`. |
| `collect_blobs.ps1` | Helper used by `dump_sam.ps1`; reads the registry blobs under SYSTEM. |
| `extract_hash.py` | Derives the boot key, decrypts user hashes and writes a hex NTLM hash store (`passstore.txt`). |
| `check_password.py` | Tests passwords typed at the prompt (or a `--store`/`--hash`) against the stored hash. |
| `fastcrack.exe` | Multi-threaded C# cracker (~21M NTLM/s on a modern CPU). |
| `fastcrack.cs` | Source for the above. |

Requirements: Windows 10/11, .NET Framework 4.x, Python 3.9+ (stdlib only), and
**Administrator** rights for the SAM dump step.

---

## Workflow

```powershell
# 1. Export SAM blobs (approve the UAC prompt)
powershell -NoProfile -ExecutionPolicy Bypass -File .\dump_sam.ps1

# 2. Extract the hash for a user (repeat per account)
python .\extract_hash.py --dump sam_dump.json --user USERNAME --store passstore.txt --show

# 3. Optionally delete the raw dump once the hash is stored
Remove-Item sam_dump.json
```

`extract_hash.py` self-test:

```powershell
python .\extract_hash.py --selftest
```

---

## Checking guesses

Interactive (unlimited attempts, visible typing by default):

```powershell
python .\check_password.py --store passstore.txt
python .\check_password.py --store passstore.txt --hidden      # masked input
python .\check_password.py --hash 4f80... --attempts 5         # limit attempts
```

Note: `--store` writes/reads `passstore.txt`; `--show` also prints the hash.
Delete `passstore.txt` when you are done — it is a credential.

---

## fastcrack usage

```
fastcrack.exe <32-hex NTLM hash> <mode> [args]
```

| Mode | Command | Notes |
|---|---|---|
| stdin | `fastcrack.exe HASH` | one candidate per line on stdin (slowest; use for pipelines) |
| dict | `fastcrack.exe HASH dict words.txt` | plain dictionary |
| sweep | `fastcrack.exe HASH sweep "word1,word2" "@,#,." 6` | word + separator + 1..6 digits |
| hybrid | `fastcrack.exe HASH hybrid "base1,base2" "abc123" 16` | inserts up to 3 chars anywhere in each base |
| brute | `fastcrack.exe HASH brute "abc123" 8` | full keyspace up to given length |

It prints `done <mode> <count> sec <s>` on completion and exits non-zero on a match,
printing the recovered password.

Rebuild after editing the source:

```powershell
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /optimize+ `
  /out:"fastcrack.exe" "fastcrack.cs"
```

---

## Reality check on cracking

- NTLM = `MD4(UTF-16LE(password))` — one-way, no decryption key exists.
- An 8+ character mixed-charset password is not brute-forceable on a CPU; only
  dictionary/rule/pattern attacks are realistic. GPU (hashcat `-m 1000`) is ~1000x faster.
- Offline comparison never triggers account lockout, unlike online guessing.

---

## If you are locked out

Prefer, in order:

1. Reset from another **admin** account: `net user USERNAME NewPassword`
   (a reset, not a change — no old password required).
2. Bootable Linux + `chntpw`, or Windows recovery media.
3. Known plaintext recovery: Wi-Fi PSKs, browsers, credential stores — this toolkit's
   hash is only useful if the same password is reused there.

**Reset vs change:** a reset invalidates DPAPI master keys, so EFS files, saved browser
logins and some app/VPN tokens tied to the old password may become inaccessible unless a
recovery mechanism (recovery key or backup) is available. Normal files, photos and
TPM-only BitLocker are unaffected. A "change" (requires the old password) re-encrypts
those keys and loses nothing.

Always verify a new password **before** ending the session (lock the screen and sign in),
and keep a working admin account until you have done so.

---

## Hygiene

- Never commit `passstore.txt`, `sam_dump.json`, or wordlists to git.
- Don't upload a real hash to online "decrypt" sites — they only run dictionaries and may
  retain it. Use local wordlists instead.
- Remove the toolkit and any hash store from a client machine when the job is done.
