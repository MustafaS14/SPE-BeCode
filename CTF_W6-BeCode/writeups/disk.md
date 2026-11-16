# CTF W6 · Disk — write-up

**Evidence:** `MFT_ctf_post_tir.raw` (a raw `$MFT` dump, ~475 MB),
`POWERSHELL.EXE-CA1AE517.pf` (a Windows Prefetch file), and
`zone_identifier.txt` (the NTFS `Zone.Identifier` alternate data stream
captured off the phishing ZIP) — all for the same `HAMILTON\lmartens`
workstation and the `SyncHelper` persistence seen in the Logs category.

No forensics suite was available offline, so each artifact was parsed by
hand against its published binary format (MFT record / `$STANDARD_INFORMATION`
and `$FILE_NAME` attributes, the Prefetch `SCCA` header, and MS-XCA/XPRESS
Huffman decompression) with small from-scratch Python scripts.

## Run value (50 pts)

**Ask:** what is the name of the Run registry value the attacker added for
persistence?

Reusing the `strings -el` dumps from the Logs category (`sysmon_strings.txt`
/ `ps_strings.txt`), the `drop_persist.ps1` script-block content that writes
the registry Run key is visible in plaintext as a PowerShell command setting
a value under `HKCU\...\CurrentVersion\Run`.

**Flag:** `OneDriveSyncHelper`

## Stage 2 path (50 pts)

**Ask:** what is the full path of the dropped second-stage script?

Same dumps show the actual payload path the Run value points at and that
`drop_persist.ps1` writes to disk:

**Flag:** `C:\Users\lmartens\AppData\Roaming\Microsoft\SyncHelper\synchelper.ps1`

## ZIP origin URL (100 pts)

**Ask:** (evidence: `zone_identifier.txt`, the ZIP's Mark-of-the-Web) what
URL did the ZIP come from?

`zone_identifier.txt` is the raw `Zone.Identifier` NTFS alternate data
stream Windows attaches to internet-downloaded files
(`C:\Users\lmartens\Downloads\INV-2026-1147.zip:Zone.Identifier`):

```ini
[ZoneTransfer]
ZoneId=3
HostUrl=https://verhaegen-packagings.test/invoices/INV-2026-1147.zip
ReferrerUrl=https://verhaegen-packagings.test/
```

Same typosquatted domain (`verhaegen-packagings.test`, extra **s**) as the
BEC email in the Email category.

**Flag:** `https://verhaegen-packagings.test/invoices/INV-2026-1147.zip`

## PowerShell execution count (150 pts)

**Ask:** (evidence: `POWERSHELL.EXE-CA1AE517.pf`) how many times was
`powershell.exe` executed on the host?

Windows 10/11 Prefetch files (signature `SCCA`, version 30/0x1E) store the
file's `RunCount` as a plain 4-byte integer in the uncompressed
`FILE_INFORMATION` header — but newer Prefetch files are stored
MS-XCA/XPRESS-Huffman-compressed (signature `MAM\x04` + a 4-byte
decompressed size at offset 4), and no decompression library was available
offline. Wrote a small from-scratch XPRESS Huffman decoder (canonical
Huffman codes built from the embedded 512 four-bit code-length table,
LZ77-style back-references for symbols 256–511) to recover the raw
`SCCA`-signed Prefetch bytes.

With the decompressed file in hand, the `LastRunTime` array (eight 8-byte
`FILETIME`s) was located empirically — the offset that makes all eight
slots decode to sane 2020s dates is `0x80`, not the more commonly cited
`0x98`/`0x90` for this Prefetch version — putting an 8-byte unknown field
right after it (ending at `0xC0`) and `RunCount` as a 4-byte `uint32` at
`0xC8`:

```python
run_count = struct.unpack('<I', decompressed[0xC8:0xCC])[0]  # -> 32
```

**Flag:** `32`

## Timestomping check (150 pts)

**Ask:** (evidence: `MFT_ctf_post_tir.raw`) for the persistence folder
`Users\lmartens\AppData\Roaming\Microsoft\SyncHelper`, compare the
`$STANDARD_INFORMATION` and `$FILE_NAME` creation times. If they match (no
timestomping), submit that shared time in UTC; if they differ, submit the
`$FILE_NAME` time (since `$FILE_NAME` timestamps live in the `$MFT`'s index
attribute and aren't touched by ordinary `SetFileTime`-based timestomping
tools, unlike `$STANDARD_INFORMATION`).

Parsed the raw `$MFT` 1024-byte record by record (`FILE` signature, walking
the attribute list from the header's first-attribute offset), matching
every record whose `$FILE_NAME` attribute decodes to `SyncHelper`. Several
decoys exist (a `SyncHelper` folder under `C:\Windows\...` and multiple
`FileSyncHelper.exe` binaries elsewhere), so the one that matters is the one
whose parent chain actually resolves to `...\Microsoft\...`
(`AppData\Roaming\Microsoft\SyncHelper`, record parent `MICROS~1`/`Microsoft`,
itself parented under `Windows`... — traced via each record's `$FILE_NAME`
parent reference):

```
record 31240, flags 0x3 (directory, in use)
  SI crtime: 2026-11-12 08:26:00.551
  FN crtime: 2026-11-12 08:26:00.551
```

`$STANDARD_INFORMATION` and `$FILE_NAME` creation times match exactly — no
timestomping on this folder — and the shared time lines up with the
`drop_persist.ps1` execution / scheduled-task-creation timestamp already
found in the Logs category.

**Flag:** `2026-11-12 08:26:00`

---

All five submitted and accepted on CTFd (500 pts total for the category).
