# CTF W6 — 32-challenge CTFd (solo)

A standalone CTF, not tied to one specific prior mission — 32 challenges on CTFd
(`http://10.50.0.240:8000/`) across nine categories: Warm-up, Email, Logs, Network,
Disk, Hunt, OSINT, Encoding, Memory. All evidence is served read-only from
`http://10.50.0.1:8080/` (see `TOOLKIT.md` there for the recommended tool per
evidence type, cross-platform).

Played solo — helping other students is allowed, but flags are never shared.
**Write-ups are the actual deliverable here, not the CTFd leaderboard.**

## Evidence files and which category they belong to

| File | Category |
|---|---|
| `maildir.zip` (22 `.eml`) | Email |
| `Security_tir.evtx`, `Microsoft-Windows-Sysmon_Operational_tir.evtx`, `Microsoft-Windows-PowerShell_Operational_tir.evtx`, `Microsoft-Windows-TaskScheduler_Operational_tir.evtx` | Logs |
| `Security_DC01_tir.evtx` | Hunt |
| `ctf_fire_dns.pcap` | Network |
| `MFT_ctf_post_tir.raw`, `POWERSHELL.EXE-CA1AE517.pf`, `zone_identifier.txt` | Disk |
| `stage2.b64.txt` | Encoding |
| `DN-5583_verhaegen.pdf` | OSINT |
| `ctf_post_tir_20261113.mem` (~4 GB) | Memory (bonus — downloaded only if attempted) |
| — | Warm-up (CyberChef only, no download) |

## Folder contents

| File/folder | What's in it |
|---|---|
| [writeups/warmup.md](writeups/warmup.md) | Warm-up category — all 4 challenges, CyberChef-style decoding done via equivalent one-line Python for each |
| [writeups/email.md](writeups/email.md) | Email category — all 4 challenges, spotting the two malicious messages in `maildir.zip` and reading their headers |
| [writeups/osint.md](writeups/osint.md) | OSINT category — the one challenge, reading `/Author` out of the PDF's raw `/Info` dictionary |
| [writeups/logs.md](writeups/logs.md) | Logs category — all 6 challenges, separating the `\CoachOrchestration\` lab scaffold from the real `\Microsoft\Windows\SyncHelper\Refresh` persistence/beacon task, found via `strings -el` on the exported `.evtx` files |
| [writeups/network.md](writeups/network.md) | Network category — all 6 challenges, separating the `b.` DNS beacon channel from the `x.` Base32 DNS-exfil channel in `ctf_fire_dns.pcap`, then correlating a beacon query's PID back to the Sysmon log via raw `.evtx` byte offsets |
| [writeups/disk.md](writeups/disk.md) | Disk category — all 5 challenges, including a from-scratch XPRESS/MS-XCA Huffman decompressor for the compressed Prefetch file and a hand-rolled `$MFT` record parser for the timestomping check |

## Progress

| Category | Solved / total |
|---|---|
| Warm-up | 4 / 4 |
| Email | 4 / 4 |
| Logs | 6 / 6 |
| Network | 6 / 6 |
| Disk | 5 / 5 |
| Hunt | 0 / 3 |
| OSINT | 1 / 1 |
| Encoding | 0 / 1 |
| Memory | 0 / 2 (bonus) |

*(Updated as challenges are solved.)*
