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

## Progress

| Category | Solved / total |
|---|---|
| Warm-up | 4 / 4 |
| Email | 4 / 4 |
| Logs | 0 / 6 |
| Network | 0 / 6 |
| Disk | 0 / 5 |
| Hunt | 0 / 3 |
| OSINT | 1 / 1 |
| Encoding | 0 / 1 |
| Memory | 0 / 2 (bonus) |

*(Updated as challenges are solved.)*
