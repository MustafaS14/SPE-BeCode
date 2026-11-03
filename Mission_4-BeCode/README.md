# Mission 04: A service account goes rogue

First mission of the blue specialisation. A service account (normally used only to run a background service, never to sign in like a person) was used on my own workstation inside a window my coach gave me — as if someone had taken it over. Job: reconstruct from my own Sentinel what it did, what it took, and whether it's still in. Stage 0 (how the account's password was actually stolen — Kerberoasting, against the domain controller) happened off my workstation and is reasoned from the mission brief, not observed; my Sentinel doesn't watch the DC yet.

| File | What's in it |
|---|---|
| [notes.md](notes.md) | My working notes: each step with what I ran, what I found, and the matching KQL where Sentinel can see it |
| [case-file.md](case-file.md) | The hand-in: built from the mission's `CASE_FILE_TEMPLATE.md` — dual-audience (manager + technician), MITRE ATT&CK mapping, impact/containment, remediation |
| [queries.kql](queries.kql) | Every KQL query run in Sentinel for this mission |

**Status: done — all four steps complete, all three CTFd flags submitted.** `svc-app58` was Kerberoasted (reasoned, not observed — happens against the DC), then used to run a recon burst on WKS-L58, stage a small customer-data cache, and plant a 15-minute recurring scheduled task for persistence — still active at the time of investigation. "Recon" (50 pts, the account's SPN service class, `MSSQLSvc`), "Data staged" (100 pts), and "Persistence" (150 pts) all solved.

**Handling note:** same redaction rule as Mission 3 — no real credential or password goes into this public repo in plaintext. CTFd flag strings (e.g. `HAM{...}`) are written out as proof-of-solve, same convention as every prior mission.
