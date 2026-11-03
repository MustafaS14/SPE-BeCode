# Mission 04: A service account goes rogue

First mission of the blue specialisation. A service account (normally used only to run a background service, never to sign in like a person) was used on my own workstation inside a window my coach gave me — as if someone had taken it over. Job: reconstruct from my own Sentinel what it did, what it took, and whether it's still in. Stage 0 (how the account's password was actually stolen — Kerberoasting, against the domain controller) happened off my workstation and is reasoned from the mission brief, not observed; my Sentinel doesn't watch the DC yet.

| File | What's in it |
|---|---|
| [notes.md](notes.md) | My working notes: each step with what I ran, what I found, and the matching KQL where Sentinel can see it |
| [case-file.md](case-file.md) | The hand-in: built from the mission's `CASE_FILE_TEMPLATE.md` — dual-audience (manager + technician), MITRE ATT&CK mapping, impact/containment, remediation |
| [queries.kql](queries.kql) | Every KQL query run in Sentinel for this mission |

**Status: just started.** Waiting on the mission window from my coach before running real queries. Three CTFd flags for this mission: "Recon" (50 pts, the service account's SPN/service type), "Data staged" (100 pts), "Persistence" (150 pts).

**Handling note:** same redaction rule as Mission 3 — no real credential, password, or flag value goes into this public repo in plaintext.
