# Mission 02: Your first intrusion

An intrusion was run against my workstation (WKS-L58) during a window the coach gave us. The job is to reconstruct it using only my own Sentinel from Mission 1. First I play attacker on my own machine to see what noise a login makes. Then I hunt the real intrusion, before and after a logging policy is switched on.

| File | What's in it |
|---|---|
| [notes.md](notes.md) | My working notes: Part 1 (labuser), the KQL warm-up, and every CTF challenge with question, hints, what I did and the answer |
| [case-file.md](case-file.md) | The hand-in: what happened on my machine from first contact to the command, backed by events, mapped to MITRE ATT&CK, with the before/after of the logging policy |
| [queries.kql](queries.kql) | Every KQL query I ran, in order |

Status: Part 1 done. Part 2: account, source and technique found and accepted (`helpdesk`, `10.50.0.100`, brute force). Still open: Proof of access, Part 3, and Part 4 (Temps 2, after the policy change).
