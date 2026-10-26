# Mission 03: Locked out

A second intrusion happened on my workstation (WKS-L58): I lost my own access, and the job is to get back in, work out how the attacker got there first, and recover what they staged. Most of this mission happens off the workstation — on my own attack machine over Tailscale — because scanning, SMB enumeration and credential decryption aren't things Sentinel can see. Only the pieces that touch WKS-L58 itself (the RDP reconnection, the lockout-era failed logons, the anonymous SMB access) will show up in my Sentinel workspace.

| File | What's in it |
|---|---|
| [notes.md](notes.md) | My working notes: each step (recon, SMB enumeration, GPP credential recovery, RDP reconnection, artifact retrieval) with what I ran, what I found, and — where Sentinel can see it — the matching KQL |
| [case-file.md](case-file.md) | The hand-in: dual-audience summary, timeline, MITRE ATT&CK mapping, control gaps mapped to ISO 27001 Annex A / NIS2, and the data-breach notification assessment for the staged data |
| [queries.kql](queries.kql) | Every KQL query I ran in Sentinel for the parts of this that are workstation-visible |

**Status: in progress.** Host confirmed (`10.50.0.58`, reached via a Tailscale subnet route into `hamilton.corp`), port scan done (SMB 445 + RDP 3389 open), anonymous SMB enumeration finds a `Public` share — but reading it is denied under every anonymous/guest method tried. Blocked and waiting on a reply from the coach before continuing past Step 2.

**Handling note:** this mission surfaces a real decrypted credential and a real Sentinel password. Neither goes into this public repo in plaintext — see the redaction note in `notes.md` and `case-file.md`. The Sentinel credential gets rotated before it's used for anything beyond proving access.
