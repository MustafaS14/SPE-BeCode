# Case file: lockout and recovery on WKS-L58

This is the hand-in for Mission 3. Same rule as Mission 2: every claim points to an event in my own Sentinel workspace where one exists, and anything that happened off the workstation is marked as such rather than guessed at. Times are in UTC.

> Draft. TODO marks what still has to come from my own results.

## Summary

**For a manager:** TODO — three or four sentences, no jargon: what happened, what I got back, what's still exposed if we don't fix it.

**For a technician:** TODO — the actual chain: what was exposed, what let the attacker (and then me) in, what was staged on the machine, and what Sentinel could and couldn't see of it.

## Scope

| | |
|---|---|
| Machine | WKS-L58.hamilton.corp |
| My attack machine | My own laptop, connected over Tailscale |
| Evidence source | My Sentinel workspace (`SecurityEvent`) for the workstation-visible parts; my own attack-machine output for everything else |
| What Sentinel can see | Only: (1) the RDP reconnection, (2) the lockout-era failed logons, (3) the anonymous SMB access to WKS-L58. Scanning, SMB enumeration, and GPP credential decryption happen off-box and will not appear here. |

## Timeline

| Time (UTC) | What happened | Evidence |
|---|---|---|
| — | Port scan of WKS-L58 (10.50.0.58): 445 (SMB) and 3389 (RDP) open, rest filtered | Attack-machine only — not in Sentinel |
| — | Anonymous SMB share enumeration: `ADMIN$`, `C$`, `IPC$`, `Public` visible; `Public` itself denied under null session, Guest, and blank/anonymous auth. RPC via IPC$ limited to `srvinfo` only | TODO: KQL, anonymous/guest logon |
| TODO | GPP `cpassword` recovered from the share's XML — **blocked**: can't read `Public` yet, escalated to coach | Attack-machine only — not in Sentinel |
| TODO | Failed RDP attempts before the security-layer fix | TODO: 4625s, lockout-era |
| TODO | Successful RDP reconnection | TODO: 4624 type 10 |
| TODO | Artifacts retrieved (flag, Sentinel credential, data cache) | Workstation only |
| TODO | Sentinel credential rotated | N/A — action taken, not an event |

## Findings

**How the attacker (and then I) got in:** TODO — SMB share exposed with anonymous/guest read access; a Group Policy Preferences file on it contained a `cpassword` whose encryption key has been public since 2014, so it isn't real protection; that gave a working credential for RDP.

**Why this matters beyond "we got back in":** TODO — the same exposed share and the same decryptable credential is exactly what an attacker without lab-given hints would also find, which is the point of calling this a control gap rather than a one-off inconvenience.

## Two sources, one answer

| Question | Attack-machine (my own tools) | KQL (Sentinel) | What the comparison means |
|---|---|---|---|
| What was exposed? | TODO: scan + SMB listing | Nothing — out of scope | Only the attack machine could answer this; Sentinel watches the endpoint, not the network surface in front of it |
| How was the credential recovered? | TODO: GPP decrypt tool | Nothing — out of scope | Same: happens entirely off-box |
| Did WKS-L58 itself log the approach? | — | TODO: anonymous SMB logon, lockout-era 4625s | This is the one place the two sides meet: Sentinel has the workstation's side of the same event |
| Getting back in | TODO: client security-layer fix | TODO: 4624 type 10 | Agree once both are filled in — the client-side cause, the server-side effect |

## MITRE ATT&CK mapping

| Step | Tactic | Technique (ID) |
|---|---|---|
| Finding the exposed share | Reconnaissance / Discovery | TODO (e.g. Network Service Discovery, T1046) |
| Reading unprotected policy files | Credential Access | Unsecured Credentials: Group Policy Preferences (T1552.006) |
| Using the recovered credential over RDP | Lateral Movement | Remote Services: Remote Desktop Protocol (T1021.001) |
| Retrieving staged data | Exfiltration / Collection | TODO |

## Control gaps and fixes (ISO 27001 Annex A / NIS2–CyFun)

| Gap | ISO 27001 Annex A control | NIS2 / CyFun angle | Fix |
|---|---|---|---|
| SMB share allows anonymous/guest read | A.8.3 (Information access restriction) / A.5.15 (Access control) | Basic cyber hygiene — access control for ICT systems | TODO: disable anonymous/guest SMB access, require authentication |
| Credentials pushed via GPP `cpassword` | A.8.24 (Use of cryptography) / A.5.17 (Authentication information) | Supply-chain-adjacent config hygiene; known-weak crypto still in use | TODO: never set local account passwords via GPP; use gMSA/LAPS instead |
| RDP reachable with a weak/legacy security-layer negotiation accepted | A.8.20 (Networks security) / A.8.5 (Secure authentication) | Resilience of network and system security | TODO: enforce NLA/TLS-only RDP, not "Negotiate" falling back to RDP Security Layer |
| TODO: anything else found in Steps 1–5 | | | |

## Data-breach notification assessment (staged/exfil cache)

**What was staged:** TODO — describe what kind of data the cache contained (without reproducing sensitive contents here) and roughly how much.

**Does it trigger a notification duty?** TODO — reason through this against: GDPR Art. 33/34 (is it personal data; is there a risk to individuals' rights and freedoms; the 72-hour clock to the supervisory authority if so) and NIS2's incident-reporting duties (early warning within 24h, incident notification within 72h, for an incident with significant impact). State the conclusion and the reasoning, not just a yes/no.

**Who would need telling, and by when:** TODO.

## Stretch

- **Second, independent foothold:** TODO (optional — only if I find one; not required for the hand-in).
# Case file: lockout and recovery on WKS-L58

This is the hand-in for Mission 3. Same rule as Mission 2: every claim points to an event in my own Sentinel workspace where one exists, and anything that happened off the workstation is marked as such rather than guessed at. Times are in UTC.

> Draft. TODO marks what still has to come from my own results.

## Summary

**For a manager:** TODO — three or four sentences, no jargon: what happened, what I got back, what's still exposed if we don't fix it.

**For a technician:** TODO — the actual chain: what was exposed, what let the attacker (and then me) in, what was staged on the machine, and what Sentinel could and couldn't see of it.

## Scope

| | |
|---|---|
| Machine | WKS-L58.hamilton.corp |
| My attack machine | My own laptop, connected over Tailscale |
| Evidence source | My Sentinel workspace (`SecurityEvent`) for the workstation-visible parts; my own attack-machine output for everything else |
| What Sentinel can see | Only: (1) the RDP reconnection, (2) the lockout-era failed logons, (3) the anonymous SMB access to WKS-L58. Scanning, SMB enumeration, and GPP credential decryption happen off-box and will not appear here. |

## Timeline

| Time (UTC) | What happened | Evidence |
|---|---|---|
| TODO | Port/service scan of WKS-L58 from my attack machine | Attack-machine only — not in Sentinel |
| TODO | Anonymous SMB access / enumeration of the exposed share | TODO: KQL, anonymous/guest logon |
| TODO | GPP `cpassword` recovered from the share's XML | Attack-machine only — not in Sentinel |
| TODO | Failed RDP attempts before the security-layer fix | TODO: 4625s, lockout-era |
| TODO | Successful RDP reconnection | TODO: 4624 type 10 |
| TODO | Artifacts retrieved (flag, Sentinel credential, data cache) | Workstation only |
| TODO | Sentinel credential rotated | N/A — action taken, not an event |

## Findings

**How the attacker (and then I) got in:** TODO — SMB share exposed with anonymous/guest read access; a Group Policy Preferences file on it contained a `cpassword` whose encryption key has been public since 2014, so it isn't real protection; that gave a working credential for RDP.

**Why this matters beyond "we got back in":** TODO — the same exposed share and the same decryptable credential is exactly what an attacker without lab-given hints would also find, which is the point of calling this a control gap rather than a one-off inconvenience.

## Two sources, one answer

| Question | Attack-machine (my own tools) | KQL (Sentinel) | What the comparison means |
|---|---|---|---|
| What was exposed? | TODO: scan + SMB listing | Nothing — out of scope | Only the attack machine could answer this; Sentinel watches the endpoint, not the network surface in front of it |
| How was the credential recovered? | TODO: GPP decrypt tool | Nothing — out of scope | Same: happens entirely off-box |
| Did WKS-L58 itself log the approach? | — | TODO: anonymous SMB logon, lockout-era 4625s | This is the one place the two sides meet: Sentinel has the workstation's side of the same event |
| Getting back in | TODO: client security-layer fix | TODO: 4624 type 10 | Agree once both are filled in — the client-side cause, the server-side effect |

## MITRE ATT&CK mapping

| Step | Tactic | Technique (ID) |
|---|---|---|
| Finding the exposed share | Reconnaissance / Discovery | TODO (e.g. Network Service Discovery, T1046) |
| Reading unprotected policy files | Credential Access | Unsecured Credentials: Group Policy Preferences (T1552.006) |
| Using the recovered credential over RDP | Lateral Movement | Remote Services: Remote Desktop Protocol (T1021.001) |
| Retrieving staged data | Exfiltration / Collection | TODO |

## Control gaps and fixes (ISO 27001 Annex A / NIS2–CyFun)

| Gap | ISO 27001 Annex A control | NIS2 / CyFun angle | Fix |
|---|---|---|---|
| SMB share allows anonymous/guest read | A.8.3 (Information access restriction) / A.5.15 (Access control) | Basic cyber hygiene — access control for ICT systems | TODO: disable anonymous/guest SMB access, require authentication |
| Credentials pushed via GPP `cpassword` | A.8.24 (Use of cryptography) / A.5.17 (Authentication information) | Supply-chain-adjacent config hygiene; known-weak crypto still in use | TODO: never set local account passwords via GPP; use gMSA/LAPS instead |
| RDP reachable with a weak/legacy security-layer negotiation accepted | A.8.20 (Networks security) / A.8.5 (Secure authentication) | Resilience of network and system security | TODO: enforce NLA/TLS-only RDP, not "Negotiate" falling back to RDP Security Layer |
| TODO: anything else found in Steps 1–5 | | | |

## Data-breach notification assessment (staged/exfil cache)

**What was staged:** TODO — describe what kind of data the cache contained (without reproducing sensitive contents here) and roughly how much.

**Does it trigger a notification duty?** TODO — reason through this against: GDPR Art. 33/34 (is it personal data; is there a risk to individuals' rights and freedoms; the 72-hour clock to the supervisory authority if so) and NIS2's incident-reporting duties (early warning within 24h, incident notification within 72h, for an incident with significant impact). State the conclusion and the reasoning, not just a yes/no.

**Who would need telling, and by when:** TODO.

## Stretch

- **Second, independent foothold:** TODO (optional — only if I find one; not required for the hand-in).
