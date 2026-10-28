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
| — | Anonymous SMB share enumeration: `ADMIN$`, `C$`, `IPC$`, `Public` visible; `Public` itself denied on WKS-L58 under null session, Guest, and blank/anonymous auth. RPC via IPC$ limited to `srvinfo` only | TODO: KQL, anonymous/guest logon |
| — | Widened the scan to the whole `10.50.0.0/24` subnet: found a block of ~17 hosts sharing WKS-L58's signature, and one of them (`10.50.0.50`) anonymously exposes `Public` as read-only. Retrieved `account-access.txt` from it: a low-privilege domain account (`training01`) and the CTF proof string `HAM{anon_smb_seat50}` | Attack-machine only — not in Sentinel |
| — | Tried using `training01` from off-box (its own share, WKS-L58, guessed SYSVOL/NETLOGON, DNS for `hamilton.corp`) — all denied or unreachable by IP/DNS at first | Attack-machine only — not in Sentinel |
| — | Found the domain controller (`10.50.0.10`) by behavioral fingerprinting rather than port scanning: its AD ports (LDAP/Kerberos) are firewalled from this network path, but a disabled Guest account, zero anonymous share enumeration, and `training01`'s `srvinfo` showing the `PDC` role flag identified it. Pulled all of SYSVOL as `training01` and found 15 near-identical GPOs (one per workstation seat), each with a GPP `cpassword` for a shared local account `svc_deploy` | Attack-machine only — not in Sentinel |
| — | Decrypted the `cpassword` for my seat (WKS-L58) using the correct MS14-025 AES-256 key, sourced from the actual `gpp-decrypt` tool rather than a hand-typed guess (two earlier guesses were wrong — one malformed, one the wrong key size entirely) | Attack-machine only — not in Sentinel |
| — | `training01` rejected for RDP (`not allowed for remote connection` — consistent with a domain account never granted interactive/RDP logon rights). `svc_deploy` rejected too, until realizing it's a **local** account (provisioned via GPP's "Local Users and Groups" extension) that has to be addressed as `.\svc_deploy`, not `HAMILTON\svc_deploy` — confirming this is the current, final blocker for Step 4 | Attack-machine only — not in Sentinel |
| TODO | Successful RDP login as `.\svc_deploy` — confirming the local-account fix | TODO: 4625s, lockout-era |
| TODO | Successful RDP reconnection | TODO: 4624 type 10 |
| TODO | Artifacts retrieved (flag, Sentinel credential, data cache) | Workstation only |
| TODO | Sentinel credential rotated | N/A — action taken, not an event |

## Findings

**How the attacker (and then I) got in:** An anonymously-readable SMB share on a sibling workstation (`10.50.0.50`, found by widening the scan from WKS-L58 to the whole subnet) handed over a low-privilege domain account. That account could read SYSVOL on the domain controller (`10.50.0.10`, itself only findable by behavioral fingerprinting since its AD ports are firewalled off this network path), which held a Group Policy Preferences file whose `cpassword` is "encrypted" with an AES key Microsoft published in 2014 — not real protection. Decrypting it gave the password for `svc_deploy`, a **local** account deployed via GPP to every workstation in the fleet, which is what actually gets back onto the machine.

**Why this matters beyond "we got back in":** The same exposed share and the same decryptable credential is exactly what an attacker without lab-given hints would also find — that's the point of calling this a control gap rather than a one-off inconvenience. It also compounds: because `svc_deploy` is the *same* local account with the *same* password pushed to every seat via this GPO (not unique per machine), recovering the cpassword once is enough for local admin on the entire fleet, not just WKS-L58.

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
| Subnet sweep to find the exposed share and the domain controller | Discovery | Network Service Discovery (T1046); Remote System Discovery (T1018) |
| Fingerprinting hosts anonymously (`srvinfo`, `rdp-ntlm-info`) to identify the DC without port-scan-visible AD services | Discovery | System Network Configuration Discovery (T1016); Domain Trust Discovery (T1482) |
| Reading unprotected policy files on SYSVOL | Credential Access | Unsecured Credentials: Group Policy Preferences (T1552.006) |
| Using the recovered local-account credential over RDP | Lateral Movement | Remote Services: Remote Desktop Protocol (T1021.001); Valid Accounts: Local Accounts (T1078.003) |
| Retrieving staged data | Exfiltration / Collection | TODO |

## Control gaps and fixes (ISO 27001 Annex A / NIS2–CyFun)

| Gap | ISO 27001 Annex A control | NIS2 / CyFun angle | Fix |
|---|---|---|---|
| SMB share allows anonymous/guest read | A.8.3 (Information access restriction) / A.5.15 (Access control) | Basic cyber hygiene — access control for ICT systems | TODO: disable anonymous/guest SMB access, require authentication |
| Credentials pushed via GPP `cpassword` | A.8.24 (Use of cryptography) / A.5.17 (Authentication information) | Supply-chain-adjacent config hygiene; known-weak crypto still in use | TODO: never set local account passwords via GPP; use gMSA/LAPS instead |
| RDP reachable with a weak/legacy security-layer negotiation accepted | A.8.20 (Networks security) / A.8.5 (Secure authentication) | Resilience of network and system security | TODO: enforce NLA/TLS-only RDP, not "Negotiate" falling back to RDP Security Layer |
| The same local admin account/password deployed via GPP to every workstation in the fleet | A.8.2 (Privileged access rights) / A.5.17 (Authentication information) | Basic cyber hygiene — no shared/standing privileged credentials | TODO: unique local admin passwords per machine (e.g. LAPS), never one shared account provisioned fleet-wide via GPO |
| Domain controller's AD-specific ports (LDAP/Kerberos) are reachable but silently firewalled from this network path while SMB stays open, rather than the DC being unreachable outright | A.8.20 (Networks security) | Network segmentation effectiveness | TODO: if this is intentional segmentation, note it as working-as-intended; if accidental, treat the asymmetry (SMB open, AD ports filtered) as its own finding worth explaining |
| TODO: anything else found in Steps 1–5 | | | |

## Data-breach notification assessment (staged/exfil cache)

**What was staged:** TODO — describe what kind of data the cache contained (without reproducing sensitive contents here) and roughly how much.

**Does it trigger a notification duty?** TODO — reason through this against: GDPR Art. 33/34 (is it personal data; is there a risk to individuals' rights and freedoms; the 72-hour clock to the supervisory authority if so) and NIS2's incident-reporting duties (early warning within 24h, incident notification within 72h, for an incident with significant impact). State the conclusion and the reasoning, not just a yes/no.

**Who would need telling, and by when:** TODO.

## Stretch

- **Second, independent foothold:** TODO (optional — only if I find one; not required for the hand-in).
