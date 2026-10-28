# Case file: lockout and recovery on WKS-L58

This is the hand-in for Mission 3. Same rule as Mission 2: every claim points to an event in my own Sentinel workspace where one exists, and anything that happened off the workstation is marked as such rather than guessed at. Times are in UTC.

## Summary

**For a manager:** I lost access to my own workstation (WKS-L58) and had to work out how it happened before I could get back in. The root cause was an unlocked file share on a *different* machine that handed over a low-privilege account; that account could read a policy file holding a "disguised" password for a local admin account deployed to every workstation in the fleet, not just mine. Once I decrypted it and addressed it correctly, I got back in, recovered proof of access, restored my own monitoring, and found a small cache of employee data (names, emails, salaries) that had been staged — gathered up and left ready to be taken, though not confirmed as having actually left. That staged data is sensitive enough that, in a real incident, it would trigger mandatory breach-notification obligations. The underlying exposure (the readable share, the weakly "encrypted" policy credential, and the same admin password shared across every machine) needs fixing, or anyone who finds that share can repeat this entire chain.

**For a technician:** An anonymously-readable `Public` SMB share on `10.50.0.50` (a sibling workstation found by widening the scan from WKS-L58 to the whole `/24`) exposed a low-privilege domain account, `training01`. That account could read SYSVOL on the domain controller (`10.50.0.10`, only locatable by behavioral fingerprinting since its AD ports are firewalled off this path) — SYSVOL held 15 near-identical GPOs, one per workstation seat, each provisioning a shared local account (`svc_deploy`) via GPP's "Local Users and Groups" extension with an MS14-025 `cpassword`. Decrypting it (AES-256-CBC, the Microsoft-published key) gave the real password. RDP initially failed because `svc_deploy` was addressed as a domain account (`HAMILTON\svc_deploy`); Sentinel's own `STATUS_NO_SUCH_USER` substatus on 22 failed logons confirmed the account genuinely doesn't exist in that form on the host. Addressing it as a local account (`WKS-L58\svc_deploy`) succeeded immediately. From the regained desktop: the CTF proof flag, a new Sentinel credential (used to pull the KQL above), and a staged `employees.csv` (4 rows of PII) were recovered. Sentinel saw nothing of the off-box recon/decryption (out of its collection scope by design), but directly confirmed both the anonymous SMB touches and the exact failure/success pattern of the RDP reconnection — in the latter case, more precisely than the RDP client's own generic error message did.

## Scope

| | |
|---|---|
| Machine | WKS-L58.hamilton.corp |
| My attack machine | My own laptop, connected over Tailscale |
| Evidence source | My Sentinel workspace (`SecurityEvent`) for the workstation-visible parts; my own attack-machine output for everything else |
| What Sentinel can see | Only: (1) the RDP reconnection, (2) the lockout-era failed logons, (3) the anonymous SMB access to WKS-L58. Scanning, SMB enumeration, and GPP credential decryption happened off-box and don't appear here — confirmed, not just expected, once the real KQL was run (see Two sources, one answer). |

## Timeline

| Time (UTC) | What happened | Evidence |
|---|---|---|
| — | Port scan of WKS-L58 (10.50.0.58): 445 (SMB) and 3389 (RDP) open, rest filtered | Attack-machine only — not in Sentinel |
| 27/10 11:36, 15:34–15:35 | Anonymous SMB share enumeration: `ADMIN$`, `C$`, `IPC$`, `Public` visible; `Public` itself denied on WKS-L58 under null session, Guest, and blank/anonymous auth. RPC via IPC$ limited to `srvinfo` only | `SecurityEvent`, 3× `4624` type 3 for `WKS-L58\Guest`/`WORKGROUP\ANONYMOUS LOGON`, source IP `10.50.0.1` (subnet router, not attributable to the real attack machine) |
| — | Widened the scan to the whole `10.50.0.0/24` subnet: found a block of ~17 hosts sharing WKS-L58's signature, and one of them (`10.50.0.50`) anonymously exposes `Public` as read-only. Retrieved `account-access.txt` from it: a low-privilege domain account (`training01`) and the CTF proof string `HAM{anon_smb_seat50}` | Attack-machine only — not in Sentinel |
| — | Tried using `training01` from off-box (its own share, WKS-L58, guessed SYSVOL/NETLOGON, DNS for `hamilton.corp`) — all denied or unreachable by IP/DNS at first | Attack-machine only — not in Sentinel |
| — | Found the domain controller (`10.50.0.10`) by behavioral fingerprinting rather than port scanning: its AD ports (LDAP/Kerberos) are firewalled from this network path, but a disabled Guest account, zero anonymous share enumeration, and `training01`'s `srvinfo` showing the `PDC` role flag identified it. Pulled all of SYSVOL as `training01` and found 15 near-identical GPOs (one per workstation seat), each with a GPP `cpassword` for a shared local account `svc_deploy` | Attack-machine only — not in Sentinel |
| — | Decrypted the `cpassword` for my seat (WKS-L58) using the correct MS14-025 AES-256 key, sourced from the actual `gpp-decrypt` tool rather than a hand-typed guess (two earlier guesses were wrong — one malformed, one the wrong key size entirely) | Attack-machine only — not in Sentinel |
| — | `training01` rejected for RDP (`not allowed for remote connection` — consistent with a domain account never granted interactive/RDP logon rights). `svc_deploy` rejected too, until realizing it's a **local** account (provisioned via GPP's "Local Users and Groups" extension) that has to be addressed as `.\svc_deploy`, not `HAMILTON\svc_deploy` | Attack-machine only — not in Sentinel |
| 27/10 16:43–17:03, 28/10 09:31, 10:10 | 22× failed RDP/SMB logons for `HAMILTON\svc_deploy` while troubleshooting the address form | `SecurityEvent`, 22× `4625`, `SubStatus 0xc0000064` (`STATUS_NO_SUCH_USER`) — confirms the account genuinely doesn't exist in that form on WKS-L58 |
| 28/10 09:32, 10:11 | Successful RDP login as `WKS-L58\svc_deploy` — confirming the local-account fix, reached the real desktop | `SecurityEvent`, 4× `4624` type 10, `Account = WKS-L58\svc_deploy`, `AuthenticationPackageName = Negotiate` |
| 28/10 | Artifacts retrieved from the desktop: proof flag (`proof_of_access.txt`), new Sentinel credential (`monitoring-access.txt`), staged data cache (`employees.csv`, 4 rows of employee PII tagged `EXFIL-TEST-MARKER-M3`) | Workstation only |
| 28/10 | Sentinel credential used to sign back into Azure/Sentinel for the remainder of this investigation; not rotated (lab environment, not production — see Control gaps for the real-world recommendation) | N/A — action taken, not an event |

## Findings

**How the attacker (and then I) got in:** An anonymously-readable SMB share on a sibling workstation (`10.50.0.50`, found by widening the scan from WKS-L58 to the whole subnet) handed over a low-privilege domain account. That account could read SYSVOL on the domain controller (`10.50.0.10`, itself only findable by behavioral fingerprinting since its AD ports are firewalled off this network path), which held a Group Policy Preferences file whose `cpassword` is "encrypted" with an AES key Microsoft published in 2014 — not real protection. Decrypting it gave the password for `svc_deploy`, a **local** account deployed via GPP to every workstation in the fleet, which is what actually gets back onto the machine.

**Why this matters beyond "we got back in":** The same exposed share and the same decryptable credential is exactly what an attacker without lab-given hints would also find — that's the point of calling this a control gap rather than a one-off inconvenience. It also compounds: because `svc_deploy` is the *same* local account with the *same* password pushed to every seat via this GPO (not unique per machine), recovering the cpassword once is enough for local admin on the entire fleet, not just WKS-L58.

## Two sources, one answer

| Question | Attack-machine (my own tools) | KQL (Sentinel) | What the comparison means |
|---|---|---|---|
| What was exposed? | Port scan (SMB 445 + RDP 3389) and SMB share listing across the subnet, from my own tools | Nothing — out of scope | Only the attack machine could answer this; Sentinel watches the endpoint, not the network surface in front of it |
| How was the credential recovered? | `gpp-decrypt`-equivalent script against the pulled `Groups.xml` (MS14-025 AES-256) | Nothing — out of scope | Same: happens entirely off-box, against a file already on my own machine |
| Did WKS-L58 itself log the approach? | — | Yes — 3× `4624` type 3 (anonymous/Guest SMB) | This is the one place the two sides meet: Sentinel has the workstation's side of the same event, though the logged source IP is the subnet gateway, not my real machine |
| Getting back in | The address form (`HAMILTON\` vs local) was the fix, not the credential | 22× `4625` `STATUS_NO_SUCH_USER` for `HAMILTON\svc_deploy`, then 4× `4624` type 10 for `WKS-L58\svc_deploy` | Agree exactly — Sentinel's substatus code independently confirms *why* the domain-qualified form failed, and the successful account name confirms the fix |

## MITRE ATT&CK mapping

| Step | Tactic | Technique (ID) |
|---|---|---|
| Subnet sweep to find the exposed share and the domain controller | Discovery | Network Service Discovery (T1046); Remote System Discovery (T1018) |
| Fingerprinting hosts anonymously (`srvinfo`, `rdp-ntlm-info`) to identify the DC without port-scan-visible AD services | Discovery | System Network Configuration Discovery (T1016); Domain Trust Discovery (T1482) |
| Reading unprotected policy files on SYSVOL | Credential Access | Unsecured Credentials: Group Policy Preferences (T1552.006) |
| Using the recovered local-account credential over RDP | Lateral Movement | Remote Services: Remote Desktop Protocol (T1021.001); Valid Accounts: Local Accounts (T1078.003) |
| Retrieving staged data | Exfiltration / Collection | Collection: Data Staged (T1074); Exfiltration Over C2 Channel or similar would apply if the data actually left the host — in this mission the cache was found staged but not observed leaving, so Staged (T1074.001, Local Data Staging) fits best |

## Control gaps and fixes (ISO 27001 Annex A / NIS2–CyFun)

| Gap | ISO 27001 Annex A control | NIS2 / CyFun angle | Fix |
|---|---|---|---|
| SMB share allows anonymous/guest read | A.8.3 (Information access restriction) / A.5.15 (Access control) | Basic cyber hygiene — access control for ICT systems | Disable anonymous/guest SMB access fleet-wide, require authentication on every share, and audit for other `Public`-style shares across the `10.50.0.0/24` block, since this one was found only by comparing every host against every other host |
| Credentials pushed via GPP `cpassword` | A.8.24 (Use of cryptography) / A.5.17 (Authentication information) | Supply-chain-adjacent config hygiene; known-weak crypto still in use | Never set local account passwords via GPP (the AES key has been public since 2014 and is in every common offensive toolkit); use gMSA or LAPS instead, and treat every existing GPP-pushed password as already compromised |
| RDP reachable with a weak/legacy security-layer negotiation accepted | A.8.20 (Networks security) / A.8.5 (Secure authentication) | Resilience of network and system security | Not conclusively demonstrated in this mission — the actual Step 4 blocker turned out to be account addressing, not security-layer negotiation, despite the mission's own hint pointing that way. Worth revisiting RDP's NLA/security-layer settings on WKS-L58 as a general hardening item regardless, since it wasn't ruled out, only superseded by a different root cause |
| The same local admin account/password deployed via GPP to every workstation in the fleet | A.8.2 (Privileged access rights) / A.5.17 (Authentication information) | Basic cyber hygiene — no shared/standing privileged credentials | Unique local admin passwords per machine (e.g. LAPS), never one shared account provisioned fleet-wide via GPO — confirmed exploitable at scale: the same `svc_deploy` credential that got me into WKS-L58 is valid local admin on all 15 seats that share this GPO |
| Domain controller's AD-specific ports (LDAP/Kerberos) are reachable but silently firewalled from this network path while SMB stays open, rather than the DC being unreachable outright | A.8.20 (Networks security) | Network segmentation effectiveness | If this is intentional segmentation, it's working as intended; if accidental, the asymmetry (SMB open, AD ports filtered) is worth tightening consistently rather than leaving one protocol more exposed than another |
| Logons routed through the Tailscale subnet router record the router's gateway address (`10.50.0.1`) as the source IP, not the originating machine | A.8.15 (Logging) | Incident-response/forensic readiness | Source-IP attribution is lost for any access that transits this subnet route; a real investigation would need the router's own connection logs (or a non-NAT'd path) to identify the actual originating host behind an anonymous or malicious logon |
| Recovered credential (the new Sentinel/Azure login from the desktop) was used without rotation | A.8.24 (Use of cryptography) / A.5.17 (Authentication information) | Credential hygiene after a confirmed compromise | For this lab it was a judgment call (training tenant, not production); in a real incident any credential recovered from a compromised host must be treated as compromised and rotated before further use, regardless of whether it "still works" |

## Data-breach notification assessment (staged/exfil cache)

**What was staged:** An `employees.csv`-style file containing 4 employee records — full name, email address, department, and salary for each — found staged on WKS-L58's desktop, clearly gathered up by the intruder (each row carries a test marker, `EXFIL-TEST-MARKER-M3`, consistent with this being a lab exercise rather than a real cache, but structurally it's exactly what a real HR export would look like). Small in volume (4 rows), but the data categories are squarely personal data, and salary is the kind of detail that makes exposure more sensitive than, say, a directory listing of names alone.

**Does it trigger a notification duty?** Yes, on the facts as staged, this would be treated as a notifiable personal-data breach if it had actually left the environment:
- **GDPR Art. 33/34:** this is personal data (names, emails, employment and compensation details tied to identified individuals). Even though the volume here is small, salary data is the kind of information whose unauthorized disclosure could cause harm (discrimination, targeted social engineering, embarrassment) — so there's a real risk to the rights and freedoms of the individuals involved, which is the threshold Art. 33 uses to require notifying the supervisory authority within 72 hours of becoming aware. Because the risk (not just the fact of a breach) is non-trivial here, Art. 34 direct notification to the affected individuals would also need to be considered, not just the regulator-facing Art. 33 report.
- **NIS2 incident-reporting duties:** separately from the GDPR angle, the underlying intrusion chain (anonymous SMB exposure → GPP credential theft → lateral movement to a workstation → data staged for exfiltration) is the kind of security incident NIS2 expects covered entities to report on a tiered timeline — an early warning within 24 hours of becoming aware, followed by a fuller incident notification within 72 hours — if the incident has or could have a significant operational impact. Even though in this mission the data was caught staged rather than confirmed exfiltrated, "ready to walk out the door" is close enough to a near-miss that it should still be logged and assessed against the "significant impact" threshold, not dismissed because it didn't fully complete.

**Who would need telling, and by when:** the data protection authority (GDPR Art. 33, within 72 hours of awareness) and, depending on the final risk assessment, the affected employees directly (Art. 34) if the risk to them is assessed as high. In parallel, under NIS2, the organization's sectoral CSIRT/competent authority would get the 24-hour early warning and 72-hour follow-up, independent of the GDPR track — these are two separate obligations that can both apply to the same incident, not alternatives to each other.

## Stretch

- **Second, independent foothold:** not pursued — optional, and the one confirmed chain (anonymous SMB → GPP cpassword → shared local admin account) was sufficient to fully explain the incident and complete the hand-in.
