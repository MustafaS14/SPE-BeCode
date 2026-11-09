# Mission 4 — DFIR report: a service account goes rogue

> Done — built from the mission's `CASE_FILE_TEMPLATE.md`, filled in once the investigation (see `notes.md`) was complete. Guidance text removed, as the template asks.

## 1. Executive summary — for a manager

A SQL Server service account (`svc-app58`) was compromised, almost certainly by Kerberoasting its service ticket and cracking the password offline against the domain controller — an attack that leaves no trace on the workstation it later touched. Starting the afternoon of 2 November 2026, the account ran a short burst of situational-awareness commands on my workstation (WKS-L58), gathered a small file of customer records (names, emails, subscription plans, revenue) into a plaintext file, and planted a scheduled task that keeps logging the account back on every 15 minutes. That task was still running, unattended, at the time of this investigation — the intruder's access is still active as of this writing. No evidence of the staged data leaving the machine was found, but it was fully prepared for exfiltration.

## 2. Technical narrative — for a technician

**Stage 0 — how the account was stolen (root cause, not in my Sentinel):** Reasoned from the mission brief, not observed: `svc-app58` holds a Service Principal Name (`MSSQLSvc/app58.hamilton.corp`, confirmed in Step 1 below), which means any domain user can request a Kerberos service ticket for it and crack the ticket offline (Kerberoasting) without touching the account or generating a failed logon. This happens against the domain controller, which my Sentinel doesn't collect from yet, so it's inferred from the mechanism, not logged evidence.

**Stage 1 — the logon that should not exist:** `HAMILTON\svc-app58` signed onto WKS-L58 with LogonType 4 (Batch — the type scheduled tasks use, never a human interactive sign-in) starting 2026-11-02 13:41:48.822 UTC. That logon type alone, for an account that should only ever run a SQL Server service, is the anomaly.

**Stage 2 — what the account did:** In the same ~1.5 seconds as that first logon, the account ran a tight, scripted burst of recon commands — `whoami`, `whoami /all`, `net user svc-app58`, `net localgroup administrators`, `ipconfig /all` — the gaps between them (tens of milliseconds) are far too fast for a human at a keyboard. This is textbook post-compromise situational awareness: who am I, what do I have access to, what does this network look like.

**Stage 3 — the data it gathered and staged:** A CSV file (`customers`) containing three customer records — name, email, subscription plan, and monthly recurring revenue — was found sitting in plaintext on the WKS-L58 desktop, created about an hour after the initial compromise. A proof file next to it confirms it as the deliberately staged cache. A second, older file on the same desktop (`employees`, tagged with a different mission's marker and dated nearly a week earlier) was ruled out as unrelated leftover rather than mistaken for this incident's data.

**Stage 4 — the way it left itself back in:** A scheduled task (`M4-SvcApp58-Persistence`) runs as `svc-app58` every 15 minutes, re-authenticating and writing a line to a log file each time — a minimal but effective heartbeat that keeps the compromised account's access alive indefinitely without anyone needing to be logged on. It started at the moment of compromise and was still firing, unattended, at the time of this investigation (confirmed both in Sentinel's recurring logon pattern and directly in Task Scheduler on the host). A second, one-shot task (`M4-SvcApp58-Session`) ran once, at a time matching the staged-data file almost exactly, and is the more likely candidate for having actually produced it.

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I observed | Where I can prove it |
|---|---|---|---|---|
| 0 — root cause | Credential Access | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting | Reasoned from the account's SPN (`MSSQLSvc/app58.hamilton.corp`) and the mission brief; no failed logons or alarms expected | reasoned — happened off my workstation, against the DC, not in my Sentinel's scope |
| 1 — initial access / logon | Defense Evasion / Initial Access | T1078.002 — Valid Accounts: Domain Accounts | `HAMILTON\svc-app58`, LogonType 4 (Batch), first at 2026-11-02 13:41:48.822 UTC | `SecurityEvent`, `EventID 4624`, `Account has "svc-app58"` |
| 2 — execution / discovery | Discovery | T1033 (System Owner/User Discovery), T1087 (Account Discovery), T1016 (System Network Config Discovery) | `whoami`, `whoami /all`, `net user svc-app58`, `net localgroup administrators`, `ipconfig /all`, all within ~1.5s | `SecurityEvent`, `EventID 4688`, `Account has "svc-app58"`, grouped by `CommandLine` |
| 3 — collection / staging | Collection | T1074.001 — Data Staged: Local Data Staging | `customers` CSV (3 records, PII + revenue data) on the WKS-L58 desktop, created ~1hr after compromise | Not in Sentinel (no file-access auditing in this workspace) — found by direct inspection of the host |
| 4 — persistence | Persistence | T1053.005 — Scheduled Task/Job: Scheduled Task | `M4-SvcApp58-Persistence`, runs as `svc-app58` every 15 minutes, still active at investigation time | Task creation (`EventID 4698`) absent workspace-wide — proven instead via `EventID 4624`, `LogonType 4`, 96 runs at a clean 900s cadence; confirmed directly via `Get-ScheduledTask` on the host |

## 4. Impact and containment

**What was taken:** A small staged cache of customer data — 3 records, each with full name, email address, subscription plan, and monthly recurring revenue (a mix of PII and commercially sensitive data). No evidence in Sentinel of this file actually leaving the machine (no outbound transfer visible with the auditing enabled here), but it was fully prepared and ready to go.

**Still inside?:** Yes. The `M4-SvcApp58-Persistence` scheduled task was still running on its 15-minute cycle at the time this investigation was performed — the account's access to WKS-L58 has not been revoked and the foothold is live right now, not just historically.

**Containment now:** Disable or delete the `M4-SvcApp58-Persistence` and `M4-SvcApp58-Session` scheduled tasks on WKS-L58 immediately. Force a password reset (and re-Kerberoast-proof the credential — see remediation) on `svc-app58`, and audit every other host this account may have reached. Treat the staged `customers` data as potentially compromised for breach-notification purposes even without confirmed exfiltration, since it was fully staged and ready.

## 5. Remediation — stop it happening again

| Weakness | Why it worked | Missing control + fix |
|---|---|---|
| `svc-app58` has an SPN and a crackable password | Any domain user can request a service ticket for an SPN-bearing account and crack it offline (Kerberoasting) with no alarm | Use a long, randomly-generated password (25+ chars) or a Group Managed Service Account (gMSA) for `svc-app58`, which rotates automatically and is effectively un-crackable offline; enforce AES-only Kerberos encryption for service accounts (disable RC4) |
| Task Scheduler object-creation events aren't audited in this environment | `EventID 4698` never appears, so a new persistence task can be created with zero SIEM visibility — this investigation only caught it through an indirect signal (recurring batch logons), not a direct alert | Enable the "Audit Other Object Access Events" advanced audit subcategory (success+failure) via GPO, so `4698`/`4699`/`4700`/`4701`/`4702` actually reach Sentinel; without it, a defender is relying on inference, not detection |
| A SQL Server service account can log on interactively/by-proxy and run shell commands at all | `svc-app58` should only ever authenticate to run the SQL Server service, never sign on with LogonType 4 and run `whoami`/`net`/`ipconfig` | Apply "Deny log on locally" / restrict allowed logon types for service accounts via GPO, and alert on any interactive or batch logon by an account whose only expected use is a Windows service logon (type 5) |
| Staged sensitive data sat as a readable plaintext file on the desktop | No file-level DLP or access auditing flagged a CSV of customer PII and revenue figures being written to a user-writable location | Enable file/object-access auditing on sensitive data paths, and apply DLP policies that flag or block PII/financial data being written outside approved locations |

---

# Part 2 — Reproducing the theft myself

> The CTFd flags keep me honest about reaching each stage — they're the engine, not the hand-in. This section is the hand-in for Part 2: I personally performed the Kerberoasting attack that Part 1 could only reason about as an unobserved root cause, against my own seat's service account (`svc-app58`) only, as an ordinary domain user with no elevated access. Remediation below is no longer theoretical — it is written having now watched the weak password fall in under a second.

## 6. Attack narrative — what I did, in my own words

Acting as an ordinary authenticated domain user (`hamilton.corp\mustafa`, no elevated rights), I enumerated every SPN-bearing account in the domain over LDAP, identified `svc-app58` as my own seat's account (same SPN, `MSSQLSvc/app58.hamilton.corp`, that Part 1 found already compromised), and requested a Kerberos service ticket for that account only. The ticket came back RC4-encrypted (etype 23) — weak enough to attack offline. I cracked it in under a second against `rockyou.txt`, the best-known leaked-password list, recovering a real working password. I used that password to sign onto WKS-L58 as `HAMILTON\svc-app58` over RDP, confirmed elevated access, and recovered the mission's third flag. At no point did I touch another seat's account, even though the same enumeration step made all 18 of them visible and requestable — the rules of engagement treat another seat exactly as a real engagement treats a system outside its signed contract: visible, reachable, and explicitly off-limits.

## 7. MITRE ATT&CK mapping — Part 2 (with defender-visibility notes)

| Step | Tactic | Technique (ID + name) | What I did | Defender visibility |
|---|---|---|---|---|
| 5 — SPN enumeration | Discovery | T1087.002 — Account Discovery: Domain Account (via LDAP query for SPNs) | Queried the DC's LDAP as an ordinary authenticated domain user to list all 18 SPN-bearing accounts | **Invisible to this workspace by design**: an LDAP query to the DC generates no Windows Security event by itself, and this collection doesn't cover the DC regardless. A DC-side LDAP-query audit policy (or a SACL on the relevant AD objects) would be the only way to see this at all. |
| 6 — TGS ticket request | Credential Access | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting | Requested a Kerberos service ticket for `svc-app58` only, via an ordinary (unprivileged, unaudited-by-default) TGS-REQ/TGS-REP exchange | **Logged, but not here**: generates Event ID 4769 (Kerberos Service Ticket Requested) — on the domain controller that issued it, not on WKS-L58. This workspace collects Security events from WKS-L58 only, so this step is a genuine collection-scope gap, not a missed query (confirmed: zero 4769 rows for WKS-L58 over 7 days). |
| 7 — offline crack | Credential Access | T1110.002 — Brute Force: Password Cracking | Cracked the RC4 ticket offline, on my own laptop, against `rockyou.txt` | **Fully invisible to any SIEM**: happens entirely offline, on attacker-controlled hardware, generating no network traffic or host events anywhere in the environment. The only way to ever see this coming is to make it fail — i.e., control the password strength/encryption type, not try to detect the cracking itself. |
| 8 — use the cracked credential | Lateral Movement / Initial Access | T1078.002 — Valid Accounts: Domain Accounts | Signed onto WKS-L58 as `HAMILTON\svc-app58` via RDP using the cracked password; confirmed elevated rights | **Fully visible**: Event ID 4624, LogonType 10 (RemoteInteractive) plus an accompanying LogonType 3 (Network), both from source `10.50.0.1` (Tailscale-gateway-masked). Compare against Part 1's intruder footprint for the same account: LogonType 4 (Batch), no source IP at all, clean ~15-minute cadence — different shape, same underlying anomaly: a service account logging on in a way it never should. |

## 8. Remediation, now concrete

Part 1's remediation table proposed a gMSA or a long random password for `svc-app58` based on reasoning about how Kerberoasting works. Having now performed the attack myself:

- **The crack took under one second**, on a first pass, against the single most famous leaked-password list that exists. This was not a sophisticated, resource-intensive attack — it is the floor of what Kerberoasting requires once an SPN account has a weak password and RC4 encryption enabled. The fix (gMSA, or at minimum a long randomly-generated password with RC4 disabled / AES-only enforced) is not a hardening nice-to-have; it is the only thing standing between "any authenticated domain user" and full compromise of the account, with no alarm raised at the moment of theft.
- **The theft itself (Steps 5–7) is structurally unobservable from a workstation-only Sentinel collection**, no matter how well-tuned the workstation-side detection is. Steps 5 and 7 generate no logged event anywhere in this environment by their nature (an LDAP read and an offline crack); Step 6 does generate an event (4769), but on the DC, which this workspace doesn't collect from. Concrete fix: onboard the domain controller's Security event log into this Sentinel workspace, specifically to catch `EventID 4769` with `TicketEncryptionType == 0x17` (RC4) for SPN-bearing accounts — that single rule is the earliest point in this entire chain (Part 1 and Part 2 combined) where the theft itself, not just its aftermath, could be caught.
- **Only Step 8 (using the stolen credential) is visible today**, and only because the account then does something a SQL Server service account has no business doing — an interactive or batch logon at all. The detection rule proposed in both Parts' stretch answers (alert on any logon type other than 5 for an account whose only expected use is a Windows service logon) is the one rule that would have caught this entire two-part incident — Part 1's intruder and my own Part 2 reproduction alike — using only what this workspace already collects, with no DC onboarding required.

---

# Part 3 — Catching it at the source (Mission 5)

> Section 8 above proposed onboarding the domain controller's Security log into Sentinel specifically to catch Event ID 4769 with RC4 encryption. This section is that proposal, built and proven: a real scheduled analytics rule, in the new shared `log-hamilton` workspace, that catches the theft itself rather than its aftermath. No CTFd flag for this mission — this section is the hand-in.

## 9. The detection rule

```kql
SecurityEvent
| where EventID == 4769
| where Computer has "DC01"
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
| extend TicketEncryptionType = tostring(column_ifexists("TicketEncryptionType", "")), TargetUserName = tostring(column_ifexists("TargetUserName", "")), ServiceName = tostring(column_ifexists("ServiceName", "")), IpAddress = tostring(column_ifexists("IpAddress", ""))
| where TicketEncryptionType == "0x17"
| where TargetUserName !endswith "$"
| where TargetUserName != "krbtgt"
| project TimeGenerated, TargetUserName, ServiceName, IpAddress, TicketEncryptionType
```

Saved in `log-hamilton` as a scheduled analytics rule named `L58 - RC4 Kerberos
service ticket request (Kerberoasting)`.

**Plain-English explanation:** Every Kerberos service-ticket request (Event ID
4769) on the domain controller packs its useful fields — including the
encryption type the ticket was issued with — into an XML blob rather than flat
columns, so the query unpacks that blob first (`parse_xml` → `mv-expand` →
`bag_unpack`). Once unpacked, the rule looks for any ticket issued with RC4
encryption (`TicketEncryptionType == "0x17"`) requested by a real user account
(excluding computer accounts, which end in `$`, and the built-in `krbtgt`
account). RC4 is a legacy encryption type that's trivially crackable offline;
in a modern domain almost nothing should still request it. Measured directly
against this domain (Mission 5, Step 3): 8,132 ticket requests over 90 days
used AES256, the modern default, versus 16 that used RC4 — RC4 is the rare,
abnormal 0.2% of traffic, which is exactly why it's a clean signal to alert
on rather than a noisy one. This is the earliest point in the entire Mission 4
attack chain (Parts 1 and 2 combined) where the theft itself — not its
aftermath — can be caught: it fires at the moment the ticket is requested, not
when the cracked credential is later used to log on somewhere.

**MITRE ATT&CK:** `T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting`
(sub-technique of `T1558`, under the `Credential Access` tactic) — the same
technique identified by reasoning in section 3 of Part 1, now detected
directly rather than inferred.

**False-positive exclusions and rationale:** The generalizing review (Mission
5, Step 5) found 21 RC4 events over a 90-day window, all of them human
accounts requesting tickets for `svc-appNN`-style service accounts — zero
computer accounts, zero `krbtgt`. So in this domain, RC4 alone already has no
observed false positives. Two defensive exclusions were added anyway, on the
assumption that won't hold forever: computer accounts (`$` suffix) can
legitimately request RC4 tickets in some AD configurations for backward
compatibility, and `krbtgt` ticket activity is a different (and separately
monitored) concern, not a Kerberoasting signal. Excluding both keeps the rule
honest if the domain's RC4-usage pattern ever changes, without weakening the
core signal today.

**Run frequency and lookback, justified by measurement:** Runs every 5
minutes with a 10-minute lookback — deliberately not equal to the run
interval, to avoid missing an event that lands right at a query-window
boundary. This is justified directly by a measured ingestion delay (Mission 5,
Step 4): a replayed ticket request was queryable roughly 25-30 seconds after
being generated — well under a minute. A 5-minute cadence with double that as
lookback comfortably covers that real-world delay with margin to spare,
without the lookback exceeding 2x the run interval (which would re-alert on
the same event across three or more consecutive runs instead of at most two).

**Proof it fires — my own replay:** Replayed the ticket-request step against
my own seat's service account (`svc-app58`) a second time and let the rule's
own schedule catch it, rather than finding it by hand. The raw event landed at
`2026-11-09 11:19:03.546 UTC`. Incident `L58 - RC4 Kerberos service ticket
request (Kerberoasting)` (workspace `log-hamilton`) recorded a timeline entry
"Detected by Microsoft Sentinel ... Tactics: Credential Access", with Entities
`mustafa@HAMILTON.CORP` and `::ffff:10.50.0.1` (the Tailscale gateway address
used throughout Mission 4) — caught well inside the rule's lookback window, no
manual query required.

**Triage — an attack I didn't launch:** Because this rule intentionally has no
account filter (it has to watch every ticket request domain-wide to do its
job), it also fired on other students' own Mission 4/5 Kerberoasting work in
the shared workspace. One clear case: an incident from this same rule with the
entity `kien@HAMILTON.CORP`. Triaging it like a first-line analyst — requesting
account, targeted service account, source address, count/pattern — against the
raw log: `kien@HAMILTON.CORP` requested RC4 tickets eight separate times over
the day, and every single one targeted `svc-app66` and nothing else — seat 66's
own service account, not mine. The source address was the same shared Tailscale
gateway every seat's traffic shows, so it offers no independent attribution,
but the account and target together are unambiguous. The same one-account,
one-target pattern held for every other classmate visible in that day's data
(`lakshmi@HAMILTON.CORP` → only `svc-app53`, her own seat; `derya@HAMILTON.CORP`
→ only `svc-app59`). Judgment: classmate-replay-within-shared-workspace-rules,
not an incident — this is what "everyone Kerberoasting their own seat's service
account for this mission" looks like from the DC's point of view, not a second
attacker. No escalation performed; the classmate had already self-resolved the
incident before I triaged it.

**Remaining defender blind spots:** Every account in this shared domain routes
through the same Tailscale-gateway source address, so IP alone can never
distinguish one student's traffic from another's — attribution here depends
entirely on the account name in the ticket request being trustworthy, which
holds for a controlled class exercise but wouldn't hold against an attacker
using a compromised or shared credential. And this rule only closes the
Mission 4 gap for Kerberoasting specifically: section 8's broader proposal —
alerting on any non-type-5 logon for an account that should only ever run a
Windows service — remains the single rule that would catch this entire attack
chain by its actual anomaly (a service account behaving like a user), rather
than by one specific technique among several that could have gotten it there.

---

**Before push checklist (from the template):**
- [x] Every section filled in English, guidance removed.
- [x] The ATT&CK table has a technique for every stage, including the root cause.
- [x] The impact section says what was taken and whether it is contained.
- [x] No live passwords or flag values pasted into the report. (Flag strings are referenced by name only in notes.md, as proof-of-solve documentation, same convention as Mission 3 — no live credentials appear anywhere in this report or notes.)
- [x] Part 2: the cracked `svc-app58` password is redacted everywhere in notes.md; only the CTFd flag string is in plaintext, per the same exemption used throughout this repo.
