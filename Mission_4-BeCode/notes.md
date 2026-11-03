# Mission 04 working notes — A service account goes rogue

> Done — all four steps complete, all three CTFd flags submitted. Same format as Missions 1-3: Question/task, hints, instructions (what I actually ran), then the answer. Where Sentinel can see the step I've added the KQL and what it shows. Stage 0 (the Kerberoasting root cause) never touches my workstation, so it has no Sentinel side by design — the briefing says this up front, not a gap. Step 4's scheduled-task-creation event (4698) turned out to be a real audit-policy gap in this lab, not a by-design one — noted explicitly where it comes up.

**Redaction note:** any real credential or flag value gets written here as `[REDACTED]` or by description only, never in plaintext — same rule as Mission 3.

**Mission window:** started the afternoon of 2026-11-02 (as told), running through the time of investigation (2026-11-03) — pinned down precisely by Step 1's first anomalous logon, 2026-11-02 13:41:48.822 UTC.

---

## Stage 0 — Background: how the account was stolen (root cause, not in my Sentinel)

**What the brief says:** the compromised account is a service account — one that exists to run a background service (database, backup job, etc.), not for a human to sign in with. Any AD account with a Service Principal Name (SPN) can have a Kerberos service ticket requested for it by *any* ordinary domain user, and that ticket is encrypted with the service account's own password hash. An attacker captures the ticket and cracks it offline — no failed logons, no alarm. This is Kerberoasting. It works best against a weak password and when the account still allows RC4 (as opposed to AES-only) Kerberos encryption.

This happens against the domain controller, not my workstation, and my Sentinel doesn't watch the DC yet (that's a later mission) — so this stage is reasoned from what I understand, not observed, and the report says so explicitly rather than pretending otherwise.

**Mission 4 CTFd flag — Recon (50 pts):** *"A service account on this domain advertises the kind of service it runs. Name that service type."* — This is about the SPN itself: an SPN has the form `<service-class>/<host>[:port]` — the service class in that string literally *is* "the kind of service it runs." `setspn -L svc-app58` initially failed with `Ldap Error (0x31 -- Invalid Credentials)` — WKS-L58 was logged on with a **local** account (`whoami /upn` confirmed "the current logged-on user is not a domain user"), so there was no Kerberos ticket for the LDAP bind. Re-ran it from a `runas /netonly /user:HAMILTON\mustafa powershell` window instead, which supplies domain credentials for the network call without needing to log off the local session — that resolved cleanly:
```
PS> setspn -L svc-app58
Registered ServicePrincipalNames for CN=svc-app58,OU=Accounts,DC=hamilton,DC=corp:
        MSSQLSvc/app58.hamilton.corp
```
The service class is `MSSQLSvc` — `svc-app58` is nominally a SQL Server service account. Worth noting for the case file: everything this account actually did on WKS-L58 (recon commands, a recurring batch logon) has nothing to do with running SQL Server — a database service account logging onto a workstation interactively-by-proxy is itself a red flag independent of the Kerberoasting root cause.

**Mission 4 CTFd flag — Recon (50 pts):** `HAM{mssqlsvc}` — unlike the other two flags this mission, this one isn't seat-specific (it's naming a service *type*, which is the same string regardless of which seat's `svc-appNN` account it is), so the `_seat58` suffix pattern the other two flags use doesn't apply here. A few `_seat58`-suffixed guesses (`mssqlsvc_seat58`, `mssql_seat58`, `sql_service_seat58`) were rejected before trying the plain, un-suffixed `mssqlsvc`, which was accepted.

---

## Step 1 — Find the logon that should not exist

**Question/task:** Find the service account's anomalous sign-on to my workstation inside the mission window.

**Hint(s):**
- Nudge 1: logon events carry the account name and the logon type. Set aside my own sign-ins and the machine's own background/service activity — looking for a non-human account signing on inside the window.
- Nudge 2: a service account's name usually points at a service, not a human. Once spotted, keep the name and exact time — that's the start of the timeline.

**Instructions:** Queried `SecurityEvent`, `EventID == 4624`, scoped to `Computer has "WKS-L58"`, over the mission's time window, and looked for an account name that isn't a person and a `LogonType` a service account has no business using. `HAMILTON\svc-app58` stood out immediately: `LogonType 4` (Batch — the type Windows assigns to scheduled-task logons, never a human interactive sign-in).

**Answer:** `HAMILTON\svc-app58`, `LogonType 4` (Batch), first logon **2026-11-02 13:41:48.822 UTC** — the start of this incident's timeline. The account name itself (`svc-appNN`) already points at "service account for some application," and the Batch logon type confirms it's being driven by something scheduled, not a person at a keyboard.

**Sentinel side:**
```kql
SecurityEvent
| where Computer has "WKS-L58"
| where EventID == 4624
| where Account has "svc-app58"
| project TimeGenerated, Account, LogonType, IpAddress, AuthenticationPackageName
| order by TimeGenerated asc
```

---

## Step 2 — Follow what it did

**Question/task:** Reconstruct what the account ran, in order, once signed on.

**Hint(s):** Same event type as Mission 2's command-line reconstruction (process creation, full command line), filtered to this account.

**Instructions:** Queried `SecurityEvent`, `EventID == 4688`, filtered to `Account has "svc-app58"`, and grouped to distinct `CommandLine` values (101 raw process-creation rows collapse to 8 distinct commands, since `conhost.exe` — the console host every one of these spawns alongside — repeats 94 times as pure noise).

**Answer:** One tight burst, all within about 1.5 seconds starting **2026-11-02 13:41:49.057 UTC** (right after the Step 1 logon): `whoami`, `whoami /all`, `net user svc-app58` (+ its `net1.exe` helper), `net localgroup administrators` (+ helper), `ipconfig /all`. The gaps between consecutive commands are tens of milliseconds — far too fast for a human typing — so this is a scripted recon sequence, not someone interactively exploring. It's classic situational-awareness: who am I, what groups exist, what's my network configuration.

**Sentinel side:**
```kql
SecurityEvent
| where Computer has "WKS-L58"
| where EventID == 4688
| where Account has "svc-app58"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by CommandLine
| order by First asc
```

---

## Step 3 — Measure the damage: what did they take?

**Question/task:** Find the data the account gathered and staged, ready to exfiltrate.

**Hint(s):** Not every action leaves a neat event — sometimes the trace is the *result* left on disk, not a log line. Look for something collected and set aside where it doesn't belong, then read the timeline around it.

**Instructions:** RDP'd into WKS-L58 and looked at the desktop. Two CSV-style files are sitting there: `employees` (dated 26/10/2026, 10:05) and `customers` (dated 02/11/2026, 14:41). The `employees` file is a leftover from Mission 3 — its rows are tagged `EXFIL-TEST-MARKER-M3`, and its date is nearly a week before this mission's window even opened, so it's a decoy, not this mission's answer. The `customers` file is dated inside the mission window (the afternoon of 02/11, a little under an hour after the 13:41 recon burst) and every row is tagged `EXFIL-TEST-MARKER-M4` — the current mission's marker. A `staging-proof.txt` file next to it on the desktop makes the match explicit by containing this step's flag directly.

**Answer:** `customers` (3 rows: `customer_id, full_name, email, plan, mrr`) is the staged/exfiltration-ready cache for this mission — PII (names, emails) plus commercial data (subscription plan, monthly recurring revenue) for three customers, gathered and left in a plaintext CSV on the compromised account's own desktop, ready to be pulled off the box. The older `employees` file (Mission 3's marker) was correctly set aside as a decoy rather than mistaken for this mission's find — same desktop, wrong mission, wrong date.

**Mission 4 CTFd flag — Data staged (100 pts):** `HAM{data_staged_seat58}` — found in `staging-proof.txt` on the WKS-L58 desktop, directly beside the staged `customers` CSV.

---

## Step 4 — Are they still in?

**Question/task:** Find the persistence mechanism — something that runs again on its own, on a schedule, long after the window closed.

**Hint(s):** Think about what, on Windows, can run a program by itself, repeatedly, with nobody logged in. Monitoring now records when one of those is *created*.

**Instructions:**
1. Went looking for the Windows event that logs a scheduled task's *creation* (`EventID 4698`, "Other Object Access Events") first, since the hint explicitly says "monitoring now records when one of those is created." It isn't there — `SecurityEvent | where EventID == 4698` returns zero rows anywhere in this workspace, over the full 30-day retention, on any computer. Checked the neighbouring IDs too (4697 service-installed, 4657 registry value changed, 4700/4702 task enabled/updated) — the only hit was two stale `4702` events from `WKS-L58\svc_deploy` on 31/10, a Mission 3 leftover, unrelated to this account or mission window. Checked the classic `Event` table (where Task Scheduler's own operational log or Service Control Manager entries would land) too — nothing but routine Windows housekeeping (TPM-WMI, Security-SPP, DistributedCOM, DNS-Client, VSS, ESENT). Conclusion: this lab's audit policy doesn't have "Audit Other Object Access Events" turned on, so task-creation auditing is a genuine blind spot here — not something I did wrong, and worth calling out as its own control gap in the case file (Mission 3's Stage-0-not-observable pattern, but this time it's a config gap rather than a by-design boundary).
2. Fell back to proving persistence *indirectly* through what Sentinel does capture: queried every `EventID == 4624`, `LogonType == 4` (Batch — the logon type scheduled tasks use) for `svc-app58` on WKS-L58, and computed the gap between consecutive logons. Clean, regular ~900-second (15-minute) spacing, 96 occurrences, starting **2026-11-02 13:41:48.822 UTC** (the exact moment of the Step 2 recon burst) and still firing as of **2026-11-03 12:11:49.326 UTC** — i.e. it was still running, unattended, the moment I checked, long after the mission window itself closed. That's strong proof of an active scheduled task even without the creation event.
3. Once on WKS-L58 over RDP (as a domain user, via `runas /netonly`), confirmed it directly: `Get-ScheduledTask | Where-Object { $_.Principal.UserId -like "*svc-app58*" }` found **two** tasks running as `svc-app58`:
   - **`M4-SvcApp58-Persistence`** — `cmd.exe /c echo proof: HAM{persistence_seat58} >> C:\ProgramData\m4-persistence-log.txt`. `LastRunTime 2026-11-03 13:26:26`, `NextRunTime 2026-11-03 13:41:41` — a 15-minute recurring trigger, matching the Sentinel-observed cadence exactly. This is the account's actual persistence mechanism: a scheduled task that re-authenticates as `svc-app58` every 15 minutes and writes a line to a log file, with nobody needing to be logged on.
   - **`M4-SvcApp58-Session`** — `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\m4_session_payload.ps1"`. `LastRunTime 2026-11-02 14:41:41`, no `NextRunTime` (ran once, not recurring). This timestamp lines up almost exactly with Step 3's `staging-proof.txt`/`customers` CSV (dated 02/11/2026 14:41) — very likely the one-shot task that actually gathered and staged the `customers` data, as distinct from the `-Persistence` task that just keeps the foothold alive.

**Answer:** The persistence mechanism is the scheduled task `M4-SvcApp58-Persistence`, running as `svc-app58`, triggered every 15 minutes. Task-creation auditing (`4698`) isn't enabled in this workspace, so the task's *creation* can't be directly observed in Sentinel — but its ongoing *execution* is: 96 matching `LogonType 4` batch logons at a clean 15-minute cadence, continuing from the moment of compromise through the time of investigation. The companion task `M4-SvcApp58-Session` (one-shot, same account) is the more likely candidate for having actually staged the Step 3 data, based on its timestamp.

**Mission 4 CTFd flag — Persistence (150 pts):** `HAM{persistence_seat58}` — found directly in the `-Command`/`Arguments` field of the `M4-SvcApp58-Persistence` scheduled task once logged onto WKS-L58 and inspected with `Get-ScheduledTask`.

**Sentinel side:** `SecurityEvent`, `EventID == 4698` (scheduled task created) — confirmed absent workspace-wide (not a missed filter; checked with no `Computer` restriction and a 30-day window). Persistence proven instead via `EventID == 4624`, `LogonType == 4`, `Account has "svc-app58"`, showing a 900-second recurring cadence:
```kql
SecurityEvent
| where Computer has "WKS-L58"
| where EventID == 4624
| where Account has "svc-app58"
| where LogonType == 4
| summarize Runs=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
```

---

## Stretch (optional)

- **One detection question I wish the SIEM had answered on its own:** "Has a service account that only ever logs on as a Windows service (LogonType 5) ever logged on with LogonType 3, 4, or 10?" That single rule would have caught Stage 1 the moment it happened, instead of me having to notice it by manually sifting every 4624 for the window.
- **What monitoring would need to watch, and where, to catch the Kerberoasting root cause at the source:** Sentinel would need to collect Security events from the domain controller itself, specifically `EventID 4769` (Kerberos service ticket requested) filtered to RC4 encryption (`TicketEncryptionType == 0x17`) for accounts with an SPN — RC4-encrypted ticket requests for service accounts are the classic Kerberoasting signal, and they're invisible from a workstation-scoped collection like this one.
- **The single change to this service account that would have made the whole chain far harder:** Converting `svc-app58` to a Group Managed Service Account (gMSA). A gMSA's password is a 240-character random value, rotated automatically by AD, and never typed or stored by a human — it would make the offline cracking step of Kerberoasting computationally infeasible, cutting off the entire incident at Stage 0 regardless of anything else in this chain.
