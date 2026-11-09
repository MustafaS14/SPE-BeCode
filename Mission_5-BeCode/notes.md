# Mission 05: Catch it at the source — working notes

Direct hands-on follow-up to Mission 4 Part 2. In Mission 4 Part 2 I performed a real
Kerberoasting ticket request against my own seat's service account (`svc-app58`), then
found that my own workstation-scoped Sentinel workspace had no trace of the request
itself — Event 4769 (Kerberos Service Ticket Requested) is written by the domain
controller that issues the ticket, not by the requesting workstation. This mission
closes that gap: the coach connected the DC to a new **shared, class-wide** Sentinel
workspace (`log-hamilton`), and the job is to find that same ticket request at the
source, turn what I learn into a real detection rule, and prove the rule catches
both my own replay and an attack I didn't launch.

No CTFd flag for this mission — the hand-in is a new **Detection** section appended
to [Mission 4's case-file.md](../Mission_4-BeCode/case-file.md).

Shared-workspace rules: every analytics rule I create is prefixed `L58 - `; I never
edit, disable or delete anything I didn't create. Rules of engagement from Mission 4
still apply — my own seat's service account only.

---

## Step 1 — Get into the shared workspace

Signed into the Defender portal / Azure portal with the same BeCode account used for
my own Sentinel. The coach initially shared `log-sentinel-lab` (my own Mission 3/4
workspace) by mistake — confirmed via `Heartbeat`/`SecurityEvent` that it only ever
contained `WKS-L58.hamilton.corp`, never a domain controller. The coach then fixed a
tenant RBAC/permissions issue and handed out the real shared workspace name,
`log-hamilton`.

```kql
Heartbeat
| where Computer has "DC01"
| summarize LastSeen = max(TimeGenerated)
```

Confirmed `DC01` is reporting into `log-hamilton` — heartbeat current, same check
pattern as Mission 1.

## Step 2 — Find my own ticket request

The brief's warning turned out to be exactly right: for Event 4769 the useful fields
(`TargetUserName`, `ServiceName`, `TicketEncryptionType`, `IpAddress`, ...) are **not**
populated as flat `SecurityEvent` columns the way they are for logon events (4624).
A first attempt filtering directly on the flat `TargetUserName` column returned no
results even though thousands of 4769 events existed in the window — the real data
lives packed inside the `EventData` column as a small XML document, one
`<Data Name="X">value</Data>` element per field.

Reusable pattern to unpack it (new skill this mission, generalizable to any Windows
event that packs its fields into `EventData`):

```kql
SecurityEvent
| where EventID == 4769
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
```

This reconstructs one wide row per original event, with one column per XML field
name — discovered automatically rather than hardcoded.

Field semantics worth noting (not obvious from the column names, confirmed
empirically): `TargetUserName` on a 4769 event is the account that **requested** the
ticket, and `ServiceName` is the account/SPN the ticket **grants access to**. For a
real Kerberoast that means `TargetUserName` = the attacker and `ServiceName` = the
targeted service account — the opposite of what the names suggest if you reason
from the 4624 schema. I initially filtered on `TargetUserName has "svc-app58"`,
which surfaced 495 unrelated rows — all routine AES256 machine-ticket renewals from
the Mission 4 `M4-SvcApp58-Persistence` scheduled task (svc-app58 as ticket *owner*,
not target), still firing every ~15 minutes. Re-filtering on `ServiceName has
"svc-app58"` instead (the account being targeted) correctly isolated exactly one
event:

```kql
SecurityEvent
| where TimeGenerated > ago(90d)
| where EventID == 4769
| where Computer has "DC01"
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
| where ServiceName has "svc-app58"
| project TimeGenerated, TargetUserName, ServiceName, TicketEncryptionType, IpAddress
| order by TimeGenerated asc
```

**Result — one row, my own Mission 4 Part 2 Kerberoast, found at the source:**

| TimeGenerated (UTC) | TargetUserName (requester) | ServiceName (target) | TicketEncryptionType | IpAddress |
|---|---|---|---|---|
| 2026-11-05 11:36:38.661 | `mustafa@HAMILTON.CORP` | `svc-app58` | `0x17` | `::ffff:10.50.0.1` |

## Step 3 — Why it stands out

Grouped every 4769 event on `DC01` over a 90-day window by `TicketEncryptionType`:

```kql
SecurityEvent
| where TimeGenerated > ago(90d)
| where EventID == 4769
| where Computer has "DC01"
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
| summarize Count=count(), Accounts=dcount(TargetUserName), Services=dcount(ServiceName) by TicketEncryptionType
| order by Count desc
```

**Result:**

| TicketEncryptionType | Count | Distinct requesting accounts | Distinct services |
|---|---|---|---|
| `0x12` (AES256-CTS-HMAC-SHA1-96) | 8,132 | 41 | 20 |
| `0x17` (RC4-HMAC) | 16 | 7 | 8 |

99.8% of all ticket requests on the DC use AES256 — ordinary, modern domain traffic
(machine-account renewals, service logons, etc). Only 16 requests (0.2%) across the
entire 90-day, class-wide window use RC4, spread across 7 distinct requesting
accounts — almost certainly my own Kerberoast plus classmates' attempts in the same
shared domain. This matches Mission 4 Part 2's finding that the ticket I cracked was
"etype 23" (decimal for RC4-HMAC = hex `0x17`).

**This is the detail that gives it away: `TicketEncryptionType == "0x17"` (RC4) on a
4769 event, requested against a service account, is rare enough in this domain to be
the heart of the detection rule** — a legitimate, modern Windows domain has no good
reason to still be issuing RC4 tickets; software requesting RC4 on purpose is the
signature of a Kerberoasting tool (e.g. Impacket's `GetUserSPNs.py`) forcing a
downgrade so the ticket is crackable offline, rather than a client negotiating
AES256 normally.

## Step 4 — Watch it arrive live

Replayed only the ticket-request step from my own laptop — own seat's
`svc-app58` only, no cracking needed, same tool/account/DC as Mission 4 Part 2:

```powershell
& "C:\Users\musta\AppData\Local\Programs\Python\Python314\python.exe" "C:\Users\musta\AppData\Local\Programs\Python\Python314\Scripts\GetUserSPNs.py" hamilton.corp/mustafa -dc-ip 10.50.0.10 -request-user svc-app58
```

Ran at approximately `2026-11-09 11:19 UTC`. Impacket returned the ticket
(`$krb5tgs$23$...`) immediately client-side, as expected — "etype 23" again, i.e.
RC4, confirming the DC still negotiates RC4 for this account on request rather than
refusing weak crypto outright.

Queried the shared workspace with the Step 2 query narrowed to the last 30 minutes:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4769
| where Computer has "DC01"
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
| where ServiceName has "svc-app58"
| project TimeGenerated, TargetUserName, ServiceName, TicketEncryptionType, IpAddress
| order by TimeGenerated desc
```

**Result:**

| TimeGenerated (UTC) | TargetUserName | ServiceName | TicketEncryptionType | IpAddress |
|---|---|---|---|---|
| 2026-11-09 11:19:03.546 | `mustafa@HAMILTON.CORP` | `svc-app58` | `0x17` | `::ffff:10.50.0.1` |

The replayed event was already present and queryable within roughly 25–30 seconds
of being run — the very first query against the shared workspace after the replay
returned it immediately. **Ingestion delay: well under a minute.** This matters
directly for Step 6: a 5-minute run frequency with a lookback a little longer than
5 minutes (to avoid the "lookback == run interval exactly can miss an event landing
right at the boundary" trap the brief warns about) comfortably covers an ingestion
delay this short.

Source address is `::ffff:10.50.0.1` again — the IPv4-mapped IPv6 form of the same
Tailscale gateway address seen throughout Mission 4. Confirms the gateway-masking
pattern holds for 4769 events at the DC too: the DC sees every student's traffic as
arriving from the same gateway address, not each laptop's real IP. Worth calling out
as a defender-visibility limitation in the case file's Detection section.

---

## Step 5 — From my attack to any attack

Reviewed every RC4 (`0x17`) event over the 90-day window directly (not just grouped
counts) to check for false positives before generalizing:

```kql
SecurityEvent
| where TimeGenerated > ago(90d)
| where EventID == 4769
| where Computer has "DC01"
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
| where TicketEncryptionType == "0x17"
| project TimeGenerated, TargetUserName, ServiceName, IpAddress
| order by TimeGenerated asc
```

**Result:** 21 rows (16 from the earlier 90-day count, plus 5 more that landed since
— other students actively working the same mission). Every single row is a human
account (`mustafa`, `kien`, `derya`, `training01`, `sajjad`, `lakshmi`,
`madumathi`, ...) requesting a ticket for an `svc-appNN` service account. **Zero**
computer accounts (names ending `$`) and **zero** `krbtgt` requests show up in RC4
traffic — the AES256 baseline is where all of that routine noise lives (confirmed
in Step 3). So empirically, in this domain, RC4 alone is already a clean signal
with no observed false positives.

Still generalized and hardened the query rather than relying on that holding
forever: dropped every self-specific filter (my seat, my account, my time window),
kept only the encryption-type signal, and added defensive exclusions for computer
accounts and `krbtgt` — legitimate in some domains/legacy setups even though they
don't appear here, and cheap insurance against a future false positive:

```kql
SecurityEvent
| where EventID == 4769
| where Computer has "DC01"
| extend Parsed = parse_xml(EventData).EventData.Data
| mv-expand Parsed
| extend Name = tostring(Parsed["@Name"]), Value = tostring(Parsed["#text"])
| summarize Fields = make_bag(pack(Name, Value)) by TimeGenerated, EventRecordId
| evaluate bag_unpack(Fields)
| where TicketEncryptionType == "0x17"
| where TargetUserName !endswith "$"
| where TargetUserName != "krbtgt"
| project TimeGenerated, TargetUserName, ServiceName, IpAddress, TicketEncryptionType
```

This is the query the Step 6 analytics rule is built from.

## Step 6 — Make it a scheduled rule

Built the Step 5 query into a scheduled analytics rule in the Azure Portal
(Microsoft Sentinel → `log-hamilton` → Analytics → + Create → Scheduled query
rule), named `L58 - RC4 Kerberos service ticket request (Kerberoasting)` per
the shared-workspace naming rule.

**General tab:** Severity `High` (credential theft, not a false-positive-prone
signal). MITRE ATT&CK: `T1558.003 - Kerberoasting` (under the `T1558 - Steal
or Forge Kerberos Tickets` technique, `Credential Access` tactic).

**Set rule logic — a validator wrinkle worth recording:** pasting the Step 5
query as-is made the rule-logic editor flag `'where' operator: Failed to
resolve column or scalar expression named 'TicketEncryptionType'` (and, once
that was patched, the same error for `TargetUserName`). Running the query via
"View query results" proved it executes correctly regardless (13 rows, exact
match to the manual hunt) — the editor's static analyzer can't infer columns
produced dynamically by `evaluate bag_unpack(...)`, even though the KQL
engine resolves them fine at runtime. This isn't just cosmetic, though: the
wizard's final "Review + create" step runs a stricter validation pass that
*does* block saving on this error. Fix: wrap each bag_unpack-produced column
used downstream in `column_ifexists("ColumnName", "")` right after the
`bag_unpack` call — a function whose return type is statically known, so the
analyzer stops trying (and failing) to resolve the dynamic column by name.
Final rule query:

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

**Query scheduling:** run every `5 minutes`, lookback `10 minutes` — not
equal to the run interval, per the brief's warning about missing events that
land right at a window boundary. Justified directly by the Step 4 measurement
(ingestion delay well under a minute): a 5-minute cadence with double that as
lookback comfortably covers the real-world delay with margin to spare, without
re-alerting on the same event twice before the next run (lookback isn't more
than 2x the interval).

**Alert threshold / event grouping:** alert when results `> 0`; "Trigger an
alert for each event" rather than grouping — each Kerberoast attempt should
surface as its own alert/incident rather than being buried in a batch.

**Entity mapping:** `Account` (identifier `FullName`) → `TargetUserName`, and
`IP` (identifier `Address`) → `IpAddress`. This is what makes the requesting
account and source address show up as recognized entities on the incident
itself, not just as raw query-result columns — directly useful for Step 8's
triage. (The `column_ifexists` fix above was also what unblocked this: the
entity-mapping column picker only offers columns the rule-logic analyzer can
resolve, so before the fix it was stuck on a disabled "Add new entity".)

**Incident settings:** incident creation enabled (default); alert grouping
left disabled, consistent with "trigger an alert for each event" above.

Saved successfully — Azure Portal confirmed "Analytics rule saved. Analytics
rule 'L58 - RC4 Kerberos service ticket request (Kerberoasting)' saved
successfully."

## Step 7 — Prove it fires

Replayed the ticket-request step again (own seat's `svc-app58`, no cracking) and
waited for the rule's own schedule to pick it up rather than just re-running the
query by hand. Confirmed two independent ways:

1. **Raw log, direct query:** the replayed event landed at `2026-11-09 11:19:03.546
   UTC` (`mustafa@HAMILTON.CORP` -> `svc-app58`, `0x17`/RC4, `IpAddress
   ::ffff:10.50.0.1` — the same Tailscale-gateway masking seen throughout Mission 4).
2. **Incident #3050/#3052** (`L58 - RC4 Kerberos service ticket request
   (Kerberoasting)`, workspace `log-hamilton`): "View full details" shows the
   timeline entry `9 Nov 15:02:22 | ... | High | Detected by Microsoft Sentinel |
   Tactics: Credential Access`, Entities `mustafa@HAMILTON.CORP` and
   `::ffff:10.50.0.1`. (The incident's displayed time, 15:02/15:10, is 1 hour ahead
   of the raw UTC log timestamps below — the Defender/Sentinel incident UI appears
   to render in UTC+1, not UTC; confirmed by comparing to a second self-replay at
   `14:02:22.845 UTC`, which lines up with the incident's "15:02" entry.)

The rule caught the replay well within its 5-minute/10-minute lookback window,
as expected from the Step 4 ingestion-delay measurement.

## Step 8 — Triage an attack I didn't launch

Because this rule has no account filter (it watches every RC4 ticket request
against DC01, domain-wide — deliberately, since the point is to catch
Kerberoasting regardless of who's doing it), it also fired on other students'
own Mission 4/5 work in the shared `log-hamilton` workspace. Two incidents stood
out as the clearest "I didn't launch this" case: **#3045** (Resolved, owned by
`vinh.kien.truong@becode.education`) and **#3047** (Active, unassigned), both
titled `L58 - RC4 Kerberos service ticket request (Kerberoasting)` — i.e. alerts
from *my* rule — both with the entity `kien@HAMILTON.CORP`, both alerting on an
event with "First/last activity: 9 Nov 2026 14:50" (displayed time; 13:50 UTC).

**Triage, first-line-analyst style:**

- **Requesting account:** `kien@HAMILTON.CORP` — a real, named classmate account
  in the shared domain, not an anonymous or external identity.
- **Targeted service account:** confirmed directly against the raw log (ran the
  Step 5/6 query over the last 6 hours, filtered to `kien`/`lakshmi` for a sanity
  check, then re-ran unfiltered over the full day to see every account's pattern).
  Kien's requests land exclusively on `svc-app66` — eight separate RC4 requests
  over the day (09:32:44, 09:55:55, 10:14:30, 10:26:53, 10:37:09, 11:12:28,
  11:31:40, 13:50:39, all UTC), every one targeting `svc-app66` and nothing else.
  `svc-app66` is seat 66's own service account, not mine (`svc-app58`) and not
  anyone else's.
- **Source address:** `::ffff:10.50.0.1` — the same Tailscale-gateway address
  every seat's traffic shows (see Mission 4), so it provides no useful
  per-student attribution on its own; it's consistent with "someone on the
  class VPN," which is all the domain can see.
- **Count/pattern:** repeated, steady, business-hours cadence against a single
  fixed target account — the signature of someone iterating on their own
  Kerberoasting exercise (retrying a command, re-running a tool), not a brute
  -force sweep or lateral movement (no account enumeration, no other event
  types, no attempt to touch `svc-app58` or anything outside seat 66's own
  scope). The same pattern holds for the other classmates visible in today's
  data: `lakshmi@HAMILTON.CORP` only ever requests `svc-app53` (her own seat),
  `derya@HAMILTON.CORP` only ever requests `svc-app59`.
- **Judgment: classmate-replay-within-rules, not an incident.** Every account
  in today's data targets exactly one service account, and in every case it
  matches that student's own seat number (66<->svc-app66, 53<->svc-app53,
  59<->svc-app59, 58<->svc-app58 for me) — exactly the shared-workspace rule
  that everyone Kerberoasts *their own* seat's service account as their Mission
  4/5 work, never someone else's. Kien's activity is that, nothing more: this is
  what "catching it at the source" looks like when the source is thirty
  classmates doing the same assigned exercise in the same domain at once, not a
  resurfaced version of the actual Mission 4 incident I investigated no
  escalation needed, and I'd close/resolve it on sight if it were mine to
  triage (Kien, in fact, already resolved #3045 himself).
- **Side finding — not a blind spot in the rule, but a quirk of how it alerts:**
  #3045 and #3047 are two separate incidents for what looks like the same
  13:50:39 UTC event (same "first/last activity" timestamp, same entity). With
  "trigger an alert for each event" and a 10-minute lookback on a 5-minute
  schedule, a single event can fall inside two consecutive rule runs' lookback
  windows and get alerted on twice before it ages out — the lookback being
  wider than the run interval (deliberately, to not miss boundary events) comes
  at the cost of this kind of double-alerting. Noted for the case file as a
  known tradeoff, not something to "fix" by shrinking the lookback back down to
  the run interval, which would reopen the boundary-miss problem it exists to
  prevent.

---

## Stretch (optional)

*(not yet attempted)*
