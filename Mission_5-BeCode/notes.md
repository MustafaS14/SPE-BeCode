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

*(pending — replaying the ticket request from my own laptop, own seat's
`svc-app58` only, no cracking needed, to measure ingestion delay and re-check the
source address against Mission 4's Tailscale-gateway-masking finding)*

---

## Stretch (optional)

*(not yet attempted)*
