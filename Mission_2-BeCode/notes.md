# Notes: Mission 02 (Your first intrusion)

My notes from Mission 2 of the BeCode Hamilton CTF. I play attacker on my own machine first (Part 1), then hunt the real intrusion in my Sentinel (Parts 2 to 4). Every challenge is written the same way as in Mission 1: question, hints, then what I actually did and the answer.

> TODO marks something I still have to fill in from my own notes or results. Nothing below a TODO is a confirmed finding yet.

| | |
|---|---|
| Workstation | WKS-L58 (WKS-L58.hamilton.corp) |
| SIEM | My Sentinel workspace from Mission 1 (`SecurityEvent` through `dcr-securityevents`, "Common" set) |
| Attack window (given by the coach) | TODO: start → end, in UTC |
| Lab account for Part 1 | `labuser`, a local account on WKS-L58 (password sent privately by the coach, not written here) |

---

## Part 1: Make some noise yourself

> Before you hunt, play attacker for five minutes. Open a new Remote Desktop connection to your own machine and sign in as `labuser`, run one harmless command (`whoami` is enough), then **sign out**, and look at what your own action left behind in the log.

**Nudge 1:** Use Remote Desktop, but sign in as the lab account. It lives on the machine itself, not in the domain, so type the user name as `.\labuser` (the `.\` means "this machine").

**Nudge 2:** Run one small command, like `whoami`, then sign out and open your logs. You are measuring your own footprint, not going further.

**Instructions:**
1. Open Remote Desktop Connection (mstsc) to my own workstation's address.
2. User name `.\labuser`, password from the coach.
3. Run `whoami`. It returns `wks-l58\labuser`.
4. Sign out from the Start menu (not just closing the window, which only disconnects the session).
5. Wait two minutes, then look for the logon in Sentinel (see the warm-up below).

**What it left behind:** the logon is at 12 October, 10:11:33 UTC, from `10.50.0.1` (details below). TODO: the other events I found (expected: a 4624 type 3 then a type 10 for the logon, a 4634/4647 for the sign-out, and **nothing** for `whoami`, because process creation isn't audited).

**Finding my labuser logon, two ways**

I looked for my own `labuser` logon twice: on the workstation itself, and in Sentinel. This is the same method I'll use for the real intrusion in Part 2.

*Method A: on the workstation*
1. Open PowerShell as administrator.
2. Get the latest successful RDP logon (4624 with logon type 10) from the local Security log:

```powershell
$event = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10']]" -MaxEvents 1
```

3. Read the account name out of the event's XML:

```powershell
[xml]$xml = $event.ToXml()
$xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName' | Select-Object -ExpandProperty '#text'
```

It returns `labuser`.

4. Because `-MaxEvents 1` only shows the newest one (see the trap below), list **every** type 10 logon with its time, account and source IP:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" | ForEach-Object {
    [xml]$xml = $_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        UserName    = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
        ClientIP    = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
    }
} | Format-Table -AutoSize
```

| TimeCreated (VM local, UTC+2) | UTC | UserName | ClientIP |
|---|---|---|---|
| 12-10-26 12:11:33 | 12 Oct 10:11:33 | labuser | 10.50.0.1 |
| 07-10-26 11:38:29 | 7 Oct 09:38:29 | mustafa | 10.50.0.1 |
| 07-10-26 11:38:29 | 7 Oct 09:38:29 | mustafa | 10.50.0.1 |

The two `mustafa` rows are my very first RDP connection from Mission 1 (the type 10 the coach asked about). `labuser` has only **one** row where `mustafa` has two: my account is an admin, so Windows logs a second logon for the elevated half of its split token, while `labuser` is a standard user.

*Method B: in the SIEM*
1. In Sentinel → Logs, list every successful RDP logon, newest first:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, Activity
| sort by TimeGenerated desc
```

2. Over the last 7 days it returns exactly **one** row:

| TimeGenerated (UTC) | Computer | TargetUserName | IpAddress | LogonTypeName |
|---|---|---|---|---|
| 12/10/2026 10:11:33.554 | WKS-L58.hamilton.corp | labuser | 10.50.0.1 | 10 - RemoteInteractive |

The source IP is `10.50.0.1`, the lab gateway, not my laptop. All my RDP connections show that address, because the gateway relays them.

**Comparing the two methods**

As in Mission 1, comparing the two sources shows what each one can and can't be trusted for.

| | Workstation (local Security log, PowerShell) | SIEM (`SecurityEvent` in Sentinel, KQL) |
|---|---|---|
| Where the data lives | On WKS-L58 itself, the machine that was broken into | In my Log Analytics workspace, copied there by the AMA through `dcr-securityevents` |
| What I need to read it | An RDP session and an admin PowerShell on the compromised machine | Only the portal. I never have to touch the machine |
| Can the attacker tamper with it? | Yes. With admin rights they can clear the log (that leaves a 1102, but the logons are gone) | Not after ingestion. Events already sent stay in the workspace even if the local log is wiped |
| Format | Raw XML. Fields are read by name through `ToXml()` (reading `Properties[n]` by position is fragile) | Already split into columns: `TargetUserName`, `IpAddress`, `LogonTypeName`, `Activity` |
| Which events | Everything the audit policy writes | Only what the DCR collects (the "Common" set), and only while under the daily cap |
| How far back | As far as the local log goes before it rolls over (20 MB; mine goes back to 21 September) | Only since collection started (7 October, ~15:08 UTC for `SecurityEvent`), for the workspace's retention |
| Time zone | The VM's local time (Romance Standard Time, UTC+2 in October) | UTC (`TimeGenerated`) |
| Delay | Immediate | A few minutes of ingestion delay |
| Seeing the whole picture | Hard. `-MaxEvents 1` only gives the newest logon, and counting failures needs another script | Easy. Time range, sort, `summarize` the 4625s and 4624s, and the same query works across several machines |
| Allowed for the flag? | Only as a cross-check. The briefing says "using only your own Sentinel" | Yes, this is the evidence |

**A trap in the PowerShell method:** `-MaxEvents 1` returns the *newest* type 10 logon, whoever it belongs to. Right after my `labuser` test that's my own logon, so it works here. But in Part 2, if I (or anyone) sign in after the attack, it returns that logon instead of the intruder's. The local result only counts if its time and source IP fall where I expect them, so I always check both, and step 4 lists every logon instead of trusting the newest.

**Do both sources agree?**

| Field | Workstation | SIEM | Same? |
|---|---|---|---|
| Account (`TargetUserName`) | labuser | labuser | Yes |
| Time of the logon | 12-10-26 12:11:33 local = 10:11:33 UTC | 10:11:33.554 UTC | Yes, same second |
| Source IP (`IpAddress`) | 10.50.0.1 | 10.50.0.1 | Yes |
| Logon type | 10 | 10 (RemoteInteractive) | Yes |
| Other type 10 logons | 2 × `mustafa` on 7 Oct, 09:38:29 UTC | None | No, and that's expected |

For my `labuser` logon both sources agree to the second, so the SIEM saw it exactly as the machine did, and I can trust it for the hunt. The difference is the history: the workstation still has my first `mustafa` logon from 7 October, but the SIEM doesn't. That logon happened at 09:38 UTC, before `SecurityEvent` started collecting (~15:08 UTC). Same lesson as Mission 1: the SIEM only knows what happened after collection started.

One limit for Part 2: the source IP is the lab gateway (`10.50.0.1`) for my connections. If the intruder also came in through the gateway, the IP alone won't tell us apart. The account and the shape of the attempts will.

---

## KQL warm-up

The coach's warm-up builds the queries for the hunt step by step, on events I created myself. All queries are in `queries.kql`.

**Step 0: make known events.** RDP to my own machine as `.\labuser`: a wrong password three times, then the right one, then sign out.

| Step | What I learned | What I saw |
|---|---|---|
| 1 | A query can be just a table name (`SecurityEvent`). It returns a sample of 1000 rows, not in time order | TODO |
| 2 | `where TimeGenerated > ago(24h)` cuts by time | TODO |
| 3 | `project` keeps only the columns I want | TODO |
| 4 | Filter on `TargetUserName`, not `Account`. A failed logon writes `.\labuser`, a successful one writes `WKS-L58\labuser`, and a `\` inside quotes breaks the query | TODO |
| 5 | 4624 = logon succeeded, 4625 = logon failed. One wrong attempt can give more than one 4625 | TODO: how many 4625s for my three wrong passwords |
| 6 | `summarize count() by EventID, IpAddress` shows shapes instead of rows | TODO: failures / successes and my source IP |
| 7 | Sorted in time, a run of 4625s followed by a 4624 is what password guessing looks like | TODO: the moment failures turn into a success |
| 8 | One RDP login = two 4624s about a second apart: type 3 (network authentication, NLA) then type 10 (the desktop session) | TODO |

---

## Part 2: Hunt the real intrusion (Temps 1)

> Someone else ran an intrusion against your machine in the window your coach gave you. Reconstruct it from your Sentinel alone. Work from the authentication story first: a login does not happen without leaving a mark.

My own Part 1 activity (labuser, from my own IP) is in the same logs. The intruder is a different account, from a different machine.

**Nudge 1:** Think about what always happens when someone connects to a Windows machine, successfully or not. That family of events is where the story starts.

**Nudge 2:** An attacker who is guessing makes a very particular shape in the data before they succeed. Look for the shape, then for the moment it turns into a success.

**Nudge 3:** Once you have the successful login, everything you need about who and from where is on that same event. Read it line by line.

### 1. M2: Compromised account

**Question:** Which account did the intruder use to get into your machine? Submit the account name only, without machine or domain in front.

**First try (wrong):** my type 10 query only returned `labuser`, so I submitted `HAM{labuser}`. It was rejected. That was my own Part 1 logon, exactly what the briefing warned about: "when a login looks like it was you, it probably was".

**Instructions (on the workstation):**
1. Open PowerShell as administrator.
2. List every local account, whether it's enabled, and when it last logged on:

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

3. List every account that has ever opened an RDP session (4624 type 10), once each:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" | ForEach-Object {
    [xml]$xml = $_.ToXml()
    ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
} | Select-Object -Unique
```

4. Compare the two lists with what I know is mine (`mustafa`, and `labuser` from Part 1). The account left over is `helpdesk`, which I had already noted in Mission 1 as "from an earlier lab setup".

TODO: the `LastLogon` of `helpdesk` from step 2, and whether it showed up in step 3. If it **didn't** show up as type 10, the intruder didn't open an RDP desktop session: they logged on another way (for example a network logon, type 3). That would also explain why my first query, filtered on type 10, only found `labuser`.

**Instructions (in the SIEM):** TODO: confirm `helpdesk` in Sentinel (query "Part 2: everything about the compromised account" in `queries.kql`): the 4625s and the 4624, their logon type, time and source IP. The case file needs the SIEM evidence, not only the workstation.

**Lesson:** filtering too early hides the answer. In Mission 1 it was filtering on an Event ID I already expected. Here it was filtering on logon type 10 because I assumed the intruder used RDP. Listing *all* accounts first, then narrowing down, found it.

**Answer:** `HAM{helpdesk}` (accepted)

### 2. M2: Attack source

**Question:** From which IP address did the intrusion come?

**Instructions:**
1. Expand the successful 4624 found in challenge 1 and read `IpAddress` (and `WorkstationName`).
2. Check it isn't my own address from Part 1.

**Answer:** TODO → `HAM{a.b.c.d}`

### 3. M2: Attack technique

**Question:** What kind of attack got the intruder in? Name the technique in two words or less (or give the MITRE ATT&CK technique ID).

**Instructions:**
1. Put the failures and the success for that account in time order (query "Part 2: the shape over time").
2. TODO: describe the shape (how many failures, over how long, then the success, and the logon type).

**Answer:** TODO → `HAM{...}`

### 4. M2: Proof of access (category Mission 2 · Attack)

**Question:** The intruder left proof that they reached your workstation. Recover it.

**Instructions:** TODO

**Answer:** TODO

---

## Part 3: The gap (still Temps 1)

**Question:** What command did the attacker run once inside? Answer from Sentinel, then write in one or two sentences why the monitoring could see the login but not the action.

**What I found:** TODO (expected: the command isn't in Sentinel).

**Why:** TODO in my own words. Starting point: logons are audited by default and the "Common" set collects 4624/4625, but process creation (4688) isn't audited on WKS-L58 and Sysmon isn't installed, so a command leaves no Security event to collect. Same gap as Mission 1, where `qemu-ga` wrote files and nothing in `SecurityEvent` showed which program did it.

---

## Part 4: After the policy changes (Temps 2)

> A logging policy is switched on for everyone, and the intrusion is replayed. Hunt again, find the command the attacker ran, and compare before and after.

**Nudge 1:** The authentication events did not change. A new kind of event appeared, one that did not exist in your data in Part 2. Find what is new since the policy change, and the command is in it.

**Instructions:**
1. List the event IDs that appear after the policy change but not before (query "Part 4: what's new since the policy change").
2. TODO

**The command:** TODO → `HAM{...}` (challenge not in CTFd yet)

**Before / after:** TODO (goes into the case file).
