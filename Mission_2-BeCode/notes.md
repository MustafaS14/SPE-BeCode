# Notes: Mission 02 (Your first intrusion)

My notes from Mission 2 of the BeCode Hamilton CTF. I play attacker on my own machine first (Part 1), then hunt the real intrusion in my Sentinel (Parts 2 to 4). Every challenge is written the same way as in Mission 1: question, hints, then what I actually did and the answer.

> TODO marks something I still have to fill in from my own notes or results. Nothing below a TODO is a confirmed finding yet.

| | |
|---|---|
| Workstation | WKS-L58 (WKS-L58.hamilton.corp) |
| SIEM | My Sentinel workspace from Mission 1 (`SecurityEvent` through `dcr-securityevents`, "Common" set) |
| Attack window (from my own SIEM) | 12 October 2026, 12:39:57 → 13:12:32 UTC (four rounds, see Part 2) |
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

The coach's warm-up builds the hunting queries step by step on events you create yourself (three wrong passwords for `labuser`, then the right one). I already learned these basics in Mission 1, so I didn't redo it. What it covers, for reference:

| Step | What it teaches |
|---|---|
| 1–3 | A query starts from a table (`SecurityEvent`), `where TimeGenerated > ago(24h)` cuts by time, `project` keeps the columns you want |
| 4 | Filter on `TargetUserName`, not `Account`: a failed logon writes `.\labuser`, a successful one `WKS-L58\labuser`, and a `\` inside quotes breaks the query |
| 5 | 4624 = logon succeeded, 4625 = logon failed. One wrong attempt can produce more than one 4625 |
| 6 | `summarize count() by EventID, IpAddress` shows shapes instead of rows |
| 7 | Sorted in time, a run of 4625s followed by a 4624 is what password guessing looks like |
| 8 | One RDP login = two 4624s about a second apart: type 3 (network authentication, NLA) then type 10 (the desktop session) |

---|---|---|
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

Output of step 2 (times are VM local, UTC+2):

| Name | Enabled | LastLogon (local) | LastLogon (UTC) |
|---|---|---|---|
| Administrator | False | | |
| becode | True | never | |
| DefaultAccount | False | | |
| Guest | False | | |
| **helpdesk** | **True** | **12-10-26 14:49:55** | **12 Oct 12:49:55** |
| labuser | True | 12-10-26 12:11:33 | 12 Oct 10:11:33 (my Part 1 logon) |
| WDAGUtilityAccount | False | | |

`helpdesk` logged on at 12:49:55 UTC today, about two and a half hours after my `labuser` test, and I didn't do it. That's the intrusion, and it gives me the time to centre the SIEM search on. (`becode` is enabled but has never logged on.)

Why my earlier type 10 listing only showed `labuser` and `mustafa`: I ran it at about 12:24 UTC, and the intrusion started at 12:39:57 UTC. It hadn't happened yet. The intruder *did* open RDP sessions (see below).

**Instructions (in the SIEM):**
1. Summarise every logon of `helpdesk` by logon type and source:

```kql
SecurityEvent
| where TimeGenerated > ago(48h)
| where TargetUserName == "helpdesk"
| where EventID in (4624, 4625)
| summarize Fail = countif(EventID == 4625), OK = countif(EventID == 4624),
            First = min(TimeGenerated), Last = max(TimeGenerated)
            by LogonType, IpAddress, WorkstationName
```

| LogonType | IpAddress | WorkstationName | Fail | OK | First (UTC) | Last (UTC) |
|---|---|---|---|---|---|---|
| 3 | 10.50.0.100 | WKSTN-07 | 20 | 4 | 12:39:57.465 | 13:12:31.034 |
| 10 | 10.50.0.100 | WKS-L58 | 0 | 4 | 12:40:01.480 | 13:12:32.657 |

2. Break it down per minute to see the rounds (query "Part 2: helpdesk rounds per minute" in `queries.kql`):

| Minute starting (UTC) | Failed (4625) | Success type 3 | Success type 10 |
|---|---|---|---|
| 12:39:57 | 5 | 1 | 0 |
| 12:40:01 | 0 | 0 | 1 |
| 12:49:52 | 5 | 1 | 1 |
| 13:05:48 | 5 | 1 | 1 |
| 13:12:28 | 5 | 1 | 1 |

The first five failures of round 1 are at 12:39:57.465, .547, .625, .705 and .787, about 80 ms apart. No person types five passwords in a third of a second: it's a script.

**Workstation vs SIEM:** the workstation's `LastLogon` for `helpdesk` (12:49:55 UTC) falls inside round 2 in the SIEM, so both sources agree. I ran `Get-LocalUser` between round 2 and round 3, which is why it shows round 2 and not the last one.

**Lesson:** filtering too early hides the answer. In Mission 1 it was filtering on an Event ID I already expected. Here it was filtering on logon type 10 because I assumed the intruder used RDP. Listing *all* accounts first, then narrowing down, found it.

**Answer:** `HAM{helpdesk}` (accepted)

### 2. M2: Attack source

**Question:** From which IP address did the intrusion come?

**Instructions (on the workstation):**
1. Open PowerShell as administrator.
2. List every RDP logon (4624 type 10) of `helpdesk`, with its time and source IP:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $user = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
    if ($user -eq 'helpdesk') {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            UserName    = $user
            ClientIP    = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
        }
    }
} | Format-Table -AutoSize
```

| TimeCreated (VM local, UTC+2) | UTC | UserName | ClientIP |
|---|---|---|---|
| 12-10-26 15:12:32 | 13:12:32 | helpdesk | 10.50.0.100 |
| 12-10-26 15:05:54 | 13:05:54 | helpdesk | 10.50.0.100 |
| 12-10-26 14:49:55 | 12:49:55 | helpdesk | 10.50.0.100 |
| 12-10-26 14:40:01 | 12:40:01 | helpdesk | 10.50.0.100 |

**Instructions (in the SIEM):**
1. List the RDP logons of `helpdesk` in Sentinel, newest first:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where TargetUserName == "helpdesk"
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, Activity
| sort by TimeGenerated desc
```

2. The summary query from challenge 1 confirms it for the failed logons too: every `helpdesk` logon, failed or successful, comes from **`10.50.0.100`**, a machine called **WKSTN-07**. On the type 10 events, `WorkstationName` shows WKS-L58 (my machine, where the session opens), so the source machine's name is read from the type 3 events.

**Comparison:** both sources give the same four RDP sessions, from the same IP, at the same times (for example 12:40:01 locally and 12:40:01.480 in Sentinel, 13:12:32 and 13:12:32.657). `10.50.0.100` is not my address: my own connections all come through the lab gateway (`10.50.0.1`), as my `labuser` test showed. Here the workstation gives the IP as well, because I read it from the 4624 events instead of from `Get-LocalUser`.

**Answer:** `HAM{10.50.0.100}` (accepted)

### 3. M2: Attack technique

**Question:** What kind of attack got the intruder in? Name the technique in two words or less (or give the MITRE ATT&CK technique ID).

**Instructions (on the workstation):**
1. Open PowerShell as administrator.
2. List every failed logon (4625) from `10.50.0.100`, with the account and the `SubStatus` (the reason it failed):

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625)]]" | ForEach-Object {
    [xml]$xml = $_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        UserName    = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
        ClientIP    = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
        SubStatus   = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubStatus').'#text'
    }
} | Where-Object { $_.ClientIP -eq '10.50.0.100' } | Format-Table -AutoSize
```

Every row is `helpdesk`, from `10.50.0.100`, with SubStatus **`0xc000006a`**, in groups of five with the same timestamp (for example five at 15:12:28 local and more at 15:05:48).

**Instructions (in the SIEM):**
1. Put every failed and successful logon from that IP in time order:

```kql
SecurityEvent
| where EventID in (4625, 4624)
| where IpAddress == "10.50.0.100"
| project TimeGenerated, EventID, Activity, TargetUserName, IpAddress, LogonType
| sort by TimeGenerated asc
```

| TimeGenerated (UTC) | EventID | TargetUserName | LogonType |
|---|---|---|---|
| 12:39:57.465 | 4625 (failed) | helpdesk | 3 |
| 12:39:57.547 | 4625 (failed) | helpdesk | 3 |
| 12:39:57.625 | 4625 (failed) | helpdesk | 3 |
| 12:39:57.705 | 4625 (failed) | helpdesk | 3 |
| 12:39:57.787 | 4625 (failed) | helpdesk | 3 |
| 12:39:59.910 | 4624 (success) | helpdesk | 3 |
| 12:40:01.480 | 4624 (success) | helpdesk | 10 |
| 12:49:52.330 | 4625 (failed) | helpdesk | 3 |
| 12:49:52.413 | 4625 (failed) | helpdesk | 3 |
| 12:49:52.498 | 4625 (failed) | helpdesk | 3 |
| … | the same pattern at 12:49, 13:05 and 13:12 | | |

**Why I'm calling it brute force:**

1. **The speed.** Five failed logons in 0.32 seconds, about 80 ms apart. Nobody types five passwords that fast, so it's a tool, not a person.
2. **The reason for the failures.** SubStatus `0xc000006a` means "the user name is correct, but the password is wrong". The attacker already had a valid account name and was only guessing its password. If they were guessing account names, I'd see `0xc0000064` ("no such user") instead.
3. **One account, one source.** All 20 failures target `helpdesk` and all come from `10.50.0.100`. Many passwords against one account is password guessing. The opposite pattern, one password tried against many accounts, would be password spraying, and many sources would point to a botnet.
4. **The failures stop at the first success.** As soon as a password works, there are no more 4625s. The tool gets a type 3 success (the network authentication that RDP does first, NLA), and two seconds later a type 10 (the desktop session opens). It found the password and used it straight away.
5. **The same shape four times.** Four rounds, each exactly five failures and then a success. That fits a script replaying the same short password list, where the right password comes after five wrong ones.

So it's brute force, more precisely password guessing (MITRE ATT&CK T1110.001), over RDP. One more thing it shows: the account was never locked, since the attempt after five wrong passwords still worked. So either there's no account lockout policy on WKS-L58, or its threshold is higher than five.

**Answer:** `HAM{brute_force}` (accepted)

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
