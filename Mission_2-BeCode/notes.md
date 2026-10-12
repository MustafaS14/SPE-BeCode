# Notes: Mission 02 (Your first intrusion)

My notes from Mission 2 of the BeCode Hamilton CTF. I played attacker on my own machine first (Part 1), then hunted the real intrusion (Parts 2 to 4). Every challenge is written the same way as in Mission 1: question, hints (the briefing's nudges, since these CTFd challenges have none), then what I actually did and the answer. Each challenge is solved twice, with PowerShell on the workstation and with KQL in Sentinel, and the two are compared.

> TODO marks something still open. Nothing marked TODO is a confirmed finding yet.

My seat in one table:

| | |
|---|---|
| Workstation | WKS-L58 (WKS-L58.hamilton.corp), clock in Romance Standard Time (UTC+2 in October) |
| SIEM | My Sentinel workspace from Mission 1 (`SecurityEvent` through `dcr-securityevents`, "Common" set) |
| Attack window (from my own SIEM) | 12 October 2026, 12:39:57 → 13:12:32 UTC |
| Lab account for Part 1 | `labuser`, a local account on WKS-L58 (password sent privately by the coach, not written here) |
| My own source IP | `10.50.0.1`, the lab gateway that relays all my RDP connections |

---

## Part 1: Make some noise yourself

> Before you hunt, play attacker for five minutes. Open a new Remote Desktop connection to your own machine and sign in as `labuser`, run one harmless command (`whoami` is enough), then **sign out**, and look at what your own action left behind in the log.

### 1. My own footprint

**Question:** Log in to your own machine as `labuser`, run `whoami`, sign out, then point to your own `labuser` login in the log.

**Hint 1:** Use Remote Desktop, but sign in as the lab account. It lives on the machine itself, not in the domain, so type the user name as `.\labuser` (the `.\` means "this machine").

**Hint 2:** Run one small command, like `whoami`, then sign out and open your logs. You are measuring your own footprint, not going further.

**Instructions:**
1. Open Remote Desktop Connection (mstsc) to my own workstation's address.
2. Sign in with user name `.\labuser` and the password from the coach.
3. Run `whoami`. It returns `wks-l58\labuser`.
4. Sign out from the Start menu (not just closing the window, which only disconnects the session).
5. On the workstation, open PowerShell as administrator and get the latest successful RDP logon (4624 with logon type 10):

```powershell
$event = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10']]" -MaxEvents 1
[xml]$xml = $event.ToXml()
$xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName' | Select-Object -ExpandProperty '#text'
```

It returns `labuser`.

6. `-MaxEvents 1` only gives the newest one, so list **every** type 10 logon with its time, account and source IP:

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

| TimeCreated (VM local) | UTC | UserName | ClientIP |
|---|---|---|---|
| 12-10-26 12:11:33 | 12 Oct 10:11:33 | labuser | 10.50.0.1 |
| 07-10-26 11:38:29 | 7 Oct 09:38:29 | mustafa | 10.50.0.1 |
| 07-10-26 11:38:29 | 7 Oct 09:38:29 | mustafa | 10.50.0.1 |

The two `mustafa` rows are my very first RDP connection from Mission 1 (the type 10 the coach asked about). `labuser` has one row where `mustafa` has two: my account is an admin, so Windows logs a second logon for the elevated half of its split token. `labuser` is a standard user.

7. In Sentinel → Logs, list every successful RDP logon, newest first:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, Activity
| sort by TimeGenerated desc
```

Over the last 7 days it returns exactly one row:

| TimeGenerated (UTC) | Computer | TargetUserName | IpAddress | LogonTypeName |
|---|---|---|---|---|
| 12/10/2026 10:11:33.554 | WKS-L58.hamilton.corp | labuser | 10.50.0.1 | 10 - RemoteInteractive |

**Answer:** my `labuser` logon is at 12 October, 10:11:33 UTC, from `10.50.0.1` (the lab gateway, not my laptop), as RDP (type 10). It's in both the workstation and Sentinel. TODO: the other events it left (expected: a 4634/4647 for the sign-out, and **nothing** for `whoami`, because process creation isn't audited).

**Before you leave: PowerShell vs SIEM**

The two sources in general:

| | Workstation (local Security log, PowerShell) | SIEM (`SecurityEvent` in Sentinel, KQL) |
|---|---|---|
| Where the data lives | On WKS-L58 itself, the machine that gets broken into | In my Log Analytics workspace, copied there by the AMA through `dcr-securityevents` |
| What I need to read it | An RDP session and an admin PowerShell on that machine | Only the portal. I never have to touch the machine |
| Can the attacker tamper with it? | Yes. With admin rights they can clear the log (that leaves a 1102, but the logons are gone) | Not after ingestion. Events already sent stay in the workspace |
| Format | Raw XML. Fields are read by name through `ToXml()` (reading `Properties[n]` by position is fragile) | Already split into columns: `TargetUserName`, `IpAddress`, `LogonTypeName`, `Activity` |
| Which events | Everything the audit policy writes | Only what the DCR collects (the "Common" set), and only while under the daily cap |
| How far back | As far as the local log goes before it rolls over (20 MB; mine goes back to 21 September) | Only since collection started (7 October, ~15:08 UTC for `SecurityEvent`), for the workspace's retention |
| Time zone | The VM's local time (UTC+2 in October) | UTC (`TimeGenerated`) |
| Delay | Immediate | A few minutes of ingestion delay |
| Seeing the whole picture | Hard. Every question needs its own script | Easy. Time range, sort, `summarize`, and the same query works across several machines |
| Allowed for the flag? | Only as a cross-check. The briefing says "using only your own Sentinel" | Yes, this is the evidence |

For this logon:

| Field | Workstation | SIEM | Same? |
|---|---|---|---|
| Account | labuser | labuser | Yes |
| Time | 12:11:33 local = 10:11:33 UTC | 10:11:33.554 UTC | Yes, same second |
| Source IP | 10.50.0.1 | 10.50.0.1 | Yes |
| Logon type | 10 | 10 (RemoteInteractive) | Yes |
| Other type 10 logons | 2 × `mustafa` on 7 Oct, 09:38:29 UTC | None | No, and that's expected |

What it signifies: both sources agree to the second, so the SIEM saw my logon exactly as the machine did, and I can trust it for the hunt. The difference is the history: the workstation still has my first `mustafa` logon from 7 October, but the SIEM doesn't, because it happened before `SecurityEvent` started collecting. Same lesson as Mission 1: the SIEM only knows what happened after collection started.

Two traps for later: `-MaxEvents 1` returns the *newest* logon, whoever it belongs to, so step 6 lists all of them instead. And my own source IP is the gateway (`10.50.0.1`), so if an intruder also came through the gateway, the IP alone wouldn't separate us.

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

---

## Part 2: Hunt the real intrusion (Temps 1)

> Someone else ran an intrusion against your machine in the window your coach gave you. Reconstruct it from your Sentinel alone. Work from the authentication story first: a login does not happen without leaving a mark.

My own Part 1 activity (`labuser`, from `10.50.0.1`) is in the same logs. The intruder is a different account, from a different machine.

### 2. M2: Compromised account

**Question:** Which account did the intruder use to get into your machine? Submit the account name only, without machine or domain in front.

**Hint 1:** Think about what always happens when someone connects to a Windows machine, successfully or not. That family of events is where the story starts.

**Instructions:**
1. Open PowerShell as administrator on the workstation.
2. List every local account, whether it's enabled, and when it last logged on:

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

| Name | Enabled | LastLogon (local) | LastLogon (UTC) |
|---|---|---|---|
| Administrator | False | | |
| becode | True | never | |
| DefaultAccount | False | | |
| Guest | False | | |
| **helpdesk** | **True** | **12-10-26 14:49:55** | **12 Oct 12:49:55** |
| labuser | True | 12-10-26 12:11:33 | 12 Oct 10:11:33 (my Part 1 logon) |
| WDAGUtilityAccount | False | | |

3. List every account that has ever opened an RDP session (4624 type 10), once each:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" | ForEach-Object {
    [xml]$xml = $_.ToXml()
    ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
} | Select-Object -Unique
```

4. Compare with what I know is mine (`mustafa`, and `labuser` from Part 1). The account left over is `helpdesk`, which I had already noted in Mission 1 as "from an earlier lab setup". It logged on at 12:49:55 UTC, about two and a half hours after my `labuser` test, and it wasn't me.
5. In Sentinel → Logs, summarise every logon of `helpdesk` by logon type and source:

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

6. Break it down per minute to see the rounds (query "Part 2: helpdesk rounds per minute" in `queries.kql`):

| Minute starting (UTC) | Failed (4625) | Success type 3 | Success type 10 |
|---|---|---|---|
| 12:39:57 | 5 | 1 | 0 |
| 12:40:01 | 0 | 0 | 1 |
| 12:49:52 | 5 | 1 | 1 |
| 13:05:48 | 5 | 1 | 1 |
| 13:12:28 | 5 | 1 | 1 |

**Answer:** `helpdesk` → `HAM{helpdesk}`. My first try, `HAM{labuser}`, was rejected: my type 10 query only showed `labuser` because I ran it at about 12:24 UTC, before the intrusion started (12:39:57). That was my own Part 1 logon, exactly what the briefing warned about: "when a login looks like it was you, it probably was".

**PowerShell vs SIEM**

| | PowerShell (workstation) | KQL (Sentinel) |
|---|---|---|
| Code | `Get-LocalUser`, then `Get-WinEvent` for 4624 type 10, unique user names | `SecurityEvent`, 4624 and 4625 for `helpdesk`, `summarize` by logon type, IP and workstation |
| Starting point | The accounts that *exist* on the machine | The logons that *happened* |
| Result | `helpdesk` is enabled, last logon 12:49:55 UTC, not one of mine | `helpdesk`: 20 failed logons and 4 successful logins from `10.50.0.100`, 12:39:57 → 13:12:32 UTC |
| Agree? | Yes. `LastLogon` 12:49:55 falls inside round 2 in Sentinel (I ran `Get-LocalUser` between rounds 2 and 3) | |

What it signifies: PowerShell was better for *finding* the account. Starting from the accounts that exist showed the one I didn't recognise, while my first KQL query, filtered on what I expected, only showed my own `labuser`. Sentinel was better for *understanding* it: `Get-LocalUser` only keeps the last logon, with no source and no failures, while the SIEM has every attempt. Lesson: filtering too early hides the answer, as in Mission 1 when I filtered on an Event ID I already expected.

### 3. M2: Attack source

**Question:** From which IP address did the intrusion come?

**Hint 1:** Once you have the successful login, everything you need about who and from where is on that same event. Read it line by line.

**Instructions:**
1. Open PowerShell as administrator on the workstation.
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

| TimeCreated (VM local) | UTC | UserName | ClientIP |
|---|---|---|---|
| 12-10-26 15:12:32 | 13:12:32 | helpdesk | 10.50.0.100 |
| 12-10-26 15:05:54 | 13:05:54 | helpdesk | 10.50.0.100 |
| 12-10-26 14:49:55 | 12:49:55 | helpdesk | 10.50.0.100 |
| 12-10-26 14:40:01 | 12:40:01 | helpdesk | 10.50.0.100 |

3. In Sentinel → Logs, list the RDP logons of `helpdesk`, newest first:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where TargetUserName == "helpdesk"
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, Activity
| sort by TimeGenerated desc
```

4. Read `IpAddress`: **`10.50.0.100`** on every row. The summary from challenge 2 shows the failed logons come from the same address, a machine called **WKSTN-07**. (On the type 10 events `WorkstationName` shows WKS-L58, my machine, where the session opens, so the source machine's name comes from the type 3 events.)
5. Check it isn't me: my own connections all come from the lab gateway, `10.50.0.1`.

**Answer:** `10.50.0.100` → `HAM{10.50.0.100}`

**PowerShell vs SIEM**

| | PowerShell (workstation) | KQL (Sentinel) |
|---|---|---|
| Code | `Get-WinEvent` with an XPath filter on 4624 type 10, then reading `TargetUserName` and `IpAddress` out of each event's XML, keeping `helpdesk` | `where EventID == 4624`, `where LogonType == 10`, `where TargetUserName == "helpdesk"`, `project` the columns |
| Effort | A `ForEach-Object` loop that parses XML by hand | Four lines. The fields are already columns |
| Result | 4 sessions from `10.50.0.100`: 12:40:01, 12:49:55, 13:05:54, 13:12:32 UTC | The same 4 sessions from `10.50.0.100`, to the second (12:40:01.480, …, 13:12:32.657) |
| Agree? | Yes, same sessions, same IP, same times | |

What it signifies: for the source IP both sources say exactly the same thing, so nothing was lost on the way from the machine to the SIEM. The difference is the cost: on the workstation I have to know the event structure and parse it myself, while in Sentinel the same answer is a filter on ready-made columns.

### 4. M2: Attack technique

**Question:** What kind of attack got the intruder in? Name the technique in two words or less (or give the MITRE ATT&CK technique ID).

**Hint 1:** An attacker who is guessing makes a very particular shape in the data before they succeed. Look for the shape, then for the moment it turns into a success.

**Instructions:**
1. Open PowerShell as administrator on the workstation.
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

3. In Sentinel → Logs, put every failed and successful logon from that IP in time order:

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

4. Read the shape: in each round, five failed logons in about a third of a second, then a success (type 3, then type 10), four rounds in a row.

**Answer:** brute force → `HAM{brute_force}`. `HAM{T1021.001}` is also accepted: that's the MITRE ID for *Remote Services: Remote Desktop Protocol*. The two answers are two halves of the same attack: brute force is how the password was found, RDP is how the intruder used it to get in.

**Why I'm calling it brute force:**

1. **The speed.** Five failed logons in 0.32 seconds, about 80 ms apart. Nobody types five passwords that fast, so it's a tool, not a person.
2. **The reason for the failures.** SubStatus `0xc000006a` means "the user name is correct, but the password is wrong". The attacker already had a valid account name and was only guessing its password. If they were guessing account names, I'd see `0xc0000064` ("no such user") instead.
3. **One account, one source.** All 20 failures target `helpdesk` and all come from `10.50.0.100`. Many passwords against one account is password guessing. The opposite pattern, one password tried against many accounts, would be password spraying, and many sources would point to a botnet.
4. **The failures stop at the first success.** As soon as a password works, there are no more 4625s. The tool gets a type 3 success (the network authentication that RDP does first, NLA), and two seconds later a type 10 (the desktop session opens). It found the password and used it straight away.
5. **The same shape four times.** Four rounds, each exactly five failures and then a success. That fits a script replaying the same short password list, where the right password comes after five wrong ones.

So it's brute force, more precisely password guessing (MITRE ATT&CK T1110.001), over RDP. It also shows that the account was never locked, since the attempt after five wrong passwords still worked. So either there's no account lockout policy on WKS-L58, or its threshold is higher than five.

**PowerShell vs SIEM**

| | PowerShell (workstation) | KQL (Sentinel) |
|---|---|---|
| Code | `Get-WinEvent` for all 4625s, reading `TargetUserName`, `IpAddress` and `SubStatus` from the XML, keeping `10.50.0.100` | `where EventID in (4625, 4624)`, `where IpAddress == "10.50.0.100"`, sorted by time |
| What it shows | Only the failures, but **with the reason** (`SubStatus` `0xc000006a` = wrong password) | Failures **and** successes in one timeline |
| Time precision | Seconds: the five failures of a round share one timestamp | Milliseconds: the five failures are 80 ms apart |
| Agree? | Yes: same account, same IP, groups of five at the same moments | |

What it signifies: here the two sources complete each other. The workstation gave me *why* the logons failed (a wrong password for a real account). The SIEM gave me the *shape*: failures and successes together, close enough in time to prove a script. `SubStatus` is in `SecurityEvent` too. I didn't project it, but the SIEM alone could have answered both. The workstation was simply where I saw the reason first.

### 5. M2: Proof of access

**Question:** The intruder left proof that they reached your workstation. Recover it.

**Instructions:** TODO

**Answer:** TODO

---

## Part 3: The gap (still Temps 1)

> Try to answer one more question from your Sentinel: what command did the attacker run once inside? You will probably fail, and that is the lesson.

### 6. The command I can't see

**Question:** What command did the attacker run once inside? Answer from Sentinel, then write in one or two sentences why the monitoring could see the login but not the action.

**Instructions:**
1. In Sentinel, look for process creation events (4688) in the attack window (query "Part 3" in `queries.kql`).
2. TODO: what I found.

**Answer:** TODO (expected: the command isn't in Sentinel). Why, in my own words: TODO. Starting point: logons are audited by default and the "Common" set collects 4624/4625, but process creation (4688) isn't audited on WKS-L58 and Sysmon isn't installed, so a command leaves no Security event to collect. Same gap as Mission 1, where `qemu-ga` wrote files and nothing in `SecurityEvent` showed which program did it.

---

## Part 4: After the policy changes (Temps 2)

> A logging policy is switched on for everyone, and the intrusion is replayed. Hunt again. This time, find the command the attacker ran on your machine and submit it in CTFd. Then compare: same attack, what you could see before, what you can see now.

### 7. The command, after the policy change

**Question:** Find the command the attacker ran on your machine.

**Hint 1:** The authentication events did not change. A new kind of event appeared, one that did not exist in your data in Part 2. Find what is new since the policy change, and the command is in it.

**Instructions:**
1. List the event IDs that appear after the policy change but not before (query "Part 4: what's new since the policy change" in `queries.kql`).
2. TODO

**Answer:** TODO → `HAM{...}` (challenge not in CTFd yet)

**Before you leave: before / after**

TODO (goes into the case file): same attack, what default logging showed, and what the policy made visible.
