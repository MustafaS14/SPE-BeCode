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

**What it left behind:** TODO: the time of my labuser logon and the events I found (expected: a 4624 type 3 then a type 10 for the logon, a 4634/4647 for the sign-out, and **nothing** for `whoami`, because process creation isn't audited).

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

**Instructions (on the workstation):**
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

**Instructions (in the SIEM):**
1. In Sentinel → Logs, list every successful RDP logon, newest first:

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, Activity
| sort by TimeGenerated desc
```

2. Rule out my own logons (my domain account, and `labuser` from Part 1 from my own IP). The account left over in the attack window is the intruder's.
3. TODO: what it looked like (time, and the failures before it).

**Answer:** TODO → `HAM{...}` (not submitted yet, the flag isn't open)

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
