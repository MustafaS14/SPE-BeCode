# Detection: Mission 01, Step 6

Once everyone's machine was connected, the coach ran something on all our workstations at the same time, without telling us what it was or when it would happen. This is what I found in my SIEM.

## How I went looking

First I checked that my machine was still sending heartbeats during that time. Otherwise "nothing found" could just mean "nothing collected". Then I went through `SecurityEvent` around the time it happened, looking for anything that didn't match my own activity: event IDs I hadn't seen before, accounts I don't use, logons I didn't make.

What actually led me to it was the workstation itself. `Get-LocalUser` showed an account I hadn't seen in Know your seat, `svc_backup`, and the local Security log had a 4720 for it. My first try in Sentinel was to filter on an Event ID I already expected, which doesn't make sense when the Event ID is what you're looking for. So instead I listed every account-management event in the last 30 days. Only one burst came back, all in the same second.

## The query

```kql
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (4720, 4722, 4724, 4725, 4726, 4728, 4732, 4738, 4781)
| project TimeGenerated, EventID, Activity, SubjectAccount, TargetAccount, MemberSid, Computer
| order by TimeGenerated asc
```

## What it returned

All on 9 October 2026, on WKS-L58.hamilton.corp, done by `HAMILTON\WKS-L58$`:

| Time (UTC) | Event ID | Target | What it shows |
|---|---|---|---|
| 12:30:07.127 | 4728 | WKS-L58\None | The new account's SID (…-1008) added to the local "None" group, which Windows does for every new local user |
| 12:30:07.128 | 4720 | WKS-L58\svc_backup | A user account was created |
| 12:30:07.131 | 4722 | WKS-L58\svc_backup | The account was enabled |
| 12:30:07.131 | 4738 | WKS-L58\svc_backup | The account was changed |
| 12:30:07.167 | 4738 | WKS-L58\svc_backup | The account was changed again |
| 12:30:07.167 | 4724 | WKS-L58\svc_backup | Its password was reset |
| 12:30:07.207 | 4732 | Builtin\Administrators | SID …-1008 (svc_backup) added to the local Administrators group |

The flags for the CTF were `HAM{4720}` (creation) and `HAM{4732}` (promotion).

## What I think happened

Someone created a local account, `svc_backup`, gave it a password and put it in the local Administrators group, all within 80 milliseconds. No person types that fast, so it was a script. The account doing it is `HAMILTON\WKS-L58$`, the computer's own account, which is how actions running as SYSTEM show up. That fits the "What just happened?" part of the CTF: the coach drives our VMs from the hypervisor through the QEMU Guest Agent (`qemu-ga`), which runs as SYSTEM, without opening a session.

The name is also a typical trick: `svc_backup` looks like a service account, the kind nobody questions, but it's a brand-new local admin.

## Why I know it wasn't me

- My only RDP logon that day was at 09:27:44 UTC (logon type 7, from the lab gateway 10.50.0.1), three hours earlier. It's a type 7 because it was a reconnect to the session I opened on day one and never signed out of. The new session (type 10) was on 7 October at 09:38:29 UTC, before my SIEM collected anything. I found it in the workstation's local Security log (see runbook, step 5).
- Between 11:30 and 13:30 UTC there's no logon of type 10 or 7 at all, only the machine account's network logons (type 3) and SYSTEM's service logons (type 5).
- The events are signed by the computer account, not by `HAMILTON\mustafa`.

## Where the SIEM was blind

The same intrusion also changed my domain account: it was added to the domain group `L58-Project-Readers`. That change was logged on DC01, the domain controller, not on my workstation. My workspace only receives logs from WKS-L58, so none of it shows in Sentinel. I could only see it from the workstation with `net user %USERNAME% /domain` after signing out and in again.

## Analytics rule: new local account added to a privileged group

In my first version I only wrote "a rule that alerts on 4720 followed by 4732" as an idea. Here it is built. The full rule definition (settings, entities, MITRE mapping) is in `rules/new-local-account-added-to-privileged-group.yaml`, and the query is also in `queries.kql`.

**The logic:** a 4720 (account created) and a 4732 (member added to a local group) on the **same computer**, for the **same SID**, within **10 minutes**, where the group is a privileged built-in group. I match on the SID, not the name. In the 4732 event the member is only given as a SID (`MemberSid`), and `TargetUserName` there is the *group* name, not the user.

```kql
let window = 10m;
// Built-in local groups that give control of the machine or remote access to it
let PrivilegedLocalGroups = dynamic([
    "S-1-5-32-544",   // Administrators
    "S-1-5-32-555",   // Remote Desktop Users
    "S-1-5-32-580",   // Remote Management Users (WinRM)
    "S-1-5-32-562"    // Distributed COM Users
]);
let Created = SecurityEvent
    | where EventID == 4720
    | project CreatedTime = TimeGenerated, Computer,
              NewAccountSid = TargetSid,
              NewAccount = strcat(TargetDomainName, "\\", TargetUserName),
              CreatedBy = SubjectAccount;
let AddedToGroup = SecurityEvent
    | where EventID == 4732 and TargetSid in (PrivilegedLocalGroups)
    | project AddedTime = TimeGenerated, Computer, MemberSid,
              Group = strcat(TargetDomainName, "\\", TargetUserName),
              AddedBy = SubjectAccount;
Created
| join kind=inner AddedToGroup
    on $left.Computer == $right.Computer, $left.NewAccountSid == $right.MemberSid
| where AddedTime between ((CreatedTime - 5s) .. (CreatedTime + window))
| extend SecondsBetween = datetime_diff('millisecond', AddedTime, CreatedTime) / 1000.0
| project CreatedTime, AddedTime, SecondsBetween, Computer, NewAccount,
          NewAccountSid, Group, CreatedBy, AddedBy
```

The `- 5s` covers the case where both events carry almost the same timestamp and arrive slightly out of order.

**Rule settings:**

| Setting | Value | Why |
|---|---|---|
| Type | Scheduled | |
| Runs every / looks back | 10 min / 30 min | The lookback has to cover the 10-minute window, the time between runs and the ingestion delay (~4 min in my lab) |
| Trigger | More than 0 results | |
| Severity | High | A new admin that nobody announced is a classic persistence step |
| MITRE ATT&CK | Persistence: T1136.001 Create Account: Local Account. Privilege Escalation: T1098 Account Manipulation | |
| Entities | Account → `NewAccount` / `NewAccountSid`, Account → `CreatedBy`, Host → `Computer` | So the incident links to the user and machine pages |
| Incident grouping | Group alerts with the same entities within 1 hour | Overlapping lookbacks can match the same pair twice. This keeps it as one incident |

**Checked against the intrusion:** on 9 October the 4720 for `svc_backup` (SID …-1008) is at 12:30:07.128. The 4732 adding that same SID to `Builtin\Administrators` (S-1-5-32-544) is at 12:30:07.207. That's 0.08 s apart, on the same computer, so the rule would have fired. To check this in the workspace, run the query with the time range set to the last 30 days. It should return exactly that one row.

**How to test it live** (on WKS-L58, admin PowerShell; delete the account afterwards):

```powershell
$pw = Read-Host -AsSecureString "Test password"
New-LocalUser -Name "test_rule" -Password $pw
Add-LocalGroupMember -Group "Administrators" -Member "test_rule"
# wait for the next rule run (up to ~15 min including ingestion), check Sentinel → Incidents
Remove-LocalUser -Name "test_rule"
```

**Limits and false positives:**
- Legitimate admins and provisioning scripts (imaging, Intune, onboarding) do exactly this. In a real environment I'd allow-list the known provisioning accounts by `CreatedBy` instead of switching the rule off.
- It only catches *new* accounts. Promoting an *existing* account (like the change to my domain account) needs its own rule on 4732/4728/4756 for privileged groups alone.
- It only sees what reaches `SecurityEvent`. Right now that means WKS-L58's local groups only. The domain version of this rule (4720 then 4728/4756 into Domain Admins, Enterprise Admins and so on) needs the domain controller's logs. See the next section.

## Getting visibility on a domain controller

The change to my domain account (added to `L58-Project-Readers`) was invisible because it was logged on DC01, and only WKS-L58 sends logs to my workspace. My idea was "connect DC01". This is how a SOC actually does that.

**1. Make sure the DC logs it at all.** Domain controllers only write account and group events if the audit policy says so. That's set in the **Default Domain Controllers Policy** GPO, under Advanced Audit Policy Configuration:
- Account Management → *Audit User Account Management* and *Audit Security Group Management* (Success). This gives 4720, 4738, 4728, 4732, 4756 and similar.
- DS Access → *Audit Directory Service Changes* (Success). This gives 5136, which shows exactly which attribute changed on which AD object.
- Check it on the DC with `auditpol /get /category:*`.

For a domain group change, the event depends on the group scope: **4728** for a global group, **4732** for a domain local group, **4756** for a universal group. So the change to my account is probably a 4728 on DC01, and my workstation never sees it.

**2. Get the events off the DC.** These are the usual options:

| Option | How it works | Trade-off |
|---|---|---|
| Agent on the DC | Onboard the DC to Azure Arc (if it's on-prem), then attach the same *Windows Security Events via AMA* DCR. Events land in `SecurityEvent` next to the workstation's | Simplest, and my rules work unchanged. But it's an agent on a Tier 0 server, so it needs the AD team's approval and change control |
| Windows Event Forwarding (WEF) | The DC forwards selected events (chosen by GPO subscription) to a collector server. Only the collector runs the agent | No third-party agent on the DC, scales to many DCs. Common in SOCs. One more server to run |
| Microsoft Defender for Identity | A sensor on each DC reads the traffic and events, and sends identity alerts and `IdentityDirectoryEvents` to Defender XDR, which connects to Sentinel | Built for AD attacks (Kerberoasting, DCSync, group changes), not just raw logs. Needs licensing |

**3. Filter what you collect.** A DC generates far more Security events than a workstation, which matters for cost and for my daily cap. I'd use a custom XPath filter in the DCR instead of "All". For example, account and group management only:

```
Security!*[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4738 or EventID=4756 or EventID=4757 or EventID=5136)]]
```

Then add logon and Kerberos events (4624, 4625, 4768, 4769, 4771) once the volume is known.

**In this lab** DC01 belongs to the coach's environment, not my subscription. So the realistic path isn't to put an agent on it from my side. It's to ask for its logs: WEF to a collector I control, or the coach sharing a workspace with me (for example via Azure Lighthouse). That's how it works in a real SOC too. The SOC rarely owns the domain controllers. It has to ask the team that does.

## What I'd look at next

- Whether `svc_backup` has logged on since (4624 with `TargetUserName == "svc_backup"`), and from where.
- ~~An analytics rule in Sentinel that alerts on 4720 followed by 4732~~ → built, see above. Next: deploy it, run the live test and record the incident.
- Turning on process creation auditing (4688) or installing Sysmon, so I can see which program ran the commands, not only their result.
- Collecting the Application log at Information level, or at least the `qemu-ga` source, so guest agent activity reaches the SIEM.
- Getting DC01's account and group management events (see above), then adding the domain version of the rule.
- An alert on the daily cap (`OverQuota` in `_LogOperation`), so a log flood that blinds the SIEM gets noticed (see runbook, step 2).
