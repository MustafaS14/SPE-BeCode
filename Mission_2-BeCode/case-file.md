# Case file: intrusion on WKS-L58

This is the hand-in for Mission 2. It's written so a teammate can follow what happened on my machine without me in the room. Every claim points to an event in my own Sentinel workspace. Times are in UTC.

> Draft. TODO marks what still has to come from my results.

## Summary

On 12 October 2026 between 12:39 and 13:13 UTC, someone at `10.50.0.100` (WKSTN-07) brute-forced the local account `helpdesk` on my workstation WKS-L58: five wrong passwords in a third of a second, then a success, four times. Each success opened a Remote Desktop session. In the last one they left `flag.txt` on the `helpdesk` Desktop (13:13:01) and signed out 20 seconds later. My Sentinel saw every failed and successful logon, but not the file or the command that wrote it: process creation isn't audited.

## Scope

| | |
|---|---|
| Machine | WKS-L58.hamilton.corp |
| Attack window | 12 October 2026, 12:39:57 → 13:13:21 UTC |
| Evidence source | My Sentinel workspace (`SecurityEvent`), plus the workstation itself where noted |
| My own activity | Part 1 `labuser` logon at 10:11:33 UTC from `10.50.0.1` (the lab gateway), before the attack and from a different address |

## Timeline

| Time (UTC) | What happened | Evidence (event, key fields) |
|---|---|---|
| 12:39:57.465 → .787 | Round 1: five failed logons for `helpdesk`, ~80 ms apart | 5 × 4625, type 3, from `10.50.0.100` (WKSTN-07) |
| 12:39:57 → 12:40:01 | Round 1 succeeds, RDP session opens | 4624 type 3 (NLA), then 4624 type 10 at 12:40:01.480 |
| 12:49:52 | Round 2: same pattern (5 failures, success, session) | 5 × 4625, 4624 type 3 + type 10 |
| 13:05:48 | Round 3: same pattern | 5 × 4625, 4624 type 3 + type 10 |
| 13:12:28 → 13:12:32 | Round 4: same pattern, last session at 13:12:32.657 | 5 × 4625, 4624 type 3 + type 10 |
| 13:11:36 | During the round 3 session: a user's local group membership is enumerated | 4798 |
| 13:13:01 | `flag.txt` created on the `helpdesk` Desktop: the proof of access (`HAM{rdp_pwned_seat58}`) | Workstation only (file creation time). Sentinel: 10 × 4799 (group membership enumerated) in the same second, no file or process event |
| 13:13:21 | `helpdesk` logs off | 4634 |
| TODO | Command run once inside | Not visible in Temps 1 (0 × 4688). TODO in Temps 2 |

## Findings

**Account used:** `helpdesk`, a local account that already existed on WKS-L58. **Source:** `10.50.0.100` (WKSTN-07). **Technique:** brute force, password guessing (T1110.001). (CTFd accepted `HAM{brute_force}`, and `HAM{T1021.001}`, RDP, is also accepted: one is how the password was found, the other how it was used.)

I first filtered on RDP logons (type 10) and only found my own `labuser` test, which was rejected. Listing every local account on the workstation showed `helpdesk` with a fresh `LastLogon`. In Sentinel, every `helpdesk` logon comes from one source, `10.50.0.100`, while all my own connections come from the gateway `10.50.0.1`. Queries: `queries.kql`, "Part 2".

**Why brute force:**
- **Speed:** five failed logons in 0.32 seconds, 80 ms apart. That's a tool, not a person typing.
- **Failure reason:** every 4625 has SubStatus `0xc000006a`, meaning "right user name, wrong password". The attacker knew the account and was guessing only its password.
- **Target:** one account (`helpdesk`), one source (`10.50.0.100`). That's password guessing, not password spraying (one password against many accounts).
- **End of the attempts:** the failures stop at the first success, which is used immediately: type 3 (NLA), then a type 10 RDP session two seconds later.
- **Repetition:** the same five failures and a success, four times. That fits a script replaying a short password list.

The account was never locked: the attempt after five failures still worked each time. So there's no account lockout, or the threshold is above five. See `notes.md`, challenge 4, for the full reasoning and both sources.

## Two sources, one answer

I confirmed the logon in two places: the workstation's own Security log (PowerShell) and Sentinel (KQL). The case rests on Sentinel, because the mission asks for it and because events there can't be wiped by someone who gets admin on the machine. The local log is a cross-check.

| Question | PowerShell (workstation) | KQL (Sentinel) | What the comparison means |
|---|---|---|---|
| Which account? | `Get-LocalUser`: `helpdesk`, last logon 12:49:55 | 20 failed + 4 successful logons for `helpdesk` | Agree. Listing existing accounts found it; the SIEM explained it |
| From where? | `Get-WinEvent` 4624 type 10: 4 sessions from `10.50.0.100` | Same 4 sessions, same IP, same second | Agree exactly: nothing lost between the machine and the SIEM |
| What kind of attack? | 4625s with SubStatus `0xc000006a` (wrong password) | Failures and successes in one timeline, 80 ms apart | Complete each other: the reason from one, the shape from the other |
| What did they leave? | `Get-ChildItem` / `Get-Content`: `flag.txt`, created 13:13:01, with the flag | No file or command (0 × 4688, 0 × 4104), only 10 × 4799 at 13:13:01 | Only the workstation could answer. The SIEM shows *when* the intruder acted, not *what* they did |

In short: every logon answer was the same in both places, which shows my collection works for logon events. What happened *inside* the session is only on the workstation. PowerShell needs XML parsing by hand and only sees one machine; Sentinel answers the same question in a few lines, keeps every attempt, and can't be wiped by someone with admin rights on the machine. The full comparison of the two methods is in `notes.md`.

## MITRE ATT&CK mapping

| Step | Tactic | Technique (ID) |
|---|---|---|
| Getting the password | Credential Access | Brute Force: Password Guessing (T1110.001) |
| Logging in remotely | Lateral Movement | Remote Services: Remote Desktop Protocol (T1021.001) |
| Using a local account | Initial Access / Persistence | Valid Accounts: Local Accounts (T1078.003) |
| Running a command | TODO | TODO |

## Before / after the logging policy

| | Temps 1 (default logging) | Temps 2 (after the policy) |
|---|---|---|
| Failed and successful logons | All of them: 20 × 4625, 4 × 4624 type 3 + type 10, source IP | TODO |
| The command the attacker ran | Not visible: 0 × 4688, 0 × 4104. Only side effects like 10 × 4799 at 13:13:01 | TODO |
| Why | TODO | TODO |

TODO: one paragraph. What default logging missed, what the policy made visible, and what that means for what a SIEM can and can't tell you.

## Stretch

- **Detection question for next week's rule:** TODO (in plain English).
- **For a non-technical manager:** TODO (three sentences: what the attacker could have done next if nobody had noticed).
