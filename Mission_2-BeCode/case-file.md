# Case file: intrusion on WKS-L58

This is the hand-in for Mission 2. It's written so a teammate can follow what happened on my machine without me in the room. Every claim points to an event in my own Sentinel workspace. Times are in UTC.

> Draft. TODO marks what still has to come from my results.

## Summary

On 12 October 2026 between 12:39 and 13:12 UTC, someone at `10.50.0.100` (WKSTN-07) brute-forced the local account `helpdesk` on my workstation WKS-L58: five wrong passwords in a third of a second, then a success, four times. Each success opened a Remote Desktop session. My Sentinel saw every failed and successful logon. TODO: what they did once inside, and what my monitoring missed.

## Scope

| | |
|---|---|
| Machine | WKS-L58.hamilton.corp |
| Attack window | 12 October 2026, 12:39:57 → 13:12:32 UTC |
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
| TODO | Command run once inside | Not visible in Temps 1. 4688 in Temps 2 |
| TODO | Proof of access left on the machine | TODO |
| TODO | Sign-out / disconnect | 4634 / 4647 |

## Findings

**Account used:** `helpdesk`, a local account that already existed on WKS-L58. **Source:** `10.50.0.100` (WKSTN-07). **Technique:** brute force, password guessing (T1110.001).

I first filtered on RDP logons (type 10) and only found my own `labuser` test, which was rejected. Listing every local account on the workstation showed `helpdesk` with a fresh `LastLogon`. In Sentinel, every `helpdesk` logon comes from one source, `10.50.0.100`, while all my own connections come from the gateway `10.50.0.1`. The 20 failures in four bursts of five, 80 ms apart, rule out a person typing. Queries: `queries.kql`, "Part 2".

## Two sources, one answer

I confirmed the logon in two places: the workstation's own Security log (PowerShell) and Sentinel (KQL). The case rests on Sentinel, because the mission asks for it and because events there can't be wiped by someone who gets admin on the machine. The local log is a cross-check.

| Field | Workstation | Sentinel | Same? |
|---|---|---|---|
| Account | `helpdesk` (`Get-LocalUser`) | `helpdesk` | Yes |
| Logon time (UTC) | `LastLogon` 12:49:55 | Round 2, 12:49:52 → 12:49:56 | Yes |
| Source IP | Not shown by `Get-LocalUser` | `10.50.0.100` | Only in the SIEM |

What the comparison shows: the workstation tells me *that* `helpdesk` logged on and when it last did, but not from where, how often, or how many attempts failed first. The SIEM has the whole story: 20 failed logons, 4 successful logins (each one a type 3 plus a type 10 event), one source. For the hunt itself, Sentinel was the better tool. The full comparison of the two methods is in `notes.md`.

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
| Failed and successful logons | TODO | TODO |
| The command the attacker ran | TODO | TODO |
| Why | TODO | TODO |

TODO: one paragraph. What default logging missed, what the policy made visible, and what that means for what a SIEM can and can't tell you.

## Stretch

- **Detection question for next week's rule:** TODO (in plain English).
- **For a non-technical manager:** TODO (three sentences: what the attacker could have done next if nobody had noticed).
