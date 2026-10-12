# Case file: intrusion on WKS-L58

This is the hand-in for Mission 2. It's written so a teammate can follow what happened on my machine without me in the room. Every claim points to an event in my own Sentinel workspace. Times are in UTC.

> Draft. TODO marks what still has to come from my results.

## Summary

TODO: three or four sentences. Who got in, from where, how, what they did, and what my monitoring saw and missed.

## Scope

| | |
|---|---|
| Machine | WKS-L58.hamilton.corp |
| Attack window | TODO |
| Evidence source | My Sentinel workspace (`SecurityEvent`), plus the workstation itself where noted |
| My own activity in the same window | Part 1 `labuser` logons from my own IP (TODO: IP), excluded from the story below |

## Timeline

| Time (UTC) | What happened | Evidence (event, key fields) |
|---|---|---|
| TODO | First failed logon attempts | 4625, `TargetUserName`, `IpAddress`, `LogonType` |
| TODO | Successful logon | 4624 type 3 then type 10, same account and IP |
| TODO | Command run once inside | Not visible in Temps 1. 4688 in Temps 2 |
| TODO | Proof of access left on the machine | TODO |
| TODO | Sign-out / disconnect | 4634 / 4647 |

## Findings

**Account used:** TODO. **Source:** TODO. **Technique:** TODO.

TODO: how I got there, with the queries (see `queries.kql`) and why I'm sure it wasn't my own Part 1 activity.

## MITRE ATT&CK mapping

| Step | Tactic | Technique (ID) |
|---|---|---|
| Getting the password | TODO | TODO |
| Logging in remotely | TODO | TODO |
| Using a local account | TODO | TODO |
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
