# Mission 05: Catch it at the source

Direct hands-on follow-up to [Mission 4](../Mission_4-BeCode). In Mission 4 Part 2 I
Kerberoasted my own seat's service account (`svc-app58`) myself and found that the
ticket-request step was invisible to my own, workstation-scoped Sentinel workspace —
Event 4769 (Kerberos Service Ticket Requested) is written by the domain controller,
not the requesting workstation. This mission closes that blind spot: the coach
connected the DC to a new **shared, class-wide** Sentinel workspace (`log-hamilton`),
and the job is to find that same attack at the source, turn it into a real detection
rule, and prove the rule catches both a replay of my own attack and an attack I
didn't launch.

| File | What's in it |
|---|---|
| [notes.md](notes.md) | My working notes for all eight steps: finding the ticket request at the DC, parsing packed XML event data, identifying the RC4 signal, the live replay, generalizing the query, building the analytics rule, and triaging a live attack |
| [queries.kql](queries.kql) | Every KQL query run in the shared workspace |

**The actual hand-in for this mission is not a file here** — it's a new **Detection**
section appended to [Mission 4's case-file.md](../Mission_4-BeCode/case-file.md), per
the mission brief. This folder holds the supporting working notes and queries, same
as every other mission folder.

**No CTFd flag for this mission.** The incident raised by my own replay is
proof-along-the-way; the case file is the deliverable.

**Shared-workspace rules:** every analytics rule I create is prefixed `L58 - `; I
never edit, disable, or delete a rule, incident, or setting I didn't create — every
change is attributed. Mission 4's rules of engagement still apply when replaying the
attack: my own seat's service account only.

**Status: in progress — Steps 1-3 done (shared workspace confirmed, own Kerberoast
ticket found at the DC, RC4 encryption identified as the distinguishing signal
across the whole domain). Steps 4-8 (replay + timing, detection rule, proof-of-fire,
triage) still to come.**
# Mission 05: Catch it at the source

Direct hands-on follow-up to [Mission 4](../Mission_4-BeCode). In Mission 4 Part 2 I
Kerberoasted my own seat's service account (`svc-app58`) myself and found that the
ticket-request step was invisible to my own, workstation-scoped Sentinel workspace —
Event 4769 (Kerberos Service Ticket Requested) is written by the domain controller,
not the requesting workstation. This mission closes that blind spot: the coach
connected the DC to a new **shared, class-wide** Sentinel workspace (`log-hamilton`),
and the job is to find that same attack at the source, turn it into a real detection
rule, and prove the rule catches both a replay of my own attack and an attack I
didn't launch.

| File | What's in it |
|---|---|
| [notes.md](notes.md) | My working notes for all eight steps: finding the ticket request at the DC, parsing packed XML event data, identifying the RC4 signal, the live replay, generalizing the query, building the analytics rule, and triaging a live attack |
| [queries.kql](queries.kql) | Every KQL query run in the shared workspace |

**The actual hand-in for this mission is not a file here** — it's a new **Detection**
section appended to [Mission 4's case-file.md](../Mission_4-BeCode/case-file.md), per
the mission brief. This folder holds the supporting working notes and queries, same
as every other mission folder.

**No CTFd flag for this mission.** The incident raised by my own replay is
proof-along-the-way; the case file is the deliverable.

**Shared-workspace rules:** every analytics rule I create is prefixed `L58 - `; I
never edit, disable, or delete a rule, incident, or setting I didn't create — every
change is attributed. Mission 4's rules of engagement still apply when replaying the
attack: my own seat's service account only.

**Status: in progress — Steps 1-3 done (shared workspace confirmed, own Kerberoast
ticket found at the DC, RC4 encryption identified as the distinguishing signal
across the whole domain). Steps 4-8 (replay + timing, detection rule, proof-of-fire,
triage) still to come.**
