# Mission 4 — DFIR report: a service account goes rogue

> Draft — built from the mission's `CASE_FILE_TEMPLATE.md`. Every section below is TODO until the real investigation (see `notes.md`) is complete. Filled in English, guidance removed, as the template asks, once there's something real to say.

## 1. Executive summary — for a manager

TODO — three to five sentences, plain language: what happened, what was taken, and whether the intruder is still inside.

## 2. Technical narrative — for a technician

One short paragraph per stage, in order. For each: what was observed, how it's known, and the time. No commands — technique and reasoning, not a command dump.

**Stage 0 — how the account was stolen (root cause, not in my Sentinel):** TODO — reasoned from the mission brief (Kerberoasting via the account's SPN), not observed in my workspace.

**Stage 1 — the logon that should not exist:** TODO.

**Stage 2 — what the account did:** TODO.

**Stage 3 — the data it gathered and staged:** TODO.

**Stage 4 — the way it left itself back in:** TODO.

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I observed | Where I can prove it |
|---|---|---|---|---|
| 0 — root cause | TODO | TODO | TODO | reasoned — happened off my workstation |
| 1 — initial access | TODO | TODO | TODO | TODO |
| 2 — execution | TODO | TODO | TODO | TODO |
| 3 — collection / staging | TODO | TODO | TODO | TODO |
| 4 — persistence | TODO | TODO | TODO | TODO |

## 4. Impact and containment

**What was taken:** TODO — the kind of data and roughly how many records, without copying the data itself.

**Still inside?:** TODO — what makes this incident ongoing, and what would run again if nobody acts.

**Containment now:** TODO — the first actions to shut this account and this foothold down today.

## 5. Remediation — stop it happening again

| Weakness | Why it worked | Missing control + fix |
|---|---|---|
| TODO | TODO | TODO |
| TODO | TODO | TODO |

---

**Before push checklist (from the template):**
- [ ] Every section filled in English, guidance removed.
- [ ] The ATT&CK table has a technique for every stage, including the root cause.
- [ ] The impact section says what was taken and whether it is contained.
- [ ] No live passwords or flag values pasted into the report.
