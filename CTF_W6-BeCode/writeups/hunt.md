# CTF W6 · Hunt — write-up

**Evidence:** `Security_DC01_tir.evtx` — the domain controller's Security event
log (`DC01.hamilton.corp`), covering roughly 11–13 Nov 2026.

This one didn't yield to the `strings -el` + `grep` approach that worked for
the Logs/Network/Disk categories. The DC's Security log is large (500k+
events once fully downloaded — the first download attempt was silently
truncated mid-chunk, which is its own lesson: always sanity-check a chunked
`.evtx` file's last chunk header against the actual bytes on disk before
trusting a "no matches" result) and almost all of the interesting fields
(`EventID`, `Status`, `TargetUserName`, …) are proper **binary XML
substitutions**, not literal text the way the lab-generated Logs/Sysmon
evidence happened to be. Grepping for `4625` or `FailureReason` turns up
nothing because those values are never stored as decimal ASCII or as a
literal field name/value pair in the file — they're binary-encoded per the
real [MS-EVTX] "BinXml" template format.

So this category was solved by writing a small from-scratch EVTX binary XML
parser in Python against the real format: locate chunks (`ElfChnk\x00` every
64 KiB), locate each record (`\x2a\x2a\x00\x00` signature), walk its
`TemplateInstanceToken`, skip over the (optionally inline) template
definition, then read the record's **substitution array** — a `count`
followed by `(size, type)` descriptors and the concatenated raw value bytes.
`EventID` turned out to sit at a fixed substitution index (3, type
`UInt16`) for every single record regardless of event type, because the
`<System>` portion of the template is identical for all Security-Auditing
events and substitution indices are assigned once per the provider's fixed
field order — so one small parser gives a reliable `EventID` histogram for
the whole file, then a second pass decodes each event type's own nested
`EventData` substitution array (its own `count`/descriptor/value trailer)
against that event ID's known Microsoft field order.

## Targeted account (50 pts)

**Ask:** which account was hit by the authentication failures?

Histogramming every record's `EventID` this way turns up exactly 9 Event ID
4625 ("An account failed to logon") records — split into two unrelated
clusters by `TargetUserName`/`IpAddress`: 3 against `sajjad` from `10.50.0.1`
(unrelated background noise), and 6 against one account from the already
compromised host (see below). Decoding the 4625 `EventData` substitutions
(`TargetUserName`, `TargetDomainName`, `Status`, `SubStatus`, `IpAddress`, …)
for that second cluster:

```
TargetUserName = 'helpdesk'
TargetDomainName = 'HAMILTON'
Status = '0xc000006d' / SubStatus = '0xc000006a'   # bad password
WorkstationName = 'HAM-FIN-WKS07'
IpAddress = '10.50.0.69'
```

Six failed NTLM logons against the same account, roughly every 24 seconds
(`10:20:00` → `10:22:01` on 12 Nov), a classic scripted password-guessing
burst.

**Flag:** `helpdesk`

## Source IP (100 pts)

**Ask:** from which IP did those failed authentications originate?

Same decoded `EventData` as above — all 6 failures carry `IpAddress =
10.50.0.69` and `WorkstationName = HAM-FIN-WKS07`, i.e. `lmartens`'s own
already-compromised workstation (the same host and persistence established
in the Logs/Network/Disk categories) was used to try — and fail — to
authenticate as `helpdesk`.

**Flag:** `10.50.0.69`

## Kerberos services (150 pts)

**Ask:** during the domain discovery, which Kerberos service ticket(s) did
the workstation request for `lmartens`?

Filtering the same parser's output for Event ID 4769 ("A Kerberos service
ticket was requested") where `TargetUserName` starts with `lmartens` turns
up 10 records. Eight of them are just routine ticket renewal for `DC01$`,
evenly spaced roughly 10 hours apart (lmartens's normal Kerberos ticket
lifetime). But three land within 130 ms of each other at `10:05:01` on 12
Nov — 15 minutes before the `helpdesk` brute-force burst above — requesting
`DC01$` (twice) and `krbtgt`: the signature of a *de novo* domain-query tool
(LDAP enumeration against the DC needs its own TGS, preceded by a fresh TGT)
rather than a long-lived session simply renewing its existing ticket. That
tight burst is the actual "domain discovery" moment.

**Flag:** `DC01$`

---

All three submitted and accepted on CTFd (300 pts total for the category).
