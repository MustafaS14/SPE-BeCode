# CTF W6 · Network — write-up

**Evidence:** `ctf_fire_dns.pcap` — a DNS-only capture of `10.50.0.69`
(`HAMILTON\lmartens`'s workstation) talking to its resolver over roughly
24 hours spanning 12–13 Nov 2026. Read with `tcpdump -r ctf_fire_dns.pcap -nn`
(no special DNS-parsing tool needed — plain-text query/response lines are
enough).

## The shape of the traffic

Almost all of the capture is ordinary Windows/Microsoft noise (Windows
Update, telemetry, MSN, Bing, Teams/Skype config, etc.) resolved against one
internal resolver. Buried in it is a second, very regular pattern: a fixed
subdomain queried every ~10 minutes, plus one short, dense burst of queries
to a different subdomain pattern under the same base domain — a classic
DNS beacon (low-and-slow check-in) paired with a DNS-exfiltration burst.

## DNS resolver (50 pts)

**Ask:** which DNS resolver does the workstation use?

Every single query in the capture — Microsoft noise and malicious traffic
alike — targets the same destination on port 53:

```
10.50.0.69.xxxxx > 10.50.0.10.53: ... A? ...
```

**Flag:** `10.50.0.10`

## Beacon domain (50 pts)

**Ask:** what domain is used for the beacon callbacks?

Filtering for the fixed, repeating subdomain (as opposed to Microsoft's
legitimate traffic) surfaces:

```
08:36:05.754943 IP 10.50.0.69.65353 > 10.50.0.10.53: 16639+ A? 7f3a9c.b.cdn-hamilton-sync.test. (49)
```

`cdn-hamilton-sync.test` looks deliberately designed to blend in with
Hamilton's own naming, with a `b.` prefix marking the beacon channel
(distinct from the `x.` exfil channel below).

**Flag:** `cdn-hamilton-sync.test`

## Beacon interval (100 pts)

**Ask:** how often does it call home?

Pulling every timestamp for `7f3a9c.b.cdn-hamilton-sync.test` queries shows
a steady cadence: `08:36:05`, `08:46:03`, `08:56:03`, `09:06:03`, `09:16:03`,
`09:26:03`, … — one query roughly every 600 seconds, for hours on end (with
occasional near-duplicate retries a few milliseconds apart, consistent with
`Resolve-DnsName` retrying on a slow/failed first attempt).

**Flag:** `10 minutes`

## Victim ID (100 pts)

**Ask:** the beacon encodes a victim identifier. What is it?

The beacon subdomain is constant across the whole capture:
`7f3a9c.b.cdn-hamilton-sync.test` — the leading label is the only
per-host-looking value, and it never changes, i.e. it's this workstation's
assigned victim/implant ID.

**Flag:** `7f3a9c`

## Reconstruct exfil (150 pts)

**Ask:** reassemble the exfiltrated data from the DNS queries and submit the
flag hidden inside it.

Separate from the `b.` beacon channel, a short burst of queries hits a
different pattern — random-looking Base32-shaped labels under `x.`:

```
grep -oE "[a-z0-9]{6,}\.x\.cdn-hamilton-sync\.test" sysmon_strings.txt | sort -u
```

16 distinct labels, each the data-carrying payload of one DNS exfil query.
Concatenating them in capture-chronological order, upper-casing, padding to
a multiple of 8 characters with `=`, and Base32-decoding:

```python
import base64
labels = [ ... ]  # in pcap timestamp order
blob = ''.join(labels).upper()
blob += '=' * ((-len(blob)) % 8)
base64.b32decode(blob)
```

produces a readable CSV of (fake) Hamilton supplier-payment records, with
the flag embedded as a comment line in the middle of the data:

```
date,supplier,invoice_ref,beneficiary,iban,amount_eur,notes
2026-10-14,Verhaegen Packaging,PO-88214-A,Verhaegen Packaging BV,BE68539007547034,4280.50,paid
2026-10-28,Meersman Food Supplies,MF-2026-0912,Meersman Food Supplies SA,BE43068999999501,1120.00,paid
2026-11-04,Verhaegen Packaging,PO-88214-B,Verhaegen Packaging BV,BE68539007547034,3975.20,pending
# HAM{supplier_data_exfiltrated}
2026-11-06,Dierckx Labels NV,DL-7741,Dierckx Labels NV,BE71096123456769,640.75,paid
```

**Flag:** `HAM{supplier_data_exfiltrated}`

## Correlate PID (150 pts)

**Ask:** correlate the pcap with the host logs — what PID produced the
beacon traffic?

The pcap alone has no process info, so this needs the Sysmon log
(`Microsoft-Windows-Sysmon_Operational_tir.evtx`) cross-referenced by
timestamp. Sysmon Event ID 22 (DNS query) records, per event: `UtcTime`
(string) → a 16-byte binary `ProcessGUID` → a 4-byte little-endian
`ProcessId` → the `QueryName` string — all laid out contiguously in the raw
`.evtx` bytes. Locating the very first beacon query's `QueryName`
occurrence (`7f3a9c.b.cdn-hamilton-sync.test`, matching the pcap's first hit
at `08:36:05`) and reading the 4 bytes immediately preceding it:

```python
idx = data.find('7f3a9c.b.cdn-hamilton-sync.test'.encode('utf-16-le'))
pid = struct.unpack('<I', data[idx-4:idx])[0]   # -> 3568
```

gives the PID of the `powershell.exe` instance that issued it — the same
process whose Sysmon Event ID 1 creation record is also the first malicious
execution timestamp found in the Logs category
(`2026-11-12 08:26:00.009`, see `logs.md`).

**Flag:** `3568`

---

All six submitted and accepted on CTFd (600 pts total for the category).
