# CTF W6 · Encoding — write-up

**Evidence:** `stage2.b64.txt` — a single line of text described as "an
obfuscated second-stage artifact" hiding a flag under three layers.

## Stage 2 — Peel three layers (150 pts)

**Ask:** peel the three layers and submit the flag.

**Layer 1 — Base64.** The file extension is the giveaway; `base64.b64decode()`
on the one-line contents gives 119 raw bytes that are about half printable,
half binary — not valid UTF-8/ASCII text, so there's more to unwrap.

**Layer 2 — repeating-key XOR.** A crypto-pals-style Hamming-distance scan
across key sizes 1–20 didn't converge on an obvious winner (flat distances
across all sizes), which is itself informative: it means the underlying
plaintext isn't ordinary English text — it's something with its own high
entropy, i.e. the *next* layer is compressed binary, not plaintext. Rather
than guess the keysize blind, the standard gzip magic bytes (`1f 8b 08 00`)
were crib-dragged against the first 4 raw bytes: `raw[0]^0x1f = 'h'`,
`raw[1]^0x8b = 'a'`, `raw[2]^0x08 = 'm'`, `raw[3]^0x00 = 'i'` — spelling out
`"hami…"`, which is obviously the start of `hamilton` (the domain name
running through every other category in this CTF). XOR-ing the full 119
bytes with the repeating key `hamilton` reproduces a clean gzip header
followed by a valid DEFLATE stream.

**Layer 3 — gzip.** `gzip -dc` on the XOR-decoded bytes unpacks cleanly to:

```
# stage 2 (CTF lab, fictional) - flag: HAM{stage2_three_layers}
Write-Output "lab stage 2 placeholder - inert"
```

i.e. a one-line fictional "stage 2" PowerShell placeholder script with the
flag sitting in its own comment.

```python
import base64, itertools
raw = base64.b64decode(open('stage2.b64.txt').read().strip())
key = b'hamilton'
xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
# xored now starts with 1f 8b 08 00 ... -> write to a .gz and `gzip -dc` it
```

**Flag:** `HAM{stage2_three_layers}`

---

Submitted and accepted on CTFd (150 pts for the category).
