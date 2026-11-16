# CTF W6 · Warm-up — write-up

No evidence download needed for this category — every challenge is a short encoded
string given directly in the challenge text, meant to be peeled apart with
CyberChef (or, equivalently, a couple of lines of Python — what I actually used,
since the transforms involved are simple enough to do without the GUI and it's
easier to show the exact steps here).

## Warm-up 1 — Base64 (50 pts)

**Given:** `SEFNe2I2NF9pc19qdXN0X2VuY29kaW5nfQ==`

Single layer, plain Base64. Decoding it directly gives the flag:

```
base64.b64decode("SEFNe2I2NF9pc19qdXN0X2VuY29kaW5nfQ==")
-> HAM{b64_is_just_encoding}
```

**Flag:** `HAM{b64_is_just_encoding}`

## Warm-up 2 — ROT13 + hex (50 pts)

**Given:** `554e5a7b65626731335f637968665f75726b7d`

Two reversible layers, as the prompt says. The string is hex first — decoding the
hex bytes gives `UNZ{ebg13_cyhf_urk}`, which is itself the flag run through ROT13
(a 13-position Caesar shift, its own inverse). Decoding hex, then applying ROT13
to the result:

```
bytes.fromhex("554e5a7b65626731335f637968665f75726b7d")
-> b'UNZ{ebg13_cyhf_urk}'
codecs.decode("UNZ{ebg13_cyhf_urk}", "rot13")
-> HAM{rot13_plus_hex}
```

**Flag:** `HAM{rot13_plus_hex}`

## Warm-up 3 — Windows FILETIME (50 pts)

**Given:** `133758548410000000` (a FILETIME value — 100-nanosecond intervals
since 1601-01-01 UTC), asked to convert to the equivalent UNIX epoch in whole
seconds.

Standard conversion: divide by 10,000,000 to get seconds since the FILETIME
epoch, then subtract the number of seconds between the FILETIME epoch
(1601-01-01) and the UNIX epoch (1970-01-01), which is 11,644,473,600 seconds.

```
133758548410000000 / 10_000_000 - 11644473600 = 1731381241
```

(Sanity check: that's 2024-11-12 03:14:01 UTC — a plausible artifact timestamp.)

**Flag:** `1731381241`

## Warm-up 4 — Peel the recipe (100 pts)

**Given:** `H4sIANPb9moC%2F%2FNw9K3OLc0pyYwvLkktiC9KTc4sSC2uBQA9oBaqFwAAAA%3D%3D`

Three steps, outermost first, exactly as the prompt frames it:

1. **URL-decode** the `%2F` and `%3D` escapes back to `/` and `=`, giving
   `H4sIANPb9moC//Nw9K3OLc0pyYwvLkktiC9KTc4sSC2uBQA9oBaqFwAAAA==`.
2. **Base64-decode** that string. The result starts with the gzip magic bytes
   (`\x1f\x8b`, which is what `H4sI` in Base64 encodes to), confirming the next
   step.
3. **Gunzip** the decoded bytes to get the plaintext flag.

```
urllib.parse.unquote(given) -> base64 string
base64.b64decode(...) -> gzip bytes
gzip.decompress(...) -> HAM{multi_step_recipes}
```

**Flag:** `HAM{multi_step_recipes}`

---

All four submitted and accepted on CTFd (200 pts total for the category).
