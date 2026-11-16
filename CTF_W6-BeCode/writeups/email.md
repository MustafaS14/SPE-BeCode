# CTF W6 · Email — write-up

**Evidence:** `maildir.zip` — 22 exported messages (`01.eml`–`22.eml`) from Lucie
Martens' (`lmartens@hamilton.corp`) mailbox at Hamilton, covering a normal
purchase-order thread with a real supplier plus everyday internal traffic. Two
of the 22 messages are malicious.

Read each `.eml`'s headers directly (`From`, `Return-Path`, `Received`,
`Reply-To`, `Authentication-Results`), per `TOOLKIT.md`'s guidance for email
evidence — no special tool needed, just `cat`.

## Spotting the two malicious messages

Walking the thread chronologically, two messages stand out against the
legitimate PO-88214 conversation with Tom Verhaegen at the real
`verhaegen-packaging.test` domain:

- **`05.eml`** (Wed 11 Nov 2026, 13:52) — subject *"Payment confirmation
  required - overdue invoice"*. Claims to be `accounts@hamilton.corp` but its
  `Reply-To` is `recover-billing@secure-paymentdesk.test`, `Return-Path` is the
  same external domain, and `Authentication-Results` reads
  `spf=softfail ... dkim=none`. A generic "Dear user" payment-release lure —
  not even pretending to be part of the PO-88214 thread.
- **`06.eml`** (Thu 12 Nov 2026, 09:12) — subject *"Re: PO-88214 - Updated bank
  details"*. This one is far more convincing: it has an `In-Reply-To` /
  `References` chain that slots it directly into the real PO-88214 thread
  (replying to Tom's own `04.eml`), and the display name is "Tom Verhaegen".
  But the `From`/`Return-Path`/`Received` domain is `verhaegen-packagings.test`
  — note the extra **s** — a typosquat of the real `verhaegen-packaging.test`,
  served from `185.220.101.47` with `spf=fail, dkim=none`. It asks Lucie to
  switch the IBAN used for `INV-2026-1147`, a classic invoice-fraud / BEC
  pivot.

(Confirmed as the only two suspicious ones: Lucie and the helpdesk's Sarah
even flag `05.eml` as phishing in a separate internal thread — `17.eml`/`18.eml`
— "that's phishing - do not click, I'll report it".)

## Email 1 — First contact (50 pts)

**Ask:** submit the exact subject line of the attacker's first contact (the
earlier of the two malicious emails by timestamp).

`05.eml` (11 Nov 13:52) predates `06.eml` (12 Nov 09:12), so it's the first
contact.

**Flag:** `Payment confirmation required - overdue invoice`

## Email 2 — Real sender domain (50 pts)

**Ask:** for the message sitting inside the legitimate PO-88214 thread that
asks to change the bank account/IBAN (`06.eml`), what domain did its sender
actually use?

`From`, `Return-Path`, and the `Received` line in `06.eml` all point to the
same typosquatted domain:

**Flag:** `verhaegen-packagings.test`

## Email 2 — Origin IP (100 pts)

**Ask:** the IP address of the server that message was received from.

From `06.eml`'s `Received` header: `from mail.verhaegen-packagings.test
([185.220.101.47])`.

**Flag:** `185.220.101.47`

## Email 2 — SPF verdict (100 pts)

**Ask:** the SPF result the mail server recorded for that message, one word.

From `06.eml`'s `Authentication-Results`: `spf=fail smtp.mailfrom=mail.verhaegen-packagings.test`.

**Flag:** `fail`

---

All four submitted and accepted on CTFd (300 pts total for the category).
