# Mission 04 working notes — A service account goes rogue

> Draft. Everything below is TODO until I've actually run it. Same format as Missions 1-3: Question/task, hints, instructions (what I actually ran), then the answer. Where Sentinel can see the step I've added the KQL and what it shows. Stage 0 (the Kerberoasting root cause) never touches my workstation, so it has no Sentinel side by design — the briefing says this up front, not a gap.

**Redaction note:** any real credential or flag value gets written here as `[REDACTED]` or by description only, never in plaintext — same rule as Mission 3.

**Mission window:** TODO — waiting on the exact start/end time the coach gives for this mission's window. Every query below needs to be scoped to it.

---

## Stage 0 — Background: how the account was stolen (root cause, not in my Sentinel)

**What the brief says:** the compromised account is a service account — one that exists to run a background service (database, backup job, etc.), not for a human to sign in with. Any AD account with a Service Principal Name (SPN) can have a Kerberos service ticket requested for it by *any* ordinary domain user, and that ticket is encrypted with the service account's own password hash. An attacker captures the ticket and cracks it offline — no failed logons, no alarm. This is Kerberoasting. It works best against a weak password and when the account still allows RC4 (as opposed to AES-only) Kerberos encryption.

This happens against the domain controller, not my workstation, and my Sentinel doesn't watch the DC yet (that's a later mission) — so this stage is reasoned from what I understand, not observed, and the report says so explicitly rather than pretending otherwise.

**Mission 4 CTFd flag — Recon (50 pts):** *"A service account on this domain advertises the kind of service it runs. Name that service type."* — TODO. This is about the SPN itself: an SPN has the form `<service-class>/<host>[:port]` (e.g. `MSSQLSvc/`, `HTTP/`, `WSMAN/`, `CIFS/`, `TERMSRV/`) — the service class in that string literally *is* "the kind of service it runs." Since I'm still domain-joined on my own workstation this mission (unlike Mission 3's external attack-machine view, where LDAP was firewalled off), I should be able to query this directly against the DC — `setspn -L <account>` or PowerShell `Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName`, or by whatever means actually resolves once I know the account name. TODO once Step 1 confirms which account it is.

---

## Step 1 — Find the logon that should not exist

**Question/task:** Find the service account's anomalous sign-on to my workstation inside the mission window.

**Hint(s):**
- Nudge 1: logon events carry the account name and the logon type. Set aside my own sign-ins and the machine's own background/service activity — looking for a non-human account signing on inside the window.
- Nudge 2: a service account's name usually points at a service, not a human. Once spotted, keep the name and exact time — that's the start of the timeline.

**Instructions:** TODO.

**Answer:** TODO.

**Sentinel side:** `SecurityEvent`, `EventID == 4624`, scoped to my workstation and the mission window — TODO exact KQL once the window is known.

---

## Step 2 — Follow what it did

**Question/task:** Reconstruct what the account ran, in order, once signed on.

**Hint(s):** Same event type as Mission 2's command-line reconstruction (process creation, full command line), filtered to this account.

**Instructions:** TODO.

**Answer:** TODO.

**Sentinel side:** `SecurityEvent`, `EventID == 4688`, filtered to the account from Step 1, ordered by time — TODO exact KQL.

---

## Step 3 — Measure the damage: what did they take?

**Question/task:** Find the data the account gathered and staged, ready to exfiltrate.

**Hint(s):** Not every action leaves a neat event — sometimes the trace is the *result* left on disk, not a log line. Look for something collected and set aside where it doesn't belong, then read the timeline around it.

**Instructions:** TODO.

**Answer:** TODO.

**Mission 4 CTFd flag — Data staged (100 pts):** TODO.

---

## Step 4 — Are they still in?

**Question/task:** Find the persistence mechanism — something that runs again on its own, on a schedule, long after the window closed.

**Hint(s):** Think about what, on Windows, can run a program by itself, repeatedly, with nobody logged in. Monitoring now records when one of those is *created*.

**Instructions:** TODO.

**Answer:** TODO.

**Mission 4 CTFd flag — Persistence (150 pts):** TODO.

**Sentinel side:** `SecurityEvent`, `EventID == 4698` (scheduled task created) — TODO exact KQL.

---

## Stretch (optional)

- One detection question I wish the SIEM had answered on its own: TODO.
- What monitoring would need to watch, and where, to catch the Kerberoasting root cause at the source: TODO.
- The single change to this service account that would have made the whole chain far harder: TODO.
