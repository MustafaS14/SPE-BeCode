# Mission 03 working notes — Locked out

> Draft. Everything below is TODO until I've actually run it. I'm keeping the same format as Mission 1 and Mission 2: Question/task, hints, instructions (the steps I actually ran), then the answer. Where Sentinel can see the step, I've added a PowerShell/attack-machine vs KQL comparison and what it signifies; most of this mission happens off the workstation, so most steps won't have a Sentinel side — that's expected, not a gap, and I note it each time.

**Redaction note:** any real credential value (the decrypted GPP password, the new Sentinel password) gets written here as `[REDACTED — recovered, rotated]`, never in plaintext. The fact that I recovered it and when is what matters for the write-up.

---

## Step 1 — See what is still exposed

**Question/task:** Find out what my workstation exposes to the network now, from my own attack machine over Tailscale.

**Hint(s):** Start broad (all ports), then look closely at whatever's listening that could hand over more than it should.

**Instructions:**
1. TODO: `nmap -sV -p- <WKS-L58 Tailscale IP>` from my attack machine — record every open port and the service/version banner.
2. TODO: note which of those services look worth a closer look (expect SMB/445 to be one).

**Answer:** TODO (list of open ports/services).

**Sentinel side:** none expected — a port scan from off-box against listening services doesn't generate a Windows Security event on its own. Noted here so the case file doesn't look like a gap.

---

## Step 2 — SMB enumeration

**Question/task:** Check whether the SMB share on WKS-L58 allows anonymous or guest access, and if so, what's on it.

**Hint(s):** Try listing shares with no credentials before trying anything else.

**Instructions:**
1. TODO: `smbclient -L //<ip> -N` (or `smbmap -H <ip>`) — record whether anonymous listing succeeds and which shares appear.
2. TODO: connect to whatever share allows it and list/pull its contents (`smbclient //<ip>/<share> -N`, then `ls`, `get`).
3. TODO: KQL — check Sentinel for the anonymous SMB access itself (logon type 3, `ANONYMOUS LOGON`, or NTLM network logons around the time of the enumeration). This is one of the few steps that *should* show up.

**Answer:** TODO (share name, what anonymous access allowed, what was retrieved).

**PowerShell (attack machine) vs KQL (Sentinel) — what it signifies:**

| | Attack-machine tool | KQL (Sentinel) |
|---|---|---|
| What it shows | TODO: the actual file listing/contents of the share | TODO: the anonymous/guest logon event itself, if any |
| Agree? | TODO once both are run | |

TODO: fill in once I've actually run the enumeration and checked Sentinel. If nothing shows up in Sentinel for this, that's worth noting — it would mean anonymous SMB access isn't being flagged, which belongs in the case file's control-gaps section.

---

## Step 3 — Group Policy Preferences credential

**Question/task:** If the SMB share held a Group Policy Preferences XML file with a `cpassword` attribute, recover the plaintext.

**Hint(s):** GPP's "encryption" uses a key Microsoft published back in 2014 (MS14-025) — this isn't something to brute-force, there are standard tools that do it in one command.

**Instructions:**
1. TODO: locate the GPP XML (classically `Groups.xml`) on the retrieved share contents.
2. TODO: run a standard GPP decrypt tool against the `cpassword` value (e.g. `gpp-decrypt`, CrackMapExec's `gpp_autologin` module, or PowerSploit's `Get-GPPPassword.ps1`).
3. Record **that** a credential was recovered and for which account — not the plaintext. `[REDACTED — recovered, rotated]`.

**Answer:** TODO (account name the credential belongs to; plaintext redacted).

**Sentinel side:** none — this decryption happens entirely on my attack machine against a file I already pulled. Nothing to query here.

---

## Step 4 — Getting back in

**Question/task:** Use the recovered credential to reconnect to WKS-L58 over RDP.

**Hint(s):** If the connection negotiates but the credential "doesn't take," it's usually not the password — it's how the RDP client is negotiating its security layer. Check the client's security-layer/NLA setting before assuming the credential is wrong.

**Instructions:**
1. TODO: attempt RDP with the recovered credential; note the exact failure mode if it doesn't work first try.
2. TODO: if it fails, check/adjust the client's security layer (e.g. mstsc Advanced → Server authentication, or the `.rdp` file's `authentication level` / `security layer` keys) and retry.
3. TODO — KQL: pull the lockout-era failed logons that led to this (4625s for the locked-out account) and the successful reconnection (4624 type 10) once it works.

**Answer:** TODO (what the actual blocker was, and the logon once it succeeded).

**PowerShell (attack machine) vs KQL (Sentinel) — what it signifies:**

| | Attack-machine side | KQL (Sentinel) |
|---|---|---|
| What it shows | The client-side negotiation failure / success | The failed and successful logon events on WKS-L58 |
| Agree? | TODO | |

This is one of the three things the brief says *will* show up in Sentinel — the reconnection itself, same as every RDP logon in Mission 2.

---

## Step 5 — Taking the proof, and seeing what they were after

**Question/task:** Retrieve the three artifacts from the regained desktop: the CTF proof flag, the new Sentinel credential, and the staged/exfiltration data cache.

**Hint(s):** None beyond: look at what's actually sitting on the desktop/profile once you're back in.

**Instructions:**
1. TODO: locate and record the proof flag.
2. TODO: locate the new Sentinel credential — `[REDACTED — recovered, rotated before use]`.
3. TODO: locate and describe (not necessarily exfiltrate further) the staged data cache — what kind of data it looks like, roughly how much, where it was staged.
4. TODO — KQL: anything workstation-side that corresponds to this session (process/file activity, if auditing is on; otherwise just the RDP session bounds from Step 4).

**Answer:** TODO.

**Rotation:** once the Sentinel credential is confirmed working, it gets rotated immediately — TODO: record that this was done (not the old or new value).

---

## PowerShell vs SIEM — overall comparison for this mission

Unlike Mission 2, most of Mission 3 happens *off* the monitored workstation — the recon, the SMB enumeration, the GPP decryption all run on my own attack machine, which isn't in Sentinel's collection scope at all. So the comparison this time isn't "did both sides agree," it's "which parts could the SIEM ever have seen, and which parts needed me there in person." TODO: write this up properly once Steps 1–5 are actually done — the short version so far: Sentinel is scoped to WKS-L58, so anything that happens on *my* machine against *their* machine over the network (the scan, the SMB listing, the decrypt) is invisible to it by design; only the inbound RDP and the anonymous SMB touch are visible, because those are things WKS-L58 itself logs.
