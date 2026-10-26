# Mission 03 working notes — Locked out

> Draft. Everything below is TODO until I've actually run it. I'm keeping the same format as Mission 1 and Mission 2: Question/task, hints, instructions (the steps I actually ran), then the answer. Where Sentinel can see the step, I've added a PowerShell/attack-machine vs KQL comparison and what it signifies; most of this mission happens off the workstation, so most steps won't have a Sentinel side — that's expected, not a gap, and I note it each time.

**Redaction note:** any real credential value (the decrypted GPP password, the new Sentinel password) gets written here as `[REDACTED — recovered, rotated]`, never in plaintext. The fact that I recovered it and when is what matters for the write-up.

---

## Step 1 — See what is still exposed

**Question/task:** Find out what my workstation exposes to the network now, from my own attack machine over Tailscale.

**Hint(s):** Start broad (all ports), then look closely at whatever's listening that could hand over more than it should.

**Instructions:**
1. Found the workstation's real address first — it isn't `WKS-L58` by name anywhere in my tailnet. `tailscale status` only shows my own device (`mus`) and lab infrastructure (`pve-*` hosts, other people's laptops). One entry, `target` (`100.66.55.46`, owned by `jay.park@`), looked like a mission-style placeholder name and I nearly scanned it — turned out to belong to someone else's exercise, not mine. Lesson: don't assume from a generic-looking hostname: verify. The real address, `10.50.0.58`, is on the internal `hamilton.corp` network (same `10.50.0.0/24` range as the gateway and the Mission 2 attacker IP) and is reachable once my Tailscale client accepts the subnet route (`tailscale set --accept-routes`). Confirmed alive: `ping 10.50.0.58` → 4/4 replies, TTL 127 (Windows).
2. `nmap -sV -p- 10.50.0.58` — the full 65535-port SYN scan wasn't usable: Nmap's raw packet crafting doesn't work reliably over the Tailscale virtual adapter on Windows (`Error compiling our pcap filter`, then `All 1000 scanned ports ... filtered` even with `--send-ip`). Switched to a TCP connect scan, which uses the real OS socket stack instead of raw packets, and narrowed to the top 1000 ports for speed:
   ```
   nmap -sV -sT -Pn -T4 --top-ports 1000 10.50.0.58
   ```

**Answer:**

| Port | State | Service |
|---|---|---|
| 445/tcp | open | microsoft-ds? (SMB) |
| 3389/tcp | open | ms-wbt-server (RDP) |

998 other ports in the top-1000 list: filtered. OS fingerprint: Windows.

**Sentinel side:** none expected — a port scan from off-box against listening services doesn't generate a Windows Security event on its own. Noted here so the case file doesn't look like a gap.

---

## Step 2 — SMB enumeration

**Question/task:** Check whether the SMB share on WKS-L58 allows anonymous or guest access, and if so, what's on it.

**Hint(s):** Try listing shares with no credentials before trying anything else.

**Instructions:**
1. `smbclient -L //10.50.0.58 -N` from WSL (native Windows `net use` kept dropping into an interactive password prompt instead of testing anonymous access cleanly — not useful for this). Anonymous *enumeration* of share names succeeded:
   ```
   Sharename       Type      Comment
   ---------       ----      -------
   ADMIN$          Disk      Remote Admin
   C$              Disk      Default share
   IPC$            IPC       Remote IPC
   Public          Disk
   SMB1 disabled -- no workgroup available
   ```
   `ADMIN$`, `C$`, `IPC$` are just Windows' default administrative shares (every machine has these). `Public` is the one custom, non-default share — the obvious target.
2. Tried to actually read `Public`, three different anonymous/guest-style logins, all denied:
   - `smbclient //10.50.0.58/Public -N` → connects, but `ls` → `NT_STATUS_ACCESS_DENIED listing \*`
   - `smbclient //10.50.0.58/Public -U 'guest%'` → connects, same access-denied on `ls`; guessed `cd Policies` → `NT_STATUS_OBJECT_NAME_NOT_FOUND` (that folder doesn't exist, or I can't even get an error that confirms a path)
   - `smbmap -H 10.50.0.58 -u 'guest' -p ''` → session authenticated, but: `ADMIN$ NO ACCESS`, `C$ NO ACCESS`, `IPC$ READ ONLY`, `Public NO ACCESS`
   - `smbmap -H 10.50.0.58 -u '' -p ''` (true blank, not named Guest) → `Established 0 SMB session(s)` — couldn't even connect this way
3. Tried the RPC side of `IPC$` too, in case it revealed anything (user list, share info, domain info) even without file access:
   - `rpcclient -U '' -N 10.50.0.58` → `Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED`
   - `rpcclient -U 'guest%' 10.50.0.58` → connects. `srvinfo` works (`10.50.0.58 Wk Sv NT`, platform_id 500, os version 10.0, server type 0x1003 — just confirms it's a Windows 10/11-era host). `enumdomusers` → `NT_STATUS_CONNECTION_DISCONNECTED`. `netshareenum` → `WERR_ACCESS_DENIED`. `querydominfo` → `NT_STATUS_CONNECTION_DISCONNECTED`.
4. KQL — haven't checked Sentinel for the anonymous SMB access itself yet (logon type 3, `ANONYMOUS LOGON`/Guest, from my Tailscale-assigned address). TODO once I'm past this gate, so I'm not burning a Sentinel query on something I'll want to re-run with a tighter time window later.

**Answer:** `Public` exists and anonymous enumeration finds it, but nothing I tried (true null session, Guest with blank password, blank/anonymous auth, or RPC via IPC$) can actually read it. This is a consistent, reproducible "no" across two different protocols (SMB file access and RPC) and three auth styles each — not a fluke or a syntax mistake on my end. Only the baseline `srvinfo` RPC call (which Windows exposes to basically anyone) succeeded; everything that would reveal users, shares, or domain info is denied. **Escalated to the coach** rather than continuing to guess blindly: asked whether `Public` is meant to be anonymously readable for this mission, or whether there's a specific account/step I'm missing. Waiting on a reply before going further here.

**PowerShell (attack machine) vs KQL (Sentinel) — what it signifies:**

| | Attack-machine tool | KQL (Sentinel) |
|---|---|---|
| What it shows | Share names enumerable anonymously; share *contents* denied under every anonymous method tried | TODO: haven't queried yet — should show the anonymous/guest logon attempts from my Tailscale address, if logon auditing on WKS-L58 covers them |
| Agree? | TODO once the KQL side is run | |

If Sentinel doesn't show these anonymous SMB attempts at all, that's worth noting in the case file's control-gaps section on its own — it would mean anonymous access attempts against a workstation aren't being surfaced, independent of whether `Public` turns out to be readable.

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
