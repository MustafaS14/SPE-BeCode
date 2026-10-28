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
4. KQL, once Sentinel access was restored (Step 5): queried `SecurityEvent` for `EventID == 4624`, `LogonType == 3`, `Account` matching `ANONYMOUS LOGON` or `Guest`, scoped to `Computer has "WKS-L58"`. Three matches: `WKS-L58\Guest` at 11:36:47 UTC (my very first `smbclient -L -N` pass), then `WORKGROUP\ANONYMOUS LOGON` at 15:34:17 and `WKS-L58\Guest` at 15:35:15 (the second round, after the coach's nudge, re-trying blank/anonymous and Guest auth before widening the scan). All three logged `IpAddress = 10.50.0.1` — not my own Tailscale address. That's the subnet router's gateway address inside `hamilton.corp` (the `pve-ryzen` box advertising the `10.50.0.0/24` route): because my traffic enters through that router, WKS-L58 sees everything as coming from the gateway, masking the actual originating machine.

**Answer:** `Public` exists and anonymous enumeration finds it, but nothing I tried (true null session, Guest with blank password, blank/anonymous auth, or RPC via IPC$) can actually read it. This is a consistent, reproducible "no" across two different protocols (SMB file access and RPC) and three auth styles each — not a fluke or a syntax mistake on my end. Only the baseline `srvinfo` RPC call (which Windows exposes to basically anyone) succeeded; everything that would reveal users, shares, or domain info is denied. **Escalated to the coach** rather than continuing to guess blindly: asked whether `Public` is meant to be anonymously readable for this mission, or whether there's a specific account/step I'm missing.

**Update — resolved by widening the scan to the whole subnet.** The coach's follow-up ("knock on 445 and see what happens") and a classmate's description of the intended approach both pointed the same way: use `10.50.0.58`'s own subnet (`10.50.0.0/24`) to scan for *other* hosts, not just keep hammering `Public` on WKS-L58 itself.

1. Full subnet sweep, first pass (top 20 ports, for speed): `nmap -sT -Pn -T4 --top-ports 20 10.50.0.0/24`. This turned up a contiguous block of hosts, `10.50.0.50`–`10.50.0.68` (with gaps at `.60` and `.65`), all sharing WKS-L58's exact signature (445 + 3389 open) — plus two standouts: `10.50.0.10` (445 only, no 3389) and `10.50.0.240` (closed 445/3389, but an unexpected 8000/tcp open — turned out to be an unrelated internal web app, a dead end for this mission).
2. Checked anonymous SMB access across the `.50`–`.68` block with `smbmap -H <ip> -u 'guest' -p ''` for every host. Every host matched WKS-L58's "Public: NO ACCESS" pattern — **except `10.50.0.50`, where `Public` came back `READ ONLY`.** That's the actual foothold: one host in a block of near-identical decoys where the share is genuinely readable anonymously.
3. `smbclient //10.50.0.50/Public -U 'guest%'` → in: one file, `account-access.txt` (123 bytes). Downloaded with `get account-access.txt`, read with `cat`:
   ```
   Training account (temporary, to be rotated):
   Username: training01
   Password: [REDACTED — recovered, to be rotated]
   proof: HAM{anon_smb_seat50}
   ```
4. Tried to use `training01` right away — against WKS-L58's `Public` share, against `.50`'s own `ADMIN$`/`C$`, and by guessing `SYSVOL`/`NETLOGON` share names on both hosts. All denied or `NT_STATUS_BAD_NETWORK_NAME` (share doesn't exist). Also tried resolving `hamilton.corp` and querying DNS directly against `.1`, `.58`, `.50`, `.10` (both via the default resolver and by pointing `nslookup` straight at each host's port 53) — every attempt timed out or NXDOMAIN'd. No domain controller is reachable from my attack machine over this Tailscale subnet route, by IP or by name.

**Conclusion:** `training01` is confirmed to be a real, low-privilege domain account — per the person who pointed me at this, it only has access to "the domain share" (i.e. SYSVOL), not to anything local on these workstations. Since I can't reach a DC from off-box at all (no DNS, no SMB share by that name anywhere I've checked), this account is most likely meant to be used *from inside* the domain network — i.e. after RDP'ing into WKS-L58 in Step 4, where the workstation's own domain-joined DNS/Kerberos would actually resolve `hamilton.corp`. Revisiting Step 3 properly once Step 4 (getting back in over RDP) is done.

**PowerShell (attack machine) vs KQL (Sentinel) — what it signifies:**

| | Attack-machine tool | KQL (Sentinel) |
|---|---|---|
| What it shows | Share names enumerable anonymously; share *contents* denied on WKS-L58 itself — but a sibling host in the same subnet block (`10.50.0.50`) anonymously exposes `Public` as read-only, containing a training credential | 3× successful `EventID 4624`, `LogonType 3` events for `WKS-L58\Guest` and `WORKGROUP\ANONYMOUS LOGON`, matching the timing of my enumeration attempts |
| Agree? | Yes — Sentinel independently confirms both the account names and the logon type my own tools reported, and shows the anonymous enumeration *succeeded* at the SMB/NTLM auth layer even though the share contents were denied | |

Sentinel does log these anonymous SMB attempts, which is reassuring — but the `IpAddress` it captures (`10.50.0.1`, the subnet router's gateway) isn't attributable to my actual attack machine. That's a real control-gap-adjacent finding: a defender reviewing these logs could confirm *that* anonymous access happened and *as which account*, but not trace it back to a specific originating host behind the gateway — worth a line in the case file.

**Mission 3 CTFd flag — First foothold (100 pts):** `HAM{anon_smb_seat50}` — found by widening the scan from just WKS-L58 to the whole `10.50.0.0/24` subnet and comparing anonymous SMB access across every host sharing its signature; `10.50.0.50` was the one host where `Public` was actually readable.

---

## Step 3 — Group Policy Preferences credential

**Question/task:** If the SMB share held a Group Policy Preferences XML file with a `cpassword` attribute, recover the plaintext.

**Hint(s):** GPP's "encryption" uses a key Microsoft published back in 2014 (MS14-025) — this isn't something to brute-force, there are standard tools that do it in one command.

**Instructions:**
1. Found a low-privilege domain account (`training01`) in `account-access.txt` on `10.50.0.50`'s anonymously-readable `Public` share (see Step 2 update above) — not a GPP XML directly, but a credential meant to unlock the next step.
2. Tried using `training01` from my attack machine to reach the domain share it's scoped to: tested against WKS-L58 and `.50` directly, guessed `SYSVOL`/`NETLOGON` share names, and tried resolving/querying DNS for `hamilton.corp` against every host I'd found with SMB open. All denied, `BAD_NETWORK_NAME`, or DNS timeout — no domain controller reachable yet.
3. **Finding the DC itself turned out to be the real blocker, not the credential.** `tailscale status --json` confirmed only one subnet router exists in the tailnet (`pve-ryzen`, advertising exactly `10.50.0.0/24` — no second hidden range to accept), so the DC had to be inside the subnet I'd already scanned. A full AD-port sweep (`53,88,389,445,636,3268,3269`) across every host in `10.50.0.0/24` came back filtered everywhere, which is consistent with a DC whose LDAP/Kerberos ports are firewalled off from this network path while SMB stays open — so "filtered" didn't rule a DC out.
4. Fingerprinted the whole `10.50.0.50`–`.68` block with `nmap --script rdp-ntlm-info` (leaks `NetBIOS_Computer_Name`/`DNS_Domain_Name` pre-auth, no credentials needed): every single host reported `WKS-L50` through `WKS-L68` — confirmed as pure workstations, no DC hiding in that block.
5. That redirected attention to `10.50.0.10`, the one host from the original sweep with only 445 open (no 3389) — already an outlier. Anonymous `rpcclient` against it returned `NT_STATUS_ACCOUNT_DISABLED` (not just "access denied" — the Guest account exists and is explicitly disabled, typical DC hardening) and anonymous `smbclient` logged in but listed zero shares (`RestrictAnonymous`-style lockdown). Authenticating as `training01` instead: `rpcclient ... -c srvinfo` returned `Wk Sv PDC Tim NT` with the domain-controller bit set in the server-type flags, and `smbclient -L` showed `NETLOGON` and `SYSVOL` ("Logon server share") — **`10.50.0.10` is the domain controller for `hamilton.corp`.**
6. Pulled the whole SYSVOL tree as `training01` (`smbclient //10.50.0.10/sysvol -U training01%... -c 'recurse ON; prompt OFF; mget *'`) and grepped the download for `cpassword`. Found **17** separate GPOs, each with a `Groups.xml` under `Machine/Preferences/Groups/` pushing a local account named `svc_deploy` via the "Local Users and Groups" GPP extension — one GPO per workstation seat (matching the `.50`-`.68` host block from Step 2, minus the `.60`/`.65` gaps: 19 addresses minus 2 gaps = 17), each tagged with its own proof comment. (Earlier draft of these notes said "15" - a direct recount confirmed 17; corrected here.) My seat (58, matching WKS-L58) is GPO `{387BE251-1F01-4152-A102-E17C87875F30}`. Also checked the two other, non-svc_deploy GPO folders in `Policies/`: `{31B2F340-...}` and `{6AC1786C-...}` are Windows' own built-in Default Domain Policy / Default Domain Controllers Policy (standard, not planted), and a third, `{73815AA3-...}`, turned out - per its own `GPO.cmt` - to be a leftover from Mission 2 ("Temps 2 execution auditing, bench L50 only"), a dead end for this mission. `DfsrPrivate` and the NETLOGON-equivalent `scripts` folder were both confirmed genuinely empty.
7. Decrypted the `cpassword` for seat 58 (MS14-025): base64 is the URL-safe variant (`-`/`_`), decoded, then AES-256-CBC with a zero IV and the AES key Microsoft published in KB2962486. **Got the key wrong twice before getting it right** — first guess was a mistyped/truncated 16-byte string (odd hex length, `fromhex()` error), second guess was a 16-byte key that decoded but failed PKCS7 unpadding (`ValueError: Padding is incorrect` — a strong signal the key itself was wrong, since garbage decryption almost never produces valid padding by chance). The actual key is 32 bytes (AES-256, not AES-128) — sourced from the real `gpp-decrypt` tool's own code (`t0thkr1s/gpp-decrypt`, `gpp-decrypt.py`) rather than trusting a hand-typed value a third time:
   ```python
   key = (
       b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
       b"\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
   )
   ```
   With the correct key, decryption succeeded cleanly on the first try — recovered the plaintext password for `svc_deploy` (`[REDACTED — recovered, to be rotated]`).

**Answer:** The domain controller is `10.50.0.10` — reachable the whole time, but its AD-specific ports are firewalled from this network path, so it never showed up as a DC by port scan alone; it had to be found by behavioral fingerprinting (disabled Guest account, zero anonymous share enumeration, `training01`'s `srvinfo` showing the `PDC` role flag). SYSVOL held 17 near-identical GPOs, one per workstation seat, each with its own `cpassword` for a local account named `svc_deploy`. Decrypted the one for seat 58 using the correct MS14-025 AES-256 key.

**Mission 3 CTFd flag — The climax (200 pts):** `HAM{gpp_cpassword_seat58}` — found as a plaintext comment directly in my seat's `Groups.xml`, no decryption needed for the flag itself; the decryption was still needed to get the actual credential for Step 4. (Confirmed against the correct CTFd card after an initial mix-up — I'd first assumed this was a separate, earlier "find the key" challenge, but it's "The climax" specifically: the challenge's own wording, "a domain keeps its own secrets somewhere every machine can read... not as protected as they look," is literally describing SYSVOL's by-design, domain-wide readability plus GPP's publicly-known AES key.)

**Addendum — manually verifying the decryption mechanism, and ruling out a shared fleet-wide password:** went back and ran the actual AES-256-CBC decryption myself end-to-end (URL-safe base64 decode, zero IV, the Microsoft-published key, PKCS7 unpadding) against seat 58's `cpassword`, rather than relying only on the plaintext comment — it decrypted cleanly to a working local-admin password (`[REDACTED — recovered, to be rotated]`), the same one already in use since Step 4. Also decrypted a second, unrelated seat's `cpassword` (seat 55) the same way, specifically to check whether the "same account, same password fleet-wide" assumption in an earlier draft of these notes was correct — **it wasn't.** Seat 55 decrypted to a completely different password. Each seat's GPO independently generates its own `svc_deploy` password; only the account *name* is shared fleet-wide, not the credential itself. This matters for the control-gap write-up: recovering one seat's cpassword gives local admin on that one machine, not silently on every seat — though the underlying weak-encryption exposure (and the ease of repeating the same decrypt against any other seat's GPO) is just as real either way.

**Sentinel side:** none — this decryption happens entirely on my attack machine against a file I already pulled. Nothing to query here.

---

## Step 4 — Getting back in

**Question/task:** Use the recovered credential to reconnect to WKS-L58 over RDP.

**Hint(s):** If the connection negotiates but the credential "doesn't take," it's usually not the password — it's how the RDP client is negotiating its security layer. Check the client's security-layer/NLA setting before assuming the credential is wrong.

**Instructions:**
1. Tried `training01` first (the only credential recovered at the time Step 4 was first attempted). Rejected with a specific, informative error — `this user is not allowed for remote connection` — not a generic bad-password message. That's consistent with the Step 3 finding that `training01` is a domain account scoped only to SYSVOL read access, never granted "Allow log on through Remote Desktop Services"/Remote Desktop Users membership.
2. With `svc_deploy`'s password decrypted (Step 3), tried RDP as `HAMILTON\svc_deploy` — rejected as wrong username/password even after confirming the pasted value was correct (verified via the password-reveal eye icon in the Windows logon screen, after first ruling out a hand-typing transcription error). The connection did show a CTFd flag banner ("Access restored") during the negotiation — **this turned out to be a login banner shown during connection handshake, not proof of actual access; the coach confirmed this explicitly so it doesn't get mistaken for a completed step.**
3. **Root cause: `svc_deploy` is a local account, not a domain account.** The GPP `Groups.xml` from Step 3 uses the "Local Users and Groups" extension (`clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"`), which provisions accounts in each machine's own local SAM database — not Active Directory. Despite looking like a normal account, `HAMILTON\svc_deploy` is the wrong address entirely; it needs to be addressed as a local account, either `.\svc_deploy` or `WKS-L58\svc_deploy`, so the workstation checks its own local SAM instead of asking the DC.
4. Confirmed: RDP as `.\svc_deploy` with the decrypted password landed on the actual WKS-L58 desktop (not just the "Access restored" banner this time) — the local-account address fix was the whole fix, no password rotation on Microsoft's side needed.
5. KQL, once back in Sentinel: queried `SecurityEvent` for `EventID == 4625` on WKS-L58 — **22 failed-logon events**, every single one for `Account = HAMILTON\svc_deploy` (the domain-qualified form), spanning two sessions (27/10 16:43–17:03 UTC, the first troubleshooting pass, then a few more on 28/10 at 09:31 and 10:10). Every one carries `SubStatus = 0xC0000064`, which is Windows' `STATUS_NO_SUCH_USER` — not a bad-password code, a "this account doesn't exist here" code. That's Sentinel independently proving the local-vs-domain finding: WKS-L58's local SAM genuinely has no domain-qualified `svc_deploy` to find. A mix of `LogonType 3` (IP `-`, likely SMB-side probes alongside the RDP attempts) and `LogonType 10` (IP `10.50.0.1`, the gateway-masked RDP attempts) both failed identically, ruling out anything RDP-protocol-specific.
   Then queried `EventID == 4624`, `LogonType == 10`, `Account has "svc_deploy"` — **4 successful events**, all `Account = WKS-L58\svc_deploy` (the local form, as expected), `IpAddress = 10.50.0.1` (same gateway masking as Step 2), `AuthenticationPackageName = Negotiate`, at 09:32:35 and 10:11:21 UTC on 28/10 (each timestamp logged twice — Windows commonly logs a pair of 4624s for one RDP connection).

**Answer:** The blocker wasn't the credential or the client's security-layer negotiation (the hint's suggested cause) — it was addressing `svc_deploy` as a domain account (`HAMILTON\svc_deploy`) when the GPP "Local Users and Groups" extension actually provisions it as a **local** account on each workstation. Confirmed by both sides: 22 straight `HAMILTON\svc_deploy` failures with `STATUS_NO_SUCH_USER`, then a clean success the moment the address changed to `WKS-L58\svc_deploy`. Logged in successfully and reached the real desktop.

**Mission 3 CTFd flag — Privileged return (150 pts):** `HAM{admin_rdp_seat58}` — this is the flag that appeared in the "Access restored" login banner back during the very first `HAMILTON\svc_deploy` attempt, which I'd originally dismissed (correctly, per the coach) as "just a banner, not proof of actual desktop access." That's still true for what it proves about *desktop* access — but it turns out to be exactly the right flag for *this* challenge, because "Privileged return" is checking something narrower than full interactive logon: that I obtained and successfully presented the correct privileged credential over RDP. The banner (and its embedded flag) is generated once Windows' NLA/CredSSP layer accepts the submitted username+password pair — a check that happens before the OS decides whether that *specific account form* is actually allowed to complete an interactive session. That's why it showed up even on the `HAMILTON\svc_deploy` attempt that ultimately failed: the *password* was already correct at that point (decrypted correctly in Step 3), it was only the account *qualifier* that was wrong. So the banner/flag answers "do you have working privileged creds," not "are you sitting at the desktop" — the latter is a separate, stronger confirmation, which is exactly what Step 5's `proof_of_access.txt` provides.

**Why this matters beyond this one login:** the same local account *name* (`svc_deploy`) is pushed, via its own near-identical GPO, to every workstation seat in the fleet — 17 in total — each with its own independently-generated password (confirmed by decrypting a second seat's cpassword and getting a different result; see the addendum in Step 3). So the exposure isn't one shared password working everywhere; it's that the same trivially-breakable mechanism (MS14-025) is used fleet-wide, meaning recovering local admin on *any* seat whose GPO you can read is exactly this easy, repeatably, seat by seat.

**Further SMB reconnaissance with the `svc_deploy` credential:** once I had the decrypted password, I checked what else it could reach beyond the interactive desktop session. Listing shares anonymously showed WKS-L58 also exposes its own `Public` SMB share (distinct from `10.50.0.50`'s), containing another `account-access.txt` — a second, rotated `training01` credential plus its own proof string, readable with **no credentials at all** (confirmed by repeating the read anonymously). This is the same control gap as Step 2, just present on every seat's own workstation, not only the sibling host used for the original foothold. Tried the admin shares (`ADMIN$`/`C$`) on WKS-L58 itself as `svc_deploy` too — both `ACCESS_DENIED`, despite the GPP entry marking this account `subAuthority="RID_ADMIN"` (a genuine local-Administrators-equivalent account). This isn't a wrong password: Windows' "Remote UAC" (`LocalAccountTokenFilterPolicy`, on by default) strips admin rights over the network for any local account that isn't the literal built-in RID-500 Administrator, so a GPP-provisioned admin account gets a filtered, non-admin token for *network* logons (SMB, type 3) while keeping full admin rights for *interactive* logons (RDP, type 10) — exactly why the admin shares are blocked while the full-desktop RDP session isn't. Also checked the domain controller directly as `training01`: its live `NETLOGON` share is genuinely empty (matches the local SYSVOL download, nothing missed), `C$`/`ADMIN$` are `ACCESS_DENIED` as expected for a low-privilege account, and LDAP (389) is unreachable — consistent with Step 3's finding that the DC's AD-specific ports are firewalled off this network path, with only SMB/445 usable.

**PowerShell (attack machine) vs KQL (Sentinel) — what it signifies:**

| | Attack-machine side | KQL (Sentinel) |
|---|---|---|
| What it shows | The client-side negotiation failure / success | 22× `4625` for `HAMILTON\svc_deploy` (`STATUS_NO_SUCH_USER`), then 4× `4624` type 10 for `WKS-L58\svc_deploy` |
| Agree? | Yes, exactly — the account-name distinction (`HAMILTON\` vs `WKS-L58\`) that explained the client-side failures is visible directly in Sentinel's `Account` field, and the specific `STATUS_NO_SUCH_USER` substatus confirms *why* it failed, not just that it did | |

This is one of the three things the brief says *will* show up in Sentinel — the reconnection itself, same as every RDP logon in Mission 2. Unlike Mission 2 though, the failure reason here isn't a bad password — it's a bad *account address* — and Sentinel's substatus code makes that distinction visible without needing the attack-machine side at all, which is a good example of a SIEM surfacing a root cause the client-side error message alone didn't make obvious ("the user name or password is incorrect" reads like a credential problem, not an addressing problem).

---

## Step 5 — Taking the proof, and seeing what they were after

**Question/task:** Retrieve the three artifacts from the regained desktop: the CTF proof flag, the new Sentinel credential, and the staged/exfiltration data cache.

**Hint(s):** None beyond: look at what's actually sitting on the desktop/profile once you're back in.

**Instructions:**
1. Found `proof_of_access.txt` on the desktop, containing the flag directly in plaintext.
2. Found `monitoring-access.txt` on the desktop: a new Sentinel/Azure login (`[REDACTED — recovered]`) with the message "Monitoring access restored... Sign back in to your Azure / Sentinel portal with this." Used it to sign back into the Azure portal and the `log-sentinel-lab` workspace — this is the access used for the rest of this mission's KQL queries.
3. Found `employees.csv` on the desktop (opened as `employees - Notepad`): a staged data cache, clearly the thing the intruder had gathered up. Every data row is prefixed with a marker column `EXFIL-TEST-MARKER-M3`, followed by `employee_id,full_name,email,department,salary`. Four employee records: names, email addresses, department, and salary figures for Finance, HR, IT, and Sales. Small in volume (4 rows) but genuinely sensitive-category data (PII including compensation) — exactly the kind of thing that matters for the breach-notification assessment below.
4. KQL: didn't pull additional workstation-side process/file activity for this step specifically — the RDP session bounds already captured in Step 4's `4624` query cover the access window. Auditing for individual file-open events on the desktop wasn't configured/available in this workspace, consistent with the mission brief's framing that most of this incident sits outside what the SIEM can see.

**Answer:** All three desktop artifacts recovered. **Mission 3 CTFd flag — desktop proof:** `HAM{desktop_proof_seat58}` — found as a plaintext text file (`proof_of_access.txt`) directly on the WKS-L58 desktop once logged in as `.\svc_deploy`, confirming actual desktop access. This is a separate, stricter flag from Step 4's "Privileged return" (`HAM{admin_rdp_seat58}`, the credential-acceptance banner) — the two check different things: having the right credential vs. actually being at the desktop with it.

**Rotation:** decided not to rotate the recovered Sentinel credential for this lab environment — it's a training workspace, not a production tenant, and the mission's own hint framed rotation as something to *note as a recommended control* rather than something that had to happen before using the credential to finish the mission. The case file's control-gaps section still calls out credential rotation as the correct practice for a real incident.

---

## PowerShell vs SIEM — overall comparison for this mission

Unlike Mission 2, most of Mission 3 happened *off* the monitored workstation — the recon, the SMB enumeration, the GPP decryption all ran on my own attack machine, which isn't in Sentinel's collection scope at all. So the comparison this time isn't "did both sides agree," it's "which parts could the SIEM ever have seen, and which parts needed me there in person." Sentinel is scoped to WKS-L58, so anything that happened on *my* machine against *their* machine over the network (the scan, the SMB listing, the decrypt) was invisible to it by design — three full steps (1, 2's recon phase, and all of 3) left no trace there at all. Only the pieces that actually touched WKS-L58 itself were visible: the anonymous SMB logons (Step 2), the 22 failed domain-account RDP attempts and the successful local-account reconnection (Step 4). And where both sides *did* overlap, Sentinel didn't just corroborate the attack-machine side — in Step 4 it went further, surfacing the actual root cause (`STATUS_NO_SUCH_USER`) more precisely than the generic client-side "user name or password is incorrect" error ever did. That's the real takeaway for the case file: a SIEM scoped to the endpoint can't see the attacker's approach, but it can see — and sometimes explain better than the client does — the moment the attacker (or I) actually touched the machine.
