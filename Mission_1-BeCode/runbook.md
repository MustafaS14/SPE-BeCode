# Runbook: Mission 01

These are my notes from connecting my lab workstation to my own Sentinel workspace. I wrote them so someone else could rebuild the same setup from scratch, mistakes included. Times are in UTC and come from my workspace and the resource group's Activity log.

## What I ended up with

| | |
|---|---|
| Region (used for everything) | francecentral |
| Resource group | rg-sentinel-lab |
| Log Analytics workspace | log-sentinel-lab (Sentinel enabled on it) |
| Daily cap | 0.2 GB/day |
| Workstation in Arc | WKS-L58 (WKS-L58.hamilton.corp) |
| DCR from Azure Monitor (chain A) | dcr-windowsevents: Application + System only now |
| DCR from the Sentinel connector (chain B) | dcr-securityevents: Security log, "Common" set |

I named everything type-first (rg-, log-, dcr-) so I can tell what something is from its name alone.

---

## How I built it, in order

### 1. Getting onto the workstation

The workstation isn't on the internet, so I first connected to the lab network with Tailscale on my laptop and waited for the coach to approve my device. Before trying RDP I pinged the workstation address from my access sheet. If the ping doesn't answer, RDP won't work either, and the error RDP gives you is less clear.

Once the ping worked I connected with Remote Desktop Connection (mstsc) and changed the password at first login.

### 2. Setting up the Azure side

I activated Azure for Students with my BeCode school account. Signing in with a personal Microsoft account here leads to an empty subscription. I checked the Education page showed the 100 USD credit before going further.

Next I had to pick a region. Our student subscriptions only allow a few regions, and the list isn't the same for everyone. I found mine under Policy → Assignments → "Allowed resource deployment regions" and picked francecentral. It was on my list and it's in the EU, so my logs stay in Europe. After that I used that one region for every resource.

Then I created, in this order:
1. the resource group,
2. the Log Analytics workspace (Pay-as-you-go pricing),
3. Microsoft Sentinel on top of the workspace. This starts a 31-day free trial.

Last, I set a daily cap of 0.2 GB on the workspace (Usage and estimated costs → Daily cap). Our credit is limited, and one noisy log source could use a lot of it overnight. The cap is a safety net, not a way to save money every day: once it's hit, collection stops until the next day, so it has to sit well above normal volume.

**The cap is also a blind spot** (added after coach feedback). An attacker can use the same behaviour against me. They flood the workstation with cheap noise until the cap is hit, for example a loop of failed logons (4625, which the "Common" set collects). After that, nothing more reaches the workspace until the daily reset, and they can act without being seen. With a cap of only 0.2 GB that doesn't take much: very roughly a couple of hundred thousand security events. The same flood can also roll over the workstation's own Security log (20 MB by default, overwrite when full), which wipes the local evidence too.

What I'd do about it:
- **Alert when the cap is hit.** Log Analytics writes an `OverQuota` record to `_LogOperation` when collection stops. A log alert on it tells me the SIEM went blind, and when (query in `queries.kql`).
- **Alert before it's hit.** Compare today's billable volume in the `Usage` table against the cap (for example at 80%), and against the normal hourly volume. A sudden jump is suspicious in itself.
- **Treat the flood as the incident.** A spike of 4625s, a cleared log (1102) or an audit policy change (4719) is a signal, not just noise to filter out.
- **In a real SOC**, security tables usually aren't hard-capped. Cost is controlled with budgets and alerts, commitment tiers, and choosing which events to collect, so an attacker can't switch off collection by making noise. In this lab I keep the cap because the credit is limited, but now I watch it.

### 3. Connecting the workstation with Azure Arc

Azure can't see a machine that lives on our lab network, so the first job is to register it with Azure Arc. I started from Azure Arc → Machines → Onboard existing machines and used these settings: same resource group and region, Windows, SQL Server option unticked, public endpoint, manual authentication. I didn't enable anything paid.

On the workstation I opened PowerShell as administrator. Windows 10 blocks downloaded scripts by default, so before pasting the Arc script I ran this:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

It only affects that one window.

The script installed the agent and opened a browser inside the VM for me to sign in. The agent installed, but Azure refused to create the machine because the sign-in hadn't used MFA, and the browser in the VM never asks for it. The fix is a device-code sign-in, run in the same admin window:

```powershell
& "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --resource-group "$env:RESOURCE_GROUP" --tenant-id "$env:TENANT_ID" --location "$env:LOCATION" --subscription-id "$env:SUBSCRIPTION_ID" --cloud "$env:CLOUD" --tags 'ArcSQLServerExtensionDeployment=Disabled' --use-device-code
```

This prints a link and a code.

**This is where I made a mistake.** I opened the link and entered the code in the browser inside the VM, through my RDP session. That is the same browser without MFA, so it failed the same way, with the same `RequestDisallowedByAzure` error about MFA. In the Activity log each attempt shows up as a pair of "'deny' Policy action." events from the policy "Multi Factor Authentication Enforcement - Write" (assignment `sys.mfa-write`), and the sign-in claims show `pwd` only, no `mfa`: at 12:29 UTC (the first run of the script), then 12:47, 12:48 and 12:52 UTC. The whole point of the device code is to do the sign-in somewhere you already have MFA, which is your own laptop. I ran the command again, entered the new code on my laptop's browser where I was already logged into the portal, and it finished with "Machine connected to Azure". A few minutes later the machine showed as Connected in Arc.

**Note for whoever does this next:** when PowerShell on the workstation gives you a link and a code, type them on your own laptop, not inside the RDP session.

Two other problems I hit at this step. First, the Arc script printed a `(400) Bad Request` from `Invoke-WebRequest`. That is only the script failing to send its error report, not the real problem. Second, once the sign-in finally had MFA (12:53 UTC, claims `pwd,mfa`), "Write Azure Arc machines" still failed, this time with `MissingSubscriptionRegistration` (HTTP 409): "The subscription is not registered to use namespace 'Microsoft.HybridCompute'". Azure registered it by itself (the Hybrid RP Application wrote at 12:55 UTC), and when I ran the connect command again it went through at 13:04 UTC.

### 4. Choosing what to collect (chain A)

Arc makes the machine visible to Azure, but nothing is sent until a data collection rule says what to collect and where to send it. I created dcr-windowsevents from Azure Monitor → Data Collection Rules (not from inside Sentinel):
- resource: only my Arc machine
- Windows Event Logs: Application and System at Critical, Error and Warning, plus the Security log (audit success and failure). I left Information off because it's far too noisy.
- destination: my workspace. Everything from this rule lands in the `Event` table.

Attaching the rule is what installs the Azure Monitor Agent on the machine as an Arc extension. I didn't download any installer myself. It showed as Succeeded under the machine's Extensions after about 10 minutes: the Activity log has "Install or Update an Azure Arc extensions" at 14:21 UTC, 9 minutes after I created the rule at 14:12 UTC.

### 5. Checking that data arrives

In Sentinel → Logs (switched to KQL mode) I ran `Heartbeat | take 10` until my machine showed up. The first heartbeat arrived on 7 October 2026 at 14:16 UTC, about 4 minutes after I created `dcr-windowsevents` (14:12 UTC). I now always check Heartbeat first: if it's there, the connection works and any problem is somewhere else. Checking services on the workstation itself doesn't help, because on an Arc machine the agent doesn't run under the name you'd expect.

To find my own RDP logon, I searched `SecurityEvent` for successful logons (4624) with logon type 10 or 7, the two types an RDP session produces, and took the earliest one (query in `queries.kql`):

| Time | Logon type | Source address |
|---|---|---|
| 7 Oct 2026, 23:16:47 UTC | 7 | 10.50.0.1 |

Logon type 7 means I reconnected to a session that was already open. A brand-new RDP session would show as 10. The address is the lab gateway that relays my connection, not my laptop.

#### Why a 7 and not a 10? (follow-up after coach feedback, confirmed on the workstation)

At first I called this "my first RDP logon". That's wrong. It is only the **earliest RDP logon my SIEM has**. A type 7 means a session already existed, so a type 10 must have happened before it. The SIEM couldn't show me that, so I checked on the workstation itself. The local Security log goes back to 21 September (it never rolled over), and the `TerminalServices-LocalSessionManager/Operational` log records every session logon (21), sign-out (23), disconnect (24) and reconnect (25). The VM's clock is set to Romance Standard Time (UTC+2 in October), so I converted everything to UTC.

| When (7 Oct 2026, UTC) | What | Where the evidence is | In the SIEM? |
|---|---|---|---|
| 09:38:29 | **4624 type 10** (two events, the normal pair for an admin's split token). My first RDP connection, password change at first login | Local Security log | No. Nothing was connected yet |
| 09:38:31 | Session logon (21) | LocalSessionManager log | No |
| 12:29 → 13:04 | Arc onboarding (MFA errors, then connected) | Activity log | No. Arc only, no DCR yet |
| 14:12 / 14:16 | `dcr-windowsevents` created / first heartbeat. Security log starts going to `Event` | Workspace | Only in `Event`, which my first query didn't search. It has no type 10 or 7 for that hour, which is correct: I was connected the whole time, so there was no new logon |
| 15:08 | First rows in `SecurityEvent` | Workspace | Yes |
| 15:15:03 | First disconnect (24) | LocalSessionManager log | No |
| 16:26:39 → 22:31 | Several reconnects and disconnects (25/24). **None of them wrote a 4624 type 7 or 10** | LocalSessionManager log | No |
| 23:16:47 | **4624 type 7** (two pairs), the first reconnect where I had to unlock the session | Local Security log **and** `SecurityEvent` | Yes. Same second in both |

What this shows:
- **The type 10 happened at 09:38:29 UTC, almost three hours before the first Arc attempt.** It exists only in the workstation's own log. The SIEM's history starts when the DCR starts, not when the machine starts: no collection ≠ no activity.
- **I never signed out.** There is no 23 after 7 October, only 24/25 pairs. That's why every later RDP logon is a reconnect, including the 09:27:44 UTC one on 9 October.
- **The SIEM's "earliest" (23:16:47) is correct.** The local log has exactly the same timestamp, so it wasn't a time-range mistake.
- **Not every reconnect is a type 7.** I reconnected at least seven times before 23:16:47, but only that one wrote a type 7. A reconnect into a session that isn't locked doesn't need an unlock logon. It most likely only left a network logon (type 3, from NLA), which my query filtered out. And 4778 (session reconnected) is missing completely: it needs *Audit Other Logon/Logoff Events*, which isn't enabled on this machine. So **4624 type 7/10 alone undercounts RDP activity**. To follow sessions properly I'd enable that audit subcategory (4778/4779) and collect the LocalSessionManager log.

Then I started asking questions with KQL (all in `queries.kql`): when the machine last checked in, whether its data is current (event time vs ingestion time, to catch a wrong clock), what levels of events come in, and who logged on. The logons were in `Event`, but the account and logon type were buried in one long text field.

### 6. Moving the Security log to the Sentinel connector (chain B)

Next I collected the Security log the way Sentinel expects it. In Sentinel I installed the Windows Security Events solution from the Content hub. Then I opened the **Windows Security Events via AMA** connector (not the deprecated legacy one) and created dcr-securityevents for my machine with the **Common** event set. The default is "All", which is too much.

The connector created the rule at 15:02 UTC and attached it to my machine at 15:04 UTC. It needed another 4 minutes before rows showed up in `SecurityEvent`, but there `Account`, `LogonType` and `IpAddress` are separate columns. The first rows I got (7 October 2026, around 15:08 UTC) were WKS-L58 logging on as NT AUTHORITY\SYSTEM with logon type 5. That's Windows starting services, not a person. One RDP connection gives several 4624 events at once (a type 3 for the network authentication, then a 10 or a 7). The IP address is the lab gateway (10.50.0.1), not my laptop.

At that point every security event was being collected twice, once per chain. So I edited dcr-windowsevents and unticked the two Security boxes, at 15:09 UTC. The last Security row to reach `Event` arrived at 15:12 UTC, a few minutes after I saved, while the agent picked up the new rule. Nothing has arrived there since, while `SecurityEvent` kept getting new rows.

---

## Chain A vs chain B

| | Chain A: Azure Monitor DCR → `Event` | Chain B: Sentinel connector → `SecurityEvent` |
|---|---|---|
| Set up from | Azure Monitor, works without Sentinel | Sentinel, needs the Windows Security Events solution |
| Collects | Any Windows log | Only the Security log |
| How you choose events | By log and severity level | Preset sets (All / Common / Minimal / Custom) |
| What the data looks like | One text blob per event, you parse it yourself | Already split into columns |
| Sentinel's built-in rules and workbooks | Mostly don't use it | Built for it |
| Who usually uses it | IT operations | Security teams |
| Cost | Per GB | Per GB, so running both means paying twice for security events |

**Why I kept only chain B for the Security log:**
Running both meant every logon was stored twice in two different tables. That's two places to look for the same thing, results that can drift apart, and double the cost. Chain B gives me the fields I actually search on, and Sentinel's detections and the next missions are built on `SecurityEvent`. Chain A is still useful for what chain B can't collect: the Application and System logs.

---

## If I did it again

- Pick the region from the policy list before creating anything.
- Use an admin PowerShell window and set the execution policy before running the Arc script.
- Do the device-code sign-in on your own laptop, not in the VM.
- Give the agent 15–30 minutes and check Heartbeat before deciding something's broken.
- Before trusting "nothing in the SIEM", check which log the event is written to and whether a DCR collects it. In the CTF, the `qemu-ga` trace was in the Application log, and the change to my domain account was logged on DC01, which isn't connected to my workspace at all.
- Don't call anything "the first" in the SIEM. It's only the earliest thing collected. My "first" RDP logon was a type 7 because the real type 10 (09:38:29 UTC) happened before any DCR existed. It was still in the workstation's local log.
- Set an alert on the daily cap the same day as the cap itself. Otherwise the safety net silently turns into a blind spot.
