# Notes: Mission 01 (CTF on hamilton.corp)

My notes from the BeCode Hamilton CTF. I explored my own seat first, then looked into the files that appeared on my Desktop, then into what the coach changed on my seat at step 6 (the intrusion). Every challenge is written the same way: question, "before you leave" (when the category has one), hint 1, hint 2, then what I actually did.

My seat in one table:

| | |
|---|---|
| Domain | hamilton.corp (NetBIOS: HAMILTON) |
| Workstation | WKS-L58 (WKS-L58.hamilton.corp) |
| Domain controller / logon server | DC01 (10.50.0.10) |
| Workstation OU | OU=L58,OU=Learners,DC=hamilton,DC=corp |
| User account OU | Accounts |
| GPO applied | Default Domain Policy |
| Domain group in local Administrators | HAMILTON\Domain Admins |

---

## Part 1: Know your seat

> Every investigation starts by knowing the ground you stand on. Explore your own seat in `hamilton.corp`: your workstation, your account, the server that vouches for you, and the rules that reach you. Everything can be found from your own workstation, connected with your own account.

### 1. My workstation's full name

**Question:** In a domain, a computer has a short name and a full name that includes the domain. What is the full name of your workstation?

**Hint 1:** The full name is the short name of the computer, followed by a dot and the name of the domain.

**Hint 2:** Windows shows this in the system information of the computer, under the device name and the domain it belongs to.

**Instructions:**
1. Press the Windows key.
2. Go to Settings → System → About.
3. Read the device name and the domain.

**Answer:** `WKS-L58.hamilton.corp` → `HAM{WKS-L58.hamilton.corp}`

### 2. Who vouched for me?

**Question:** You connected to your workstation with a domain account, so your workstation did not check your password itself. Which server did? Give its short name.

**Hint 1:** Re-read idea 2 of the sheet. The server you are looking for has a role with a name.

**Hint 2:** Windows remembers, for your current session, which server handled your logon. It keeps it as an environment variable.

When you log on with a domain account, your workstation does not know your password. It asks a domain controller, a server that holds the directory and vouches for domain identities. If the domain controller says yes, the workstation opens the session.

**Instructions:**
1. Open Command Prompt.
2. Run `echo %LOGONSERVER%`. It returns `\\DC01`.
3. (Check) `nltest /dsgetdc:` also shows the DC as `DC01.hamilton.corp`.

**Answer:** `DC01` → `HAM{DC01}`

### 3. Where does it live?

**Question:** What is the IP address of the server from challenge 2?

**Hint 1:** A name can be turned into an address by asking the DNS. Your workstation already knows which DNS server to ask.

**Instructions:**
1. Open Command Prompt.
2. Run `nslookup DC01` (the server name from challenge 2).

**Answer:** `10.50.0.10` → `HAM{10.50.0.10}`

### 4. My workstation's place in the tree

**Question:** Your workstation exists in Active Directory as a computer object, stored in an OU (Organizational Unit). Give the full path of that OU, written as a distinguished name, the way Active Directory writes it.

**Hint 1:** A distinguished name reads from the most specific part to the most general one, separated by commas. In the made-up domain of the sheet, the OU of LAPTOP-07 would be written `OU=Laptops,DC=example,DC=corp`.

**Hint 2:** Windows can produce a report of the group policy it applied. That report names the computer object and where it sits in the tree. The computer part of the report needs an elevated prompt.

**Instructions:**
1. Open Command Prompt as administrator.
2. Run `gpresult /h C:\report.html`.
3. Open `C:\report.html` in a browser.
4. The computer part shows the OU as `hamilton.corp/Learners/L58`.
5. Rewrite it from most specific to most general.

**Answer:** `HAM{OU=L58,OU=Learners,DC=hamilton,DC=corp}`

### 5. My account's place in the tree

**Question:** Your user account is an object in Active Directory too. In which OU is it stored? Give only the name of that OU.

**Hint 1:** The same group policy report also has a user part. Compare where your account lives with where your workstation lives: are they in the same place?

**Instructions:**
1. Open `C:\report.html` in the browser.
2. Go to the General section of the user part.
3. The workstation is in `hamilton.corp/Learners/L58`, but my user account is in a different OU: `Accounts`.

**Answer:** `HAM{Accounts}`

### 6. The rules that reach me

**Question:** GPOs reach a computer through the OUs above it. Which GPO is applied to your workstation? Give its exact name.

**Hint 1:** The report from challenge 4 lists the GPOs that were applied to the computer, and those that were filtered out.

**Hint 2:** A GPO linked at the very top of the tree reaches every computer below it, including yours.

**Instructions:**
1. Open `C:\report.html` in the browser.
2. Look at the Group Policy Objects section (Applied GPOs).

**Answer:** `HAM{Default Domain Policy}`

### 7. Local power, domain identity

**Question:** Your domain account is allowed to administer your workstation, because it is a member of the workstation's **local** Administrators group. That local group also contains a **domain** group. Which one?

**Before you leave this category:** In a few lines, in your own notes: which of these answers came from your workstation, and which came from the domain?

**Hint 1:** Local groups live on the machine itself. Look at the members of the local Administrators group, and notice how each member is written.

**Hint 2:** A member written with the domain name in front is a domain identity. Your own account is one of them; there is another.

**Instructions:**
1. Press Windows key + R.
2. Type `lusrmgr.msc`.
3. Click Groups.
4. Click Administrators. The members include `HAMILTON\Domain Admins`.

**Answer:** `HAM{Domain Admins}`

**Before you leave: workstation or domain?**

- **From the workstation** (local configuration and identities): the hostname (WKS-L58), its local group memberships (the local Administrators group) and local group policy.
- **From the domain** (network-wide resources and identities managed centrally by AD): my domain username, the logon server (DC01), my user account's OU (Accounts), my computer object's OU path (OU=L58,OU=Learners) and the enterprise-wide Group Policy (Default Domain Policy).

---

## Part 2: What just happened?

> Two files appeared on your Desktop: the sheet *Identity in hamilton.corp* and your CTFd credentials. You did not create them. Before trusting anything that shows up on a machine, an analyst asks who put it there and how.

### 8. Whose file is it?

**Question:** Every file on Windows has an owner. Who owns the sheet *Identity in hamilton.corp* on your Desktop? Write it the way Windows writes it, with the part before the backslash.

**Hint 1:** The owner is part of the security settings of a file, in its properties.

**Hint 2:** Re-read idea 1 of the sheet. The owner is not you, and it is not a person.

**Instructions:**
1. On the Desktop, right-click *Identity in hamilton.corp* (not `CTFD_CREDENTIALS.txt`, which is a different file) and choose Properties.
2. Go to the Security tab and click Advanced.
3. Read the Owner line at the top.
4. Or in PowerShell: `Get-Acl "$env:USERPROFILE\Desktop\Identity in hamilton.corp" | Select-Object -ExpandProperty Owner`
5. Keep only the part before the backslash.

**Answer:** The Properties window shows the owner as `Administrators (WKS-L58\Administrators)`, the local Administrators group, not me and not a person. But `HAM{WKS-L58}` was rejected: the Properties window puts the computer name in front, while Windows itself writes this group as `BUILTIN\Administrators` (that's what `Get-Acl` returns). So the part before the backslash is `BUILTIN` → `HAM{BUILTIN}`

### 9. Which program wrote it?

**Question:** Nobody opened a session on your workstation to drop these files, yet they were written. Windows recorded which program did it. What is the name of that program?

**Hint 1:** Look at what was logged on your workstation around the time the file was created. You know that time: it is in the file's properties.

**Hint 2:** Your workstation is a virtual machine. Whoever manages the virtual machines installed a small program inside it to talk to the machine from the outside.

**Instructions:**
1. Press Windows key + R.
2. Run `services.msc`.
3. Notice the VirtIO-FS Service. It means the VM runs on a KVM/QEMU hypervisor, not VMware, so the program is not `vmtoolsd.exe`.
4. The hypervisor talks to the guest OS through the QEMU Guest Agent service (`qemu-ga`).

**Answer:** `HAM{qemu-ga}`

### 10. Where was it written down?

**Question:** In which Windows log did you find the trace of that program?

**Before you leave this category:** Look for the same trace in your SIEM. What do you find, and why? Write a few lines in your notes: what changed, where you found it, and where you could not.

**Hint 1:** It is not the Security log.

**Instructions:**
1. Open PowerShell.
2. Run `Get-WinEvent -ListProvider *qemu* | Select-Object Name, LogLinks`.
3. The `qemu-ga` provider writes to the Application log. (`HAM{System}` was wrong, and there was no Event ID 7036 for it.)

**Answer:** `HAM{Application}`

**Before you leave: what I found**

- **What changed / happened:** The QEMU Guest Agent (`qemu-ga`) carried out actions on the VM directly from the hypervisor, writing the files to my Desktop without a user session and without triggering normal process creation auditing.
- **Where it was found:** Locally on the endpoint, in the Application Windows event log, under the `qemu-ga` provider.
- **Where it was not found:** Not in the Security log, because process creation auditing (Event ID 4688) was not enabled and Sysmon is not installed. My `SecurityEvent` 4688 queries in Sentinel, `search "vmtoolsd.exe"` and `Event | where EventID == 4688` all came back empty. It was also not in the SIEM (Azure Log Analytics workspace), because the Data Collection Rules only collected specific logs and events (like Security), not the local Application channel.
- **How to get it into the SIEM:** Add the Application log to `dcr-windowsevents`, then query:

```kql
Event
| where Source == "qemu-ga" or RenderedDescription has "qemu-ga"
| sort by TimeGenerated desc
| take 10
```

---

## Part 3: Something changed (step 6, the intrusion)

> The coach has just made changes to your seat. Nothing was dropped on your Desktop this time. Your job: find out what changed, prove it, and say where the evidence lives. You know your seat now: start from what you noted about it.

### 11. A new identity

**Question:** A new account exists on your workstation. What is its name?

**Hint 1:** Re-read idea 1 of the sheet. Is this account local or a domain account? That tells you where to look.

**Hint 2:** Compare the list of accounts with what you noted in Know your seat. Look at when each account was created.

**Instructions:**
1. Open PowerShell as administrator.
2. Run `Get-LocalUser`. (`helpdesk` and `labuser` are from earlier lab setups.)
3. Press Windows key + R and type `compmgmt.msc`.
4. Go to System Tools → Local Users and Groups → Users.
5. Press Windows key + R and type `eventvwr.msc`.
6. Go to Windows Logs → Security.
7. Click Filter Current Log on the right and filter on `4720` (A user account was created).
8. Click the event and scroll to the New Account section to see the name (Account Domain: WKS-L58, so it is a local account).

**Answer:** `HAM{svc_backup}`

### 12. What it can do

**Question:** That account is a member of a local group that gives full control of the machine. Which group?

**Hint 1:** You already looked at the members of this group in Know your seat. Look again.

**Instructions:**
1. Open PowerShell as administrator.
2. Run `Get-LocalGroupMember -Group "Administrators"`. `svc_backup` is now in the list.

**Answer:** `HAM{Administrators}`

### 13. The SIEM saw the creation

**Question:** Find, in your SIEM, the event that recorded the creation of that account. What is its Event ID?

**Hint 1:** Search the security events of your workstation around the time the account was created, and look for the activity of account management.

**Instructions:**
1. In Microsoft Sentinel, open Logs and set the time range wide enough (for example the last 30 days).
2. Search by account name instead of by Event ID, since the Event ID is what I'm looking for:

```kql
SecurityEvent
| where TargetUserName == "svc_backup" or MemberName contains "svc_backup" or Account contains "svc_backup"
| project TimeGenerated, EventID, Activity, TargetUserName, MemberName, Computer
```

3. Read the EventID of the "A user account was created" row.

**Answer:** `HAM{4720}`

### 14. The SIEM saw the promotion

**Question:** Find, in your SIEM, the event that recorded the account being added to that group. What is its Event ID?

**Hint 1:** It happened a few seconds after the creation, on the same machine.

**Instructions:**
1. Use the same query as in challenge 13.
2. Look for the row a few seconds after the creation: "A member was added to a security-enabled local group" (the Administrators group).

**Answer:** `HAM{4732}`

### 15. Bonus: you changed too

**Question:** Your own domain account was changed. It is now a member of a new domain group. What is the name of that group?

**Hint 1:** Re-read idea 2. A change to a domain account is made in the directory, not on your workstation. Ask the domain about your account.

**Hint 2:** The groups of your current session were fixed when you logged on. Sign out and sign in again, then compare.

**Instructions:**
1. Sign out and sign back in so the session token gets the new group memberships.
2. Open Command Prompt.
3. Run `net user %USERNAME% /domain`. (`Get-ADPrincipalGroupMembership` doesn't work because the AD PowerShell module (RSAT) is not installed. `whoami /groups` also works after signing in again.)
4. Under Global Group memberships: `Domain Users` and the new group, `L58-Project-Readers`.

**Answer:** `HAM{L58-Project-Readers}`

### 16. Bonus: who wrote it down?

**Question:** Which machine recorded the change to your domain account in its security log? Give its short name.

**Before you leave this category:** In your notes: list the three changes you investigated (the files on your Desktop, the new account, your new group). For each one, write where the evidence lives and whether your SIEM could see it. What does that tell you about what your SIEM covers?

**Hint 1:** Who manages domain accounts? Not your workstation.

**Instructions:**
1. Open Command Prompt.
2. Run `nltest /dsgetdc:` (or `echo %LOGONSERVER%`). The domain controller is `DC01.hamilton.corp`.
3. Domain account and group changes are made and logged on the domain controller, not on the workstation.

**Answer:** `HAM{DC01}`

**Before you leave: the three changes**

| Change | Where the evidence lives | Could my SIEM see it? |
|---|---|---|
| Files on my Desktop (written by `qemu-ga`) | WKS-L58, Application log (`qemu-ga` provider) | No. The DCR didn't collect the Application log at that time, and there was no process creation auditing (4688) or Sysmon. |
| New local account `svc_backup` added to Administrators | WKS-L58, Security log (4720 creation, 4732 group add) | Yes. `SecurityEvent` comes in through `dcr-securityevents`. |
| My domain account added to `L58-Project-Readers` | DC01, Security log | No. Only my workstation is connected to my workspace, not the domain controller. |

**What this tells me:** My SIEM only sees what my Data Collection Rules collect, from the machines that are connected. Right now that is WKS-L58 and the log channels I chose. Anything logged in a channel I don't collect (Application at the time) or on another machine (the DC) stays invisible to it, even if it changes my own account.
