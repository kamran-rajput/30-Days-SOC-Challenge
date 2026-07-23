## tags: [soc, log-analysis, challenge-01] challenge: 1 days: 1-5

# 📘 Challenge 01 — Overview

Focus of this block: **log analysis fundamentals** — what a log is, where Windows/Linux logs live, and hands-on detection of common attack patterns (failed logons, PowerShell abuse, port scans, SSH brute force).

**Days in this file:**

- [[#Day 1 Introduction to Log Analysis|Day 1 — Introduction to Log Analysis]]
- [[#Day 2 Windows Security Logs|Day 2 — Windows Security Logs]]
- [[#Day 3 Windows PowerShell Logs|Day 3 — Windows PowerShell Logs]]
- [[#Day 4 Network-Based Attack Detection Using UFW|Day 4 — Network-Based Attack Detection (UFW)]]
- [[#Day 5 Linux Auth Logs — SSH Brute Force Detection|Day 5 — Linux Auth Logs (SSH Brute Force)]]

---

# Day 1: Introduction to Log Analysis

> [!info]+ Objective Understand what a log is, where logs live on Windows/Linux, and how a SOC analyst uses them — then generate and find one yourself via a PowerShell event.

## 🧩 Concepts You Need First

- **Log** — a timestamped record of an event (error, warning, login, command run). Every log carries roughly the same DNA: **timestamp, source, severity, description**.
- **Linux log locations** — `/var/log/syslog` (system-wide), `/var/log/auth.log` (logins/auth), `/var/log/kern.log` (kernel), plus app-specific logs like `apache2/access.log`.
- **Windows log locations** — Event Viewer, split into **System**, **Security**, **Application**, and **PowerShell (Operational)** logs.
- **Why SOC analysts care**: logs are the raw material for detection (spotting bad logins), forensics (reconstructing what an attacker did), monitoring (catching things live), and compliance (proving you _can_ reconstruct events).

## 🛠️ Step-by-Step

### Step 1: Reading a real log line

```
Apr  7 10:42:15 ubuntu sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
```

> [!note] Breaking it down `Apr 7 10:42:15` timestamp · `ubuntu` hostname · `sshd[12345]` service + PID · `Failed password for invalid user admin` the event · `192.168.1.100:54321` attacker's source IP/port · `ssh2` protocol.

### Step 2: Enable PowerShell logging (Windows)

Open `gpedit.msc` → `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell` → enable **Module Logging**, **Script Block Logging**, **Script Execution**.

> [!note] Why By default Windows doesn't log the _content_ of PowerShell commands — just that PowerShell ran. These policies turn on the detailed logging a SOC actually needs.

### Step 3: Generate a suspicious-looking event

```powershell
Get-LocalUser | Select-Object Name, Enabled
```

> [!note] Why this matters Enumerating local users is a common early move for an attacker who's landed on a box post-exploitation — checking what accounts exist before deciding what to target next.

### Step 4: Find the event in Event Viewer

1. `Win + R` → `eventvwr.msc`
2. Navigate: `Applications and Services Logs → Microsoft → Windows → PowerShell → Operational`
3. Filter Current Log → **Event ID 4104** (logs PowerShell script block execution)
4. Locate the entry showing your `Get-LocalUser` command.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`/var/log/syslog`|General system events (Linux)|
|`/var/log/auth.log`|Authentication attempts — logins, sudo, SSH (Linux)|
|`/var/log/kern.log`|Kernel messages (Linux)|
|`/var/log/apache2/access.log`|Web server request logs (Linux)|
|Event Viewer → PowerShell/Operational|PowerShell script block execution logs (Windows)|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`Get-LocalUser \| Select-Object Name, Enabled`|Lists local Windows accounts + enabled status|
|Event ID **4104**|PowerShell script block logging — shows executed command text|
|`eventvwr.msc`|Opens Windows Event Viewer via Run dialog|

## ⚠️ Gotchas / Things That Tripped Me Up

- PowerShell logging is **off by default** — if Event ID 4104 never shows up, check the Group Policy settings in Step 2 first.
- Don't confuse the **Security** log (login/permission events) with the **PowerShell Operational** log (script execution) — they're different logs for different purposes.

## 📌 Key Takeaways (Deep Concepts)

- Every log format looks different, but the four elements — timestamp, source, severity, description — are always there once you know to look for them.
- "Enumerate local users" is a textbook post-exploitation step — recognizing _why_ an action is suspicious matters more than memorizing the exact command.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - A log = timestamp + source + severity + description.
> - Linux logs live in `/var/log/`; Windows logs live in Event Viewer.
> - Enabled PowerShell script logging, ran `Get-LocalUser`, found it under Event ID 4104.
> - SOC analysts use logs for detection, forensics, monitoring, and compliance.

---


# Day 2: Windows Security Logs

> [!info]+ Objective Learn what lives in the Windows **Security** log, recognize the key Event IDs, and prove it hands-on by generating and finding a failed logon.

## 🧩 Concepts You Need First

- **Windows Security Log** — records auth-related events: logons/logoffs, account lockouts, group membership changes, and privilege escalation. This is the log a SOC analyst checks first for unauthorized-access questions.
- **Event ID** — a numeric code identifying the _type_ of security event. Knowing the ID lets you filter thousands of events down to exactly what you're hunting for.

## 🛠️ Step-by-Step

### Step 1: Simulate a failed login

Create a test user `haxuser1`, then trigger a deliberately wrong authentication attempt:

```cmd
net use \\127.0.0.1\IPC$ /user:haxuser1 WrongPassword
```

> [!note] What this does `net use` connects to a shared resource; `\\127.0.0.1\IPC$` is the hidden admin share used for inter-process auth on localhost. Supplying the wrong password forces Windows to log a failed logon — without touching a second machine.

_(Alternative: just sign out and try logging in as `haxuser1` with a wrong password.)_

### Step 2: Find it in Event Viewer

1. `Windows Logs → Security`
2. Filter Current Log → **Event ID 4625** (Failed Logon)
3. Locate your attempt and note: username, logon type, source network address.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Event Viewer → Windows Logs → Security|All authentication/authorization events|

## ⌨️ Command Cheat-Sheet

|Event ID|Meaning|
|---|---|
|**4624**|Successful logon|
|**4625**|Failed logon|
|**4740**|Account lockout (too many bad attempts)|
|**4732**|User added to a security-enabled local group|
|**4672**|Special privileges assigned to a new logon (privilege escalation)|

## ⚠️ Gotchas / Things That Tripped Me Up

- `net use ... IPC$` needs the target reachable and SMB enabled — on a locked-down machine this can fail for network reasons, not auth reasons. The simple sign-out/sign-in method is the reliable fallback.
- Event ID 4625 shows the **logon type** (e.g. interactive vs. network) — this detail matters for telling apart "someone at the keyboard" from "someone hitting a network service."

## 📌 Key Takeaways (Deep Concepts)

- A _single_ 4625 is noise; a _pattern_ of 4625s (many, fast, same source) is a brute-force signal — the value is always in the pattern, not the single event.
- 4672 (privilege escalation) paired with a recent 4624 is a classic "attacker just got admin rights" sequence worth knowing by sight.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Windows Security log = logons, lockouts, group/privilege changes.
> - Forced a failed logon on `haxuser1`, found it under Event ID 4625.
> - Core IDs to memorize: 4624 success, 4625 fail, 4740 lockout, 4732 group change, 4672 privilege escalation.

---


# Day 3: Windows PowerShell Logs

> [!info]+ Objective Go deeper on PowerShell logging beyond Day 1's Event ID 4104 — learn the full set of PowerShell-related Event IDs and understand why they matter for spotting LOLBAS-style abuse.

## 🧩 Concepts You Need First

- **LOLBAS (Living Off The Land Binaries)** — legitimate, pre-installed Windows tools (PowerShell, certutil, mshta, rundll32...) that attackers repurpose for malicious actions specifically _because_ they're trusted and already on the system — no malware binary needed to trigger AV.
- PowerShell logging isn't one event type — different IDs capture different granularity (script block vs. command invocation vs. module use).

## 🛠️ Step-by-Step

### Step 1: Confirm logging is enabled

Same as Day 1 — `gpedit.msc` → `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell` → enable **Module Logging**, **Script Block Logging**, **Script Execution**.

### Step 2: Generate a log entry

```powershell
Start-Process "notepad.exe" -ArgumentList "C:\Windows\System32\drivers\etc\hosts"
```

> [!note] What this does Launches Notepad with the `hosts` file as an argument — a benign stand-in for how attackers use `Start-Process` to launch payloads or open sensitive files programmatically.

### Step 3: Find it in Event Viewer

`Applications and Services Logs → Microsoft → Windows → PowerShell → Operational` → filter for **Event ID 4103** (command invocation with parameter binding — shows the full command + arguments, not just the script block).

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Event Viewer → PowerShell/Operational|PowerShell execution logs (script block + command invocation)|

## ⌨️ Command Cheat-Sheet

|Event ID|Meaning|
|---|---|
|**4104**|Script block logging — captures the actual command text|
|**4103**|Command invocation with parameter binding — detailed execution|
|**4101**|Command execution via command-line arguments|
|**4698**|Module logging for specific module execution|

### LOLBAS tools worth recognizing on sight

|Tool|Abuse technique|
|---|---|
|`powershell.exe`|Execute payloads, download malware, bypass AV|
|`certutil.exe`|Download files: `certutil -urlcache -f`|
|`mshta.exe`|Run malicious HTML apps / remote scripts|
|`regsvr32.exe`|Load/execute remote or local DLLs|
|`rundll32.exe`|Execute DLLs/scripts to evade detection|
|`wmic.exe`|Execute commands, gather system info|
|`bitsadmin.exe`|Silent file download/upload|
|`schtasks.exe`|Create scheduled tasks for persistence|

_(Full reference: [lolbas-project.github.io](https://lolbas-project.github.io))_

## ⚠️ Gotchas / Things That Tripped Me Up

- 4104 vs 4103: 4104 = the script block itself; 4103 = the command as invoked with parameters. If you're not seeing the detail you expect, you may be checking the wrong ID.
- Logging must be turned on _before_ the event happens — there's no retroactive capture.

## 📌 Key Takeaways (Deep Concepts)

- The danger of LOLBAS tools is that blocking them outright breaks legitimate admin work — detection (via these Event IDs) matters more than prevention here.
- Recognizing a LOLBAS binary by its path (e.g. seeing `certutil.exe -urlcache -f` in a 4103 log) is a fast way to flag suspicious activity without needing a malware signature.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - PowerShell logging has multiple Event IDs: 4104 (script block), 4103 (command + params), 4101, 4698 (module).
> - Ran `Start-Process`, found it as Event ID 4103.
> - LOLBAS tools (powershell, certutil, mshta, rundll32, etc.) are legitimate binaries abused by attackers — watch for their unusual use in logs.

---

# Day 4: Network-Based Attack Detection Using UFW

> [!info]+ Objective Simulate a port scan from a Kali attacker machine against an Ubuntu target, then detect and block it using UFW's logging.

## 🧩 Concepts You Need First

- **Port scan** — probing a system's ports to find open/running services. Almost always **reconnaissance before exploitation** — it's how an attacker finds out what's worth attacking.
- **Nmap** — the standard tool for this. Key scan types: `-sS` (SYN, fast/stealthy), `-sT` (full TCP connect, less stealthy), `-sU` (UDP), `-sn` (ping scan, host discovery only — no ports).
- **UFW (Uncomplicated Firewall)** — a friendlier front-end for `iptables`. Logs to `/var/log/ufw.log`; rules live in `/etc/ufw/before.rules`.

## 🛠️ Step-by-Step

### Step 1: Run the scan (attacker/Kali)

```bash
nmap -p80 TARGET-IP
```

> [!note] What this does Probes port 80 (HTTP) specifically on the target — a narrow, targeted scan rather than a full 1–65535 sweep.

### Step 2: Install and enable UFW with logging (target/Ubuntu)

```bash
sudo apt install ufw
sudo ufw enable
sudo ufw logging on
sudo ufw logging high
```

### Step 3: Block the attacker

```bash
sudo ufw deny from <attacker-ip> to any port 80 proto tcp
sudo ufw reload
```

### Step 4: Watch the block happen live

```bash
sudo tail -f /var/log/ufw.log | grep "<attacker-ip>"
```

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`/var/log/ufw.log`|UFW's log of allowed/blocked traffic|
|`/etc/ufw/before.rules`|Low-level UFW rule definitions|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`ufw status`|Shows current firewall state|
|`ufw status numbered`|Shows rules with index numbers (for deletion)|
|`ufw allow <port>`|Opens a port|
|`ufw deny <port>`|Blocks a port|
|`ufw allow <service>`|Opens by service name, e.g. `ufw allow ssh`|
|`ufw allow from <ip>`|Whitelists a specific source IP|
|`ufw allow from <ip> to any port <port>`|Whitelists an IP for one specific port|
|`ufw delete allow <port>`|Removes a rule|

## ⚠️ Gotchas / Things That Tripped Me Up

- `ufw logging on` alone isn't enough detail — `ufw logging high` is what actually surfaces the blocked-packet entries you want to `grep` for.
- Rules take effect only after `ufw reload` — adding a `deny` rule without reloading can leave you watching a log that never shows the block.

## 📌 Key Takeaways (Deep Concepts)

- A port scan is the _reconnaissance_ phase — catching it here means you're stopping an attack before exploitation even starts, which is far cheaper than incident response later.
- Firewall logs (`ufw.log`) are a different data source from application/auth logs (Days 1–3) — a full SOC picture needs both network-layer and host-layer visibility.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Port scan = reconnaissance; Nmap is the standard tool (`-sS`, `-sT`, `-sU`, `-sn`).
> - UFW logs to `/var/log/ufw.log`; enable with `ufw logging high`.
> - Scanned target port 80, blocked the attacker IP with `ufw deny ... proto tcp`, confirmed the block by tailing the log.

---

# Day 5: Linux Auth Logs — SSH Brute Force Detection

> [!info]+ Objective Simulate an SSH brute-force attack with Hydra, then detect it by pattern-hunting through `/var/log/auth.log`.

## 🧩 Concepts You Need First

- **Brute force attack** — rapidly trying many username/password combinations until one works. Automated with tools like Hydra rather than typed by hand.
- **Why it's dangerous**: a successful brute force = full shell access, which an attacker can use to pivot, install malware, or exfiltrate data — and it's easy to miss without active log monitoring.
- **Hydra** — a fast password-cracking tool supporting 50+ protocols (SSH, FTP, HTTP, SMB...). Syntax: `hydra -L users.txt -P passlist.txt <target_ip> <protocol>` (use `-l`/`-p` for single user/pass instead of file lists).

## 🛠️ Step-by-Step

### Step 1: Confirm SSH is up (target)

```bash
sudo systemctl status ssh
```

### Step 2: Run the brute-force (attacker/Kali)

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET-IP
```

> [!note] What this does `-l root` targets a single username; `-P <wordlist>` tries every password in the file against it over SSH.

### Step 3: Hunt for failed logins (target)

```bash
sudo grep "Failed password" /var/log/auth.log
```

### Step 4: Find which usernames were targeted

```bash
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr
```

### Step 5: Watch it happen live

```bash
sudo tail -f /var/log/auth.log
```

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`/var/log/auth.log`|SSH/authentication log (Ubuntu/Debian)|
|`/var/log/secure`|Same purpose, CentOS/RHEL equivalent|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`hydra -l <user> -P <wordlist> ssh://<ip>`|Brute-forces one username over SSH|
|`grep "Failed password" /var/log/auth.log`|Lists all failed login lines|
|`awk '{print $(NF-5)}' \| sort \| uniq -c \| sort -nr`|Tallies which usernames were attempted, most-tried first|
|`tail -f /var/log/auth.log`|Live-streams new log lines as they're written|

## ⚠️ Gotchas / Things That Tripped Me Up

- The `awk '{print $(NF-5)}'` field position depends on the exact log line format — if the count looks wrong, print the whole line first and count fields manually before trusting the offset.
- A brute force doesn't have to fail forever — the real danger sign is a **success right after a run of failures**, not just the failures themselves.

## 📌 Key Takeaways (Deep Concepts)

- The detection signal is always the _pattern_: 20+ failed attempts from one IP in under 5 minutes, targeting sensitive accounts (`root`, `admin`), is the threshold worth memorizing.
- Detection (log analysis) pairs naturally with automated response — tools like `fail2ban` read these same auth log patterns and auto-block offending IPs, closing the loop from "detect" to "contain."

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Brute force = automated password guessing (Hydra); danger is full shell access if it succeeds.
> - `/var/log/auth.log` (Ubuntu) / `/var/log/secure` (RHEL) hold every login attempt.
> - Detection pattern: many fast failures from one IP, especially against root/admin, especially if followed by a success.
> - `grep "Failed password"` + `awk`/`sort`/`uniq -c` turns raw log lines into a ranked list of targeted usernames.