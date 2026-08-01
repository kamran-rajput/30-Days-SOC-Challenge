## tags: [soc, incident-response, challenge-03]

challenge: 3 days: 11-15

# 📘 Challenge 03 — Overview

Focus of this block: **Incident Response (IR)** — moving from "I can spot suspicious activity" (Challenges 01–02) to "I can run the structured process that detects, contains, and documents an incident once it's found," across both Windows and Linux.

**Days in this file:**

- [[#Day 11 Introduction to Incident Response|Day 11 — Introduction to Incident Response]]
- [[#Day 12 Incident Response Basics — Linux Suspicious Bash Script Execution|Day 12 — Linux Suspicious Bash Script Execution]]
- [[#Day 13 Detecting and Removing Malicious Cron Jobs — Linux Incident Response Lab|Day 13 — Malicious Cron Jobs (Linux)]]
- [[#Day 14 Detecting Suspicious PowerShell Activity — Windows Incident Response Lab|Day 14 — Suspicious PowerShell Activity (Windows)]]
- [[#Day 15 Incident Response Basics — Suspicious Network Connection|Day 15 — Suspicious Network Connection (Linux)]]

---

# Day 11: Introduction to Incident Response

> [!info]+ Objective Learn the core concepts of Incident Response and the NIST IR lifecycle, understand how common incident types look across different platforms, and run a full detect-and-respond exercise against a simulated Windows RDP brute-force attack.

## 🧩 Concepts You Need First

- **Incident Response (IR)** — the structured process for handling the aftermath of a security breach: detect it, contain the damage, investigate root cause, recover normal operations, then report and document. Everything from Challenges 01–02 (spotting a brute-force pattern, reading a packet capture) feeds into IR as the "what do I actually do once I've found something" layer.
- **NIST SP 800-61 Rev. 2 lifecycle** — the industry-standard 4-phase model for IR:

| Phase                                     | Description                                                                            |
| ----------------------------------------- | -------------------------------------------------------------------------------------- |
| 1. Preparation                            | Establish policies, train the team, set up tools and logging _before_ anything happens |
| 2. Detection and Analysis                 | Identify potential incidents using logs, alerts, and anomaly detection                 |
| 3. Containment, Eradication, and Recovery | Isolate the threat, remove malware/artifacts, restore systems securely                 |
| 4. Post-Incident Activity                 | Lessons learned, reporting, and improving the IR plan for next time                    |

- **Incident types by platform** — the same four-phase process applies everywhere, but what you're looking for changes by platform:

|Platform|Common Incident Types|
|---|---|
|Windows|Unauthorized login attempts (RDP/local brute force), PowerShell-based attacks, malware/ransomware execution, credential dumping (e.g. Mimikatz against LSASS), lateral movement via WMI/RDP|
|Linux|SSH brute force, malicious cron jobs for persistence, sudo abuse/privilege escalation, web shell uploads, crypto miner installation|
|AWS|IAM credential misuse, root user console access, unusual S3 bucket access, CloudTrail/logging disabled, EC2 abuse for C2|
|Network|DDoS, port scanning/recon, ARP spoofing/MitM, DNS tunneling, unauthorized VPN access|
|Email|Phishing/credential harvesting, malware via attachments, Business Email Compromise (BEC), spoofed domains, internal account compromise|

- **The SOC analyst's role in IR** — monitor logs/alerts via SIEM, investigate suspicious behavior, contain and isolate infected systems, coordinate with other teams, then document and report.

## 🛠️ Step-by-Step

### Step 1: Set up the lab environment

```
Windows Server 2019/2022 — RDP enabled, Event Viewer access, one local test account
Kali Linux VM — Hydra installed, same LAN/virtual network as the Windows Server
```

> [!note] What this does Mirrors the Challenge 01 Day 5 SSH brute-force setup, but against RDP (TCP/3389) instead of SSH — same attack class, different protocol and platform.

### Step 2: Enable RDP and create a test account

```
System Properties → Remote → Enable Remote Desktop
Windows Defender Firewall → Advanced Settings → Inbound Rules → Remote Desktop (TCP-In) → Enable
net user attackerlab Password123 /add
```

> [!note] What this does Opens the attack surface intentionally for the lab and creates a known-credential account to brute-force against — standard practice for a controlled, authorized exercise.

### Step 3: Simulate the RDP brute-force attack

```bash
sudo apt update && sudo apt install hydra
hydra -t 4 -V -f -l attackerlab -P /usr/share/wordlists/rockyou.txt rdp://<Windows_Server_IP>
```

> [!note] What this does Same Hydra tool from Challenge 01 Day 5, now pointed at RDP instead of SSH — `-t 4` sets 4 parallel tasks, `-V` shows each attempt, `-f` stops on first valid credential found.

### Step 4: Detect the attack in Event Viewer

```
Event Viewer → Windows Logs → Security → filter for Event ID 4625
```

> [!note] What to look for Multiple 4625 (Failed Logon) events with **Logon Type 10** (RemoteInteractive/RDP specifically — distinct from the generic 4625s covered in Challenge 01), a Failure Reason of "Unknown user name or bad password," and a Caller IP Address matching the Kali machine.

### Step 5: Respond — contain and document

```powershell
net user attackerlab /active:no
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound -RemoteAddress <Kali_IP> -Action Block
```

> [!note] What this does Disables the targeted account and blocks the attacker's IP at the Windows Firewall level — the Containment step of the NIST lifecycle. Export the relevant Event Logs as evidence, then write a short report: what was detected, how it was confirmed, and what action was taken.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Event Viewer → Windows Logs → Security|Where Event ID 4625 (Failed Logon) events are reviewed|
|`/usr/share/wordlists/rockyou.txt`|Wordlist used by Hydra for the brute-force attempt|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`net user attackerlab Password123 /add`|Create the test account targeted by the attack|
|`hydra -t 4 -V -f -l attackerlab -P <wordlist> rdp://<IP>`|Run the RDP brute-force simulation|
|`net user attackerlab /active:no`|Disable the compromised/targeted account (containment)|
|`New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound -RemoteAddress <IP> -Action Block`|Block the attacker's IP at the firewall (containment)|

## ⚠️ Gotchas / Things That Tripped Me Up

- Logon Type matters as much as the Event ID itself — a 4625 with Logon Type 10 (RDP) tells a different story than one with Logon Type 3 (network) or Logon Type 2 (interactive/local console); don't stop at "it's a 4625," check the Logon Type field every time.
- This lab is intentionally scoped **without Sysmon** — real environments almost always layer Sysmon on top of native Windows logging for richer process-level detail; treat this as the baseline detection capability, not the ceiling.

## 📌 Key Takeaways (Deep Concepts)

- IR isn't a separate skill from detection — it's detection (Challenges 01–02) plus a repeatable structure for what happens _next_. The NIST 4-phase model gives that structure regardless of platform or attack type.
- The same "many failures, fast, from one source, especially followed by a success" pattern from Challenge 01 Day 5 applies directly here — only the Event ID's Logon Type changes to reflect the protocol (RDP vs. SSH).

## ✅ Summary (10-second recall)

> [!summary]
> 
> - IR = detect → contain → investigate → recover → report. NIST lifecycle: Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-Incident Activity.
> - Incident types differ by platform (Windows, Linux, AWS, Network, Email) but the response process is the same across all of them.
> - Lab: simulated RDP brute force with Hydra, detected via Event ID 4625 + Logon Type 10, contained by disabling the account and blocking the attacker IP with `New-NetFirewallRule`.

---

# Day 12: Incident Response Basics — Linux Suspicious Bash Script Execution

> [!info]+ Objective Apply the same NIST IR process from Day 11 to a Linux scenario: detect a suspicious script running from `/tmp`, investigate what it's doing, contain and remove it, then document findings and prevention steps.

## 🧩 Concepts You Need First

- **The scenario** — a monitoring system flags a suspicious file in `/tmp`: a bash script (`payload.sh`) that connects out to an unknown IP. `/tmp` is a classic staging location for attacker scripts because it's world-writable by default and often overlooked.
- **NIST lifecycle applied to Linux** — identical 4 phases as Day 11, just with Linux-native tools instead of Event Viewer/PowerShell:

|Phase|Description|
|---|---|
|1. Preparation|Logging enabled, investigation tools (`ps`, `find`, `lsof`, `curl`, `grep`) available|
|2. Detection and Analysis|Identify the suspicious activity via running processes and file checks|
|3. Containment, Eradication, and Recovery|Kill the process, remove the script, check for persistence|
|4. Post-Incident Activity|Document what happened and implement prevention measures|

## 🛠️ Step-by-Step

### Step 1: Simulate the scenario

```bash
mkdir ~/script-lab && cd ~/script-lab
nano fakebackup.sh
```

```bash
#!/bin/bash
echo "[*] Simulating backup operation..."
sleep 60
```

```bash
chmod +x fakebackup.sh
./fakebackup.sh &
```

> [!note] What this does Creates a harmless stand-in script that mimics a real payload's behavior — runs in the background and stays alive for a while, giving you a live process to actually go find, rather than investigating something purely theoretical.

### Step 2: Detection and Analysis

```bash
ps aux | grep fakebackup.sh
find /tmp -name "*.sh"
```

> [!note] What this does `ps aux | grep` confirms the script is actually running and shows you the process ID and the user who launched it; `find /tmp -name "*.sh"` searches for script files sitting in the classic attacker staging directory, whether or not they're currently running.

### Step 3: Containment, Eradication, and Recovery

```bash
pkill curl
rm -f /tmp/payload.sh
crontab -e
```

> [!note] What this does `pkill curl` kills any related outbound-connection process the script may have spawned; `rm -f` removes the malicious file itself; checking `crontab -e` confirms the attacker didn't also plant a scheduled task to re-launch the payload after removal — persistence is the thing that turns a one-time cleanup into a recurring incident (a theme Day 13 digs into directly).

### Step 4: Post-Incident Activity

> [!note] What to document What triggered the alert, what the script was actually doing, and which user account executed it. Recommendations to carry forward: enable file integrity monitoring (e.g. AIDE), mount `/tmp` with the `noexec` option to block script execution there outright, and educate users on not running unknown scripts.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`/tmp`|Common attacker staging location — world-writable, easy to overlook|
|`crontab -e`|Where scheduled-task persistence would be planted and needs checking|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`ps aux \| grep <name>`|Confirm a suspicious script is running and identify its PID/user|
|`find /tmp -name "*.sh"`|Search for script files in the classic staging directory|
|`pkill curl`|Kill processes matching a name (here, an outbound-connection tool)|
|`rm -f /tmp/payload.sh`|Remove the malicious file|
|`crontab -e`|Check/edit scheduled tasks for planted persistence|

## ⚠️ Gotchas / Things That Tripped Me Up

- Killing the process and deleting the file isn't the full job — skipping the `crontab` check means a persistence mechanism can silently relaunch the payload later, turning "resolved" into "recurring."
- `/tmp` being world-writable by default is the actual root cause here, not just the symptom — the `noexec` mount-option recommendation addresses the underlying weakness, not just this one incident.

## 📌 Key Takeaways (Deep Concepts)

- The NIST 4-phase process is genuinely OS-agnostic — Day 11 ran it against Windows RDP/Event Viewer, Day 12 runs the identical structure against Linux processes/files. The tools change; Preparation → Detection → Containment → Post-Incident does not.
- This connects directly back to Challenge 01 Day 5's auth.log brute-force hunting: both are Linux-side investigations built on the same instinct — check what's running, check what's scheduled, and never assume removal alone means the threat is fully gone.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Scenario: suspicious `payload.sh` found running from `/tmp`, connecting to an unknown IP.
> - Detection: `ps aux | grep`, `find /tmp -name "*.sh"`.
> - Containment: `pkill curl`, `rm -f`, then check `crontab -e` for persistence.
> - Prevention: file integrity monitoring (AIDE), mount `/tmp` with `noexec`, user education.

---

# Day 13: Detecting and Removing Malicious Cron Jobs — Linux Incident Response Lab

> [!info]+ Objective Investigate a malicious cron job used for persistence on Linux: simulate the attack, detect the scheduled task, analyze the script it runs, and remove it — the persistence check that Day 12 flagged but didn't dig into.

## 🧩 Concepts You Need First

- **Cron job** — a scheduled task that runs automatically at defined intervals on Unix/Linux. Legitimately used for backups, updates, and monitoring — but attackers use the exact same mechanism to re-execute payloads, reconnect to C2, or simply survive a reboot.
- **Crontab entry format** — five time fields followed by the command to run:

```
*  *  *  *  *  command-to-run
│  │  │  │  │
│  │  │  │  └─ Day of week (0-7, Sun = 0 or 7)
│  │  │  └──── Month (1-12)
│  │  └─────── Day of month (1-31)
│  └────────── Hour (0-23)
└───────────── Minute (0-59)
```

- **NIST lifecycle applied here**:

|Phase|Description|
|---|---|
|1. Preparation|System logging active, users trained to notice unusual cron behavior|
|2. Detection and Analysis|Identify unauthorized cron entries and investigate their scripts/IPs|
|3. Containment, Eradication, and Recovery|Stop the cron activity, remove the script, restore configuration|
|4. Post-Incident Activity|Document the incident, set alerts for future cron changes|

- **The scenario** — an attacker has added a cron job silently running a malicious script from `/tmp` every minute.

## 🛠️ Step-by-Step

### Step 1: Simulate the incident

```bash
echo -e '#!/bin/bash\necho "Ping from attacker server" >> /tmp/.cron.log' > /tmp/malicious.sh
chmod +x /tmp/malicious.sh
echo "* * * * * /tmp/malicious.sh" >> /var/spool/cron/root
```

> [!note] What this does Creates a script that logs a fake "ping" every time it runs, then schedules it to fire every minute by appending directly to root's crontab file — the same technique an attacker uses to establish silent, recurring execution.

### Step 2: Detection and Analysis

```bash
sudo systemctl status cron
crontab -l
grep -r "/tmp/" /etc/cron* /var/spool/cron/crontabs
cat /tmp/.cron.log
cat /tmp/malicious.sh
```

> [!note] What this does Confirms cron itself is running, lists the current user's crontab, then greps across _all_ the places cron jobs can live (not just `crontab -l`, which only shows the current user's entries) for anything pointing at `/tmp`. The log file and script contents confirm what the job is actually doing.

### Step 3: Containment, Eradication, and Recovery

```bash
crontab -l | grep -v "malicious.sh" | crontab -
rm -f /tmp/malicious.sh /tmp/.cron.log
sudo systemctl restart cron
```

> [!note] What this does Rebuilds the crontab excluding the malicious line, deletes the script and its log output, then restarts the cron service to make sure no stale in-memory schedule is still holding the old entry.

### Step 4: Post-Incident Activity

> [!note] What to document When the cron job was added, what the script was doing, and any signs of lateral movement or download activity. Recommendations: restrict cron access to authorized users only, enable cron integrity checks, and set up alerts for new cron entries using `auditd` or `inotify`.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`/tmp/malicious.sh`|The simulated malicious script|
|`/var/spool/cron/root`|Root's crontab file — where the persistence entry was added directly|
|`/etc/cron*`, `/var/spool/cron/crontabs`|Other locations cron jobs can live — must be checked, not just `crontab -l`|
|`/var/log/syslog` or `/var/log/cron`|Where cron execution logs typically live|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`sudo systemctl status cron`|Confirm the cron service is running|
|`crontab -l`|List the current user's scheduled jobs|
|`grep -r "/tmp/" /etc/cron* /var/spool/cron/crontabs`|Search all cron locations for suspicious entries|
|`crontab -l \| grep -v "malicious.sh" \| crontab -`|Remove a specific line from the crontab in place|
|`sudo systemctl restart cron`|Restart the cron service after cleanup|

## ⚠️ Gotchas / Things That Tripped Me Up

- `crontab -l` only shows the invoking user's jobs — an entry written directly into `/var/spool/cron/root` (as this simulation does) or into `/etc/cron.d/` won't show up unless you specifically grep those locations too.
- This is exactly the persistence mechanism Day 12 warned about checking for but didn't investigate directly — Day 12's `crontab -e` check would only have caught this if it happened to be the current user's own crontab.

## 📌 Key Takeaways (Deep Concepts)

- Persistence is often the actual objective of an intrusion, not the initial script execution — a one-off malicious script (Day 12) is an inconvenience; a cron job re-running it every minute is a foothold. Checking for persistence mechanisms is what separates "cleaned up the symptom" from "closed the incident."
- Cron abuse detection generalizes the same way IR did across Days 11–12: know every location a mechanism can hide in (multiple crontab paths here, multiple Logon Types on Day 11), not just the one place that's easiest to check.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Cron job = scheduled task; attackers abuse it for persistence (re-running payloads, reconnecting to C2).
> - Detection: `crontab -l` PLUS `grep -r "/tmp/" /etc/cron* /var/spool/cron/crontabs` — don't rely on `crontab -l` alone.
> - Containment: rebuild crontab without the malicious line, delete the script/log, restart cron.
> - Prevention: restrict cron access, integrity checks, `auditd`/`inotify` alerts on new entries.

---

# Day 14: Detecting Suspicious PowerShell Activity — Windows Incident Response Lab

> [!info]+ Objective Simulate and investigate a suspicious PowerShell command on Windows: enable proper script-block logging, detect the command via Event Viewer, and run through containment, eradication, and recovery for a hosts-file-tampering scenario.

## 🧩 Concepts You Need First

- **Why PowerShell matters in IR** — it's a legitimate, powerful admin tool that's equally attractive to attackers for downloading malware, moving laterally, and running hidden scripts. Good logging is what turns PowerShell from a blind spot into a detection source.
- **NIST lifecycle applied here**:

|Phase|Description|
|---|---|
|1. Preparation|Enable PowerShell logging, ensure security auditing is in place|
|2. Detection and Analysis|Identify and investigate PowerShell misuse in logs|
|3. Containment, Eradication, and Recovery|Kill malicious processes, remove scripts, secure PowerShell usage|
|4. Post-Incident Activity|Document findings, improve PowerShell restrictions and monitoring|

- **PowerShell logs to monitor** — this expands directly on the Event IDs from Challenge 01 Day 3:

|Event ID|Meaning|
|---|---|
|4104|Script block logging — the raw PowerShell commands executed|
|4103|Command invocation with parameter binding — detailed command execution|
|4698|PowerShell Module Logging for specific module execution|
|4101|Execution of PowerShell commands via command-line arguments|

- **The scenario** — a user accidentally ran a PowerShell command simulating suspicious behavior: contacting a remote server and writing data to disk. The lab stands in a safer version of that: opening a sensitive system file (the hosts file) via `Start-Process`.

## 🛠️ Step-by-Step

### Step 1: Enable PowerShell script block logging

```
Win + R → gpedit.msc
Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell
Enable: Module Logging, Script Block Logging, Script Execution
```

> [!note] What this does Without this Preparation step, none of the detection that follows is possible — this is the same "logging isn't automatic, it has to be turned on and configured" lesson as `ufw logging high` back in Challenge 01 Day 4.

### Step 2: Generate a PowerShell log entry

```powershell
Start-Process "notepad.exe" -ArgumentList "C:\Windows\System32\drivers\etc\hosts"
```

> [!note] What this does Launches Notepad directly against the hosts file — a stand-in for the kind of command an attacker might run to inspect or modify DNS overrides on the machine.

### Step 3: Find and analyze the event

```
Event Viewer → Applications and Services Logs → Microsoft → Windows → PowerShell → Operational
Look for Event ID 4103
```

> [!note] What to capture The exact PowerShell command executed, the user who ran it, and the timestamp — the same three data points that make any log entry useful for a report, not just this one.

### Step 4: Incident response — check, contain, eradicate, recover

```powershell
# Check the file
Get-Content "C:\Windows\System32\drivers\etc\hosts"

# Containment (normally an EDR tool's job — done manually here)
New-NetFirewallRule -DisplayName "Block Network Access" -Direction Outbound -Action Block -Enable

# Eradication
Copy-Item "C:\Backup\hosts" -Destination "C:\Windows\System32\drivers\etc\hosts" -Force
Remove-Item "C:\Path\To\SuspiciousFile.exe" -Force

# Recovery
Restore-Computer -RestorePoint 1
Set-NetFirewallRule -DisplayName "Block Network Access" -Enabled False
```

> [!note] What this does Walks the full Containment → Eradication → Recovery sequence: cut outbound network access first, restore the tampered file from a known-good backup and remove any suspicious binaries, then roll back to a system restore point and re-enable network access once the system is confirmed clean. Close out with a written incident report covering the timeline and commands used.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`C:\Windows\System32\drivers\etc\hosts`|System file targeted in this scenario — DNS override location, a common attacker tampering target|
|Event Viewer → Applications and Services Logs → Microsoft → Windows → PowerShell → Operational|Where 4103/4104 script-block and command logs live|
|`gpedit.msc` → Windows PowerShell settings|Where Module/Script Block/Script Execution logging is enabled|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`Start-Process "notepad.exe" -ArgumentList "<path>"`|Generate a PowerShell execution log entry (simulated suspicious action)|
|`New-NetFirewallRule -DisplayName "Block Network Access" -Direction Outbound -Action Block -Enable`|Cut outbound network access (containment)|
|`Copy-Item <backup> -Destination <target> -Force`|Restore a tampered file from backup (eradication)|
|`Remove-Item <path> -Force`|Delete a suspicious file (eradication)|
|`Restore-Computer -RestorePoint 1`|Roll the system back to a clean restore point (recovery)|
|`Set-NetFirewallRule -DisplayName "Block Network Access" -Enabled False`|Re-enable network access once the system is clean (recovery)|

## ⚠️ Gotchas / Things That Tripped Me Up

- 4103 and 4104 are not duplicates — 4103 shows the command with its bound parameters (what was invoked), while 4104 shows the raw script block text (what the script actually contained). Real investigations often need both to get the full picture, a distinction first introduced back in Challenge 01 Day 3.
- Logging has to be explicitly enabled via Group Policy before any of this works — a fresh Windows install won't have Script Block Logging on by default, so "Preparation" here is a hard prerequisite, not an optional first step.
- `Restore-Computer` depends on restore points actually existing — a system with System Restore disabled or no prior checkpoints won't have anything to roll back to.

## 📌 Key Takeaways (Deep Concepts)

- This lab operationalizes the PowerShell logging theory from Challenge 01 Day 3 into a full IR lifecycle — Day 3 was "know these Event IDs exist," Day 14 is "use them to actually detect, contain, and recover from an incident."
- LOLBAS-style abuse (Challenge 01) and PowerShell misuse (this lab) are the same underlying problem: legitimate, pre-installed tools being used for harm. The defense in both cases is the same — logging and monitoring, not blocking the tool outright, since admins need it too.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - PowerShell logging must be enabled via `gpedit.msc` (Module Logging, Script Block Logging, Script Execution) before detection is possible.
> - Detection: Event ID 4103 (command + parameters) in PowerShell → Operational logs; 4104 gives the raw script block text.
> - IR flow: check the affected file → block outbound network (containment) → restore from backup + remove suspicious files (eradication) → restore point + re-enable network (recovery) → report.

---

# Day 15: Incident Response Basics — Suspicious Network Connection

> [!info]+ Objective Investigate a suspicious outbound network connection on Linux that mimics C2 beaconing: identify the active connection, trace it to its source process, then contain and document the finding.

## 🧩 Concepts You Need First

- **Why it matters** — attackers rely on outbound connections to talk to command-and-control (C2) servers. Spotting and cutting these off is core SOC/IR work, and it's the host-side complement to the packet-capture view of beaconing covered in Challenge 02 Day 9's HTTP analysis.
- **NIST lifecycle applied here**:

|Phase|Description|
|---|---|
|1. Preparation|`netstat`, `ss`, `lsof` installed; `auditd`/network logging enabled|
|2. Detection and Analysis|Identify unexpected remote connections and their processes|
|3. Containment, Eradication, and Recovery|Kill the process, investigate the binary, block the destination IP|
|4. Post-Incident Activity|Document findings, improve firewall rules, configure monitoring|

- **The scenario** — a Linux system shows an active connection to an unknown IP, `45.13.220.98:443`, unrelated to any known service.

## 🛠️ Step-by-Step

### Step 1: Simulate the suspicious connection

```bash
nohup bash -c 'while true; do curl http://45.13.220.98/ping >/dev/null 2>&1; sleep 30; done' &
```

> [!note] What this does Runs a loop in the background that pings the target IP every 30 seconds indefinitely — a simplified stand-in for real beaconing malware, which typically calls home on a regular interval to check for new instructions.

### Step 2: Detect the active connection

```bash
netstat -plant
# or
ss -plant
```

> [!note] What each flag means `-p` shows the PID and program name behind the connection, `-l` shows listening sockets, `-a` shows all connections and listening ports, `-n` shows numeric addresses instead of resolving hostnames, `-t` restricts output to TCP. Look for the suspicious `45.13.220.98:443` entry.

### Step 3: Identify the responsible process

```bash
ps aux | grep 45.13.220.98
```

> [!note] What this does Takes the PID surfaced by `netstat`/`ss` and confirms which running process — and which command line — is actually behind the connection, turning "some process is talking to this IP" into "this specific script is."

### Step 4: Contain and eradicate

```bash
kill <PID>
# or
pkill curl
ufw deny out to 45.13.220.98
```

> [!note] What this does Kills the offending process directly, then adds a UFW rule to block any _future_ outbound traffic to that IP — the same `ufw` tool from Challenge 01 Day 4, now used for egress filtering instead of blocking inbound port-scan traffic.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Process list (`ps aux`)|Where the PID from netstat/ss is traced back to a command line and binary|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`netstat -plant` / `ss -plant`|List active connections with PID/program name|
|`ps aux \| grep <ip>`|Trace a connection's PID back to its process and command line|
|`kill <PID>`|Terminate the specific offending process|
|`pkill curl`|Kill all processes matching a name|
|`ufw deny out to <ip>`|Block future outbound traffic to a specific IP (egress filtering)|

## ⚠️ Gotchas / Things That Tripped Me Up

- `netstat` isn't installed by default on many modern distros — `ss` is the current standard replacement and worth defaulting to.
- `ufw deny out` blocks _new_ outbound connections going forward; it doesn't tear down a connection that's already established — the process still needs to be killed separately, which is why containment here is kill-the-process AND block-the-IP, not either alone.
- Seeing the program name in `netstat -p`/`ss -p` output for processes owned by other users typically requires root/sudo.

## 📌 Key Takeaways (Deep Concepts)

- This is the host-side mirror of Challenge 02 Day 9's network-capture-side beaconing detection — Wireshark spotting repeated HTTP requests to one host from _outside_ the machine, versus `netstat`/`ps` spotting the same pattern from _inside_ it. A real investigation usually needs both vantage points.
- UFW's reappearance here (after Challenge 01 Day 4's inbound port-scan blocking) is a good example of one tool serving two directions of the same job: inbound rules stop reconnaissance from coming in, outbound (egress) rules stop compromised hosts from calling out.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Scenario: unexplained outbound connection to `45.13.220.98:443`, simulating C2 beaconing.
> - Detection: `netstat -plant` / `ss -plant` to find the connection, `ps aux | grep <ip>` to trace it to a process.
> - Containment: `kill <PID>` (or `pkill curl`) AND `ufw deny out to <ip>` — killing the process alone doesn't block future reconnection attempts.
> - Recommendations: egress filtering, IDS/IPS, ongoing outbound traffic monitoring.
