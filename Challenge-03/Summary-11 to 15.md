## tags: [soc, summary, challenge-03]

challenge: 3 days: 11-15

# 🧠 Challenge 03 — Quick Revision Summary

Everything from Days 11–15 in one scan. Read top to bottom in ~2 minutes.

## 🧩 Core Concepts (one-liners)

- **Incident Response (IR)** = detect → contain → investigate root cause → recover → report. Detection (Challenges 01–02) tells you _what happened_; IR is the structured process for _what you do about it_.
- **NIST SP 800-61 Rev. 2 lifecycle** = Preparation → Detection and Analysis → Containment, Eradication, and Recovery → Post-Incident Activity. Same 4 phases regardless of platform or attack type.
- **Incident types are platform-specific, the process isn't** — Windows (RDP/PowerShell/credential dumping), Linux (SSH/cron/sudo abuse), AWS (IAM/S3/CloudTrail), Network (DDoS/scanning/MitM), Email (phishing/BEC) all get the same 4-phase treatment.
- **RDP brute force (Day 11)** = same Hydra pattern as Challenge 01's SSH brute force, detected via Event ID 4625 with **Logon Type 10** specifically (not just any 4625).
- **Persistence is the real objective** — a one-off malicious script (Day 12) is a nuisance; a cron job re-running it every minute (Day 13) is a foothold. Always check for scheduled-task persistence, not just the initial artifact.
- **Cron jobs can hide outside `crontab -l`** — direct entries in `/var/spool/cron/root` or `/etc/cron.d/` won't show up unless you grep those locations too.
- **PowerShell 4103 vs. 4104** (from Challenge 01 Day 3) put into practice: 4103 = command + bound parameters, 4104 = raw script block text — real investigations often need both.
- **Killing a process ≠ blocking future reconnection** (Day 15) — `kill`/`pkill` stops what's running now; a firewall rule (`ufw deny out`) is still needed to stop it from reconnecting.
- **UFW works both directions** — Challenge 01 Day 4 used it for inbound port-scan blocking; Day 15 uses the same tool for outbound (egress) filtering against C2 traffic.

## 📁 Directories & Log Files

|Path|OS|Purpose|
|---|---|---|
|Event Viewer → Windows Logs → Security|Windows|Event ID 4625 (Failed Logon) — check the Logon Type field|
|Event Viewer → Apps and Services Logs → Microsoft → Windows → PowerShell → Operational|Windows|4103/4104 PowerShell script and command logs|
|`gpedit.msc` → Windows PowerShell settings|Windows|Where Module/Script Block/Script Execution logging is enabled|
|`C:\Windows\System32\drivers\etc\hosts`|Windows|DNS override file — common tampering target|
|`/tmp`|Linux|Common attacker staging directory — world-writable by default|
|`/var/spool/cron/root`, `/etc/cron*`, `/var/spool/cron/crontabs`|Linux|All the places a cron job can hide — not just `crontab -l`|
|`/var/log/syslog` or `/var/log/cron`|Linux|Cron execution logs|
|Process list (`ps aux`)|Linux|Traces a PID from netstat/ss back to a command line|

## 🔑 Windows Event IDs to Know Cold

|ID|Meaning|
|---|---|
|4625|Failed logon — check Logon Type (10 = RDP) to know which protocol was targeted|
|4103|PowerShell command invocation with parameter binding|
|4104|PowerShell script block logging (raw command text)|

## ⌨️ Command Cheat-Sheet

**Windows — RDP brute force (Day 11) & PowerShell (Day 14)**

```powershell
net user attackerlab Password123 /add                 # create test account (Day 11)
net user attackerlab /active:no                        # disable account — containment (Day 11)
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound -RemoteAddress <IP> -Action Block   # (Day 11)
Start-Process "notepad.exe" -ArgumentList "<path>"      # generate PS log entry (Day 14)
New-NetFirewallRule -DisplayName "Block Network Access" -Direction Outbound -Action Block -Enable        # (Day 14)
Copy-Item "<backup>" -Destination "<target>" -Force     # restore tampered file (Day 14)
Remove-Item "<path>" -Force                             # remove suspicious file (Day 14)
Restore-Computer -RestorePoint 1                        # roll back to clean state (Day 14)
Set-NetFirewallRule -DisplayName "Block Network Access" -Enabled False   # re-enable network (Day 14)
```

**Kali — attack simulation**

```bash
hydra -t 4 -V -f -l attackerlab -P /usr/share/wordlists/rockyou.txt rdp://<Windows_Server_IP>   # (Day 11)
```

**Linux — bash script & cron (Days 12–13)**

```bash
ps aux | grep fakebackup.sh                             # confirm process running (Day 12)
find /tmp -name "*.sh"                                    # search staging directory (Day 12)
pkill curl && rm -f /tmp/payload.sh                       # containment (Day 12)
crontab -l                                                  # list current user's cron jobs (Day 13)
grep -r "/tmp/" /etc/cron* /var/spool/cron/crontabs        # check ALL cron locations (Day 13)
crontab -l | grep -v "malicious.sh" | crontab -             # remove one line from crontab (Day 13)
sudo systemctl restart cron                                 # restart service after cleanup (Day 13)
```

**Linux — network connection (Day 15)**

```bash
netstat -plant                                              # or: ss -plant — list active connections
ps aux | grep <ip>                                          # trace PID to process
kill <PID>                                                    # or: pkill curl — terminate process
ufw deny out to <ip>                                          # block future outbound traffic
```

## 🚩 Red Flags Learned This Week

- [ ] 4625 with Logon Type 10 — RDP-specific brute-force attempt (not just any failed logon)
- [ ] Unknown script or binary running from `/tmp`, especially one making outbound connections
- [ ] Cron entries pointing at `/tmp` or unfamiliar paths — check all cron locations, not just `crontab -l`
- [ ] Unexpected PowerShell command activity in 4103/4104 logs, especially touching sensitive system files
- [ ] Active outbound connection to an unrecognized IP, particularly on a regular interval (beaconing)
- [ ] Any cleanup that stops at "killed the process" without checking for a persistence mechanism (cron, scheduled task, startup entry)

## ✅ 10-Second Recall

> [!summary]
> 
> - Day 11: IR = NIST 4-phase lifecycle (Prep → Detect/Analyze → Contain/Eradicate/Recover → Post-Incident). RDP brute force via Hydra, detected by 4625 + Logon Type 10.
> - Day 12: Linux `/tmp` script investigation — `ps aux`, `find`, kill + remove, then check `crontab -e` for persistence.
> - Day 13: Malicious cron jobs hide beyond `crontab -l` — grep all cron locations, remove the entry, restart cron.
> - Day 14: PowerShell logging (4103/4104) must be enabled via `gpedit.msc` first; full contain → restore-from-backup → recovery-point flow for a hosts-file tampering scenario.
> - Day 15: Outbound beaconing — `netstat`/`ss` to spot it, `ps aux` to trace the process, kill the process AND block the IP with `ufw deny out` (killing alone doesn't prevent reconnection).