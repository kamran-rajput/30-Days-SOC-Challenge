## tags: [soc, summary, challenge-01] 
challenge: 1 
days: 1-5

# 🧠 Challenge 01 — Quick Revision Summary

Everything from Days 1–5 in one scan. Read top to bottom in ~2 minutes.

## 🧩 Core Concepts (one-liners)

- **Log** = timestamp + source + severity + description. Every format looks different; these four fields are always there.
- **Windows Security log** = auth events (logons, lockouts, group/privilege changes) — check first for unauthorized-access questions.
- **PowerShell logging** has layers: 4104 (script block text) vs 4103 (command + parameters as invoked) — different granularity, not duplicates.
- **LOLBAS** = legitimate pre-installed Windows binaries (powershell, certutil, mshta, rundll32...) abused by attackers because they're already trusted — detection matters more than blocking them outright.
- **Port scan** = reconnaissance, not the attack itself. Catching it here stops things before exploitation starts.
- **UFW** = friendly front-end for `iptables`; logs need `logging high` (not just `on`) to show blocked-packet detail.
- **Brute force** = automated credential guessing (Hydra); danger is full shell access on success.
- **The detection signal is always the pattern**, never a single event: many failures, fast, from one IP, against sensitive accounts (root/admin) — and especially a **success right after failures**.

## 📁 Directories & Log Files

|Path|OS|Purpose|
|---|---|---|
|`/var/log/syslog`|Linux|General system events|
|`/var/log/auth.log`|Linux (Debian/Ubuntu)|SSH/authentication attempts|
|`/var/log/secure`|Linux (RHEL/CentOS)|Same purpose as `auth.log`|
|`/var/log/kern.log`|Linux|Kernel messages|
|`/var/log/ufw.log`|Linux|UFW allow/deny/block events|
|`/etc/ufw/before.rules`|Linux|Low-level UFW rule definitions|
|Event Viewer → Security|Windows|Logons, lockouts, privilege/group changes|
|Event Viewer → PowerShell/Operational|Windows|Script block + command invocation logs|

## 🔑 Windows Event IDs to Know Cold

|ID|Meaning|
|---|---|
|4624|Successful logon|
|4625|Failed logon|
|4740|Account lockout|
|4732|User added to a security-enabled local group|
|4672|Special privileges assigned to new logon (privilege escalation)|
|4104|PowerShell script block logging (raw command text)|
|4103|PowerShell command invocation with parameter binding|
|4101|PowerShell execution via command-line arguments|
|4698|PowerShell module logging|

## ⌨️ Command Cheat-Sheet

**Windows**

```powershell
Get-LocalUser | Select-Object Name, Enabled          # enumerate local accounts (Day 1)
net use \\127.0.0.1\IPC$ /user:haxuser1 WrongPassword # force a failed logon (Day 2)
Start-Process "notepad.exe" -ArgumentList "<path>"    # generate PS execution log (Day 3)
eventvwr.msc                                          # open Event Viewer
```

**Linux — UFW / network (Day 4)**

```bash
nmap -p80 TARGET-IP                                       # port scan (attacker)
sudo apt install ufw && sudo ufw enable
sudo ufw logging on && sudo ufw logging high               # verbose logging
sudo ufw deny from <ip> to any port 80 proto tcp
sudo ufw reload
sudo tail -f /var/log/ufw.log | grep "<ip>"
ufw status numbered                                        # list rules with index
```

**Linux — Auth logs / brute force (Day 5)**

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET-IP
sudo grep "Failed password" /var/log/auth.log
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr
sudo tail -f /var/log/auth.log
```

## 🚩 Red Flags Learned This Week

- [ ] 4625 spikes — many failed logons, same source, short window
- [ ] 4672 right after a fresh 4624 — possible privilege escalation
- [ ] LOLBAS binary (certutil, mshta, rundll32...) doing something outside its normal use
- [ ] Repeated port-scan hits in `ufw.log` from one IP
- [ ] 20+ `Failed password` lines from one IP in <5 min in `auth.log`, especially targeting `root`/`admin`
- [ ] A login **success** immediately following a run of failures

## ✅ 10-Second Recall

> [!summary]
> 
> - Day 1: Logs = timestamp+source+severity+description. Linux → `/var/log/`. Windows → Event Viewer.
> - Day 2: Security log Event IDs — 4624/4625/4740/4732/4672.
> - Day 3: PowerShell logs — 4104 (script block) vs 4103 (command+params); watch for LOLBAS abuse.
> - Day 4: Port scan = recon. UFW logs to `/var/log/ufw.log`; block with `ufw deny ... proto tcp`.
> - Day 5: SSH brute force via Hydra → hunt `/var/log/auth.log` for failed-password patterns; pair with `fail2ban` for auto-response.