## tags: [soc, summary, challenge-05]

challenge: 5 days: 21-25

# 🧠 Challenge 05 — Quick Revision Summary

Everything from Days 21–25 in one scan. Read top to bottom in ~2 minutes.

## 🧩 Core Concepts (one-liners)

- **Phishing analysis** = investigate headers, body, URLs, and attachments for signs of deception. 8-step process: collect → headers → body → URLs → scan → decode → extract IOCs → respond/report.
- **Phishing types** span generic email phishing up through spear phishing, whaling, smishing, vishing, clone phishing, and BEC — same investigation process applies to all of them.
- **From ≠ Return-Path** — the displayed sender is trivially spoofed; the Return-Path (envelope sender) and the sender IP in `Received` headers reveal the real sending infrastructure.
- **SPF/DKIM/DMARC** — authentication layers that can each pass or fail independently; none of them alone proves legitimacy if the domain itself is a lookalike.
- **Threat Intelligence (TI)** has three tiers: tactical (IPs/hashes/domains — where this challenge mostly lives), operational (campaigns/malware families), strategic (big-picture trends).
- **Static malware analysis** = examine a file without executing it: hash, AV detections, metadata, entropy/packing, strings, embedded URLs, imports. Dynamic analysis (sandboxing) is the execution-based complement.
- **EICAR** = a standardized benign test string, not real malware — a positive detection validates your tooling works, it isn't a real infection.
- **Digital forensics 5-step process**: Identification → Preservation → Collection → Analysis → Reporting — evidence integrity and chain of custody are the point, distinguishing it from the NIST IR lifecycle it otherwise parallels.
- **Order of volatility**: memory is captured before disk or anything else, because RAM contents are lost the instant a system loses power.
- **The chain across this challenge**: phishing email → IOCs (21–22) → threat intel enrichment of those IOCs (23) → static analysis of a suspicious file using the same hash-lookup skill (24) → memory acquisition to support a deeper investigation (25).

## 📁 Directories & Files

|Path|Purpose|
|---|---|
|`.eml` / `.msg`|Standard email sample export formats (Days 21–22)|
|`sample-1.eml`|Sample phishing email the Day 23 TI scenario's IOCs were drawn from|
|EICAR test file|Safe standardized file for static malware analysis practice (Day 24)|
|`linux_memory.mem`|Acquired memory dump on the target machine (Day 25)|
|`~/forensics/memory_dumps/`|Destination directory on the analysis machine (Day 25)|

## 🛠️ Tool Cheat-Sheet by Purpose

|Purpose|Tools|
|---|---|
|Email header analysis|MX Toolbox, EML Analyzer|
|IP/domain reputation|VirusTotal, AbuseIPDB, Cisco Talos, Whois|
|URL/link analysis|urlscan.io, VirusTotal|
|Threat intel feeds|AlienVault OTX, ThreatFox (abuse.ch)|
|Decode obfuscated data|CyberChef|
|File hash & AV detection|VirusTotal, HashCalc, HashMyFiles, PowerShell `Get-FileHash`|
|File metadata/packing|ExifTool, PEStudio, Detect It Easy, binwalk|
|String extraction|`strings`, FLOSS, BinText|
|Sandboxing (dynamic analysis)|Hybrid Analysis, Any.Run|
|Memory acquisition|AVML (Microsoft)|

## ⌨️ Command Cheat-Sheet

**Digital forensics — memory acquisition (Day 25)**

```bash
wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x ./avml
sudo ./avml linux_memory.mem
ls -lh linux_memory.mem
strings linux_memory.mem | grep "mozilla"
mkdir ~/forensics/memory_dumps
scp user@<Target-IP>:/home/user/linux_memory.mem ~/forensics/memory_dumps/
```

## 🚩 Red Flags Learned This Week

- [ ] Lookalike domain using near-identical characters (`l`/`I`/`1`, `rn`/`m`, `0`/`O`) in place of the real brand's domain
- [ ] Mismatch between the From address and the Return-Path/sender IP
- [ ] SPF result of Fail (or Neutral/SoftFail) on a message claiming to be from a trusted brand
- [ ] Urgency-driven content (expiring points, account suspension, executive request) designed to short-circuit careful checking
- [ ] A hash, IP, or domain with poor reputation or known campaign tags across multiple TI sources
- [ ] Unusually high file entropy or packing indicators — signs of an obfuscated/encrypted payload

## ✅ 10-Second Recall

> [!summary]
> 
> - Day 21: Phishing types/techniques; 8-step process; lookalike domain (`secure-paypai.com`) checked via reputation lookup.
> - Day 22: Full header investigation on a real sample — From vs. Return-Path, sender IP reputation, SPF result, suspicious URL.
> - Day 23: TI enrichment of phishing-derived IOCs (IP, domain, hash) via VirusTotal, AbuseIPDB, OTX, ThreatFox.
> - Day 24: Static malware analysis (hash, AV detection, strings, decode) practiced safely on the EICAR test file.
> - Day 25: Digital forensics 5-step process; acquired and transferred a Linux memory dump with AVML — memory first, per order of volatility.