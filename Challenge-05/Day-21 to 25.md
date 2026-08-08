## tags: [soc, phishing, threat-intel, malware-analysis, forensics, challenge-05]

challenge: 5 days: 21-25

# 📘 Challenge 05 — Overview

Focus of this block: **investigation past the network** — phishing emails, the threat intelligence used to enrich indicators found in them, static malware analysis of suspicious files, and the digital forensics process for acquiring evidence. Each day hands off an artifact to the next: a phishing email yields IOCs (Day 21–22), those IOCs get enriched with threat intel (Day 23), a suspicious file gets analyzed on its own (Day 24), and a compromised system gets its memory captured for deeper investigation (Day 25).

**Days in this file:**

- [[#Day 21 Introduction to Phishing Analysis|Day 21 — Introduction to Phishing Analysis]]
- [[#Day 22 Phishing Analysis — Investigating a Phishing Email|Day 22 — Investigating a Phishing Email]]
- [[#Day 23 Threat Intelligence Basics|Day 23 — Threat Intelligence Basics]]
- [[#Day 24 Introduction to Malware Analysis|Day 24 — Introduction to Malware Analysis]]
- [[#Day 25 Introduction to Digital Forensics|Day 25 — Introduction to Digital Forensics]]

---

# Day 21: Introduction to Phishing Analysis

> [!info]+ Objective Learn how to analyze a phishing email — headers, body, URLs, and attachments — understand the different phishing types and techniques, and use open-source tools to extract Indicators of Compromise (IOCs).

## 🧩 Concepts You Need First

- **Phishing analysis** — investigating a suspicious email to determine whether it's crafted to steal information or deliver malware, by examining metadata, links, files, and content for signs of deception.
- **Phishing types** — not all phishing is the same generic "fake bank email":

|Type|Description|
|---|---|
|Email Phishing|Generic emails impersonating a trusted brand|
|Spear Phishing|Targeted at a specific person or department|
|Whaling|Spear phishing aimed at executives (CEO/CFO fraud)|
|Smishing|Phishing via SMS with malicious links|
|Vishing|Voice phishing calls impersonating IT/helpdesk|
|Clone Phishing|A legitimate email re-sent with a malicious link/file swapped in|
|Business Email Compromise (BEC)|Impersonating senior staff to trick finance/HR into transferring money or data|

- **Common techniques** — display name spoofing (a friendly name masking a lookalike address), lookalike domains (character substitution like `paypai.com` for `paypal.com`), URL redirection through shorteners, HTML forms embedded directly in the email body, macro-based documents, QR code phishing ("quishing"), and attachment-only phishing with no body text at all.
- **The 8-step investigation process** — collect the sample (`.eml`/`.msg`) → analyze headers (sender IP, Return-Path, SPF/DKIM/DMARC) → examine body content (tone, branding, urgency) → hover over URLs to check for display/actual mismatches → scan URLs/files (VirusTotal, sandbox) → decode obfuscated data (CyberChef) → extract indicators (domains, IPs, hashes, sender addresses) → respond and report.

## 🛠️ Step-by-Step

### Step 1: Investigate the reported sender address

```
noreply@secure-paypai.com
```

> [!note] What to look for `secure-paypai.com` swaps the lowercase `l` in "paypal" for an `i` — a classic lookalike domain that's easy to miss at a glance, especially in a font where `l` and `I` render similarly.

### Step 2: Check the domain's reputation

```
Whois/IP lookup + VirusTotal or a similar reputation tool, searching the domain "secure-paypai.com"
```

> [!note] What this does Reputation tools aggregate prior sightings of a domain — how recently it was registered, whether it's been flagged in other phishing campaigns, and what infrastructure it resolves to. A domain registered days ago and already flagged is a strong signal on its own, even before reading the email body.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`.eml` / `.msg`|Standard export formats for a captured email sample|

## ⌨️ Tool Cheat-Sheet

|Tool|Purpose|
|---|---|
|Email Header Analyzer|Decode sender metadata and trace origin|
|VirusTotal|Scan email links and attachments for malware|
|Hybrid Analysis / Any.Run|Sandbox for dynamic file and URL behavior|
|OLETools|Analyze Office macros in `.doc`/`.xls` files|
|CyberChef|Decode base64, hex, and obfuscated strings|
|Whois/IP Lookup|Check sender domain and IP reputation|

## ⚠️ Gotchas / Things That Tripped Me Up

- Lookalike domains rely on characters that look nearly identical in most fonts (`l`/`I`/`1`, `rn`/`m`, `0`/`O`) — reading the domain isn't enough; it's worth copying it out and comparing character-by-character against the real one when in doubt.
- Display name spoofing and domain spoofing are separate techniques that often get combined — a display name of "PayPal Support" can sit in front of literally any sending address, so the display name alone proves nothing.

## 📌 Key Takeaways (Deep Concepts)

- Phishing is one of the five platform categories introduced back in Challenge 03 Day 11's incident-type table — this challenge is where that category gets its own dedicated investigation workflow, the same way Challenge 04 gave SIEM analysis its own deep dive.
- Reputation and metadata checks (this day) come _before_ diving into headers and body content (Day 22) for a reason — cheap, fast checks first, deeper manual analysis once something's flagged as worth the time.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Phishing types range from generic email phishing to targeted spear phishing/whaling/BEC; techniques include lookalike domains, display name spoofing, and macro-based documents.
> - 8-step process: collect → headers → body → URLs → scan → decode → extract IOCs → respond/report.
> - Lookalike domain example: `secure-paypai.com` impersonating PayPal — checked via Whois/reputation lookup tools.

---

# Day 22: Phishing Analysis — Investigating a Phishing Email

> [!info]+ Objective Apply the full investigation process from Day 21 to a real-world phishing sample: review headers, validate the sender's identity, check domain/IP reputation, and extract IOCs from an end-to-end scenario.

## 🧩 Concepts You Need First

- **Email header fields worth knowing**:
    - **From** — the display sender, easily spoofed and not proof of anything on its own (as flagged in Day 21).
    - **Return-Path** — the actual envelope-sender address bounces go to; often reveals real sending infrastructure even when "From" is spoofed.
    - **SPF (Sender Policy Framework)** — checks whether the sending server is authorized to send mail for that domain; result is Pass / Fail / Neutral / SoftFail.
    - **DKIM/DMARC** — additional authentication layers verifying message integrity and enforcing what happens on SPF/DKIM failure.
- **The scenario** — an email claiming to be from BANCO DO BRADESCO LIVELO, warning that 92,990 loyalty points are expiring today, sent from `banco.bradesco@atendimento.com.br` — a classic urgency-driven phishing hook (Day 21's "tone, branding, urgency" body-analysis step in action).

## 🛠️ Step-by-Step

### Step 1: Identify the sender's full address and sending domain

> [!note] What to check Compare the **From** address against the **Return-Path** header — a mismatch between the two (a legitimate-looking From over a completely unrelated Return-Path domain) is one of the clearest spoofing signals available.

### Step 2: Extract the sender's IP address from the header

> [!note] Where to look The originating IP is typically found in the earliest (bottom-most, if reading top-to-bottom chronologically in most clients) `Received:` header line — the header trace shows every hop the message passed through.

### Step 3: Check the sender IP's reputation

```
AbuseIPDB or VirusTotal — look up the extracted sender IP
```

> [!note] What this does Confirms whether the IP has a history of abuse reports (spam, phishing, malware distribution) — answers the Yes/No blacklist question directly.

### Step 4: Check SPF authentication result

> [!note] Where to find it Usually surfaced directly in the `Authentication-Results` header line, or via a dedicated header analyzer (MX Toolbox). A Fail here means the sending server wasn't authorized to send as that domain — strong corroborating evidence alongside the Return-Path mismatch.

### Step 5: Find a suspicious URL in the email body

> [!note] What to do Hover (don't click) over any call-to-action link in the body — comparing the displayed text against the actual destination URL is Day 21's "hover over URLs" step applied directly.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Email header (`Received`, `Return-Path`, `Authentication-Results`)|Where sender IP, real sending domain, and SPF result all live|

## ⌨️ Tool Cheat-Sheet

|Tool|Purpose|
|---|---|
|MX Toolbox Email Header Analyzer|Parses raw headers into a readable format|
|EML Analyzer|Alternative `.eml` parsing/analysis tool|
|AbuseIPDB / VirusTotal / Cisco Talos|IP reputation and blacklist checks|
|whois.domaintools.com|Domain registration lookup|
|urlscan.io|Scans and screenshots a URL's actual landing page|

## ⚠️ Gotchas / Things That Tripped Me Up

- The From address alone answered none of the six investigation questions on its own — every question required pulling a _different_ field or running a _different_ tool, which is the actual point: phishing verdicts come from triangulating several independent signals, not one.
- SPF, DKIM, and DMARC check different things and can disagree — SPF passing doesn't mean DKIM does, and neither passing guarantees the message is legitimate if the domain itself is a lookalike rather than the real brand's domain.

## 📌 Key Takeaways (Deep Concepts)

- This day is Day 21's framework applied end-to-end against one real sample — the shift from "here's the process" to "here's the process producing an actual verdict," which is the same progression Challenge 01 Day 5 → Challenge 04 Day 18 made for SSH brute-force detection.
- Urgency ("points expiring today") is a deliberate design choice in phishing content, not incidental — it's meant to short-circuit the kind of careful header/domain checking this lab just walked through.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Compare From vs. Return-Path for a spoofing mismatch; extract sender IP from `Received` headers.
> - Check IP reputation (AbuseIPDB/VirusTotal) and SPF result (Pass/Fail/Neutral) via header analysis.
> - Hover over body URLs to compare displayed text against actual destination.
> - Six investigation questions, six different fields/tools — phishing verdicts come from triangulating signals, not one check.

---

# Day 23: Threat Intelligence Basics

> [!info]+ Objective Take IOCs surfaced from a suspicious email and use threat intelligence tools to investigate their context and maliciousness — extending Day 21–22's phishing investigation into broader indicator enrichment.

## 🧩 Concepts You Need First

- **Threat Intelligence (TI)** — information about threats, threat actors, and their tactics, used to investigate alerts faster and make more informed response decisions.
- **Three tiers of TI**:

|Tier|Description|
|---|---|
|Tactical|IOCs — IPs, hashes, domains|
|Operational|Campaign and malware-family information|
|Strategic|Big-picture trends, threat groups, geopolitical context|

- **The scenario** — while triaging a phishing alert, three indicators surfaced: an IP address, a domain, and a file hash (SHA256) — exactly the kind of tactical IOC set Day 21–22's header/body analysis would produce.

## 🛠️ Step-by-Step

### Step 1: Look up the file hash

```
VirusTotal — search the SHA256 hash
```

> [!note] What this does VirusTotal aggregates detections from dozens of AV engines plus community analysis, often identifying the file type and any known associated malware family from the hash alone — no need to have the file itself.

### Step 2: Look up the IP's registration/geolocation

```
AbuseIPDB or VirusTotal — search the IP address
```

> [!note] What this does Surfaces the country the IP is registered in along with any abuse history — geolocation alone isn't proof of malicious intent, but it's useful context alongside the hash and domain findings.

### Step 3: Check the domain

```
VirusTotal, URLScan.io, or AlienVault OTX / ThreatFox — search the domain
```

> [!note] What this does Cross-referencing the domain across multiple TI sources (not just one) increases confidence — ThreatFox and AlienVault OTX in particular often tag indicators with the specific campaign or malware family they've been observed in.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`sample-1.eml`|Sample phishing email the scenario's IOCs were drawn from|

## ⌨️ Tool Cheat-Sheet

|Tool|Purpose|
|---|---|
|VirusTotal|Hash, domain, and IP lookups against aggregated AV/community data|
|AbuseIPDB|IP abuse history and reputation|
|URLScan.io|Live scan/screenshot of a URL's actual destination|
|AlienVault OTX|Community threat intelligence feed with campaign tagging|
|ThreatFox (abuse.ch)|IOC feed tagged by malware family|
|MXToolbox Header Analyzer|Header parsing (carried over from Day 22)|

## ⚠️ Gotchas / Things That Tripped Me Up

- The lab's own scenario IOCs (`18.188.148.80`, `aaronthompson.ug`, and a SHA256 hash) don't match the IOCs listed in its Submission checklist (`185.220.101.19`, `secure-login-verification.com`, and a different MD5-length hash) — worth reconciling against your actual lab source before submitting, since it's not clear from the raw material which set is authoritative.
- A single "malicious" verdict from one AV engine on VirusTotal isn't the same as consensus — check the overall detection ratio, not just whether any single engine flagged it.

## 📌 Key Takeaways (Deep Concepts)

- This day operationalizes the "extract indicators" step from Day 21's 8-step process — Days 21–22 taught you _how to find_ IOCs in a phishing email; Day 23 teaches what to _do_ with them once found.
- The tactical tier (IPs, hashes, domains) is what nearly all of this challenge lives in so far — but knowing the operational and strategic tiers exist is what lets an analyst eventually ask "is this part of a known campaign?" instead of just "is this one indicator bad?"

## ✅ Summary (10-second recall)

> [!summary]
> 
> - TI = threat/actor/tactic context; three tiers: tactical (IOCs), operational (campaigns/malware families), strategic (big-picture trends).
> - Enriched a phishing-derived IP, domain, and file hash using VirusTotal, AbuseIPDB, URLScan.io, AlienVault OTX, and ThreatFox.
> - This is Day 21's "extract indicators" step, extended into "now investigate what those indicators actually are."

---

# Day 24: Introduction to Malware Analysis

> [!info]+ Objective Learn the basics of static malware analysis — identifying malicious files and extracting hashes, strings, and behavioral indicators using free tools, without executing the file.

## 🧩 Concepts You Need First

- **Malware analysis** — examining malicious software to understand its origin, behavior, impact, and indicators, so a SOC analyst can detect infections, contain threats, and prevent future compromise.
- **Four types of analysis**:

|Type|Description|
|---|---|
|Static Analysis|Examining a file without executing it|
|Dynamic Analysis|Observing behavior during execution (sandboxing)|
|Memory Analysis|Investigating malware artifacts in memory|
|Reverse Engineering|Deconstructing the code (advanced)|

- **Key static-analysis activities** — checking the file hash (identity + threat-intel lookup, directly reusing Day 23's skill), checking AV detections, inspecting metadata, checking entropy for packing/encryption, extracting readable strings, detecting obfuscation, scanning for embedded domains/URLs, and analyzing imported functions.

## 🛠️ Step-by-Step

### Step 1: Get a safe test file

```
EICAR test file — a standardized, harmless string that legitimate AV engines are designed to flag
```

> [!note] What this does EICAR isn't real malware — it's an industry-standard test string every AV vendor recognizes, letting you safely practice the detection workflow without handling an actual malicious binary.

### Step 2: Scan the file hash and content on VirusTotal

> [!note] What this does Same lookup skill from Day 23, now applied to a file you have in hand — check the detection ratio and any associated tags or names.

### Step 3: Run it through a sandbox (optional)

```
Hybrid Analysis or Any.Run
```

> [!note] What this does Sandboxing detonates the file in an isolated environment and records what it actually does — network calls, file writes, registry changes — the dynamic-analysis complement to everything else in this lab, which stays static.

### Step 4: Decode any obfuscated content

```
CyberChef — base64 decode
```

> [!note] What this does Many malicious files or scripts hide payloads or C2 addresses behind base64 or hex encoding; CyberChef's recipe-based interface makes decoding these a drag-and-drop operation rather than manual scripting.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|EICAR test file|Safe standardized file used for this lab's hands-on practice|

## ⌨️ Tool Cheat-Sheet

|Activity|Tools|
|---|---|
|Hash check (MD5/SHA256)|VirusTotal, HashCalc, HashMyFiles, PowerShell `Get-FileHash`|
|AV detection check|VirusTotal, MetaDefender, Hybrid Analysis|
|Metadata inspection|ExifTool, PEStudio, Detect It Easy, `file`|
|Entropy / packing check|Detect It Easy, PEStudio, binwalk|
|String extraction|`strings`, FLOSS, BinText|
|Embedded URL/domain scan|VirusTotal, CyberChef, URLScan.io|
|Import/function analysis|PEStudio, CFF Explorer, IDA Free, Ghidra|

## ⚠️ Gotchas / Things That Tripped Me Up

- EICAR being "detected as malicious" is the intended, correct outcome — it validates that your AV/sandbox pipeline works, not that you've found a real threat. Don't let a positive EICAR detection train the instinct that every detection means genuine danger; it means the tooling is functioning.
- Static analysis alone can miss malware that only reveals its true behavior at runtime (e.g. logic bombs, environment checks) — that's precisely why dynamic analysis (sandboxing) exists as a separate discipline, not a redundant one.

## 📌 Key Takeaways (Deep Concepts)

- This day directly extends Day 23's hash-lookup skill: Day 23 handed you a hash and asked what VirusTotal says about it; Day 24 teaches where that hash and the accompanying strings/metadata actually come from and how to generate them yourself from a file in hand.
- The Static → Dynamic → Memory → Reverse Engineering progression mirrors this whole challenge's own structure: cheap, safe checks first (hash/strings), then progressively deeper and more resource-intensive investigation as needed — the same "start broad, narrow in" instinct as Challenge 04's conn-log-to-protocol-log pivot.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Static analysis = examine without executing: hash, AV detections, metadata, entropy/packing, strings, embedded URLs, imports.
> - Practiced safely with the EICAR test file — a standardized benign string, not real malware.
> - VirusTotal (hash/AV check), sandbox (Hybrid Analysis/Any.Run, dynamic), CyberChef (decode obfuscation).
> - Builds directly on Day 23's hash-lookup skill — now generating the hash/strings yourself instead of being handed one.

---

# Day 25: Introduction to Digital Forensics

> [!info]+ Objective Learn the digital forensics process and acquire a Linux memory dump using AVML — capturing live memory from a target machine and transferring it to an analysis machine for further investigation.

## 🧩 Concepts You Need First

- **Digital Forensics** — the science of identifying, preserving, analyzing, and presenting digital evidence in a legally acceptable manner, used in cybercrime investigations, incident response, insider threat detection, and legal proceedings.
- **Forensics disciplines by domain**:

|Type|Description|Common Tools|
|---|---|---|
|Linux Forensics|Linux systems, logs, memory, file integrity|`log2timeline`, `auditd`, `grep`, `KAPE`, `AVML`|
|Windows Forensics|Registry, Event Logs, prefetch, file metadata|`FTK Imager`, `Registry Explorer`, `KAPE`, `PECmd`|
|Mobile Forensics|Deleted data, call logs, chats, app artifacts|`Cellebrite`, `Magnet AXIOM`, `MobSF`|
|Network Forensics|Packets, logs, intrusion traces|`Wireshark`, `tcpdump`, `Zeek`, `Suricata`|
|Memory Forensics|Live RAM acquisition and volatile artifact analysis|`Volatility`, `Rekall`, `LiME`, `AVML`|
|Cloud Forensics|Cloud logs, APIs, storage for abnormal activity|`AWS CloudTrail`, `GCP Logs`, `AZ Sentinel`|
|IoT Forensics|Embedded devices and sensor data|`Autopsy`, `Binwalk`, `Scalpel`|

- **The 5-step forensics process** — Identification (spot potential evidence sources) → Preservation (isolate/protect from tampering or loss) → Collection (acquire volatile and non-volatile data) → Analysis (uncover indicators/artifacts) → Reporting (document findings with timelines and evidence).
- **This lab focuses on Collection specifically**, and specifically _volatile_ data — memory — which is lost the moment a system reboots or shuts down, making it the most time-sensitive evidence to capture first.

## 🛠️ Step-by-Step

### Step 1: Download AVML on the target machine

```bash
wget https://github.com/microsoft/avml/releases/latest/download/avml
```

> [!note] What this does AVML ("Acquire Volatile Memory for Linux") is Microsoft's open-source memory acquisition tool — downloading the release binary directly avoids needing to compile anything on the target system, which matters when you want to touch the system as little as possible during evidence collection.

### Step 2: Make it executable and verify

```bash
chmod +x ./avml
./avml --help
```

### Step 3: Acquire the memory dump

```bash
sudo ./avml linux_memory.mem
ls -lh linux_memory.mem
```

> [!note] What this does Captures the full contents of live RAM into a single file — everything currently running, including processes, network connections, and artifacts an attacker might have deliberately kept off disk specifically to avoid leaving a trace.

### Step 4: Validate the dump

```bash
strings linux_memory.mem | grep "mozilla"
```

> [!note] What this does A quick sanity check — if recognizable application strings show up, the capture actually contains real memory content rather than being empty or corrupted.

### Step 5: Transfer to the analysis machine

```bash
mkdir ~/forensics/memory_dumps
scp user@<Target-Machine-IP>:/home/user/linux_memory.mem ~/forensics/memory_dumps/
ls -lh ~/forensics/memory_dumps/
```

> [!note] What this does Moves the evidence off the (potentially still-compromised) target system and onto a dedicated analysis machine — keeping the original acquisition intact for chain-of-custody purposes while analysis happens elsewhere.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`linux_memory.mem`|The acquired memory dump on the target machine|
|`~/forensics/memory_dumps/`|Destination directory on the analysis machine|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`wget <avml-release-url>`|Download the AVML binary|
|`chmod +x ./avml`|Make it executable|
|`sudo ./avml linux_memory.mem`|Acquire a full memory dump|
|`strings linux_memory.mem \| grep "mozilla"`|Sanity-check the dump contains real content|
|`scp user@<IP>:<path> ~/forensics/memory_dumps/`|Transfer the dump to the analysis machine|

## ⚠️ Gotchas / Things That Tripped Me Up

- Microsoft's tool is named **AVML** (Acquire Volatile Memory for Linux) — worth double-checking your own notes don't carry over a "KVML" typo, since that's not the actual tool name.
- Memory dumps are large (matching the system's RAM size) — confirm available disk space on both the target and analysis machine, and expect the `scp` transfer to take real time over anything but a fast local network.
- Order of volatility matters: memory should be captured _before_ powering down or deeply investigating disk, since RAM contents are gone the instant the system loses power — this is why memory acquisition is typically one of the very first Collection-phase actions, not something done after other investigation steps.

## 📌 Key Takeaways (Deep Concepts)

- This closes the technical arc of the 30-day challenge so far: Challenge 01 taught reading logs, Challenge 02 taught reading packets, Challenge 03 taught responding to an incident once found, Challenge 04 taught searching logs at SIEM scale, and Challenge 05 taught investigating email, indicators, files, and now volatile memory — each challenge adding the next layer of what a real incident actually requires.
- The 5-step forensics process (Identification → Preservation → Collection → Analysis → Reporting) parallels the NIST IR lifecycle from Challenge 03 Day 11 closely but isn't identical — forensics is specifically about evidence integrity and legal defensibility, which is why "Preservation" (protecting evidence from tampering) gets its own dedicated step where NIST's IR model folds that concern into Containment.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Digital forensics = identify → preserve → collect → analyze → report, with strict attention to evidence integrity and chain of custody.
> - This lab = Collection of volatile evidence: memory is captured first because it's lost on reboot/shutdown (order of volatility).
> - AVML acquires the dump (`sudo ./avml linux_memory.mem`), `strings | grep` validates it, `scp` transfers it to an analysis machine.
> - Closes the challenge's technical arc: logs → packets → IR → SIEM → phishing/TI/malware → forensics.

