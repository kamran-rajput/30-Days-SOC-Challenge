## tags: [soc, siem, splunk, challenge-04]

challenge: 4 days: 16-20

# 📘 Challenge 04 — Overview

Focus of this block: **SIEM operations with Splunk** — standing up the platform, then using SPL (Search Processing Language) to do at scale what earlier challenges did with grep, awk, and Wireshark filters: find the top talkers, the failures, and the outliers in a sea of log data.

**Days in this file:**

- [[#Day 16 Install and Configure Splunk|Day 16 — Install and Configure Splunk]]
- [[#Day 17 Splunk Basics — DNS Log Analysis|Day 17 — DNS Log Analysis]]
- [[#Day 18 Splunk Basics — SSH Log Analysis|Day 18 — SSH Log Analysis]]
- [[#Day 19 Splunk Basics — HTTP Log Analysis|Day 19 — HTTP Log Analysis]]
- [[#Day 20 Splunk Basics — Zeek Connection Log Analysis|Day 20 — Zeek Connection Log Analysis]]

---

# Day 16: Install and Configure Splunk

> [!info]+ Objective Install Splunk Enterprise on Ubuntu, configure it as an auto-starting service, and confirm access to the web interface — the platform every other day in this challenge builds on.

## 🧩 Concepts You Need First

- **Splunk** — a SIEM (Security Information and Event Management) platform: it ingests logs from many sources, indexes them, and lets you search across all of them with a single query language (SPL). This is the tool version of what "monitor logs and alerts via SIEM" (mentioned back in Challenge 03 Day 11's SOC analyst responsibilities) actually looks like in practice.
- **Index** — Splunk's term for a searchable data store. Different log sources typically land in different indexes (you'll see `dns_lab`, `ssh_lab`, `http_lab`, `conn_lab` created across this challenge) so searches can be scoped to just the relevant data set.
- **Free/local Enterprise version** — sufficient for a single-host lab setup like this; production deployments typically add forwarders (lightweight agents shipping logs from remote hosts) and distributed indexing, neither of which this lab needs.

## 🛠️ Step-by-Step

### Step 1: Download and install Splunk

```bash
wget -O splunk-9.3.0-51ccf43db5bd-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.3.0/linux/splunk-9.3.0-51ccf43db5bd-linux-2.6-amd64.deb"
sudo dpkg -i splunk-9.3.0-51ccf43db5bd-linux-2.6-amd64.deb
```

> [!note] What this does Pulls the official `.deb` package directly from Splunk and installs it via `dpkg`, the standard Debian/Ubuntu package manager.

### Step 2: Enable Splunk as a boot-start service

```bash
cd /opt/splunk/bin
sudo ./splunk enable boot-start --accept-license
sudo ./splunk start
```

> [!note] What this does `enable boot-start` registers Splunk to launch automatically on system boot, and `--accept-license` accepts the EULA non-interactively. `splunk start` brings it up immediately and prompts you to set the admin username and password on first run.

### Step 3: Access the web interface

```
http://<your-server-ip>:8000
```

> [!note] What this does Splunk Web listens on port 8000 by default. Logging in here with the admin credentials set in Step 2 gives you the dashboard used for every remaining day of this challenge — data uploads, SPL searches, and results all happen through this interface.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`/opt/splunk/bin`|Splunk's installation directory — where the `splunk` control binary lives|
|`http://<server-ip>:8000`|Splunk Web interface|

## ⌨️ Command Cheat-Sheet

|Command|What it does|
|---|---|
|`wget -O <file> "<url>"`|Download the Splunk `.deb` installer|
|`sudo dpkg -i <file>.deb`|Install the downloaded package|
|`sudo ./splunk enable boot-start --accept-license`|Register Splunk to auto-start on boot, accept EULA|
|`sudo ./splunk start`|Start the Splunk service|

## ⚠️ Gotchas / Things That Tripped Me Up

- Port 8000 needs to actually be reachable — on a cloud VM or VirtualBox setup this often means a firewall rule or NAT port-forward in addition to Splunk itself running correctly.
- The free local install is meant for learning and small-scale use; production environments layer on forwarders and distributed indexing that aren't part of this single-host setup.

## 📌 Key Takeaways (Deep Concepts)

- Everything from Challenges 01–03 (auth.log greps, Event Viewer filters, Wireshark display filters) has been manual, single-source investigation. Splunk is the shift to centralized, queryable log analysis at scale — the same investigative questions, but askable across every log source at once.
- Getting the platform running correctly is itself a Preparation-phase IR task (Challenge 03's NIST lifecycle) — a SIEM that isn't ingesting the right data yet can't detect anything.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Splunk = SIEM platform; ingests logs into indexes, searched via SPL.
> - Install: `wget` the `.deb`, `dpkg -i` to install, `splunk enable boot-start --accept-license`, `splunk start`.
> - Access via `http://<server-ip>:8000` with the admin credentials set during setup.
> - This install is the foundation every remaining day in Challenge 04 builds on.

---

# Day 17: Splunk Basics — DNS Log Analysis

> [!info]+ Objective Ingest Zeek-formatted DNS logs into Splunk and write SPL queries to find the most-queried domains, the most active source hosts, and the breakdown of DNS query types.

## 🧩 Concepts You Need First

- **SPL (Search Processing Language)** — Splunk's query language. The core pattern used constantly across this challenge is `stats count by <field> | sort -count`: count occurrences grouped by a field, then sort descending — the SPL equivalent of the `awk ... | sort | uniq -c | sort -nr` pipeline from Challenge 01 Day 5, just expressed differently.
- **Zeek logs** — this lab's DNS data comes pre-formatted as JSON by Zeek (a network security monitor), meaning fields like `query`, `qtype`, and `id.orig_h` (the originating host) are already parsed out rather than needing to be extracted from raw text.
- **Index and sourcetype scoping** — every search here starts with `index=dns_lab sourcetype="json"` to make sure you're only searching this lab's data, not every log Splunk has ingested.

## 🛠️ Step-by-Step

### Step 1: Upload the DNS log

```
Splunk Web → Settings → Add Data → Upload → select dns.log
Source type: json (or custom "dns")
Index: main, or create dns_lab
```

> [!note] What this does Ingests the sample DNS log into a dedicated index (`dns_lab`) so subsequent searches can be scoped cleanly and won't mix results with other labs' data later in this challenge.

### Step 2: Find the most frequently queried domains

```spl
index=dns_lab sourcetype="json"
| stats count by query
| sort -count
```

> [!note] What this does Groups every DNS event by the queried domain name and counts occurrences, then sorts to put the most-queried domains first — the fastest way to spot both normal top talkers and anything unexpectedly popular.

### Step 3: Find the most active source hosts

```spl
index=dns_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
```

> [!note] What this does Same pattern, grouped by the originating host IP instead of the domain — surfaces which internal machine is generating the most DNS traffic, which matters for spotting a single compromised host doing something unusual.

### Step 4: Break down DNS query types

```spl
index=dns_lab sourcetype="json"
| stats count by qtype
```

> [!note] What this does Groups by record type (A, AAAA, CNAME, PTR, etc.) — a normal environment should show a fairly predictable mix; a spike in an unusual type (like TXT, often abused for DNS tunneling) is worth a second look.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`dns.log`|Sample Zeek DNS log uploaded for this lab|
|`dns_lab` (Splunk index)|Where the DNS data is indexed and searched from|

## ⌨️ Command Cheat-Sheet

|SPL Query|What it does|
|---|---|
|`stats count by query \| sort -count`|Rank domains by query frequency|
|`stats count by "id.orig_h" \| sort -count`|Rank source hosts by DNS activity|
|`stats count by qtype`|Break down traffic by DNS record type|

## ⚠️ Gotchas / Things That Tripped Me Up

- Zeek's nested field names (`id.orig_h`) need quoting in SPL when they contain a literal dot, or Splunk can misinterpret the syntax — worth double-checking query results actually populate rather than silently returning nothing.
- `sourcetype="json"` scopes to how the data was _parsed_, not what it semantically _is_ — if a custom sourcetype like `dns` was set during upload instead, the queries need to reference that instead of `json`.

## 📌 Key Takeaways (Deep Concepts)

- `stats count by X | sort -count` is the single most reusable SPL pattern in this entire challenge — nearly every "find the top N" task across Days 17–20 is a variation of it.
- This is functionally the same investigative question Challenge 02's Wireshark work asked (which hosts, which domains, how much traffic) — Splunk just answers it against indexed, structured log data instead of raw packets, at a scale a human couldn't filter through packet-by-packet.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - DNS log ingested into `dns_lab` index as JSON (Zeek format).
> - Core pattern: `stats count by <field> | sort -count` — reused constantly for "find the top N" questions.
> - Tasks: top queried domains (`by query`), top source hosts (`by "id.orig_h"`), query type breakdown (`by qtype`).

---

# Day 18: Splunk Basics — SSH Log Analysis

> [!info]+ Objective Ingest Zeek-style SSH logs into Splunk and use SPL to detect failed and successful authentication attempts and spot patterns suggesting brute force or unauthorized access.

## 🧩 Concepts You Need First

- **The scenario mirrors Challenge 01 Day 5** — that lab hunted SSH brute force by grepping "Failed password" out of `auth.log` directly on the host. This lab asks the identical question, but against structured, indexed Zeek SSH log data in Splunk instead.
- **Key fields**: `auth_success` (boolean — did the login succeed), `event_type` (categorizes each event, e.g. successful/failed/no-auth/multiple-failed), `id.orig_h` (source host of the connection attempt).

## 🛠️ Step-by-Step

### Step 1: Upload the SSH log

```
Splunk Web → Settings → Add Data → Upload → select synthetic_zeek_ssh.json
Source type: json (or custom "zeek:ssh")
Index: main, or create ssh_lab
```

### Step 2: Find the top sources of failed logins

```spl
index=ssh_lab sourcetype="json" auth_success=false
| stats count by "id.orig_h"
| sort -count
| head 10
```

> [!note] What this does Filters down to only failed authentication events, groups by source IP, sorts by volume, and keeps the top 10 — directly analogous to Challenge 01 Day 5's `grep "Failed password" | awk ... | sort | uniq -c | sort -nr`, just as a single SPL pipeline instead of a chain of Unix tools.

### Step 3: Count total SSH connections

```spl
index=ssh_lab sourcetype="json"
| stats count as total_ssh_connections
```

> [!note] What this does A simple aggregate count with no grouping — gives you a baseline volume figure to contextualize how significant the failed-login count from Step 2 actually is (10 failures out of 15 connections tells a very different story than 10 out of 10,000).

### Step 4: Break down event types

```spl
index=ssh_lab sourcetype="json"
| stats count by event_type
```

> [!note] What this does Groups every event by its labeled type (successful, failed, no-auth, multiple-failed) — a quick way to see the overall shape of SSH activity in the dataset before drilling into any one category.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`synthetic_zeek_ssh.json`|Sample Zeek-style SSH log uploaded for this lab|
|`ssh_lab` (Splunk index)|Where the SSH data is indexed and searched from|

## ⌨️ Command Cheat-Sheet

|SPL Query|What it does|
|---|---|
|`auth_success=false \| stats count by "id.orig_h" \| sort -count \| head 10`|Top 10 sources of failed logins|
|`stats count as total_ssh_connections`|Total connection count (baseline for context)|
|`stats count by event_type`|Breakdown of event categories|

## ⚠️ Gotchas / Things That Tripped Me Up

- `auth_success=false` depends on the field being a proper boolean in the parsed data — if the source data represents it as a string (`"false"`) instead, the filter needs to match that representation exactly or it silently returns nothing.
- A raw failed-login count means little without the total-connections baseline from Step 3 — always pull both before drawing conclusions about how significant a spike is.

## 📌 Key Takeaways (Deep Concepts)

- This day is a direct evolution of Challenge 01 Day 5: same detection goal (find brute-force sources), same underlying pattern (many failures, from one source, in volume), just expressed as SPL against indexed data instead of grep/awk against a flat text file. Recognizing that these are the same skill in different syntax is the actual lesson.
- `event_type` breakdowns like this are a fast way to sanity-check a dataset before doing deeper analysis — knowing the overall shape of the data (how many failed vs. succeeded vs. no-auth) shapes which follow-up questions are worth asking.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - SSH log ingested into `ssh_lab` index; key fields: `auth_success`, `event_type`, `id.orig_h`.
> - Top failed-login sources: `auth_success=false | stats count by "id.orig_h" | sort -count | head 10`.
> - Same brute-force detection goal as Challenge 01 Day 5's `auth.log` grep — now done via SPL at Splunk scale.
> - Always pull a total-connections baseline alongside failure counts to judge significance.

---

# Day 19: Splunk Basics — HTTP Log Analysis

> [!info]+ Objective Ingest Zeek-style HTTP logs into Splunk and use SPL to detect server errors, identify suspicious User-Agents associated with scripted attacks, and flag unusually large file transfers.

## 🧩 Concepts You Need First

- **The scenario connects back to Challenge 02 Day 9** — that lab read HTTP traffic live in Wireshark; this one analyzes it after the fact, at scale, from indexed logs. Same protocol, same kinds of findings (data exposure, suspicious activity), different vantage point.
- **Key fields**: `status_code` (HTTP response status), `user_agent` (client identification string — legitimate browsers vs. scripting/scanning tools), `resp_body_len` (response size in bytes, useful for spotting large transfers), `id.orig_h`/`id.resp_h` (source/destination hosts).

## 🛠️ Step-by-Step

### Step 1: Upload the HTTP log

```
Splunk Web → Settings → Add Data → Upload → select synthetic_zeek_http.json
Source type: json (or custom "zeek:http")
Index: main, or create http_lab
```

### Step 2: Find the top traffic-generating endpoints

```spl
index=http_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
| head 10
```

> [!note] What this does Same top-talker pattern from Days 17–18, applied here to HTTP source hosts — establishes a baseline of normal traffic volume per host before hunting for anomalies.

### Step 3: Count server errors (5xx)

```spl
index=http_lab sourcetype="json" status_code>=500 status_code<600
| stats count as server_errors
```

> [!note] What this does Filters to responses in the 500–599 range (server-side errors) and counts them — a spike here can indicate an application under attack or actively failing, both worth investigating.

### Step 4: Identify suspicious User-Agents

```spl
index=http_lab sourcetype="json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent
```

> [!note] What this does Filters for known scripting/scanning tool signatures (sqlmap is a SQL injection tool, curl/python-requests are common scripting libraries, "botnet-checker" is an explicit red flag) — real browsers don't identify themselves this way, so any hits here warrant direct follow-up.

### Step 5: Find large file transfers

```spl
index=http_lab sourcetype="json" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len
```

> [!note] What this does Filters to responses over ~500KB and lays out the timestamp, source/destination, requested URI, and size in a readable table — large, unexpected transfers are a classic data-exfiltration or malware-download signature.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`synthetic_zeek_http.json`|Sample Zeek-style HTTP log uploaded for this lab|
|`http_lab` (Splunk index)|Where the HTTP data is indexed and searched from|

## ⌨️ Command Cheat-Sheet

|SPL Query|What it does|
|---|---|
|`stats count by "id.orig_h" \| sort -count \| head 10`|Top 10 HTTP traffic sources|
|`status_code>=500 status_code<600 \| stats count as server_errors`|Count of 5xx server errors|
|`user_agent IN (...) \| stats count by user_agent`|Hits from known scripting/scanning tool signatures|
|`resp_body_len>500000 \| table ts ... \| sort -resp_body_len`|Large file transfers, largest first|

## ⚠️ Gotchas / Things That Tripped Me Up

- In SPL, two numeric conditions written side by side (`status_code>=500 status_code<600`) are implicitly ANDed — no explicit `AND` keyword needed, which reads ambiguously at first glance if you're coming from SQL-style syntax.
- The lab's own submission checklist lists a "Task 5" screenshot, but only four tasks are actually defined — worth double-checking the original lab source for a missing task before assuming it's a typo.
- A User-Agent filter is only as good as the list behind it — real attackers frequently spoof common browser User-Agent strings specifically to avoid a check like this one.

## 📌 Key Takeaways (Deep Concepts)

- This day is the log-analysis complement to Challenge 02 Day 9's live packet-capture HTTP analysis — same protocol, same categories of finding (data exposure, suspicious downloads, scripted access), different tool and vantage point (after-the-fact indexed search vs. live traffic inspection).
- Combining several signals (unusual User-Agent + large transfer + off-hours timestamp, for example) is far more reliable than any single filter alone — each of Tasks 2–4 here is a building block, not a standalone verdict.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - HTTP log ingested into `http_lab` index; key fields: `status_code`, `user_agent`, `resp_body_len`.
> - Server errors: `status_code>=500 status_code<600` (implicit AND — no keyword needed).
> - Suspicious tooling: `user_agent IN (...)` against known scripting/scanning signatures — but spoofable, so treat as one signal among several.
> - Large transfers: `resp_body_len>500000`, tabled and sorted — classic exfiltration/malware-download signature.

---

# Day 20: Splunk Basics — Zeek Connection Log Analysis

> [!info]+ Objective Upload Zeek connection ("conn") logs into Splunk and use SPL to find top clients, top servers, the most common services, and unusually long-duration connections.

## 🧩 Concepts You Need First

- **Zeek conn logs** — a summary record of every network connection (who talked to whom, over what service, for how long, how much data) rather than a full packet capture. This is a step back in granularity from Wireshark's full-packet view (Challenge 02) but a step up in scale — conn logs are practical to search across huge volumes of traffic in a way raw PCAP isn't.
- **Key fields**: `id.orig_h`/`id.resp_h` (client/server IPs), `service` (the identified application protocol, e.g. http, dns, ssh), `duration` (connection length in seconds).

## 🛠️ Step-by-Step

### Step 1: Upload the connection log

```
Splunk Web → Settings → Add Data → Upload → select zeek_conn_logs.json
Source type: json (or custom "zeek:conn")
Index: main, or create conn_lab
```

### Step 2: Find the top 10 client IPs

```spl
index=conn_lab sourcetype="json"
| stats count by id.orig_h
| sort -count
| head 10
```

> [!note] What this does The same top-talker pattern from every prior day this challenge, applied to raw connection counts — establishes which internal hosts are the most network-active overall, across every protocol at once rather than one log type at a time.

### Step 3: List the most common services

```spl
index=conn_lab sourcetype="json"
| stats count by service
| sort -count
```

> [!note] What this does Groups by identified application protocol — gives a quick read on the overall traffic mix (mostly HTTP? A surprising amount of an unexpected service?) across the whole environment in one query.

### Step 4: Find long-duration connections

```spl
index=conn_lab sourcetype="json" duration>1
| table ts id.orig_h id.resp_h service duration
| sort -duration
```

> [!note] What this does Filters to connections lasting more than 1 second and tables the key fields, longest first — unusually long-lived connections can indicate a persistent C2 channel or an interactive session where a short request/response was expected instead.

### Step 5: Identify the most-accessed internal servers

```spl
index=conn_lab sourcetype="json"
| stats count by "id.resp_h"
| sort -count
| head 10
```

> [!note] What this does Mirrors Step 2 but grouped by destination instead of source — surfaces which internal servers are receiving the most connections, useful for spotting an unexpected service being hammered or scanned.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`zeek_conn_logs.json`|Sample Zeek-style connection log uploaded for this lab|
|`conn_lab` (Splunk index)|Where the connection data is indexed and searched from|

## ⌨️ Command Cheat-Sheet

|SPL Query|What it does|
|---|---|
|`stats count by id.orig_h \| sort -count \| head 10`|Top 10 client IPs by connection count|
|`stats count by service \| sort -count`|Most common services/protocols|
|`duration>1 \| table ts id.orig_h id.resp_h service duration \| sort -duration`|Long-duration connections, longest first|
|`stats count by "id.resp_h" \| sort -count \| head 10`|Most-accessed internal servers|

## ⚠️ Gotchas / Things That Tripped Me Up

- Field name quoting is inconsistent across the raw lab tasks (`id.orig_h` unquoted in some queries, `"id.orig_h"` quoted in others) — worth testing both forms in your own environment and standardizing on whichever actually parses correctly rather than assuming they're interchangeable.
- Duration thresholds need context from the environment — "over 1 second" is a very low bar and will surface a lot of ordinary traffic; treat this task as a starting filter to narrow down from, not a finished verdict.

## 📌 Key Takeaways (Deep Concepts)

- Conn logs sit at a different altitude than everything else in this challenge: DNS/SSH/HTTP logs (Days 17–19) describe _what_ happened at the application layer, conn logs describe _that a connection happened at all_, across every protocol. In a real investigation, conn logs are often where you start (spot the anomaly) before pivoting into protocol-specific logs to understand _what_ was happening.
- This closes Challenge 04's arc: Day 16 built the platform, Days 17–19 analyzed protocol-specific logs individually, and Day 20's connection-level view is the summary layer that ties them together — the same relationship Challenge 01's Summary docs have to that challenge's daily notes, just applied to live network data instead of study notes.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Conn logs = per-connection summary records (who/what service/how long/how much data), one altitude above protocol-specific logs and one below full packet capture.
> - Top clients/servers: `stats count by id.orig_h` / `"id.resp_h"`, sorted and headed.
> - Most common services: `stats count by service`.
> - Long connections: `duration>1`, tabled and sorted — a starting filter, not a finished verdict.
> - Conn logs are typically where a real investigation starts before pivoting into DNS/SSH/HTTP-specific logs for detail.
