## tags: [soc, summary, challenge-04]

challenge: 4 days: 16-20

# 🧠 Challenge 04 — Quick Revision Summary

Everything from Days 16–20 in one scan. Read top to bottom in ~2 minutes.

## 🧩 Core Concepts (one-liners)

- **Splunk** = SIEM platform — ingests logs into **indexes**, searched via **SPL** (Search Processing Language). Centralized, queryable log analysis at scale, replacing the manual single-source digging of Challenges 01–03.
- **The one SPL pattern that does most of the work**: `stats count by <field> | sort -count` — group, count, rank. Nearly every "find the top N" task across this challenge is a variation of it, same job as `awk ... | sort | uniq -c | sort -nr` did in Challenge 01 Day 5, different syntax.
- **Zeek logs** — pre-parsed JSON network data (DNS, SSH, HTTP, conn) with fields already broken out (`query`, `auth_success`, `status_code`, `duration`, etc.) instead of raw text needing extraction.
- **Index scoping matters** — every search starts with `index=<lab> sourcetype="json"` so results stay scoped to the right dataset; each log type got its own index (`dns_lab`, `ssh_lab`, `http_lab`, `conn_lab`).
- **SSH brute-force hunting in Splunk (Day 18)** = the same detection goal as Challenge 01 Day 5's `auth.log` grep, now done via `auth_success=false | stats count by "id.orig_h"` instead of shell tools.
- **HTTP analysis in Splunk (Day 19)** = the log-side complement to Challenge 02 Day 9's live Wireshark capture — same categories of finding (data exposure, suspicious activity, large transfers), different vantage point.
- **Conn logs sit above protocol-specific logs** — DNS/SSH/HTTP logs describe _what_ happened at the application layer; conn logs describe _that a connection happened at all_, across every protocol. Real investigations often start at the conn-log altitude before pivoting into protocol detail.
- **No single filter is a verdict** — a suspicious User-Agent, a large transfer, or a long connection are each one signal; User-Agent strings especially are trivially spoofable, so combining signals beats trusting any one alone.

## 📁 Directories & Indexes

|Path / Index|Purpose|
|---|---|
|`/opt/splunk/bin`|Splunk installation directory — control binary lives here|
|`http://<server-ip>:8000`|Splunk Web interface|
|`dns_lab`|Index for Zeek DNS log data (Day 17)|
|`ssh_lab`|Index for Zeek SSH log data (Day 18)|
|`http_lab`|Index for Zeek HTTP log data (Day 19)|
|`conn_lab`|Index for Zeek connection log data (Day 20)|

## 🔍 SPL Cheat-Sheet by Log Type

**Splunk setup (Day 16)**

```bash
wget -O <file> "<splunk-download-url>"
sudo dpkg -i <file>.deb
cd /opt/splunk/bin
sudo ./splunk enable boot-start --accept-license
sudo ./splunk start
```

**DNS (Day 17)**

```spl
index=dns_lab sourcetype="json" | stats count by query | sort -count
index=dns_lab sourcetype="json" | stats count by "id.orig_h" | sort -count
index=dns_lab sourcetype="json" | stats count by qtype
```

**SSH (Day 18)**

```spl
index=ssh_lab sourcetype="json" auth_success=false | stats count by "id.orig_h" | sort -count | head 10
index=ssh_lab sourcetype="json" | stats count as total_ssh_connections
index=ssh_lab sourcetype="json" | stats count by event_type
```

**HTTP (Day 19)**

```spl
index=http_lab sourcetype="json" | stats count by "id.orig_h" | sort -count | head 10
index=http_lab sourcetype="json" status_code>=500 status_code<600 | stats count as server_errors
index=http_lab sourcetype="json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0") | stats count by user_agent
index=http_lab sourcetype="json" resp_body_len>500000 | table ts "id.orig_h" "id.resp_h" uri resp_body_len | sort -resp_body_len
```

**Zeek Connection Logs (Day 20)**

```spl
index=conn_lab sourcetype="json" | stats count by id.orig_h | sort -count | head 10
index=conn_lab sourcetype="json" | stats count by service | sort -count
index=conn_lab sourcetype="json" duration>1 | table ts id.orig_h id.resp_h service duration | sort -duration
index=conn_lab sourcetype="json" | stats count by "id.resp_h" | sort -count | head 10
```

## 🚩 Red Flags Learned This Week

- [ ] A domain or query type appearing far more often than expected — possible tunneling or beaconing (e.g. unusual TXT record volume)
- [ ] One source IP responsible for a disproportionate share of failed SSH logins
- [ ] A spike in HTTP 5xx server errors — app under attack or actively failing
- [ ] Requests carrying known scripting/scanning User-Agents (sqlmap, curl, python-requests, or explicit tool names) — but verify further, since these are spoofable
- [ ] HTTP responses over ~500KB to/from unexpected hosts — possible exfiltration or malware download
- [ ] Connections with unusually long duration for the service involved — possible persistent C2 channel

## ✅ 10-Second Recall

> [!summary]
> 
> - Day 16: Installed Splunk on Ubuntu (`dpkg -i`, `boot-start --accept-license`, `splunk start`); accessed via port 8000.
> - Day 17: DNS logs → `dns_lab`. Core pattern: `stats count by <field> | sort -count` for top domains, top hosts, query-type breakdown.
> - Day 18: SSH logs → `ssh_lab`. `auth_success=false` isolates failed logins — same brute-force hunt as Challenge 01 Day 5, now in SPL.
> - Day 19: HTTP logs → `http_lab`. 5xx errors, suspicious User-Agents, and large `resp_body_len` transfers — the log-side twin of Challenge 02's Wireshark HTTP work.
> - Day 20: Conn logs → `conn_lab`. Top clients/servers, common services, long-duration connections — the summary altitude above DNS/SSH/HTTP, usually where a real investigation starts.