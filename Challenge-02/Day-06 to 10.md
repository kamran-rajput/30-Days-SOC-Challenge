## tags: [soc, packet-analysis, challenge-02]

challenge: 2 days: 6-10

# 📘 Challenge 02 — Overview

Focus of this block: **network packet analysis with Wireshark** — reading raw traffic, understanding the protocols that make up a connection, and building the filter vocabulary a SOC analyst uses daily to separate normal traffic from suspicious activity.

**Days in this file:**

- [[#Day 6 Introduction to Wireshark — Packet Analysis for SOC Analysts|Day 6 — Introduction to Wireshark]]
- [[#Day 7 Wireshark Basics — ICMP Protocol Analysis|Day 7 — ICMP Protocol Analysis]]
- [[#Day 8 Wireshark Basics — TCP Protocol Analysis|Day 8 — TCP Protocol Analysis]]

---

# Day 6: Introduction to Wireshark — Packet Analysis for SOC Analysts

> [!info]+ Objective Get comfortable in the Wireshark interface, set up an analyst-specific profile, capture live traffic, and write both capture and display filters — the foundation every later packet-analysis day builds on.

## 🧩 Concepts You Need First

- **Wireshark** — an open-source network protocol analyzer. It captures packets off a live interface or reads them from a saved **PCAP** file, then lets you inspect each one down to the individual header field.
- **PCAP file** — a saved recording of network traffic. Analysts use these constantly: an incident doesn't wait for you to have Wireshark open, so most real investigation happens on a PCAP captured earlier (by a firewall, a SPAN port, or an EDR sensor) rather than live.
- **Capture filter vs. Display filter** — the distinction that trips up almost everyone starting out:
    - A **capture filter** is applied _before_ packets are written to disk — it uses Berkeley Packet Filter (BPF) syntax and permanently discards anything that doesn't match.
    - A **display filter** is applied _after_ capture, purely to change what you _see_ — nothing is discarded, so you can loosen or change it without re-capturing.
- **Wireshark profile** — a saved set of preferences (columns, colorization rules, filter bookmarks). Analysts keep separate profiles per use case so a "SOC Analyst" profile can surface security-relevant columns (like the ICMP type or TCP flags) that the default profile hides.

## 🛠️ Step-by-Step

### Step 1: Install Wireshark and get a sample capture

```
Download: https://www.wireshark.org/download.html
Sample PCAP: Protocol_Analysis_pcap.pcapng
```

> [!note] What this does Installing the latest stable release ensures you get current protocol dissectors. Working from a pre-made PCAP means you're practicing analysis, not just waiting around for live traffic to happen.

### Step 2: Create a dedicated analyst profile

```
Edit → Configuration Profiles → + → name it "SOC Analyst"
```

> [!note] Why this matters A dedicated profile keeps your security-focused view (custom columns, color rules for suspicious traffic) separate from Wireshark's general-purpose default — and it's portable if you ever export/share your setup.

### Step 3: Write a display filter for ICMP

```
icmp
```

> [!note] What this does Typing this into the **Display Filter** bar (top of the window, not the capture options screen) narrows the already-captured packet list down to ICMP only — everything else is still there, just hidden.

### Step 4: Write a capture filter for ICMP

```
icmp
```

> [!note] What this does Same keyword, different box — entered in **Capture → Options → Capture Filter** instead. This time Wireshark only writes ICMP packets to the capture in the first place; non-ICMP traffic is never recorded.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`Protocol_Analysis_pcap.pcapng`|Sample capture used for this challenge's labs|
|Wireshark → Edit → Configuration Profiles|Where analyst-specific profiles are created and switched|

## ⌨️ Command Cheat-Sheet

|Filter|Type|What it does|
|---|---|---|
|`icmp`|Display|Show only ICMP packets already captured|
|`icmp`|Capture|Only capture ICMP packets going forward|

## ⚠️ Gotchas / Things That Tripped Me Up

- Capture filters and display filters use **different syntax dialects** (BPF vs. Wireshark's own) — `icmp` happens to work in both, but many filters (like `tcp.flags.syn == 1`) are display-only and will error out if pasted into the capture filter box.
- A capture filter is a one-way door: traffic it excludes is gone for good. When in doubt during a real investigation, capture broadly and filter the _display_ instead — you can't un-discard packets.

## 📌 Key Takeaways (Deep Concepts)

- SOC use cases for Wireshark, in order of how often they come up: **incident investigation** (spotting C2 traffic, lateral movement), **malware analysis** (pulling IOCs — domains, IPs, payloads — out of suspicious sessions), **threat hunting** (catching beaconing, DNS tunneling, unauthorized FTP/SSH), and **protocol troubleshooting** (service failures, misconfig, latency).
- Building the habit of a dedicated profile now pays off later — as the filter vocabulary grows (Days 7–8 and beyond), a profile with saved filter buttons turns a 30-second filter-typing task into a one-click one.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - Wireshark = open-source packet analyzer; works on live traffic or saved PCAP files.
> - Capture filter (BPF, applied before saving) ≠ Display filter (Wireshark syntax, applied after — nothing lost).
> - Created a "SOC Analyst" Wireshark profile; wrote `icmp` as both a display and a capture filter.
> - Core SOC use cases: incident investigation, malware analysis, threat hunting, protocol troubleshooting.

---

# Day 7: Wireshark Basics — ICMP Protocol Analysis

> [!info]+ Objective Understand ICMP's structure well enough to pick an Echo Request/Reply pair out of a capture on sight, and know which display filters isolate ICMP traffic by type.

## 🧩 Concepts You Need First

- **ICMP (Internet Control Message Protocol)** — a Layer 3 protocol used for error reporting and operational signaling between hosts, not for carrying application data. `ping` is the most familiar use of it.
- **Echo Request / Echo Reply** — the two ICMP message types behind `ping`: Type 8 (Request) goes out, Type 0 (Reply) comes back if the host is up and not filtering ICMP.
- **ICMP packet fields** — the header pieces worth recognizing on sight:

|Field Name|Description|
|---|---|
|Type|Defines the ICMP message type (8 = Echo Request, 0 = Echo Reply, etc.)|
|Code|Extra detail within a Type — e.g. Type 3 (Destination Unreachable) has codes for _why_ it's unreachable|
|Checksum|Error-checking for the header|
|Identifier|Ties a Reply back to its originating Request|
|Sequence No.|Orders multiple Request/Reply pairs in one ping session|
|Data|Optional payload, often just padding bytes|

## 🛠️ Step-by-Step

### Step 1: Open the sample capture

Load the same `Protocol_Analysis_pcap.pcapng` used in Day 6 (or generate your own by running `ping` against a live host while capturing).

### Step 2: Isolate ICMP traffic

```
icmp
```

> [!note] What this does Same display filter from Day 6 — this narrows the packet list to only ICMP, which is the starting point before drilling into specific types.

### Step 3: Find an Echo Request / Echo Reply pair

```
icmp.type == 8
icmp.type == 0
```

> [!note] What this does Filtering `icmp.type == 8` isolates outbound pings; `icmp.type == 0` isolates the replies. Matching Identifier and Sequence No. fields between a Request and its Reply confirms they belong to the same ping exchange.

### Step 4: Check for unreachable-host signals

```
icmp.code == 3
```

> [!note] Why this matters A spike of "Destination Unreachable" ICMP messages across many IPs in a short window is a classic host-discovery/ping-sweep signature — worth recognizing even though this challenge focuses on the basic Request/Reply pair.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`Protocol_Analysis_pcap.pcapng`|Sample capture containing ICMP Echo traffic to analyze|

## ⌨️ Command Cheat-Sheet

|Filter|Description|
|---|---|
|`icmp`|Show all ICMP traffic|
|`icmp.type == 8`|Show Echo Requests (ping)|
|`icmp.type == 0`|Show Echo Replies|
|`icmp.code == 3`|Destination unreachable|
|`ip.addr == 192.168.1.10`|ICMP traffic to/from a specific host|

## ⚠️ Gotchas / Things That Tripped Me Up

- ICMP has no concept of ports — `tcp.port`/`udp.port`-style filters don't apply here; matching Request to Reply relies on the **Identifier** and **Sequence No.** fields instead.
- A missing Echo Reply doesn't always mean the host is down — it can just as easily mean a firewall is dropping ICMP, so treat "no reply" as inconclusive, not proof.

## 📌 Key Takeaways (Deep Concepts)

- ICMP is a fundamental troubleshooting protocol, but from a detection standpoint it's also a recon signal: **ping sweeps** and **network scanning** both generate distinctive ICMP patterns (many Echo Requests to sequential IPs, or a burst of Destination Unreachable replies) worth flagging the same way a port-scan pattern was flagged in Challenge 01.
- Wireshark turns an abstract protocol spec into something you can actually point at — seeing the Type/Code/Identifier fields in a real packet locks in the concept far better than reading the RFC.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - ICMP = Layer 3 protocol for error/operational messages; `ping` uses Echo Request (Type 8) / Echo Reply (Type 0).
> - Key fields: Type, Code, Checksum, Identifier, Sequence No., Data.
> - Filters: `icmp`, `icmp.type == 8`, `icmp.type == 0`, `icmp.code == 3`, `ip.addr == <host>`.
> - Detection angle: ICMP patterns can reveal ping sweeps and network scanning, not just connectivity issues.

---

# Day 8: Wireshark Basics — TCP Protocol Analysis

> [!info]+ Objective Understand how TCP establishes a connection via the 3-way handshake, recognize the core TCP fields and flags, and use display filters to isolate handshake stages and host-specific traffic.

## 🧩 Concepts You Need First

- **TCP (Transmission Control Protocol)** — a Layer 4 (Transport) protocol that guarantees reliable, ordered, error-checked delivery between two applications, unlike best-effort protocols such as UDP.
- **3-way handshake** — how every TCP connection starts: **SYN** (client requests a connection) → **SYN-ACK** (server acknowledges and agrees) → **ACK** (client confirms). Only after this completes does actual data flow.
- **TCP fields and flags** — the pieces that matter for reading a session:

|Field Name|Description|
|---|---|
|Source Port|Sender's port number|
|Destination Port|Receiver's port number|
|Sequence Number|Byte-offset of the first byte in this segment|
|Acknowledgment No.|Confirms which bytes the other side has received|
|Flags|Control bits: SYN, ACK, FIN, RST, PSH, URG|
|Window Size|How much buffer space is available for incoming data|
|Checksum|Error-checking field|

## 🛠️ Step-by-Step

### Step 1: Show all TCP traffic

```
tcp
```

> [!note] What this does Baseline filter — narrows the capture to TCP only, same pattern as `icmp` in Day 7 but for the transport layer instead of ICMP.

### Step 2: Isolate the start of connections

```
tcp.flags.syn == 1
```

> [!note] What this does Shows SYN packets — the first leg of every handshake. In a healthy capture each SYN should be followed shortly by a SYN-ACK and then an ACK from the original sender.

### Step 3: Isolate the end of connections

```
tcp.flags.fin == 1
```

> [!note] What this does Shows FIN packets, which mark a graceful connection close (as opposed to RST, which signals an abrupt reset — worth noting even though this day's submission focuses on FIN).

### Step 4: Filter by port and by host

```
tcp.port == 80
ip.addr == 192.168.1.1
```

> [!note] What this does `tcp.port == 80` isolates HTTP-over-TCP traffic; `ip.addr == 192.168.1.1` isolates everything to/from one specific host regardless of port. Combining both (`tcp.port == 80 && ip.addr == 192.168.1.1`) narrows to one host's web traffic specifically.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|`Protocol_Analysis_pcap.pcapng`|Sample capture containing TCP sessions to analyze|

## ⌨️ Command Cheat-Sheet

|Filter|Description|
|---|---|
|`tcp`|Show all TCP packets|
|`tcp.flags.syn == 1`|Show SYN packets (start of connection)|
|`tcp.flags.fin == 1`|Show FIN packets (end of connection)|
|`tcp.port == 80`|Show TCP packets on port 80|
|`ip.addr == 192.168.1.1`|TCP traffic to/from a specific host|

## ⚠️ Gotchas / Things That Tripped Me Up

- A SYN with no matching SYN-ACK/ACK isn't automatically suspicious on its own — but a _large volume_ of unanswered SYNs to sequential ports on one host is the classic signature of a SYN scan (Nmap's `-sS`, from Challenge 01's Day 4), so the pattern-over-single-event rule from Challenge 01 carries straight over to TCP analysis.
- `tcp.port` matches either source _or_ destination port — if you need only one direction, use `tcp.srcport` or `tcp.dstport` instead, or the filter will pull in more traffic than expected.

## 📌 Key Takeaways (Deep Concepts)

- TCP flags are the backbone of **connection state tracking** — being able to read SYN/SYN-ACK/ACK vs. FIN vs. RST at a glance is what separates "a connection happened" from "I can tell you exactly how it started and ended."
- The same flag-level visibility is what surfaces abnormal behavior: RST floods, half-open connections from a SYN scan, or sessions that never complete a handshake are all detectable purely from flag patterns, without needing to inspect payload data at all.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - TCP = Layer 4 protocol; reliable/ordered delivery via the 3-way handshake (SYN → SYN-ACK → ACK).
> - Key fields: ports, Sequence/Ack numbers, Flags (SYN/ACK/FIN/RST/PSH/URG), Window Size, Checksum.
> - Filters: `tcp`, `tcp.flags.syn == 1`, `tcp.flags.fin == 1`, `tcp.port == 80`, `ip.addr == <host>`.
> - Detection angle: flag patterns (unanswered SYNs, RST floods) reveal scanning and abnormal connection behavior — same "pattern over single event" principle as Challenge 01.

---


# Day 9: Wireshark Basics — HTTP Protocol Analysis

> [!info]+ Objective Analyze HTTP request/response traffic in Wireshark, understand the headers that make up web communication, and learn to spot HTTP-based data exposure and C2 beaconing.

## 🧩 Concepts You Need First

- **HTTP (Hypertext Transfer Protocol)** — an application-layer protocol for client (browser) ↔ server communication, conventionally running over TCP port 80. Unlike TCP itself (Day 8), HTTP carries the actual application-level content: the pages, requests, and responses a user or attacker sees.
- **Request/Response model** — every HTTP exchange is a client request (method + URI + headers) answered by a server response (status code + headers + body). Reading both sides is what turns a packet capture into a readable "conversation."
- **HTTP fields worth recognizing on sight**:

|Field Name|Description|
|---|---|
|Request Method|GET, POST, HEAD, etc. — what the client is asking the server to do|
|Host|The website being accessed|
|User-Agent|Client/browser identification string|
|URI|Resource path being requested on the server|
|Status Code|Server's response status (e.g. 200 OK, 404 Not Found)|
|Content-Type|MIME type of the response body (e.g. text/html)|
|Cookie/Header|Session or tracking data attached to the request|

## 🛠️ Step-by-Step

### Step 1: Show all HTTP traffic

```
http
```

> [!note] What this does Baseline filter, same pattern as `icmp` and `tcp` from Days 7–8 — narrows the capture down to the application-layer HTTP conversations sitting on top of the TCP sessions you already know how to read.

### Step 2: Isolate by default port as a cross-check

```
tcp.port == 80
```

> [!note] Why this matters `http` filters by protocol dissection; `tcp.port == 80` filters by port number instead. They usually overlap, but they're not identical — HTTP explicitly run on a non-standard port won't match `tcp.port == 80`, and traffic merely _using_ port 80 without valid HTTP won't match `http`. Cross-checking both is a useful sanity habit.

### Step 3: Show all GET requests

```
http.request.method == "GET"
```

> [!note] What this does Isolates only the requests asking the server to retrieve a resource — the most common method and usually the first thing worth scanning in a capture full of web traffic.

### Step 4: View requested resources

```
http.request.uri
```

> [!note] What this does Surfaces the actual resource paths being requested — this is where sensitive data exposure often shows up directly in the URL (e.g. a token or session ID passed as a query parameter instead of a header).

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Sample PCAP file (Wireshark labs)|Capture containing HTTP request/response traffic to analyze|

## ⌨️ Command Cheat-Sheet

|Filter|Description|
|---|---|
|`http`|Show all HTTP traffic|
|`tcp.port == 80`|HTTP traffic by default port|
|`http.request.method == "GET"`|Show all GET requests|
|`http.request.uri`|View requested resources|
|`http.set_cookie`|Show cookies set in HTTP responses|
|`ip.addr == 192.168.1.10`|HTTP traffic to/from a specific host|

## ⚠️ Gotchas / Things That Tripped Me Up

- HTTP is **plaintext by design** — that's exactly what makes it easy to analyze here, but it's also why HTTP alone shouldn't carry anything sensitive; if you see credentials or tokens riding in cleartext HTTP, that's a finding worth flagging on its own.
- `http.request.uri` filters on presence, not content — pair it with `contains` (e.g. `http.request.uri contains "admin"`) when hunting for something specific rather than just listing every URI.

## 📌 Key Takeaways (Deep Concepts)

- Analyzing HTTP traffic surfaces three recurring SOC findings: **sensitive data exposure** in URLs or headers, **malware beaconing** to C2 servers (often visible as regular, repeated requests to the same host/URI), and **suspicious downloads** or unauthorized access attempts.
- HTTP sits directly on top of the TCP sessions from Day 8 — the 3-way handshake still happens first, then HTTP request/response pairs ride inside the established connection. Reading a capture well means moving fluidly between transport-layer (TCP) and application-layer (HTTP) views of the same traffic.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - HTTP = application-layer protocol for client/server web communication, typically over TCP port 80.
> - Key fields: Request Method, Host, User-Agent, URI, Status Code, Content-Type, Cookie/Header.
> - Filters: `http`, `tcp.port == 80`, `http.request.method == "GET"`, `http.request.uri`, `http.set_cookie`.
> - Detection angle: cleartext HTTP can expose sensitive data directly, and repeated requests to the same host/URI are a classic beaconing signature.

---

# Day 10: Wireshark Basics — TLS Protocol Analysis

> [!info]+ Objective Understand how TLS secures HTTP and other traffic, recognize the handshake messages that set up an encrypted session, and learn what metadata is still visible even when the payload itself isn't.

## 🧩 Concepts You Need First

- **TLS (Transport Layer Security)** — a cryptographic protocol that encrypts traffic between client and server, commonly over TCP port 443. It's what turns the plaintext HTTP from Day 9 into HTTPS, and is also used to secure FTPS, SMTPS, and other protocols.
- **The TLS handshake** — the sequence of messages that negotiates encryption _before_ any application data flows, conceptually parallel to the TCP 3-way handshake from Day 8 but one layer up and far more involved:

|Message Type|Description|
|---|---|
|Client Hello|Client initiates the secure connection and offers a list of supported cipher suites|
|Server Hello|Server selects a cipher suite and returns its certificate|
|Certificate|Server's digital certificate (X.509) proving its identity|
|Key Exchange|Client and server exchange the key material for the session|
|Finished|Handshake complete — the encrypted session begins|

- **What's still visible without decryption** — Wireshark can't read TLS payload by default, but the handshake itself happens in the clear: server name (SNI), certificate details, and the negotiated TLS version are all visible even on fully encrypted traffic.

## 🛠️ Step-by-Step

### Step 1: Show all TLS traffic

```
tls
```

> [!note] What this does Same baseline pattern as every previous protocol filter this challenge (`icmp`, `tcp`, `http`) — narrows the capture to TLS-negotiated sessions, usually riding on top of TCP port 443.

### Step 2: Isolate the handshake start

```
tls.handshake.type == 1
```

> [!note] What this does Filters to Client Hello messages — the very first packet of any TLS session, and the one that reveals the SNI (which website is being requested) even though everything after the handshake is encrypted.

### Step 3: Confirm the negotiated TLS version

```
tls.record.version == 0x0303
```

> [!note] What this does `0x0303` corresponds to TLS 1.2. Checking this against expected values is how you catch outdated TLS versions (like TLS 1.0) still in use — a real finding worth flagging in an assessment, not just a lab exercise.

## 📁 Important Files & Directories

|Path|Purpose|
|---|---|
|Sample PCAP file (Wireshark labs)|Capture containing TLS handshake traffic to analyze|

## ⌨️ Command Cheat-Sheet

|Filter|Description|
|---|---|
|`tls`|Show all TLS traffic|
|`tcp.port == 443`|TLS over HTTPS|
|`tls.handshake.type == 1`|Client Hello messages|
|`tls.handshake.type == 2`|Server Hello messages|
|`tls.record.version == 0x0303`|TLS 1.2 traffic|
|`tls.record.version == 0x0304`|TLS 1.3 traffic|

## ⚠️ Gotchas / Things That Tripped Me Up

- Wireshark **cannot decrypt TLS payload by default** — don't go looking for readable HTTP-style content inside a `tls` filter result; the value here is entirely in the handshake metadata (SNI, certificate, version), not the encrypted body.
- The Client Hello's SNI field is the single most useful piece of metadata in an encrypted capture — it's often the only way to tell _which_ site a host talked to when the rest of the session is unreadable.

## 📌 Key Takeaways (Deep Concepts)

- TLS metadata analysis is its own detection category, distinct from payload inspection: outdated TLS versions, suspicious or self-signed certificates, and domains abusing encryption to hide malicious traffic are all findings visible purely from the handshake, without ever decrypting anything.
- This closes the protocol-layer arc of Challenge 02 — ICMP (Day 7) and TCP (Day 8) covered network/transport visibility, HTTP (Day 9) covered plaintext application content, and TLS (Day 10) covers what's still knowable once that application content is encrypted. Together they map the full stack a SOC analyst reads packet-by-packet.

## ✅ Summary (10-second recall)

> [!summary]
> 
> - TLS = cryptographic protocol securing traffic (e.g. HTTPS), typically over TCP port 443; handshake = Client Hello → Server Hello → Certificate → Key Exchange → Finished.
> - Wireshark can't decrypt TLS by default, but handshake metadata (SNI, certificate, version) is still visible.
> - Filters: `tls`, `tcp.port == 443`, `tls.handshake.type == 1`, `tls.handshake.type == 2`, `tls.record.version == 0x0303/0x0304`.
> - Detection angle: outdated TLS versions and suspicious certificates are visible findings even without decrypting payload.

---