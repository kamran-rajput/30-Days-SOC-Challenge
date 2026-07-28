## tags: [soc, summary, challenge-02]

challenge: 2 days: 6-10

# 🧠 Challenge 02 — Quick Revision Summary

Everything from Days 6–10 in one scan. Read top to bottom in ~2 minutes.

## 🧩 Core Concepts (one-liners)

- **Wireshark** = open-source packet analyzer — captures live traffic or reads saved **PCAP** files, down to individual header fields.
- **Capture filter vs. Display filter** — capture (BPF syntax) is applied before saving and permanently discards non-matches; display (Wireshark syntax) is applied after and only changes what you see.
- **Wireshark profile** = a saved set of columns/colorization/filters — keep a dedicated "SOC Analyst" profile separate from the default.
- **ICMP** = Layer 3, error/operational messaging (`ping` = Echo Request Type 8 / Echo Reply Type 0). No ports — Request/Reply pairs match via Identifier + Sequence No.
- **TCP** = Layer 4, reliable/ordered delivery via the **3-way handshake** (SYN → SYN-ACK → ACK). Flags (SYN/ACK/FIN/RST/PSH/URG) are the backbone of connection-state tracking.
- **HTTP** = application-layer, plaintext by design, typically TCP port 80. Readable request/response pairs make it the easiest layer to fully analyze — and the easiest place to spot accidental data exposure.
- **TLS** = secures traffic (commonly HTTPS, TCP port 443) via a handshake (Client Hello → Server Hello → Certificate → Key Exchange → Finished). Wireshark can't decrypt payload by default, but handshake metadata (SNI, certificate, version) stays visible.
- **The stack, top to bottom this challenge**: ICMP/TCP (network & transport visibility) → HTTP (plaintext application content) → TLS (what's still knowable once that content is encrypted).
- **Pattern over single event still holds**: unanswered SYNs, ICMP sweep bursts, and repeated beacon-like HTTP requests are all detection signals _because_ of volume/repetition, not any one packet alone — same principle as Challenge 01.

## 📁 Directories & Files

|Path|Purpose|
|---|---|
|`Protocol_Analysis_pcap.pcapng`|Sample capture used across Days 6–10 for hands-on filtering|
|Wireshark → Edit → Configuration Profiles|Where the "SOC Analyst" profile is created and switched|
|Wireshark Display Filter bar|Post-capture filtering — Wireshark's own filter syntax|
|Wireshark → Capture → Options → Capture Filter|Pre-capture filtering — BPF syntax|

## 🔍 Filter Cheat-Sheet by Protocol

**ICMP (Day 7)**

```
icmp
icmp.type == 8        # Echo Request
icmp.type == 0         # Echo Reply
icmp.code == 3          # Destination unreachable
ip.addr == 192.168.1.10
```

**TCP (Day 8)**

```
tcp
tcp.flags.syn == 1     # start of connection
tcp.flags.fin == 1      # end of connection
tcp.port == 80
ip.addr == 192.168.1.1
```

**HTTP (Day 9)**

```
http
tcp.port == 80
http.request.method == "GET"
http.request.uri
http.set_cookie
ip.addr == 192.168.1.10
```

**TLS (Day 10)**

```
tls
tcp.port == 443
tls.handshake.type == 1        # Client Hello
tls.handshake.type == 2        # Server Hello
tls.record.version == 0x0303   # TLS 1.2
tls.record.version == 0x0304   # TLS 1.3
```

## 🚩 Red Flags Learned This Week

- [ ] Burst of ICMP Echo Requests to sequential IPs, or a wave of Destination Unreachable replies — ping sweep / host discovery
- [ ] Large volume of unanswered SYNs to sequential ports on one host — SYN scan signature
- [ ] Sensitive data (tokens, credentials, session IDs) riding in cleartext HTTP URLs or headers
- [ ] Regular, repeated HTTP requests to the same host/URI — possible malware beaconing to a C2 server
- [ ] TLS handshake negotiating an outdated version (e.g. TLS 1.0) instead of 1.2/1.3
- [ ] Suspicious or self-signed certificates in the TLS Certificate message

## ✅ 10-Second Recall

> [!summary]
> 
> - Day 6: Wireshark = packet analyzer for live traffic or PCAPs. Capture filter (BPF, pre-save) ≠ Display filter (post-save). Built a "SOC Analyst" profile.
> - Day 7: ICMP = Layer 3 messaging; Echo Request (Type 8) / Echo Reply (Type 0); filters by `icmp.type`/`icmp.code`.
> - Day 8: TCP = Layer 4, 3-way handshake (SYN→SYN-ACK→ACK); flags (`tcp.flags.syn`/`fin`) track connection state.
> - Day 9: HTTP = plaintext application layer over TCP port 80; `http.request.method`/`uri` surface requests and possible data exposure.
> - Day 10: TLS = encrypts traffic over TCP port 443; handshake metadata (`tls.handshake.type`, `tls.record.version`) stays visible even without decryption.