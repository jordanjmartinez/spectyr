# DNS Normal Traffic Patterns for Spectyr

> Purpose: Realistic background noise for SOC training scenarios
> Source: Windows DNS Server Analytical Logs (ETW)

---

## Schema

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |
|------|------------|------------|-----------|---------|----------|---------|-----------------|

**MESSAGE** = Raw log line (shown in main table view)
**KEY VALUE PAIRS** = Parsed fields (shown in expanded/collapsed view only)

---

## DNS Event Types (from Windows DNS Server Analytical Logs)

| Event Type | Description |
|------------|-------------|
| QUERY_RECEIVED | DNS query received from client |
| RESPONSE_SUCCESS | DNS response sent successfully (NOERROR) |
| RESPONSE_FAILURE | DNS response with error (NXDOMAIN, SERVFAIL) |
| RECURSE_QUERY_OUT | Recursive query sent to upstream DNS |
| RECURSE_RESPONSE_IN | Response received from upstream DNS |

**Query Types (qtype):** A (1), AAAA (28), CNAME (5), MX (15), PTR (12), TXT (16), SRV (33)
**Response Codes (rcode):** NOERROR (0), NXDOMAIN (3), SERVFAIL (2), REFUSED (5)

---

## Normal Traffic Logs (20 Events)

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |
|------|------------|------------|-----------|---------|----------|---------|-----------------|
| 08:01:05 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=www.google.com.; QTYPE=1; Port=52314; XID=12345` | `qname=www.google.com, qtype=A, qtype_id=1, source_ip=10.0.1.45, source_port=52314, xid=12345, rd=true, tcp=false` |
| 08:01:05 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=www.google.com.; QTYPE=1; RCODE=0; XID=12345; RDATA=142.250.191.46` | `qname=www.google.com, qtype=A, rcode=NOERROR, rcode_id=0, answer=142.250.191.46, xid=12345, tcp=false` |
| 08:15:22 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=outlook.office365.com.; QTYPE=1; Port=52418; XID=12346` | `qname=outlook.office365.com, qtype=A, qtype_id=1, source_ip=10.0.1.45, source_port=52418, xid=12346, rd=true, tcp=false` |
| 08:15:22 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=outlook.office365.com.; QTYPE=1; RCODE=0; XID=12346; RDATA=52.96.166.24` | `qname=outlook.office365.com, qtype=A, rcode=NOERROR, rcode_id=0, answer=52.96.166.24, xid=12346, tcp=false` |
| 08:22:45 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=www.google.com.; QTYPE=28; Port=52512; XID=12347` | `qname=www.google.com, qtype=AAAA, qtype_id=28, source_ip=10.0.1.45, source_port=52512, xid=12347, rd=true, tcp=false` |
| 08:22:45 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=www.google.com.; QTYPE=28; RCODE=0; XID=12347; RDATA=2607:f8b0:4004:800::2004` | `qname=www.google.com, qtype=AAAA, rcode=NOERROR, rcode_id=0, answer=2607:f8b0:4004:800::2004, xid=12347, tcp=false` |
| 08:30:11 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=teams.microsoft.com.; QTYPE=1; Port=52620; XID=12348` | `qname=teams.microsoft.com, qtype=A, qtype_id=1, source_ip=10.0.1.45, source_port=52620, xid=12348, rd=true, tcp=false` |
| 08:30:11 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=teams.microsoft.com.; QTYPE=1; RCODE=0; XID=12348; RDATA=13.107.42.16` | `qname=teams.microsoft.com, qtype=A, rcode=NOERROR, rcode_id=0, answer=13.107.42.16, xid=12348, tcp=false` |
| 09:00:18 | QUERY_RECEIVED | DNS | 10.0.1.50 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.50; RD=1; QNAME=slack.com.; QTYPE=1; Port=53100; XID=12349` | `qname=slack.com, qtype=A, qtype_id=1, source_ip=10.0.1.50, source_port=53100, xid=12349, rd=true, tcp=false` |
| 09:00:18 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.50 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.50; QNAME=slack.com.; QTYPE=1; RCODE=0; XID=12349; RDATA=99.181.64.71` | `qname=slack.com, qtype=A, rcode=NOERROR, rcode_id=0, answer=99.181.64.71, xid=12349, tcp=false` |
| 09:15:02 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=github.com.; QTYPE=1; Port=53200; XID=12350` | `qname=github.com, qtype=A, qtype_id=1, source_ip=10.0.1.45, source_port=53200, xid=12350, rd=true, tcp=false` |
| 09:15:02 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=github.com.; QTYPE=1; RCODE=0; XID=12350; RDATA=140.82.112.4` | `qname=github.com, qtype=A, rcode=NOERROR, rcode_id=0, answer=140.82.112.4, xid=12350, tcp=false` |
| 09:30:00 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=_dmarc.google.com.; QTYPE=16; Port=53300; XID=12351` | `qname=_dmarc.google.com, qtype=TXT, qtype_id=16, source_ip=10.0.1.45, source_port=53300, xid=12351, rd=true, tcp=false` |
| 09:30:00 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | TCP/53 | `RESPONSE_SUCCESS: TCP=1; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=_dmarc.google.com.; QTYPE=16; RCODE=0; XID=12351; RDATA="v=DMARC1; p=reject; rua=mailto:..."` | `qname=_dmarc.google.com, qtype=TXT, rcode=NOERROR, rcode_id=0, answer="v=DMARC1; p=reject...", xid=12351, tcp=true, note=truncated_retry` |
| 09:45:12 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=_ldap._tcp.corp.local.; QTYPE=33; Port=53400; XID=12352` | `qname=_ldap._tcp.corp.local, qtype=SRV, qtype_id=33, source_ip=10.0.1.45, source_port=53400, xid=12352, rd=true, tcp=false` |
| 09:45:12 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=_ldap._tcp.corp.local.; QTYPE=33; RCODE=0; XID=12352; RDATA=0 100 389 dc01.corp.local.` | `qname=_ldap._tcp.corp.local, qtype=SRV, rcode=NOERROR, rcode_id=0, answer=dc01.corp.local, priority=0, weight=100, port=389, xid=12352, tcp=false` |
| 10:00:03 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=10.1.0.10.in-addr.arpa.; QTYPE=12; Port=53500; XID=12353` | `qname=10.1.0.10.in-addr.arpa, qtype=PTR, qtype_id=12, source_ip=10.0.1.45, source_port=53500, xid=12353, rd=true, tcp=false` |
| 10:00:03 | RESPONSE_SUCCESS | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=10.1.0.10.in-addr.arpa.; QTYPE=12; RCODE=0; XID=12353; RDATA=fs01.corp.local.` | `qname=10.1.0.10.in-addr.arpa, qtype=PTR, rcode=NOERROR, rcode_id=0, answer=fs01.corp.local, xid=12353, tcp=false` |
| 10:22:18 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=oldcompanysite.net.; QTYPE=1; Port=53600; XID=12354` | `qname=oldcompanysite.net, qtype=A, qtype_id=1, source_ip=10.0.1.45, source_port=53600, xid=12354, rd=true, tcp=false` |
| 10:22:18 | RESPONSE_FAILURE | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_FAILURE: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=oldcompanysite.net.; QTYPE=1; RCODE=3; XID=12354` | `qname=oldcompanysite.net, qtype=A, rcode=NXDOMAIN, rcode_id=3, xid=12354, tcp=false` |
| 11:00:12 | QUERY_RECEIVED | DNS | 10.0.1.45 | 10.0.1.1 | UDP/53 | `QUERY_RECEIVED: TCP=0; InterfaceIP=10.0.1.1; Source=10.0.1.45; RD=1; QNAME=wpad.corp.local.; QTYPE=1; Port=53700; XID=12355` | `qname=wpad.corp.local, qtype=A, qtype_id=1, source_ip=10.0.1.45, source_port=53700, xid=12355, rd=true, tcp=false` |
| 11:00:12 | RESPONSE_FAILURE | DNS | 10.0.1.1 | 10.0.1.45 | UDP/53 | `RESPONSE_FAILURE: TCP=0; InterfaceIP=10.0.1.1; Destination=10.0.1.45; QNAME=wpad.corp.local.; QTYPE=1; RCODE=3; XID=12355` | `qname=wpad.corp.local, qtype=A, rcode=NXDOMAIN, rcode_id=3, xid=12355, tcp=false` |

---

## Traffic Distribution Notes

**Normal Query Type Distribution:**
- A records: ~75-80% (IPv4 lookups dominate)
- AAAA records: ~10-15% (IPv6, often paired with A)
- PTR: ~2-3% (reverse lookups for logging/auditing)
- SRV: ~1-2% (service discovery, AD-related)
- MX/TXT/CNAME: <1% each

**Normal Response Code Distribution:**
- NOERROR: ~90-95% (successful resolutions)
- NXDOMAIN: ~5-10% (typos, old bookmarks, WPAD probes)
- SERVFAIL: <1% (rare, indicates DNS issues)

**Common Benign NXDOMAIN Sources:**
- wpad.* - Windows Proxy Auto-Discovery (normal if not configured)
- Old/defunct domains from bookmarks
- Typos in manual URL entry

---

## Network Context

| IP | Hostname | Role |
|----|----------|------|
| 10.0.1.1 | DNS01 | Internal DNS Server |
| 10.0.1.45 | WS-PC045 | jsmith workstation |
| 10.0.1.50 | WS-PC050 | User workstation |

---

## References

- Microsoft DNS Logging and Diagnostics: https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics
- Windows DNS Server ETW Provider: {EB79061A-A566-4698-9119-3ED2807060E7}
- Raw message format: `EVENT_TYPE: TCP=0; InterfaceIP=x; Source=x; RD=1; QNAME=x; QTYPE=x; Port=x; XID=x`
