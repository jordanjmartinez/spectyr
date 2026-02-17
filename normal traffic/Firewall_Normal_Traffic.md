# Firewall Normal Traffic Patterns for Spectyr

> Purpose: Realistic background noise for SOC training scenarios
> Source: Generic firewall syslog format (based on Cisco Meraki/pfSense/FortiGate patterns)

---

## Schema

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |
|------|------------|------------|-----------|---------|----------|---------|-----------------|

**MESSAGE** = Raw log line (shown in main table view)
**KEY VALUE PAIRS** = Parsed fields (shown in expanded/collapsed view only)

---

## Normal Traffic Logs (20 Events)

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |
|------|------------|------------|-----------|---------|----------|---------|-----------------|
| 08:00:22 | ALLOW | Firewall | 10.0.1.45 | 10.0.1.1 | UDP/53 | `firewall src=10.0.1.45 dst=10.0.1.1 mac=00:1A:2B:3C:4D:45 protocol=udp sport=49152 dport=53 pattern: allow dns_outbound` | `src_ip=10.0.1.45, dst_ip=10.0.1.1, src_port=49152, dst_port=53, protocol=udp, action=allow, rule=dns_outbound, mac=00:1A:2B:3C:4D:45, direction=outbound` |
| 08:01:15 | ALLOW | Firewall | 10.0.1.45 | 142.250.191.46 | TCP/443 | `firewall src=10.0.1.45 dst=142.250.191.46 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49200 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=142.250.191.46, src_port=49200, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=google.com, direction=outbound` |
| 08:05:33 | ALLOW | Firewall | 10.0.1.45 | 52.96.166.24 | TCP/443 | `firewall src=10.0.1.45 dst=52.96.166.24 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49215 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=52.96.166.24, src_port=49215, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=outlook.office365.com, direction=outbound` |
| 08:10:44 | ALLOW | Firewall | 10.0.1.45 | 10.0.1.10 | TCP/445 | `firewall src=10.0.1.45 dst=10.0.1.10 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49300 dport=445 pattern: allow smb_internal` | `src_ip=10.0.1.45, dst_ip=10.0.1.10, src_port=49300, dst_port=445, protocol=tcp, action=allow, rule=smb_internal, dst_host=FS01, direction=internal` |
| 08:15:02 | ALLOW | Firewall | 10.0.1.45 | 10.0.1.20 | TCP/9100 | `firewall src=10.0.1.45 dst=10.0.1.20 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49350 dport=9100 pattern: allow print_internal` | `src_ip=10.0.1.45, dst_ip=10.0.1.20, src_port=49350, dst_port=9100, protocol=tcp, action=allow, rule=print_internal, dst_host=PRINT01, direction=internal` |
| 08:22:18 | ALLOW | Firewall | 10.0.1.45 | 13.107.42.16 | TCP/443 | `firewall src=10.0.1.45 dst=13.107.42.16 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49400 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=13.107.42.16, src_port=49400, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=teams.microsoft.com, direction=outbound` |
| 08:30:00 | ALLOW | Firewall | 10.0.1.50 | 10.0.1.1 | UDP/53 | `firewall src=10.0.1.50 dst=10.0.1.1 mac=00:1A:2B:3C:4D:50 protocol=udp sport=49500 dport=53 pattern: allow dns_outbound` | `src_ip=10.0.1.50, dst_ip=10.0.1.1, src_port=49500, dst_port=53, protocol=udp, action=allow, rule=dns_outbound, mac=00:1A:2B:3C:4D:50, direction=outbound` |
| 08:30:45 | ALLOW | Firewall | 10.0.1.50 | 208.65.153.238 | TCP/443 | `firewall src=10.0.1.50 dst=208.65.153.238 mac=00:1A:2B:3C:4D:50 protocol=tcp sport=49550 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.50, dst_ip=208.65.153.238, src_port=49550, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=youtube.com, direction=outbound` |
| 09:00:12 | ALLOW | Firewall | 10.0.1.100 | 10.0.1.45 | TCP/445 | `firewall src=10.0.1.100 dst=10.0.1.45 mac=00:1A:2B:3C:4D:00 protocol=tcp sport=49600 dport=445 pattern: allow smb_internal` | `src_ip=10.0.1.100, dst_ip=10.0.1.45, src_port=49600, dst_port=445, protocol=tcp, action=allow, rule=smb_internal, src_host=BACKUP01, direction=internal` |
| 09:15:33 | ALLOW | Firewall | 10.0.1.45 | 99.181.64.71 | TCP/443 | `firewall src=10.0.1.45 dst=99.181.64.71 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49700 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=99.181.64.71, src_port=49700, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=slack.com, direction=outbound` |
| 09:22:05 | ALLOW | Firewall | 10.0.1.45 | 104.16.85.20 | TCP/443 | `firewall src=10.0.1.45 dst=104.16.85.20 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49750 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=104.16.85.20, src_port=49750, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=cdn.jsdelivr.net, direction=outbound` |
| 09:30:00 | ALLOW | Firewall | 10.0.1.1 | 129.6.15.28 | UDP/123 | `firewall src=10.0.1.1 dst=129.6.15.28 mac=00:1A:2B:3C:4D:01 protocol=udp sport=49800 dport=123 pattern: allow ntp_outbound` | `src_ip=10.0.1.1, dst_ip=129.6.15.28, src_port=49800, dst_port=123, protocol=udp, action=allow, rule=ntp_outbound, dst_host=time.nist.gov, direction=outbound` |
| 10:00:15 | DENY | Firewall | 203.0.113.50 | 10.0.1.5 | TCP/22 | `firewall src=203.0.113.50 dst=10.0.1.5 protocol=tcp sport=45123 dport=22 pattern: deny inbound_default` | `src_ip=203.0.113.50, dst_ip=10.0.1.5, src_port=45123, dst_port=22, protocol=tcp, action=deny, rule=inbound_default, direction=inbound, reason=blocked_port` |
| 10:15:22 | ALLOW | Firewall | 10.0.1.45 | 10.0.1.10 | TCP/445 | `firewall src=10.0.1.45 dst=10.0.1.10 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49900 dport=445 pattern: allow smb_internal` | `src_ip=10.0.1.45, dst_ip=10.0.1.10, src_port=49900, dst_port=445, protocol=tcp, action=allow, rule=smb_internal, dst_host=FS01, direction=internal` |
| 10:30:44 | ALLOW | Firewall | 10.0.1.45 | 151.101.1.140 | TCP/443 | `firewall src=10.0.1.45 dst=151.101.1.140 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=49950 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=151.101.1.140, src_port=49950, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=reddit.com, direction=outbound` |
| 11:00:08 | DENY | Firewall | 198.51.100.22 | 10.0.1.5 | TCP/3389 | `firewall src=198.51.100.22 dst=10.0.1.5 protocol=tcp sport=52100 dport=3389 pattern: deny inbound_default` | `src_ip=198.51.100.22, dst_ip=10.0.1.5, src_port=52100, dst_port=3389, protocol=tcp, action=deny, rule=inbound_default, direction=inbound, reason=blocked_port` |
| 11:15:33 | ALLOW | Firewall | 10.0.1.45 | 140.82.112.4 | TCP/443 | `firewall src=10.0.1.45 dst=140.82.112.4 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=50000 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=140.82.112.4, src_port=50000, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=github.com, direction=outbound` |
| 11:30:00 | ALLOW | Firewall | 10.0.1.45 | 10.0.1.1 | UDP/53 | `firewall src=10.0.1.45 dst=10.0.1.1 mac=00:1A:2B:3C:4D:45 protocol=udp sport=50050 dport=53 pattern: allow dns_outbound` | `src_ip=10.0.1.45, dst_ip=10.0.1.1, src_port=50050, dst_port=53, protocol=udp, action=allow, rule=dns_outbound, direction=outbound` |
| 12:00:22 | ALLOW | Firewall | 10.0.1.45 | 157.240.214.35 | TCP/443 | `firewall src=10.0.1.45 dst=157.240.214.35 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=50100 dport=443 pattern: allow https_outbound` | `src_ip=10.0.1.45, dst_ip=157.240.214.35, src_port=50100, dst_port=443, protocol=tcp, action=allow, rule=https_outbound, dst_host=facebook.com, direction=outbound` |
| 12:15:45 | ALLOW | Firewall | 10.0.1.45 | 10.0.1.10 | TCP/445 | `firewall src=10.0.1.45 dst=10.0.1.10 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=50150 dport=445 pattern: allow smb_internal` | `src_ip=10.0.1.45, dst_ip=10.0.1.10, src_port=50150, dst_port=445, protocol=tcp, action=allow, rule=smb_internal, dst_host=FS01, direction=internal` |

---

## Event Type Distribution

| Action | Count | Description |
|--------|-------|-------------|
| ALLOW | 18 | Permitted traffic matching firewall rules |
| DENY | 2 | Blocked traffic (external SSH/RDP attempts) |

---

## Traffic Categories

### Outbound Web Traffic (HTTPS - TCP/443)
- Google, Microsoft 365, Teams, Slack
- YouTube, GitHub, Reddit, Facebook
- CDN services (jsdelivr)

### Internal Traffic
- SMB file shares (TCP/445) to FS01
- Print jobs (TCP/9100) to PRINT01
- Backup connections from BACKUP01

### Infrastructure Services
- DNS queries (UDP/53) to internal DNS (10.0.1.1)
- NTP time sync (UDP/123) to time.nist.gov

### Blocked External Attempts
- SSH (TCP/22) from internet - default deny
- RDP (TCP/3389) from internet - default deny

---

## Network Topology

| IP Address | Hostname | Role |
|------------|----------|------|
| 10.0.1.1 | FW01/DNS | Firewall / Internal DNS |
| 10.0.1.5 | WEB01 | Web server (DMZ) |
| 10.0.1.10 | FS01 | File server |
| 10.0.1.20 | PRINT01 | Print server |
| 10.0.1.45 | WS-PC045 | User workstation (jsmith) |
| 10.0.1.50 | WS-PC050 | User workstation |
| 10.0.1.100 | BACKUP01 | Backup server |

---

## Common Ports Reference

| Port | Protocol | Service | Normal Direction |
|------|----------|---------|------------------|
| 22 | TCP | SSH | Outbound only (block inbound) |
| 53 | UDP | DNS | Outbound to DNS server |
| 80 | TCP | HTTP | Outbound (updates, APIs) |
| 123 | UDP | NTP | Outbound to time servers |
| 443 | TCP | HTTPS | Outbound (web, APIs, SaaS) |
| 445 | TCP | SMB | Internal only |
| 3389 | TCP | RDP | Internal only (block external) |
| 9100 | TCP | Print | Internal only |

---

## Usage Notes

1. **ALLOW dominates** (~90%) - most normal traffic is permitted
2. **DENY events** should be rare in noise - save for attack scenarios
3. **Outbound HTTPS** is highest volume in modern networks
4. **Internal SMB/print** traffic is repetitive throughout the day
5. **External blocked attempts** (SSH, RDP) are common background noise from internet scanners
6. **DNS queries** precede most outbound connections
7. **SOURCE IP** is internal for outbound, external for inbound attempts

---

## Firewall Action Reference

| Action | Description | Use Case |
|--------|-------------|----------|
| ALLOW | Traffic permitted by rule | Normal business traffic |
| DENY | Traffic blocked, RST sent | Policy violation, blocked ports |
| DROP | Traffic silently discarded | Stealth blocking, no response |
| RESET-BOTH | Connection reset both sides | Terminate suspicious sessions |
