# Environment Report: Stage 1+ Flag Ledger

Running ledger for every stub, simplification, and unresolved identity in the
simulated environment from Stage 1 onward. MIGRATION_REPORT.md is frozen as
the Stage 0 artifact; new flags land here. Each entry stays until a review
resolves it (resolution noted inline, entry kept for the record).

## Stage 1 (Endpoint Context Pages)

### Open flags

- **Proxy software identity (carried from Stage 0).** ACME-SVR06 is named
  like a Windows server while proxy/firewall log fields follow Palo Alto CIM.
  Until decided, the proxy endpoint page shows a base Windows Server baseline:
  no proxy daemon process, no proxy service, no proxy listening ports are
  modeled. Whoever resolves this decides between PAN appliance (drop the
  endpoint) or Windows proxy software (name the real product).
- **Defender binary paths simplified.** MsMpEng.exe / NisSrv.exe are listed
  at C:\Program Files\Windows Defender\. Running instances normally load from
  the versioned C:\ProgramData\Microsoft\Windows Defender\Platform\<version>
  directory; the version-stamped path is omitted rather than invented.
- **Backup role minimally modeled.** Only the Veeam Backup Service
  (VeeamBackupSvc) and its default 9392 port, plus the 10006 agent port the
  scenario chain itself establishes. Console, catalog/database engine, and
  mount services are omitted rather than guessed.
- **phishing_link autorun value ends in `.ex`.** The authored SetValue
  details string is `...\AppData\Roaming\InvoiceService.ex` (likely a
  truncated `.exe`). Pre-existing chain content; surfacing it in the Autoruns
  tab preserves it byte-for-byte. Needs an approved correction if it is a
  typo, not a deliberate oddity.

### Recorded decisions (not open)

- **Firewall is a log source, not a managed endpoint.** ACME-FW01 never
  enters the endpoint world; no Windows telemetry is fabricated for PAN-OS.
  It remains in every scenario environment and in network events.
- **Org egress IP is generated.** No scenario chain declares an organization
  egress address (source IPs are internal 10.0.1.x; external addresses are
  attacker or destination infrastructure), so one RFC 5737 TEST-NET-3 address
  (203.0.113.x, excluding the .50 inbound-scanner template) is derived per
  session from the stable key (session_seed, "org_egress_ip"). Every managed
  endpoint displays the same address. If a future scenario authors a real
  egress address, resolve_egress_ip must learn to prefer it and to fail on
  conflicts.
- **MAC addresses use the VMware manual-assignment OUI** (00:50:56, fourth
  octet masked to the manual 00-3F range): the fleet reads as virtualized.
  Set dressing, stable per (session, host).
- **Process memory values are set dressing**, stable-key derived per
  (session, host, process identity), range-banded by process type.
- **explorer.exe's PPID dangles by design** and is marked parent_exited:
  userinit.exe spawns it and exits. This is how real EDR process tables look.
- **Host status is scenario-declared** (schema v2 host `status`, default
  online). No generator may set it; only derived timestamps use the seed.
- **spectyr-agent 1.0.0** is the agent identity constant on every endpoint.
