# Splunk CIM Field Placement Notes

**Status: Ruling recorded; official field-table citation pending.** The
project owner will paste the official dvc and src/src_ip/src_user field
description rows from the Splunk CIM Web data model documentation (with
version and URL) below. Until that lands, the ruling alone is NOT a
verification basis for any future correction: new CIM corrections wait for
the official field table.

Working notes for authoring and correcting proxy/firewall/DNS events, which
follow Palo Alto formats normalized through Splunk CIM. Created at Stage 1
review (follow-up 3): no in-repo CIM notes existed before this file; the
placements below record the review ruling and the CIM Web/Network data model
semantics it applied.

## Official field-table citation (PENDING)

Awaiting the official Splunk CIM Web data model rows for `dvc`, `src`,
`src_ip`, `src_user` with CIM version and URL.

## Device vs source vs destination

| Field | Meaning | In this corpus |
|---|---|---|
| `dvc` | The device that GENERATED the event | Proxy events: the proxy itself (`{infra.proxy.hostname}` renders ACME-SVR06). Firewall events: `ACME-FW01`. DNS query logs: the DNS server (`{infra.dns.hostname}`) |
| `src_ip` / `src` | The client that originated the traffic | The workstation (`{victim.ip}`) |
| `src_user` | The authenticated client user | `{victim.username}` |
| `dst_ip` / `dest_port` | The traffic destination | External or internal target |

The client host NEVER belongs in `dvc`. The pre-correction corpus carried
`dvc: "{victim.hostname}"` on 15 proxy steps (the Stage 0 flag undercounted
at 14); all were corrected in the Stage 1 follow-up 3 batch registered in
`scenario_corrections.py`.

## Ruling provenance

Stage 1 review (2026-07-16): "Per Splunk CIM, dvc is the device that
generated the event. For proxy events that is the proxy itself. Client host
belongs in the source fields (src / src_host per the CIM Web datamodel)."
The same review reclassified ACME-SVR06 as a PAN-OS VM-Series explicit proxy
appliance (log source, never a managed endpoint).
