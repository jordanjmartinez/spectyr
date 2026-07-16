# Splunk CIM Field Placement Notes

**Status: Verified.** Field semantics below are cited from the official Splunk
Common Information Model documentation, version 8.5 (Web and Network Traffic
data model pages last updated 2026-04-01), verified live 2026-07-16. New CIM
corrections cite this file.

Working notes for authoring and correcting proxy/firewall/DNS events, which
follow Palo Alto formats normalized through Splunk CIM.

## Sources

- Web data model:
  https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/web
- Network Traffic data model:
  https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-traffic

## Official field table (CIM 8.5)

| Field | Dataset | Type | Definition |
|---|---|---|---|
| `src` | Web | string (recommended, required for pytest-splunk-addon) | The source of the network traffic, i.e. the client requesting the connection. |
| `dvc` | All_Traffic (Network Traffic) | string (recommended, required for pytest-splunk-addon) | The device that reported the traffic event; may be aliased from `dvc_host`, `dvc_ip`, or `dvc_name`. |

**IMPORTANT: the Web data model field table contains NO `dvc` field.** Spectyr
must never describe `dvc` as a native Web CIM field. When `dvc` appears on a
Spectyr proxy event, its semantics come from the Network Traffic data model,
used here as a documented cross-model usage. (This supersedes the earlier
reviewer instruction to cite both fields from the Web page.)

## Spectyr proxy event semantics

Example: ACME-WS04 browsing via the proxy ACME-SVR06 to a remote site.

| Field | Value | Meaning |
|---|---|---|
| `src` / `src_ip` | ACME-WS04 | the client (source of the traffic) |
| `dest` / `dst_ip` | remote site | the traffic destination |
| `dvc` | ACME-SVR06 | the reporting device (the proxy), cross-model from All_Traffic |
| `src_user` | the client user | the authenticated client identity |

The client host NEVER belongs in `dvc`. The Stage 1 follow-up 3 batch (15
proxy steps registered in `scenario_corrections.py`) moved `dvc` from the
client hostname to `{infra.proxy.hostname}` (renders ACME-SVR06) on this
basis. Client identity stays in `src_ip` / `src_user`, which every corrected
step already carries.

## Firewall and DNS

- Firewall events: `dvc` is `ACME-FW01` (the reporting firewall).
- DNS query logs: `dvc` is the DNS server (`{infra.dns.hostname}`).
- Same principle throughout: `dvc` is the reporting device, `src` is the
  client that originated the traffic.

## Ruling provenance

Stage 1 review (2026-07-16): "Per Splunk CIM, dvc is the device that generated
the event. For proxy events that is the proxy itself. Client host belongs in
the source fields." Micro follow-up B (2026-07-16) added the official CIM 8.5
field-table citations above and the correction that `dvc` is a Network Traffic
field, not a Web field.
