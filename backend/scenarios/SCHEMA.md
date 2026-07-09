# Scenario File Format (Phase 1 — DRAFT, format review)

One YAML file per scenario in `backend/scenarios/`. Replaces the three-way split
of `CAMPAIGN_LEVELS` (metadata) + `simulated_attack_logs.ndjson` (chain) +
`TRIAGE_REVIEWS` (education), which are linked only by a bare label string with
nothing validating that they agree.

**Status: draft.** `malware_usb.yaml` (attack) and `false_positive_veeam.yaml`
(FP) are converter output from the live data for format review. Nothing loads
these yet; the remaining 18 scenarios are NOT converted until the format is
approved.

## Top level

| Field | Type | Notes |
|---|---|---|
| `label` | string | unique, `^[a-z0-9_]+$` — stable across the migration so saved reports/actions keep matching |
| `category` | enum | one of the 8 attack categories or `False Positive` |
| `difficulty` | int 1–3 | **new** — Phase 2 uses it for queue ordering and noise ratio |
| `threat_pattern` | string | display name (was per-log in the NDJSON) |
| `narrative` | object | `ticket_title`, `storyline` |
| `entities` | object | named entities, see below |
| `chain` | array | ordered event steps, see below |
| `triage_review` | object | `mitre` (optional — FPs have none), `what_is_it`, `response_actions` |

## Entities

Declared once, resolved once per run; every reference gets the same value, so
host/user/IP consistency through a chain is automatic instead of hand-kept.

```yaml
entities:
  victim:
    type: "employee"          # drawn from the EMPLOYEES roster at runtime
  c2:
    type: "external_ip"
    value: "185.141.62.11"    # static entities pin their values
  backup_server:
    type: "internal_host"
    hostname: "ACME-VEEAM01"
    ip: "10.0.1.210"
```

Entity types: `employee` (roster-resolved: `.username .hostname .ip
.user_domain .email .full_name`), `external_ip` (`.ip`), `internal_host`
(`.hostname .ip`), `domain`, `file`, `hash` (`.value`). `infra` is built in
and exposes the SERVERS dict: `{infra.dns.ip}`, `{infra.file.ip}`,
`{infra.dc.ip}`, `{infra.print.ip}`.

**Placeholder grammar** — strictly `{name.field}`: two dot-separated
identifiers where `name` is a declared entity (or `infra`). Anything else in
braces passes through verbatim — this matters because real log data contains
brace-wrapped GUIDs (`{4d36e967-e325-...}`) and Windows logon GUIDs that must
not be touched. The loader **errors** on a dotted two-part reference that
doesn't match a declared entity (it's almost certainly a typo), and ignores
everything else.

## Chain steps

```yaml
chain:
  - offset: 0                 # first event fires at drip time
    event_type: "6416"
    source_type: "Windows Security"
    severity: "low"
    hostname: "{victim.hostname}"
    source_ip: "{victim.ip}"
    message: "A new external device was recognized."
    key_value_pairs:
      event_id: 6416          # unquoted int — types are preserved exactly
      channel: "WinEventLog:Security"
  - offset: [8, 20]           # 8-20s after the previous step (jitter)
    ...
```

- `offset`: seconds after the *previous* step — a number, or `[min, max]` for
  jitter. Replaces the uniform hardcoded 3–8s gap (which made a 2 GB
  migration and a registry write take the same time).
- Step fields mirror today's per-log fields (`event_type`, `source_type`,
  `log_source`, `severity`, `hostname`, `source_ip`, `destination_ip`,
  `user_account`, `message`, `key_value_pairs`). `label`, `category`,
  `threat_pattern`, `scenario_id`, queue position etc. are attached by the
  generator at runtime exactly as today — **the emitted log shape does not
  change**, which is what makes parity diffing possible.
- **Clock model** (decided): compressed but causally ordered. Timestamps stay
  within the session's wall-clock and always advance in chain order; narrative
  fields inside `key_value_pairs` (e.g. Veeam's `duration_seconds: "4208"`)
  may describe longer spans than the compressed clock shows. We accept that
  mismatch rather than faking multi-hour timestamps that would break the
  live-tail experience.

## YAML typing rules

- **Generated files quote every string** using JSON escaping (valid YAML
  double-quoted scalars), so `"110"`, `"0xC000006D"`, `"no"`, `"1.10"` can
  never be coerced. Ints/bools that are genuinely typed in today's data
  (`event_id: 6416`, `initiated: true`) are emitted unquoted and stay typed.
- Hand-authored files must follow the same rule for anything ambiguous:
  **quote event IDs, ports, hex codes, and version-like strings.**
- After parsing, the structure is validated against `schema.json`
  (JSON Schema draft 2020-12) and the loader fails **at boot, loudly**, with
  the filename and path of the violation. Beyond the schema, the loader also
  checks: label uniqueness, placeholder resolution (above), and an event-ID ↔
  channel pairing whitelist (the class of wince Phase 0 fixed by hand).
- If quoting discipline proves too fragile in practice, fallback is JSON5/JSONC
  per review agreement — flagged if we get there.

## Migration / parity plan

1. Converter emits all 20 scenarios from the current three sources (the two
   examples here are its output).
2. Loader builds the same in-memory structures behind a flag:
   `SPECTYR_SCENARIO_SOURCE=ndjson|yaml`, default `ndjson`.
3. Parity check: generate N seeded runs from both sources and diff emitted
   logs (ignoring ids/timestamps within jitter bounds). Flag flips to `yaml`
   only when the diff is clean; NDJSON loader is deleted only after that.

New dependencies: `PyYAML`, `jsonschema` (both pure-Python, self-hosting
stays trivial).
