"""Approved schema corrections: the places where the v2 scenario corpus
intentionally diverges from the frozen v1 corpus.

Every record here went through the schema correction workflow (official
template first, then correction) and a review checkpoint. This module is the
single source of truth consumed by:

    scenarios/migrate_v1_to_v2.py   applies the correction when regenerating v2
    parity_check_v2.py              allows exactly these rendered diffs, and
                                    fails if an expected divergence is missing
    test_scenario_loader_v2.py      normalizes chain-equality assertions and
                                    asserts each correction is present

Record fields:
    label         scenario the correction applies to
    kind          "step" (one authored chain field), "entity" (an entity
                  declaration value; the chain YAML is untouched because the
                  placeholders re-resolve, only rendered values move), or
                  "triage" (a triage_review field; educational copy, no
                  chain or render impact)
    step / field  step kind: 0-based chain index; "kvp.<key>" for
                  key_value_pairs entries, else the step field
    entity/field  entity kind: entity name and declaration field
    field         triage kind: dotted path inside triage_review
                  (e.g. "mitre.name")
    v1 / v2       authored values (v2 may be a placeholder)
    rendered_v1 / rendered_v2
                  post-substitution values the parity diff will observe; for
                  entity kind, every rendered field where v2 equals v1 with
                  rendered_v1 replaced by rendered_v2 is an approved diff
    old_line / new_line
                  exact YAML lines for the textual migration rewrite
    reason        why the v1 value is wrong, template-first
    approved      review provenance; PENDING until explicitly approved
"""

CORRECTIONS = [
    {
        "label": "false_positive_ssl_inspection",
        "kind": "step",
        "step": 4,
        "field": "kvp.dvc",
        "v1": "ACME-PROXY-01",
        "v2": "{infra.proxy.hostname}",
        "rendered_v1": "ACME-PROXY-01",
        "rendered_v2": "ACME-SVR06",
        "old_line": '      dvc: "ACME-PROXY-01"',
        "new_line": '      dvc: "{infra.proxy.hostname}"',
        "reason": (
            "Splunk CIM: dvc is the device that reported the event; for a "
            "proxy SSL_INSPECT log that is the proxy itself. ACME-PROXY-01 "
            "does not exist in the reference environment, where the proxy is "
            "ACME-SVR06 (10.0.1.205). Emitted as {infra.proxy.hostname} per "
            "placeholder discipline; renders as ACME-SVR06."
        ),
        "approved": "Stage 0 review, follow-up 2 (approved 2026-07-16)",
    },
    {
        "label": "false_positive_veeam",
        "kind": "entity",
        "entity": "backup_server",
        "field": "ip",
        "v1": "10.0.1.210",
        "v2": "10.0.1.206",
        "rendered_v1": "10.0.1.210",
        "rendered_v2": "10.0.1.206",
        "old_line": '    ip: "10.0.1.210"',
        "new_line": '    ip: "10.0.1.206"',
        "reason": (
            "The reference environment gained a canonical backup role: "
            "ACME-VEEAM01 at 10.0.1.206 (SERVERS['backup']). The entity's "
            "10.0.1.210 predates the mapping. The chain YAML is unchanged; "
            "{backup_server.ip} placeholders re-resolve to the canonical IP."
        ),
        "approved": "Stage 0 review, follow-up 3 (approved 2026-07-16)",
    },
    {
        "label": "lateral_movement_1",
        "kind": "triage",
        "field": "mitre.name",
        "v1": "Network Service Scanning",
        "v2": "Network Service Discovery",
        "rendered_v1": "Network Service Scanning",
        "rendered_v2": "Network Service Discovery",
        "old_line": '    name: "Network Service Scanning"',
        "new_line": '    name: "Network Service Discovery"',
        "reason": (
            "ATT&CK renamed T1046 to Network Service Discovery (ID "
            "unchanged). Verified live against attack.mitre.org 2026-07-16. "
            "Display name only; the frozen v1 corpus keeps the old name."
        ),
        "approved": "Stage 1 review, follow-up 1 (approved 2026-07-16)",
    },
    {
        "label": "lateral_movement_1",
        "kind": "triage",
        "field": "what_is_it.title",
        "v1": "Network Service Scanning",
        "v2": "Network Service Discovery",
        "rendered_v1": "Network Service Scanning",
        "rendered_v2": "Network Service Discovery",
        "old_line": '    title: "Network Service Scanning"',
        "new_line": '    title: "Network Service Discovery"',
        "reason": (
            "Educational title carries the technique display name; follows "
            "the T1046 rename. Description prose is unchanged: it describes "
            "the scanning activity, not the technique name."
        ),
        "approved": "Stage 1 review, follow-up 1 (approved 2026-07-16)",
    },
]

# Stage 1 review follow-up 3: Splunk CIM defines dvc as the device that
# generated the event; for proxy logs that is the proxy itself (see
# scenarios/CIM_NOTES.md). The client belongs in the source fields, and
# every one of these steps already carries src_ip / src_user, so only dvc
# moves; no other field is restructured. Authored as
# {infra.proxy.hostname} per placeholder discipline; renders as ACME-SVR06.
# rendered_v1 is the victim workstation under the parity fixture
# (nkhan -> ACME-WS12); at runtime it is whichever workstation resolves.
# Recount at implementation: 15 steps, not the 14 the Stage 0 flag said.
_PROXY_DVC_BATCH = [
    ("c2_http", 2), ("c2_http", 4), ("data_exfil_archive", 4),
    ("false_positive_oauth", 1), ("false_positive_pentest", 0),
    ("false_positive_pentest", 2), ("false_positive_pentest", 4),
    ("false_positive_robocopy", 4), ("false_positive_ssl_inspection", 0),
    ("false_positive_ssl_inspection", 1), ("insider_shadow_it", 4),
    ("insider_staging", 4), ("phishing_1", 0), ("phishing_1", 1),
    ("phishing_link", 1),
]
CORRECTIONS += [
    {
        "label": label, "kind": "step", "step": step, "field": "kvp.dvc",
        "v1": "{victim.hostname}", "v2": "{infra.proxy.hostname}",
        "rendered_v1": "ACME-WS12", "rendered_v2": "ACME-SVR06",
        "old_line": '      dvc: "{victim.hostname}"',
        "new_line": '      dvc: "{infra.proxy.hostname}"',
        "reason": "CIM dvc placement batch; see the block comment above "
                  "and scenarios/CIM_NOTES.md.",
        "approved": "Stage 1 review, follow-up 3 (approved 2026-07-16, all 15)",
    }
    for label, step in _PROXY_DVC_BATCH
]


# v19.1 ATT&CK migration (2026-07-17): T1562.001 -> T1685 and T1070.001 ->
# T1685.005 (Disable or Modify Tools family), tactic Defense Evasion (retired in
# v19) -> Defense Impairment. Validated against the official Enterprise ATT&CK
# v19.1 STIX dataset (github.com/mitre/cti tag ATT&CK-v19.1; enterprise-attack
# .json sha256 fc783039f17fba646f79448f1322996457c658a9474f6d14c3bc924a2cf1c97d).
# The frozen v1 corpus keeps the v18.1 mapping; these carry the v2 triage_review.
_V19_MIGRATION = [
    ("defense_evasion", "mitre.id", "T1562.001", "T1685",
     '    id: "T1562.001"', '    id: "T1685"'),
    ("defense_evasion", "mitre.name", "Impair Defenses: Disable or Modify Tools",
     "Disable or Modify Tools",
     '    name: "Impair Defenses: Disable or Modify Tools"',
     '    name: "Disable or Modify Tools"'),
    ("defense_evasion", "mitre.tactic", "Defense Evasion", "Defense Impairment",
     '    tactic: "Defense Evasion"', '    tactic: "Defense Impairment"'),
    ("defense_evasion", "mitre.url",
     "https://attack.mitre.org/techniques/T1562/001/",
     "https://attack.mitre.org/techniques/T1685/",
     '    url: "https://attack.mitre.org/techniques/T1562/001/"',
     '    url: "https://attack.mitre.org/techniques/T1685/"'),
    ("defense_evasion_log_clearing", "mitre.id", "T1070.001", "T1685.005",
     '    id: "T1070.001"', '    id: "T1685.005"'),
    ("defense_evasion_log_clearing", "mitre.name",
     "Indicator Removal: Clear Windows Event Logs",
     "Disable or Modify Tools: Clear Windows Event Logs",
     '    name: "Indicator Removal: Clear Windows Event Logs"',
     '    name: "Disable or Modify Tools: Clear Windows Event Logs"'),
    ("defense_evasion_log_clearing", "mitre.tactic", "Defense Evasion",
     "Defense Impairment",
     '    tactic: "Defense Evasion"', '    tactic: "Defense Impairment"'),
    ("defense_evasion_log_clearing", "mitre.url",
     "https://attack.mitre.org/techniques/T1070/001/",
     "https://attack.mitre.org/techniques/T1685/005/",
     '    url: "https://attack.mitre.org/techniques/T1070/001/"',
     '    url: "https://attack.mitre.org/techniques/T1685/005/"'),
]
CORRECTIONS += [
    {"label": lbl, "kind": "triage", "field": fld, "v1": v1v, "v2": v2v,
     "rendered_v1": v1v, "rendered_v2": v2v, "old_line": ol, "new_line": nl,
     "reason": "v19.1 ATT&CK migration: Disable or Modify Tools family / "
               "Defense Impairment tactic; dataset-validated (ATT&CK-v19.1 "
               "STIX). Frozen v1 corpus keeps the v18.1 mapping.",
     "approved": "v19 migration stage (approved 2026-07-17)"}
    for lbl, fld, v1v, v2v, ol, nl in _V19_MIGRATION
]


# 3c Batch 2 review: insider_staging is an insider-threat scenario where the
# account holder is the threat, not a victim. The employee/account entity is
# renamed victim -> insider (internal id only; every {victim.X} placeholder
# re-resolves as {insider.X} to the same substituted value, so rendered output
# is byte-identical and parity_check_v2 stays CLEAN with no new rendered diff).
CORRECTIONS += [
    {
        "label": "insider_staging",
        "kind": "rename_entity",
        "v1": "victim",
        "v2": "insider",
        "reason": (
            "Insider-threat scenario: the account holder is the threat, not a "
            "victim (I2 ruling). The employee/account entity id is renamed "
            "victim -> insider; the ws_victim HOST id is unchanged. Internal "
            "id only: placeholders re-resolve to the same values, rendered "
            "logs byte-identical."
        ),
        "approved": "3c Batch 2 review (approved 2026-07-17)",
    },
    {
        "label": "insider_shadow_it",
        "kind": "rename_entity",
        "v1": "victim",
        "v2": "employee",
        "reason": (
            "Shadow-IT scenario (S1 ruling): the account holder is the actor "
            "but malicious intent is NOT established, so 'victim' is wrong; the "
            "account entity id is renamed victim -> employee (neutral). The "
            "ws_victim HOST id is unchanged. Internal id only: placeholders "
            "re-resolve to the same values, rendered logs byte-identical."
        ),
        "approved": "3c Batch 4 review (approved 2026-07-17)",
    },
]


def for_label(label):
    return [c for c in CORRECTIONS if c["label"] == label]


def entity_renames(label):
    """(old_key, new_key) entity renames approved for a label. Applied by the
    loader-parity test when projecting the frozen v1 corpus onto v2 for
    comparison. (The v2 corpus is the hand-maintained source of truth from
    Stage 2 on; the Stage-0 migrator is not re-run, so it does not emit this
    rename any more than it emits the Stage 2 detections or Stage 3 actions.)"""
    return [(c["v1"], c["v2"]) for c in CORRECTIONS
            if c["label"] == label and c["kind"] == "rename_entity"]
