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
    step          0-based chain index
    field         "kvp.<key>" for key_value_pairs entries, else the step field
    v1 / v2       authored values (v2 may be a placeholder)
    rendered_v1 / rendered_v2
                  post-substitution values the parity diff will observe
    old_line / new_line
                  exact YAML lines for the textual migration rewrite
    reason        why the v1 value is wrong, template-first
    approved      review provenance; PENDING until explicitly approved
"""

CORRECTIONS = [
    {
        "label": "false_positive_ssl_inspection",
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
]


def for_label(label):
    return [c for c in CORRECTIONS if c["label"] == label]
