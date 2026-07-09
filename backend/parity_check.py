"""Seeded parity diff: NDJSON source vs YAML source.

For each of the 20 labels, builds the attack chain from both sources with the
SAME forced employee, then diffs the emitted logs field by field. Fields that
are non-deterministic by design are ignored:
  - id, scenario_id, alert_id : random/uuid per run
  - timestamp                 : YAML uses authored offsets, NDJSON uses random
                                3-8s gaps (agreed divergence)
  - level, level_name, storyline, category, alert_id, status, flagged, level:
    injected identically from the queue entry, not from the scenario source
  - detected_by               : legacy-only hint field, superseded by source_type

Everything an analyst actually reads in the Events/Alerts views (event_type,
source_type, severity, source_ip, destination_ip, hostname, message, and the
full key_value_pairs) must match exactly.

Run from backend/:
  python parity_check.py            # summary
  python parity_check.py -v         # + every field diff
Does NOT flip any flag or write state.
"""
import copy
import importlib
import os
import sys

# Import app once per source by toggling the env flag and reloading.
IGNORE = {
    "id", "scenario_id", "alert_id", "timestamp", "status", "flagged",
    "level", "level_name", "storyline", "category", "detected_by",
}

# threat_pattern is scenario-level metadata used only in an internal React key
# (never displayed). The NDJSON stored it per-log and one chain (pentest) is
# self-inconsistent across steps; the YAML normalizes it to the scenario mode.
# Reported in its own bucket, not as a content diff.
SCENARIO_LEVEL = {"threat_pattern"}

# YAML step schema intentionally dropped these legacy per-log keys; they are
# either re-injected at runtime (category, scenario_id) or dead metadata that
# nothing downstream reads. Presence-only differences on these are expected.
EXPECTED_KEY_DIFFS = {"log_source", "protocol", "user", "user_account"}


def build_all(source, employee):
    os.environ["SPECTYR_SCENARIO_SOURCE"] = source
    import app
    importlib.reload(app)
    emp = next(e for e in app.EMPLOYEES if e["name"] == employee)
    out = {}
    for label in sorted(app.attack_chains):
        entry = {
            "scenario_label": label, "queue_position": 1,
            "ticket_title": "T", "storyline": "S", "category": "C",
        }
        # deterministic gaps so timestamps line up too (we ignore them anyway)
        logs = app.build_attack_chain_logs({"used_alert_ids": set()}, entry, employee=emp)
        out[label] = logs
    return out


def norm(log):
    d = {k: v for k, v in log.items() if k not in IGNORE}
    return d


def diff_log(a, b):
    """Return list of (field, a_val, b_val) content differences on shared keys."""
    diffs = []
    for k in sorted(set(a) | set(b)):
        if k in IGNORE or k in SCENARIO_LEVEL:
            continue
        av, bv = a.get(k, "<MISSING>"), b.get(k, "<MISSING>")
        if k == "key_value_pairs":
            for kk in sorted(set(av or {}) | set(bv or {})):
                if (av or {}).get(kk) != (bv or {}).get(kk):
                    diffs.append((f"kvp.{kk}", (av or {}).get(kk), (bv or {}).get(kk)))
            continue
        if av != bv:
            diffs.append((k, av, bv))
    return diffs


def main():
    verbose = "-v" in sys.argv
    employee = "nkhan"
    nd = build_all("ndjson", employee)
    ya = build_all("yaml", employee)

    total_content_diffs = 0
    key_only_diffs = 0
    clean = 0
    tp_normalized = []
    for label in sorted(nd):
        # scenario-level threat_pattern: compare first-log value, report separately
        nd_tp = nd[label][0].get("threat_pattern", "")
        ya_tp = ya[label][0].get("threat_pattern", "")
        if nd_tp != ya_tp:
            tp_normalized.append((label, nd_tp, ya_tp))
        nlogs, ylogs = nd[label], ya[label]
        if len(nlogs) != len(ylogs):
            print(f"[LEN] {label}: ndjson {len(nlogs)} vs yaml {len(ylogs)}")
            total_content_diffs += 1
            continue
        label_content_diffs = []
        label_key_diffs = set()
        for i, (nl, yl) in enumerate(zip(nlogs, ylogs)):
            for field, av, bv in diff_log(norm(nl), norm(yl)):
                base = field.split(".")[0]
                missing = av == "<MISSING>" or bv == "<MISSING>"
                if missing and (field in EXPECTED_KEY_DIFFS or base in EXPECTED_KEY_DIFFS):
                    label_key_diffs.add(field)
                else:
                    label_content_diffs.append((i, field, av, bv))
        if label_content_diffs:
            total_content_diffs += len(label_content_diffs)
            print(f"[DIFF] {label}: {len(label_content_diffs)} content difference(s)")
            if verbose:
                for i, field, av, bv in label_content_diffs:
                    print(f"        step {i} {field}: ndjson={av!r} yaml={bv!r}")
        else:
            clean += 1
            if label_key_diffs:
                key_only_diffs += 1
        if verbose and label_key_diffs:
            print(f"[keys] {label}: expected key-only diffs {sorted(label_key_diffs)}")

    print(f"\n{'='*60}")
    print(f"clean (content-identical): {clean}/20")
    print(f"  of those, {key_only_diffs} have only expected legacy key-presence diffs")
    if tp_normalized:
        print(f"threat_pattern normalized (scenario-level, internal-only field): "
              f"{len(tp_normalized)}")
        for label, a, b in tp_normalized:
            print(f"    {label}: ndjson {a!r} -> yaml {b!r}")
    print(f"content differences: {total_content_diffs}")
    print("PARITY CLEAN" if total_content_diffs == 0 else "PARITY FAILURES ABOVE")
    return 0 if total_content_diffs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
