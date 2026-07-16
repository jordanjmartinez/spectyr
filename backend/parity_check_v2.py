"""Byte-identity parity diff: YAML v1 source vs YAML v2 source (Stage 0 gate).

Phase 1's ndjson-vs-yaml diff had agreed divergences (timestamps, dead legacy
keys). v2 has none: it wraps the same chain data, so the bar is BYTE-IDENTICAL
rendered event output. To prove it at the full pipeline level, this harness
renders every scenario through app.build_attack_chain_logs — the real producer,
including runtime decoration — with every nondeterminism source pinned:

    employee pick     forced to the same roster member (nkhan)
    offset jitter     random.seed(...) before each render
    INC alert id      same seeded rng
    log ids           uuid.uuid4 patched to a counter, reset per render
    timestamps        app.datetime patched to a frozen clock

Then it compares the JSON serialization of the full log lists. Any difference
on any field fails. Triage review dicts and label sets are compared for
equality too.

Run from backend/:  python parity_check_v2.py
Read-only: no flags flipped, no state written.
"""
import itertools
import json
import os
import random
import sys
import uuid as uuid_module
from datetime import datetime

os.environ["SPECTYR_SCENARIO_SOURCE"] = "yaml"  # app boots on the v1 catalog

import app  # noqa: E402
import scenario_corrections  # noqa: E402
import scenario_loader  # noqa: E402
import scenario_loader_v2  # noqa: E402

SEED = 20260715

# Approved schema corrections: v2 intentionally diverges from v1 on exactly
# these rendered values. Any other diff fails; a MISSING expected divergence
# also fails (it means the correction regressed).
#   step kind   -> exact (step, field, v1, v2) match
#   entity kind -> substitution rule: a diff is approved iff the v2 value is
#                  the v1 value with rendered_v1 replaced by rendered_v2
APPROVED_STEP = {}
APPROVED_SUBST = {}
for _c in scenario_corrections.CORRECTIONS:
    if _c["kind"] == "entity":
        APPROVED_SUBST.setdefault(_c["label"], []).append(
            (_c["rendered_v1"], _c["rendered_v2"], _c["approved"]))
    elif _c["kind"] == "step":
        APPROVED_STEP.setdefault(_c["label"], {})[(_c["step"], _c["field"])] = (
            _c["rendered_v1"], _c["rendered_v2"], _c["approved"])
    # triage corrections never touch rendered logs; handled in the
    # reviews comparison below


def _expected_reviews(v1_reviews):
    """v1 triage reviews with the approved triage corrections applied — the
    exact content the v2 corpus must carry."""
    import copy
    expected = copy.deepcopy(v1_reviews)
    for c in scenario_corrections.CORRECTIONS:
        if c["kind"] != "triage":
            continue
        node = expected[c["label"]]
        *parents, leaf = c["field"].split(".")
        for part in parents:
            node = node[part]
        if node.get(leaf) != c["v1"]:
            raise SystemExit(
                f"[FAIL] triage correction precondition: {c['label']} "
                f"{c['field']} is {node.get(leaf)!r}, expected {c['v1']!r}")
        node[leaf] = c["v2"]
    return expected


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 7, 15, 12, 0, 0, tzinfo=tz)


def _patched_uuid4_factory():
    counter = itertools.count()
    return lambda: f"00000000-0000-4000-8000-{next(counter):012d}"


def render_all(catalog, emp):
    app.yaml_catalog = catalog
    out = {}
    for label in sorted(catalog):
        random.seed(SEED)
        uuid_module.uuid4 = _patched_uuid4_factory()
        entry = {
            "scenario_label": label, "queue_position": 1,
            "ticket_title": "T", "storyline": "S", "category": "C",
        }
        logs = app.build_attack_chain_logs(
            {"used_alert_ids": set()}, entry, employee=emp)
        if logs is None:
            print(f"[FAIL] {label}: no chain rendered")
            sys.exit(1)
        out[label] = logs
    return out


def main():
    emp = next(e for e in app.EMPLOYEES if e["name"] == "nkhan")
    v1_catalog, v1_reviews = app.yaml_catalog, app.yaml_triage_reviews
    v2_catalog, v2_reviews = scenario_loader_v2.load_scenarios()

    failures = 0
    if set(v1_catalog) != set(v2_catalog):
        print(f"[FAIL] label sets differ: {set(v1_catalog) ^ set(v2_catalog)}")
        failures += 1
    expected_reviews = _expected_reviews(v1_reviews)
    if expected_reviews != v2_reviews:
        diff = [k for k in expected_reviews if expected_reviews[k] != v2_reviews.get(k)]
        print(f"[FAIL] triage reviews differ (after approved corrections) for: {diff}")
        failures += 1

    real_uuid4 = uuid_module.uuid4
    real_datetime = app.datetime
    try:
        app.datetime = _FrozenDatetime
        v1_out = render_all(v1_catalog, emp)
        v2_out = render_all(v2_catalog, emp)
    finally:
        uuid_module.uuid4 = real_uuid4
        app.datetime = real_datetime
        app.yaml_catalog = v1_catalog

    approved_total = 0
    for label in sorted(v1_out):
        if len(v1_out[label]) != len(v2_out[label]):
            print(f"[FAIL] {label}: {len(v1_out[label])} v1 logs vs "
                  f"{len(v2_out[label])} v2 logs")
            failures += 1
            continue
        diffs = []  # (step, field, v1_val, v2_val)
        for i, (la, lb) in enumerate(zip(v1_out[label], v2_out[label])):
            for k in sorted(set(la) | set(lb)):
                if k == "key_value_pairs":
                    ka, kb = la.get(k) or {}, lb.get(k) or {}
                    for kk in sorted(set(ka) | set(kb)):
                        if ka.get(kk) != kb.get(kk):
                            diffs.append((i, f"kvp.{kk}", ka.get(kk), kb.get(kk)))
                elif la.get(k) != lb.get(k):
                    diffs.append((i, k, la.get(k), lb.get(k)))

        approved = dict(APPROVED_STEP.get(label, {}))
        subst_rules = APPROVED_SUBST.get(label, [])
        subst_used = [0] * len(subst_rules)
        unexpected, matched = [], []
        for i, field, av, bv in diffs:
            want = approved.pop((i, field), None)
            if want and (av, bv) == want[:2]:
                matched.append((i, field, av, bv, want[2]))
                continue
            for ri, (r1, r2, prov) in enumerate(subst_rules):
                if (isinstance(av, str) and isinstance(bv, str)
                        and r1 in av and av.replace(r1, r2) == bv):
                    subst_used[ri] += 1
                    matched.append((i, field, av, bv, prov))
                    break
            else:
                unexpected.append((i, field, av, bv))
        unused_rules = [subst_rules[ri][:2] for ri, n in enumerate(subst_used) if n == 0]

        if unexpected:
            failures += 1
            print(f"[DIFF] {label}: {len(unexpected)} unapproved difference(s)")
            for i, field, av, bv in unexpected:
                print(f"        step {i} {field}: v1={av!r} v2={bv!r}")
        elif approved or unused_rules:
            failures += 1
            print(f"[FAIL] {label}: expected approved divergence(s) missing "
                  f"(correction regressed?): "
                  f"{sorted(approved) + unused_rules}")
        elif matched:
            approved_total += len(matched)
            print(f"[OK]   {label}: {len(v1_out[label])} logs, "
                  f"{len(matched)} approved divergence(s):")
            for i, field, av, bv, prov in matched:
                print(f"        step {i} {field}: {av!r} -> {bv!r} [{prov}]")
        else:
            print(f"[OK]   {label}: {len(v1_out[label])} logs byte-identical")

    print("=" * 60)
    if failures:
        print(f"PARITY FAILURES: {failures}")
        return 1
    note = (f" ({approved_total} approved divergence(s), listed above)"
            if approved_total else "")
    print(f"PARITY CLEAN: {len(v1_out)}/20 scenarios{note}; everything else "
          f"byte-identical (chain content, timestamps, ids, alert ids)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
