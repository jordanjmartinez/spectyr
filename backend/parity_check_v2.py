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
import scenario_loader  # noqa: E402
import scenario_loader_v2  # noqa: E402

SEED = 20260715


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
    if v1_reviews != v2_reviews:
        diff = [k for k in v1_reviews if v1_reviews[k] != v2_reviews.get(k)]
        print(f"[FAIL] triage reviews differ for: {diff}")
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

    for label in sorted(v1_out):
        a = json.dumps(v1_out[label], sort_keys=True)
        b = json.dumps(v2_out[label], sort_keys=True)
        if a == b:
            print(f"[OK]   {label}: {len(v1_out[label])} logs byte-identical")
        else:
            failures += 1
            print(f"[DIFF] {label}")
            for i, (la, lb) in enumerate(zip(v1_out[label], v2_out[label])):
                for k in sorted(set(la) | set(lb)):
                    if la.get(k) != lb.get(k):
                        print(f"        step {i} {k}: v1={la.get(k)!r} v2={lb.get(k)!r}")

    print("=" * 60)
    if failures:
        print(f"PARITY FAILURES: {failures}")
        return 1
    print(f"PARITY CLEAN: {len(v1_out)}/20 scenarios byte-identical "
          f"(chain content, timestamps, ids, alert ids)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
