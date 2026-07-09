"""Analyst-mode fairness check.

In Analyst mode only a scenario's trigger step(s) are shown; the rest of the
chain must be reconstructable by pivoting on a shared entity. This asserts that
property statically for every scenario:

  for each non-trigger step, the set of resolved entity VALUES it contains must
  intersect the union of entity values across the trigger step(s).

If a step shares no entity value with any trigger, an analyst pivoting from the
trigger could never reach it -> a dead end -> the scenario is unfair. Such a
scenario needs another trigger marked (or an entity added) before it ships.

Run from backend/:  python fairness_check.py
Exit 0 = all reachable; non-zero lists the dead ends.
"""
import random
import sys

import scenario_loader as sl

# One fixed roster/servers fixture; entity VALUES (not fields) are what a pivot
# filters on, so we resolve once and scan the emitted strings.
EMPLOYEES = [{
    "name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com",
    "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12",
}]
SERVERS = {
    "dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200"},
    "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201"},
    "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202"},
    "print": {"hostname": "ACME-SVR04", "ip": "10.0.1.203"},
    "web": {"hostname": "ACME-SVR05", "ip": "10.0.1.204"},
    "proxy": {"hostname": "ACME-SVR06", "ip": "10.0.1.205"},
}

# Pivotable entity values: victim host/user/ip + any static entity's values.
# (infra/server values are shared by unrelated normal traffic, so they don't
# count as a distinguishing pivot — a pivot on 10.0.1.200 returns the whole
# domain's auth noise, not this chain.)
def pivot_values(scenario, resolved):
    vals = set()
    for name, spec in scenario["entities"].items():
        if name == "infra":
            continue
        for field, v in resolved.get(name, {}).items():
            if v:
                vals.add(str(v))
    return vals


def step_values(step, pivots):
    """Which pivot values appear anywhere in this resolved step."""
    import json
    blob = json.dumps(step)
    return {v for v in pivots if v in blob}


def main():
    catalog, _ = sl.load_scenarios()
    rng = random.Random(0)
    failures = []
    for label, sc in sorted(catalog.items()):
        resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=rng)
        chain = sl.substitute_deep(sc["chain"], resolved)
        pivots = pivot_values(sc, resolved)

        trig_idx = [i for i, s in enumerate(sc["chain"]) if s.get("trigger")]
        if not trig_idx:
            failures.append((label, "no trigger step marked"))
            continue

        trigger_vals = set()
        for i in trig_idx:
            trigger_vals |= step_values(chain[i], pivots)

        for i, step in enumerate(chain):
            if i in trig_idx:
                continue
            reachable = step_values(step, pivots) & trigger_vals
            if not reachable:
                failures.append(
                    (label, f"step {i} ({sc['chain'][i].get('event_type')}) shares "
                            f"no entity value with any trigger")
                )

        # report the pivot the analyst would use
        shared = sorted(trigger_vals)
        print(f"{label:32} trigger step(s) {trig_idx}  pivot on: {shared}")

    print()
    if failures:
        print(f"UNFAIR — {len(failures)} dead end(s):")
        for label, why in failures:
            print(f"  {label}: {why}")
        return 1
    print(f"FAIR — all {len(catalog)} scenarios fully reachable by entity pivot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
