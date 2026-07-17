"""3d close-out, component 1: deterministic detection-order shuffle.

order_detections_for_client must derive order from the stable-key detection id:
deterministic within a session, independent of authoring/materialization order,
different across sessions, and never grouping authored-before-ambient.

Run: python test_detection_order.py  (or pytest)
"""
import random

import scenario_loader as sl
import scenario_loader_v2 as slv2
import snapshot_generator as sg
import detection_templates as dt

CATALOG, _ = slv2.load_scenarios()
EMP = [{"name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com",
        "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12"}]
SRV = {"dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200"},
       "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201"},
       "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202"},
       "print": {"hostname": "ACME-SVR04", "ip": "10.0.1.203"},
       "web": {"hostname": "ACME-SVR05", "ip": "10.0.1.204"},
       "proxy": {"hostname": "ACME-SVR06", "ip": "10.0.1.205"},
       "backup": {"hostname": "ACME-VEEAM01", "ip": "10.0.1.206"},
       "scan": {"hostname": "ACME-SEC01", "ip": "10.0.1.207"}}


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__(); self._forced = forced

    def choice(self, seq):
        return self._forced


def _materialize(label, seed):
    """(instances, views) for a scenario's full feed: authored + ambient."""
    sc = CATALOG[label]
    res = sl.resolve_entities(sc, EMP, SRV, rng=_Forced(EMP[0]))
    env = sl.substitute_deep(sc["environment"], res)
    logs, sup_logs, sup_meta = [], [], []
    for i, step in enumerate(sc["chain"]):
        lg = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, res)
        lg.update({"scenario_id": f"scenario-{label}",
                   "timestamp": f"2026-07-16T12:00:{i:02d}+00:00"})
        logs.append(lg)
    for sup in sc.get("supplemental_events", []):
        f = {k: v for k, v in sup.items() if k not in ("offset", "host", "user", "id")}
        lg = sl.substitute_deep(f, res); lg["timestamp"] = "2026-07-16T11:58:00+00:00"
        sup_logs.append(lg); sup_meta.append({"id": sup["id"], "host": sup["host"]})
    insts = dt.build_scenario_detections(f"scenario-{label}", sc, logs, seed,
                                         supplemental_logs=sup_logs,
                                         supplemental_meta=sup_meta, concrete_env=env)
    started = "2026-07-16T12:00:00+00:00"
    seen = set()
    for h in env["hosts"]:
        if h["role"] in sg.NON_ENDPOINT_ROLES or h["hostname"] in seen:
            continue
        seen.add(h["hostname"])
        owner = next((a for a in env.get("accounts", []) if a.get("host") == h["id"]), None)
        owner = {"username": owner["username"], "domain": owner.get("domain", "ACME")} if owner else None
        insts += dt.benign_detections_for_host(h, owner, seed, started)
    views = [dt.sanitize_detection(i) for i in insts]
    return insts, views


def test_order_is_deterministic_within_a_session():
    _, views = _materialize("lateral_movement_1", "seedA")
    a = [v["id"] for v in dt.order_detections_for_client(views)]
    b = [v["id"] for v in dt.order_detections_for_client(list(views))]
    assert a == b


def test_order_is_independent_of_input_order():
    _, views = _materialize("lateral_movement_1", "seedA")
    base = [v["id"] for v in dt.order_detections_for_client(views)]
    for _ in range(8):
        shuffled = list(views); random.shuffle(shuffled)
        assert [v["id"] for v in dt.order_detections_for_client(shuffled)] == base


def test_order_differs_across_sessions():
    # same scenario, different session seeds -> different order (ids re-hash).
    diffs = 0
    for label in ("lateral_movement_1", "malware_ransomware", "brute_force_attack"):
        _, va = _materialize(label, "sessionA")
        _, vb = _materialize(label, "sessionB")
        # match by rule_name sequence (ids themselves differ across sessions)
        oa = [v["rule_name"] for v in dt.order_detections_for_client(va)]
        ob = [v["rule_name"] for v in dt.order_detections_for_client(vb)]
        if oa != ob:
            diffs += 1
    assert diffs >= 2, "order should vary across sessions for most scenarios"


def test_not_authored_first_or_ambient_last():
    """A scenario with both authored and ambient detections must not present
    all authored before all ambient (the old time-sort tell)."""
    checked = 0
    for label in ("malware_ransomware", "lateral_movement_1", "brute_force_attack",
                  "phishing_link"):
        insts, views = _materialize(label, "seedX")
        kind = {i["id"]: ("ambient" if i["scenario_id"] is None else "authored")
                for i in insts}
        if not any(k == "ambient" for k in kind.values()):
            continue
        ordered = [kind[v["id"]] for v in dt.order_detections_for_client(views)]
        # authored-first would mean every 'authored' index < every 'ambient' index
        last_authored = max((i for i, k in enumerate(ordered) if k == "authored"),
                            default=-1)
        first_ambient = min((i for i, k in enumerate(ordered) if k == "ambient"),
                            default=len(ordered))
        assert not (last_authored < first_ambient), (
            f"{label}: authored-first grouping detected: {ordered}")
        checked += 1
    assert checked >= 2, "expected at least two scenarios with ambient detections"


def test_order_is_not_time_sorted():
    """Order must not follow the event timestamps (ambient share the session
    start time; a time sort would cluster them)."""
    _, views = _materialize("lateral_movement_1", "seedT")
    ordered = dt.order_detections_for_client(views)
    times = [v.get("time") or "" for v in ordered]
    assert times != sorted(times, reverse=True) or len(set(times)) == 1


if __name__ == "__main__":
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        fn(); print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
