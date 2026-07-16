"""Tests for the Stage 2 detections feed, including the leak guard.

Run: python -m pytest test_detections.py -q  (or python test_detections.py)

The critical property (ratified): a detection's answer-key disposition, its
scenario linkage, and any scoring field must NEVER survive serialization to
the client. sanitize_detection is the only path to the client.
"""
import json
import random

import scenario_loader as sl
import scenario_loader_v2 as slv2
import detection_templates as dt

EMPLOYEES = [
    {"name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com",
     "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12"},
]
SERVERS = {
    "dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200"},
    "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201"},
    "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202"},
    "print": {"hostname": "ACME-SVR04", "ip": "10.0.1.203"},
    "web": {"hostname": "ACME-SVR05", "ip": "10.0.1.204"},
    "proxy": {"hostname": "ACME-SVR06", "ip": "10.0.1.205"},
    "backup": {"hostname": "ACME-VEEAM01", "ip": "10.0.1.206"},
}
CATALOG, _ = slv2.load_scenarios()
SEED = "test-session-det"

# Fields that must never appear anywhere in a client payload.
FORBIDDEN = ("disposition", "scenario_id", "detection_key", "label",
             "category", "analyst_category", "category_correct", "flagged",
             "level", "level_name", "storyline", "alert_id", "answer_key")


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__()
        self._forced = forced

    def choice(self, seq):
        return self._forced


def _render(label):
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=_Forced(EMPLOYEES[0]))
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        # decorate like build_attack_chain_logs would (the leaky fields)
        log.update({"scenario_id": f"scenario-{label}", "label": label,
                    "category": sc["category"], "level": 3, "flagged": True,
                    "alert_id": "INC-9999", "storyline": "secret",
                    "timestamp": f"2026-07-16T12:00:{i:02d}+00:00", "status": "active"})
        logs.append(log)
    return sc, logs


def _assert_clean(payload):
    blob = json.dumps(payload)
    for bad in FORBIDDEN:
        assert f'"{bad}"' not in blob, f"forbidden field {bad!r} leaked: {blob[:200]}"


def test_scenario_detection_builds_and_carries_disposition():
    sc, logs = _render("lateral_movement_1")
    dets = dt.build_scenario_detections("scenario-lm1", sc, logs, SEED)
    assert len(dets) == 1
    inst = dets[0]
    assert inst["disposition"] == "true_positive"       # server-side present
    assert inst["scenario_id"] == "scenario-lm1"
    assert inst["rule_name"]
    assert inst["triggering_events"], "detail card needs the trigger event"


def test_sanitize_strips_disposition_and_linkage():
    sc, logs = _render("lateral_movement_1")
    inst = dt.build_scenario_detections("scenario-lm1", sc, logs, SEED)[0]
    for include in (False, True):
        view = dt.sanitize_detection(inst, include_events=include)
        _assert_clean(view)
        assert "disposition" not in view
        assert view["rule_name"] == inst["rule_name"]


def test_sanitized_triggering_events_are_whitelisted():
    sc, logs = _render("malware_usb")
    inst = dt.build_scenario_detections("scenario-usb", sc, logs, SEED)[0]
    view = dt.sanitize_detection(inst, include_events=True)
    for ev in view["triggering_events"]:
        assert set(ev).issubset(set(dt.EVENT_WHITELIST)), ev
    _assert_clean(view)


def test_fp_scenario_detection_disposition():
    sc, logs = _render("false_positive_veeam")
    inst = dt.build_scenario_detections("scenario-veeam", sc, logs, SEED)[0]
    assert inst["disposition"] == "false_positive"
    _assert_clean(dt.sanitize_detection(inst, include_events=True))


def test_benign_detections_deterministic_and_benign():
    host = {"id": "ws_victim", "role": "workstation", "hostname": "ACME-WS12", "ip": "10.0.1.12"}
    owner = {"username": "nkhan", "domain": "ACME"}
    a = dt.benign_detections_for_host(host, owner, SEED, "2026-07-16T12:00:00+00:00")
    b = dt.benign_detections_for_host(host, owner, SEED, "2026-07-16T12:00:00+00:00")
    assert json.dumps(a) == json.dumps(b), "benign detections must be deterministic"
    for inst in a:
        assert inst["disposition"] == "benign_expected"
        assert inst["scenario_id"] is None
        _assert_clean(dt.sanitize_detection(inst, include_events=True))


def test_benign_only_on_eligible_roles():
    # a DNS server (PAN-OS-adjacent role) still Windows, but proxy/firewall are
    # excluded by the caller; here confirm role gating picks eligible templates
    dc = {"id": "dc", "role": "dc", "hostname": "ACME-SVR01", "ip": "10.0.1.200"}
    dets = dt.benign_detections_for_host(dc, None, SEED, "2026-07-16T12:00:00+00:00")
    for inst in dets:
        # every benign detection assigned to the dc must list dc in its roles
        key = inst["detection_key"]
        tmpl = next(t for t in dt.BENIGN_DETECTIONS if t[0] == key)
        assert "dc" in tmpl[3], f"{key} not eligible for dc"


def test_whole_corpus_detections_sanitize_clean():
    for label in CATALOG:
        sc, logs = _render(label)
        for inst in dt.build_scenario_detections(f"scenario-{label}", sc, logs, SEED):
            _assert_clean(dt.sanitize_detection(inst, include_events=True))


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
