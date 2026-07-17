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
    "scan": {"hostname": "ACME-SEC01", "ip": "10.0.1.207"},
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
    """Render the attack chain AND supplemental events, mirroring the drip.
    Returns (sc, attack_logs, sup_logs, sup_meta, concrete_env)."""
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=_Forced(EMPLOYEES[0]))
    env = sl.substitute_deep(sc["environment"], resolved)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        # decorate like build_attack_chain_logs would (the leaky fields)
        log.update({"scenario_id": f"scenario-{label}", "label": label,
                    "category": sc["category"], "level": 3, "flagged": True,
                    "alert_id": "INC-9999", "storyline": "secret",
                    "timestamp": f"2026-07-16T12:00:{i:02d}+00:00", "status": "active"})
        logs.append(log)
    sup_logs, sup_meta = [], []
    for sup in sc.get("supplemental_events", []):
        fields = {k: v for k, v in sup.items() if k not in ("offset", "host", "user", "id")}
        log = sl.substitute_deep(fields, resolved)
        log.update({"category": "Benign", "status": "active",
                    "timestamp": "2026-07-16T11:58:00+00:00"})
        sup_logs.append(log)
        m = {"id": sup["id"], "host": sup["host"]}
        if "user" in sup:
            m["user"] = sup["user"]
        sup_meta.append(m)
    return sc, logs, sup_logs, sup_meta, env


def _build(label, scenario_id=None):
    sc, logs, sup_logs, sup_meta, env = _render(label)
    return dt.build_scenario_detections(
        scenario_id or f"scenario-{label}", sc, logs, SEED,
        supplemental_logs=sup_logs, supplemental_meta=sup_meta, concrete_env=env)


def _assert_clean(payload):
    blob = json.dumps(payload)
    for bad in FORBIDDEN:
        assert f'"{bad}"' not in blob, f"forbidden field {bad!r} leaked: {blob[:200]}"


def test_scenario_detection_builds_and_carries_disposition():
    dets = _build("lateral_movement_1")
    # density pilot: 2 TP + 1 coexisting FP (the FP triggers on a supplemental
    # event, so it only resolves when supplemental logs are rendered too)
    assert len(dets) == 3
    keys = {d["detection_key"]: d["disposition"] for d in dets}
    assert keys["det_lateral_logon"] == "true_positive"
    assert keys["det_portscan_exec"] == "true_positive"
    assert keys["det_scanner_sweep"] == "false_positive"
    for inst in dets:
        assert inst["scenario_id"] == "scenario-lateral_movement_1"
        assert inst["triggering_events"], "detail card needs the trigger event"


def test_supplemental_triggered_detection_entity_is_actor():
    """The scanner-sweep FP triggers on a firewall supplemental event; its
    entity resolves to the scanner host (source), not the firewall."""
    dets = _build("lateral_movement_1")
    sweep = next(d for d in dets if d["detection_key"] == "det_scanner_sweep")
    assert sweep["entity"]["host"] == "ACME-SEC01"


def test_sanitize_strips_disposition_and_linkage():
    for inst in _build("lateral_movement_1"):
        for include in (False, True):
            view = dt.sanitize_detection(inst, include_events=include)
            _assert_clean(view)
            assert "disposition" not in view
            assert view["rule_name"] == inst["rule_name"]


def test_sanitized_triggering_events_are_whitelisted():
    for label in ("malware_usb", "lateral_movement_1"):
        for inst in _build(label):
            view = dt.sanitize_detection(inst, include_events=True)
            for ev in view["triggering_events"]:
                assert set(ev).issubset(set(dt.EVENT_WHITELIST)), ev
            _assert_clean(view)


def test_fp_scenario_detection_disposition():
    dets = _build("false_positive_veeam")
    assert len(dets) == 3  # density pilot 2: all TP-looking FPs
    assert all(d["disposition"] == "false_positive" for d in dets)
    sevs = {d["severity"] for d in dets}
    assert "critical" in sevs and "medium" in sevs, "FPs must span severities"
    for inst in dets:
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
        for inst in _build(label):
            _assert_clean(dt.sanitize_detection(inst, include_events=True))


def test_supplemental_events_never_carry_answer_fields():
    """Supplemental benign telemetry, rendered into the pool, must carry no
    disposition/answer field and sanitize like any event."""
    for label in CATALOG:
        _, _, sup_logs, _, _ = _render(label)
        for log in sup_logs:
            blob = json.dumps(log)
            for bad in ("disposition", "answer_key", "true_positive",
                        "false_positive", "benign_expected"):
                assert bad not in blob, f"{label}: supplemental event leaked {bad}"
            assert set(dt.sanitize_event(log)).issubset(set(dt.EVENT_WHITELIST))


def test_all_tp_scenario_has_ambient_dismissables():
    """Batch 2 binding: an all-TP scenario (malware_ransomware) is only valid
    if the feed also carries ambient benign dismissables. The victim
    workstation always yields at least one ambient benign detection."""
    sc = CATALOG["malware_ransomware"]
    assert all(d["disposition"] == "true_positive" for d in sc["detections"])
    assert len(sc["detections"]) >= 3
    # the workstation the scenario runs on always has >= 1 ambient benign
    ws = next(h for h in sc["environment"]["hosts"] if h["role"] == "workstation")
    host = {"id": ws["id"], "role": "workstation",
            "hostname": ws["hostname"].replace("{victim.hostname}", "ACME-WS12"),
            "ip": "10.0.1.12"}
    owner = {"username": "nkhan", "domain": "ACME"}
    benign = dt.benign_detections_for_host(host, owner, SEED, "2026-07-16T12:00:00+00:00")
    assert len(benign) >= 1, "all-TP scenario has no discoverable dismissables"
    assert all(b["disposition"] == "benign_expected" for b in benign)


def test_density_no_single_authored_detection():
    """Densified scenarios (pilots + batch 1) have more than one authored
    detection. The corpus-wide invariant lands at 3d close-out."""
    densified = ("lateral_movement_1", "false_positive_veeam", "malware_usb",
                 "c2_http", "password_spray", "false_positive_pentest",
                 "lateral_movement_2", "malware_ransomware",
                 "data_exfil_archive", "false_positive_oauth",
                 "defense_evasion", "c2_dns_tunnel", "insider_shadow_it",
                 "false_positive_robocopy", "brute_force_attack",
                 "insider_staging", "phishing_1")
    for label in densified:
        assert len(CATALOG[label]["detections"]) >= 2, label


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
