"""Stage 3.9B: the incident presentation-scope guards.

The scope read serves the player-visible incident scope from OBSERVABLE
attribution only (C1): event participants + the authoritative detection roster,
never scenario_grading / expected_actions / answer keys / grading config. These
tests prove the structural guard, the serialized-field leak guard, the A2
pre-seal total withholding, and that the observable roster matches the
readiness roster (so the Triage "X of Y" is consistent with the submission gate).

Run: python test_incident_scope.py  (or python -m pytest test_incident_scope.py -q)
"""
import inspect
import json
import os
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402

WS = "ACME-WS12"
STARTED = "2026-07-17T12:00:00+00:00"
INC = "INC-0001"
SID = "scenario-x"


def _api_session():
    client = app.app.test_client()
    sid = client.get("/api/health").headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def _seed(s, sealed=True, dispositioned=True):
    """One incident on WS: a written attack event (observable host), a
    scenario-tagged TP + an ambient benign on WS, a grading record scoped to WS
    (readiness), and a queue entry sealed iff `sealed`."""
    act = "dismissed" if dispositioned else "open"
    app._write_ndjson_unlocked(s["paths"]["generated_logs"], [{
        "id": "e1", "timestamp": STARTED, "scenario_id": SID, "label": "malware_usb",
        "category": "Malware", "alert_id": INC, "hostname": WS, "status": "active",
        "chain_complete": sealed, "severity": "high", "event_type": "1",
        "message": "seed", "source_type": "Sysmon",
        "key_value_pairs": {"account_name": "ACME\\nkhan"}}])
    s["incident_index"] = {INC: SID}
    s["alert_queue"] = [{"scenario_id": SID, "incident_id": INC, "queue_position": 1,
                         "ticket_title": "T", "injected_at": STARTED,
                         "chain_complete_at": STARTED if sealed else None,
                         "scenario_label": "malware_usb"}]
    s["queue_length"] = 1
    s["scenario_grading"] = [{"scenario_id": SID, "reviewed": True,
                              "hostnames": {WS}, "accounts": set()}]
    s["detections"] = [
        {"id": "det-tp", "scenario_id": SID, "disposition": "true_positive",
         "player_action": act, "entity": {"host": WS}},
        {"id": "det-amb", "scenario_id": None, "disposition": "benign_expected",
         "player_action": act, "entity": {"host": WS}},
        # unrelated ambient on a different host: must NOT be in this roster
        {"id": "det-other", "scenario_id": None, "disposition": "benign_expected",
         "player_action": "open", "entity": {"host": "ACME-WS99"}},
    ]


def test_scope_serializes_observable_fields_only():
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed(s)
        body = client.get(f"/api/incidents/{INC}/scope",
                          headers={"X-Session-ID": sid}).get_json()
        assert set(body) >= {"incident_id", "sealed", "hosts", "accounts",
                             "detection_ids"}
        assert body["incident_id"] == INC and body["sealed"] is True
        assert WS in body["hosts"] and "ACME\\nkhan" in body["accounts"]
        blob = json.dumps(body)
        for needle in ("scenario_id", "scenario-x", "category", "Malware",
                       "answer_key", "required", "expected", "disposition",
                       "true_positive"):
            assert needle not in blob, f"scope leaked {needle!r}"
    finally:
        _cleanup(sid, s)


def test_scope_withholds_roster_total_before_seal():
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed(s, sealed=False)
        pre = client.get(f"/api/incidents/{INC}/scope",
                         headers={"X-Session-ID": sid}).get_json()
        assert pre["sealed"] is False and "triage" not in pre  # A2: no total
        with s["io_lock"]:
            _seed(s, sealed=True, dispositioned=False)
        post = client.get(f"/api/incidents/{INC}/scope",
                          headers={"X-Session-ID": sid}).get_json()
        assert post["sealed"] is True
        assert post["triage"]["total"] == 2 and post["triage"]["triaged"] == 0
    finally:
        _cleanup(sid, s)


def test_scope_structural_no_grading_or_expected_actions():
    """C1: the scope-read implementation references no answer-key / grading
    input. Structural guard over the source, complementing the field leak check."""
    src = inspect.getsource(app._incident_observable_scope)
    src += inspect.getsource(app.incident_scope_route)
    for forbidden in ("expected_actions", "scenario_grading", "_grading_record_for",
                      "grading_rec", "answer_key"):
        assert forbidden not in src, f"scope read references {forbidden!r}"


def test_observable_roster_matches_readiness_roster():
    """The observable roster equals the readiness roster (`_incident_detections`),
    so the Triage 'X of Y' is consistent with the submission gate; the unrelated
    ambient on another host is excluded from both."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed(s)
            grec = app._grading_record_for(s, SID)
            readiness = {d["id"] for d in app._incident_detections(s, SID, grec)}
            observable = set(app._incident_observable_scope(s, INC)["roster_ids"])
        assert observable == readiness == {"det-tp", "det-amb"}
        assert "det-other" not in observable
    finally:
        _cleanup(sid, s)


def test_scope_unknown_incident_404():
    client, sid, s = _api_session()
    try:
        assert client.get("/api/incidents/INC-9999/scope",
                          headers={"X-Session-ID": sid}).status_code == 404
    finally:
        _cleanup(sid, s)


def test_list_withholds_roster_total_before_seal():
    """A2 parity on GET /api/incidents: a pre-seal active card carries no
    roster-derived total (no triage / open_detections / ready), while a sealed
    active card carries the observable triage counts."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            # INC (WS12) sealed + dispositioned; INC-0002 (WS20) NOT sealed
            _seed(s, sealed=True, dispositioned=True)
            logs = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
            logs.append({"id": "e2", "timestamp": STARTED, "scenario_id": "scenario-b",
                         "label": "phishing_1", "category": "Phishing", "alert_id": "INC-0002",
                         "hostname": "ACME-WS20", "status": "active", "chain_complete": False,
                         "severity": "high", "message": "seed", "source_type": "Sysmon"})
            app._write_ndjson_unlocked(s["paths"]["generated_logs"], logs)
            s["incident_index"]["INC-0002"] = "scenario-b"
            s["alert_queue"].append({"scenario_id": "scenario-b", "incident_id": "INC-0002",
                                     "queue_position": 2, "ticket_title": "T2",
                                     "injected_at": STARTED, "chain_complete_at": None,
                                     "scenario_label": "phishing_1"})
            s["detections"].append({"id": "det-b", "scenario_id": "scenario-b",
                                    "disposition": "true_positive", "player_action": "open",
                                    "entity": {"host": "ACME-WS20"}})
        body = client.get("/api/incidents", headers={"X-Session-ID": sid}).get_json()
        active = {c["incident_id"]: c for c in body["active"]}
        # pre-seal card: no roster total
        pre = active["INC-0002"]
        assert pre["sealed"] is False
        assert "triage" not in pre and "open_detections" not in pre and "ready" not in pre
        # sealed card: observable triage counts present
        sealed = active[INC]
        assert sealed["sealed"] is True and sealed["triage"]["total"] == 2
    finally:
        _cleanup(sid, s)


def _run_all():
    fns = [(n, f) for n, f in globals().items()
           if n.startswith("test_") and inspect.isfunction(f)]
    for n, f in sorted(fns):
        f()
        print(f"  ok  {n}")
    print(f"\n{len(fns)}/{len(fns)} incident-scope tests passed")


if __name__ == "__main__":
    _run_all()
