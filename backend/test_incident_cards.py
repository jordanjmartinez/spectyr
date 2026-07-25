"""Stage 5 Phase 2, D4 (ratified OD-8): the `related_actions` observable
count on active sealed incident cards.

Run: python test_incident_cards.py  (or python -m pytest test_incident_cards.py -q)

The count is the player's own successful action-log entries whose
registry-resolved target sits in the incident's OBSERVABLE scope (hosts +
accounts) -- a deliberately separate join from the grading-record join
(scaffold ruling D). Guards, landing in the same commit as the field (R2):
shape (int, active sealed cards only), count correctness (success only;
off-scope, failed, and no_op excluded; account targets via the sanctioned
resolver), and the structural no-answer-key guard: expected_actions and
scenario_grading content cannot influence the count.
"""
import os
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402

STARTED = "2026-07-17T12:00:00+00:00"
INC = "INC-4400"


def _api_session():
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def _fixture(s, expected_actions=None, grading=None):
    """A sealed one-incident session whose observable scope is exactly
    {ACME-WS12} + account nkhan (from the written event + tagged detection)."""
    with s["io_lock"]:
        app._write_ndjson_unlocked(s["paths"]["generated_logs"], [
            {"id": "e1", "timestamp": STARTED, "scenario_id": "scenario-m",
             "label": "malware_usb", "category": "Malware", "alert_id": INC,
             "level": 1, "level_name": "M", "status": "active",
             "chain_complete": True, "severity": "high",
             "hostname": "ACME-WS12", "message": "seed",
             "source_type": "Sysmon",
             "key_value_pairs": {"account_name": "nkhan"}}])
        s["incident_index"] = {INC: "scenario-m"}
        s["alert_queue"] = [{"scenario_id": "scenario-m", "incident_id": INC,
                             "queue_position": 1, "ticket_title": "M",
                             "injected_at": STARTED,
                             "chain_complete_at": STARTED,
                             "scenario_label": "malware_usb"}]
        s["queue_length"] = 1
        s["detections"] = [
            {"id": "det-1", "scenario_id": "scenario-m", "rule_name": "R1",
             "rule_type": "sigma_behavioral", "severity": "high",
             "description": "x", "entity": {"host": "ACME-WS12"},
             "time": STARTED, "player_action": "open",
             "disposition": "true_positive", "triggers": []}]
        s["detection_index"] = {d["id"]: d for d in s["detections"]}
        s["entity_index"] = {
            "ent-aaaaaaaaaaaa": {"kind": "host", "hostname": "ACME-WS12"},
            "ent-bbbbbbbbbbbb": {"kind": "host", "hostname": "ACME-OFF99"},
            "ent-cccccccccccc": {"kind": "process", "hostname": "ACME-WS12",
                                 "pid": 500, "name": "helper.exe"},
            "ent-dddddddddddd": {"kind": "account", "domain": "ACME",
                                 "username": "nkhan", "scope": "domain"},
            "ent-eeeeeeeeeeee": {"kind": "account", "domain": "ACME",
                                 "username": "outsider", "scope": "domain"},
        }
        s["overlay"]["log"] = [
            # counted: success on the observable host
            {"seq": 1, "timestamp": STARTED, "action": "isolate_host",
             "target": {"id": "ent-aaaaaaaaaaaa", "kind": "host",
                        "label": "ACME-WS12"},
             "outcome": "success", "reason": None},
            # counted: success on a process bound to the observable host
            {"seq": 2, "timestamp": STARTED, "action": "kill_process",
             "target": {"id": "ent-cccccccccccc", "kind": "process",
                        "label": "helper.exe (PID 500) on ACME-WS12"},
             "outcome": "success", "reason": None},
            # counted: success on the observable account (resolver join)
            {"seq": 3, "timestamp": STARTED, "action": "disable_account",
             "target": {"id": "ent-dddddddddddd", "kind": "account",
                        "label": "ACME\\nkhan"},
             "outcome": "success", "reason": None},
            # NOT counted: success on an off-scope host
            {"seq": 4, "timestamp": STARTED, "action": "isolate_host",
             "target": {"id": "ent-bbbbbbbbbbbb", "kind": "host",
                        "label": "ACME-OFF99"},
             "outcome": "success", "reason": None},
            # NOT counted: success on an off-scope account
            {"seq": 5, "timestamp": STARTED, "action": "disable_account",
             "target": {"id": "ent-eeeeeeeeeeee", "kind": "account",
                        "label": "ACME\\outsider"},
             "outcome": "success", "reason": None},
            # NOT counted: failed attempt on the observable host
            {"seq": 6, "timestamp": STARTED, "action": "isolate_host",
             "target": {"id": "ent-aaaaaaaaaaaa", "kind": "host",
                        "label": "ACME-WS12"},
             "outcome": "failed_precondition", "reason": "x"},
            # NOT counted: no_op repeat on the observable host
            {"seq": 7, "timestamp": STARTED, "action": "isolate_host",
             "target": {"id": "ent-aaaaaaaaaaaa", "kind": "host",
                        "label": "ACME-WS12"},
             "outcome": "no_op", "reason": "Host is already isolated."},
        ]
        s["overlay"]["seq"] = 7
        s["expected_actions"] = list(expected_actions or [])
        s["scenario_grading"] = list(grading or [])


def _card(client, sid):
    body = client.get("/api/incidents", headers={"X-Session-ID": sid}).get_json()
    assert len(body["active"]) == 1
    return body["active"][0]


def test_related_actions_counts_observable_scope_successes_only():
    client, sid, s = _api_session()
    try:
        _fixture(s)
        card = _card(client, sid)
        assert card["sealed"] is True
        # 3 successes in observable scope; off-scope + failed + no_op excluded
        assert card["related_actions"] == 3
        assert isinstance(card["related_actions"], int)
    finally:
        _cleanup(sid, s)


def test_related_actions_absent_pre_seal_and_on_completed_cards():
    client, sid, s = _api_session()
    try:
        _fixture(s)
        with s["io_lock"]:
            # unseal: chain_complete_at removed -> pre-seal card
            s["alert_queue"][0]["chain_complete_at"] = None
            logs = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
            for l in logs:
                l["chain_complete"] = False
            app._write_ndjson_unlocked(s["paths"]["generated_logs"], logs)
        card = _card(client, sid)
        assert card["sealed"] is False
        assert "related_actions" not in card
        assert "triage" not in card
    finally:
        _cleanup(sid, s)


def test_related_actions_is_answer_key_independent_structurally():
    """The structural no-answer-key guard over the new reader: the count is
    byte-identical whether expected_actions / scenario_grading are empty or
    carry planted answer-key content naming entirely different targets."""
    client, sid, s = _api_session()
    try:
        _fixture(s)
        baseline = _card(client, sid)["related_actions"]
        with s["io_lock"]:
            s["expected_actions"] = [
                {"scenario_id": "scenario-m", "eid": "planted", "action":
                 "isolate_host", "status": "required",
                 "target": {"hostname": "ACME-PLANTED-MARKER-77"},
                 "after": []}]
            s["scenario_grading"] = [
                {"scenario_id": "scenario-m", "reviewed": True,
                 "hostnames": {"ACME-PLANTED-MARKER-77"},
                 "accounts": {("acme", "planted")}}]
        assert _card(client, sid)["related_actions"] == baseline
        # and the planted marker never serializes anywhere on the card list
        body = client.get("/api/incidents",
                          headers={"X-Session-ID": sid}).get_json()
        assert "PLANTED-MARKER" not in str(body)
    finally:
        _cleanup(sid, s)


def _main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} passed")


if __name__ == "__main__":
    _main()
