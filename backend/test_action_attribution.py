"""Stage 6 per-case attribution guards.

The owner-ruled attribution model: every response action is stamped at
execution time with the incident it was taken under, and each incident's
grade is computed ONLY over its own attributed actions. These are the
permanent regression guards for the defect class that motivated it: one
incident's correct action being re-judged by every other submitted
incident's answer key (cross-charging, employee-collision zeros,
submit-order dependence).

Run: python test_action_attribution.py
"""
import json
import os
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402

STARTED = "2026-07-17T12:00:00+00:00"
WS = "ACME-WS12"

INC_A = "INC-1001"   # attack incident
INC_B = "INC-1002"   # inaction-correct (FP) incident sharing the host
SCEN_A = "scenario-attack"
SCEN_B = "scenario-fp"


def _api_session():
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def _seed_two_incidents(s, overlay_log, isolated=frozenset(),
                        expected_a=None):
    """Two sealed, detection-free (= submission-ready) incidents whose
    grading scopes BOTH claim the same workstation: the attack scenario A
    and the FP inaction unit B. The employee-collision configuration."""
    app._write_ndjson_unlocked(s["paths"]["generated_logs"], [
        {"id": "e1", "timestamp": STARTED, "scenario_id": SCEN_A,
         "label": "attack_fixture", "category": "Malware", "alert_id": INC_A,
         "hostname": WS, "status": "active", "chain_complete": True,
         "severity": "high", "message": "seed", "source_type": "Sysmon"},
        {"id": "e2", "timestamp": STARTED, "scenario_id": SCEN_B,
         "label": "fp_fixture", "category": "False Positive", "alert_id": INC_B,
         "hostname": WS, "status": "active", "chain_complete": True,
         "severity": "low", "message": "seed", "source_type": "Sysmon"},
    ])
    s["incident_index"] = {INC_A: SCEN_A, INC_B: SCEN_B}
    s["alert_queue"] = [
        {"scenario_id": SCEN_A, "incident_id": INC_A, "queue_position": 1,
         "ticket_title": "A", "injected_at": STARTED,
         "chain_complete_at": STARTED, "scenario_label": "attack_fixture"},
        {"scenario_id": SCEN_B, "incident_id": INC_B, "queue_position": 2,
         "ticket_title": "B", "injected_at": STARTED,
         "chain_complete_at": STARTED, "scenario_label": "fp_fixture"},
    ]
    s["queue_length"] = 2
    s["expected_actions"] = list(expected_a if expected_a is not None else [
        {"scenario_id": SCEN_A, "eid": None, "action": "kill_process",
         "status": "required", "target": {"hostname": WS, "pid": 4756},
         "after": []},
    ])
    s["scenario_grading"] = [
        {"scenario_id": SCEN_A, "reviewed": True,
         "hostnames": {WS}, "accounts": set()},
        {"scenario_id": SCEN_B, "reviewed": True,
         "hostnames": {WS}, "accounts": set()},
    ]
    s["entity_index"] = {
        "ent-aaaa11112222": {"kind": "host", "hostname": WS},
        "ent-cccc11112222": {"kind": "process", "hostname": WS,
                             "pid": 4756, "name": "payload.exe"},
    }
    s["overlay"]["log"] = list(overlay_log)
    s["overlay"]["isolated"] = set(isolated)
    s["overlay"]["seq"] = max((e["seq"] for e in overlay_log), default=0)


def _submit(client, sid, incident, verdict, category=None):
    payload = {"verdict": verdict}
    if category:
        payload["category"] = category
    return client.post(f"/api/incidents/{incident}/submit",
                       headers={"X-Session-ID": sid}, json=payload)


def _kill_entry(seq, incident_id):
    return {"seq": seq, "timestamp": STARTED, "action": "kill_process",
            "target": {"id": "ent-cccc11112222", "kind": "process",
                       "label": f"payload.exe (PID 4756) on {WS}"},
            "outcome": "success", "reason": None, "incident_id": incident_id}


def _iso_entry(seq, action, incident_id):
    return {"seq": seq, "timestamp": STARTED, "action": action,
            "target": {"id": "ent-aaaa11112222", "kind": "host", "label": WS},
            "outcome": "success", "reason": None, "incident_id": incident_id}


def test_no_cross_charge_required_action_never_zeroes_shared_scope_fp():
    """THE regression guard (red on the pre-Stage-6 pooled scorer): a
    required kill executed under attack incident A, whose target host the
    FP incident B's grading scope also claims, credits A in full and
    leaves B's intentional inaction intact. Before attribution this exact
    configuration charged the kill as collateral in B and zeroed it."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_two_incidents(s, [_kill_entry(1, INC_A)])
        assert _submit(client, sid, INC_A, "threat", "Malware").status_code == 200
        assert _submit(client, sid, INC_B, "false_positive").status_code == 200
        with s["io_lock"]:
            rc_a = s["submissions"][INC_A]["report_card"]
            rc_b = s["submissions"][INC_B]["report_card"]
        assert rc_a["response"]["correct"] == 1
        assert rc_a["response"]["accuracy"] == 100.0
        assert rc_b["response"]["collateral"] == 0
        assert rc_b["_inaction_collateral"] is False
        assert rc_b["response"]["accuracy"] == 100.0, \
            "a correct action for A zeroed B's intentional inaction"
        codes = {e["reason_code"] for e in rc_b["response_review"]["entries"]}
        assert "inaction_correct" in codes and "collateral_in_scope" not in codes
    finally:
        _cleanup(sid, s)


def test_submit_order_independence_byte_identical_response_sections():
    """Identical analyst work must grade identically regardless of submit
    order: A-then-B and B-then-A yield byte-identical per-incident response
    sections (the pooled scorer graded them differently because B's scorer
    saw A's actions only if they existed at B's submit)."""
    def run(order):
        client, sid, s = _api_session()
        try:
            with s["io_lock"]:
                _seed_two_incidents(s, [_kill_entry(1, INC_A)])
            for inc in order:
                if inc == INC_A:
                    assert _submit(client, sid, inc, "threat",
                                   "Malware").status_code == 200
                else:
                    assert _submit(client, sid, inc,
                                   "false_positive").status_code == 200
            with s["io_lock"]:
                return {
                    inc: json.dumps(
                        {"response": s["submissions"][inc]["report_card"]["response"],
                         "raw": s["submissions"][inc]["report_card"]["_response_raw"],
                         "inaction": s["submissions"][inc]["report_card"]["_inaction_collateral"],
                         "review": s["submissions"][inc]["report_card"]["response_review"]["entries"]},
                        sort_keys=True)
                    for inc in (INC_A, INC_B)}
        finally:
            _cleanup(sid, s)

    ab = run([INC_A, INC_B])
    ba = run([INC_B, INC_A])
    assert ab[INC_A] == ba[INC_A], "A's grade depends on submit order"
    assert ab[INC_B] == ba[INC_B], "B's grade depends on submit order"


def test_isolation_ownership_latest_isolate_wins_end_state():
    """Per-case isolation ownership: isolate under A, release, re-isolate
    under B. A keeps only the occurrence (end-state forfeited:
    released_after_isolation), B owns the live isolation and earns its
    required-isolation credit; the frozen records' isolation_end_state
    carries the ownership split."""
    client, sid, s = _api_session()
    try:
        expected = [
            {"scenario_id": SCEN_A, "eid": None, "action": "isolate_host",
             "status": "required", "target": {"hostname": WS}, "after": []},
            {"scenario_id": SCEN_B, "eid": None, "action": "isolate_host",
             "status": "required", "target": {"hostname": WS}, "after": []},
        ]
        log = [
            _iso_entry(1, "isolate_host", INC_A),
            _iso_entry(2, "release_host", INC_A),
            _iso_entry(3, "isolate_host", INC_B),
        ]
        with s["io_lock"]:
            _seed_two_incidents(s, log, isolated={WS}, expected_a=expected)
        assert _submit(client, sid, INC_A, "threat", "Malware").status_code == 200
        assert _submit(client, sid, INC_B, "threat", "Malware").status_code == 200
        with s["io_lock"]:
            rec_a = s["submissions"][INC_A]
            rec_b = s["submissions"][INC_B]
        assert rec_a["inputs"]["isolation_end_state"] == []
        assert rec_b["inputs"]["isolation_end_state"] == [WS]
        assert rec_a["inputs"]["attributed_action_seqs"] == [1, 2]
        assert rec_b["inputs"]["attributed_action_seqs"] == [3]
        codes_a = {e["reason_code"]
                   for e in rec_a["report_card"]["response_review"]["entries"]}
        assert "released_after_isolation" in codes_a
        assert rec_a["report_card"]["response"]["correct"] == 0
        assert rec_b["report_card"]["response"]["correct"] == 1
        assert rec_b["report_card"]["response"]["accuracy"] == 100.0
    finally:
        _cleanup(sid, s)


def test_unattributed_legacy_entries_are_grading_inert():
    """Entries without an attribution stamp (direct-harness writes) belong
    to no case: they never credit, never charge, and never spoil inaction."""
    client, sid, s = _api_session()
    try:
        legacy = _kill_entry(1, None)
        legacy.pop("incident_id")
        with s["io_lock"]:
            _seed_two_incidents(s, [legacy])
        assert _submit(client, sid, INC_A, "threat", "Malware").status_code == 200
        assert _submit(client, sid, INC_B, "false_positive").status_code == 200
        with s["io_lock"]:
            rc_a = s["submissions"][INC_A]["report_card"]
            rc_b = s["submissions"][INC_B]["report_card"]
        assert rc_a["response"]["correct"] == 0, "an unattributed entry credited"
        assert rc_b["response"]["collateral"] == 0
        assert rc_b["response"]["accuracy"] == 100.0
    finally:
        _cleanup(sid, s)


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
