"""Stage 5 Phase 5: the response-review teaching layer (contract 7.1-7.5;
ratified OD-1..OD-4; scaffold ruling B conditions).

Run: python test_response_review.py

Commit 5.1 rows: the binding reason-code registry; Tier 1 template purity
(purpose only, the two contract examples byte-canonical, no scenario token
beyond nothing at all -- whys are label-free by construction).
Commit 5.2 rows: every registry code fixture-pinned to the scorer's own
verdict (R1: reuse, not reimplementation); the popped `_review` detail
leaves the public score dict byte-identical; the 19.16 count
reconciliation over fixtures (both fold-in mappings).
Commit 5.3 rows: the frozen record (freeze completeness, byte-identity,
404/absence, planted markers over the ENUMERATED pre-submission surfaces,
aggregate-shape assertion, empty states) plus the real-drip corpus
reconciliation pass.
"""
import copy
import json
import os
import shutil
from datetime import datetime, timezone

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402
import response_review as rr  # noqa: E402
import sim_epoch  # noqa: E402

WS = "ACME-WS12"
SVR = "ACME-SVR02"
STARTED = "2026-07-17T12:00:00+00:00"
INC = "INC-0001"
SCEN = "scenario-x"

GRADING = [{"scenario_id": "scenario-x", "reviewed": True,
            "hostnames": {WS, SVR},
            "accounts": {("acme", "nkhan"), ("acme", "innocent")}}]


def _exp(action, target, eid=None, after=None, scenario="scenario-x",
         status="required"):
    return {"scenario_id": scenario, "eid": eid, "action": action,
            "status": status, "target": target, "after": list(after or [])}


def _run(action, target, seq):
    return {"seq": seq, "action": action, "target": target}


def _score(expected, executed, isolated, grading=None):
    return app.compute_action_score(expected, executed, isolated,
                                    GRADING if grading is None else grading)


def _entries(result):
    return result["_review"]["entries"]


def _codes(result):
    return sorted(e["reason_code"] for e in _entries(result))


# --- 5.1: registry + templates ------------------------------------------------

def test_registry_buckets_are_the_binding_71_set():
    assert rr.BUCKET_OF == {
        "required_completed": "completed",
        "required_not_attempted": "missed",
        "required_attempt_failed": "missed",
        "out_of_order": "missed",
        "released_after_isolation": "missed",
        "acceptable_completed": "acceptable",
        "collateral_in_scope": "collateral",
        "inaction_correct": "inaction",
        "inaction_spoiled": "inaction",
    }


def test_contract_canonical_examples_render_byte_exact():
    assert rr.render_why(rr.REQUIRED_NOT_ATTEMPTED, "isolate_host") == (
        "Isolating an implicated host cuts an attacker's access to it while "
        "the investigation continues. This host required isolation and was "
        "not isolated at submission.")
    assert rr.render_why(rr.COLLATERAL_IN_SCOPE, "kill_process") == (
        "This action was not part of the expected response for this "
        "incident. Acting on targets the evidence does not implicate "
        "disrupts clean assets.")
    assert rr.render_why(rr.INACTION_CORRECT, None) == (
        "No response action was required. The correct response here was "
        "investigation without action.")


def test_template_purity_no_scenario_tokens_and_deterministic():
    """Purpose-only rule (correction 4): whys are label-free and identical
    regardless of any target; no hostname, account, path, or scenario token
    can appear because none is ever passed in."""
    verbs = ["isolate_host", "kill_process", "delete_file", "disable_account",
             "revoke_sessions", "force_password_reset", "remove_persistence"]
    codes = [rr.REQUIRED_COMPLETED, rr.REQUIRED_NOT_ATTEMPTED,
             rr.REQUIRED_ATTEMPT_FAILED, rr.OUT_OF_ORDER,
             rr.ACCEPTABLE_COMPLETED]
    for v in verbs:
        for c in codes:
            w1 = rr.render_why(c, v)
            w2 = rr.render_why(c, v)
            assert w1 == w2 and w1
            assert "ACME" not in w1 and "scenario" not in w1.lower()
            assert "\u2014" not in w1          # no em dash


def test_expected_label_registry_lookup_and_composite_fallback():
    registry = {
        "ent-aaaaaaaaaaaa": {"kind": "host", "hostname": WS},
        "ent-cccccccccccc": {"kind": "process", "hostname": WS,
                             "pid": 4756, "name": "payload.exe"},
    }
    assert rr.expected_label("isolate_host", {"hostname": WS}, registry) == WS
    assert "payload.exe" in rr.expected_label(
        "kill_process", {"hostname": WS, "pid": 4756}, registry)
    # fallback grammar when the registry lacks the entity
    assert rr.expected_label("kill_process", {"hostname": WS, "pid": 9999},
                             registry) == f"PID 9999 on {WS}"
    assert rr.expected_label("disable_account",
                             {"domain": "ACME", "username": "nkhan"}, {}) \
        == "ACME\\nkhan"


# --- 5.2: every registry code pinned to the scorer's own verdict ---------------

def test_required_completed_and_not_attempted_pin():
    exp = [_exp("kill_process", {"hostname": WS, "pid": 4756}),
           _exp("delete_file", {"hostname": WS, "path": "c:\\x\\p.exe"})]
    r = _score(exp, [_run("kill_process",
                          {"hostname": WS, "pid": 4756, "name": "p.exe"}, 1)],
               set())
    assert r["correct"] == 1 and r["missed"] == 1
    ent = _entries(r)
    done = next(e for e in ent if e["reason_code"] == rr.REQUIRED_COMPLETED)
    miss = next(e for e in ent if e["reason_code"] == rr.REQUIRED_NOT_ATTEMPTED)
    assert done["seq"] == 1 and done["action"] == "kill_process"
    assert miss["seq"] is None and miss["action"] == "delete_file"


def test_released_after_isolation_pin_carries_the_isolate_seq():
    exp = [_exp("isolate_host", {"hostname": WS})]
    executed = [_run("isolate_host", {"hostname": WS}, 3)]
    r = _score(exp, executed, set())          # end-state: NOT isolated
    assert r["missed"] == 1
    ent = _entries(r)
    assert _codes(r) == [rr.RELEASED_AFTER_ISOLATION]
    assert ent[0]["seq"] == 3


def test_out_of_order_pin():
    exp = [_exp("isolate_host", {"hostname": WS}, eid="a_iso"),
           _exp("kill_process", {"hostname": WS, "pid": 4756},
                after=["a_iso"])]
    executed = [_run("kill_process",
                     {"hostname": WS, "pid": 4756, "name": "p.exe"}, 1),
                _run("isolate_host", {"hostname": WS}, 2)]
    r = _score(exp, executed, {WS})
    assert r["order_violations"] == 1
    codes = _codes(r)
    assert rr.OUT_OF_ORDER in codes and rr.REQUIRED_COMPLETED in codes
    ooo = next(e for e in _entries(r) if e["reason_code"] == rr.OUT_OF_ORDER)
    assert ooo["seq"] == 1


def test_acceptable_completed_and_collateral_pins():
    exp = [_exp("kill_process", {"hostname": WS, "pid": 4756},
                status="acceptable")]
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 4756, "name": "p.exe"}, 1),
        _run("delete_file", {"hostname": WS, "path": "c:\\clean\\doc.txt",
                             "display": "C:\\clean\\doc.txt"}, 2),
    ]
    r = _score(exp, executed, set())
    assert r["collateral"] == 1
    acc = next(e for e in _entries(r)
               if e["reason_code"] == rr.ACCEPTABLE_COMPLETED)
    col = next(e for e in _entries(r)
               if e["reason_code"] == rr.COLLATERAL_IN_SCOPE)
    assert acc["seq"] == 1 and col["seq"] == 2
    assert col["action"] == "delete_file"


def test_endstate_isolation_collateral_pin():
    r = _score([], [_run("isolate_host", {"hostname": SVR}, 5)], {SVR})
    col = next(e for e in _entries(r)
               if e["reason_code"] == rr.COLLATERAL_IN_SCOPE)
    assert col["action"] == "isolate_host" and col["seq"] == 5


def test_inaction_pins_both_ways():
    grading = [{"scenario_id": "scenario-fp", "reviewed": True,
                "hostnames": {WS}, "accounts": set()}]
    clean = app.compute_action_score([], [], set(), grading)
    assert _codes(clean) == [rr.INACTION_CORRECT]
    assert _entries(clean)[0]["seq"] is None
    spoiled = app.compute_action_score(
        [], [_run("kill_process",
                  {"hostname": WS, "pid": 500, "name": "x.exe"}, 1)],
        set(), grading)
    codes = _codes(spoiled)
    assert rr.INACTION_SPOILED in codes and rr.COLLATERAL_IN_SCOPE in codes


def test_popped_review_leaves_public_score_dict_byte_identical():
    """Ruling B: the internal detail is removed at every call site and the
    public result is byte-identical to the pre-change shape (the untouched
    test_action_scoring suite pins the values; this pins the KEY SET)."""
    exp = [_exp("isolate_host", {"hostname": WS})]
    r = _score(exp, [_run("isolate_host", {"hostname": WS}, 1)], {WS})
    r.pop("_review")
    assert set(r.keys()) == {
        "required", "correct", "missed", "collateral", "order_violations",
        "graded", "accuracy", "accuracy_raw", "inaction_collateral",
        "grade", "acceptable_seqs"}


def test_count_reconciliation_fixtures_both_fold_ins():
    """19.16: bucket counts reconcile exactly against the frozen score
    section, including the inaction fold-in and the out_of_order subset."""
    # attack incident with a mix
    exp = [_exp("isolate_host", {"hostname": WS}, eid="a_iso"),
           _exp("kill_process", {"hostname": WS, "pid": 4756},
                after=["a_iso"]),
           _exp("delete_file", {"hostname": WS, "path": "c:\\x\\p.exe"})]
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 4756, "name": "p"}, 1),
        _run("isolate_host", {"hostname": WS}, 2),
        _run("disable_account", {"domain": "ACME", "username": "innocent"}, 3),
    ]
    r = _score(exp, executed, {WS})
    ent = _entries(r)
    buckets = {}
    for e in ent:
        buckets.setdefault(rr.BUCKET_OF[e["reason_code"]], []).append(e)
    assert len(buckets.get("completed", [])) == r["correct"]
    assert len(buckets.get("missed", [])) == r["missed"]
    assert len(buckets.get("collateral", [])) == r["collateral"]
    assert sum(1 for e in ent if e["reason_code"] == rr.OUT_OF_ORDER) \
        == r["order_violations"]
    # inaction incident: the single unit reconciles against correct/missed
    grading = [{"scenario_id": "scenario-fp", "reviewed": True,
                "hostnames": {WS}, "accounts": set()}]
    clean = app.compute_action_score([], [], set(), grading)
    assert clean["correct"] == 1 and clean["required"] == 1
    assert [e["reason_code"] for e in _entries(clean)] == [rr.INACTION_CORRECT]
    spoiled = app.compute_action_score(
        [], [_run("kill_process",
                  {"hostname": WS, "pid": 500, "name": "x"}, 1)],
        set(), grading)
    assert spoiled["missed"] == 1
    assert sum(1 for e in _entries(spoiled)
               if e["reason_code"] == rr.INACTION_SPOILED) == 1


# --- 5.3: the frozen record ----------------------------------------------------

def _api_session():
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def _seed_review_incident(s):
    """One sealed, ready incident exercising every 5.3 join: a required
    isolation EXECUTED (completed entry, log label), a required kill with a
    FAILED attempt only (the not_attempted -> attempt_failed upgrade), a
    successful clean-file delete (collateral, log label), an isolation no_op
    (attempt history), and two dispositioned detections (one call right, one
    wrong)."""
    logs = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
    logs.append({
        "id": f"e-{INC}", "timestamp": STARTED, "scenario_id": SCEN,
        "label": "malware_usb", "category": "Malware", "alert_id": INC,
        "level": 1, "level_name": "Test Incident", "status": "active",
        "chain_complete": True, "severity": "high",
        "message": "seed event", "source_type": "Sysmon", "hostname": WS})
    app._write_ndjson_unlocked(s["paths"]["generated_logs"], logs)
    s.setdefault("incident_index", {})[INC] = SCEN
    s.setdefault("alert_queue", []).append({
        "scenario_id": SCEN, "incident_id": INC, "queue_position": 1,
        "ticket_title": "Test Incident", "storyline": "",
        "injected_at": STARTED, "chain_complete_at": STARTED,
        "scenario_label": "malware_usb"})
    s["queue_length"] = 1
    s.setdefault("scenario_history", [])
    s.setdefault("scenario_grading", []).append({
        "scenario_id": SCEN, "reviewed": True,
        "hostnames": {WS}, "accounts": set()})
    s.setdefault("benign_hosts", set()).add(WS)
    dets = s.setdefault("detections", [])
    dets.extend([
        {"id": "det-tp", "scenario_id": SCEN, "disposition": "true_positive",
         "player_action": "promoted", "entity": {"host": WS},
         "rule_name": "Rule det-tp", "rule_type": "sigma_behavioral",
         "severity": "high", "mitre": None, "yara_rule_name": None,
         "description": "seed", "time": STARTED, "sha256": None,
         "triggering_events": []},
        {"id": "det-fp", "scenario_id": SCEN, "disposition": "false_positive",
         "player_action": "promoted", "entity": {"host": WS},
         "rule_name": "Rule det-fp", "rule_type": "sigma_behavioral",
         "severity": "high", "mitre": None, "yara_rule_name": None,
         "description": "seed", "time": STARTED, "sha256": None,
         "triggering_events": []},
    ])
    s["detection_index"] = {d["id"]: d for d in dets}
    s.setdefault("entity_index", {}).update({
        "ent-aaaaaaaaaaaa": {"kind": "host", "hostname": WS},
        "ent-cccccccccccc": {"kind": "process", "hostname": WS,
                             "pid": 4756, "name": "payload.exe"},
        "ent-dddddddddddd": {"kind": "file", "hostname": WS,
                             "path": "c:\\clean\\doc.txt",
                             "display": "C:\\clean\\doc.txt"},
    })
    s.setdefault("expected_actions", []).extend([
        {"scenario_id": SCEN, "eid": None, "action": "isolate_host",
         "status": "required", "target": {"hostname": WS}, "after": []},
        {"scenario_id": SCEN, "eid": None, "action": "kill_process",
         "status": "required", "target": {"hostname": WS, "pid": 4756},
         "after": []},
    ])
    ov = s["overlay"]
    ov["log"] = [
        {"seq": 1, "timestamp": STARTED, "action": "isolate_host",
         "target": {"id": "ent-aaaaaaaaaaaa", "kind": "host", "label": WS},
         "outcome": "success", "reason": None},
        {"seq": 2, "timestamp": STARTED, "action": "kill_process",
         "target": {"id": "ent-cccccccccccc", "kind": "process",
                    "label": "payload.exe (PID 4756) on ACME-WS12"},
         "outcome": "failed_precondition", "reason": "Process not found."},
        {"seq": 3, "timestamp": STARTED, "action": "delete_file",
         "target": {"id": "ent-dddddddddddd", "kind": "file",
                    "label": "C:\\clean\\doc.txt on ACME-WS12"},
         "outcome": "success", "reason": None},
        {"seq": 4, "timestamp": STARTED, "action": "isolate_host",
         "target": {"id": "ent-aaaaaaaaaaaa", "kind": "host", "label": WS},
         "outcome": "no_op", "reason": "Host is already isolated."},
    ]
    ov["isolated"] = {WS}
    ov["deleted_files"] = {(WS, "c:\\clean\\doc.txt")}
    ov["seq"] = 4


def _submit(client, sid, incident=INC, verdict="threat", category="Malware"):
    payload = {"verdict": verdict}
    if category:
        payload["category"] = category
    return client.post(f"/api/incidents/{incident}/submit",
                       headers={"X-Session-ID": sid}, json=payload)


def test_frozen_record_carries_the_complete_response_review():
    """The stored record's response_review: the four-key block, every entry
    in the {bucket, reason_code, action, target_label, why,
    source_action_seq, expected_ref} shape, executed labels from the action
    log, never-executed labels from the registry grammar, the
    failed-attempt upgrade, the collateral entry without expected_ref, the
    ordered attempt history, and the detections block via the shared
    disposition rule."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_review_incident(s)
        r = _submit(client, sid)
        assert r.status_code == 200, r.get_json()
        rev = s["submissions"][INC]["report_card"]["response_review"]
        assert set(rev.keys()) == {"entries", "attempt_history",
                                   "detections", "scenario_rationale"}
        assert rev["scenario_rationale"] is None
        shape = {"bucket", "reason_code", "action", "target_label", "why",
                 "source_action_seq", "expected_ref"}
        assert all(set(e.keys()) == shape for e in rev["entries"])
        by_code = {e["reason_code"]: e for e in rev["entries"]}
        assert set(by_code) == {rr.REQUIRED_COMPLETED,
                                rr.REQUIRED_ATTEMPT_FAILED,
                                rr.COLLATERAL_IN_SCOPE}
        done = by_code[rr.REQUIRED_COMPLETED]
        assert done["bucket"] == "completed" and done["action"] == "isolate_host"
        assert done["target_label"] == WS          # from the action log
        assert done["source_action_seq"] == 1
        assert done["expected_ref"] == f"isolate_host:{WS}"
        assert done["why"] == rr.render_why(rr.REQUIRED_COMPLETED, "isolate_host")
        # the upgrade: never succeeded, but a FAILED attempt on the exact
        # composite exists in the overlay log
        failed = by_code[rr.REQUIRED_ATTEMPT_FAILED]
        assert failed["bucket"] == "missed" and failed["action"] == "kill_process"
        assert failed["source_action_seq"] is None
        assert failed["target_label"] == "payload.exe (PID 4756) on ACME-WS12"
        assert failed["expected_ref"] == f"kill_process:{WS}/4756"
        col = by_code[rr.COLLATERAL_IN_SCOPE]
        assert col["bucket"] == "collateral" and col["action"] == "delete_file"
        assert col["source_action_seq"] == 3 and col["expected_ref"] is None
        assert col["target_label"] == "C:\\clean\\doc.txt on ACME-WS12"
        assert col["why"] == rr.COLLATERAL_WHY
        # attempt history: seq-ordered, factual codes only
        hist = rev["attempt_history"]
        assert [(h["seq"], h["reason_code"], h["outcome"]) for h in hist] == [
            (2, rr.FAILED_PRECONDITION, "failed_precondition"),
            (4, rr.NO_EFFECT_REPEAT, "no_op")]
        # detections block: the shared disposition-correctness rule
        det = {d["rule_name"]: d for d in rev["detections"]}
        assert det["Rule det-tp"] == {"rule_name": "Rule det-tp",
                                      "entity_label": WS,
                                      "your_call": "promoted", "correct": True}
        assert det["Rule det-fp"]["correct"] is False
    finally:
        _cleanup(sid, s)


def test_stored_review_is_frozen_against_template_and_registry_change():
    """Correction 6 / OD-2: the record stores RENDERED text at submit time.
    Mutating the Tier 1 templates (and the registry) afterwards changes
    nothing served for this incident: the score view and the idempotent
    resubmit return the byte-identical stored review."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_review_incident(s)
        assert _submit(client, sid).status_code == 200
        view1 = client.get(f"/api/incidents/{INC}/score",
                           headers={"X-Session-ID": sid}).get_json()
        frozen = json.dumps(view1, sort_keys=True)
        saved_purpose = dict(rr._PURPOSE)
        saved_released = rr.RELEASED_WHY
        try:
            for k in rr._PURPOSE:
                rr._PURPOSE[k] = "MUTATED TEMPLATE TEXT."
            rr.RELEASED_WHY = "MUTATED."
            with s["io_lock"]:
                s["entity_index"].clear()
            view2 = client.get(f"/api/incidents/{INC}/score",
                               headers={"X-Session-ID": sid}).get_json()
            assert json.dumps(view2, sort_keys=True) == frozen
            again = _submit(client, sid)
            assert again.status_code == 200
            view3 = client.get(f"/api/incidents/{INC}/score",
                               headers={"X-Session-ID": sid}).get_json()
            assert json.dumps(view3, sort_keys=True) == frozen
            assert "MUTATED" not in frozen
        finally:
            rr._PURPOSE.update(saved_purpose)
            rr.RELEASED_WHY = saved_released
    finally:
        _cleanup(sid, s)


def test_unknown_incident_404_and_no_review_before_submission():
    """404 for an unknown incident id; the in-progress score view carries no
    response_review, reason codes, or rationale text."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_review_incident(s)
        assert client.get("/api/incidents/INC-9999/score",
                          headers={"X-Session-ID": sid}).status_code == 404
        view = client.get(f"/api/incidents/{INC}/score",
                          headers={"X-Session-ID": sid})
        assert view.status_code == 200
        body = view.get_data(as_text=True)
        assert json.loads(body)["state"] == "in_progress"
        for marker in ('"response_review"', '"reason_code"', '"bucket"',
                       '"why"', '"expected_ref"', '"scenario_rationale"'):
            assert marker not in body, marker
    finally:
        _cleanup(sid, s)


def test_planted_template_marker_never_leaks_pre_submission():
    """Plant a canary in every Tier 1 template, then sweep the ENUMERATED
    pre-submission surfaces: incident cards, per-incident score, detections
    feed, threats, the response log, and the three session-wide analytics.
    The canary (and the review vocabulary) must appear nowhere: the review
    is assembled at the submission boundary and no earlier surface renders
    any template."""
    client, sid, s = _api_session()
    canary = "CANARY-53-REVIEW"
    saved_purpose = dict(rr._PURPOSE)
    try:
        with s["io_lock"]:
            _seed_review_incident(s)
        for k in rr._PURPOSE:
            rr._PURPOSE[k] = f"{canary} {rr._PURPOSE[k]}"
        surfaces = [
            "/api/incidents",
            f"/api/incidents/{INC}/score",
            "/api/detections",
            "/api/threats",
            "/api/actions",
            "/api/analytics/report_card",
            "/api/analytics/action_score",
            "/api/analytics/detection_score",
        ]
        for path in surfaces:
            resp = client.get(path, headers={"X-Session-ID": sid})
            assert resp.status_code == 200, (path, resp.status_code)
            body = resp.get_data(as_text=True)
            assert canary not in body, path
            assert '"response_review"' not in body, path
            assert '"reason_code"' not in body, path
    finally:
        rr._PURPOSE.clear()
        rr._PURPOSE.update(saved_purpose)
        _cleanup(sid, s)


def test_aggregates_never_carry_review_content():
    """D1: the teaching breakdown is per-incident only. After submission the
    per-incident view serves it; the three session-wide analytics payloads
    never contain response_review, reason codes, or the internal _review."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_review_incident(s)
        assert _submit(client, sid).status_code == 200
        inc_view = client.get(f"/api/incidents/{INC}/score",
                              headers={"X-Session-ID": sid}).get_json()
        assert inc_view["state"] == "submitted"
        rev = inc_view["grading"]["response_review"]
        assert set(rev.keys()) == {"entries", "attempt_history",
                                   "detections", "scenario_rationale"}
        assert rev["entries"], "submitted review must carry its entries"
        for path in ("/api/analytics/report_card",
                     "/api/analytics/action_score",
                     "/api/analytics/detection_score"):
            body = client.get(path, headers={"X-Session-ID": sid}) \
                .get_data(as_text=True)
            assert json.loads(body)["state"] == "submitted"
            for marker in ('"response_review"', '"reason_code"', '"_review"',
                           '"scenario_rationale"'):
                assert marker not in body, (path, marker)
    finally:
        _cleanup(sid, s)


def test_empty_states_correct_inaction_review():
    """A reviewed no-required incident with clean hands: exactly one
    inaction_correct entry (action None, label None, expected_ref
    'inaction', the canonical why), an empty attempt history, and the
    detections block still renders its dispositioned rows."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_review_incident(s)
            # strip the response fixtures: reviewed with NO expected actions
            s["expected_actions"] = []
            s["overlay"]["log"] = []
            s["overlay"]["isolated"] = set()
            s["overlay"]["deleted_files"] = set()
        assert _submit(client, sid, verdict="false_positive",
                       category=None).status_code == 200
        rev = s["submissions"][INC]["report_card"]["response_review"]
        assert [e["reason_code"] for e in rev["entries"]] == [rr.INACTION_CORRECT]
        e = rev["entries"][0]
        assert e["bucket"] == "inaction" and e["action"] is None
        assert e["target_label"] is None and e["source_action_seq"] is None
        assert e["expected_ref"] == "inaction"
        assert e["why"] == rr.INACTION_CORRECT_WHY
        assert rev["attempt_history"] == []
        assert len(rev["detections"]) == 2
        assert all(d["your_call"] == "promoted" for d in rev["detections"])
    finally:
        _cleanup(sid, s)


# --- 5.3: real-drip corpus reconciliation (19.16) ------------------------------

OWILSON = next(e for e in app.EMPLOYEES if e["name"] == "owilson")


def _catalog_labels():
    out = []
    for lvl in app.CAMPAIGN_LEVELS:
        for _cat, sc in lvl["scenarios"].items():
            out.append(sc["scenario_label"])
    return sorted(out)


def _drip_one(label):
    """Real drip of one scenario in a fresh session (the corpus-gate
    technique: the writer thread's exact order, no threads)."""
    client = app.app.test_client()
    sid = client.get("/api/health").headers["X-Session-ID"]
    s = app.sessions[sid]
    queue = app.build_guided_queue(app._catalog_id_for(label))
    s["game_mode"] = "guided"
    s["alert_queue"] = queue
    s["queue_length"] = 1
    s["resolved_count"] = 0
    s["injected_count"] = 0
    s["scenario_history"] = []
    with s["io_lock"]:
        s["world"] = {"hosts": {}, "started_at": sim_epoch.epoch_iso(s["id"])}
        s["detections"] = []
        s["detection_index"] = {}
        s["benign_hosts"] = set()
        s["overlay"] = ao.new_overlay()
        s["entity_index"] = {}
        s["env_accounts"] = {}
        s["expected_actions"] = []
        s["scenario_grading"] = []
        s["submissions"] = {}
        s["incident_index"] = {}
        s["assisted"] = set()
    s["gap_rng"] = sim_epoch.gap_rng(s["id"])
    entry = s["alert_queue"][0]
    chain = app.build_attack_chain_logs(s, entry, employee=OWILSON)
    assert chain, f"{label}: no chain generated"
    entry["injected_at"] = datetime.now(timezone.utc).isoformat()
    s["injected_count"] = 1
    for log in chain:
        app.append_pool_event(s, log)
    app.finalize_chain(s, entry["scenario_id"])
    entry["chain_complete_at"] = datetime.now(timezone.utc).isoformat()
    return client, sid, s, entry


def test_corpus_real_drip_review_reconciles_with_frozen_scores():
    """19.16 on the REAL corpus: drip all 20 scenarios, disposition
    everything, submit act-on-nothing, and reconcile every stored review
    against its own frozen score section: bucket counts equal the score
    counters, the detections block equals the graded roster with the
    correct-call count, attempt history is empty (no attempts were made),
    and every entry carries a registry-grammar label and non-empty why."""
    for label in _catalog_labels():
        client, sid, s, entry = _drip_one(label)
        try:
            inc = entry["incident_id"]
            with s["io_lock"]:
                for d in s["detections"]:
                    d["player_action"] = "dismissed"
            r = _submit(client, sid, incident=inc, verdict="false_positive",
                        category=None)
            assert r.status_code == 200, (label, r.get_json())
            rc = s["submissions"][inc]["report_card"]
            rev = rc["response_review"]
            resp = rc["response"]
            buckets = {}
            for e in rev["entries"]:
                assert e["reason_code"] in rr.BUCKET_OF, (label, e)
                assert e["bucket"] == rr.BUCKET_OF[e["reason_code"]]
                assert e["why"], (label, e)
                buckets.setdefault(e["bucket"], []).append(e)
            assert len(buckets.get("completed", [])) == resp["correct"] - (
                1 if any(x["reason_code"] == rr.INACTION_CORRECT
                         for x in rev["entries"]) else 0), label
            missed_units = [x for x in rev["entries"]
                            if x["bucket"] == "missed"
                            or x["reason_code"] == rr.INACTION_SPOILED]
            assert len(missed_units) == resp["missed"], label
            assert len(buckets.get("collateral", [])) == resp["collateral"], label
            assert sum(1 for e in rev["entries"]
                       if e["reason_code"] == rr.OUT_OF_ORDER) \
                == resp["order_violations"], label
            # act-on-nothing: nothing executed, so every non-inaction entry
            # is a required miss with a registry-grammar expected label
            for e in rev["entries"]:
                if e["reason_code"] == rr.INACTION_CORRECT:
                    continue
                assert e["reason_code"] == rr.REQUIRED_NOT_ATTEMPTED, (label, e)
                assert e["target_label"], (label, e)
                assert e["expected_ref"] and ":" in e["expected_ref"], (label, e)
            assert rev["attempt_history"] == [], label
            det_block = rev["detections"]
            assert len(det_block) == rc["detection"]["graded"], label
            assert sum(1 for d in det_block if d["correct"]) \
                == rc["detection"]["correct"], label
            assert all(d["your_call"] == "dismissed" for d in det_block), label
            assert rev["scenario_rationale"] is None, label
        finally:
            _cleanup(sid, s)
    print(f"  corpus reconciliation: {len(_catalog_labels())} scenarios")


def _main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} passed")


if __name__ == "__main__":
    _main()
