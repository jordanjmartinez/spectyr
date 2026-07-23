"""Stage 3.9A: the permanent temporal leak-guard suite.

The ruled principle: grading is served ONLY across a submission boundary, from
an immutable stored record. Existing leak guards protect FIELDS (the answer key
never serializes); this suite protects TIMING (no grading or correctness of an
incident is disclosed before that incident is submitted). Every session-wide
grading surface must therefore return the discriminated in_progress shape until
an incident is submitted, and only the submitted shape after.

Run: python -m pytest test_submission_gate.py -q  (or python test_submission_gate.py)
"""
import json
import os
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402

WS = "ACME-WS12"
STARTED = "2026-07-17T12:00:00+00:00"
INC = "INC-0001"
SID_SCENARIO = "scenario-x"

# The five session-wide grading surfaces the boundary governs.
GRADING_SURFACES = [
    "/api/analytics/report_card",
    "/api/analytics/action_score",
    "/api/analytics/detection_score",
]

# Any substring that would betray correctness or an answer-key-derived total if
# it appeared in a pre-submission (in_progress) payload.
FORBIDDEN_IN_PROGRESS = [
    '"grading"', '"composite"', '"accuracy"', '"grade"',
    '"threats_caught"', '"correct_category"', '"category_correct"',
    '"required"', '"missed"', '"collateral"',
]


def _api_session():
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def _add_incident(s, incident_id, scenario_id, host, category, label,
                  det_specs, sealed=True, required_isolate=True, ent_id=None,
                  extra_env_hosts=(), ambient_specs=()):
    """Append ONE incident to a fresh session WITHOUT the drip threads: a raw
    event, the incident index entry, a queue entry (chain_complete_at set iff
    `sealed`), a reviewed grading record scoped to `host` + `extra_env_hosts`,
    its detections (`det_specs` = list of (id, disposition, player_action)),
    ambient benign detections (`ambient_specs` = list of (id, player_action,
    ambient_host) with scenario_id None), and optionally a required-and-executed
    isolation. Appends, so several incidents coexist.

    Pre-Stage-5 fixture-class note: the original fixture always set grading
    hostnames == {the single observable event host}, so environment-declared ==
    observed by construction and the roster-join divergence was unreachable.
    `extra_env_hosts` exists to break that alignment on purpose: a host listed
    there is environment-declared (grading scope) with NO written event —
    exactly the escaped configuration."""
    logs = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
    logs.append({
        "id": f"e-{incident_id}", "timestamp": STARTED, "scenario_id": scenario_id,
        "label": label, "category": category, "alert_id": incident_id,
        "level": 1, "level_name": "Test Incident", "status": "active",
        "chain_complete": sealed, "severity": "high",
        "message": "seed event", "source_type": "Sysmon", "hostname": host})
    app._write_ndjson_unlocked(s["paths"]["generated_logs"], logs)
    s.setdefault("incident_index", {})[incident_id] = scenario_id
    q = s.setdefault("alert_queue", [])
    q.append({
        "scenario_id": scenario_id, "incident_id": incident_id,
        "queue_position": len(q) + 1, "ticket_title": "Test Incident",
        "storyline": "", "injected_at": STARTED,
        "chain_complete_at": STARTED if sealed else None,
        "scenario_label": label})
    s["queue_length"] = len(q)
    s.setdefault("scenario_history", [])
    s.setdefault("scenario_grading", []).append({
        "scenario_id": scenario_id, "reviewed": True,
        "hostnames": {host, *extra_env_hosts}, "accounts": set()})
    # Mirror the real drip: the host's ambient benign is materialized once, then
    # the host is recorded in benign_hosts so no later drip re-attaches to it.
    s.setdefault("benign_hosts", set()).update({host, *extra_env_hosts})
    dets = s.setdefault("detections", [])
    for did, disp, act in det_specs:
        dets.append({
            "id": did, "scenario_id": scenario_id, "disposition": disp,
            "player_action": act, "entity": {"host": host},
            # feed-complete fields (sanitize_detection reads these)
            "rule_name": f"Rule {did}", "rule_type": "sigma_behavioral",
            "severity": "high", "mitre": None, "yara_rule_name": None,
            "description": "seed detection", "time": STARTED, "sha256": None,
            "triggering_events": []})
    for did, act, amb_host in ambient_specs:
        dets.append({
            "id": did, "scenario_id": None, "disposition": "benign_expected",
            "player_action": act, "entity": {"host": amb_host},
            "rule_name": f"Rule {did}", "rule_type": "sigma_behavioral",
            "severity": "low", "mitre": None, "yara_rule_name": None,
            "description": "seed ambient benign", "time": STARTED, "sha256": None,
            "triggering_events": []})
    s["detection_index"] = {d["id"]: d for d in dets}
    if required_isolate:
        ent = ent_id or f"ent-{host}"
        s.setdefault("entity_index", {})[ent] = {"kind": "host", "hostname": host}
        s.setdefault("expected_actions", []).append({
            "scenario_id": scenario_id, "eid": None, "action": "isolate_host",
            "status": "required", "target": {"hostname": host}, "after": []})
        ov = s["overlay"]
        seq = ov.get("seq", 0) + 1
        ov.setdefault("log", []).append({
            "seq": seq, "timestamp": STARTED, "action": "isolate_host",
            "target": {"id": ent, "kind": "host", "label": host},
            "outcome": "success", "reason": None})
        ov["isolated"] = set(ov.get("isolated", set())) | {host}
        ov["seq"] = seq


def _seed_incident(s, category="Malware", label="malware_usb", sealed=True,
                   det_specs=None):
    """The canonical single ready incident (INC-0001 on ACME-WS12): sealed
    roster, one required+executed isolation, and by default two dispositioned
    detections (TP promoted + FP promoted -> 50% detection). Grades to
    classification 100 / detection 50 / response 100 / composite 85."""
    if det_specs is None:
        det_specs = [("det-tp", "true_positive", "promoted"),
                     ("det-fp", "false_positive", "promoted")]
    _add_incident(s, INC, SID_SCENARIO, WS, category, label, det_specs,
                  sealed=sealed, required_isolate=True, ent_id="ent-host-000000")


# --- the temporal gate ---------------------------------------------------------

def test_no_grading_surface_leaks_before_submission():
    """Before ANY incident is submitted, every session-wide grading surface
    returns the in_progress shape and discloses no grading, correctness, or
    answer-key-derived total."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        hdr = {"X-Session-ID": sid}
        for path in GRADING_SURFACES:
            body = client.get(path, headers=hdr).get_json()
            assert body["state"] == "in_progress", f"{path} not gated"
            assert "grading" not in body, f"{path} exposed grading pre-submit"
            assert "progress" in body
            blob = json.dumps(body["progress"])
            for needle in FORBIDDEN_IN_PROGRESS:
                assert needle not in blob, f"{path} progress leaked {needle}"
    finally:
        _cleanup(sid, s)


def test_progress_shape_is_observable_activity_only():
    """The in_progress progress payload carries observable activity only:
    submitted/triaged/attempted counts, never a required-action count or any
    answer-key-derived total."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        prog = client.get("/api/analytics/report_card",
                          headers={"X-Session-ID": sid}).get_json()["progress"]
        assert set(prog) >= {"submitted", "detections_triaged", "detections_open",
                             "actions_attempted", "actions_executed"}
        assert "required" not in prog and "correct" not in prog
        assert prog["submitted"] == 0
    finally:
        _cleanup(sid, s)


def test_incident_score_is_in_progress_before_submit():
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        body = client.get(f"/api/incidents/{INC}/score",
                          headers={"X-Session-ID": sid}).get_json()
        assert body["state"] == "in_progress"
        assert "grading" not in body
        blob = json.dumps(body)
        assert '"classified": "not_submitted"' in blob
    finally:
        _cleanup(sid, s)


def test_grading_appears_only_after_submission_and_matches_record():
    """After the incident is submitted, the session surfaces reveal grading
    that matches the immutable stored record, and the per-incident score view
    flips to the submitted shape."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        hdr = {"X-Session-ID": sid}

        # submit: correct classification (category matches), isolate executed,
        # detections 1 correct / 1 wrong.
        resp = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                           json={"verdict": "threat", "category": "Malware",
                                 "report": "seed report"})
        assert resp.status_code == 200
        view = resp.get_json()
        assert view["state"] == "submitted"
        rc = view["grading"]
        assert rc["classification"]["correct"] is True
        assert rc["classification"]["accuracy"] == 100.0
        assert rc["detection"]["accuracy"] == 50.0
        assert rc["response"]["accuracy"] == 100.0
        # composite 0.4*100 + 0.3*50 + 0.3*100 = 85.0
        assert rc["composite"]["accuracy"] == 85.0
        assert rc["composite"]["grade"] == "B"

        # session surfaces now submitted and consistent with the record
        report = client.get("/api/analytics/report_card", headers=hdr).get_json()
        assert report["state"] == "submitted"
        assert report["grading"]["composite"]["accuracy"] == 85.0
        assert report["grading"]["classification"]["threats_caught"] == 1

        act = client.get("/api/analytics/action_score", headers=hdr).get_json()
        assert act["state"] == "submitted"
        assert act["grading"]["accuracy"] == 100.0

        det = client.get("/api/analytics/detection_score", headers=hdr).get_json()
        assert det["state"] == "submitted"
        assert det["grading"]["accuracy"] == 50.0

        # per-incident score view flips to submitted and is stable on re-read
        again = client.get(f"/api/incidents/{INC}/score", headers=hdr).get_json()
        assert again["state"] == "submitted"
        assert again["grading"]["composite"]["accuracy"] == 85.0
    finally:
        _cleanup(sid, s)


def test_submission_is_idempotent_and_immutable():
    """A second submit returns the same grade; later session activity never
    rewrites a submitted incident's stored record."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        hdr = {"X-Session-ID": sid}
        first = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                           json={"verdict": "threat", "category": "Malware"}).get_json()
        # mutate live state AFTER submission: it must not change the stored grade
        with s["io_lock"]:
            s["overlay"]["isolated"] = set()  # "release" the host post-submit
            s["detections"][0]["player_action"] = "dismissed"
        second = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                            json={"verdict": "false_positive", "category": "x"}).get_json()
        assert second["grading"]["composite"]["accuracy"] == \
            first["grading"]["composite"]["accuracy"]
        assert second["grading"]["response"]["accuracy"] == 100.0
    finally:
        _cleanup(sid, s)


def test_submitted_grade_byte_identical_under_cross_incident_activity():
    """Carried-over review item: a submitted incident's score read is
    byte-identical after unrelated later activity, including submitting a
    DIFFERENT incident and mutating live detection/response state."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)  # incident A (INC / scenario-x on ACME-WS12)
        hdr = {"X-Session-ID": sid}
        client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                    json={"verdict": "threat", "category": "Malware"})
        before = client.get(f"/api/incidents/{INC}/score", headers=hdr).data

        # later cross-incident activity: seed + submit incident B, and mutate A's
        # live detections/response state (which A's frozen record must ignore).
        with s["io_lock"]:
            _add_incident(s, "INC-0002", "scenario-b", "ACME-WS20", "Phishing",
                          "phishing_1",
                          det_specs=[("b-tp", "true_positive", "promoted")],
                          sealed=True)
            s["detections"][0]["player_action"] = "dismissed"
            s["overlay"]["isolated"] = set()
        client.post("/api/incidents/INC-0002/submit", headers=hdr,
                    json={"verdict": "threat", "category": "Phishing"})

        after = client.get(f"/api/incidents/{INC}/score", headers=hdr).data
        assert before == after, "submitted incident A grade changed after later activity"
    finally:
        _cleanup(sid, s)


def test_wrong_classification_scores_zero_classification():
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, category="Malware")
        hdr = {"X-Session-ID": sid}
        view = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                          json={"verdict": "threat", "category": "Phishing"}).get_json()
        assert view["grading"]["classification"]["correct"] is False
        assert view["grading"]["classification"]["accuracy"] == 0.0
    finally:
        _cleanup(sid, s)


# --- Check Answer (Guided-only, marks Assisted, classification only) -----------

def test_check_answer_reveals_classification_only_and_marks_assisted():
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, category="Malware")
        s["game_mode"] = "training"
        hdr = {"X-Session-ID": sid}
        r = client.post(f"/api/incidents/{INC}/check-answer", headers=hdr,
                       json={"verdict": "threat", "category": "Malware"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["assisted"] is True
        assert body["classification"]["correct"] is True
        # classification ONLY: no detection/response/composite disclosed
        blob = json.dumps(body)
        for needle in ('"detection"', '"response"', '"composite"'):
            assert needle not in blob
        assert INC in s["assisted"]

        # the eventual submission carries the assisted flag
        view = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                          json={"verdict": "threat", "category": "Malware"}).get_json()
        assert view["assisted"] is True
    finally:
        _cleanup(sid, s)


def test_check_answer_allow_list_guided_only():
    """Allow-list by mode, NOT deny-list: Check Answer is available ONLY in
    Guided mode, and rejected in every other mode (Hardcore and Analyst/SOC
    Queue alike)."""
    payload = {"verdict": "threat", "category": "Malware"}
    # Guided (training): allowed
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        s["game_mode"] = "training"
        assert client.post(f"/api/incidents/{INC}/check-answer",
                           headers={"X-Session-ID": sid}, json=payload).status_code == 200
    finally:
        _cleanup(sid, s)
    # Every non-Guided mode: rejected
    for mode in ("hardcore", "analyst", "soc_queue"):
        client, sid, s = _api_session()
        try:
            with s["io_lock"]:
                _seed_incident(s)
            s["game_mode"] = mode
            r = client.post(f"/api/incidents/{INC}/check-answer",
                           headers={"X-Session-ID": sid}, json=payload)
            assert r.status_code == 403, f"check-answer allowed in {mode}"
        finally:
            _cleanup(sid, s)


# --- submission readiness (roster sealed + every scoped detection dispositioned) --

def test_open_detections_block_submission():
    """An incident with an un-dispositioned detection in its finalized roster
    cannot be submitted; the 409 carries the observable count only, never any
    correctness, and the incident stays in progress."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, det_specs=[
                ("det-tp", "true_positive", "promoted"),
                ("det-open", "false_positive", "open")])  # one still open
        hdr = {"X-Session-ID": sid}
        r = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                       json={"verdict": "threat", "category": "Malware"})
        assert r.status_code == 409
        body = r.get_json()
        assert body["reason"] == "open_detections" and body["open_detections"] == 1
        # no correctness leaked in the block
        for needle in ("correct", "true_positive", "false_positive", "composite"):
            assert needle not in json.dumps(body)
        # not submitted: still in progress, no stored record
        assert INC not in s["submissions"]
        assert client.get(f"/api/incidents/{INC}/score",
                          headers=hdr).get_json()["state"] == "in_progress"
    finally:
        _cleanup(sid, s)


def test_sealing_roster_blocks_submission():
    """While the detection roster is still attaching (chain not finalized), the
    incident cannot be submitted and the copy is neutral telemetry-loading."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, sealed=False)  # chain_complete_at unset
        hdr = {"X-Session-ID": sid}
        r = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                       json={"verdict": "threat", "category": "Malware"})
        assert r.status_code == 409
        assert r.get_json()["reason"] == "sealing"
        assert INC not in s["submissions"]
    finally:
        _cleanup(sid, s)


def test_completing_dispositions_enables_full_grade():
    """Once every scoped detection is dispositioned, submission is enabled and
    produces Classification, Detection, Response, AND a complete Composite grade
    (never '-')."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, det_specs=[
                ("det-tp", "true_positive", "promoted"),
                ("det-open", "false_positive", "open")])
        hdr = {"X-Session-ID": sid}
        assert client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                          json={"verdict": "threat", "category": "Malware"}).status_code == 409
        # disposition the open detection (as the triage endpoint would)
        with s["io_lock"]:
            for d in s["detections"]:
                if d["id"] == "det-open":
                    d["player_action"] = "dismissed"
        view = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                          json={"verdict": "threat", "category": "Malware"}).get_json()
        assert view["state"] == "submitted"
        g = view["grading"]
        # all four components graded; composite is a real grade, not '-'
        assert g["classification"]["accuracy"] is not None
        assert g["detection"]["accuracy"] is not None and g["detection"]["graded"] == 2
        assert g["response"]["accuracy"] is not None
        assert g["composite"]["accuracy"] is not None and g["composite"]["grade"] != "-"
    finally:
        _cleanup(sid, s)


def test_remaining_count_and_readiness_are_incident_scoped():
    """The remaining-detections count is per incident: another incident's open
    detections never affect this incident's readiness."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            # A: two open detections; B: fully dispositioned, disjoint host
            _seed_incident(s, det_specs=[
                ("a1", "true_positive", "open"),
                ("a2", "false_positive", "open")])
            _add_incident(s, "INC-0002", "scenario-b", "ACME-WS20", "Phishing",
                          "phishing_1",
                          det_specs=[("b1", "true_positive", "promoted")],
                          sealed=True)
        hdr = {"X-Session-ID": sid}
        # A blocked with its OWN count (2), not 2+B
        ra = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                        json={"verdict": "threat", "category": "Malware"})
        assert ra.status_code == 409 and ra.get_json()["open_detections"] == 2
        # B submits fine despite A's open detections (independent readiness)
        rb = client.post("/api/incidents/INC-0002/submit", headers=hdr,
                        json={"verdict": "threat", "category": "Phishing"})
        assert rb.status_code == 200 and rb.get_json()["state"] == "submitted"
        # A is still blocked and still unsubmitted
        assert client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                          json={"verdict": "threat", "category": "Malware"}).status_code == 409
        assert INC not in s["submissions"]
    finally:
        _cleanup(sid, s)


def test_fp_inaction_scenario_reaches_readiness_and_full_grade():
    """An inaction-correct (false-positive) scenario with no required actions
    reaches readiness once its detections are dispositioned and submits with a
    complete grade (clean-hands response = 100)."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            # FP incident: no required actions (inaction), two FP detections
            _add_incident(s, "INC-0003", "scenario-fp", "ACME-WS30",
                          "False Positive", "false_positive_veeam",
                          det_specs=[("fp1", "false_positive", "open"),
                                     ("fp2", "benign_expected", "open")],
                          sealed=True, required_isolate=False)
        hdr = {"X-Session-ID": sid}
        # blocked while its detections are open
        assert client.post("/api/incidents/INC-0003/submit", headers=hdr,
                          json={"verdict": "false_positive",
                                "category": "x"}).status_code == 409
        with s["io_lock"]:
            for d in s["detections"]:
                d["player_action"] = "dismissed"
        view = client.post("/api/incidents/INC-0003/submit", headers=hdr,
                          json={"verdict": "false_positive", "category": "x"}).get_json()
        assert view["state"] == "submitted"
        g = view["grading"]
        assert g["classification"]["correct"] is True       # FP called FP
        assert g["response"]["accuracy"] == 100.0            # clean-hands inaction
        assert g["composite"]["accuracy"] is not None and g["composite"]["grade"] != "-"
    finally:
        _cleanup(sid, s)


def test_incident_cards_surface_incident_scoped_readiness():
    """P8.3 retarget (was test_grouped_alerts_surface_incident_scoped_
    readiness; the grouped-alerts route is deleted): the /api/incidents
    active card carries observable readiness (sealed + open count),
    incident-scoped, for the frontend Submit gate."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, det_specs=[
                ("g1", "true_positive", "open"),
                ("g2", "false_positive", "promoted")])
        cards = client.get("/api/incidents",
                           headers={"X-Session-ID": sid}).get_json()["active"]
        card = next(c for c in cards if c["incident_id"] == INC)
        assert card["sealed"] is True
        assert card["open_detections"] == 1
        assert card["ready"] is False
    finally:
        _cleanup(sid, s)


# --- invariant 1: roster finality (3.9A re-review) --------------------------------

def test_sealed_roster_finality_no_growth_on_poll_or_unrelated_activity():
    """The sealed roster is fixed: duplicate polling never regenerates it, the
    host is recorded in benign_hosts so no later drip re-attaches ambient benign
    to it, and another incident's detections never enter this roster."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, det_specs=[
                ("r1", "true_positive", "promoted"),
                ("r2", "false_positive", "dismissed")])
        hdr = {"X-Session-ID": sid}
        base = {d["id"] for d in app._incident_detections(s, SID_SCENARIO)}
        assert base == {"r1", "r2"}
        # the runtime guard: the host is in benign_hosts, so the drip's
        # ambient-benign step is a no-op for it (no re-attach)
        assert WS in s["benign_hosts"]

        # duplicate polling must not regenerate/expand the roster (P8.3: the
        # readiness-bearing poll surface is /api/incidents)
        for _ in range(3):
            client.get("/api/detections", headers=hdr)
            client.get("/api/incidents", headers=hdr)
        after_poll = {d["id"] for d in app._incident_detections(s, SID_SCENARIO)}
        assert after_poll == base

        # an unrelated incident's detections (other scenario, other host) never
        # enter this incident's roster
        with s["io_lock"]:
            _add_incident(s, "INC-0002", "scenario-b", "ACME-WS20", "Phishing",
                          "phishing_1",
                          det_specs=[("b1", "true_positive", "open")], sealed=True)
        still = {d["id"] for d in app._incident_detections(s, SID_SCENARIO)}
        assert still == base
    finally:
        _cleanup(sid, s)


def test_no_detection_attaches_to_a_submitted_incident():
    """After submission the roster is frozen in the immutable record: a
    detection attached afterward (even one scoped to this scenario and host) can
    never change the stored grade."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        hdr = {"X-Session-ID": sid}
        rec = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                         json={"verdict": "threat", "category": "Malware"}).get_json()
        frozen_inputs = json.dumps(s["submissions"][INC]["inputs"]["detection_dispositions"],
                                   sort_keys=True)
        before = client.get(f"/api/incidents/{INC}/score", headers=hdr).data

        # attach a NEW detection to this scenario + host AFTER submission
        with s["io_lock"]:
            s["detections"].append({
                "id": "late-attach", "scenario_id": SID_SCENARIO,
                "disposition": "true_positive", "player_action": "open",
                "entity": {"host": WS}})
        after = client.get(f"/api/incidents/{INC}/score", headers=hdr).data
        assert after == before, "submitted incident grade changed after a late detection"
        # the stored roster snapshot is unchanged and excludes the late detection
        now_inputs = json.dumps(s["submissions"][INC]["inputs"]["detection_dispositions"],
                                sort_keys=True)
        assert now_inputs == frozen_inputs and "late-attach" not in now_inputs
    finally:
        _cleanup(sid, s)


def test_every_sealed_roster_detection_is_dispositionable_in_feed():
    """Readiness can never demand an action the player cannot perform: every
    detection in the sealed roster is present in the /api/detections feed (which
    carries the promote/dismiss controls)."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, det_specs=[
                ("d1", "true_positive", "open"),
                ("d2", "false_positive", "open"),
                ("d3", "benign_expected", "open")])
        hdr = {"X-Session-ID": sid}
        roster = {d["id"] for d in app._incident_detections(s, SID_SCENARIO)}
        feed_ids = {d["id"] for d in
                    client.get("/api/detections", headers=hdr).get_json()["detections"]}
        assert roster and roster <= feed_ids, "a sealed-roster detection is not in the feed"
    finally:
        _cleanup(sid, s)


# --- pre-Stage-5 hotfix: ONE shared incident roster ------------------------------
# The escaped INC-1310 configuration and its class: display, "X of Y", Ready,
# Submit enablement, submit-time readiness, and grading must all consume the
# SAME observable roster (_incident_roster). These fixtures deliberately break
# the environment==observed alignment every 3.9 fixture silently assumed.

ENV_ONLY = "ACME-WS27"


def test_env_only_host_ambient_never_gates_grades_or_blocks_submit():
    """The exact escaped defect: the scenario's environment declares an extra
    host with NO written event, and an OPEN ambient benign sits on it. The
    incident-scoped display excludes it; displayed roster, readiness roster,
    and grading roster are identical; the unrelated Session-wide detection
    stays visible session-wide and does NOT block submission. (Red on the
    pre-hotfix environment-host ambient join.)"""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _add_incident(s, INC, SID_SCENARIO, WS, "Malware", "malware_usb",
                          det_specs=[("det-tp", "true_positive", "promoted"),
                                     ("det-fp", "false_positive", "promoted")],
                          extra_env_hosts=(ENV_ONLY,),
                          ambient_specs=[("det-envonly", "open", ENV_ONLY)])
        hdr = {"X-Session-ID": sid}
        card = next(c for c in client.get("/api/incidents", headers=hdr)
                    .get_json()["active"] if c["incident_id"] == INC)
        assert card["ready"] is True and card["open_detections"] == 0
        assert card["triage"] == {"total": 2, "triaged": 2}
        scope = client.get(f"/api/incidents/{INC}/scope", headers=hdr).get_json()
        assert set(scope["detection_ids"]) == {"det-tp", "det-fp"}
        assert ENV_ONLY not in scope["hosts"]
        # the grading-side progress view agrees with the card in the same cycle
        prog = client.get(f"/api/incidents/{INC}/score",
                          headers=hdr).get_json()["progress"]
        assert prog["detections_open"] == 0 and prog["submission_ready"] is True
        # session-wide feed still carries the unrelated detection (triage material)
        feed = {d["id"] for d in client.get("/api/detections", headers=hdr)
                .get_json()["detections"]}
        assert "det-envonly" in feed
        # submit succeeds despite the open env-only ambient
        r = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                        json={"verdict": "threat", "category": "Malware"})
        assert r.status_code == 200 and r.get_json()["state"] == "submitted"
        rec = s["submissions"][INC]
        assert set(rec["inputs"]["detection_dispositions"]) == {"det-tp", "det-fp"}
        assert rec["report_card"]["detection"]["graded"] == 2
        env = next(d for d in s["detections"] if d["id"] == "det-envonly")
        assert env["player_action"] == "open"  # untouched, never demanded
    finally:
        _cleanup(sid, s)


def test_ambient_on_observable_host_gates_and_one_disposition_satisfies_all():
    """The accepted rule is preserved: an ambient benign on a genuinely
    observable participant host appears in the displayed incident roster,
    raises the displayed total, and blocks submission until dispositioned. Two
    incidents sharing that observable host both carry it, and ONE disposition
    satisfies every roster in which it legitimately appears."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _add_incident(s, INC, SID_SCENARIO, WS, "Malware", "malware_usb",
                          det_specs=[("a1", "true_positive", "promoted")],
                          required_isolate=False,
                          ambient_specs=[("amb-ws", "open", WS)])
            _add_incident(s, "INC-0002", "scenario-b", WS, "Phishing",
                          "phishing_1",
                          det_specs=[("b1", "true_positive", "promoted")],
                          required_isolate=False)
        hdr = {"X-Session-ID": sid}
        sa = client.get(f"/api/incidents/{INC}/scope", headers=hdr).get_json()
        sb = client.get("/api/incidents/INC-0002/scope", headers=hdr).get_json()
        assert "amb-ws" in sa["detection_ids"] and "amb-ws" in sb["detection_ids"]
        assert sa["triage"] == sb["triage"] == {"total": 2, "triaged": 1}
        ra = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                         json={"verdict": "threat", "category": "Malware"})
        assert ra.status_code == 409 and ra.get_json()["open_detections"] == 1
        rb = client.post("/api/incidents/INC-0002/submit", headers=hdr,
                         json={"verdict": "threat", "category": "Phishing"})
        assert rb.status_code == 409 and rb.get_json()["open_detections"] == 1
        # one disposition, through the real triage API, unblocks both
        assert client.post("/api/detections/amb-ws/disposition", headers=hdr,
                           json={"action": "dismiss"}).status_code == 200
        assert client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                           json={"verdict": "threat",
                                 "category": "Malware"}).status_code == 200
        assert client.post("/api/incidents/INC-0002/submit", headers=hdr,
                           json={"verdict": "threat",
                                 "category": "Phishing"}).status_code == 200
    finally:
        _cleanup(sid, s)


def test_all_surfaces_consume_the_shared_roster_and_agree():
    """Surface agreement: the card triage counts (the "X of Y" phase strip),
    the incident-scoped Detections view (scope.detection_ids), the Ready label
    + Submit enablement (card.ready), the /score progress view, and submit-time
    validation all consume the SAME shared roster and agree — in a mixed triage
    state and again after the displayed roster is fully reviewed."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _add_incident(s, INC, SID_SCENARIO, WS, "Malware", "malware_usb",
                          det_specs=[("t1", "true_positive", "promoted"),
                                     ("t2", "false_positive", "open")],
                          required_isolate=False,
                          extra_env_hosts=(ENV_ONLY,),
                          ambient_specs=[("amb-ws", "open", WS),
                                         ("amb-env", "open", ENV_ONLY)])
        hdr = {"X-Session-ID": sid}

        def surfaces():
            card = next(c for c in client.get("/api/incidents", headers=hdr)
                        .get_json()["active"] if c["incident_id"] == INC)
            scope = client.get(f"/api/incidents/{INC}/scope",
                               headers=hdr).get_json()
            prog = client.get(f"/api/incidents/{INC}/score",
                              headers=hdr).get_json()["progress"]
            return card, scope, prog

        card, scope, prog = surfaces()
        # roster = t1 + t2 + amb-ws; amb-env (env-only host) excluded everywhere
        assert set(scope["detection_ids"]) == {"t1", "t2", "amb-ws"}
        assert card["triage"] == scope["triage"] == {"total": 3, "triaged": 1}
        assert card["open_detections"] == 2 and card["ready"] is False
        assert prog["detections_triaged"] == 1 and prog["detections_open"] == 2
        assert prog["submission_ready"] is False
        r = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                        json={"verdict": "threat", "category": "Malware"})
        assert r.status_code == 409 and r.get_json()["open_detections"] == 2

        # review exactly the displayed roster -> every surface flips together
        for did in ("t2", "amb-ws"):
            assert client.post(f"/api/detections/{did}/disposition", headers=hdr,
                               json={"action": "dismiss"}).status_code == 200
        card, scope, prog = surfaces()
        assert card["triage"] == scope["triage"] == {"total": 3, "triaged": 3}
        assert card["ready"] is True and prog["submission_ready"] is True
        assert client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                           json={"verdict": "threat",
                                 "category": "Malware"}).status_code == 200
    finally:
        _cleanup(sid, s)


def test_submitted_record_grades_exactly_the_displayed_roster_and_stays_frozen():
    """Submitted-record protection: the record is graded against EXACTLY the
    roster displayed at submission (same ids, same count), and later attaches —
    a tagged detection, an ambient on the observable host, an ambient on the
    env-only host — never change the frozen record or its served grading."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _add_incident(s, INC, SID_SCENARIO, WS, "Malware", "malware_usb",
                          det_specs=[("t1", "true_positive", "promoted")],
                          required_isolate=False,
                          extra_env_hosts=(ENV_ONLY,),
                          ambient_specs=[("amb-ws", "dismissed", WS),
                                         ("amb-env", "open", ENV_ONLY)])
        hdr = {"X-Session-ID": sid}
        displayed = set(client.get(f"/api/incidents/{INC}/scope", headers=hdr)
                        .get_json()["detection_ids"])
        assert displayed == {"t1", "amb-ws"}
        r = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                        json={"verdict": "threat", "category": "Malware"})
        assert r.status_code == 200
        rec = s["submissions"][INC]
        assert set(rec["inputs"]["detection_dispositions"]) == displayed
        assert rec["report_card"]["detection"]["graded"] == len(displayed)
        before = client.get(f"/api/incidents/{INC}/score", headers=hdr).data
        with s["io_lock"]:
            for late in (
                {"id": "late-tagged", "scenario_id": SID_SCENARIO,
                 "disposition": "true_positive", "player_action": "open",
                 "entity": {"host": WS}},
                {"id": "late-amb-ws", "scenario_id": None,
                 "disposition": "benign_expected", "player_action": "open",
                 "entity": {"host": WS}},
                {"id": "late-amb-env", "scenario_id": None,
                 "disposition": "benign_expected", "player_action": "open",
                 "entity": {"host": ENV_ONLY}},
            ):
                s["detections"].append(late)
        after = client.get(f"/api/incidents/{INC}/score", headers=hdr).data
        assert after == before, "submitted grading changed after late attaches"
        assert set(s["submissions"][INC]["inputs"]["detection_dispositions"]) == displayed
    finally:
        _cleanup(sid, s)


# --- invariant 2: guided assistance (3.9A re-review) ------------------------------

def test_assisted_survives_submission_and_idempotent_resubmission():
    """Check Answer permanently marks the incident Assisted; the flag survives
    submission and an idempotent resubmission byte-identically, and rides on the
    immutable per-incident report."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s, category="Malware")
        s["game_mode"] = "training"
        hdr = {"X-Session-ID": sid}
        client.post(f"/api/incidents/{INC}/check-answer", headers=hdr,
                    json={"verdict": "threat", "category": "Malware"})
        first = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                           json={"verdict": "threat", "category": "Malware"}).get_json()
        assert first["assisted"] is True
        assert s["submissions"][INC]["assisted"] is True
        before = client.get(f"/api/incidents/{INC}/score", headers=hdr).data
        # idempotent resubmission: byte-identical, still Assisted
        second = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                            json={"verdict": "false_positive", "category": "z"}).get_json()
        assert second["assisted"] is True
        after = client.get(f"/api/incidents/{INC}/score", headers=hdr).data
        assert before == after
    finally:
        _cleanup(sid, s)


def test_unassisted_incident_reports_assisted_false():
    """An incident submitted WITHOUT Check Answer carries assisted=False (the
    blind-run condition)."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)
        s["game_mode"] = "training"
        view = client.post(f"/api/incidents/{INC}/submit",
                          headers={"X-Session-ID": sid},
                          json={"verdict": "threat", "category": "Malware"}).get_json()
        assert view["assisted"] is False
    finally:
        _cleanup(sid, s)


# --- invariant 3: classification enforcement (3.9A re-review) ---------------------

def test_submit_without_valid_classification_creates_no_record():
    """A submission must carry a valid classification; the API rejects its
    absence with a neutral 400 and NO record is created. Enforced server-side,
    never defaulted."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            _seed_incident(s)  # sealed + dispositioned => ready, so only the
            #                     classification gate can block this submit
        hdr = {"X-Session-ID": sid}
        for bad in ({}, {"category": "Malware"}, {"verdict": "maybe"},
                    {"verdict": "threat"}, {"verdict": "threat", "category": "  "}):
            r = client.post(f"/api/incidents/{INC}/submit", headers=hdr, json=bad)
            assert r.status_code == 400, f"payload {bad} was not rejected"
            assert r.get_json().get("reason") == "invalid_classification"
            blob = json.dumps(r.get_json())
            assert "correct" not in blob and "composite" not in blob  # neutral
            assert INC not in s["submissions"], f"payload {bad} created a record"
        # a valid classification then submits
        ok = client.post(f"/api/incidents/{INC}/submit", headers=hdr,
                        json={"verdict": "threat", "category": "Malware"})
        assert ok.status_code == 200 and ok.get_json()["state"] == "submitted"
        assert INC in s["submissions"]
    finally:
        _cleanup(sid, s)


def test_unknown_incident_is_404_everywhere():
    client, sid, s = _api_session()
    try:
        hdr = {"X-Session-ID": sid}
        assert client.get("/api/incidents/INC-9999/score", headers=hdr).status_code == 404
        assert client.post("/api/incidents/INC-9999/submit", headers=hdr,
                          json={"verdict": "threat"}).status_code == 404
        assert client.post("/api/incidents/INC-9999/check-answer", headers=hdr,
                          json={"verdict": "threat"}).status_code == 404
    finally:
        _cleanup(sid, s)


def _run_all():
    import inspect
    fns = [(n, f) for n, f in globals().items()
           if n.startswith("test_") and inspect.isfunction(f)]
    passed = 0
    for n, f in sorted(fns):
        f()
        passed += 1
        print(f"  ok  {n}")
    print(f"\n{passed}/{len(fns)} submission-gate tests passed")


if __name__ == "__main__":
    _run_all()
