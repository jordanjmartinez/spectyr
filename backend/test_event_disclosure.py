"""Pre-Stage-4 event-disclosure hotfix: the permanent leak-guard suite for the
two legacy event endpoints.

Both /api/fake-events and /api/grouped-alerts historically serialized the raw
event pool to the browser, leaking scenario wiring and the classification answer
(category, scenario_id, label, threat_pattern, storyline, level_name, alert_id,
...). The frontend display whitelist hid these from view, but they rode the
network payload -- a client-side render filter is not a disclosure boundary.

This suite proves the SERVER now whitelists both endpoints so no answer-bearing
field reaches the client at any nesting level, for authored attack events AND
generated background traffic, across modes and independent runs, and that an
unknown future internal field does not pass through. It uses RECURSIVE response
inspection (not a top-level key check) for the planted-marker guard.

Run: python test_event_disclosure.py   (also: python -m pytest test_event_disclosure.py -q)
"""
import json
import os
import shutil
import sys
import time

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import detection_templates as dt  # noqa: E402

STARTED = "2026-07-17T12:00:00+00:00"
SID = "scenario-mal-x"
INC = "INC-7777"
HOST = "ACME-WS12"
MARKER = "ZZZ_ANSWER_KEY_MARKER_ZZZ"

# The client-safe field sets, sourced from the server code itself so the test
# tracks the whitelist rather than duplicating it.
FEED = set(dt.FEED_EVENT_WHITELIST)
GROUP = {"incident_id", "detections_sealed", "open_detections", "submission_ready"}
STATS = {"total_alerts", "closed_alerts", "open_alerts",
         "severity_breakdown", "source_breakdown"}

# Answer-bearing / scenario-wiring / internal keys that must never surface on an
# event or a group (exact top-level keys; SIEM detail inside key_value_pairs is
# legitimately arbitrary and is NOT screened as a top-level key).
FORBIDDEN = {
    "category", "scenario_id", "label", "threat_pattern", "storyline",
    "level_name", "ticket_title", "analyst_category", "alert_id", "level",
    "flagged", "status", "detected_by", "log_source", "trigger", "red_herring",
    "offset", "chain_complete", "host", "user", "process_id",
    "parent_process_id", "logs", "log_count", "total_log_count", "hidden_count",
    "group_severity", "pivot_values", "disposition", "expected_actions",
    "answer_key", "__future_internal__",
}


# --- helpers -----------------------------------------------------------------

def _api_session():
    client = app.app.test_client()
    sid = client.get("/api/health").headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _stop(sid, s):
    # Removing the session signals the log_writer thread to exit (it checks
    # `session['id'] not in sessions` at the top of every tick); pause + a short
    # wait let it drain before the dir is removed.
    app.sessions.pop(sid, None)
    s["paused"] = True
    time.sleep(1.2)
    shutil.rmtree(s.get("session_dir", ""), ignore_errors=True)


def _all_strings(obj):
    """Every string scalar anywhere in a nested JSON structure (recursive,
    including inside key_value_pairs) -- for the planted-marker guard."""
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_all_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_all_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _all_keys(obj):
    """Every dict key anywhere in a nested JSON structure (recursive)."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            out |= _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _all_keys(v)
    return out


def _attack_event(**over):
    """A drip-time attack event carrying EVERY answer-bearing field the real
    build_attack_chain_logs stamps, plus schema-v2 authored tags -- the worst
    case the sanitizer must strip."""
    ev = {
        "id": "atk-1", "timestamp": STARTED, "scenario_id": SID,
        "label": "malware_ransomware", "category": "Malware",
        "threat_pattern": "Ransomware Encryption", "storyline": "the secret plot",
        "level_name": "Ransomware Ticket", "ticket_title": "Ransomware Ticket",
        "analyst_category": "Malware", "alert_id": INC, "level": 2,
        "status": "active", "flagged": True, "chain_complete": True,
        "trigger": True, "detected_by": "Sysmon", "red_herring": False,
        "log_source": "Microsoft-Windows-Sysmon/Operational", "offset": 3,
        "host": HOST, "user": "ACME\\jdoe",
        # legitimate raw-log fields (must survive):
        "severity": "high", "hostname": HOST, "source_ip": "10.0.1.24",
        "destination_ip": "8.8.8.8", "user_account": "ACME\\jdoe",
        "message": "suspicious encryption activity", "source_type": "Sysmon",
        "protocol": "tcp",
        # key_value_pairs legitimately holds arbitrary SIEM detail (incl. keys
        # like process_id / image) -- it is a whitelisted blob:
        "key_value_pairs": {"image": "C:\\evil.exe", "command_line": "evil -enc",
                            "process_id": "8844"},
    }
    ev.update(over)
    return ev


def _seed(s, with_marker=False):
    """Seed a sealed incident (queue + reviewed grading + a chain-complete attack
    event with every answer field), one REAL generated normal-traffic event, and
    optionally a marker-laden event carrying forbidden fields + an unknown field.
    No drip thread is started."""
    logs = [_attack_event()]
    logs.append(app.generate_normal_event())            # real background traffic
    if with_marker:
        logs.append({
            "id": "mark-1", "timestamp": STARTED, "scenario_id": SID,
            "chain_complete": True, "label": "malware_ransomware",
            "category": MARKER, "storyline": MARKER, "threat_pattern": MARKER,
            "level_name": MARKER, "alert_id": INC, "analyst_category": MARKER,
            "__future_internal__": MARKER,               # an unknown internal field
            "message": "benign-looking message", "severity": "low",
            "hostname": HOST, "source_type": "Sysmon", "source_ip": "10.0.1.24",
            "key_value_pairs": {},
        })
    app._write_ndjson_unlocked(s["paths"]["generated_logs"], logs)
    s.setdefault("incident_index", {})[INC] = SID
    s.setdefault("alert_queue", []).append({
        "scenario_id": SID, "incident_id": INC, "queue_position": 1,
        "ticket_title": "Ransomware Ticket", "storyline": "",
        "injected_at": STARTED, "chain_complete_at": STARTED,
        "scenario_label": "malware_ransomware"})
    s["queue_length"] = 1
    s.setdefault("scenario_grading", []).append({
        "scenario_id": SID, "reviewed": True,
        "hostnames": {HOST}, "accounts": set()})
    s.setdefault("benign_hosts", set()).add(HOST)
    s.setdefault("detections", [])
    s["detection_index"] = {}


# --- unit --------------------------------------------------------------------

def test_sanitize_feed_event_strips_all_but_whitelist():
    out = dt.sanitize_feed_event(_attack_event())
    assert set(out) <= FEED, f"leaked keys: {set(out) - FEED}"
    assert not (FORBIDDEN & set(out)), f"forbidden key: {FORBIDDEN & set(out)}"
    assert out["id"] == "atk-1"                     # opaque row id retained
    assert out["message"] == "suspicious encryption activity"
    assert out["key_value_pairs"]["process_id"] == "8844"   # kvp blob preserved
    assert out["protocol"] == "tcp"                 # benign filter field retained


def test_generated_background_traffic_is_sanitized():
    # A REAL normal-traffic event carries a non-null scenario_id, `user`, label,
    # detected_by, process ids -- none may survive sanitization.
    normal = app.generate_normal_event()
    assert normal["scenario_id"] is not None        # confirms the leak source
    out = dt.sanitize_feed_event(normal)
    assert set(out) <= FEED
    for k in ("scenario_id", "label", "user", "detected_by",
              "process_id", "parent_process_id", "flagged"):
        assert k not in out


# --- /api/fake-events --------------------------------------------------------

def test_fake_events_serializes_only_the_whitelist():
    client, sid, s = _api_session()
    try:
        _seed(s)
        events = client.get("/api/fake-events",
                            headers={"X-Session-ID": sid}).get_json()
        assert len(events) == 2
        for e in events:
            extra = set(e) - FEED
            assert not extra, f"feed event leaked keys: {extra}"
            assert not (FORBIDDEN & set(e)), f"forbidden key present: {e}"
            assert "id" in e                        # required row identity
    finally:
        _stop(sid, s)


def test_fake_events_unknown_future_field_does_not_pass_through():
    client, sid, s = _api_session()
    try:
        _seed(s, with_marker=True)
        events = client.get("/api/fake-events",
                            headers={"X-Session-ID": sid}).get_json()
        for e in events:
            assert "__future_internal__" not in e
            assert set(e) <= FEED
    finally:
        _stop(sid, s)


# --- /api/grouped-alerts -----------------------------------------------------

def test_grouped_alerts_serializes_only_the_whitelist():
    client, sid, s = _api_session()
    try:
        _seed(s)
        body = client.get("/api/grouped-alerts",
                          headers={"X-Session-ID": sid}).get_json()
        assert set(body) == {"alerts", "stats"}
        assert set(body["stats"]) <= STATS
        assert body["alerts"], "expected the sealed incident group"
        for grp in body["alerts"]:
            extra = set(grp) - GROUP
            assert not extra, f"group leaked keys: {extra}"
        # every nested key across the whole response is answer-free
        leaked = FORBIDDEN & _all_keys(body)
        assert not leaked, f"forbidden key nested in grouped-alerts: {leaked}"
        # observable readiness still present and correct (Stage 3.9A contract)
        grp = next(g for g in body["alerts"] if g["incident_id"] == INC)
        assert grp["detections_sealed"] is True
        assert grp["open_detections"] == 0
        assert grp["submission_ready"] is True
    finally:
        _stop(sid, s)


# --- planted marker (recursive) ---------------------------------------------

def test_no_planted_answer_marker_in_either_response():
    client, sid, s = _api_session()
    try:
        _seed(s, with_marker=True)
        hdr = {"X-Session-ID": sid}
        feed = client.get("/api/fake-events", headers=hdr).get_json()
        grouped = client.get("/api/grouped-alerts", headers=hdr).get_json()
        for name, resp in (("fake-events", feed), ("grouped-alerts", grouped)):
            hits = [v for v in _all_strings(resp) if MARKER in v]
            assert not hits, f"planted marker leaked in {name}: {hits}"
    finally:
        _stop(sid, s)


# --- incident scoping must not reintroduce hidden fields ---------------------

def test_incident_scope_carries_no_hidden_fields():
    # /api/incidents/<id>/scope is separately guarded by test_incident_scope.py;
    # this asserts the event-disclosure vocabulary specifically does not surface
    # through the scoped read either.
    client, sid, s = _api_session()
    try:
        _seed(s, with_marker=True)
        body = client.get(f"/api/incidents/{INC}/scope",
                          headers={"X-Session-ID": sid}).get_json()
        leaked = FORBIDDEN & _all_keys(body)
        assert not leaked, f"scope leaked forbidden keys: {leaked}"
        assert not [v for v in _all_strings(body) if MARKER in v]
    finally:
        _stop(sid, s)


# --- live drip: real generators, across modes --------------------------------

def test_live_drip_feed_is_clean_across_modes():
    """Exercise the REAL drip (build_attack_chain_logs + generate_normal_event)
    in each mode, so the guard covers actual generator output, not only the
    hand-seeded shapes. Each run draws an independent random scenario sample."""
    for mode in ("guided", "analyst", "hardcore"):
        client, sid, s = _api_session()
        try:
            body = {"game_mode": mode, "analyst_name": "Probe"}
            if mode in ("guided", "training"):
                body["catalog_id"] = "random"
            r = client.post("/api/start-simulator",
                            headers={"X-Session-ID": sid,
                                     "Content-Type": "application/json"},
                            data=json.dumps(body))
            assert r.status_code == 200, (mode, r.status_code,
                                          r.get_data(as_text=True))
            hdr = {"X-Session-ID": sid}
            events = []
            deadline = time.time() + 20
            while time.time() < deadline:
                events = client.get("/api/fake-events", headers=hdr).get_json()
                if len(events) >= 5:
                    break
                time.sleep(0.3)
            assert events, f"no events dripped in mode={mode}"
            for e in events:
                extra = set(e) - FEED
                assert not extra, f"{mode}: feed leaked keys {extra}"
                assert not (FORBIDDEN & set(e)), f"{mode}: forbidden key present"
            grouped = client.get("/api/grouped-alerts", headers=hdr).get_json()
            for grp in grouped.get("alerts", []):
                extra = set(grp) - GROUP
                assert not extra, f"{mode}: group leaked keys {extra}"
            assert not [v for v in _all_strings(grouped) if MARKER in v]
        finally:
            _stop(sid, s)


if __name__ == "__main__":
    import traceback
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok  {name}")
        except Exception:
            failed += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
    if failed:
        print(f"[test_event_disclosure] {failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"[test_event_disclosure] all {len(tests)} passed")
