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

# The client-safe field set, sourced from the server code itself so the test
# tracks the whitelist rather than duplicating it. (The GROUP/STATS whitelists
# retired with /api/grouped-alerts in P8.3.)
FEED = set(dt.FEED_EVENT_WHITELIST)

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


# P8.3: the single event path. Rows are fetched through the query read; the
# legacy /api/fake-events and /api/grouped-alerts routes are deleted.
_Q_ALL = "/api/events/query?q=all%20%7C%20*%20%7C%20*%20%7C%20*&scope=session"


def _query_rows(client, sid):
    r = client.get(_Q_ALL, headers={"X-Session-ID": sid})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()["rows"]


# --- unit --------------------------------------------------------------------

def test_sanitize_feed_event_strips_all_but_whitelist():
    ev = _attack_event()
    out = dt.sanitize_feed_event(ev)
    assert set(out) <= FEED, f"leaked keys: {set(out) - FEED}"
    assert not (FORBIDDEN & set(out)), f"forbidden key: {FORBIDDEN & set(out)}"
    assert out["id"] == "atk-1"                     # opaque row id retained
    assert out["message"] == "suspicious encryption activity"
    assert out["key_value_pairs"]["process_id"] == "8844"   # kvp blob preserved
    # OD-10: protocol never serializes top-level; it lands inside a COPIED kvp
    assert "protocol" not in out
    assert out["key_value_pairs"]["protocol"] == "tcp"
    assert "protocol" not in ev["key_value_pairs"], \
        "the stored log's kvp must never be mutated by serialization"


def test_generated_background_traffic_is_sanitized():
    # A REAL normal-traffic event carries a non-null scenario_id, `user`, label,
    # detected_by, process ids -- none may survive sanitization.
    normal = app.generate_normal_event()
    assert normal["scenario_id"] is not None        # confirms the leak source
    out = dt.sanitize_feed_event(normal)
    assert set(out) <= FEED
    for k in ("scenario_id", "label", "user", "detected_by",
              "process_id", "parent_process_id", "flagged", "protocol"):
        assert k not in out
    # OD-10: the canonical account field is present on background events too
    assert out["user_account"] == normal["user"]
    # OD-10: a background protocol value serializes inside key_value_pairs
    if normal.get("protocol") not in (None, ""):
        assert out["key_value_pairs"]["protocol"] == normal["protocol"]


def test_shape_parity_no_population_exclusive_top_level_field():
    """OD-10 acceptance (contract Section 18 'Shape parity'): no serialized
    row carries top-level `protocol`, and every row whose internal shape has
    account data (authored `user_account` or background `user`) serializes
    the canonical `user_account` -- so top-level field presence never marks a
    row as authored or background.

    The authored-side proof is deterministic (a built chain, no drip race:
    malware_usb authors both `user_account` and a kvp-nested protocol); the
    live-drip sweep then proves uniformity over both real populations without
    depending on WHICH random scenario dripped or how far its chain got."""
    # authored side, deterministic
    emp = next(e for e in app.EMPLOYEES if e["name"] == "nkhan")
    chain = app.build_attack_chain_logs(
        {"used_alert_ids": set()},
        {"scenario_label": "malware_usb", "queue_position": 1,
         "ticket_title": "T", "storyline": "S", "category": "C"},
        employee=emp)
    authored = [dt.sanitize_feed_event(l) for l in chain]
    assert all("protocol" not in e for e in authored)
    assert any(e.get("user_account") for e in authored), \
        "authored population must carry the canonical account field"

    # live drip, both real populations
    client, sid, s = _api_session()
    try:
        r = client.post("/api/start-simulator",
                        headers={"X-Session-ID": sid,
                                 "Content-Type": "application/json"},
                        data=json.dumps({"game_mode": "guided",
                                         "catalog_id": "random",
                                         "analyst_name": "Probe"}))
        assert r.status_code == 200
        hdr = {"X-Session-ID": sid}
        deadline = time.time() + 25
        raw, feed = [], []
        while time.time() < deadline:
            raw = app.read_ndjson(s, "generated_logs")
            feed = _query_rows(client, sid)
            has_bg = any(l.get("label") == "normal_traffic" for l in raw)
            has_atk = any(l.get("label") not in (None, "normal_traffic")
                          for l in raw)
            if has_bg and has_atk and len(feed) >= 6:
                break
            time.sleep(0.3)
        assert raw and feed, "no live drip captured"
        by_id = {e["id"]: e for e in feed}
        saw_bg_account = False
        for l in raw:
            e = by_id.get(l["id"])
            assert e is not None, "every pool row must serialize"
            assert "protocol" not in e, \
                "top-level protocol is a population discriminator (OD-10)"
            internal_account = l.get("user_account") or l.get("user")
            if internal_account:
                assert e.get("user_account") == internal_account
                if l.get("label") == "normal_traffic":
                    saw_bg_account = True
            if l.get("protocol") not in (None, ""):
                assert e["key_value_pairs"]["protocol"] == l["protocol"]
        assert saw_bg_account, \
            "background rows always carry `user`; the canonical mapping " \
            "must have produced user_account on at least one"
    finally:
        _stop(sid, s)


# --- the query read (P8.3 retarget of the fake-events guards) ----------------

def test_query_rows_serialize_only_the_whitelist():
    """P8.3 retarget (was test_fake_events_serializes_only_the_whitelist):
    identical assertions over rows from the single event path."""
    client, sid, s = _api_session()
    try:
        _seed(s)
        events = _query_rows(client, sid)
        assert len(events) == 2
        for e in events:
            extra = set(e) - FEED
            assert not extra, f"feed event leaked keys: {extra}"
            assert not (FORBIDDEN & set(e)), f"forbidden key present: {e}"
            assert "id" in e                        # required row identity
    finally:
        _stop(sid, s)


def test_query_rows_unknown_future_field_does_not_pass_through():
    """P8.3 retarget (was test_fake_events_unknown_future_field_does_not_
    pass_through): identical assertions over the single event path."""
    client, sid, s = _api_session()
    try:
        _seed(s, with_marker=True)
        events = _query_rows(client, sid)
        for e in events:
            assert "__future_internal__" not in e
            assert set(e) <= FEED
    finally:
        _stop(sid, s)


# test_grouped_alerts_serializes_only_the_whitelist RETIRED with its route
# (P8.3, scaffold Section 3.5 map): the group whitelist has no serialization
# to guard. Readiness disclosure on the surviving surface is guarded by
# test_submission_gate.py::test_incident_cards_surface_incident_scoped_
# readiness; /api/incidents card fields are guarded by the 3.9B suites.


# --- planted marker (recursive) ---------------------------------------------

def test_no_planted_answer_marker_in_query_or_count_response():
    """P8.3 retarget (was test_no_planted_answer_marker_in_either_response,
    over the two retired routes): the marker scan now covers the query read
    (rows + identity, the whole response) and the token-bound count read."""
    client, sid, s = _api_session()
    try:
        _seed(s, with_marker=True)
        hdr = {"X-Session-ID": sid}
        q = client.get(_Q_ALL, headers=hdr).get_json()
        count = client.get("/api/events/query/new-count?token=" + q["token"],
                           headers=hdr).get_json()
        for name, resp in (("events-query", q), ("new-count", count)):
            hits = [v for v in _all_strings(resp) if MARKER in v]
            assert not hits, f"planted marker leaked in {name}: {hits}"
    finally:
        _stop(sid, s)


def test_planted_marker_absent_in_query_and_count_in_every_mode():
    """Phase 9 closure gap-fill: the recursive planted-marker scan, PER MODE.
    The scan above proves the serializer strips markers on a seeded modeless
    session; this runs the same scan through a REAL session started in each
    player mode (Guided / SOC Queue [internal key `analyst`] / Hardcore),
    planting a marker-laden pool event through the live append-and-stamp
    choke point and scanning the full query + new-count responses
    recursively. The presence assertion keeps the scan non-vacuous."""
    for mode in ("guided", "analyst", "hardcore"):
        client, sid, s = _api_session()
        try:
            body = {"game_mode": mode, "analyst_name": "Probe"}
            if mode == "guided":
                body["catalog_id"] = "random"
            r = client.post("/api/start-simulator",
                            headers={"X-Session-ID": sid,
                                     "Content-Type": "application/json"},
                            data=json.dumps(body))
            assert r.status_code == 200, (mode, r.get_data(as_text=True))
            app.append_pool_event(s, {
                "id": "mark-1", "timestamp": STARTED, "scenario_id": SID,
                "chain_complete": True, "label": "malware_ransomware",
                "category": MARKER, "storyline": MARKER,
                "threat_pattern": MARKER, "level_name": MARKER,
                "alert_id": INC, "analyst_category": MARKER,
                "__future_internal__": MARKER,
                "message": "benign-looking message", "severity": "low",
                "hostname": HOST, "source_type": "Sysmon",
                "source_ip": "10.0.1.24", "key_value_pairs": {}})
            hdr = {"X-Session-ID": sid}
            q = client.get(_Q_ALL, headers=hdr).get_json()
            count = client.get("/api/events/query/new-count?token="
                               + q["token"], headers=hdr).get_json()
            assert any(e.get("id") == "mark-1" for e in q["rows"]), \
                f"{mode}: the marker-laden row must be visible (sanitized), " \
                "else the scan is vacuous"
            for name, resp in (("events-query", q), ("new-count", count)):
                hits = [v for v in _all_strings(resp) if MARKER in v]
                assert not hits, \
                    f"{mode}: planted marker leaked in {name}: {hits}"
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
                events = _query_rows(client, sid)
                if len(events) >= 5:
                    break
                time.sleep(0.3)
            assert events, f"no events dripped in mode={mode}"
            for e in events:
                extra = set(e) - FEED
                assert not extra, f"{mode}: feed leaked keys {extra}"
                assert not (FORBIDDEN & set(e)), f"{mode}: forbidden key present"
            # P8.3: the surviving aggregate surface is /api/incidents -- the
            # forbidden-vocabulary and marker scans continue there (the group
            # whitelist retired with the grouped-alerts route)
            inc = client.get("/api/incidents", headers=hdr).get_json()
            leaked = FORBIDDEN & _all_keys(inc)
            assert not leaked, f"{mode}: /api/incidents leaked {leaked}"
            assert not [v for v in _all_strings(inc) if MARKER in v]
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
