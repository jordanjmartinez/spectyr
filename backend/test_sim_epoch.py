"""Stage 4 Phase 1.1: the simulation-epoch determinism suite (contract R8/A1).

Proves: the epoch is a pure function of session identity inside the canonical
work-week window; world["started_at"] IS the epoch; authored occurrence times
recompute exactly from (epoch, per-position spacing, authored offsets, the
dedicated seeded gap stream) with no wall-clock input; and the response-action
clock is untouched (it inherits the epoch through started_at; scoring never
reads timestamps). Background occurrence times are Phase 1.2 (test_event_seq).

Run: python test_sim_epoch.py   (also: python -m pytest test_sim_epoch.py -q)
"""
import inspect
import json
import os
import shutil
import sys
import time
from datetime import timedelta, timezone

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay  # noqa: E402
import sim_epoch  # noqa: E402


# --- epoch derivation --------------------------------------------------------

def test_epoch_deterministic_per_session_id():
    a1 = sim_epoch.epoch_dt("session-aaaa")
    a2 = sim_epoch.epoch_dt("session-aaaa")
    b = sim_epoch.epoch_dt("session-bbbb")
    assert a1 == a2, "same session id must yield the same epoch"
    assert a1 != b, "different session ids must yield different epochs"
    for e in (a1, b):
        assert e.tzinfo is not None and e.utcoffset() == timedelta(0)
        assert e.second == 0 and e.microsecond == 0, "whole minutes only"
        offset_min = (e - sim_epoch.SIM_BASE).total_seconds() / 60
        assert 0 <= offset_min < sim_epoch.EPOCH_WINDOW_MINUTES, \
            "epoch must land inside the canonical work-week window"
    assert sim_epoch.epoch_dt(None) == sim_epoch.SIM_BASE, \
        "bare harness sessions fall back to SIM_BASE"
    assert sim_epoch.epoch_iso("session-aaaa") == a1.isoformat()


def test_authored_base_spacing():
    sid = "session-cccc"
    e = sim_epoch.epoch_dt(sid)
    assert sim_epoch.authored_base(sid, 1) == e
    assert sim_epoch.authored_base(sid, 4) == e + timedelta(
        seconds=3 * sim_epoch.POSITION_SPACING_S)
    assert sim_epoch.authored_base(sid, None) == e, "missing position -> base"


# --- authored occurrence-time recomputation ---------------------------------

def _expected_chain_times(label, session_id, position):
    """Recompute the chain's occurrence timestamps from first principles:
    epoch + position spacing + authored offsets, with [lo, hi] ranges drawn
    from a fresh copy of the session's dedicated gap stream (mirroring
    _raw_chain_yaml's draw order exactly)."""
    scenario = app.yaml_catalog[label]
    rng = sim_epoch.gap_rng(session_id)
    base = sim_epoch.authored_base(session_id, position)
    times, cum = [], 0
    for i, step in enumerate(scenario["chain"]):
        off = step.get("offset", 0)
        gap = 0 if i == 0 else (rng.randint(off[0], off[1])
                                if isinstance(off, list) else off)
        cum += gap
        times.append((base + timedelta(seconds=cum)).isoformat())
    return times


def _build_chain(session_id, label, position):
    emp = next(e for e in app.EMPLOYEES if e["name"] == "nkhan")
    session = {"id": session_id, "used_alert_ids": set(),
               "gap_rng": sim_epoch.gap_rng(session_id)}
    entry = {"scenario_label": label, "queue_position": position,
             "ticket_title": "T", "storyline": "S", "category": "C"}
    logs = app.build_attack_chain_logs(session, entry, employee=emp)
    assert logs, f"no chain rendered for {label}"
    return logs


def test_occurrence_times_recompute_from_epoch_spacing_offsets_gapstream():
    sid = "session-recompute"
    for label, position in (("malware_usb", 1), ("data_exfil_archive", 3),
                            ("brute_force_attack", 10)):
        logs = _build_chain(sid, label, position)
        expected = _expected_chain_times(label, sid, position)
        got = [l["timestamp"] for l in logs]
        assert got == expected, (
            f"{label} at position {position}: occurrence times diverge from "
            f"the epoch recomputation\n got: {got}\n exp: {expected}")


def test_no_wall_clock_in_occurrence_timestamps():
    """Two builds of the same (session id, scenario, position) separated by
    real wall time produce byte-identical occurrence timestamps; wall time is
    structurally absent from the derivation."""
    sid = "session-nowall"
    first = [l["timestamp"] for l in _build_chain(sid, "phishing_1", 2)]
    time.sleep(0.05)
    second = [l["timestamp"] for l in _build_chain(sid, "phishing_1", 2)]
    assert first == second, "wall clock leaked into occurrence timestamps"


def test_negative_supplemental_offsets_precede_epoch_base():
    """data_exfil_archive authors supplemental events at negative offsets; at
    position 1 their occurrence times land BEFORE the epoch. This is the fact
    behind the corrected `all`-range rule (start = minimum visible occurrence,
    scaffold Section 2.7); the query-read fixture lands in Phase 3."""
    scenario = app.yaml_catalog["data_exfil_archive"]
    offsets = [s.get("offset", 0) for s in scenario.get("supplemental_events", [])]
    assert any(o < 0 for o in offsets), \
        "expected an authored negative supplemental offset in data_exfil_archive"


# --- started_at == epoch (live session) --------------------------------------

def test_world_started_at_equals_epoch():
    client = app.app.test_client()
    sid = client.get("/api/health").headers["X-Session-ID"]
    s = app.sessions[sid]
    try:
        r = client.post("/api/start-simulator",
                        headers={"X-Session-ID": sid,
                                 "Content-Type": "application/json"},
                        data=json.dumps({"game_mode": "guided",
                                         "catalog_id": "random",
                                         "analyst_name": "Probe"}))
        assert r.status_code == 200
        assert s["world"]["started_at"] == sim_epoch.epoch_iso(sid)
        assert s["gap_rng"] is not None
    finally:
        app.sessions.pop(sid, None)
        s["paused"] = True
        time.sleep(1.2)
        shutil.rmtree(s.get("session_dir", ""), ignore_errors=True)


# --- response-action clock: unchanged, aligned, score-neutral ----------------

def test_action_clock_base_equals_epoch():
    """The action clock is byte-for-byte the Stage 3.9 formula
    (started_at + seq seconds); under A1 it inherits the epoch through
    started_at with zero code change (scaffold Section 2.4b)."""
    sid = "session-actionclock"
    overlay = action_overlay.new_overlay()
    entry = action_overlay.record_attempt(
        overlay, sim_epoch.epoch_iso(sid), "isolate_host", "ent-abcdef123456",
        {"kind": "host", "hostname": "ACME-WS10"}, "success", "containment")
    expected = (sim_epoch.epoch_dt(sid) + timedelta(seconds=1)).isoformat()
    assert entry["timestamp"] == expected
    second = action_overlay.record_attempt(
        overlay, sim_epoch.epoch_iso(sid), "release_host", "ent-abcdef123456",
        {"kind": "host", "hostname": "ACME-WS10"}, "success", "release")
    assert second["timestamp"] == (
        sim_epoch.epoch_dt(sid) + timedelta(seconds=2)).isoformat(), \
        "monotonic +1s sequence must be preserved"


def test_action_score_is_timestamp_invariant():
    """Scoring never reads the action-log clock: compute_action_score's source
    references no timestamp key (structural guard, same technique as
    test_incident_scope's no-answer-key-input guard)."""
    src = inspect.getsource(app.compute_action_score)
    assert '"timestamp"' not in src and "'timestamp'" not in src, \
        "compute_action_score must not read action timestamps"


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
        print(f"[test_sim_epoch] {failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"[test_sim_epoch] all {len(tests)} passed")
