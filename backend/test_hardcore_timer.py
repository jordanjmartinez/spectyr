"""Stage 6 playtest fix: Hardcore timer expiry is self-enforcing.

Run: python test_hardcore_timer.py  (or python -m pytest test_hardcore_timer.py -q)

The defect: expiry lived only in a client poll. If no poll delivered
timer_expired at 0:00, the run kept running -- the drip continued and triage
stayed live on a dead run, with the failure overlay appearing only on the
next interaction-driven read. The contract pinned here:

- the first /api/game-state read past the deadline pauses the session on its
  own (the drip gate) and freezes the clock at a post-deadline instant, so
  timer_expired stays latched True on every later read;
- a pause that happens BEFORE the deadline (queue completion, wrong-submit)
  freezes the clock below the duration and never reads as expired;
- POST /api/game-timeout clamps the frozen clock to no earlier than the
  deadline, so a client countdown firing a beat early still latches;
- the timer is hardcore-only: training never expires, and the timeout POST
  is rejected outside hardcore;
- a reset re-arms: timer_expired reads False again (the frontend re-arms its
  one-shot trigger on exactly that transition).

Retry (bug 2) contract, pinned here too:

- a stale timeout report (an out-of-order poll surviving from a dead run)
  can never halt a fresh run: /api/game-timeout refuses reports further than
  TIMEOUT_EARLY_TOLERANCE_SECONDS from the deadline, and no-ops without
  moving the frozen clock when the session is already halted;
- the full Retry cycle (expiry latch -> reset -> start) lands a genuinely
  fresh hardcore run: full timer, not expired, unpaused, fresh queue, and a
  bumped run generation (run_seq);
- the surviving log-writer thread drops its leftover chain state at the
  generation bump, so the retried run's pool never contains ghost events
  carrying the dead run's scenario id.
"""
import os
import shutil
import time as time_mod
from datetime import datetime, timezone, timedelta

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")

import app  # noqa: E402

DURATION = app.get_timer_duration(1)


def _api_session():
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def _hardcore(s, elapsed_seconds, paused=False):
    s["game_mode"] = "hardcore"
    s["timer_start"] = datetime.now(timezone.utc) - timedelta(seconds=elapsed_seconds)
    s["paused"] = paused
    s["timer_paused_at"] = None


def _game_state(client, sid):
    r = client.get("/api/game-state", headers={"X-Session-ID": sid})
    assert r.status_code == 200
    return r.get_json()


def test_expiry_auto_pauses_and_latches():
    """The first read past the deadline ends the run server-side, and the
    expired flag survives every subsequent read (frozen clock >= deadline)."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, DURATION + 5)
        data = _game_state(client, sid)
        assert data["timer_expired"] is True
        assert data["timer_remaining"] == 0
        assert s["paused"] is True, "expired run must pause (the drip gate)"
        assert s["timer_paused_at"] is not None
        frozen = (s["timer_paused_at"] - s["timer_start"]).total_seconds()
        assert frozen >= DURATION, "frozen elapsed must sit at/after the deadline"
        # Latched: later reads of the paused session still report expiry.
        again = _game_state(client, sid)
        assert again["timer_expired"] is True
        assert again["timer_remaining"] == 0
        assert again["paused"] is True
    finally:
        _cleanup(sid, s)


def test_pre_deadline_pause_never_reads_expired():
    """A session paused before the deadline (completion, wrong-submit)
    freezes below the duration: no failure overlay after a finished run."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, 100, paused=True)
        data = _game_state(client, sid)
        assert data["timer_expired"] is False
        assert data["timer_remaining"] > 0
        first_remaining = data["timer_remaining"]
        again = _game_state(client, sid)
        assert again["timer_expired"] is False
        assert again["timer_remaining"] == first_remaining, "paused clock must not drift"
    finally:
        _cleanup(sid, s)


def test_timeout_post_latches_even_a_beat_early():
    """The client countdown may fire ~a second before the server clock
    crosses zero; the timeout POST clamps the frozen clock to the deadline
    so the run still reads as expired, not paused-with-time-remaining."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, DURATION - 2)  # 2s still on the server clock
        r = client.post("/api/game-timeout", headers={"X-Session-ID": sid})
        assert r.status_code == 200
        assert s["paused"] is True
        frozen = (s["timer_paused_at"] - s["timer_start"]).total_seconds()
        assert frozen >= DURATION, "clamp must push the frozen clock to the deadline"
        data = _game_state(client, sid)
        assert data["timer_expired"] is True
        assert data["timer_remaining"] == 0
    finally:
        _cleanup(sid, s)


def test_timeout_post_rejected_outside_hardcore():
    client, sid, s = _api_session()
    try:
        s["game_mode"] = "guided"
        r = client.post("/api/game-timeout", headers={"X-Session-ID": sid})
        assert r.status_code == 400
    finally:
        _cleanup(sid, s)


def test_training_never_expires_or_auto_pauses():
    client, sid, s = _api_session()
    try:
        s["game_mode"] = "training"
        s["timer_start"] = datetime.now(timezone.utc) - timedelta(seconds=DURATION + 500)
        s["paused"] = False
        s["timer_paused_at"] = None
        data = _game_state(client, sid)
        assert data["timer_expired"] is False
        assert data["timer_remaining"] is None
        assert s["paused"] is False, "auto-pause is hardcore-only"
    finally:
        _cleanup(sid, s)


def test_reset_rearms_the_expired_flag():
    """After a latched expiry, a reset reads as non-expired again -- the
    observable transition the frontend re-arms its one-shot trigger on."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, DURATION + 5)
        assert _game_state(client, sid)["timer_expired"] is True
        r = client.post("/api/reset-simulator", headers={"X-Session-ID": sid})
        assert r.status_code == 200
        data = _game_state(client, sid)
        assert data["timer_expired"] is False
        assert data["timer_remaining"] is None
    finally:
        _cleanup(sid, s)


def test_stale_timeout_post_cannot_kill_a_fresh_run():
    """An out-of-order expiry report from a dead run arriving against the
    retried run is refused: no pause, no clock stamp, run stays alive."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, 10)  # a fresh run, 10s in
        r = client.post("/api/game-timeout", headers={"X-Session-ID": sid})
        assert r.status_code == 409
        assert s["paused"] is False
        assert s["timer_paused_at"] is None
        data = _game_state(client, sid)
        assert data["timer_expired"] is False
        assert data["timer_remaining"] > DURATION - 60
    finally:
        _cleanup(sid, s)


def test_timeout_post_noop_when_already_halted():
    """A late client report against an already-halted session (completion,
    wrong-submit, auto-pause) never moves the frozen clock -- in particular
    it cannot convert a completed run into an expired one."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, 100, paused=True)  # halted well before the deadline
        frozen_before = _game_state(client, sid)["timer_remaining"]
        r = client.post("/api/game-timeout", headers={"X-Session-ID": sid})
        assert r.status_code == 200
        data = _game_state(client, sid)
        assert data["timer_expired"] is False
        assert data["timer_remaining"] == frozen_before
    finally:
        _cleanup(sid, s)


def _start_hardcore(client, sid, name="retry-tester"):
    r = client.post("/api/start-simulator",
                    headers={"X-Session-ID": sid},
                    json={"game_mode": "hardcore", "analyst_name": name})
    assert r.status_code == 200
    return r.get_json()


def _teardown_running(sid, s):
    """Pop the session first so the writer thread exits, then remove files."""
    app.sessions.pop(sid, None)
    time_mod.sleep(1.5)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def test_retry_full_cycle_lands_a_fresh_run():
    """The exact Retry sequence after a latched expiry: reset then start
    yields a full-timer, unexpired, unpaused run with a fresh queue and a
    bumped run generation."""
    client, sid, s = _api_session()
    try:
        _hardcore(s, DURATION + 5)
        assert _game_state(client, sid)["timer_expired"] is True
        assert s["paused"] is True  # the expiry auto-pause
        run_seq_before = s.get("run_seq", 0)

        r = client.post("/api/reset-simulator", headers={"X-Session-ID": sid})
        assert r.status_code == 200
        _start_hardcore(client, sid)

        data = _game_state(client, sid)
        assert data["timer_expired"] is False
        assert data["timer_remaining"] > DURATION - 10
        assert data["paused"] is False
        assert s["resolved_count"] == 0
        assert s["queue_length"] == len(s["alert_queue"]) > 0
        assert all(e.get("resolved_at") is None for e in s["alert_queue"])
        assert s.get("run_seq", 0) == run_seq_before + 1, \
            "start must bump the run generation (the writer-thread reset signal)"
    finally:
        _teardown_running(sid, s)


def _wait_for(predicate, deadline_seconds, step=0.2):
    waited = 0.0
    while waited < deadline_seconds:
        if predicate():
            return True
        time_mod.sleep(step)
        waited += step
    return False


def test_retry_never_inherits_ghost_events_from_the_dead_run():
    """Pause a run mid-chain (the expiry auto-pause shape), then reset and
    start again: the surviving writer thread must drop its queued leftover
    chain events, so nothing in the new run's pool carries the dead run's
    scenario id."""
    client, sid, s = _api_session()
    try:
        _start_hardcore(client, sid)
        old_sid_holder = {}

        def first_chain_event_written():
            if not s["alert_queue"]:
                return False
            entry = s["alert_queue"][0]
            scenario_id = entry.get("scenario_id")
            if scenario_id is None or entry.get("injected_at") is None:
                return False
            pool = app.read_ndjson(s, "generated_logs")
            if any(e.get("scenario_id") == scenario_id for e in pool):
                old_sid_holder["scenario_id"] = scenario_id
                return True
            return False

        assert _wait_for(first_chain_event_written, 30), \
            "the first chain event never appeared (drip stalled?)"
        # Halt mid-chain, exactly like the expiry auto-pause.
        s["paused"] = True
        time_mod.sleep(1.5)  # let the writer settle into the paused branch

        r = client.post("/api/reset-simulator", headers={"X-Session-ID": sid})
        assert r.status_code == 200
        _start_hardcore(client, sid)

        assert _wait_for(
            lambda: len(app.read_ndjson(s, "generated_logs")) >= 6, 30), \
            "the retried run never produced events (writer stalled?)"
        ghost_sid = old_sid_holder["scenario_id"]
        new_pool = app.read_ndjson(s, "generated_logs")
        ghosts = [e for e in new_pool if e.get("scenario_id") == ghost_sid]
        assert ghosts == [], \
            f"the retried run inherited {len(ghosts)} ghost event(s) from the dead run"
    finally:
        _teardown_running(sid, s)


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
