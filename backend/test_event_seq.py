"""Stage 4 Phase 1.2: the event_seq foundation suite (scaffold 2.3, review
correction 4).

Proves the pool append-and-stamp choke point: event_seq is unique, strictly
increasing, CONTIGUOUS (1..N, no gaps -- pool_growth = max_seq - cutoff_seq
depends on it), assigned exactly once, and a failed append never advances the
counter. Background occurrence times derive from epoch + spacing * seq.
Includes the quantified authored/background coherence bound (review
correction 3) computed from the live catalog's reference write model.

Run: python test_event_seq.py   (also: python -m pytest test_event_seq.py -q)
"""
import builtins
import json
import math
import os
import shutil
import sys
import tempfile
import threading
import time
from datetime import timedelta
from unittest import mock

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import detection_templates as dt  # noqa: E402
import sim_epoch  # noqa: E402

SID = "session-eventseq"


def _pool_session(tmpdir):
    return {
        "id": SID,
        "io_lock": threading.Lock(),
        "paths": {"generated_logs": os.path.join(tmpdir, "generated_logs.ndjson")},
        "world": {"hosts": {}, "started_at": sim_epoch.epoch_iso(SID)},
        "event_seq": 0,
    }


def _attack(i):
    return {"id": f"atk-{i}", "label": "malware_usb", "timestamp": "2026-03-16T09:00:00+00:00",
            "event_type": "ProcessCreate", "source_type": "Sysmon",
            "severity": "high", "hostname": "ACME-WS12", "message": "m",
            "key_value_pairs": {}}


def _normal(i):
    n = app.generate_normal_event()
    n["id"] = f"nrm-{i}"
    return n


# --- uniqueness, strict increase, contiguity ---------------------------------

def test_event_seq_unique_and_strictly_monotonic():
    tmp = tempfile.mkdtemp()
    try:
        s = _pool_session(tmp)
        for i in range(6):
            app.append_pool_event(s, _attack(i) if i % 3 == 0 else _normal(i))
        with s["io_lock"]:
            app._append_pool_event_unlocked(s, _normal(99))
        rows = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
        seqs = [r["event_seq"] for r in rows]
        assert len(seqs) == len(set(seqs)) == 7, "event_seq must be unique"
        assert seqs == sorted(seqs), "event_seq must strictly increase in write order"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_event_seq_contiguous_no_gaps():
    tmp = tempfile.mkdtemp()
    try:
        s = _pool_session(tmp)
        for i in range(10):
            app.append_pool_event(s, _normal(i))
        rows = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
        seqs = [r["event_seq"] for r in rows]
        assert seqs == list(range(1, 11)), \
            f"event_seq must be contiguous 1..N with no gaps, got {seqs}"
        assert s["event_seq"] == 10 == max(seqs), \
            "counter must equal max_seq (pool_growth arithmetic)"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_event_seq_assigned_exactly_once():
    tmp = tempfile.mkdtemp()
    try:
        s = _pool_session(tmp)
        app.append_pool_event(s, _attack(1))
        first = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
        # reads and re-serializations never re-stamp
        for _ in range(3):
            again = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
            assert again == first
            dt.sanitize_feed_event(again[0])
        final = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
        assert final[0]["event_seq"] == 1
        assert s["event_seq"] == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_failed_append_does_not_advance_counter():
    tmp = tempfile.mkdtemp()
    try:
        s = _pool_session(tmp)
        app.append_pool_event(s, _normal(1))
        real_open = builtins.open

        def failing_open(*a, **k):
            raise OSError("disk full")

        with mock.patch("builtins.open", side_effect=failing_open):
            try:
                app.append_pool_event(s, _normal(2))
                assert False, "append should have raised"
            except OSError:
                pass
        assert s["event_seq"] == 1, "failed append must not advance the counter"
        # recovery: the next successful append is contiguous
        app.append_pool_event(s, _normal(3))
        rows = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
        assert [r["event_seq"] for r in rows] == [1, 2]
        assert real_open is builtins.open
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- background occurrence times ---------------------------------------------

def test_background_occurrence_from_epoch_and_seq():
    tmp = tempfile.mkdtemp()
    try:
        s = _pool_session(tmp)
        app.append_pool_event(s, _attack(1))       # authored: timestamp kept
        app.append_pool_event(s, _normal(2))       # background: stamped
        app.append_pool_event(s, _normal(3))
        rows = app._read_ndjson_unlocked(s["paths"]["generated_logs"])
        assert rows[0]["timestamp"] == "2026-03-16T09:00:00+00:00", \
            "authored occurrence times must not be re-stamped"
        epoch = sim_epoch.epoch_dt(SID)
        for row, seq in ((rows[1], 2), (rows[2], 3)):
            expected = (epoch + timedelta(
                seconds=sim_epoch.BACKGROUND_SPACING_S * seq)).isoformat()
            assert row["timestamp"] == expected, \
                f"background occurrence must equal epoch + spacing*seq (seq {seq})"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- serialization -----------------------------------------------------------

def test_event_seq_serializes_on_feed_and_not_on_triggering_events():
    ev = _attack(1)
    ev["event_seq"] = 41
    out = dt.sanitize_feed_event(ev)
    assert out["event_seq"] == 41, "feed rows carry event_seq"
    # detection triggering events keep the EVENT_WHITELIST shape: no id, no
    # event_seq (D11 invariant; R17 rule-evidence framing)
    trig = dt.sanitize_event(ev)
    assert "event_seq" not in trig and "id" not in trig
    # absent event_seq (legacy hand-seeded fixtures) is simply omitted
    ev2 = _attack(2)
    assert "event_seq" not in dt.sanitize_feed_event(ev2)


# --- live drip: every pool row carries a contiguous seq ----------------------

def test_live_drip_pool_rows_carry_contiguous_event_seq():
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
        hdr = {"X-Session-ID": sid}
        events = []
        deadline = time.time() + 20
        while time.time() < deadline:
            events = client.get("/api/fake-events", headers=hdr).get_json()
            if len(events) >= 6:
                break
            time.sleep(0.3)
        assert len(events) >= 6, "no events dripped"
        assert all("event_seq" in e for e in events), \
            "every product-written pool row must serialize event_seq"
        seqs = sorted(e["event_seq"] for e in events)
        assert seqs == list(range(1, len(seqs) + 1)), \
            f"live pool seq must be contiguous 1..N, got {seqs}"
        # append-only under polling: a second read is byte-identical or longer,
        # never mutated (compare the common prefix by id+seq)
        again = client.get("/api/fake-events", headers=hdr).get_json()
        prefix = {e["id"]: e["event_seq"] for e in events}
        for e in again:
            if e["id"] in prefix:
                assert e["event_seq"] == prefix[e["id"]], \
                    "polling must never re-stamp event_seq"
    finally:
        app.sessions.pop(sid, None)
        s["paused"] = True
        time.sleep(1.2)
        shutil.rmtree(s.get("session_dir", ""), ignore_errors=True)


# --- quantified authored/background coherence bound (review correction 3) ----

def test_authored_background_gap_within_bound():
    """Reference write model over the LIVE catalog (scaffold Section 6): 10
    positions, drip every 30 ticks, one attack write per ~3.5 ticks while a
    chain drains, supplemental events appended at drip, authored [lo,hi]
    offsets at their hi values. The latest background occurrence must land
    within 300s of the latest authored occurrence. Background spacing is the
    first permitted tuning knob if this bound fails (2s already failed the
    model and was tuned to 3s at scaffold correction)."""
    def chain_hi_span(entry):
        span = 0
        for i, step in enumerate(entry["chain"]):
            off = step.get("offset", 0)
            if i == 0:
                continue
            span += off[1] if isinstance(off, list) else off
        return span

    catalog = app.yaml_catalog
    max_chain_len = max(len(e["chain"]) for e in catalog.values())
    max_hi_span = max(chain_hi_span(e) for e in catalog.values())
    sup_counts = sorted((len(e.get("supplemental_events", []))
                         for e in catalog.values()), reverse=True)
    sup_total_worst = sum(sup_counts[:10])

    drip_gap_ticks = 30                      # mid of the 20-40s product range
    drain_ticks = math.ceil(max_chain_len * 3.5)
    n_model = drip_gap_ticks * 9 + drain_ticks + sup_total_worst

    background_max_s = sim_epoch.BACKGROUND_SPACING_S * n_model
    authored_max_s = sim_epoch.POSITION_SPACING_S * 9 + max_hi_span

    gap = abs(authored_max_s - background_max_s)
    assert gap <= 300, (
        f"authored/background latest-occurrence gap {gap}s exceeds the 300s "
        f"bound (authored {authored_max_s}s vs background {background_max_s}s "
        f"over {n_model} modeled seq steps); background spacing is the first "
        f"permitted tuning knob")


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
        print(f"[test_event_seq] {failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"[test_event_seq] all {len(tests)} passed")
