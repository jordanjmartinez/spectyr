"""Pre-Stage-5 hotfix corpus gate: ONE shared incident roster, proven on the
REAL corpus.

Every 3.9 unit fixture hand-built its grading record with hostnames equal to
the observable event host, so the environment-vs-observed roster divergence was
structurally unreachable in tests while manifesting at runtime (INC-1310,
password_spray). This gate closes that class at the mechanism level: for every
catalog scenario it runs the REAL drip (build_guided_queue ->
build_attack_chain_logs -> append_pool_event -> finalize_chain -> seal) against
the real scenario environment in a fresh session, then asserts

    displayed roster (_incident_observable_scope)
 == readiness roster (_incident_detections / _incident_open_detections)
 == grading roster (the submitted record's detection_dispositions)

seed-independently, and reports the detection-score denominator delta versus
the retired environment-host ambient join (diagnosis Section 12 fixture 2).

Run: python test_incident_roster_corpus.py
"""
import os
import shutil
from datetime import datetime, timezone

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import sim_epoch  # noqa: E402
import action_overlay  # noqa: E402

OWILSON = next(e for e in app.EMPLOYEES if e["name"] == "owilson")


def _catalog_labels():
    out = []
    for lvl in app.CAMPAIGN_LEVELS:
        for _cat, sc in lvl["scenarios"].items():
            out.append(sc["scenario_label"])
    return sorted(out)


def _drip_one(label):
    """Real drip of one scenario in a fresh session (the writer thread's exact
    order, no threads), forced employee owilson for a deterministic victim."""
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
        s["overlay"] = action_overlay.new_overlay()
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


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def test_corpus_every_scenario_has_one_roster():
    """Real-drip all 20 scenarios: displayed == readiness == grading roster."""
    deltas = []
    for label in _catalog_labels():
        client, sid, s, entry = _drip_one(label)
        try:
            inc, scen = entry["incident_id"], entry["scenario_id"]
            with s["io_lock"]:
                obs = app._incident_observable_scope(s, inc)
                readiness = {d["id"] for d in app._incident_detections(s, scen)}
                open_ids = {d["id"]
                            for d in app._incident_open_detections(s, scen)}
                # the RETIRED environment-host join, recomputed only to report
                # the detection-score denominator delta
                grec = app._grading_record_for(s, scen)
                old_join = {d["id"] for d in s["detections"]
                            if d.get("scenario_id") == scen
                            or (d.get("scenario_id") is None
                                and (d.get("entity") or {}).get("host")
                                in grec["hostnames"])}
            displayed = set(obs["roster_ids"])
            assert displayed == readiness, (
                f"{label}: displayed roster {sorted(displayed)} != readiness "
                f"roster {sorted(readiness)}")
            assert open_ids <= displayed, (
                f"{label}: readiness demands a detection outside the display")

            # grading roster: disposition everything session-wide (valid under
            # either join), submit, and read the immutable record
            with s["io_lock"]:
                for d in s["detections"]:
                    d["player_action"] = "dismissed"
            r = client.post(f"/api/incidents/{inc}/submit",
                            headers={"X-Session-ID": sid},
                            json={"verdict": "false_positive"})
            assert r.status_code == 200, (
                f"{label}: submit failed {r.status_code} {r.get_json()}")
            rec = s["submissions"][inc]
            graded = set(rec["inputs"]["detection_dispositions"])
            assert graded == displayed, (
                f"{label}: grading roster {sorted(graded)} != displayed "
                f"roster {sorted(displayed)}")
            assert rec["report_card"]["detection"]["graded"] == len(displayed)
            deltas.append((label, len(old_join), len(displayed)))
        finally:
            _cleanup(sid, s)

    changed = [(l, o, n) for l, o, n in deltas if o != n]
    print("\n  detection-score denominators (this run's session seeds):")
    for l, o, n in deltas:
        mark = "  CHANGED" if o != n else ""
        print(f"    {l:38s} env-join {o:2d} -> observable {n:2d}{mark}")
    print(f"  {len(changed)}/{len(deltas)} scenarios change denominator "
          f"this seed: {[l for l, _, _ in changed]}")


def _run_all():
    test_corpus_every_scenario_has_one_roster()
    print("\n1/1 incident-roster corpus tests passed")


if __name__ == "__main__":
    _run_all()
