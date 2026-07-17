"""Tests for the Stage 3a action engine and API.

Run: python -m pytest test_actions.py -q  (or python test_actions.py)

Covers the complete state-transition matrix (every cell), action log
determinism (frozen clock + sequence, byte-identical replays), concurrency
under the session lock, the immutable-evidence guarantee at the API level,
and the leak guard on every action payload (answer keys, dispositions, and
raw composite targets never serialize; invalid targets are rejected
without being logged).
"""
import copy
import json
import os
import random
import shutil
import threading

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import scenario_loader as sl  # noqa: E402
import snapshot_generator as sg  # noqa: E402
import action_overlay as ao  # noqa: E402

CATALOG = app.yaml_catalog
SEED = "test-session-actions"
STARTED = "2026-07-17T12:00:00+00:00"

EMPLOYEE = {"name": "nkhan", "full_name": "Nadia Khan",
            "email": "nadia.khan@acme.com", "dept": "HR",
            "workstation": "ACME-WS12", "ip": "10.0.1.12"}

# Fields that must never appear anywhere in an action payload.
FORBIDDEN = ("disposition", "scenario_id", "detection_key", "answer_key",
             "category", "flagged", "level", "storyline", "alert_id")


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__()
        self._forced = forced

    def choice(self, seq):
        return self._forced


def _render(label):
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, [EMPLOYEE], app.SERVERS, rng=_Forced(EMPLOYEE))
    env = sl.substitute_deep(sc["environment"], resolved)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        log["scenario_id"] = f"scenario-{label}"
        log["timestamp"] = f"2026-07-17T12:01:{i:02d}+00:00"
        logs.append(log)
    return sc, env, logs


def _build_state(label="malware_usb", seed=SEED, extra_hosts=()):
    """(world, registry, env_accounts) mirroring the drip path, plus
    hand-declared extra hosts (e.g. an offline one)."""
    sc, env, logs = _render(label)
    world = {"hosts": {}, "started_at": STARTED}
    sg.extend_world(world, sc, env, logs, seed, app.RESERVED_PIDS, app.SERVERS)
    env_accounts = {}
    ao.collect_env_accounts(env_accounts, env)
    for host in extra_hosts:
        owner = None
        world["hosts"][host["hostname"]] = sg.build_baseline(
            host, owner, seed, app.RESERVED_PIDS, app.SERVERS, STARTED)
    registry = ao.build_entity_registry(world, env_accounts, seed)
    return world, registry, env_accounts


def _eid(registry, kind, **match):
    for eid, e in registry.items():
        if e["kind"] == kind and all(e.get(k) == v for k, v in match.items()):
            return eid, e
    raise AssertionError(f"no {kind} entity matching {match}")


def _attempt(world, overlay, registry, action, eid):
    entry = registry[eid]
    outcome, reason = ao.execute(world, overlay, entry, action)
    ao.record_attempt(overlay, world["started_at"], action, eid, entry,
                      outcome, reason)
    return outcome, reason


OFFLINE_HOST = {"id": "h_off", "role": "server", "hostname": "ACME-OFF01",
                "ip": "10.0.1.240", "os": "Windows Server 2022",
                "status": "offline"}


# --- state-transition matrix ----------------------------------------------------

def test_isolate_matrix():
    world, reg, _ = _build_state(extra_hosts=(OFFLINE_HOST,))
    overlay = ao.new_overlay()
    online_id, online = _eid(reg, "host", hostname="ACME-WS12")
    offline_id, _ = _eid(reg, "host", hostname="ACME-OFF01")

    assert _attempt(world, overlay, reg, "isolate_host", online_id)[0] == ao.SUCCESS
    out, reason = _attempt(world, overlay, reg, "isolate_host", online_id)
    assert out == ao.NO_OP and "already isolated" in reason
    out, reason = _attempt(world, overlay, reg, "isolate_host", offline_id)
    assert out == ao.FAILED and "offline" in reason
    assert "ACME-OFF01" not in overlay["isolated"]


def test_release_matrix():
    world, reg, _ = _build_state()
    overlay = ao.new_overlay()
    host_id, _ = _eid(reg, "host", hostname="ACME-WS12")

    out, reason = _attempt(world, overlay, reg, "release_host", host_id)
    assert out == ao.FAILED and "not isolated" in reason
    assert _attempt(world, overlay, reg, "isolate_host", host_id)[0] == ao.SUCCESS
    assert _attempt(world, overlay, reg, "release_host", host_id)[0] == ao.SUCCESS
    # both isolate and release stay in the log even though they cancel out
    actions = [e["action"] for e in overlay["log"]]
    assert actions == ["release_host", "isolate_host", "release_host"]


def test_kill_matrix():
    world, reg, _ = _build_state()
    overlay = ao.new_overlay()
    snap = world["hosts"]["ACME-WS12"]
    pid = snap["processes"][10]["pid"]
    proc_id, entry = _eid(reg, "process", hostname="ACME-WS12", pid=pid)

    assert _attempt(world, overlay, reg, "kill_process", proc_id)[0] == ao.SUCCESS
    out, reason = _attempt(world, overlay, reg, "kill_process", proc_id)
    assert out == ao.NO_OP and "already terminated" in reason

    # missing (host, pid): a registry entry whose composite is not in the
    # world. No client path mints one today; the cell is defined and tested.
    ghost = {"kind": "process", "hostname": "ACME-WS12", "pid": 99996,
             "name": "ghost.exe"}
    out, reason = ao.execute(world, overlay, ghost, "kill_process")
    assert out == ao.FAILED and "No running process" in reason


def test_delete_matrix():
    world, reg, _ = _build_state()
    overlay = ao.new_overlay()
    snap = world["hosts"]["ACME-WS12"]
    path = ao.norm_path(ao.extract_image_path(snap["autoruns"][0]["command"]))
    file_id, _ = _eid(reg, "file", hostname="ACME-WS12", path=path)

    assert _attempt(world, overlay, reg, "delete_file", file_id)[0] == ao.SUCCESS
    out, reason = _attempt(world, overlay, reg, "delete_file", file_id)
    assert out == ao.NO_OP and "already deleted" in reason

    ghost = {"kind": "file", "hostname": "ACME-WS12",
             "path": "c:\\nosuch\\file.exe", "display": "C:\\nosuch\\file.exe"}
    out, reason = ao.execute(world, overlay, ghost, "delete_file")
    assert out == ao.FAILED and "not found" in reason


def test_identity_matrix():
    world, reg, _ = _build_state()
    overlay = ao.new_overlay()
    acct_id, entry = _eid(reg, "account", username="nkhan")

    for action in ("disable_account", "revoke_sessions", "force_password_reset"):
        assert _attempt(world, overlay, reg, action, acct_id)[0] == ao.SUCCESS
        out, reason = _attempt(world, overlay, reg, action, acct_id)
        assert out == ao.NO_OP and "already" in reason
    state = overlay["accounts"][ao.account_key(entry["domain"], entry["username"])]
    assert state == {"disabled": True, "sessions_revoked": True,
                     "password_reset": True}


# --- action log ----------------------------------------------------------------

def test_log_records_every_attempt_with_frozen_clock_sequence():
    world, reg, _ = _build_state(extra_hosts=(OFFLINE_HOST,))
    overlay = ao.new_overlay()
    online_id, _ = _eid(reg, "host", hostname="ACME-WS12")
    offline_id, _ = _eid(reg, "host", hostname="ACME-OFF01")

    _attempt(world, overlay, reg, "isolate_host", online_id)   # success
    _attempt(world, overlay, reg, "isolate_host", online_id)   # no_op
    _attempt(world, overlay, reg, "isolate_host", offline_id)  # failed

    assert [e["seq"] for e in overlay["log"]] == [1, 2, 3]
    assert [e["outcome"] for e in overlay["log"]] == [ao.SUCCESS, ao.NO_OP, ao.FAILED]
    assert [e["timestamp"] for e in overlay["log"]] == [
        "2026-07-17T12:00:01+00:00",
        "2026-07-17T12:00:02+00:00",
        "2026-07-17T12:00:03+00:00",
    ]
    assert overlay["log"][0]["reason"] is None
    assert overlay["log"][2]["reason"].startswith("Host is offline.")


def test_replay_determinism_byte_identical_logs():
    def run():
        world, reg, _ = _build_state(extra_hosts=(OFFLINE_HOST,))
        overlay = ao.new_overlay()
        snap = world["hosts"]["ACME-WS12"]
        seq = [
            ("isolate_host", _eid(reg, "host", hostname="ACME-WS12")[0]),
            ("kill_process", _eid(reg, "process", hostname="ACME-WS12",
                                  pid=snap["processes"][12]["pid"])[0]),
            ("isolate_host", _eid(reg, "host", hostname="ACME-OFF01")[0]),
            ("release_host", _eid(reg, "host", hostname="ACME-WS12")[0]),
            ("disable_account", _eid(reg, "account", username="nkhan")[0]),
        ]
        for action, eid in seq:
            _attempt(world, overlay, reg, action, eid)
        return json.dumps(overlay["log"], sort_keys=True)

    assert run() == run(), "identical action sequences must yield byte-identical logs"


# --- API level -----------------------------------------------------------------

def _api_session():
    """A live session through the Flask test client, world populated the way
    the drip populates it. Returns (client, sid, session)."""
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    s = app.sessions[sid]
    sc, env, logs = _render("malware_usb")
    with s["io_lock"]:
        s["world"]["started_at"] = STARTED
        sg.extend_world(s["world"], sc, env, logs, s["id"],
                        app.RESERVED_PIDS, app.SERVERS)
        ao.collect_env_accounts(s["env_accounts"], env)
        s["entity_index"] = ao.build_entity_registry(
            s["world"], s["env_accounts"], s["id"])
    return client, sid, s


def _cleanup(sid):
    s = app.sessions.pop(sid, None)
    if s:
        shutil.rmtree(s["session_dir"], ignore_errors=True)


def _post(client, sid, body):
    return client.post("/api/actions", json=body, headers={"X-Session-ID": sid})


def _assert_clean(payload):
    blob = json.dumps(payload)
    for bad in FORBIDDEN:
        assert f'"{bad}"' not in blob, f"forbidden field {bad!r} leaked"


def test_api_execute_and_response_log():
    client, sid, s = _api_session()
    try:
        host_id, _ = _eid(s["entity_index"], "host", hostname="ACME-WS12")
        r = _post(client, sid, {"action": "isolate_host", "target": host_id})
        assert r.status_code == 200
        body = r.get_json()
        assert body["outcome"] == "success" and body["seq"] == 1
        assert set(body) == {"seq", "timestamp", "action", "outcome", "reason", "target"}
        assert set(body["target"]) == {"id", "kind", "label"}
        _assert_clean(body)

        r = client.get("/api/actions", headers={"X-Session-ID": sid})
        log = r.get_json()
        assert log["count"] == 1 and log["actions"][0]["action"] == "isolate_host"
        _assert_clean(log)

        # the endpoint list now shows the host isolated
        r = client.get("/api/endpoints", headers={"X-Session-ID": sid})
        row = next(x for x in r.get_json()["endpoints"]
                   if x["hostname"] == "ACME-WS12")
        assert row["isolation"] == "isolated"
    finally:
        _cleanup(sid)


def test_api_rejects_invalid_targets_unlogged():
    client, sid, s = _api_session()
    try:
        host_id, _ = _eid(s["entity_index"], "host", hostname="ACME-WS12")
        cases = [
            {"action": "self_destruct", "target": host_id},   # unknown action
            {"action": "kill_process", "target": host_id},    # kind mismatch
            {"action": "isolate_host", "target": "ent-000000000000"},  # stale
            {"action": "isolate_host"},                       # missing target
            {"action": "isolate_host", "target": None},
        ]
        for body in cases:
            r = _post(client, sid, body)
            assert r.status_code == 400, body
            _assert_clean(r.get_json())
        r = client.get("/api/actions", headers={"X-Session-ID": sid})
        assert r.get_json()["count"] == 0, "a rejected attempt reached the log"
    finally:
        _cleanup(sid)


def test_api_foreign_session_ids_indistinguishable_from_unknown():
    """Logging boundary: a valid entity id from ANOTHER session is rejected
    exactly like a garbage id (same status, same body: no cross-session
    existence leak) and neither session's action log records the attempt."""
    client_a, sid_a, s_a = _api_session()
    client_b, sid_b, s_b = _api_session()
    try:
        foreign_id, _ = _eid(s_a["entity_index"], "host", hostname="ACME-WS12")
        assert foreign_id not in s_b["entity_index"], \
            "fixture invalid: entity id collided across sessions"

        r_foreign = client_b.post("/api/actions",
                                  json={"action": "isolate_host", "target": foreign_id},
                                  headers={"X-Session-ID": sid_b})
        r_garbage = client_b.post("/api/actions",
                                  json={"action": "isolate_host",
                                        "target": "ent-000000000000"},
                                  headers={"X-Session-ID": sid_b})
        assert r_foreign.status_code == r_garbage.status_code == 400
        assert r_foreign.get_json() == r_garbage.get_json(), \
            "foreign-session rejection distinguishable from unknown-id rejection"
        for sid, client in ((sid_a, client_a), (sid_b, client_b)):
            log = client.get("/api/actions", headers={"X-Session-ID": sid}).get_json()
            assert log["count"] == 0, "a rejected attempt reached an action log"
    finally:
        _cleanup(sid_a)
        _cleanup(sid_b)


def test_api_immutable_evidence_after_kill():
    """Killing a process removes it from the live endpoint view; the event
    record (and the base world) keep it."""
    client, sid, s = _api_session()
    try:
        snap = s["world"]["hosts"]["ACME-WS12"]
        pid = next(c["pid"] for c in snap["network"]["connections"] if c["pid"])
        # plant a pool event referencing the pid, as the chain writer would
        evidence = {"id": "ev-1", "timestamp": STARTED, "event_type": "1",
                    "severity": "high", "hostname": "ACME-WS12",
                    "message": f"process {pid} created",
                    "key_value_pairs": {"process_id": str(pid)}}
        with open(s["paths"]["generated_logs"], "a", encoding="utf-8") as f:
            f.write(json.dumps(evidence) + "\n")

        proc_id, _ = _eid(s["entity_index"], "process",
                          hostname="ACME-WS12", pid=pid)
        r = _post(client, sid, {"action": "kill_process", "target": proc_id})
        assert r.get_json()["outcome"] == "success"

        detail = client.get("/api/endpoints/ACME-WS12",
                            headers={"X-Session-ID": sid}).get_json()
        assert all(p["pid"] != pid for p in detail["processes"])
        assert all(c["pid"] != pid for c in detail["network"]["connections"])

        events = client.get("/api/fake-events",
                            headers={"X-Session-ID": sid}).get_json()
        assert any(e["id"] == "ev-1" for e in events), "historical record changed"
        assert any(p["pid"] == pid for p in snap["processes"]), "base world changed"
    finally:
        _cleanup(sid)


def test_api_concurrent_isolate_single_success():
    client, sid, s = _api_session()
    try:
        host_id, _ = _eid(s["entity_index"], "host", hostname="ACME-WS12")
        results = []
        lock = threading.Lock()

        def worker():
            c = app.app.test_client()
            r = c.post("/api/actions",
                       json={"action": "isolate_host", "target": host_id},
                       headers={"X-Session-ID": sid})
            with lock:
                results.append(r.get_json()["outcome"])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count("success") == 1, results
        assert results.count("no_op") == 7, results
        log = client.get("/api/actions", headers={"X-Session-ID": sid}).get_json()
        assert [e["seq"] for e in log["actions"]] == list(range(1, 9))
    finally:
        _cleanup(sid)


def test_api_detection_entity_carries_account_ref_and_state():
    """Account-bearing detection entities expose the account entity id and
    the CURRENT identity state; the answer key never rides along."""
    client, sid, s = _api_session()
    try:
        with s["io_lock"]:
            s["detections"].append({
                "id": "det-aaaaaaaaaaaa", "scenario_id": "scenario-x",
                "detection_key": "det_test", "rule_name": "Test Rule",
                "rule_type": "sigma_behavioral", "severity": "high",
                "mitre": None, "yara_rule_name": None, "description": "d",
                "entity": {"host": None, "account": "nkhan@acme.local"},
                "time": STARTED, "triggering_events": [],
                "sha256": None, "disposition": "true_positive",
                "player_action": "promoted",
            })
            s["detection_index"] = {d["id"]: d for d in s["detections"]}

        threats = client.get("/api/threats",
                             headers={"X-Session-ID": sid}).get_json()
        _assert_clean(threats)
        ent = threats["threats"][0]["entity"]
        assert ent["account_id"] is not None
        assert ent["account_state"] == {"disabled": False,
                                        "sessions_revoked": False,
                                        "password_reset": False}

        r = _post(client, sid, {"action": "disable_account",
                                "target": ent["account_id"]})
        assert r.get_json()["outcome"] == "success"
        threats = client.get("/api/threats",
                             headers={"X-Session-ID": sid}).get_json()
        assert threats["threats"][0]["entity"]["account_state"]["disabled"] is True
    finally:
        _cleanup(sid)


def test_no_wall_clock_in_log_entries():
    """Every logged timestamp derives from the frozen session clock, so a
    log written now and a log written later from the same sequence match."""
    world, reg, _ = _build_state()
    overlay = ao.new_overlay()
    host_id, _ = _eid(reg, "host", hostname="ACME-WS12")
    _attempt(world, overlay, reg, "isolate_host", host_id)
    entry = overlay["log"][0]
    assert entry["timestamp"].startswith("2026-07-17T12:00"), \
        "timestamp did not derive from the frozen session clock"


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
