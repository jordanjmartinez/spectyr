"""Tests for Stage 3b response-action scoring v1 (deterministic, server-side).

Run: python -m pytest test_action_scoring.py -q  (or python test_action_scoring.py)

The ruled grading model: successful actions only; isolation graded on
END-STATE at scoring time (released required containment = forfeited
credit, nothing stacked; clean-host isolation is collateral only while in
effect); kill/delete/identity graded on OCCURRENCE; release_host never
credits and never penalizes; order-sensitive checks only where the answer
key declares them, compared on first successful occurrence; identical
inputs (including reversal sequences) always yield identical scores; the
scoring endpoint leaks no target detail.
"""
import json
import os
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402
import scenario_loader as sl  # noqa: E402

WS = "ACME-WS12"
SVR = "ACME-SVR02"
STARTED = "2026-07-17T12:00:00+00:00"


def _exp(action, target, eid=None, after=None, scenario="scenario-x"):
    return {"scenario_id": scenario, "eid": eid, "action": action,
            "target": target, "after": list(after or [])}


def _run(action, target, seq):
    return {"seq": seq, "action": action, "target": target}


EXPECTED_FULL = [
    _exp("isolate_host", {"hostname": WS}, eid="a_iso"),
    _exp("kill_process", {"hostname": WS, "pid": 4756}),
    _exp("delete_file", {"hostname": WS, "path": "c:\\users\\public\\payload.exe"}),
    _exp("disable_account", {"domain": "ACME", "username": "nkhan"}),
]

EXECUTED_FULL = [
    _run("isolate_host", {"hostname": WS}, 1),
    _run("kill_process", {"hostname": WS, "pid": 4756, "name": "payload.exe"}, 2),
    _run("delete_file", {"hostname": WS, "path": "c:\\users\\public\\payload.exe",
                         "display": "C:\\Users\\Public\\payload.exe"}, 3),
    _run("disable_account", {"domain": "ACME", "username": "nkhan"}, 4),
]


def test_all_required_actions_credited():
    r = app.compute_action_score(EXPECTED_FULL, EXECUTED_FULL, {WS})
    assert r["required"] == 4 and r["correct"] == 4 and r["missed"] == 0
    assert r["collateral"] == 0 and r["order_violations"] == 0
    assert r["accuracy"] == 100.0 and r["grade"] == "A"


def test_missing_required_actions_are_missed():
    r = app.compute_action_score(EXPECTED_FULL, EXECUTED_FULL[:1], {WS})
    assert r["correct"] == 1 and r["missed"] == 3
    assert r["accuracy"] == 25.0 and r["grade"] == "F"


def test_isolation_grades_on_end_state_release_forfeits_without_stacking():
    """Required containment released before submission: the credit is
    forfeited (missed), and that forfeiture is the WHOLE cost: no
    collateral, no extra penalty for the reversal."""
    expected = [_exp("isolate_host", {"hostname": WS})]
    executed = [_run("isolate_host", {"hostname": WS}, 1),
                _run("release_host", {"hostname": WS}, 2)]
    r = app.compute_action_score(expected, executed, set())
    assert r["correct"] == 0 and r["missed"] == 1
    assert r["collateral"] == 0, "reversal must not stack a penalty"

    # re-isolated before submission: end-state credit restored
    executed_again = executed + [_run("isolate_host", {"hostname": WS}, 3)]
    r2 = app.compute_action_score(expected, executed_again, {WS})
    assert r2["correct"] == 1 and r2["missed"] == 0


def test_clean_host_isolation_is_collateral_only_while_in_effect():
    executed = [_run("isolate_host", {"hostname": SVR}, 1)]
    still = app.compute_action_score([], executed, {SVR})
    assert still["collateral"] == 1 and still["grade"] == "F"
    released = app.compute_action_score([], executed, set())
    assert released["collateral"] == 0 and released["grade"] == "-"


def test_collateral_on_irreversible_clean_targets():
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 900, "name": "benign.exe"}, 1),
        _run("delete_file", {"hostname": WS, "path": "c:\\good\\tool.exe"}, 2),
        _run("disable_account", {"domain": "ACME", "username": "innocent"}, 3),
    ]
    r = app.compute_action_score([], executed, set())
    assert r["collateral"] == 3 and r["required"] == 0
    assert r["graded"] == 3 and r["accuracy"] == 0.0


def test_same_pid_or_path_on_other_host_is_not_credit():
    """Composite matching: the right PID or path on the WRONG host is a
    collateral hit plus a miss, never a credit."""
    expected = [_exp("kill_process", {"hostname": WS, "pid": 4756})]
    executed = [_run("kill_process", {"hostname": SVR, "pid": 4756,
                                      "name": "same.exe"}, 1)]
    r = app.compute_action_score(expected, executed, set())
    assert r["correct"] == 0 and r["missed"] == 1 and r["collateral"] == 1


def test_release_host_never_credits_or_penalizes():
    executed = [_run("isolate_host", {"hostname": WS}, 1),
                _run("release_host", {"hostname": WS}, 2)]
    r = app.compute_action_score([], executed, set())
    assert r == app.compute_action_score([], [], set())


def test_order_sensitivity_only_where_declared():
    expected = [
        _exp("isolate_host", {"hostname": WS}, eid="a_iso"),
        _exp("force_password_reset", {"domain": "ACME", "username": "nkhan"},
             eid="a_reset", after=["a_iso"]),
    ]
    reset = _run("force_password_reset", {"domain": "ACME", "username": "nkhan"}, 1)
    iso = _run("isolate_host", {"hostname": WS}, 2)

    # declared order violated: reset before containment
    r = app.compute_action_score(expected, [reset, iso], {WS})
    assert r["correct"] == 1 and r["missed"] == 1 and r["order_violations"] == 1

    # declared order satisfied
    ok = app.compute_action_score(
        expected,
        [_run("isolate_host", {"hostname": WS}, 1),
         _run("force_password_reset", {"domain": "ACME", "username": "nkhan"}, 2)],
        {WS})
    assert ok["correct"] == 2 and ok["order_violations"] == 0

    # prerequisite never occurred: dependent action is order-violated
    r2 = app.compute_action_score(expected, [reset], set())
    assert r2["correct"] == 0 and r2["order_violations"] == 1


def test_order_uses_first_occurrence_not_end_state_credit():
    """Releasing containment later forfeits the isolation credit but does
    not retroactively invalidate an action correctly taken under it."""
    expected = [
        _exp("isolate_host", {"hostname": WS}, eid="a_iso"),
        _exp("force_password_reset", {"domain": "ACME", "username": "nkhan"},
             eid="a_reset", after=["a_iso"]),
    ]
    executed = [
        _run("isolate_host", {"hostname": WS}, 1),
        _run("force_password_reset", {"domain": "ACME", "username": "nkhan"}, 2),
        _run("release_host", {"hostname": WS}, 3),
    ]
    r = app.compute_action_score(expected, executed, set())
    assert r["missed"] == 1, "isolation credit is forfeited by the release"
    assert r["correct"] == 1 and r["order_violations"] == 0, \
        "the reset stays credited: it happened under containment"


def test_replay_determinism_including_reversal_sequences():
    expected = EXPECTED_FULL
    executed = EXECUTED_FULL + [
        _run("release_host", {"hostname": WS}, 5),
        _run("isolate_host", {"hostname": WS}, 6),
    ]
    a = app.compute_action_score(expected, executed, {WS})
    b = app.compute_action_score(expected, executed, {WS})
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_empty_session_grades_dash():
    r = app.compute_action_score([], [], set())
    assert r["grade"] == "-" and r["graded"] == 0 and r["accuracy"] == 0.0


def test_materialize_expected_actions_resolves_composites():
    """Drip-time resolution: environment ids to concrete hostnames and
    accounts, placeholders substituted like chain content, paths in the
    overlay's canonical form."""
    sc = app.yaml_catalog["malware_usb"]
    emp = {"name": "nkhan", "full_name": "Nadia Khan",
           "email": "nadia.khan@acme.com", "dept": "HR",
           "workstation": "ACME-WS12", "ip": "10.0.1.12"}

    class _Forced:
        def choice(self, seq):
            return emp
    resolved = sl.resolve_entities(sc, [emp], app.SERVERS, rng=_Forced())
    env = sl.substitute_deep(sc["environment"], resolved)
    host_id = env["hosts"][0]["id"]
    account_id = env["accounts"][0]["id"]

    entity = next(iter(sc["entities"]))
    actions = [
        {"id": "a_iso", "action": "isolate_host", "target": {"host": host_id}},
        {"action": "delete_file",
         "target": {"host": host_id,
                    "path": "C:\\Users\\{%s.username}\\payload.exe" % entity
                    if sc["entities"][entity]["type"] == "employee"
                    else "C:\\Users\\Public\\payload.exe"}},
        {"action": "disable_account", "target": {"account": account_id},
         "after": ["a_iso"]},
    ]
    out = app.materialize_expected_actions(actions, "scenario-t", env, resolved)
    assert out[0]["target"] == {"hostname": env["hosts"][0]["hostname"]}
    assert out[1]["target"]["hostname"] == env["hosts"][0]["hostname"]
    path = out[1]["target"]["path"]
    assert path == ao.norm_path(path) and "{" not in path, \
        "path must be substituted and canonical"
    acct = env["accounts"][0]
    assert out[2]["target"] == {"domain": acct["domain"],
                                "username": acct["username"]}
    assert out[2]["after"] == ["a_iso"] and out[2]["eid"] is None


def test_score_endpoint_counts_only_no_target_leak():
    """Leak guard: the scoring payload carries counts and a grade only;
    expected composites (a distinctive path, host, account) never appear,
    and neither does any answer-key field."""
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    s = app.sessions[sid]
    try:
        marker_path = "c:\\users\\public\\very_distinctive_payload_xyz.exe"
        with s["io_lock"]:
            s["expected_actions"] = [
                _exp("delete_file", {"hostname": "ACME-WS77", "path": marker_path}),
                _exp("isolate_host", {"hostname": "ACME-WS77"}),
            ]
        resp = client.get("/api/analytics/action_score",
                          headers={"X-Session-ID": sid})
        assert resp.status_code == 200
        body = resp.get_json()
        assert set(body) == {"required", "correct", "missed", "collateral",
                             "order_violations", "graded", "accuracy", "grade"}
        blob = json.dumps(body)
        for needle in ("very_distinctive_payload_xyz", "ACME-WS77",
                       "answer_key", "expected", "target"):
            assert needle not in blob, f"score payload leaked {needle!r}"
        assert body["required"] == 2 and body["missed"] == 2
    finally:
        app.sessions.pop(sid, None)
        shutil.rmtree(s["session_dir"], ignore_errors=True)


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
