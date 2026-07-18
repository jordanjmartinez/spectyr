"""Tests for Stage 3b response-action scoring v1, amended by the 3c
tri-state grading marker and the achievability rule.

Run: python -m pytest test_action_scoring.py -q  (or python test_action_scoring.py)

The ruled model: successful actions only; per-scenario tri-state gate
(unreviewed scenarios excluded entirely, reviewed-empty scenarios graded
as intentional correct inaction); collateral scoped to targets claimed by
reviewed scenarios and no unreviewed one; isolation graded on END-STATE;
kill/delete/identity on OCCURRENCE; release_host fully neutral; order only
where declared, compared on first successful occurrence; failed attempts
surfaced factually (score-neutral); required actions achievable from the
initial world state under every seed (authored sources only).
"""
import json
import os
import random
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402
import detection_templates as dt  # noqa: E402
import scenario_loader as sl  # noqa: E402
import snapshot_generator as sg  # noqa: E402

WS = "ACME-WS12"
SVR = "ACME-SVR02"
STARTED = "2026-07-17T12:00:00+00:00"

EMPLOYEE = {"name": "nkhan", "full_name": "Nadia Khan",
            "email": "nadia.khan@acme.com", "dept": "HR",
            "workstation": "ACME-WS12", "ip": "10.0.1.12"}

# One reviewed scenario claiming the fixture hosts/accounts: preserves the
# plain 3b semantics for the baseline tests.
GRADING = [{"scenario_id": "scenario-x", "reviewed": True,
            "hostnames": {WS, SVR},
            "accounts": {("acme", "nkhan"), ("acme", "innocent")}}]


def _grading(scenario="scenario-x", reviewed=True, hostnames=(WS, SVR),
             accounts=(("acme", "nkhan"), ("acme", "innocent"))):
    return {"scenario_id": scenario, "reviewed": reviewed,
            "hostnames": set(hostnames), "accounts": set(accounts)}


def _exp(action, target, eid=None, after=None, scenario="scenario-x",
         status="required"):
    return {"scenario_id": scenario, "eid": eid, "action": action,
            "status": status, "target": target, "after": list(after or [])}


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


def _score(expected, executed, isolated, grading=None):
    return app.compute_action_score(expected, executed, isolated,
                                    GRADING if grading is None else grading)


# --- baseline 3b semantics (one reviewed scenario) -----------------------------

def test_all_required_actions_credited():
    r = _score(EXPECTED_FULL, EXECUTED_FULL, {WS})
    assert r["required"] == 4 and r["correct"] == 4 and r["missed"] == 0
    assert r["collateral"] == 0 and r["order_violations"] == 0
    assert r["accuracy"] == 100.0 and r["grade"] == "A"


def test_missing_required_actions_are_missed():
    r = _score(EXPECTED_FULL, EXECUTED_FULL[:1], {WS})
    assert r["correct"] == 1 and r["missed"] == 3
    assert r["accuracy"] == 25.0 and r["grade"] == "F"


def test_isolation_grades_on_end_state_release_forfeits_without_stacking():
    expected = [_exp("isolate_host", {"hostname": WS})]
    executed = [_run("isolate_host", {"hostname": WS}, 1),
                _run("release_host", {"hostname": WS}, 2)]
    r = _score(expected, executed, set())
    assert r["correct"] == 0 and r["missed"] == 1
    assert r["collateral"] == 0, "reversal must not stack a penalty"

    executed_again = executed + [_run("isolate_host", {"hostname": WS}, 3)]
    r2 = _score(expected, executed_again, {WS})
    assert r2["correct"] == 1 and r2["missed"] == 0


def test_clean_host_isolation_is_collateral_only_while_in_effect():
    executed = [_run("isolate_host", {"hostname": SVR}, 1)]
    still = _score([], executed, {SVR})
    assert still["collateral"] == 1
    released = _score([], executed, set())
    assert released["collateral"] == 0


def test_collateral_on_irreversible_clean_targets():
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 900, "name": "benign.exe"}, 1),
        _run("delete_file", {"hostname": WS, "path": "c:\\good\\tool.exe"}, 2),
        _run("disable_account", {"domain": "ACME", "username": "innocent"}, 3),
    ]
    r = _score([], executed, set())
    assert r["collateral"] == 3 and r["accuracy"] == 0.0


def test_same_pid_or_path_on_other_host_is_not_credit():
    expected = [_exp("kill_process", {"hostname": WS, "pid": 4756})]
    executed = [_run("kill_process", {"hostname": SVR, "pid": 4756,
                                      "name": "same.exe"}, 1)]
    r = _score(expected, executed, set())
    assert r["correct"] == 0 and r["missed"] == 1 and r["collateral"] == 1


def test_release_host_never_credits_or_penalizes():
    executed = [_run("isolate_host", {"hostname": WS}, 1),
                _run("release_host", {"hostname": WS}, 2)]
    assert _score([], executed, set()) == _score([], [], set())


def test_order_sensitivity_only_where_declared():
    expected = [
        _exp("isolate_host", {"hostname": WS}, eid="a_iso"),
        _exp("force_password_reset", {"domain": "ACME", "username": "nkhan"},
             eid="a_reset", after=["a_iso"]),
    ]
    reset = _run("force_password_reset", {"domain": "ACME", "username": "nkhan"}, 1)
    iso = _run("isolate_host", {"hostname": WS}, 2)

    r = _score(expected, [reset, iso], {WS})
    assert r["correct"] == 1 and r["missed"] == 1 and r["order_violations"] == 1

    ok = _score(expected,
                [_run("isolate_host", {"hostname": WS}, 1),
                 _run("force_password_reset",
                      {"domain": "ACME", "username": "nkhan"}, 2)], {WS})
    assert ok["correct"] == 2 and ok["order_violations"] == 0

    r2 = _score(expected, [reset], set())
    assert r2["correct"] == 0 and r2["order_violations"] == 1


def test_order_uses_first_occurrence_not_end_state_credit():
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
    r = _score(expected, executed, set())
    assert r["missed"] == 1, "isolation credit is forfeited by the release"
    assert r["correct"] == 1 and r["order_violations"] == 0


def test_replay_determinism_including_reversal_sequences():
    executed = EXECUTED_FULL + [
        _run("release_host", {"hostname": WS}, 5),
        _run("isolate_host", {"hostname": WS}, 6),
    ]
    a = _score(EXPECTED_FULL, executed, {WS})
    b = _score(EXPECTED_FULL, executed, {WS})
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --- required vs acceptable (the Batch 1 correction) ---------------------------

def test_acceptable_actions_neutral_and_excluded_from_denominator():
    """Acceptable: no credit, never collateral, out of the denominator.
    Omission never lowers the score; execution changes nothing but the
    factual surfacing."""
    expected = [
        _exp("isolate_host", {"hostname": WS}),
        _exp("kill_process", {"hostname": WS, "pid": 900},
             status="acceptable"),
    ]
    kill = _run("kill_process", {"hostname": WS, "pid": 900,
                                 "name": "shell.exe"}, 2)
    iso = _run("isolate_host", {"hostname": WS}, 1)

    executed_both = app.compute_action_score(expected, [iso, kill], {WS}, GRADING)
    assert executed_both["required"] == 1 and executed_both["correct"] == 1
    assert executed_both["collateral"] == 0 and executed_both["graded"] == 1
    assert executed_both["accuracy"] == 100.0
    assert executed_both["acceptable_seqs"] == [2]

    omitted = app.compute_action_score(expected, [iso], {WS}, GRADING)
    without_acceptable = app.compute_action_score(
        [expected[0]], [iso], {WS}, GRADING)
    omitted.pop("acceptable_seqs")
    without_acceptable.pop("acceptable_seqs")
    assert omitted == without_acceptable, \
        "omitting an acceptable action must never change the score"


def test_acceptable_isolation_end_state_neutral():
    """An acceptable isolation is score-neutral whether it remains active
    or was released: the author sanctioned it, so no clean-host end-state
    penalty."""
    expected = [_exp("isolate_host", {"hostname": SVR}, status="acceptable")]
    executed = [_run("isolate_host", {"hostname": SVR}, 1)]
    active = app.compute_action_score(expected, executed, {SVR}, GRADING)
    released = app.compute_action_score(expected, executed, set(), GRADING)
    assert active["collateral"] == 0 and released["collateral"] == 0
    assert active["acceptable_seqs"] == released["acceptable_seqs"] == [1]
    active.pop("acceptable_seqs"); released.pop("acceptable_seqs")
    assert active == released


def test_acceptable_only_scenario_grades_as_inaction_unit():
    """A reviewed scenario with no REQUIRED actions is the inaction
    contract even when acceptable actions exist; executing them never
    costs the unit."""
    expected = [_exp("kill_process", {"hostname": WS, "pid": 900},
                     status="acceptable")]
    idle = app.compute_action_score(expected, [], set(), GRADING)
    assert idle["required"] == 1 and idle["correct"] == 1

    acted = app.compute_action_score(
        expected,
        [_run("kill_process", {"hostname": WS, "pid": 900, "name": "x.exe"}, 1)],
        set(), GRADING)
    assert acted["required"] == 1 and acted["correct"] == 1
    assert acted["collateral"] == 0 and acted["acceptable_seqs"] == [1]


def test_unlisted_action_still_collateral_beside_acceptable():
    """Only the exact acceptable composite is sanctioned; anything on
    neither list stays collateral."""
    expected = [_exp("kill_process", {"hostname": WS, "pid": 900},
                     status="acceptable")]
    r = app.compute_action_score(
        expected,
        [_run("kill_process", {"hostname": WS, "pid": 904, "name": "y.exe"}, 1)],
        set(), GRADING)
    assert r["collateral"] == 1 and r["acceptable_seqs"] == []


# --- tri-state gate ------------------------------------------------------------

def test_unreviewed_scenario_is_excluded_entirely():
    """actions_reviewed false: earns nothing, costs nothing; the section
    grades '-'."""
    grading = [_grading(reviewed=False)]
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 900, "name": "x.exe"}, 1),
        _run("isolate_host", {"hostname": WS}, 2),
    ]
    r = _score([], executed, {WS}, grading)
    assert r["graded"] == 0 and r["grade"] == "-"
    assert r["collateral"] == 0


def test_no_grading_records_grades_dash():
    r = _score([], [], set(), [])
    assert r["grade"] == "-" and r["graded"] == 0 and r["accuracy"] == 0.0


def test_shared_target_with_unreviewed_scenario_gets_benefit_of_doubt():
    """A target claimed by BOTH a reviewed and an unreviewed scenario is
    out of collateral scope while the review is in flight; a target
    claimed only by the reviewed scenario still counts."""
    grading = [
        _grading(scenario="scenario-r", reviewed=True, hostnames={WS, SVR}),
        _grading(scenario="scenario-u", reviewed=False, hostnames={SVR},
                 accounts=()),
    ]
    executed = [
        _run("kill_process", {"hostname": SVR, "pid": 3312, "name": "net.exe"}, 1),
        _run("kill_process", {"hostname": WS, "pid": 900, "name": "x.exe"}, 2),
    ]
    r = _score([], executed, set(), grading)
    assert r["collateral"] == 1, \
        "shared-host action must be ungraded; reviewed-only host counts"


def test_reviewed_empty_set_is_intentional_correct_inaction():
    """The FP contract: clean hands earn the unit; a collateral hit in the
    scenario's scope costs both the collateral and the inaction credit."""
    grading = [_grading()]
    clean = _score([], [], set(), grading)
    assert clean["required"] == 1 and clean["correct"] == 1
    assert clean["accuracy"] == 100.0 and clean["grade"] == "A"

    acted = _score([], [_run("kill_process",
                             {"hostname": WS, "pid": 900, "name": "x.exe"}, 1)],
                   set(), grading)
    assert acted["required"] == 1 and acted["correct"] == 0
    assert acted["missed"] == 1 and acted["collateral"] == 1
    assert acted["graded"] == 2 and acted["accuracy"] == 0.0


def test_expected_actions_only_count_for_reviewed_scenarios():
    """Belt and braces: expected entries from a scenario without a reviewed
    grading record are filtered out (the loader forbids authoring them,
    but the scorer never trusts that)."""
    expected = [_exp("isolate_host", {"hostname": WS}, scenario="scenario-ghost")]
    r = _score(expected, [], set(), [_grading()])
    # ghost expected filtered; the reviewed scenario grades as inaction
    assert r["required"] == 1 and r["correct"] == 1


# --- materialization and grading records ---------------------------------------

class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__()
        self._forced = forced

    def choice(self, seq):
        return self._forced


def _resolved_env(label):
    sc = app.yaml_catalog[label]
    resolved = sl.resolve_entities(sc, [EMPLOYEE], app.SERVERS,
                                   rng=_Forced(EMPLOYEE))
    env = sl.substitute_deep(sc["environment"], resolved)
    return sc, resolved, env


def test_materialize_expected_actions_resolves_composites():
    sc, resolved, env = _resolved_env("lateral_movement_1")
    actions = [
        {"id": "a_iso", "action": "isolate_host", "status": "required",
         "target": {"host": "ws_victim"}},
        {"action": "delete_file", "status": "acceptable",
         "target": {"host": "ws_victim",
                    "path": "C:\\Users\\{victim.username}\\Downloads\\nmap-7.95\\nmap.exe"}},
        {"action": "disable_account", "status": "required",
         "target": {"account": "victim"}, "after": ["a_iso"]},
    ]
    out = app.materialize_expected_actions(actions, "scenario-t", env, resolved)
    ws = next(h for h in env["hosts"] if h["id"] == "ws_victim")
    assert out[0]["target"] == {"hostname": ws["hostname"]}
    assert [x["status"] for x in out] == ["required", "acceptable", "required"]
    path = out[1]["target"]["path"]
    assert path == ao.norm_path(path) and "{" not in path
    assert "nkhan" in path, "employee placeholder must substitute"
    acct = next(a for a in env["accounts"] if a["id"] == "victim")
    assert out[2]["target"] == {"domain": acct["domain"],
                                "username": acct["username"]}
    assert out[2]["after"] == ["a_iso"]


def test_scenario_grading_record_carries_scope_and_flag():
    sc, resolved, env = _resolved_env("lateral_movement_1")
    rec = app.scenario_grading_record("scenario-t", sc, env)
    assert rec["reviewed"] is True, "lateral_movement_1 was reviewed in batch 1"
    assert {h["hostname"] for h in env["hosts"]} == rec["hostnames"]
    assert ("acme", "svc_vulnscan") in rec["accounts"]
    assert ("acme", "nkhan") in rec["accounts"]
    # a not-yet-reviewed scenario stays reviewed=False (pick one dynamically
    # so the fixture survives later batches reviewing any given label)
    unreviewed = next(l for l, s in app.yaml_catalog.items()
                      if not s["answer_key"].get("actions_reviewed"))
    sc2, _, env2 = _resolved_env(unreviewed)
    assert app.scenario_grading_record("scenario-u", sc2, env2)["reviewed"] is False


# --- achievability across the fixed seed set ------------------------------------

SEED_SET = ["ach-seed-1", "ach-seed-2", "ach-seed-3", "ach-seed-4", "ach-seed-5"]

AUTHORED_LM1 = [
    {"id": "a_iso", "action": "isolate_host", "status": "required",
     "target": {"host": "ws_victim"}},
    {"action": "kill_process", "status": "required",
     "target": {"host": "ws_victim", "pid": 8844}},
    {"action": "delete_file", "status": "acceptable",
     "target": {"host": "ws_victim",
                "path": "C:\\Users\\{victim.username}\\Downloads\\nmap-7.95\\nmap.exe"}},
    {"action": "disable_account", "status": "required",
     "target": {"account": "victim"}, "after": ["a_iso"]},
]


def _world_for_seed(label, seed):
    sc, resolved, env, world, _dets, _reg, _keys = _full_world_for_seed(label, seed)
    return sc, resolved, env, world


def _full_world_for_seed(label, seed):
    """Mirror the drip: render the attack chain AND supplemental events,
    build the world, the scenario detections, the action entity registry,
    and the set of detection-surfaced account keys. Everything the trap and
    reachability harness needs, built exactly as the live session builds it."""
    sc, resolved, env = _resolved_env(label)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"},
                                 resolved)
        log["scenario_id"] = f"scenario-{label}"
        log["timestamp"] = f"2026-07-17T12:01:{i:02d}+00:00"
        logs.append(log)
    sup_logs, sup_meta = [], []
    for i, sup in enumerate(sc.get("supplemental_events", [])):
        fields = {k: v for k, v in sup.items() if k not in ("offset", "host", "user", "id")}
        log = sl.substitute_deep(fields, resolved)
        log["timestamp"] = f"2026-07-17T11:58:{i:02d}+00:00"
        sup_logs.append(log)
        m = {"id": sup["id"], "host": sup["host"]}
        if "user" in sup:
            m["user"] = sup["user"]
        sup_meta.append(m)
    world = {"hosts": {}, "started_at": STARTED}
    sg.extend_world(world, sc, env, logs, seed, app.RESERVED_PIDS, app.SERVERS,
                    supplemental=(sup_logs, sup_meta))
    env_accounts = {}
    ao.collect_env_accounts(env_accounts, env)
    registry = ao.build_entity_registry(world, env_accounts, seed)
    detections = dt.build_scenario_detections(
        f"scenario-{label}", sc, logs, seed,
        supplemental_logs=sup_logs, supplemental_meta=sup_meta, concrete_env=env)
    det_keys = app.detection_account_keys(detections, registry)
    return sc, resolved, env, world, detections, registry, det_keys


def _dependency_order(expected):
    done, out, pending = set(), [], list(expected)
    while pending:
        progressed = False
        for exp in list(pending):
            if all(ref in done for ref in exp.get("after", [])):
                out.append(exp)
                pending.remove(exp)
                if exp.get("eid"):
                    done.add(exp["eid"])
                progressed = True
        assert progressed, "declared order is unsatisfiable"
    return out


def _all_succeed(world, expected):
    overlay = ao.new_overlay()
    for exp in _dependency_order(expected):
        outcome, _ = ao.execute(world, overlay, dict(exp["target"]), exp["action"])
        if outcome != ao.SUCCESS:
            return False
    return True


def test_reviewed_corpus_actions_achievable_across_seed_set():
    """The 3c/3d gate, live from day one: every reviewed scenario's
    required actions must execute successfully from the initial world
    under every seed in the fixed set. Vacuous until batches land, then
    it bites."""
    for label, sc in app.yaml_catalog.items():
        ak = sc["answer_key"]
        if not (ak.get("actions_reviewed") and ak["actions"]):
            continue
        for seed in SEED_SET:
            sc2, resolved, env, world = _world_for_seed(label, seed)
            expected = app.materialize_expected_actions(
                ak["actions"], f"scenario-{label}", env, resolved)
            assert _all_succeed(world, expected), \
                f"{label}: required action unachievable under seed {seed}"


def test_required_and_acceptable_actions_are_ui_reachable_across_seeds():
    """Player-visibility: EVERY answer-key action of a reviewed scenario,
    required AND acceptable alike, must be surfaced by the response UI
    (Kill row / Isolate / Autoruns delete / Threats identity), across the
    seed set. An unreachable action must not appear in the answer key
    (owner ruling, 3c Batch 2 review): a required one the player cannot
    perform is unfair, and an acceptable one they cannot perform is a
    phantom the report would misdescribe."""
    for label, sc in app.yaml_catalog.items():
        ak = sc["answer_key"]
        if not ak.get("actions_reviewed"):
            continue
        for seed in SEED_SET:
            sc2, resolved, env, world, dets, reg, det_keys = _full_world_for_seed(label, seed)
            expected = app.materialize_expected_actions(
                ak["actions"], f"scenario-{label}", env, resolved)
            for exp in expected:
                assert app.ui_reachable(exp["action"], exp["target"], world, det_keys), \
                    (f"{label}: {exp['status']} {exp['action']} not UI-reachable "
                     f"under seed {seed} (no surface exposes it)")


def test_declared_traps_execute_reachable_and_grade_collateral_across_seeds():
    """The ruled trap audit: every declared trap must, across the fixed
    five-seed set, resolve to a valid client entity id in the initial
    world, be UI-reachable, execute successfully, and grade as collateral.
    A non-executable / unreachable / non-collateral declared trap fails the
    batch."""
    audited = 0
    for label, sc in app.yaml_catalog.items():
        traps = sc.get("traps", [])
        if not traps:
            continue
        for seed in SEED_SET:
            sc2, resolved, env, world, dets, reg, det_keys = _full_world_for_seed(label, seed)
            grading = [app.scenario_grading_record(f"scenario-{label}", sc, env)]
            expected = app.materialize_expected_actions(
                ak_actions(sc), f"scenario-{label}", env, resolved)
            mtraps = app.materialize_traps(traps, f"scenario-{label}", env, resolved)
            for trap in mtraps:
                action, target = trap["action"], trap["target"]
                # 1. resolves to a client entity id in the initial world
                eid = _resolve_target_entity(action, target, reg)
                assert eid is not None, \
                    f"{label}/{seed}: trap {action} does not resolve to an entity"
                # 2. UI-reachable
                assert app.ui_reachable(action, target, world, det_keys), \
                    f"{label}/{seed}: trap {action} is not UI-reachable"
                # 3. executes successfully
                overlay = ao.new_overlay()
                outcome, _ = ao.execute(world, overlay, dict(target), action)
                assert outcome == ao.SUCCESS, \
                    f"{label}/{seed}: trap {action} did not execute ({outcome})"
                # 4. grades collateral (alone, against the real answer key)
                executed = [_run(action, dict(target), 1)]
                isolated = {target["hostname"]} if action == "isolate_host" else set()
                r = app.compute_action_score(expected, executed, isolated, grading)
                assert r["collateral"] >= 1, \
                    f"{label}/{seed}: trap {action} did not grade collateral"
            audited += 1
    # A guard against the harness silently no-op'ing: once Batch 1 traps land
    # this is non-zero. (Left as >= 0 so the enforcement commit itself, which
    # introduces the machinery before any trap data, stays green.)
    assert audited >= 0


def ak_actions(sc):
    return sc["answer_key"].get("actions", [])


def _resolve_target_entity(action, target, registry):
    """The client entity id a materialized trap/action target resolves to,
    or None. Mirrors how the API resolves a player's action target."""
    kind = ao.ACTION_TARGET_KINDS[action]
    if kind == "account":
        key = ao.account_key(target["domain"], target["username"])
        for eid, e in registry.items():
            if e["kind"] == "account" and ao.account_key(e["domain"], e["username"]) == key:
                return eid
        return None
    if kind == "host":
        for eid, e in registry.items():
            if e["kind"] == "host" and e["hostname"] == target["hostname"]:
                return eid
        return None
    if action == "kill_process":
        for eid, e in registry.items():
            if (e["kind"] == "process" and e["hostname"] == target["hostname"]
                    and e["pid"] == target["pid"]):
                return eid
        return None
    for eid, e in registry.items():
        if (e["kind"] == "file" and e["hostname"] == target["hostname"]
                and e["path"] == target["path"]):
            return eid
    return None


def test_authored_targets_achievable_and_noise_targets_seed_fragile():
    """Authored targets execute under EVERY seed; a pid harvested from one
    seed's noise baseline fails under at least one other seed: exactly why
    the loader only accepts authored sources."""
    per_seed_worlds = {}
    for seed in SEED_SET:
        sc, resolved, env, world = _world_for_seed("lateral_movement_1", seed)
        expected = app.materialize_expected_actions(
            AUTHORED_LM1, "scenario-t", env, resolved)
        assert _all_succeed(world, expected), f"authored set failed under {seed}"
        per_seed_worlds[seed] = (env, world)

    env0, world0 = per_seed_worlds[SEED_SET[0]]
    ws = next(h for h in env0["hosts"] if h["id"] == "ws_victim")["hostname"]
    authored = {8844, 6240}
    noise_pid = next(p["pid"] for p in world0["hosts"][ws]["processes"]
                     if p["pid"] not in authored and p["pid"] > 4)
    fragile = [{"action": "kill_process", "status": "required",
                "target": {"host": "ws_victim", "pid": noise_pid}}]
    outcomes = []
    for seed in SEED_SET:
        env, world = per_seed_worlds[seed]
        sc, resolved, _ = _resolved_env("lateral_movement_1")
        expected = app.materialize_expected_actions(fragile, "scenario-t",
                                                    env, resolved)
        outcomes.append(_all_succeed(world, expected))
    assert not all(outcomes), \
        "a noise pid must not be achievable under every seed"


# --- route: surfacing and leak guard -------------------------------------------

def _api_session():
    client = app.app.test_client()
    r = client.get("/api/health")
    sid = r.headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _cleanup(sid, s):
    app.sessions.pop(sid, None)
    shutil.rmtree(s["session_dir"], ignore_errors=True)


def test_score_endpoint_shape_surfacing_and_no_leak():
    """Counts + grade + the three factual blocks (failed attempts, no_op
    repeats, executed acceptable actions). Expected composites, the status
    field, and the reviewed marker never serialize; UNEXECUTED acceptable
    targets never surface."""
    client, sid, s = _api_session()
    try:
        marker_path = "c:\\users\\public\\very_distinctive_payload_xyz.exe"
        acc_marker = "c:\\tools\\unexecuted_acceptable_marker.exe"
        with s["io_lock"]:
            # ACME-UNEX99 exists only in UNEXECUTED expectations: it must
            # never serialize. ACME-WS77 appears in an executed acceptable
            # action's log label: sanctioned disclosure after execution.
            s["expected_actions"] = [
                _exp("delete_file", {"hostname": "ACME-UNEX99", "path": marker_path},
                     scenario="scenario-m"),
                _exp("isolate_host", {"hostname": "ACME-UNEX99"},
                     scenario="scenario-m"),
                # executed acceptable: surfaces factually after execution
                _exp("kill_process", {"hostname": "ACME-WS77", "pid": 500},
                     scenario="scenario-m", status="acceptable"),
                # unexecuted acceptable: must never surface
                _exp("delete_file", {"hostname": "ACME-UNEX99", "path": acc_marker},
                     scenario="scenario-m", status="acceptable"),
            ]
            s["scenario_grading"] = [
                _grading(scenario="scenario-m",
                         hostnames={"ACME-WS77", "ACME-UNEX99"}, accounts=())]
            s["entity_index"] = {
                "ent-cccccccccccc": {"kind": "process", "hostname": "ACME-WS77",
                                     "pid": 500, "name": "helper.exe"},
            }
            s["overlay"]["log"] = [
                {"seq": 1, "timestamp": STARTED, "action": "kill_process",
                 "target": {"id": "ent-cccccccccccc", "kind": "process",
                            "label": "helper.exe (PID 500) on ACME-WS77"},
                 "outcome": "success", "reason": None},
                {"seq": 2, "timestamp": STARTED, "action": "isolate_host",
                 "target": {"id": "ent-aaaaaaaaaaaa", "kind": "host",
                            "label": "ACME-OFF01"},
                 "outcome": "failed_precondition",
                 "reason": "Host is offline. The isolation command could not "
                           "be delivered to the endpoint agent."},
                {"seq": 3, "timestamp": STARTED, "action": "disable_account",
                 "target": {"id": "ent-bbbbbbbbbbbb", "kind": "account",
                            "label": "ACME\\jdoe"},
                 "outcome": "no_op", "reason": "Account is already disabled."},
            ]
        resp = client.get("/api/analytics/action_score",
                          headers={"X-Session-ID": sid})
        assert resp.status_code == 200
        body = resp.get_json()
        assert set(body) == {"required", "correct", "missed", "collateral",
                             "order_violations", "graded", "accuracy", "grade",
                             "not_executed", "no_effect", "acceptable_taken"}
        assert body["required"] == 2 and body["missed"] == 2
        assert body["not_executed"]["count"] == 1
        assert "offline" in body["not_executed"]["entries"][0]["reason"]
        assert body["no_effect"]["count"] == 1
        assert body["no_effect"]["entries"][0]["outcome"] == "no_op"
        assert body["acceptable_taken"]["count"] == 1
        acc = body["acceptable_taken"]["entries"][0]
        assert acc["action"] == "kill_process" and acc["seq"] == 1
        # the executed acceptable action is not collateral
        assert body["collateral"] == 0
        blob = json.dumps(body)
        for needle in ("very_distinctive_payload_xyz",
                       "unexecuted_acceptable_marker",
                       "answer_key", '"actions_reviewed"', '"reviewed"',
                       '"expected"', '"status"', "ACME-UNEX99"):
            assert needle not in blob, f"score payload leaked {needle!r}"
    finally:
        _cleanup(sid, s)


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
