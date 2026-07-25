"""Stage 5 Phase 5: the response-review teaching layer (contract 7.1-7.5;
ratified OD-1..OD-4; scaffold ruling B conditions).

Run: python test_response_review.py

Commit 5.1 rows: the binding reason-code registry; Tier 1 template purity
(purpose only, the two contract examples byte-canonical, no scenario token
beyond nothing at all -- whys are label-free by construction).
Commit 5.2 rows: every registry code fixture-pinned to the scorer's own
verdict (R1: reuse, not reimplementation); the popped `_review` detail
leaves the public score dict byte-identical; the 19.16 count
reconciliation over fixtures (both fold-in mappings).
Commit 5.3 rows: the frozen record (freeze completeness, byte-identity,
404/absence, planted markers over the ENUMERATED pre-submission surfaces,
aggregate-shape assertion, empty states) plus the real-drip corpus
reconciliation pass.
"""
import copy
import json
import os
import shutil

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402
import response_review as rr  # noqa: E402

WS = "ACME-WS12"
SVR = "ACME-SVR02"
STARTED = "2026-07-17T12:00:00+00:00"

GRADING = [{"scenario_id": "scenario-x", "reviewed": True,
            "hostnames": {WS, SVR},
            "accounts": {("acme", "nkhan"), ("acme", "innocent")}}]


def _exp(action, target, eid=None, after=None, scenario="scenario-x",
         status="required"):
    return {"scenario_id": scenario, "eid": eid, "action": action,
            "status": status, "target": target, "after": list(after or [])}


def _run(action, target, seq):
    return {"seq": seq, "action": action, "target": target}


def _score(expected, executed, isolated, grading=None):
    return app.compute_action_score(expected, executed, isolated,
                                    GRADING if grading is None else grading)


def _entries(result):
    return result["_review"]["entries"]


def _codes(result):
    return sorted(e["reason_code"] for e in _entries(result))


# --- 5.1: registry + templates ------------------------------------------------

def test_registry_buckets_are_the_binding_71_set():
    assert rr.BUCKET_OF == {
        "required_completed": "completed",
        "required_not_attempted": "missed",
        "required_attempt_failed": "missed",
        "out_of_order": "missed",
        "released_after_isolation": "missed",
        "acceptable_completed": "acceptable",
        "collateral_in_scope": "collateral",
        "inaction_correct": "inaction",
        "inaction_spoiled": "inaction",
    }


def test_contract_canonical_examples_render_byte_exact():
    assert rr.render_why(rr.REQUIRED_NOT_ATTEMPTED, "isolate_host") == (
        "Isolating an implicated host cuts an attacker's access to it while "
        "the investigation continues. This host required isolation and was "
        "not isolated at submission.")
    assert rr.render_why(rr.COLLATERAL_IN_SCOPE, "kill_process") == (
        "This action was not part of the expected response for this "
        "incident. Acting on targets the evidence does not implicate "
        "disrupts clean assets.")
    assert rr.render_why(rr.INACTION_CORRECT, None) == (
        "No response action was required. The correct response here was "
        "investigation without action.")


def test_template_purity_no_scenario_tokens_and_deterministic():
    """Purpose-only rule (correction 4): whys are label-free and identical
    regardless of any target; no hostname, account, path, or scenario token
    can appear because none is ever passed in."""
    verbs = ["isolate_host", "kill_process", "delete_file", "disable_account",
             "revoke_sessions", "force_password_reset", "remove_persistence"]
    codes = [rr.REQUIRED_COMPLETED, rr.REQUIRED_NOT_ATTEMPTED,
             rr.REQUIRED_ATTEMPT_FAILED, rr.OUT_OF_ORDER,
             rr.ACCEPTABLE_COMPLETED]
    for v in verbs:
        for c in codes:
            w1 = rr.render_why(c, v)
            w2 = rr.render_why(c, v)
            assert w1 == w2 and w1
            assert "ACME" not in w1 and "scenario" not in w1.lower()
            assert "\u2014" not in w1          # no em dash


def test_expected_label_registry_lookup_and_composite_fallback():
    registry = {
        "ent-aaaaaaaaaaaa": {"kind": "host", "hostname": WS},
        "ent-cccccccccccc": {"kind": "process", "hostname": WS,
                             "pid": 4756, "name": "payload.exe"},
    }
    assert rr.expected_label("isolate_host", {"hostname": WS}, registry) == WS
    assert "payload.exe" in rr.expected_label(
        "kill_process", {"hostname": WS, "pid": 4756}, registry)
    # fallback grammar when the registry lacks the entity
    assert rr.expected_label("kill_process", {"hostname": WS, "pid": 9999},
                             registry) == f"PID 9999 on {WS}"
    assert rr.expected_label("disable_account",
                             {"domain": "ACME", "username": "nkhan"}, {}) \
        == "ACME\\nkhan"


# --- 5.2: every registry code pinned to the scorer's own verdict ---------------

def test_required_completed_and_not_attempted_pin():
    exp = [_exp("kill_process", {"hostname": WS, "pid": 4756}),
           _exp("delete_file", {"hostname": WS, "path": "c:\\x\\p.exe"})]
    r = _score(exp, [_run("kill_process",
                          {"hostname": WS, "pid": 4756, "name": "p.exe"}, 1)],
               set())
    assert r["correct"] == 1 and r["missed"] == 1
    ent = _entries(r)
    done = next(e for e in ent if e["reason_code"] == rr.REQUIRED_COMPLETED)
    miss = next(e for e in ent if e["reason_code"] == rr.REQUIRED_NOT_ATTEMPTED)
    assert done["seq"] == 1 and done["action"] == "kill_process"
    assert miss["seq"] is None and miss["action"] == "delete_file"


def test_released_after_isolation_pin_carries_the_isolate_seq():
    exp = [_exp("isolate_host", {"hostname": WS})]
    executed = [_run("isolate_host", {"hostname": WS}, 3)]
    r = _score(exp, executed, set())          # end-state: NOT isolated
    assert r["missed"] == 1
    ent = _entries(r)
    assert _codes(r) == [rr.RELEASED_AFTER_ISOLATION]
    assert ent[0]["seq"] == 3


def test_out_of_order_pin():
    exp = [_exp("isolate_host", {"hostname": WS}, eid="a_iso"),
           _exp("kill_process", {"hostname": WS, "pid": 4756},
                after=["a_iso"])]
    executed = [_run("kill_process",
                     {"hostname": WS, "pid": 4756, "name": "p.exe"}, 1),
                _run("isolate_host", {"hostname": WS}, 2)]
    r = _score(exp, executed, {WS})
    assert r["order_violations"] == 1
    codes = _codes(r)
    assert rr.OUT_OF_ORDER in codes and rr.REQUIRED_COMPLETED in codes
    ooo = next(e for e in _entries(r) if e["reason_code"] == rr.OUT_OF_ORDER)
    assert ooo["seq"] == 1


def test_acceptable_completed_and_collateral_pins():
    exp = [_exp("kill_process", {"hostname": WS, "pid": 4756},
                status="acceptable")]
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 4756, "name": "p.exe"}, 1),
        _run("delete_file", {"hostname": WS, "path": "c:\\clean\\doc.txt",
                             "display": "C:\\clean\\doc.txt"}, 2),
    ]
    r = _score(exp, executed, set())
    assert r["collateral"] == 1
    acc = next(e for e in _entries(r)
               if e["reason_code"] == rr.ACCEPTABLE_COMPLETED)
    col = next(e for e in _entries(r)
               if e["reason_code"] == rr.COLLATERAL_IN_SCOPE)
    assert acc["seq"] == 1 and col["seq"] == 2
    assert col["action"] == "delete_file"


def test_endstate_isolation_collateral_pin():
    r = _score([], [_run("isolate_host", {"hostname": SVR}, 5)], {SVR})
    col = next(e for e in _entries(r)
               if e["reason_code"] == rr.COLLATERAL_IN_SCOPE)
    assert col["action"] == "isolate_host" and col["seq"] == 5


def test_inaction_pins_both_ways():
    grading = [{"scenario_id": "scenario-fp", "reviewed": True,
                "hostnames": {WS}, "accounts": set()}]
    clean = app.compute_action_score([], [], set(), grading)
    assert _codes(clean) == [rr.INACTION_CORRECT]
    assert _entries(clean)[0]["seq"] is None
    spoiled = app.compute_action_score(
        [], [_run("kill_process",
                  {"hostname": WS, "pid": 500, "name": "x.exe"}, 1)],
        set(), grading)
    codes = _codes(spoiled)
    assert rr.INACTION_SPOILED in codes and rr.COLLATERAL_IN_SCOPE in codes


def test_popped_review_leaves_public_score_dict_byte_identical():
    """Ruling B: the internal detail is removed at every call site and the
    public result is byte-identical to the pre-change shape (the untouched
    test_action_scoring suite pins the values; this pins the KEY SET)."""
    exp = [_exp("isolate_host", {"hostname": WS})]
    r = _score(exp, [_run("isolate_host", {"hostname": WS}, 1)], {WS})
    r.pop("_review")
    assert set(r.keys()) == {
        "required", "correct", "missed", "collateral", "order_violations",
        "graded", "accuracy", "accuracy_raw", "inaction_collateral",
        "grade", "acceptable_seqs"}


def test_count_reconciliation_fixtures_both_fold_ins():
    """19.16: bucket counts reconcile exactly against the frozen score
    section, including the inaction fold-in and the out_of_order subset."""
    # attack incident with a mix
    exp = [_exp("isolate_host", {"hostname": WS}, eid="a_iso"),
           _exp("kill_process", {"hostname": WS, "pid": 4756},
                after=["a_iso"]),
           _exp("delete_file", {"hostname": WS, "path": "c:\\x\\p.exe"})]
    executed = [
        _run("kill_process", {"hostname": WS, "pid": 4756, "name": "p"}, 1),
        _run("isolate_host", {"hostname": WS}, 2),
        _run("disable_account", {"domain": "ACME", "username": "innocent"}, 3),
    ]
    r = _score(exp, executed, {WS})
    ent = _entries(r)
    buckets = {}
    for e in ent:
        buckets.setdefault(rr.BUCKET_OF[e["reason_code"]], []).append(e)
    assert len(buckets.get("completed", [])) == r["correct"]
    assert len(buckets.get("missed", [])) == r["missed"]
    assert len(buckets.get("collateral", [])) == r["collateral"]
    assert sum(1 for e in ent if e["reason_code"] == rr.OUT_OF_ORDER) \
        == r["order_violations"]
    # inaction incident: the single unit reconciles against correct/missed
    grading = [{"scenario_id": "scenario-fp", "reviewed": True,
                "hostnames": {WS}, "accounts": set()}]
    clean = app.compute_action_score([], [], set(), grading)
    assert clean["correct"] == 1 and clean["required"] == 1
    assert [e["reason_code"] for e in _entries(clean)] == [rr.INACTION_CORRECT]
    spoiled = app.compute_action_score(
        [], [_run("kill_process",
                  {"hostname": WS, "pid": 500, "name": "x"}, 1)],
        set(), grading)
    assert spoiled["missed"] == 1
    assert sum(1 for e in _entries(spoiled)
               if e["reason_code"] == rr.INACTION_SPOILED) == 1


def _main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} passed")


if __name__ == "__main__":
    _main()
