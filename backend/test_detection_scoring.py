"""Tests for Stage 2 disposition scoring v1 (deterministic, server-side).

Run: python -m pytest test_detection_scoring.py -q

Correct = promote a true positive, dismiss a false positive, dismiss a
benign_expected. Wrong = the inverse. Open detections are pending (excluded
from the grade). Same inputs always yield the same score.
"""
import os

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402


def _d(disposition, action):
    return {"disposition": disposition, "player_action": action}


def test_all_correct_is_grade_a():
    dets = [_d("true_positive", "promoted"), _d("false_positive", "dismissed"),
            _d("benign_expected", "dismissed")]
    r = app.compute_detection_score(dets)
    assert r["correct"] == 3 and r["wrong"] == 0
    assert r["accuracy"] == 100.0 and r["grade"] == "A"
    assert r["open"] == 0


def test_inverse_actions_are_wrong():
    dets = [_d("true_positive", "dismissed"),   # missed a real threat
            _d("false_positive", "promoted"),   # false escalation
            _d("benign_expected", "promoted")]  # false escalation
    r = app.compute_detection_score(dets)
    assert r["correct"] == 0 and r["wrong"] == 3
    assert r["accuracy"] == 0.0 and r["grade"] == "F"
    assert r["tp_dismissed"] == 1 and r["fp_promoted"] == 1 and r["benign_promoted"] == 1


def test_open_is_pending_not_graded():
    dets = [_d("true_positive", "open"), _d("false_positive", "open")]
    r = app.compute_detection_score(dets)
    assert r["open"] == 2 and r["graded"] == 0
    assert r["grade"] == "-" and r["accuracy"] == 0.0


def test_mixed_accuracy():
    # 3 correct, 1 wrong -> 75% -> C
    dets = [_d("true_positive", "promoted"), _d("false_positive", "dismissed"),
            _d("benign_expected", "dismissed"), _d("true_positive", "dismissed"),
            _d("false_positive", "open")]
    r = app.compute_detection_score(dets)
    assert r["correct"] == 3 and r["wrong"] == 1 and r["open"] == 1
    assert r["accuracy"] == 75.0 and r["grade"] == "C"
    assert r["total"] == 5


def test_empty_is_dash():
    r = app.compute_detection_score([])
    assert r["grade"] == "-" and r["graded"] == 0 and r["total"] == 0


def test_deterministic():
    dets = [_d("true_positive", "promoted"), _d("false_positive", "promoted"),
            _d("benign_expected", "open")]
    assert app.compute_detection_score(dets) == app.compute_detection_score(dets)


def test_grade_boundaries():
    # 9 correct, 1 wrong = 90% = A; 8/10 = 80% = B
    a = app.compute_detection_score([_d("true_positive", "promoted")] * 9
                                    + [_d("true_positive", "dismissed")])
    assert a["accuracy"] == 90.0 and a["grade"] == "A"
    b = app.compute_detection_score([_d("true_positive", "promoted")] * 8
                                    + [_d("true_positive", "dismissed")] * 2)
    assert b["accuracy"] == 80.0 and b["grade"] == "B"


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
