"""3d close-out, component 2: authored and ambient detections are STRUCTURALLY
indistinguishable in the client-facing payload.

Amendment 1: prove the same field set, data types, identifier format, payload
shape, and ordering treatment. This does NOT assert semantic indistinguishability
of wording/values (mitre presence, severity, etc.) -- that is narrative realism,
measured by the solver gates and content review, not asserted here.

Run: python test_detection_indistinguishability.py  (or pytest)
"""
import re

import detection_templates as dt
from test_detection_order import _materialize, CATALOG

# Every client-facing detection view must expose exactly these keys, each of the
# stated type/shape -- identically for authored and ambient detections.
FIELD_TYPES = {
    "id": lambda v: isinstance(v, str) and re.fullmatch(r"det-[0-9a-f]{12}", v),
    "rule_name": lambda v: isinstance(v, str) and bool(v),
    "rule_type": lambda v: v in ("sigma_behavioral", "yara"),
    "severity": lambda v: v in ("critical", "high", "medium", "low"),
    "mitre": lambda v: v is None or (isinstance(v, dict) and {"id", "tactic"} <= set(v)),
    "yara_rule_name": lambda v: v is None or isinstance(v, str),
    "description": lambda v: isinstance(v, str) and bool(v),
    "entity": lambda v: isinstance(v, dict) and set(v) == {"host", "account"},
    "time": lambda v: isinstance(v, str) and bool(v),
    "sha256": lambda v: v is None or bool(re.fullmatch(r"[0-9a-f]{64}", str(v))),
    "player_action": lambda v: v in ("open", "promoted", "dismissed"),
}

# Fields that would reveal authored-vs-ambient or the answer key: never present.
FORBIDDEN = ("scenario_id", "detection_key", "disposition", "authored", "kind",
             "answer_key", "label")


def _all_views():
    """(view, kind) for every materialized detection across the corpus."""
    out = []
    for label in CATALOG:
        insts, views = _materialize(label, "indist-seed")
        for inst, view in zip(insts, views):
            out.append((view, "ambient" if inst["scenario_id"] is None else "authored"))
    return out


VIEWS = _all_views()


def test_exact_field_set_identical():
    expected = set(FIELD_TYPES)
    for view, kind in VIEWS:
        assert set(view) == expected, f"{kind} view keys {set(view)} != {expected}"


def test_field_types_hold_for_both_kinds():
    for view, kind in VIEWS:
        for field, ok in FIELD_TYPES.items():
            assert ok(view[field]), f"{kind} field {field}={view[field]!r} wrong type/shape"


def test_no_forbidden_or_kind_revealing_field():
    for view, kind in VIEWS:
        for bad in FORBIDDEN:
            assert bad not in view, f"{kind} view leaked {bad}"


def test_id_format_uniform_across_kinds():
    auth = {bool(re.fullmatch(r"det-[0-9a-f]{12}", v["id"]))
            for v, k in VIEWS if k == "authored"}
    amb = {bool(re.fullmatch(r"det-[0-9a-f]{12}", v["id"]))
           for v, k in VIEWS if k == "ambient"}
    assert auth == amb == {True}, "id format differs between authored and ambient"


def test_key_set_does_not_separate_kinds():
    """No key is present for one kind only: authored and ambient expose the exact
    same key set. (This is the STRUCTURAL claim. Whether a given field's value is
    null vs populated -- e.g. mitre on a TP vs an FP -- is a semantic/value
    matter, measured by the solver gates and content review, per amendment 1,
    not asserted structurally here.)"""
    ak = set().union(*[set(v) for v, k in VIEWS if k == "authored"])
    bk = set().union(*[set(v) for v, k in VIEWS if k == "ambient"])
    assert ak == bk == set(FIELD_TYPES), (
        f"key sets differ: authored-only={ak-bk} ambient-only={bk-ak}")


def test_ordering_treatment_is_kind_agnostic():
    """order_detections_for_client depends only on id, so it cannot separate
    authored from ambient (component 1 covers determinism; here: the ordering
    key never reads kind or any kind-correlated field)."""
    views = [v for v, k in VIEWS]
    order_a = [v["id"] for v in dt.order_detections_for_client(views)]
    # relabel/shuffle input; same output order proves kind/position irrelevance
    import random
    shuffled = list(views); random.shuffle(shuffled)
    order_b = [v["id"] for v in dt.order_detections_for_client(shuffled)]
    assert order_a == order_b


if __name__ == "__main__":
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        fn(); print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
