"""Detections decision-layer pass (2026-10-13): the three serialized additions
(`why`, `guidance`, `mitre.name/gloss`) are observable-only and verdict-free.

  - Coverage: every rule_name the corpus and the ambient templates can
    materialize has authored guidance (no instance falls to the fallback), with
    a non-empty harmless line and 3-5 checks; every tagged technique id has a
    pinned name + gloss, and the names equal the loader guard's canonical map.
  - Verdict-free: no guidance, gloss, or rendered why line carries a verdict
    word (the denylist), an em dash, or any forbidden answer-key field.
  - Observable-only: the why line is a pure function of the SANITIZED first
    triggering event + the entity (recomputing it from the client view
    reproduces it byte for byte), identical in shape for authored and ambient,
    and it never changes with the disposition.

Run: python test_detection_guidance.py  (or pytest)
"""
import copy
import re

import detection_guidance as dg
import detection_templates as dt
from test_detection_order import _materialize, CATALOG
from test_scenario_loader_v2 import CANONICAL_TECHNIQUE_NAMES, PINNED_DETECTION_TECHNIQUES

SEED = "guidance-seed"

# Words that would turn teaching copy into a verdict.
DENYLIST = re.compile(
    r"scenario|answer key|true positive|false positive|benign_expected|"
    r"disposition|\bpromote\b|\bdismiss\b|this instance is|this detection is",
    re.IGNORECASE)
FORBIDDEN = ("disposition", "scenario_id", "detection_key", "answer_key",
             "category", "storyline", "label")


def _all():
    out = []
    for label in CATALOG:
        insts, views = _materialize(label, SEED)
        for inst, view in zip(insts, views):
            out.append((label, inst, view))
    return out


ALL = _all()
# The AUTHORITATIVE rule and technique sets: every authored detection in the
# corpus plus every ambient template (a fixed-seed materialization samples
# 0-2 ambient rules per host, so it must not define coverage).
RULES = sorted({d["rule_name"] for sc in CATALOG.values() for d in sc.get("detections", [])}
               | {t[1] for t in dt.BENIGN_DETECTIONS})
TECHS = sorted({d["mitre"]["id"] for sc in CATALOG.values()
                for d in sc.get("detections", []) if d.get("mitre")}
               | {tid for tid, _ in dt.BENIGN_MITRE.values()})


def test_every_materialized_rule_has_authored_guidance():
    missing = [r for r in RULES if r not in dg.GUIDANCE]
    assert not missing, f"rules without authored guidance: {missing}"
    stale = [r for r in dg.GUIDANCE if r not in RULES]
    assert not stale, f"guidance for rules that no longer exist: {stale}"


def test_guidance_shape_harmless_line_and_three_to_five_checks():
    for rule, g in dg.GUIDANCE.items():
        assert isinstance(g["harmless"], str) and len(g["harmless"]) > 20, rule
        assert isinstance(g["checks"], list) and 3 <= len(g["checks"]) <= 5, rule
        for c in g["checks"]:
            assert isinstance(c, str) and len(c) > 10, rule


def test_every_tagged_technique_has_a_pinned_name_and_gloss():
    for tid in TECHS:
        name, gloss = dg.TECHNIQUES.get(tid, (None, None))
        assert name and gloss, f"{tid} has no pinned name/gloss"
    # the answer-key techniques carry the loader guard's exact canonical names
    for tid, canonical in CANONICAL_TECHNIQUE_NAMES.items():
        assert dg.TECHNIQUES[tid][0] == canonical, (tid, dg.TECHNIQUES[tid][0], canonical)
    # and nothing outside the pinned baseline is named here (no ambient drift)
    for tid in dg.TECHNIQUES:
        assert tid in CANONICAL_TECHNIQUE_NAMES or tid in PINNED_DETECTION_TECHNIQUES, tid


def test_no_verdict_words_or_em_dashes_in_teaching_copy():
    texts = []
    for rule, g in dg.GUIDANCE.items():
        texts.append((rule, g["harmless"]))
        texts += [(rule, c) for c in g["checks"]]
    texts += [(tid, n) for tid, (n, _) in dg.TECHNIQUES.items()]
    texts += [(tid, gl) for tid, (_, gl) in dg.TECHNIQUES.items()]
    for where, t in texts:
        assert not DENYLIST.search(t), (where, t)
        assert "—" not in t, (where, t)


def test_why_is_a_pure_function_of_the_sanitized_view():
    for label, inst, view in ALL:
        assert view["why"] and isinstance(view["why"], str), (label, inst["rule_name"])
        assert "—" not in view["why"]
        assert not DENYLIST.search(view["why"]), (label, view["why"])
        detail = dt.sanitize_detection(inst, include_events=True)
        recomputed = dg.render_why(detail["triggering_events"][0], detail["entity"])
        assert recomputed == view["why"], (label, inst["rule_name"])
        assert "guidance" in detail and "guidance" not in view
        assert detail["guidance"] == dg.guidance_for(inst["rule_name"])
        for bad in FORBIDDEN:
            assert bad not in view["why"].lower().replace(" ", "_"), (label, bad)


def test_why_never_changes_with_the_disposition_or_linkage():
    for label, inst, view in ALL:
        twin = copy.deepcopy(inst)
        twin["disposition"] = {"true_positive": "benign_expected",
                               "false_positive": "true_positive",
                               "benign_expected": "false_positive"}[inst["disposition"]]
        twin["scenario_id"] = None if inst["scenario_id"] else "scenario-x"
        assert dt.sanitize_detection(twin)["why"] == view["why"], (label, inst["rule_name"])


def test_why_falls_through_to_the_message_for_unknown_shapes():
    ev = {"event_type": "X", "source_type": "Other", "hostname": "H1",
          "message": "Something happened.", "key_value_pairs": {}}
    assert dg.render_why(ev, {"host": "H1", "account": "u"}) == "Something happened on H1 as u."
    assert dg.render_why(None, {"host": "H1", "account": None}).endswith("on H1.")


def test_mitre_enrichment_is_derived_from_the_id_alone():
    assert dg.enrich_mitre(None) is None
    m = dg.enrich_mitre({"id": "T1486", "tactic": "Impact"})
    assert m == {"id": "T1486", "tactic": "Impact",
                 "name": "Data Encrypted for Impact", "gloss": dg.TECHNIQUES["T1486"][1]}
    unknown = dg.enrich_mitre({"id": "T9999", "tactic": "X"})
    assert unknown["name"] is None and unknown["gloss"] is None


if __name__ == "__main__":
    import sys
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as e:  # noqa: BLE001
                fails += 1
                print(f"FAIL {name}: {e}")
    sys.exit(1 if fails else 0)
