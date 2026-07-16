"""Tests for the dashboard ATT&CK coverage radar data (Stage 1.5).

Run: python -m pytest test_attack_coverage.py -q  (or python test_attack_coverage.py)

The critical property: the radar is a pure function of COMPLETED scenarios.
An in-progress scenario, even with every event already injected into the
pool, contributes nothing, so the dashboard can never draw the active
scenario's kill chain shape.
"""
import os

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")

import app  # noqa: E402


def _entry(label, resolved=False, injected=True):
    return {
        "scenario_label": label,
        "queue_position": 1,
        "injected_at": "2026-07-16T12:00:00+00:00" if injected else None,
        "chain_complete_at": "2026-07-16T12:01:00+00:00" if injected else None,
        "resolved_at": "2026-07-16T12:05:00+00:00" if resolved else None,
    }


REVIEWS = {
    "lateral_movement_1": {"mitre": {"id": "T1046", "tactic": "Discovery"}},
    "malware_usb": {"mitre": {"id": "T1091", "tactic": "Initial Access"}},
    "malware_ransomware": {"mitre": {"id": "T1486", "tactic": "Impact"}},
    "phishing_1": {"mitre": {"id": "T1583.001", "tactic": "Resource Development"}},
    "false_positive_veeam": {"what_is_it": {"title": "Backup"}},  # no mitre
}


def _by_tactic(result):
    return {t["tactic"]: t["count"] for t in result["tactics"]}


def test_in_progress_scenarios_contribute_nothing():
    """The leak proof: injected-but-unresolved scenarios are invisible."""
    queue = [
        _entry("lateral_movement_1", resolved=False, injected=True),
        _entry("malware_usb", resolved=False, injected=True),
        _entry("malware_ransomware", resolved=False, injected=False),
    ]
    result = app.compute_attack_coverage(queue, REVIEWS)
    assert result["completed"] == 0
    assert result["covered"] == 0
    assert result["most_practiced"] is None
    assert all(t["count"] == 0 for t in result["tactics"])


def test_completed_scenarios_land_on_axes():
    queue = [
        _entry("lateral_movement_1", resolved=True),
        _entry("malware_usb", resolved=True),
        _entry("malware_ransomware", resolved=False),  # active: invisible
    ]
    result = app.compute_attack_coverage(queue, REVIEWS)
    counts = _by_tactic(result)
    assert result["completed"] == 2
    assert counts["Discovery"] == 1 and counts["Initial Access"] == 1
    assert counts["Impact"] == 0, "active scenario leaked onto the radar"
    assert result["covered"] == 2
    assert result["most_practiced"] in ("Discovery", "Initial Access")


def test_fp_and_off_radar_tactics():
    """FPs (no mitre) complete without an axis; Resource Development sits
    outside the 12 and counts as off_radar."""
    queue = [
        _entry("false_positive_veeam", resolved=True),
        _entry("phishing_1", resolved=True),
    ]
    result = app.compute_attack_coverage(queue, REVIEWS)
    assert result["completed"] == 2
    assert result["covered"] == 0
    assert result["off_radar"] == 1
    assert all(t["count"] == 0 for t in result["tactics"])


def test_axes_fixed_and_ordered():
    result = app.compute_attack_coverage([], REVIEWS)
    assert [t["tactic"] for t in result["tactics"]] == app.ENTERPRISE_TACTICS
    assert result["total_tactics"] == 12
    assert result["completed"] == 0


def test_deterministic():
    queue = [_entry("lateral_movement_1", resolved=True),
             _entry("malware_usb", resolved=False)]
    a = app.compute_attack_coverage(queue, REVIEWS)
    b = app.compute_attack_coverage(queue, REVIEWS)
    assert a == b


def test_corpus_tactics_map_onto_axes():
    """Every attack tactic in the live catalog lands on an axis, except the
    known Resource Development outlier (phishing_1)."""
    reviews = app.yaml_triage_reviews
    outliers = []
    for label, review in reviews.items():
        tactic = (review.get("mitre") or {}).get("tactic")
        if tactic and tactic not in app.ENTERPRISE_TACTICS:
            outliers.append((label, tactic))
    assert outliers == [("phishing_1", "Resource Development")], outliers


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
