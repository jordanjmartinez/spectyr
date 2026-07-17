"""3d close-out, component 5: permanent FP severity-rank uniformity gate.

Across the corpus, an authored false-positive detection in an ATTACK scenario
(one carrying at least one true-positive detection) sits at one of four ranks by
severity, relative to ALL of that scenario's authored detections:

  sole-top    : FP severity == the scenario max, and it is the UNIQUE max
                (exactly one detection at that severity).
  shared-top  : FP severity == the scenario max, and >1 detection is at the max.
  bottom      : FP severity == the scenario min (ties allowed -- shared-bottom
                still counts as bottom).
  middle      : anything else (strictly between min and max).

Counting: every authored FP instance is counted once; a scenario with two FPs
contributes two instances (e.g. data_exfil_archive). The denominator is the
TOTAL number of attack-scenario authored FP instances. Ambient benign detections
are NOT authored and are excluded from the rank computation.

Gate: no rank may hold more than 40% of the FP instances, so a future scenario
or severity edit cannot silently reskew the distribution.

Run: python test_rank_uniformity.py  (or pytest)
"""
import scenario_loader_v2 as slv2

CATALOG, _ = slv2.load_scenarios()
SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1}
MAX_SHARE = 0.40


def _fp_rank(fp_sev, all_sevs):
    ranks = [SEV[s] for s in all_sevs]
    mx, mn = max(ranks), min(ranks)
    r = SEV[fp_sev]
    if r == mx:
        return "sole-top" if ranks.count(mx) == 1 else "shared-top"
    if r == mn:
        return "bottom"
    return "middle"


def rank_distribution():
    """{rank: count} over every attack-scenario authored FP instance, plus the
    total. Attack scenario = has >=1 true_positive AND >=1 false_positive."""
    counts = {"sole-top": 0, "shared-top": 0, "middle": 0, "bottom": 0}
    per_scenario = {}
    for label, sc in CATALOG.items():
        dets = sc.get("detections") or []
        tps = [d for d in dets if d["disposition"] == "true_positive"]
        fps = [d for d in dets if d["disposition"] == "false_positive"]
        if not (tps and fps):
            continue
        all_sevs = [d["severity"] for d in dets]
        per_scenario[label] = []
        for fp in fps:
            r = _fp_rank(fp["severity"], all_sevs)
            counts[r] += 1
            per_scenario[label].append((fp["id"], fp["severity"], r))
    total = sum(counts.values())
    return counts, total, per_scenario


def test_no_fp_rank_exceeds_40_percent():
    counts, total, _ = rank_distribution()
    assert total > 0
    worst = max(counts.values())
    assert worst <= MAX_SHARE * total + 1e-9, (
        f"a severity rank holds {worst}/{total} = {100*worst/total:.1f}% of "
        f"attack-scenario FP instances (>40%): {counts}")


def test_every_rank_is_populated():
    """Sanity: the de-correlation actually spreads FPs across all four ranks."""
    counts, _, _ = rank_distribution()
    empty = [r for r, c in counts.items() if c == 0]
    assert not empty, f"unpopulated FP ranks: {empty} ({counts})"


if __name__ == "__main__":
    counts, total, per = rank_distribution()
    print(f"attack-scenario authored FP instances: {total}")
    for r in ("sole-top", "shared-top", "middle", "bottom"):
        print(f"  {r:11s} {counts[r]:2d}  {100*counts[r]/total:5.1f}%")
    print(f"  max share: {100*max(counts.values())/total:.1f}% (cap 40%)")
    for fn in (test_no_fp_rank_exceeds_40_percent, test_every_rank_is_populated):
        fn(); print(f"PASS {fn.__name__}")
