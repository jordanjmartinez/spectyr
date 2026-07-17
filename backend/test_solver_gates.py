"""3d close-out, component 3: deterministic solver gates.

Three naive strategies are run against the full materialized corpus (every
scenario's authored detections PLUS the ambient benign of its hosts), across a
fixed set of session seeds, seeing ONLY the sanitized player-visible view. Each
must score no better than the uninformed baseline plus a one-prediction epsilon,
under BOTH micro (every detection equal) and macro (every scenario equal)
accounting -- so a large scenario cannot hide a leak in small ones.

Solvers (all consume sanitized feed views only; no id internals, authored status,
disposition, or answer key):

  promote-N (N=1..max): per scenario, rank detections by (severity desc, id) and
      promote the top N, dismiss the rest. Evaluated for every N; the gate is the
      worst (highest-accuracy) N; the report also names the best (lowest) N.
  dismiss-top-severity / promote-top-severity: per scenario, act on every
      detection at the scenario's maximum severity (dismiss them, resp. promote
      them); do the opposite to the rest.
  odd-one-out / keep-the-crowd: per scenario, feature-vector each detection over
      the player-visible fields (severity rank, rule_type, mitre tactic, whether
      a yara rule name is shown, whether an endpoint host is shown), score each
      by total Hamming distance to the others, and take the single most-unlike
      detection (ties -> lowest id). odd-one-out promotes it and dismisses the
      rest; keep-the-crowd does the opposite.

Null baseline (amendment 4): the best of always-promote, always-dismiss, and
class-frequency guessing (analytic expected accuracy p^2+(1-p)^2). Epsilon is one
prediction in the aggregate denominator: micro -> 1/total predictions across all
seeds; macro -> 1/(scenarios * seeds).

Run: python test_solver_gates.py   (prints the full table; also used by pytest)
"""
import random

import scenario_loader as sl
import scenario_loader_v2 as slv2
import snapshot_generator as sg
import detection_templates as dt

CATALOG, _ = slv2.load_scenarios()
SEEDS = ("sess-01", "sess-02", "sess-03", "sess-04", "sess-05")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

EMP = [{"name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com",
        "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12"}]
SRV = {"dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200"},
       "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201"},
       "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202"},
       "print": {"hostname": "ACME-SVR04", "ip": "10.0.1.203"},
       "web": {"hostname": "ACME-SVR05", "ip": "10.0.1.204"},
       "proxy": {"hostname": "ACME-SVR06", "ip": "10.0.1.205"},
       "backup": {"hostname": "ACME-VEEAM01", "ip": "10.0.1.206"},
       "scan": {"hostname": "ACME-SEC01", "ip": "10.0.1.207"}}


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__(); self._forced = forced

    def choice(self, seq):
        return self._forced


def _materialize(label, seed):
    """A scenario's per-incident feed: [(view, disposition)] for its authored
    detections plus the ambient benign of its endpoint hosts. Views are the
    sanitized, player-visible payloads only."""
    sc = CATALOG[label]
    res = sl.resolve_entities(sc, EMP, SRV, rng=_Forced(EMP[0]))
    env = sl.substitute_deep(sc["environment"], res)
    logs, sup_logs, sup_meta = [], [], []
    for i, step in enumerate(sc["chain"]):
        lg = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, res)
        lg.update({"scenario_id": f"scenario-{label}",
                   "timestamp": f"2026-07-16T12:00:{i:02d}+00:00"})
        logs.append(lg)
    for sup in sc.get("supplemental_events", []):
        f = {k: v for k, v in sup.items() if k not in ("offset", "host", "user", "id")}
        lg = sl.substitute_deep(f, res); lg["timestamp"] = "2026-07-16T11:58:00+00:00"
        sup_logs.append(lg); sup_meta.append({"id": sup["id"], "host": sup["host"]})
    insts = dt.build_scenario_detections(f"scenario-{label}", sc, logs, seed,
                                         supplemental_logs=sup_logs,
                                         supplemental_meta=sup_meta, concrete_env=env)
    started = "2026-07-16T12:00:00+00:00"
    seen = set()
    for h in env["hosts"]:
        if h["role"] in sg.NON_ENDPOINT_ROLES or h["hostname"] in seen:
            continue
        seen.add(h["hostname"])
        owner = next((a for a in env.get("accounts", []) if a.get("host") == h["id"]), None)
        owner = {"username": owner["username"], "domain": owner.get("domain", "ACME")} if owner else None
        insts += dt.benign_detections_for_host(h, owner, seed, started)
    return [(dt.sanitize_detection(i), i["disposition"]) for i in insts]


ALL_FEEDS = {seed: {lbl: _materialize(lbl, seed) for lbl in CATALOG} for seed in SEEDS}


def _correct(action, disp):
    return (disp == "true_positive") if action == "promote" else (disp != "true_positive")


# --- solvers: feed [(view,disp)] -> [(action, disp)] ------------------------

def _ranked(feed):
    return sorted(feed, key=lambda vd: (-SEV_RANK[vd[0]["severity"]], vd[0]["id"]))


def solve_promote_n(feed, n):
    order = _ranked(feed)
    return [("promote" if i < n else "dismiss", d) for i, (v, d) in enumerate(order)]


def solve_promote_top_severity(feed):
    mx = max(SEV_RANK[v["severity"]] for v, d in feed)
    return [("promote" if SEV_RANK[v["severity"]] == mx else "dismiss", d) for v, d in feed]


def solve_dismiss_top_severity(feed):
    mx = max(SEV_RANK[v["severity"]] for v, d in feed)
    return [("dismiss" if SEV_RANK[v["severity"]] == mx else "promote", d) for v, d in feed]


def _feature(v):
    return (SEV_RANK[v["severity"]], v["rule_type"],
            (v.get("mitre") or {}).get("tactic"), bool(v.get("yara_rule_name")),
            bool((v.get("entity") or {}).get("host")))


def _odd_index(feed):
    feats = [_feature(v) for v, d in feed]
    def dist(a, b):
        return sum(1 for x, y in zip(a, b) if x != y)
    scores = [(sum(dist(feats[i], feats[j]) for j in range(len(feats)) if j != i),
               feed[i][0]["id"], i) for i in range(len(feats))]
    scores.sort(key=lambda s: (-s[0], s[1]))   # most-unlike first, tie -> lowest id
    return scores[0][2]


def solve_odd_one_out(feed):
    oi = _odd_index(feed)
    return [("promote" if i == oi else "dismiss", d) for i, (v, d) in enumerate(feed)]


def solve_keep_the_crowd(feed):
    oi = _odd_index(feed)
    return [("dismiss" if i == oi else "promote", d) for i, (v, d) in enumerate(feed)]


# --- null strategies --------------------------------------------------------

def null_always_promote(feed):
    return [("promote", d) for v, d in feed]


def null_always_dismiss(feed):
    return [("dismiss", d) for v, d in feed]


# --- evaluation (micro + macro across seeds) --------------------------------

def _evaluate(solver):
    micro_c = micro_n = 0
    pair_accs = []
    for seed in SEEDS:
        for feed in ALL_FEEDS[seed].values():
            dec = solver(feed)
            c = sum(_correct(a, d) for a, d in dec)
            micro_c += c; micro_n += len(dec)
            pair_accs.append(c / len(dec))
    return micro_c / micro_n, sum(pair_accs) / len(pair_accs), micro_n, len(pair_accs)


def _class_freq_expected():
    """Analytic expected accuracy of class-frequency guessing (micro and macro):
    predict promote with prob p=P(TP); E[acc] = p^2+(1-p)^2 on any subpopulation
    with true-positive rate p."""
    disps = [d for seed in SEEDS for feed in ALL_FEEDS[seed].values() for v, d in feed]
    p = sum(1 for d in disps if d == "true_positive") / len(disps)
    micro = p * p + (1 - p) * (1 - p)
    accs = []
    for seed in SEEDS:
        for feed in ALL_FEEDS[seed].values():
            q = sum(1 for v, d in feed if d == "true_positive") / len(feed)
            accs.append(p * q + (1 - p) * (1 - q))
    return micro, sum(accs) / len(accs)


def null_baseline():
    ap_mi, ap_ma, n_mi, n_ma = _evaluate(null_always_promote)
    ad_mi, ad_ma, _, _ = _evaluate(null_always_dismiss)
    cf_mi, cf_ma = _class_freq_expected()
    return (max(ap_mi, ad_mi, cf_mi), max(ap_ma, ad_ma, cf_ma), n_mi, n_ma)


NULL_MICRO, NULL_MACRO, N_MICRO, N_MACRO = null_baseline()
EPS_MICRO = 1.0 / N_MICRO
EPS_MACRO = 1.0 / N_MACRO

GATED = {
    "promote-top-severity": solve_promote_top_severity,
    "dismiss-top-severity": solve_dismiss_top_severity,
    "odd-one-out": solve_odd_one_out,
    "keep-the-crowd": solve_keep_the_crowd,
}
_MAX_N = max(len(feed) for seed in SEEDS for feed in ALL_FEEDS[seed].values())
for _n in range(1, _MAX_N + 1):
    GATED[f"promote-N={_n}"] = (lambda f, n=_n: solve_promote_n(f, n))


def results():
    rows = {}
    for name, fn in GATED.items():
        mi, ma, _, _ = _evaluate(fn)
        rows[name] = (mi, ma, mi <= NULL_MICRO + EPS_MICRO, ma <= NULL_MACRO + EPS_MACRO)
    return rows


def test_gated_solvers_do_not_beat_baseline():
    rows = results()
    failures = []
    for name, (mi, ma, ok_mi, ok_ma) in rows.items():
        if not (ok_mi and ok_ma):
            failures.append(f"{name}: micro={mi:.4f} (null {NULL_MICRO:.4f}+{EPS_MICRO:.4f}"
                            f", ok={ok_mi}), macro={ma:.4f} (null {NULL_MACRO:.4f}+{EPS_MACRO:.4f}"
                            f", ok={ok_ma})")
    assert not failures, "solver gate(s) beat the baseline:\n  " + "\n  ".join(failures)


if __name__ == "__main__":
    print(f"seeds={len(SEEDS)}  micro-denominator={N_MICRO}  macro-denominator={N_MACRO}")
    print(f"null: micro={NULL_MICRO:.4f} (+eps {EPS_MICRO:.4f}={NULL_MICRO+EPS_MICRO:.4f})  "
          f"macro={NULL_MACRO:.4f} (+eps {EPS_MACRO:.4f}={NULL_MACRO+EPS_MACRO:.4f})")
    print(f"\n{'solver':26s} {'micro':>8s} {'ok':>3s} {'macro':>8s} {'ok':>3s}")
    rows = results()
    for name, (mi, ma, ok_mi, ok_ma) in rows.items():
        print(f"{name:26s} {mi:8.4f} {'Y' if ok_mi else 'N':>3s} "
              f"{ma:8.4f} {'Y' if ok_ma else 'N':>3s}")
    pn = {int(k.split('=')[1]): v for k, v in rows.items() if k.startswith('promote-N=')}
    worst = max(pn, key=lambda n: max(pn[n][0], pn[n][1]))
    best = min(pn, key=lambda n: max(pn[n][0], pn[n][1]))
    print(f"\npromote-N worst N={worst} (micro {pn[worst][0]:.4f}), "
          f"best N={best} (micro {pn[best][0]:.4f})")
    allok = all(ok_mi and ok_ma for _, _, ok_mi, ok_ma in rows.values())
    print("\nGATE:", "PASS" if allok else "FAIL")
