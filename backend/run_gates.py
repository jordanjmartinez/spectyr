"""The canonical halt-on-failure gate runner (never-land-red enforcement).

One command runs the full battery and exits non-zero at the FIRST failed
suite; nothing downstream runs after a failure. The pre-commit hook in
.githooks/ invokes this scoped to what the staged changes touch; run it
manually before any hand-verification:

    python backend/run_gates.py            # backend battery
    python backend/run_gates.py --frontend # frontend suite only
    python backend/run_gates.py --all      # both

Ruled at the 3c Batch 1 review after commit de6a891 landed red through
an unchained gate command. Suites listed here are the project gate set;
extend the lists when a new suite becomes a gate, never bypass.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FRONTEND = os.path.join(REPO, "frontend")

BACKEND_SUITES = [
    "test_scenario_loader_v2.py",
    "test_scenario_loader.py",
    "test_action_scoring.py",
    "test_submission_gate.py",
    "test_incident_scope.py",
    "test_event_disclosure.py",
    "test_guided_catalog.py",
    "test_actions.py",
    "test_action_overlay.py",
    "test_persistence.py",
    "test_persistence_response.py",
    "test_snapshot_generator.py",
    "test_sim_epoch.py",
    "test_event_seq.py",
    "test_lcql.py",
    "test_detections.py",
    "test_detection_scoring.py",
    "test_detection_order.py",
    "test_detection_indistinguishability.py",
    "test_rank_uniformity.py",
    "test_attack_coverage.py",
    "test_solver_gates.py",
    "parity_check.py",
    "parity_check_v2.py",
    "fairness_check.py",
]


def run(cmd, cwd, env=None):
    print(f"[gate] {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=cwd, env=env)
    if result.returncode != 0:
        print(f"[gate] RED: {' '.join(cmd)} (exit {result.returncode})",
              flush=True)
        sys.exit(result.returncode or 1)


def run_backend():
    for suite in BACKEND_SUITES:
        run([sys.executable, suite], cwd=HERE)


def run_frontend():
    env = dict(os.environ, CI="true")
    npx = "npx.cmd" if os.name == "nt" else "npx"
    run([npx, "react-scripts", "test", "--watchAll=false"],
        cwd=FRONTEND, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend", action="store_true",
                        help="frontend suite only")
    parser.add_argument("--all", action="store_true",
                        help="backend battery plus frontend suite")
    args = parser.parse_args()

    if args.all:
        run_backend()
        run_frontend()
    elif args.frontend:
        run_frontend()
    else:
        run_backend()
    print("[gate] ALL GREEN", flush=True)


if __name__ == "__main__":
    main()
