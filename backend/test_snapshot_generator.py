"""Unit tests for the Stage 1 snapshot generator.

Run: python -m pytest test_snapshot_generator.py -q  (or python test_snapshot_generator.py)

Builds the world for every scenario in the v2 catalog with a forced employee
and asserts the Stage 1 acceptance criteria:
  - every host in every scenario renders all tabs without errors
  - attack lineage is present with authored PIDs/PPIDs, parents materialized
  - benign volume is 30-50 processes per Windows host role
  - determinism: same seed, same world
  - no placeholders and no attack/benign or scenario markers leak to the API
"""
import copy
import json
import random

import scenario_loader as sl
import scenario_loader_v2 as slv2
import snapshot_generator as sg

EMPLOYEES = [
    {"name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com",
     "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12"},
]
SERVERS = {
    "dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200", "desc": "Domain Controller"},
    "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201", "desc": "File Server"},
    "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202", "desc": "DNS Server"},
    "print": {"hostname": "ACME-SVR04", "ip": "10.0.1.203", "desc": "Print Server"},
    "web": {"hostname": "ACME-SVR05", "ip": "10.0.1.204", "desc": "Web Server"},
    "proxy": {"hostname": "ACME-SVR06", "ip": "10.0.1.205", "desc": "Proxy Server"},
    "backup": {"hostname": "ACME-VEEAM01", "ip": "10.0.1.206", "desc": "Backup Server"},
}

CATALOG, _ = slv2.load_scenarios()
RESERVED = sg.collect_reserved_pids(CATALOG)
SEED = "test-session-0001"


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__()
        self._forced = forced

    def choice(self, seq):
        return self._forced


def _render(label):
    """Substituted (env, logs) for one scenario, mirroring the drip path."""
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=_Forced(EMPLOYEES[0]))
    env = sl.substitute_deep(sc["environment"], resolved)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        log["scenario_id"] = f"scenario-{label}"
        log["timestamp"] = f"2026-07-16T12:00:{i:02d}+00:00"
        logs.append(log)
    return sc, env, logs


def _world_for(label):
    sc, env, logs = _render(label)
    world = {"hosts": {}}
    sg.extend_world(world, sc, env, logs, SEED, RESERVED, SERVERS)
    return sc, env, logs, world


TAB_KEYS = ("processes", "services", "users", "autoruns", "network")


def test_every_host_renders_all_tabs():
    for label in CATALOG:
        _, env, _, world = _world_for(label)
        assert len(world["hosts"]) == len(env["hosts"]), label
        for hostname, snap in world["hosts"].items():
            for key in TAB_KEYS:
                assert key in snap, f"{label}/{hostname}: missing {key}"
            assert "connections" in snap["network"] and "dns" in snap["network"]
            if snap["role"] == "firewall":
                assert snap["appliance"] is True
            else:
                assert snap["appliance"] is False


def test_benign_volume_30_to_50():
    """Baseline (pre-merge) process volume per Windows role."""
    for label in CATALOG:
        sc, env, _, _ = _world_for(label)
        for host in env["hosts"]:
            if host["role"] == "firewall":
                continue
            owner = next((a for a in env["accounts"] if a.get("host") == host["id"]), None)
            snap = sg.build_baseline(host, owner, SEED, RESERVED, SERVERS,
                                     "2026-07-16T12:00:00+00:00")
            n = len(snap["processes"])
            assert 30 <= n <= 50, f"{label}/{host['hostname']} ({host['role']}): {n} processes"


def test_attack_lineage_pids_consistent():
    """Every authored ProcessCreate lands with its authored PID, and its
    authored parent PID exists as a real node."""
    for label in CATALOG:
        sc, env, logs, world = _world_for(label)
        hosts_by_id = {h["id"]: h for h in env["hosts"]}
        for log, meta in zip(logs, sc["attack_meta"]):
            kvp = log.get("key_value_pairs") or {}
            if log.get("source_type") != "Sysmon" or str(kvp.get("event_id")) != "1":
                continue
            hostname = hosts_by_id[meta["host"]]["hostname"]
            snap = world["hosts"][hostname]
            pids = {p["pid"]: p for p in snap["processes"]}
            pid, ppid = int(kvp["process_id"]), int(kvp["parent_process_id"])
            assert pid in pids, f"{label}/{hostname}: authored pid {pid} missing"
            assert pids[pid]["path"] == kvp["image"], f"{label}/{hostname}: image mismatch"
            assert pids[pid]["ppid"] == ppid, f"{label}/{hostname}: ppid mismatch"
            assert ppid in pids, f"{label}/{hostname}: parent pid {ppid} not materialized"


def test_no_duplicate_pids():
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        for hostname, snap in world["hosts"].items():
            pids = [p["pid"] for p in snap["processes"]]
            assert len(pids) == len(set(pids)), f"{label}/{hostname}: duplicate PIDs"


def test_baseline_avoids_reserved_pids():
    for label in CATALOG:
        sc, env, _, _ = _world_for(label)
        for host in env["hosts"]:
            if host["role"] == "firewall":
                continue
            snap = sg.build_baseline(host, None, SEED, RESERVED, SERVERS, None)
            clash = {p["pid"] for p in snap["processes"]} & RESERVED
            assert not clash, f"{label}/{host['hostname']}: baseline uses reserved {clash}"


def test_deterministic():
    for label in ("lateral_movement_1", "password_spray", "false_positive_veeam"):
        _, _, _, w1 = _world_for(label)
        _, _, _, w2 = _world_for(label)
        assert json.dumps(w1, sort_keys=True, default=str) == \
               json.dumps(w2, sort_keys=True, default=str), label


def test_no_placeholders_leak():
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        text = json.dumps(world, default=str)
        assert sl.PLACEHOLDER.findall(text) == [], f"{label}: unresolved placeholders"


def test_public_view_strips_markers():
    _, _, _, world = _world_for("lateral_movement_1")
    for snap in world["hosts"].values():
        pub = sg.public_view(snap)
        assert not any(k.startswith("_") for k in pub)
        text = json.dumps(pub, default=str)
        assert "lateral_movement_1" not in text, "scenario label leaked"
        assert "scenario-" not in text, "scenario id leaked"


def test_autorun_artifacts_surface():
    expectations = {
        "malware_usb": "WindowsUpdate",
        "defense_evasion": "WindowsServices",
        "phishing_link": "InvoiceService",
    }
    for label, name in expectations.items():
        _, env, _, world = _world_for(label)
        ws = next(h["hostname"] for h in env["hosts"] if h["role"] == "workstation")
        entries = {a["name"] for a in world["hosts"][ws]["autoruns"]}
        assert name in entries, f"{label}: autorun artifact {name!r} missing ({entries})"


def test_password_spray_users_on_dc():
    """Successful 4624 surfaces a session; failed 4625s must not."""
    _, env, _, world = _world_for("password_spray")
    dc = next(h["hostname"] for h in env["hosts"] if h["role"] == "dc")
    users = {u["username"]: u for u in world["hosts"][dc]["users"]}
    assert "lgreen" in users and users["lgreen"].get("last_logon"), "compromised session missing"
    for sprayed in ("dpark", "mjohnson", "bwilliams", "achen", "jkim"):
        assert sprayed not in users, f"failed logon {sprayed} must not create a session"


def test_lateral_movement_file_server_logon():
    _, env, _, world = _world_for("lateral_movement_1")
    fs = next(h["hostname"] for h in env["hosts"] if h["role"] == "file")
    users = {u["username"] for u in world["hosts"][fs]["users"]}
    assert "nkhan" in users, "victim network logon missing from file server users"


def test_shared_host_merges_two_scenarios():
    """Two scenarios touching the file server share one baseline."""
    world = {"hosts": {}}
    for label in ("lateral_movement_1", "insider_staging"):
        sc, env, logs = _render(label)
        sg.extend_world(world, sc, env, logs, SEED, RESERVED, SERVERS)
    fs = SERVERS["file"]["hostname"]
    snap = world["hosts"][fs]
    assert len(snap["_scenario_ids"]) == 2
    pids = [p["pid"] for p in snap["processes"]]
    assert len(pids) == len(set(pids)), "merge produced duplicate PIDs"
    # lateral_movement_1's net.exe (authored pid) still present after merge
    assert any(p["name"] == "net.exe" for p in snap["processes"])


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
