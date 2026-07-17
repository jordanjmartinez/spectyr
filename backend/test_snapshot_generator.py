"""Unit tests for the Stage 1 snapshot generator (incl. addendum invariants).

Run: python -m pytest test_snapshot_generator.py -q  (or python test_snapshot_generator.py)

Builds the world for every scenario in the v2 catalog with a forced employee
and asserts the Stage 1 acceptance criteria plus the addendum clarifications:
  - managed endpoint scope: Windows hosts only, firewall never an endpoint
  - every host renders all tabs; OS labels come from the environment block
  - attack lineage keeps authored PIDs/PPIDs, parents materialized
  - every network/DNS row PID resolves to a process in the same snapshot
  - every nonzero PPID resolves, except explicitly marked exited parents
  - stable-key determinism: values survive scenario arrival reordering
  - frozen session time: no generated value reads the wall clock
  - benign volume 30-50 processes per role; no placeholder or answer leaks
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
    "scan": {"hostname": "ACME-SEC01", "ip": "10.0.1.207", "desc": "Security Scanner"},
}

CATALOG, _ = slv2.load_scenarios()
RESERVED = sg.collect_reserved_pids(CATALOG)
SEED = "test-session-0001"
STARTED = "2026-07-16T12:00:00+00:00"


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__()
        self._forced = forced

    def choice(self, seq):
        return self._forced


def _render(label):
    """Substituted (scenario, env, logs) mirroring the drip path."""
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=_Forced(EMPLOYEES[0]))
    env = sl.substitute_deep(sc["environment"], resolved)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        log["scenario_id"] = f"scenario-{label}"
        log["timestamp"] = f"2026-07-16T12:01:{i:02d}+00:00"
        logs.append(log)
    return sc, env, logs


def _render_supplemental(sc, resolved):
    sup_logs, sup_meta = [], []
    for i, sup in enumerate(sc.get("supplemental_events", [])):
        fields = {k: v for k, v in sup.items() if k not in ("offset", "host", "user", "id")}
        log = sl.substitute_deep(fields, resolved)
        log["timestamp"] = f"2026-07-16T11:58:{i:02d}+00:00"
        sup_logs.append(log)
        m = {"id": sup["id"], "host": sup["host"]}
        if "user" in sup:
            m["user"] = sup["user"]
        sup_meta.append(m)
    return sup_logs, sup_meta


def _world_for(label, with_supplemental=False):
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=_Forced(EMPLOYEES[0]))
    env = sl.substitute_deep(sc["environment"], resolved)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        log["scenario_id"] = f"scenario-{label}"
        log["timestamp"] = f"2026-07-16T12:01:{i:02d}+00:00"
        logs.append(log)
    world = {"hosts": {}, "started_at": STARTED}
    supplemental = _render_supplemental(sc, resolved) if with_supplemental else None
    sg.extend_world(world, sc, env, logs, SEED, RESERVED, SERVERS,
                    supplemental=supplemental)
    return sc, env, logs, world


def _managed(env):
    return [h for h in env["hosts"] if h["role"] not in sg.NON_ENDPOINT_ROLES]


TAB_KEYS = ("processes", "services", "users", "autoruns", "network", "system")


def test_every_managed_host_renders_all_tabs():
    for label in CATALOG:
        _, env, _, world = _world_for(label)
        assert len(world["hosts"]) == len(_managed(env)), label
        for hostname, snap in world["hosts"].items():
            for key in TAB_KEYS:
                assert key in snap, f"{label}/{hostname}: missing {key}"
            assert "connections" in snap["network"] and "dns" in snap["network"]
            assert snap["status"] == "online"
            assert snap["isolation"] == "not_isolated"


def test_pan_os_devices_never_endpoints():
    """Firewall and proxy are log sources: present in the environment,
    never in the world."""
    for label in ("lateral_movement_1", "false_positive_veeam", "c2_dns_tunnel"):
        _, env, _, world = _world_for(label)
        assert any(h["role"] == "firewall" for h in env["hosts"]), label
        for snap in world["hosts"].values():
            assert snap["role"] not in sg.NON_ENDPOINT_ROLES, \
                f"{label}: {snap['role']} entered the world"
    # ssl_inspection's environment includes the PAN-OS proxy
    _, env, _, world = _world_for("false_positive_ssl_inspection")
    proxy = next(h for h in env["hosts"] if h["role"] == "proxy")
    assert proxy["os"] == "PAN-OS", "proxy OS must be PAN-OS in the environment"
    assert proxy["hostname"] not in world["hosts"], "proxy entered the world"


def test_os_labels_come_from_environment():
    for label in CATALOG:
        _, env, _, world = _world_for(label)
        for host in _managed(env):
            assert world["hosts"][host["hostname"]]["os"] == host["os"], label


def test_benign_volume_30_to_50():
    for label in CATALOG:
        sc, env, _, _ = _world_for(label)
        for host in _managed(env):
            owner = next((a for a in env["accounts"] if a.get("host") == host["id"]), None)
            snap = sg.build_baseline(host, owner, SEED, RESERVED, SERVERS, STARTED)
            n = len(snap["processes"])
            assert 30 <= n <= 50, f"{label}/{host['hostname']} ({host['role']}): {n} processes"


def test_attack_lineage_pids_consistent():
    for label in CATALOG:
        sc, env, logs, world = _world_for(label)
        hosts_by_id = {h["id"]: h for h in _managed(env)}
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


def test_network_and_dns_pids_resolve():
    """Addendum: every PID referenced by a network/DNS row resolves to
    exactly one process in the same snapshot."""
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        for hostname, snap in world["hosts"].items():
            counts = {}
            for p in snap["processes"]:
                counts[p["pid"]] = counts.get(p["pid"], 0) + 1
            for c in snap["network"]["connections"]:
                if c["pid"] is not None:
                    assert counts.get(c["pid"]) == 1, \
                        f"{label}/{hostname}: connection pid {c['pid']} resolves {counts.get(c['pid'], 0)}x"
            for d in snap["network"]["dns"]:
                if d["pid"] is not None:
                    assert counts.get(d["pid"]) == 1, \
                        f"{label}/{hostname}: dns pid {d['pid']} unresolved"


def test_ppids_resolve_or_are_marked_exited():
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        for hostname, snap in world["hosts"].items():
            pids = {p["pid"] for p in snap["processes"]}
            for p in snap["processes"]:
                if p["ppid"] == 0 or p.get("parent_exited"):
                    continue
                if p["ppid"] not in pids:
                    # authored chain parents are materialized; anything else
                    # dangling is a bug
                    raise AssertionError(
                        f"{label}/{hostname}: {p['name']} ppid {p['ppid']} dangling")


def test_no_duplicate_pids():
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        for hostname, snap in world["hosts"].items():
            pids = [p["pid"] for p in snap["processes"]]
            assert len(pids) == len(set(pids)), f"{label}/{hostname}: duplicate PIDs"


def test_baseline_avoids_reserved_pids():
    for label in CATALOG:
        sc, env, _, _ = _world_for(label)
        for host in _managed(env):
            snap = sg.build_baseline(host, None, SEED, RESERVED, SERVERS, STARTED)
            clash = {p["pid"] for p in snap["processes"]} & RESERVED
            assert not clash, f"{label}/{host['hostname']}: baseline uses reserved {clash}"


def test_deterministic_and_order_independent():
    """Same seed, same world; scenario arrival order must not change values
    on a shared host (stable-key determinism, addendum)."""
    def build(order):
        world = {"hosts": {}, "started_at": STARTED}
        for label in order:
            sc, env, logs = _render(label)
            sg.extend_world(world, sc, env, logs, SEED, RESERVED, SERVERS)
        return world

    a = build(["lateral_movement_1", "insider_staging"])
    b = build(["insider_staging", "lateral_movement_1"])
    fs = SERVERS["file"]["hostname"]
    ja = json.dumps({k: v for k, v in a["hosts"][fs].items() if k != "_scenario_ids"},
                    sort_keys=True, default=str)
    jb = json.dumps({k: v for k, v in b["hosts"][fs].items() if k != "_scenario_ids"},
                    sort_keys=True, default=str)
    assert ja == jb, "shared-host snapshot depends on scenario arrival order"

    _, _, _, w1 = _world_for("password_spray")
    _, _, _, w2 = _world_for("password_spray")
    assert json.dumps(w1, sort_keys=True, default=str) == \
           json.dumps(w2, sort_keys=True, default=str)


def test_frozen_time_and_system_block():
    """System info derives from the frozen session timestamp and stable keys:
    identical inputs give identical values; the shared egress IP is one
    address across all hosts; heartbeat equals the frozen timestamp online."""
    _, env, _, world = _world_for("lateral_movement_1")
    egress = {snap["system"]["external_ip"] for snap in world["hosts"].values()}
    assert len(egress) == 1, "egress IP must be one shared address"
    ip = egress.pop()
    assert ip.startswith("203.0.113.") and ip != "203.0.113.50"
    for snap in world["hosts"].values():
        sysinfo = snap["system"]
        assert sysinfo["last_heartbeat"] == STARTED
        assert sysinfo["first_seen"] < STARTED
        assert sysinfo["registered"] == sysinfo["first_seen"]
        assert sysinfo["mac_address"].startswith("00:50:56:")
        assert sysinfo["agent"] == "spectyr-agent 1.0.0"
        assert len(sysinfo["sensor_id"]) == 36


def test_defender_platform_path_versioned():
    """Defender binaries run from the doc-verified versioned platform dir;
    the version is a stable-key pick from the documented set and identical
    across processes and services of one host."""
    import re
    pat = re.compile(r"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
                     r"(4\.18\.\d{5}\.\d+)-0\\(MsMpEng|NisSrv)\.exe")
    _, _, _, world = _world_for("lateral_movement_1")
    for hostname, snap in world["hosts"].items():
        versions = set()
        for p in snap["processes"]:
            if p["name"] in ("MsMpEng.exe", "NisSrv.exe"):
                m = pat.fullmatch(p["path"])
                assert m, f"{hostname}: unversioned Defender path {p['path']!r}"
                versions.add(m.group(1))
        for svc in snap["services"]:
            if svc["name"] in ("WinDefend", "WdNisSvc"):
                assert "\\Platform\\" in svc["path"], f"{hostname}: {svc['path']!r}"
                m = pat.search(svc["path"])
                versions.add(m.group(1))
        assert len(versions) == 1, f"{hostname}: mixed platform versions {versions}"
        assert versions.pop() in ("4.18.25050.5", "4.18.25040.2")


def test_supplemental_process_event_integrity():
    """A supplemental process event (the scanner's nessusd on ACME-SEC01)
    merges into that host's snapshot with a resolving PID/PPID, same integrity
    bar as attack events."""
    _, env, _, world = _world_for("lateral_movement_1", with_supplemental=True)
    scan = next(h["hostname"] for h in env["hosts"] if h["role"] == "scanner")
    snap = world["hosts"][scan]
    nessus = [p for p in snap["processes"] if p["name"] == "nessusd.exe"]
    assert len(nessus) == 1, "supplemental nessusd process missing/duplicated"
    n = nessus[0]
    assert n["path"] == "C:\\Program Files\\Tenable\\Nessus\\nessusd.exe"
    pids = {p["pid"] for p in snap["processes"]}
    # authored PID present, authored parent materialized
    assert n["pid"] == 4120 and n["ppid"] == 784
    assert 784 in pids, "supplemental parent PID not materialized"
    # no duplicate PIDs after the supplemental merge
    all_pids = [p["pid"] for p in snap["processes"]]
    assert len(all_pids) == len(set(all_pids))


def test_supplemental_host_enters_world():
    """The canonical scanner host (ACME-SEC01) enters the world as a managed
    endpoint via the environment, and renders all tabs."""
    _, env, _, world = _world_for("lateral_movement_1", with_supplemental=True)
    assert "ACME-SEC01" in world["hosts"]
    snap = world["hosts"]["ACME-SEC01"]
    assert snap["role"] == "scanner" and snap["status"] == "online"
    assert 30 <= len(snap["processes"]) <= 60  # baseline + one supplemental proc


def test_memory_on_every_process():
    for label in ("c2_http", "lateral_movement_1"):
        _, _, _, world = _world_for(label)
        for snap in world["hosts"].values():
            for p in snap["processes"]:
                assert isinstance(p["memory_mb"], int) and p["memory_mb"] > 0


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


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
