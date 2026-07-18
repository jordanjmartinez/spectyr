"""Tests for the Stage 3a response-action overlay architecture.

Run: python -m pytest test_action_overlay.py -q  (or python test_action_overlay.py)

The load-bearing properties:
  - the base world is IMMUTABLE: applying any overlay never changes it
  - composite keys: kill is (host, pid), delete is (host, path); the same
    PID or path on another host is untouched
  - cascade map: a killed process disappears from live processes, its
    network/DNS rows go with it, orphaned children are marked
    parent_exited, a service whose only backing process died shows Stopped
    (svchost is exempt); isolation severs non-listening connections and
    release restores; deleted files leave autorun rows; identity state
    renders on user rows
  - the full Stage 1 integrity suite holds on base+overlay, not just base
  - the entity registry is stable-key, shape-uniform, and drip-order
    independent
"""
import copy
import json
import random

import scenario_loader as sl
import scenario_loader_v2 as slv2
import snapshot_generator as sg
import action_overlay as ao

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
SEED = "test-session-overlay"
STARTED = "2026-07-17T12:00:00+00:00"


class _Forced(random.Random):
    def __init__(self, forced):
        super().__init__()
        self._forced = forced

    def choice(self, seq):
        return self._forced


def _render(label):
    sc = CATALOG[label]
    resolved = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=_Forced(EMPLOYEES[0]))
    env = sl.substitute_deep(sc["environment"], resolved)
    logs = []
    for i, step in enumerate(sc["chain"]):
        log = sl.substitute_deep({k: v for k, v in step.items() if k != "offset"}, resolved)
        log["scenario_id"] = f"scenario-{label}"
        log["timestamp"] = f"2026-07-17T12:01:{i:02d}+00:00"
        logs.append(log)
    sup_logs, sup_meta = [], []
    for i, sup in enumerate(sc.get("supplemental_events", [])):
        fields = {k: v for k, v in sup.items() if k not in ("offset", "host", "user", "id")}
        log = sl.substitute_deep(fields, resolved)
        log["timestamp"] = f"2026-07-17T11:58:{i:02d}+00:00"
        sup_logs.append(log)
        m = {"id": sup["id"], "host": sup["host"]}
        if "user" in sup:
            m["user"] = sup["user"]
        sup_meta.append(m)
    return sc, env, logs, (sup_logs, sup_meta)


def _world_for(label):
    sc, env, logs, supplemental = _render(label)
    world = {"hosts": {}, "started_at": STARTED}
    sg.extend_world(world, sc, env, logs, SEED, RESERVED, SERVERS,
                    supplemental=supplemental)
    return sc, env, logs, world


def _view(world, hostname, overlay=None):
    """The route pattern: deep-copied public view, then base+overlay."""
    snap = copy.deepcopy(sg.public_view(world["hosts"][hostname]))
    return ao.apply_overlay(snap, overlay or ao.new_overlay())


def _host(role, hostname, ip):
    return {"id": f"h_{role}", "role": role, "hostname": hostname, "ip": ip,
            "os": "Windows Server 2022"}


# --- path helpers --------------------------------------------------------------

def test_extract_image_path_forms():
    assert ao.extract_image_path(
        '"C:\\Users\\nkhan\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background'
    ) == "C:\\Users\\nkhan\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    assert ao.extract_image_path(
        "C:\\Windows\\System32\\SecurityHealthSystray.exe"
    ) == "C:\\Windows\\System32\\SecurityHealthSystray.exe"
    assert ao.extract_image_path(
        "C:\\Windows\\System32\\svchost.exe -k netsvcs"
    ) == "C:\\Windows\\System32\\svchost.exe"
    assert ao.extract_image_path("") is None
    assert ao.extract_image_path(None) is None
    assert ao.extract_image_path("rundll32 someargs") is None


def test_norm_path_is_key_only():
    assert ao.norm_path('"C:\\Program Files\\App\\a.exe"') == "c:\\program files\\app\\a.exe"
    assert ao.norm_path("C:\\A.EXE") == "c:\\a.exe"
    assert ao.norm_path(None) == ""


# --- immutability --------------------------------------------------------------

def test_base_world_never_mutated_by_overlay():
    _, _, _, world = _world_for("malware_usb")
    hostname = sorted(world["hosts"])[0]
    before = json.dumps(world["hosts"][hostname], sort_keys=True, default=list)

    overlay = ao.new_overlay()
    overlay["isolated"].add(hostname)
    snap = world["hosts"][hostname]
    overlay["killed"].update((hostname, p["pid"]) for p in snap["processes"][:5])
    overlay["deleted_files"].add(
        (hostname, ao.norm_path(snap["processes"][0]["path"])))
    overlay["accounts"][ao.account_key("ACME", "nkhan")] = {
        "disabled": True, "sessions_revoked": True, "password_reset": False}

    _view(world, hostname, overlay)
    after = json.dumps(world["hosts"][hostname], sort_keys=True, default=list)
    assert before == after, "applying an overlay mutated the base world"


# --- kill cascade --------------------------------------------------------------

def test_kill_removes_process_and_its_network_rows():
    ws = _host("workstation", "ACME-WS12", "10.0.1.12")
    owner = {"username": "nkhan", "domain": "ACME"}
    snap = sg.build_baseline(ws, owner, SEED, RESERVED, SERVERS, STARTED)
    world = {"hosts": {"ACME-WS12": snap}, "started_at": STARTED}

    with_rows = [c["pid"] for c in snap["network"]["connections"] if c["pid"]]
    target = with_rows[0]

    overlay = ao.new_overlay()
    overlay["killed"].add(("ACME-WS12", target))
    view = _view(world, "ACME-WS12", overlay)

    assert all(p["pid"] != target for p in view["processes"])
    assert all(c["pid"] != target for c in view["network"]["connections"])
    assert all(d["pid"] != target for d in view["network"]["dns"])
    # the base still has all three
    assert any(p["pid"] == target for p in snap["processes"])
    assert any(c["pid"] == target for c in snap["network"]["connections"])


def test_orphan_ppid_annotation_and_integrity_after_kill_sequences():
    """3a close-out (c): killed parents leave surviving children rendering
    the original PPID annotated parent_terminated (real-EDR orphan
    rendering), the killed row itself is NOT retained, and the strict
    base+overlay integrity suite passes. Includes the Chrome-verified
    shape: a chrome parent killed, its renderer surviving."""
    ws = _host("workstation", "ACME-WS12", "10.0.1.12")
    owner = {"username": "nkhan", "domain": "ACME"}
    snap = sg.build_baseline(ws, owner, SEED, RESERVED, SERVERS, STARTED)
    world = {"hosts": {"ACME-WS12": snap}, "started_at": STARTED}

    by_ppid = {}
    for p in snap["processes"]:
        by_ppid.setdefault(p["ppid"], []).append(p)
    parents = [p for p in snap["processes"] if by_ppid.get(p["pid"])]
    # the Chrome-verified case when the baseline carries it: a chrome.exe
    # parent with a surviving chrome.exe child
    chrome_parent = next((p for p in parents if p["name"] == "chrome.exe"), None)
    parent = chrome_parent or parents[0]
    children = [c for c in by_ppid[parent["pid"]] if c["pid"] != parent["pid"]]
    assert children, "need a parent with a distinct surviving child"

    overlay = ao.new_overlay()
    overlay["killed"].add(("ACME-WS12", parent["pid"]))
    view = _view(world, "ACME-WS12", overlay)

    # no Terminated row is retained in the live Processes tab
    assert all(p["pid"] != parent["pid"] for p in view["processes"])
    live = {p["pid"]: p for p in view["processes"]}
    for child in children:
        row = live[child["pid"]]
        assert row.get("parent_terminated") is True, \
            f"orphaned child {child['name']} not annotated parent_terminated"
        assert row["ppid"] == parent["pid"], "orphan must keep the original PPID"
    # the base rows carry no such marker
    assert not any(p.get("parent_terminated") for p in snap["processes"])
    _integrity(view, snap, overlay)


def test_kill_leaves_no_running_service_backed_by_killed_pid():
    """3a close-out (b): no Services row still shows Running whose backing
    process (name + svchost -k group) was killed; other groups' svchost
    services keep Running."""
    dns = _host("dns", "ACME-SVR03", "10.0.1.202")
    snap = sg.build_baseline(dns, None, SEED, RESERVED, SERVERS, STARTED)
    world = {"hosts": {"ACME-SVR03": snap}, "started_at": STARTED}

    dns_proc = next(p for p in snap["processes"] if p["name"] == "dns.exe")
    netsvc_host = next(p for p in snap["processes"]
                       if p["name"] == "svchost.exe"
                       and "-k netsvcs" in p["cmdline"].lower())

    overlay = ao.new_overlay()
    overlay["killed"].add(("ACME-SVR03", dns_proc["pid"]))
    overlay["killed"].add(("ACME-SVR03", netsvc_host["pid"]))
    view = _view(world, "ACME-SVR03", overlay)

    live = view["processes"]
    for svc in view["services"]:
        if svc["status"] != "Running":
            continue
        name, group = ao._service_backing(svc.get("path") or "")
        if not name:
            continue
        backed = [p for p in live if p["name"].lower() == name
                  and (group is None or group in (p.get("cmdline") or "").lower())]
        had = [p for p in snap["processes"] if p["name"].lower() == name
               and (group is None or group in (p.get("cmdline") or "").lower())]
        assert backed or not had, \
            f"service {svc['name']} still Running with its backing process killed"
    # the killed instances' services flipped, others did not
    dns_svc = next(s for s in view["services"] if s["name"] == "DNS")
    assert dns_svc["status"] == "Stopped"
    assert any(s["status"] == "Running" for s in view["services"]
               if "-k" in (s.get("path") or "")), \
        "killing one svchost group stopped unrelated svchost services"
    # the base service rows are untouched
    assert next(s for s in snap["services"] if s["name"] == "DNS")["status"] == "Running"


# --- isolation -----------------------------------------------------------------

def test_isolation_severs_connections_keeps_listeners_and_release_restores():
    _, env, _, world = _world_for("c2_http")
    hostname = sorted(world["hosts"])[0]
    base_view = _view(world, hostname)
    listening = [c for c in base_view["network"]["connections"] if c["state"] == "LISTENING"]
    established = [c for c in base_view["network"]["connections"] if c["state"] != "LISTENING"]
    assert listening and established, "need both kinds for a meaningful test"

    overlay = ao.new_overlay()
    overlay["isolated"].add(hostname)
    view = _view(world, hostname, overlay)
    assert view["isolation"] == "isolated"
    assert all(c["state"] == "LISTENING" for c in view["network"]["connections"])
    assert len(view["network"]["connections"]) == len(listening)
    # DNS is a historical query log: isolation does not rewrite it
    assert view["network"]["dns"] == base_view["network"]["dns"]

    overlay["isolated"].discard(hostname)
    restored = _view(world, hostname, overlay)
    assert restored["isolation"] == "not_isolated"
    assert restored["network"]["connections"] == base_view["network"]["connections"]


# --- delete file ---------------------------------------------------------------

def test_delete_file_leaves_persistence_row_until_registration_removed():
    """Dual-flag state model (Stage 3c.5): deleting a file-backed Run key's
    payload clears the file flag but leaves the registration active, so the
    persistence row survives (annotated file-deleted). Only when the
    registration is ALSO removed does the row leave the live view. This is
    what keeps a required delete_file reachable regardless of when an
    acceptable remove_persistence is taken."""
    ws = _host("workstation", "ACME-WS12", "10.0.1.12")
    owner = {"username": "nkhan", "domain": "ACME"}
    snap = sg.build_baseline(ws, owner, SEED, RESERVED, SERVERS, STARTED)
    world = {"hosts": {"ACME-WS12": snap}, "started_at": STARTED}

    target = next(a for a in snap["autoruns"] if "OneDrive" in a["name"])
    path = ao.norm_path(ao.extract_image_path(target["command"]))
    ident = tuple(target["identity"])

    overlay = ao.new_overlay()
    overlay["deleted_files"].add(("ACME-WS12", path))
    view = _view(world, "ACME-WS12", overlay)
    row = next((a for a in view["autoruns"] if a["name"] == target["name"]), None)
    assert row is not None, "a file-only delete must not drop the persistence row"
    assert row["registration"] == "active" and row["file_state"] == "deleted"
    # a running process keeps its in-memory image reference
    assert len(view["processes"]) == len(snap["processes"])

    overlay["removed_persistence"].add(ident)
    view2 = _view(world, "ACME-WS12", overlay)
    assert all(a["name"] != target["name"] for a in view2["autoruns"]), \
        "both flags cleared: the row must leave the live view"
    # base untouched
    assert any(a["name"] == target["name"] for a in snap["autoruns"])


# --- composite keys across hosts ------------------------------------------------

def test_pid_and_path_composites_never_cross_hosts():
    a = _host("workstation", "ACME-WS12", "10.0.1.12")
    b = _host("workstation", "ACME-WS13", "10.0.1.13")
    owner = {"username": "nkhan", "domain": "ACME"}
    snap_a = sg.build_baseline(a, owner, SEED, RESERVED, SERVERS, STARTED)
    snap_b = sg.build_baseline(b, owner, SEED, RESERVED, SERVERS, STARTED)
    world = {"hosts": {"ACME-WS12": snap_a, "ACME-WS13": snap_b},
             "started_at": STARTED}

    # same autorun path exists on both workstations
    shared_path = ao.norm_path(ao.extract_image_path(snap_a["autoruns"][0]["command"]))
    assert any(ao.norm_path(ao.extract_image_path(x["command"])) == shared_path
               for x in snap_b["autoruns"])

    overlay = ao.new_overlay()
    overlay["killed"].add(("ACME-WS12", snap_a["processes"][10]["pid"]))
    overlay["deleted_files"].add(("ACME-WS12", shared_path))
    overlay["isolated"].add("ACME-WS12")

    view_b = _view(world, "ACME-WS13", overlay)
    untouched = _view(world, "ACME-WS13")
    assert view_b == untouched, "an action on WS12 leaked into WS13's view"


def test_pid_collision_key_is_host_scoped():
    """Hand-built snapshots with the SAME pid on two hosts: killing on one
    host must not remove the other's process."""
    def mini(hostname):
        return {
            "hostname": hostname, "status": "online", "isolation": "not_isolated",
            "processes": [
                {"pid": 4000, "ppid": 0, "parent_name": "-", "name": "same.exe",
                 "path": "C:\\Tools\\same.exe", "cmdline": "same.exe", "user": "-",
                 "signer": None, "signed": False, "memory_mb": 10},
            ],
            "services": [], "users": [], "autoruns": [],
            "network": {"connections": [], "dns": []},
        }
    overlay = ao.new_overlay()
    overlay["killed"].add(("HOST-A", 4000))
    va = ao.apply_overlay(mini("HOST-A"), overlay)
    vb = ao.apply_overlay(mini("HOST-B"), overlay)
    assert va["processes"] == []
    assert len(vb["processes"]) == 1


# --- identity ------------------------------------------------------------------

def test_identity_states_render_on_user_rows():
    _, env, _, world = _world_for("insider_staging")
    hostname = sorted(world["hosts"])[0]
    snap = world["hosts"][hostname]
    domain_user = next(u for u in snap["users"] if u.get("type") == "Domain")

    overlay = ao.new_overlay()
    key = ao.account_key(domain_user["domain"], domain_user["username"])
    overlay["accounts"][key] = {"disabled": True, "sessions_revoked": True,
                                "password_reset": False}
    view = _view(world, hostname, overlay)
    row = next(u for u in view["users"]
               if u["username"] == domain_user["username"]
               and u["domain"] == domain_user["domain"])
    assert row["enabled"] is False
    assert row["identity_state"] == {"disabled": True, "sessions_revoked": True,
                                     "password_reset": False}
    # base row untouched
    assert "identity_state" not in domain_user


# --- Stage 1 integrity suite on base+overlay -----------------------------------

def _integrity(view, base_snap, overlay):
    """The Stage 1 invariants against a rendered (base+overlay) view, with
    the terminated-parent PPID exception wired in STRICTLY: a dangling PPID
    is acceptable only for (1) a base-authored exited parent (the marker
    must exist on the same base row) or (2) an overlay-killed parent (the
    (host, ppid) must genuinely be in the overlay's killed set). The
    exception never silently waives resolution for any other cause."""
    hostname = view["hostname"]
    killed = {pid for (h, pid) in overlay["killed"] if h == hostname}
    base_exited = {p["pid"] for p in base_snap["processes"] if p.get("parent_exited")}

    pids = [p["pid"] for p in view["processes"]]
    counts = {}
    for pid in pids:
        counts[pid] = counts.get(pid, 0) + 1
    assert len(pids) == len(set(pids)), "duplicate PIDs in live view"
    for c in view["network"]["connections"]:
        if c["pid"] is not None:
            assert counts.get(c["pid"]) == 1, \
                f"live connection pid {c['pid']} unresolved"
    for d in view["network"]["dns"]:
        if d["pid"] is not None:
            assert counts.get(d["pid"]) == 1, f"live dns pid {d['pid']} unresolved"

    live = set(pids)
    for p in view["processes"]:
        if p["ppid"] == 0:
            continue
        if p["ppid"] in live:
            assert not p.get("parent_terminated"), \
                f"{p['name']}: parent_terminated but parent {p['ppid']} is live"
            continue
        if p.get("parent_terminated"):
            assert p["ppid"] in killed, \
                f"{p['name']}: parent_terminated waiving a non-killed ppid {p['ppid']}"
        elif p.get("parent_exited"):
            assert p["pid"] in base_exited, \
                f"{p['name']}: parent_exited marker not authored in the base"
        else:
            raise AssertionError(
                f"{p['name']}: ppid {p['ppid']} dangles in live view unmarked")


def test_integrity_suite_holds_on_base_plus_overlay_corpus_wide():
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        for hostname in world["hosts"]:
            snap = world["hosts"][hostname]
            overlay = ao.new_overlay()
            # kill every 4th process (deterministic slice), isolate, delete
            # every autorun-borne file: a worst-case action barrage
            victims = sorted(p["pid"] for p in snap["processes"])[::4]
            overlay["killed"].update((hostname, pid) for pid in victims)
            overlay["isolated"].add(hostname)
            # Neutralize every persistence artifact on both flags: delete the
            # file AND remove the registration, so every row is fully cleared.
            for a in snap["autoruns"]:
                np = ao.norm_path(ao.extract_image_path(a.get("command") or ""))
                if np:
                    overlay["deleted_files"].add((hostname, np))
                if a.get("identity"):
                    overlay["removed_persistence"].add(tuple(a["identity"]))
            view = _view(world, hostname, overlay)
            _integrity(view, snap, overlay)
            # Every persistence row must be gone: a live row would mean an
            # artifact survived a full-neutralization barrage.
            assert not view["autoruns"], \
                f"{label}/{hostname}: persistence row survived full neutralization"


def test_integrity_exception_rejects_unsanctioned_markers():
    """The exception must not waive resolution for any other cause: a
    parent_terminated marker pointing at a NOT-killed pid, and an unmarked
    dangling ppid, must both fail the suite."""
    def mini(marker):
        return {
            "hostname": "HOST-A", "status": "online", "isolation": "not_isolated",
            "processes": [
                {"pid": 4000, "ppid": 9996, "parent_name": "gone.exe",
                 "name": "child.exe", "path": "C:\\t\\c.exe", "cmdline": "c",
                 "user": "-", "signer": None, "signed": False, "memory_mb": 4,
                 **marker},
            ],
            "services": [], "users": [], "autoruns": [],
            "network": {"connections": [], "dns": []},
        }
    overlay = ao.new_overlay()
    for marker in ({"parent_terminated": True}, {}, {"parent_exited": True}):
        snap = mini({})  # base carries no authored exited parents
        view = ao.apply_overlay(mini(marker), overlay)
        try:
            _integrity(view, snap, overlay)
        except AssertionError:
            continue
        raise AssertionError(f"integrity accepted unsanctioned marker {marker}")


def test_kill_leaves_no_live_network_or_dns_attribution_to_killed_pid():
    """3a close-out (a): after kill sequences, no live Network connection
    or DNS attribution resolves to a killed (host, pid), corpus-wide."""
    for label in CATALOG:
        _, _, _, world = _world_for(label)
        for hostname in world["hosts"]:
            snap = world["hosts"][hostname]
            with_rows = sorted({c["pid"] for c in snap["network"]["connections"]
                                if c["pid"]}
                               | {d["pid"] for d in snap["network"]["dns"] if d["pid"]})
            if not with_rows:
                continue
            overlay = ao.new_overlay()
            overlay["killed"].update((hostname, pid) for pid in with_rows[::2])
            view = _view(world, hostname, overlay)
            killed = {pid for (h, pid) in overlay["killed"] if h == hostname}
            assert all(c.get("pid") not in killed
                       for c in view["network"]["connections"]), \
                f"{label}/{hostname}: live connection attributed to killed pid"
            assert all(d.get("pid") not in killed
                       for d in view["network"]["dns"]), \
                f"{label}/{hostname}: live dns row attributed to killed pid"
            _integrity(view, snap, overlay)


# --- entity registry -----------------------------------------------------------

def _registry_for(*labels):
    world = {"hosts": {}, "started_at": STARTED}
    env_accounts = {}
    for label in labels:
        sc, env, logs, supplemental = _render(label)
        sg.extend_world(world, sc, env, logs, SEED, RESERVED, SERVERS,
                        supplemental=supplemental)
        ao.collect_env_accounts(env_accounts, env)
    return world, ao.build_entity_registry(world, env_accounts, SEED)


def test_registry_ids_uniform_unique_and_kind_opaque():
    world, reg = _registry_for("lateral_movement_1")
    assert reg, "registry is empty"
    for eid, entry in reg.items():
        assert ao.ENTITY_ID_RE.match(eid), f"id shape violation: {eid}"
        assert entry["kind"] in ("host", "process", "file", "account", "persistence")
    kinds = {e["kind"] for e in reg.values()}
    # every managed host carries benign Run keys, so persistence is present too
    assert {"host", "process", "file", "account", "persistence"} <= kinds


def test_registry_is_drip_order_independent():
    _, reg_ab = _registry_for("lateral_movement_1", "insider_staging")
    _, reg_ba = _registry_for("insider_staging", "lateral_movement_1")
    assert reg_ab == reg_ba


def test_annotated_view_ids_resolve_in_registry():
    world, reg = _registry_for("malware_usb")
    for hostname in world["hosts"]:
        view = ao.annotate_view(_view(world, hostname), SEED)
        assert reg[view["entity_id"]]["kind"] == "host"
        assert reg[view["entity_id"]]["hostname"] == hostname
        for p in view["processes"]:
            entry = reg[p["entity_id"]]
            assert (entry["kind"], entry["hostname"], entry["pid"]) == \
                ("process", hostname, p["pid"])
        for a in view["autoruns"]:
            if a["file_entity_id"] is not None:
                assert reg[a["file_entity_id"]]["kind"] == "file"
        for u in view["users"]:
            entry = reg.get(u["entity_id"])
            assert entry is not None and entry["kind"] == "account"


def test_resolve_account_key_forms():
    _, reg = _registry_for("insider_staging")
    domain_accounts = [e for e in reg.values()
                       if e["kind"] == "account" and e["scope"] == "domain"]
    assert domain_accounts, "no domain accounts registered"
    target = domain_accounts[0]
    down_level = f"{target['domain']}\\{target['username']}"
    upn = f"{target['username']}@acme.local"
    for form in (down_level, upn, target["username"]):
        eid = ao.resolve_account_key(form, reg)
        assert eid is not None, f"form {form!r} did not resolve"
        assert reg[eid]["username"].lower() == target["username"].lower()
    assert ao.resolve_account_key("", reg) is None
    assert ao.resolve_account_key("nosuchuser", reg) is None


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
