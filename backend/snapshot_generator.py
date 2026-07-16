"""Endpoint snapshot generator (Phase 2 Stage 1).

Builds one world state per session: a dict of per-host EDR-style snapshots
(processes, network, services, users, autoruns) derived from

    environment   the scenario's substituted environment block
    event pool    the scenario's rendered (substituted) attack logs, each
                  positionally paired with its attack_meta actor tag
    noise         role profiles from noise_profiles.py

Rules the rest of the pivot depends on:

- Pure derivation. Every tab is a view over (baseline + event pool). There
  are no per-tab generators and nothing here re-randomizes on read.
- Determinism. All randomness flows through a random.Random seeded from
  (session_seed, hostname). The module-level random is never touched, so
  chain rendering parity is unaffected.
- Lineage. Attack processes keep their authored PIDs/PPIDs. Authored parents
  are materialized: a singleton baseline process (explorer.exe) is re-pinned
  to the authored parent PID; a parent with no baseline image (cmd.exe) is
  created from the authored parent_* fields. Every authored PID in the whole
  catalog is reserved up front so baseline PIDs can never collide with any
  scenario that might drip later.
- No answer leakage. Snapshots carry no scenario labels and no attack/benign
  markers; internal bookkeeping fields start with "_" and the API strips them.

Windows PIDs are multiples of 4, so generated PIDs are too.
"""
import hashlib
import os
import random
import re

import noise_profiles

RUN_KEY_RE = re.compile(r"\\CurrentVersion\\Run\\", re.IGNORECASE)


# --- authored PID reservation -------------------------------------------------

def collect_reserved_pids(catalog):
    """Every process_id / parent_process_id authored anywhere in the catalog.
    Reserved so baseline PID assignment can never collide with a chain."""
    reserved = set()
    for sc in catalog.values():
        for step in sc["chain"]:
            kvp = step.get("key_value_pairs") or {}
            for key in ("process_id", "parent_process_id"):
                val = str(kvp.get(key, ""))
                if val.isdigit():
                    reserved.add(int(val))
    return reserved


def _host_rng(session_seed, hostname):
    digest = hashlib.sha256(f"{session_seed}:{hostname}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


# --- baseline ------------------------------------------------------------------

def build_baseline(host, owner, session_seed, reserved_pids, servers, base_time_iso):
    """Benign snapshot for one host: processes/services/users/autoruns/network
    from the role profile. `owner` is the substituted owning account dict or
    None; `servers` is app.SERVERS for internal network noise targets."""
    rng = _host_rng(session_seed, host["hostname"])
    role = host["role"]

    if role == "firewall":
        return {
            "host_id": host["id"], "hostname": host["hostname"],
            "ip": host["ip"], "role": role, "os": host["os"],
            "desc": host.get("desc", ""), "appliance": True,
            "owner": None, "processes": [], "services": [], "users": [],
            "autoruns": [],
            "network": {"connections": [], "dns": []},
            "_scenario_ids": [], "_pid_locks": {},
        }

    owner_user = f"{owner['domain']}\\{owner['username']}" if owner else None
    owner_name = owner["username"] if owner else None

    def sub(text):
        if not isinstance(text, str):
            return text
        out = text.replace("__HOSTNAME__", host["hostname"])
        if owner_name:
            out = out.replace("__OWNERNAME__", owner_name)
        if owner_user:
            out = out.replace(noise_profiles.OWNER, owner_user)
        return out

    # processes: assign increasing multiple-of-4 PIDs, skipping reserved ones
    processes = []
    by_name = {}
    pid = 4
    specs = []
    for spec in noise_profiles.processes_for_role(role):
        if owner_name is None and spec["user"] == noise_profiles.OWNER:
            continue  # no interactive session on an ownerless host
        for _ in range(spec.get("dup", 1)):
            specs.append(spec)

    def next_pid(cursor):
        cursor += 4 * rng.randint(2, 30)
        while cursor in reserved_pids:
            cursor += 4
        return cursor

    cursor = 4
    for spec in specs:
        if spec["name"] == "System":
            node_pid = 4
        else:
            cursor = next_pid(cursor)
            node_pid = cursor
        node = {
            "pid": node_pid,
            "name": spec["name"],
            "path": sub(spec["path"]),
            "cmdline": sub(spec["cmdline"]),
            "user": sub(spec["user"]),
            "signer": spec["signer"],
            "signed": spec["signer"] is not None,
            "_parent_name": spec["parent"],
        }
        processes.append(node)
        by_name.setdefault(spec["name"], []).append(node)

    # resolve parents by name; "<exited>" gets a phantom PID (never listed).
    # Phantom PIDs sit below the child and collide with nothing: userinit
    # really does start before explorer and exit.
    used_pids = {p["pid"] for p in processes}
    for node in processes:
        pname = node.pop("_parent_name")
        if pname == "" or node["name"] == "System":
            node["ppid"] = 0
            node["parent_name"] = "-"
        elif pname == "<exited>":
            phantom = node["pid"] - 4 * rng.randint(1, 6)
            while phantom in used_pids or phantom in reserved_pids or phantom <= 4:
                phantom -= 4
                if phantom <= 4:
                    phantom = node["pid"] + 4
                    while phantom in used_pids or phantom in reserved_pids:
                        phantom += 4
                    break
            used_pids.add(phantom)
            node["ppid"] = phantom
            node["parent_name"] = "userinit.exe"
        elif pname in by_name:
            parent = by_name[pname][0]
            node["ppid"] = parent["pid"]
            node["parent_name"] = parent["name"]
        else:
            node["ppid"] = 0
            node["parent_name"] = pname
    processes.sort(key=lambda n: n["pid"])

    services = [
        {k: sub(v) if isinstance(v, str) else v for k, v in svc.items()}
        for svc in noise_profiles.services_for_role(role)
    ]
    users = [
        {k: sub(v) if isinstance(v, str) else v for k, v in u.items()}
        for u in noise_profiles.users_for_role(role)
    ]
    if owner:
        users.append({
            "username": owner["username"], "domain": owner["domain"],
            "type": "Domain", "enabled": True,
            "description": "Assigned workstation user",
        })
    autoruns = [
        {k: sub(v) for k, v in a.items()}
        for a in noise_profiles.autoruns_for_role(role)
    ]

    # network noise: listeners + a seeded sample of benign traffic
    connections = []
    for proto, port, pname in noise_profiles.ROLE_LISTENING.get(role, []):
        connections.append({
            "proto": proto, "local_ip": host["ip"], "local_port": port,
            "remote_ip": "-", "remote_port": None, "state": "LISTENING",
            "process": pname,
        })
    dns = []
    if role == "workstation":
        ext = rng.sample(noise_profiles.BENIGN_EXTERNAL,
                         k=min(4, len(noise_profiles.BENIGN_EXTERNAL)))
        internal = [("tcp", servers["dc"]["ip"], 445, "System"),
                    ("tcp", servers["dc"]["ip"], 389, "lsass.exe"),
                    ("tcp", servers["file"]["ip"], 445, "System")]
        for proto, rip, rport, pname in internal:
            connections.append({
                "proto": proto, "local_ip": host["ip"],
                "local_port": rng.randrange(49700, 65000, 4),
                "remote_ip": rip, "remote_port": rport,
                "state": "ESTABLISHED", "process": pname,
            })
        for domain, ip, port in ext:
            connections.append({
                "proto": "tcp", "local_ip": host["ip"],
                "local_port": rng.randrange(49700, 65000, 4),
                "remote_ip": ip, "remote_port": port,
                "state": "ESTABLISHED",
                "process": rng.choice(["chrome.exe", "msedge.exe", "OUTLOOK.EXE", "svchost.exe"]),
            })
            dns.append({"query": domain, "record_type": "A",
                        "timestamp": base_time_iso})
        for domain, rtype in rng.sample(noise_profiles.BENIGN_DNS_EXTRA, k=4):
            dns.append({"query": domain, "record_type": rtype,
                        "timestamp": base_time_iso})
    else:
        for domain, ip, port in noise_profiles.BENIGN_EXTERNAL[-2:]:
            connections.append({
                "proto": "tcp", "local_ip": host["ip"],
                "local_port": rng.randrange(49700, 65000, 4),
                "remote_ip": ip, "remote_port": port,
                "state": "ESTABLISHED", "process": "svchost.exe",
            })
            dns.append({"query": domain, "record_type": "A",
                        "timestamp": base_time_iso})

    return {
        "host_id": host["id"], "hostname": host["hostname"], "ip": host["ip"],
        "role": role, "os": host["os"], "desc": host.get("desc", ""),
        "appliance": False,
        "owner": ({"username": owner["username"], "domain": owner["domain"]}
                  if owner else None),
        "processes": processes, "services": services, "users": users,
        "autoruns": autoruns,
        "network": {"connections": connections, "dns": dns},
        "_scenario_ids": [], "_pid_locks": {},
    }


# --- attack merge ----------------------------------------------------------------

def _find_singleton(snapshot, name):
    hits = [p for p in snapshot["processes"] if p["name"].lower() == name.lower()]
    return hits[0] if len(hits) == 1 else None


def _ensure_process(snapshot, pid, name, path, cmdline, user, signer):
    """Add or pin a process node at an authored PID. Returns the node."""
    for p in snapshot["processes"]:
        if p["pid"] == pid:
            return p
    node = {"pid": pid, "ppid": 0, "parent_name": "-", "name": name,
            "path": path, "cmdline": cmdline or path, "user": user or "-",
            "signer": signer, "signed": bool(signer)}
    snapshot["processes"].append(node)
    return node


def _merge_process_create(snapshot, log):
    kvp = log.get("key_value_pairs") or {}
    pid = int(str(kvp.get("process_id", "0")) or 0)
    ppid = int(str(kvp.get("parent_process_id", "0")) or 0)
    image = kvp.get("image", "")
    name = os.path.basename(image) or image
    company = (kvp.get("company") or "").strip()
    signer = company if company and company != "-" else None

    # parent first: pin a singleton baseline image to the authored PID, or
    # materialize the authored parent node
    parent_image = kvp.get("parent_image", "")
    parent_name = os.path.basename(parent_image) or "-"
    parent_node = None
    if ppid:
        parent_node = next((p for p in snapshot["processes"] if p["pid"] == ppid), None)
        if parent_node is None:
            singleton = _find_singleton(snapshot, parent_name)
            locked = snapshot["_pid_locks"].get(parent_name.lower())
            if singleton is not None and locked is None:
                singleton["pid"] = ppid
                snapshot["_pid_locks"][parent_name.lower()] = ppid
                for child in snapshot["processes"]:
                    if child.get("parent_name") == singleton["name"] and child is not singleton:
                        child["ppid"] = ppid
                parent_node = singleton
            else:
                parent_node = _ensure_process(
                    snapshot, ppid, parent_name, parent_image,
                    kvp.get("parent_command_line", parent_image),
                    kvp.get("parent_user", "-"),
                    "Microsoft Windows" if parent_image.lower().startswith("c:\\windows\\") else None,
                )

    node = _ensure_process(snapshot, pid, name, image,
                           kvp.get("command_line", image),
                           kvp.get("user", log.get("user_account", "-")), signer)
    node["ppid"] = ppid
    node["parent_name"] = parent_name if ppid else "-"
    snapshot["processes"].sort(key=lambda n: n["pid"])


def _merge_network(snapshot, log):
    kvp = log.get("key_value_pairs") or {}
    dst_ip = kvp.get("destination_ip") or kvp.get("dst_ip") or log.get("destination_ip")
    if not dst_ip:
        return
    port = kvp.get("destination_port") or kvp.get("dest_port")
    proto = (kvp.get("protocol") or kvp.get("transport") or "tcp").lower()
    image = kvp.get("image", "")
    local_port = kvp.get("src_port") or kvp.get("source_port")
    snapshot["network"]["connections"].append({
        "proto": proto, "local_ip": log.get("source_ip", snapshot["ip"]),
        "local_port": int(local_port) if str(local_port or "").isdigit() else None,
        "remote_ip": dst_ip,
        "remote_port": int(port) if str(port or "").isdigit() else None,
        "state": "ESTABLISHED",
        "process": os.path.basename(image) if image else "-",
    })


def _merge_dns(snapshot, log):
    kvp = log.get("key_value_pairs") or {}
    query = kvp.get("query")
    if query:
        snapshot["network"]["dns"].append({
            "query": query,
            "record_type": kvp.get("query_type", "A"),
            "timestamp": log.get("timestamp"),
        })


def _merge_logon(snapshot, log):
    kvp = log.get("key_value_pairs") or {}
    if str(kvp.get("event_id")) != "4624":
        return
    username = kvp.get("account_name")
    domain = kvp.get("account_domain", "-")
    if not username or username in ("-", "SYSTEM"):
        return
    for u in snapshot["users"]:
        if u["username"].lower() == username.lower() and u["domain"] == domain:
            u["last_logon"] = log.get("timestamp")
            u["logon_type"] = kvp.get("logon_type")
            return
    snapshot["users"].append({
        "username": username, "domain": domain, "type": "Domain",
        "enabled": True, "description": "Domain user (network logon)",
        "last_logon": log.get("timestamp"), "logon_type": kvp.get("logon_type"),
    })


def _merge_autorun(snapshot, log):
    kvp = log.get("key_value_pairs") or {}
    target = kvp.get("target_object", "")
    if not RUN_KEY_RE.search(target):
        return
    location, _, name = target.rpartition("\\")
    snapshot["autoruns"].append({
        "location": location, "name": name,
        "command": kvp.get("details", ""),
    })


def merge_events(snapshot, tagged_events):
    """Merge one scenario's events for this host into its snapshot.
    tagged_events: [(rendered_log, meta)] where meta is the step's attack_meta."""
    for log, _meta in tagged_events:
        etype = log.get("event_type", "")
        source = log.get("source_type", "")
        kvp = log.get("key_value_pairs") or {}
        if source == "Sysmon" and str(kvp.get("event_id")) == "1":
            _merge_process_create(snapshot, log)
        elif source == "Sysmon" and str(kvp.get("event_id")) == "3":
            _merge_network(snapshot, log)
        elif source == "Sysmon" and str(kvp.get("event_id")) == "13":
            _merge_autorun(snapshot, log)
        elif source == "DNS" and etype == "QUERY":
            _merge_dns(snapshot, log)
        elif source == "Firewall" and etype == "ALLOW":
            _merge_network(snapshot, log)
        elif source == "Proxy" and (etype.startswith("HTTP_") or etype.startswith("SSL_")):
            _merge_network(snapshot, log)
        elif source == "Windows Security":
            _merge_logon(snapshot, log)


# --- world assembly -----------------------------------------------------------------

def extend_world(world, scenario, concrete_env, rendered_logs, session_seed,
                 reserved_pids, servers):
    """Fold one dripped scenario into the session world (caller holds the
    session lock). Baselines are built once per host and kept; attack
    artifacts merge on top. Returns the hostnames touched."""
    hosts_by_id = {h["id"]: h for h in concrete_env["hosts"]}
    accounts = concrete_env.get("accounts", [])
    meta = scenario["attack_meta"]
    base_time = rendered_logs[0].get("timestamp") if rendered_logs else None

    touched = []
    for host_id, host in hosts_by_id.items():
        hostname = host["hostname"]
        if hostname not in world["hosts"]:
            owner = next((a for a in accounts if a.get("host") == host_id), None)
            world["hosts"][hostname] = build_baseline(
                host, owner, session_seed, reserved_pids, servers, base_time)
        touched.append(hostname)

    per_host = {}
    for log, m in zip(rendered_logs, meta):
        host = hosts_by_id.get(m["host"])
        if host is None:
            continue
        per_host.setdefault(host["hostname"], []).append((log, m))

    scenario_id = rendered_logs[0].get("scenario_id") if rendered_logs else None
    for hostname, tagged in per_host.items():
        snapshot = world["hosts"][hostname]
        merge_events(snapshot, tagged)
        if scenario_id and scenario_id not in snapshot["_scenario_ids"]:
            snapshot["_scenario_ids"].append(scenario_id)

    return touched


def public_view(snapshot):
    """The API-facing snapshot: internal bookkeeping stripped."""
    return {k: v for k, v in snapshot.items() if not k.startswith("_")}
