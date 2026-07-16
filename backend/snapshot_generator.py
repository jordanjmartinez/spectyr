"""Endpoint snapshot generator (Phase 2 Stage 1).

Builds one world state per session: a dict of per-host EDR-style snapshots
(processes, network, services, users, autoruns, system info) derived from

    environment   the scenario's substituted environment block
    event pool    the scenario's rendered (substituted) attack logs, each
                  positionally paired with its attack_meta actor tag
    noise         role profiles from noise_profiles.py

Rules the rest of the pivot depends on:

- Managed endpoint scope. Only Windows hosts get snapshots. PAN-OS devices
  (the firewall, and the proxy per the Stage 1 review ruling) are log
  sources, not managed endpoints: they stay in the environment and in
  network events but never enter the world.
- Pure derivation. Every tab is a view over (baseline + event pool). There
  are no per-tab generators and nothing regenerates on read.
- Stable-key determinism. Every generated value (PIDs, MAC, sensor id,
  timestamps, memory) derives from sha256 over stable keys such as
  (session_seed, hostname, identity, field), never from draw order.
  Reordering hosts, profile entries, or scenarios cannot change a
  previously generated value. The module-level random is never touched, so
  chain rendering parity is unaffected.
- Frozen session time. All timestamps derive from the session's frozen
  start timestamp plus stable offsets. Nothing reads the wall clock.
- Lineage. Attack processes keep their authored PIDs/PPIDs. Authored
  parents are materialized (singleton baseline images re-pinned; absent
  parents like cmd.exe created from the authored parent_* fields). Every
  authored PID in the catalog is reserved so noise can never collide.
  Every network/DNS row's PID resolves to a process in the same snapshot.
  The one deliberately dangling PPID is explorer.exe's parent, marked
  parent_exited: userinit.exe really does exit after spawning it.
- Host status is scenario-declared (environment host `status`, default
  online), never generated. Only derived timestamps use the seed.
- No answer leakage. Snapshots carry no scenario or attack/benign markers;
  internal fields start with "_" and public_view strips them.

Windows PIDs are multiples of 4, so generated PIDs are too. Boot-order
strata keep parents below children without draw-order dependence.
"""
import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta

import noise_profiles

RUN_KEY_RE = re.compile(r"\\CurrentVersion\\Run\\", re.IGNORECASE)

AGENT_NAME = "spectyr-agent"
AGENT_VERSION = "1.0.0"

# PAN-OS log sources: in the environment, in events, never endpoints.
NON_ENDPOINT_ROLES = {"firewall", "proxy"}

# Boot strata: PID ranges per process tier so lineage reads naturally
# (parents low, children higher) while every PID is still stable-key derived.
_BOOT = {"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
         "services.exe", "lsass.exe", "fontdrvhost.exe"}
_STRATA = {"boot": (300, 900), "service": (900, 3600), "user": (3600, 16000)}


def _digest(*parts):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()


def _stable_int(lo, hi, *parts):
    """Deterministic int in [lo, hi] from stable key parts (inclusive)."""
    return lo + int.from_bytes(_digest(*parts)[:8], "big") % (hi - lo + 1)


def _stable_mac(session_seed, hostname):
    """VMware manual-assignment MAC (00:50:56:00..3F:xx:xx), stable per host."""
    d = _digest(session_seed, hostname, "mac")
    return "00:50:56:%02X:%02X:%02X" % (d[0] & 0x3F, d[1], d[2])


def _stable_uuid(session_seed, hostname):
    d = bytearray(_digest(session_seed, hostname, "sensor_id")[:16])
    d[6] = (d[6] & 0x0F) | 0x40  # version 4
    d[8] = (d[8] & 0x3F) | 0x80  # RFC 4122 variant
    return str(uuid.UUID(bytes=bytes(d)))


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def _parse_iso(ts):
    return datetime.fromisoformat(ts)


def collect_reserved_pids(catalog):
    """Every process_id / parent_process_id authored anywhere in the catalog.
    Reserved so generated PIDs can never collide with a chain."""
    reserved = set()
    for sc in catalog.values():
        for step in sc["chain"]:
            kvp = step.get("key_value_pairs") or {}
            for key in ("process_id", "parent_process_id"):
                val = str(kvp.get(key, ""))
                if val.isdigit():
                    reserved.add(int(val))
    return reserved


def resolve_egress_ip(session_seed):
    """The org's shared egress address. No scenario chain declares an org
    egress address (source IPs are internal; external addresses are attacker
    or destination infrastructure), so one RFC 5737 TEST-NET-3 address is
    generated per session. 203.0.113.50 is excluded: normal-traffic templates
    use it as an inbound scanner. Recorded in ENVIRONMENT_REPORT.md."""
    host_part = _stable_int(10, 250, session_seed, "org_egress_ip")
    if host_part == 50:
        host_part = 51
    return f"203.0.113.{host_part}"


# --- baseline ------------------------------------------------------------------

def _memory_mb(session_seed, hostname, name, cmdline, idx):
    heavy = {"MsMpEng.exe": (120, 260), "chrome.exe": (90, 380),
             "msedge.exe": (90, 300), "OUTLOOK.EXE": (150, 400),
             "explorer.exe": (80, 220), "SearchIndexer.exe": (40, 140),
             "Microsoft.ActiveDirectory.WebServices.exe": (60, 160),
             "Veeam.Backup.Service.exe": (90, 240), "dns.exe": (40, 120),
             "lsass.exe": (30, 90), "w3wp.exe": (60, 200),
             "slack.exe": (80, 260), "Zoom.exe": (70, 220),
             "OneDrive.exe": (40, 140), "dwm.exe": (30, 120)}
    lo, hi = heavy.get(name, (4, 60))
    return _stable_int(lo, hi, session_seed, hostname, name, cmdline, idx, "mem")


def _assign_pid(used, reserved, lo, hi, *key_parts):
    """Stable-key PID: hash-derived base, ascending multiple-of-4 probe.
    Assignment iterates a canonically sorted spec list, so the outcome does
    not depend on profile declaration order."""
    span = (hi - lo) // 4
    base = lo + 4 * _stable_int(0, span - 1, *key_parts)
    pid = base
    while pid in used or pid in reserved:
        pid += 4
        if pid > hi:
            pid = lo
        if pid == base:
            raise RuntimeError("PID range exhausted")
    used.add(pid)
    return pid


def _stratum(spec):
    if spec["name"] in _BOOT:
        return "boot"
    if spec["parent"] in ("services.exe", "wininit.exe", "winlogon.exe", "smss.exe"):
        return "service"
    return "user"


def build_baseline(host, owner, session_seed, reserved_pids, servers,
                   session_started_at):
    """Benign snapshot for one Windows host. `owner` is the substituted
    owning account dict or None; `servers` is app.SERVERS for internal noise
    targets; `session_started_at` is the frozen session ISO timestamp."""
    role = host["role"]
    hostname = host["hostname"]
    status = host.get("status", "online")
    started = _parse_iso(session_started_at)

    owner_user = f"{owner['domain']}\\{owner['username']}" if owner else None
    owner_name = owner["username"] if owner else None

    # Defender platform version: stable-key pick from the documented set
    # (session_seed + hostname + field_name), never draw order.
    defender_ver = noise_profiles.DEFENDER_PLATFORM_VERSIONS[
        _stable_int(0, len(noise_profiles.DEFENDER_PLATFORM_VERSIONS) - 1,
                    session_seed, hostname, "defender_platform")]

    def sub(text):
        if not isinstance(text, str):
            return text
        out = text.replace("__HOSTNAME__", hostname)
        out = out.replace("__DEFENDERVER__", defender_ver)
        if owner_name:
            out = out.replace("__OWNERNAME__", owner_name)
        if owner_user:
            out = out.replace(noise_profiles.OWNER, owner_user)
        return out

    # --- processes: canonical order, stable-key PIDs, boot strata ---
    expanded = []
    for spec in noise_profiles.processes_for_role(role):
        if owner_name is None and spec["user"] == noise_profiles.OWNER:
            continue  # no interactive session on an ownerless host
        for idx in range(spec.get("dup", 1)):
            expanded.append((spec, idx))
    expanded.sort(key=lambda t: (t[0]["name"], t[0]["cmdline"], t[1]))

    used = set()
    nodes = []
    for spec, idx in expanded:
        if spec["name"] in ("System", "Registry"):
            pid = 4 if spec["name"] == "System" else _assign_pid(
                used, reserved_pids, 68, 296, session_seed, hostname,
                spec["name"], idx, "pid")
            used.add(pid)
        else:
            lo, hi = _STRATA[_stratum(spec)]
            pid = _assign_pid(used, reserved_pids, lo, hi, session_seed,
                              hostname, spec["name"], spec["cmdline"], idx, "pid")
        nodes.append({
            "pid": pid,
            "name": spec["name"],
            "path": sub(spec["path"]),
            "cmdline": sub(spec["cmdline"]),
            "user": sub(spec["user"]),
            "signer": spec["signer"],
            "signed": spec["signer"] is not None,
            "memory_mb": _memory_mb(session_seed, hostname, spec["name"],
                                    spec["cmdline"], idx),
            "_spec_parent": spec["parent"],
        })

    by_name = {}
    for node in nodes:
        by_name.setdefault(node["name"], []).append(node)
    for node in nodes:
        pname = node.pop("_spec_parent")
        if pname == "" or node["name"] == "System":
            node["ppid"] = 0
            node["parent_name"] = "-"
        elif pname == "<exited>":
            # userinit.exe spawns explorer and exits: deliberately dangling,
            # marked so integrity checks can except it.
            phantom = node["pid"] - 4 * _stable_int(
                1, 6, session_seed, hostname, node["name"], "phantom")
            while phantom in used or phantom in reserved_pids or phantom <= 4:
                phantom -= 4
                if phantom <= 4:
                    phantom = node["pid"] + 4
                    while phantom in used or phantom in reserved_pids:
                        phantom += 4
                    break
            used.add(phantom)
            node["ppid"] = phantom
            node["parent_name"] = "userinit.exe"
            node["parent_exited"] = True
        elif pname in by_name:
            parent = by_name[pname][0]
            node["ppid"] = parent["pid"]
            node["parent_name"] = parent["name"]
        else:
            node["ppid"] = 0
            node["parent_name"] = pname
    nodes.sort(key=lambda n: (n["pid"], n["name"]))

    def pid_of(name, cmdline_part=None):
        for n in nodes:
            if n["name"] == name and (cmdline_part is None or cmdline_part in n["cmdline"]):
                return n
        return None

    # --- services / users / autoruns ---
    services = [
        {k: sub(v) if isinstance(v, str) else v for k, v in svc.items()}
        for svc in noise_profiles.services_for_role(role)
    ]
    services.sort(key=lambda s: s["name"].lower())
    users = [
        {**{k: sub(v) if isinstance(v, str) else v for k, v in u.items()}}
        for u in noise_profiles.users_for_role(role)
    ]
    if owner:
        users.append({
            "username": owner["username"], "domain": owner["domain"],
            "type": "Domain", "enabled": True, "groups": ["Domain Users"],
            "description": "Assigned workstation user",
        })
    autoruns = [
        {**{k: sub(v) for k, v in a.items()}, "signer": a.get("_signer", "Microsoft Corporation")}
        for a in noise_profiles.autoruns_for_role(role)
    ]
    for a in autoruns:
        a.pop("_signer", None)

    # --- network: listeners + benign traffic, every row bound to a PID ---
    connections = []
    for proto, port, pname in noise_profiles.ROLE_LISTENING.get(role, []):
        node = pid_of(pname) or pid_of("svchost.exe")
        if pname == "System":
            node = pid_of("System")
        connections.append({
            "proto": proto, "local_ip": host["ip"], "local_port": port,
            "remote_ip": "-", "remote_port": None, "state": "LISTENING",
            "process": pname, "pid": node["pid"] if node else 4,
        })

    dns = []
    net_svchost = pid_of("svchost.exe", "-k NetworkService")

    def dns_ts(key):
        return _iso(started - timedelta(
            minutes=_stable_int(2, 180, session_seed, hostname, key, "dns_ts")))

    if role == "workstation":
        ext_pool = noise_profiles.BENIGN_EXTERNAL
        picks = sorted(range(len(ext_pool)),
                       key=lambda i: _digest(session_seed, hostname, "extpick", i))[:4]
        internal = [("tcp", servers["dc"]["ip"], 445, "System"),
                    ("tcp", servers["dc"]["ip"], 389, "lsass.exe"),
                    ("tcp", servers["file"]["ip"], 445, "System")]
        for proto, rip, rport, pname in internal:
            node = pid_of(pname)
            connections.append({
                "proto": proto, "local_ip": host["ip"],
                "local_port": 4 * _stable_int(12430, 16240, session_seed,
                                              hostname, rip, rport, "lport"),
                "remote_ip": rip, "remote_port": rport,
                "state": "ESTABLISHED", "process": pname,
                "pid": node["pid"] if node else 4,
            })
        browsers = [n for n in (pid_of("chrome.exe"), pid_of("msedge.exe"),
                                pid_of("OUTLOOK.EXE"), net_svchost) if n]
        for i in picks:
            domain, ip, port = ext_pool[i]
            node = browsers[_stable_int(0, len(browsers) - 1, session_seed,
                                        hostname, domain, "proc")] if browsers else None
            connections.append({
                "proto": "tcp", "local_ip": host["ip"],
                "local_port": 4 * _stable_int(12430, 16240, session_seed,
                                              hostname, domain, "lport"),
                "remote_ip": ip, "remote_port": port,
                "state": "ESTABLISHED",
                "process": node["name"] if node else "svchost.exe",
                "pid": node["pid"] if node else (net_svchost["pid"] if net_svchost else 4),
            })
            dns.append({"query": domain, "record_type": "A", "resolved": ip,
                        "process": "svchost.exe",
                        "pid": net_svchost["pid"] if net_svchost else 4,
                        "timestamp": dns_ts(domain)})
        extra_pool = noise_profiles.BENIGN_DNS_EXTRA
        extra_picks = sorted(range(len(extra_pool)),
                             key=lambda i: _digest(session_seed, hostname, "dnspick", i))[:4]
        for i in extra_picks:
            domain, rtype, resolved = extra_pool[i]
            if resolved == "__DC__":
                resolved = servers["dc"]["ip"]
            dns.append({"query": domain, "record_type": rtype,
                        "resolved": resolved, "process": "svchost.exe",
                        "pid": net_svchost["pid"] if net_svchost else 4,
                        "timestamp": dns_ts(domain)})
    else:
        for domain, ip, port in noise_profiles.BENIGN_EXTERNAL[-2:]:
            node = net_svchost or pid_of("svchost.exe")
            connections.append({
                "proto": "tcp", "local_ip": host["ip"],
                "local_port": 4 * _stable_int(12430, 16240, session_seed,
                                              hostname, domain, "lport"),
                "remote_ip": ip, "remote_port": port,
                "state": "ESTABLISHED", "process": "svchost.exe",
                "pid": node["pid"] if node else 4,
            })
            dns.append({"query": domain, "record_type": "A", "resolved": ip,
                        "process": "svchost.exe",
                        "pid": node["pid"] if node else 4,
                        "timestamp": dns_ts(domain)})

    # --- system information (all stable-key derived, frozen clock) ---
    first_seen = _iso(started - timedelta(
        days=_stable_int(21, 160, session_seed, hostname, "first_seen"),
        minutes=_stable_int(0, 1400, session_seed, hostname, "first_seen_min")))
    if status == "online":
        last_seen = session_started_at
    else:
        last_seen = _iso(started - timedelta(
            minutes=_stable_int(45, 2880, session_seed, hostname, "last_seen")))
    system = {
        "platform": "windows",
        "architecture": "x64",
        "internal_ip": host["ip"],
        "external_ip": resolve_egress_ip(session_seed),
        "mac_address": _stable_mac(session_seed, hostname),
        "sensor_id": _stable_uuid(session_seed, hostname),
        "agent": f"{AGENT_NAME} {AGENT_VERSION}",
        "agent_version": AGENT_VERSION,
        "first_seen": first_seen,
        "registered": first_seen,
        "last_heartbeat": last_seen,
    }

    return {
        "host_id": host["id"], "hostname": hostname, "ip": host["ip"],
        "role": role, "os": host["os"], "desc": host.get("desc", ""),
        "status": status, "isolation": "not_isolated",
        "owner": ({"username": owner["username"], "domain": owner["domain"]}
                  if owner else None),
        "system": system,
        "processes": nodes, "services": services, "users": users,
        "autoruns": autoruns,
        "network": {"connections": connections, "dns": dns},
        "_scenario_ids": [], "_pid_locks": {},
    }


# --- attack merge ----------------------------------------------------------------

def _find_singleton(snapshot, name):
    hits = [p for p in snapshot["processes"] if p["name"].lower() == name.lower()]
    return hits[0] if len(hits) == 1 else None


def _ensure_process(snapshot, pid, name, path, cmdline, user, signer, session_seed):
    """Add or return the process node at an authored PID."""
    for p in snapshot["processes"]:
        if p["pid"] == pid:
            return p
    node = {"pid": pid, "ppid": 0, "parent_name": "-", "name": name,
            "path": path, "cmdline": cmdline or path, "user": user or "-",
            "signer": signer, "signed": bool(signer),
            "memory_mb": _memory_mb(session_seed, snapshot["hostname"],
                                    name, cmdline or path, pid)}
    snapshot["processes"].append(node)
    return node


def _merge_process_create(snapshot, log, session_seed):
    kvp = log.get("key_value_pairs") or {}
    pid = int(str(kvp.get("process_id", "0")) or 0)
    ppid = int(str(kvp.get("parent_process_id", "0")) or 0)
    image = kvp.get("image", "")
    name = os.path.basename(image) or image
    company = (kvp.get("company") or "").strip()
    signer = company if company and company != "-" else None

    parent_image = kvp.get("parent_image", "")
    parent_name = os.path.basename(parent_image) or "-"
    if ppid:
        parent_node = next((p for p in snapshot["processes"] if p["pid"] == ppid), None)
        if parent_node is None:
            singleton = _find_singleton(snapshot, parent_name)
            locked = snapshot["_pid_locks"].get(parent_name.lower())
            if singleton is not None and locked is None:
                # re-pin the singleton baseline image to the authored PID
                singleton["pid"] = ppid
                snapshot["_pid_locks"][parent_name.lower()] = ppid
                for child in snapshot["processes"]:
                    if child.get("parent_name") == singleton["name"] and child is not singleton:
                        child["ppid"] = ppid
            else:
                _ensure_process(
                    snapshot, ppid, parent_name, parent_image,
                    kvp.get("parent_command_line", parent_image),
                    kvp.get("parent_user", "-"),
                    "Microsoft Windows" if parent_image.lower().startswith("c:\\windows\\") else None,
                    session_seed,
                )

    node = _ensure_process(snapshot, pid, name, image,
                           kvp.get("command_line", image),
                           kvp.get("user", log.get("user_account", "-")),
                           signer, session_seed)
    node["ppid"] = ppid
    node["parent_name"] = parent_name if ppid else "-"
    snapshot["processes"].sort(key=lambda n: (n["pid"], n["name"]))


def _merge_network(snapshot, log, session_seed):
    kvp = log.get("key_value_pairs") or {}
    dst_ip = kvp.get("destination_ip") or kvp.get("dst_ip") or log.get("destination_ip")
    if not dst_ip:
        return
    port = kvp.get("destination_port") or kvp.get("dest_port")
    proto = (kvp.get("protocol") or kvp.get("transport") or "tcp").lower()
    image = kvp.get("image", "")
    local_port = kvp.get("src_port") or kvp.get("source_port")

    pid = None
    raw_pid = str(kvp.get("process_id", ""))
    if raw_pid.isdigit():
        pid = int(raw_pid)
        _ensure_process(snapshot, pid, os.path.basename(image) or "-", image,
                        image, kvp.get("user", "-"), None, session_seed)
    snapshot["network"]["connections"].append({
        "proto": proto, "local_ip": log.get("source_ip", snapshot["ip"]),
        "local_port": int(local_port) if str(local_port or "").isdigit() else None,
        "remote_ip": dst_ip,
        "remote_port": int(port) if str(port or "").isdigit() else None,
        "state": "ESTABLISHED",
        "process": os.path.basename(image) if image else "-",
        "pid": pid,
    })


def _merge_dns(snapshot, log):
    kvp = log.get("key_value_pairs") or {}
    query = kvp.get("query")
    if query:
        snapshot["network"]["dns"].append({
            "query": query,
            "record_type": kvp.get("query_type", "A"),
            "resolved": "-", "process": "-", "pid": None,
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
    ts = log.get("timestamp")
    for u in snapshot["users"]:
        if u["username"].lower() == username.lower() and u["domain"] == domain:
            # keep the LATEST logon: realistic, and merge-order independent
            if ts and (not u.get("last_logon") or ts > u["last_logon"]):
                u["last_logon"] = ts
                u["logon_type"] = kvp.get("logon_type")
            return
    snapshot["users"].append({
        "username": username, "domain": domain, "type": "Domain",
        "enabled": True, "groups": ["Domain Users"],
        "description": "Domain user (network logon)",
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
        "command": kvp.get("details", ""), "signer": None,
    })


def merge_events(snapshot, tagged_events, session_seed):
    """Merge one scenario's events for this host into its snapshot.
    tagged_events: [(rendered_log, meta)] where meta is the step's attack_meta."""
    for log, _meta in tagged_events:
        etype = log.get("event_type", "")
        source = log.get("source_type", "")
        kvp = log.get("key_value_pairs") or {}
        if source == "Sysmon" and str(kvp.get("event_id")) == "1":
            _merge_process_create(snapshot, log, session_seed)
        elif source == "Sysmon" and str(kvp.get("event_id")) == "3":
            _merge_network(snapshot, log, session_seed)
        elif source == "Sysmon" and str(kvp.get("event_id")) == "13":
            _merge_autorun(snapshot, log)
        elif source == "DNS" and etype == "QUERY":
            _merge_dns(snapshot, log)
        elif source == "Firewall" and etype == "ALLOW":
            _merge_network(snapshot, log, session_seed)
        elif source == "Proxy" and (etype.startswith("HTTP_") or etype.startswith("SSL_")):
            _merge_network(snapshot, log, session_seed)
        elif source == "Windows Security":
            _merge_logon(snapshot, log)


def _sort_merged(snapshot):
    """Stable ordering after merges, so scenario arrival order never shows."""
    net = snapshot["network"]
    net["connections"].sort(key=lambda c: (
        c["state"], str(c["remote_ip"]), c["remote_port"] or 0,
        c["local_port"] or 0, c["proto"]))
    net["dns"].sort(key=lambda d: (d["query"], str(d.get("timestamp"))))
    snapshot["autoruns"].sort(key=lambda a: (a["location"], a["name"]))
    snapshot["users"].sort(key=lambda u: (u["domain"], u["username"].lower()))
    snapshot["processes"].sort(key=lambda n: (n["pid"], n["name"]))


# --- world assembly -----------------------------------------------------------------

def extend_world(world, scenario, concrete_env, rendered_logs, session_seed,
                 reserved_pids, servers):
    """Fold one dripped scenario into the session world (caller holds the
    session lock). Baselines build once per host and persist; attack
    artifacts merge on top. PAN-OS devices (firewall, proxy) are log
    sources, never endpoints. Returns the hostnames touched."""
    session_started_at = world.get("started_at") or (
        rendered_logs[0].get("timestamp") if rendered_logs else None)
    world.setdefault("org", concrete_env.get("org", {}))

    hosts_by_id = {h["id"]: h for h in concrete_env["hosts"]
                   if h["role"] not in NON_ENDPOINT_ROLES}
    accounts = concrete_env.get("accounts", [])

    touched = []
    for host_id, host in hosts_by_id.items():
        hostname = host["hostname"]
        if hostname not in world["hosts"]:
            owner = next((a for a in accounts if a.get("host") == host_id), None)
            world["hosts"][hostname] = build_baseline(
                host, owner, session_seed, reserved_pids, servers,
                session_started_at)
        touched.append(hostname)

    per_host = {}
    for log, m in zip(rendered_logs, scenario["attack_meta"]):
        host = hosts_by_id.get(m["host"])
        if host is None:
            continue  # actor is a non-endpoint (never the case today)
        per_host.setdefault(host["hostname"], []).append((log, m))

    scenario_id = rendered_logs[0].get("scenario_id") if rendered_logs else None
    for hostname, tagged in per_host.items():
        snapshot = world["hosts"][hostname]
        merge_events(snapshot, tagged, session_seed)
        _sort_merged(snapshot)
        if scenario_id and scenario_id not in snapshot["_scenario_ids"]:
            snapshot["_scenario_ids"].append(scenario_id)

    return touched


def public_view(snapshot):
    """The API-facing snapshot: internal bookkeeping stripped."""
    return {k: v for k, v in snapshot.items() if not k.startswith("_")}
