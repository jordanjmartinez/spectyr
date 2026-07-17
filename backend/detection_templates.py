"""Detection feed helpers (Phase 2 Stage 2).

Two detection sources feed the session:

  scenario detections   authored per scenario in the v2 catalog
                        (migrate_v1_to_v2.DETECTIONS). One per scenario:
                        true_positive for attacks, false_positive for the
                        FP scenarios. Materialized when the scenario drips.

  ambient benign        benign_expected detections generated per managed host
                        from BENIGN_DETECTIONS below (software updaters,
                        backup agents, admin tooling), so the feed always
                        carries benign-but-suspicious entries to dismiss or
                        leave open. Stable-key generated when a host baseline
                        is first built.

Leak discipline (ratified): `disposition` is a server-side answer key. The API
serializes every detection through `sanitize_detection`, which drops the
disposition and scenario linkage and runs each triggering event through the
same field whitelist the SIEM JSON view uses. Disposition, answer-key, and
scoring fields never reach the client. Proven by test_detections_leak_guard.

Realism bar: benign templates are plausible per host role. The set is
intentionally small and flagged in FLAGS; expand only from real product
behavior, same bar as noise_profiles.
"""
import hashlib

FLAGS = [
    "Benign detection templates (BENIGN_DETECTIONS) cover a minimal set of "
    "common benign_expected triggers: software updaters, backup agents, admin "
    "tooling. Stub, flagged; expand only from real product behavior.",
    "Ambient benign detections carry a synthesized minimal triggering event "
    "(process name + path + user), not a full Sysmon record. Enough for the "
    "feed and a reduced detail card; not a full endpoint telemetry event.",
]

# All rule text here is ORIGINAL (no SigmaHQ content). See ENVIRONMENT_REPORT.md
# Stage 2 license note.
# Each: (key, rule_name, severity, roles, image, process_name, description)
BENIGN_DETECTIONS = [
    ("chrome_updater", "Software Updater Outbound Connection", "medium",
     ("workstation",),
     "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", "GoogleUpdate.exe",
     "Periodic outbound connection from the Google Update service checking for "
     "browser updates. Expected on managed workstations."),
    ("edge_updater", "Microsoft Edge Update Service Beacon", "medium",
     ("workstation",),
     "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
     "MicrosoftEdgeUpdate.exe",
     "Scheduled Edge update check reaching Microsoft update endpoints. "
     "Routine background activity."),
    ("backup_agent", "Backup Agent Periodic Beacon", "medium",
     ("workstation", "file", "backup"),
     "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\Veeam.EndPoint.Service.exe",
     "Veeam.EndPoint.Service.exe",
     "Regular outbound from the endpoint backup agent to the backup server on "
     "the backup port. Expected during backup windows."),
    ("admin_psexec", "Remote Admin Tool Service Install", "medium",
     ("file", "dc", "web"),
     "C:\\Windows\\PSEXESVC.exe", "PSEXESVC.exe",
     "PsExec service installed by an administrator for remote management. "
     "Common in IT operations; benign when tied to a named admin and a change "
     "record."),
    ("patch_scan", "Vulnerability Scanner Authenticated Sweep", "medium",
     ("workstation", "file", "web"),
     "C:\\Program Files\\Tenable\\Nessus Agent\\nessusd.exe", "nessusd.exe",
     "Authenticated vulnerability-scanner sweep from the security team's "
     "scanning host. Expected on scan days."),
]


def _digest(*parts):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()


def _stable_int(lo, hi, *parts):
    return lo + int.from_bytes(_digest(*parts)[:8], "big") % (hi - lo + 1)


def _det_id(*parts):
    return "det-" + _digest(*parts).hex()[:12]


def _stable_sha256(*parts):
    """A fictional but stable SHA256 for a file, for the detail card. Spectyr
    hashes are fictional by design (no VirusTotal lookup); deterministic per
    (session, file)."""
    return _digest(*parts).hex()


def _evidence_sha256(session_seed, event):
    """SHA256 for the triggering file, when the event names a process image."""
    image = (event.get("key_value_pairs") or {}).get("image")
    return _stable_sha256(session_seed, image) if image else None


# --- scenario detections ------------------------------------------------------

# Sensor sources report on behalf of the traffic origin, so the detection
# entity is the source host (by source_ip), not the reporting device.
_SENSOR_SOURCES = {"Firewall", "Proxy", "DNS"}


def build_scenario_detections(scenario_id, catalog_entry, rendered_logs,
                              session_seed, supplemental_logs=None,
                              supplemental_meta=None, concrete_env=None):
    """Materialize a scenario's authored detections into session instances.

    Each authored detection fires on attack step id(s) and/or supplemental
    event id(s); the matching rendered log(s) are attached for the detail
    card. Entity is the actor host (resolved from source_ip for sensor
    events), and time comes from the first trigger event. The answer-key
    disposition is carried server-side.
    """
    id_to_log = {}
    for m, log in zip(catalog_entry.get("attack_meta", []), rendered_logs):
        id_to_log[m["id"]] = log
    for m, log in zip(supplemental_meta or [], supplemental_logs or []):
        id_to_log[m["id"]] = log

    ip_to_host = {}
    if concrete_env:
        for h in concrete_env.get("hosts", []):
            if h.get("ip"):
                ip_to_host[h["ip"]] = h["hostname"]

    def entity_host(log):
        # sensor events (firewall/proxy/dns) report on behalf of the source
        if log.get("source_type") in _SENSOR_SOURCES:
            src = log.get("source_ip")
            if src in ip_to_host:
                return ip_to_host[src]
        return log.get("hostname")

    out = []
    for det in catalog_entry.get("detections", []):
        trig_logs = [id_to_log[t] for t in det["triggers"] if t in id_to_log]
        if not trig_logs:
            continue
        first = trig_logs[0]
        kvp = first.get("key_value_pairs") or {}
        account = (first.get("user_account") or kvp.get("account_name") or "")
        account = account.split("\\")[-1] if account and account != "-" else None
        instance = {
            "id": _det_id(session_seed, scenario_id, det["id"]),
            "scenario_id": scenario_id,          # server-side linkage
            "detection_key": det["id"],
            "rule_name": det["rule_name"],
            "rule_type": det["rule_type"],
            "severity": det["severity"],
            "mitre": det.get("mitre"),
            "yara_rule_name": det.get("yara_rule_name"),
            "description": det["description"],
            "entity": {"host": entity_host(first), "account": account},
            "time": first.get("timestamp"),
            "triggering_events": trig_logs,
            "sha256": _evidence_sha256(session_seed, first),  # fictional, evidence
            "disposition": det["disposition"],   # answer key, server-side
            "player_action": "open",
        }
        out.append(instance)
    return out


# --- ambient benign detections ------------------------------------------------

def benign_detections_for_host(host, owner, session_seed, base_time_iso):
    """0-2 benign_expected detections for a host, stable-key selected by role.

    Managed Windows hosts only (callers already exclude PAN-OS devices).
    Deterministic per (session, host); order-independent.
    """
    role = host["role"]
    hostname = host["hostname"]
    eligible = [t for t in BENIGN_DETECTIONS if role in t[3]]
    if not eligible:
        return []
    # Workstations always carry at least one ambient benign detection (every
    # managed workstation runs an updater), so all-TP scenarios on a
    # workstation always have discoverable dismissables in the feed. Servers
    # get 0-2.
    lo = 1 if role == "workstation" else 0
    count = _stable_int(lo, min(2, len(eligible)), session_seed, hostname, "benign_n")
    if count == 0:
        return []
    ranked = sorted(eligible, key=lambda t: _digest(session_seed, hostname, t[0]))
    owner_user = owner["username"] if owner else "SYSTEM"
    out = []
    for key, rule_name, severity, roles, image, pname, desc in ranked[:count]:
        # a minimal synthetic triggering event (flagged: not a full Sysmon record)
        synth = {
            "event_type": "ProcessCreate",
            "source_type": "Sysmon",
            "severity": severity,
            "hostname": hostname,
            "source_ip": host["ip"],
            "user_account": owner_user,
            "message": f"Process observed: {pname}",
            "timestamp": base_time_iso,
            "key_value_pairs": {
                "image": image,
                "process_id": str(4 * _stable_int(400, 3000, session_seed, hostname, key, "pid")),
                "user": owner_user,
                "company": "Google LLC" if "Google" in image else (
                    "Microsoft Corporation" if "Microsoft" in image else
                    "Veeam Software Group GmbH" if "Veeam" in image else "-"),
            },
        }
        out.append({
            "id": _det_id(session_seed, hostname, key),
            "scenario_id": None,
            "detection_key": key,
            "rule_name": rule_name,
            "rule_type": "sigma_behavioral",
            "severity": severity,
            "mitre": None,
            "yara_rule_name": None,
            "description": desc,
            "entity": {"host": hostname, "account": owner_user if owner else None},
            "time": base_time_iso,
            "triggering_events": [synth],
            "sha256": _evidence_sha256(session_seed, synth),
            "disposition": "benign_expected",    # answer key, server-side
            "player_action": "open",
        })
    return out


# --- leak-safe serialization --------------------------------------------------

# The raw-log fields a real SIEM would store; everything else (scenario wiring,
# category, analyst state) is stripped, mirroring the frontend sanitizeEvent.
EVENT_WHITELIST = (
    "timestamp", "event_type", "source_type", "severity", "hostname",
    "source_ip", "destination_ip", "user_account", "message", "key_value_pairs",
)


def sanitize_event(log):
    return {k: log[k] for k in EVENT_WHITELIST
            if log.get(k) not in (None, "")}


def sanitize_detection(instance, include_events=False):
    """Client-safe detection. Drops disposition and scenario linkage; runs
    triggering events through the field whitelist. `include_events` adds the
    sanitized triggering events for the detail view."""
    out = {
        "id": instance["id"],
        "rule_name": instance["rule_name"],
        "rule_type": instance["rule_type"],
        "severity": instance["severity"],
        "mitre": instance["mitre"],
        "yara_rule_name": instance["yara_rule_name"],
        "description": instance["description"],
        "entity": instance["entity"],
        "time": instance["time"],
        "sha256": instance.get("sha256"),
        "player_action": instance["player_action"],
    }
    if include_events:
        out["triggering_events"] = [sanitize_event(e)
                                    for e in instance["triggering_events"]]
    return out
