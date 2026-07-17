"""Response-action overlay (Phase 2 Stage 3a).

The session world built by snapshot_generator is IMMUTABLE once built:
response actions never mutate it or the event pool. Every action effect
lives in a session-local overlay, and current-state surfaces (endpoint
tabs, status badges, identity state) render base+overlay at serialization
time. Historical surfaces (SIEM events, detections, triggering-event
evidence, lineage) always render the immutable base: response changes the
present, never the record.

Rules this module owes the rest of the pivot:

- Client entity ids. Every actionable object (host, process, file,
  account) gets a session-local client id, stable-key derived (sha256 over
  session seed + kind + composite key), shape-uniform across kinds and
  origins (ent- + 12 hex, the id-normalization precedent). Raw composite
  keys never serialize; the registry resolves ids server-side.
- Composite targets. Processes are (hostname, pid); files are
  (hostname, normalized path). PIDs and paths are not unique corpus-wide,
  so neither is ever a key on its own. Accounts are (domain, username),
  lowercased; local accounts carry their host as the domain, so the same
  local username on two hosts is two entities.
- Deterministic registry. Rebuilt from the base world after each drip,
  under the session lock. Iteration is sorted, every id is stable-key
  derived, so drip order never changes an id or a registry entry.
- Cascade map (applied through the overlay, never to the base):
    kill (host, pid)   the live Processes tab does NOT retain a Terminated
                       row (killed = not running; historical rows belong to
                       base surfaces). Its live network connections and DNS
                       attributions go with it. Surviving children keep the
                       original PPID, marked parent_terminated (real-EDR
                       orphan rendering); that marker is the sanctioned
                       terminated-parent PPID exception and the integrity
                       suite accepts it ONLY when the PPID is genuinely in
                       the overlay's killed set. A service whose backing
                       process is gone shows Stopped; svchost services
                       match on the -k group, so one killed instance stops
                       only its own group's services.
    isolate host       live non-listening connections severed; isolation
                       badge everywhere the host renders. Release restores
                       by removing the overlay entry; the base was never
                       touched.
    delete (host,path) path removed from live file-bearing views (autorun
                       rows whose image resolves to the path). A running
                       process keeps its in-memory image reference: the
                       row is telemetry about how it started, not a file
                       view.
    identity actions   disabled / sessions_revoked / password_reset flags
                       render wherever the account appears in current
                       state (Users tab, entity chips). Simulated response
                       state only; no answer-key linkage.
"""
import copy
import hashlib
import re
from datetime import datetime, timedelta


ENTITY_ID_RE = re.compile(r"^ent-[0-9a-f]{12}$")

_EXE_PATH_RE = re.compile(r"[A-Za-z]:\\[^\"]*?\.exe", re.IGNORECASE)


def _digest(*parts):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()


def entity_id(session_seed, kind, *key_parts):
    """Stable-key client entity id, shape-uniform across kinds (ent- + 12 hex)."""
    return "ent-" + _digest(session_seed, "entity", kind, *key_parts).hex()[:12]


def _basename(path):
    return re.split(r"[\\/]", path)[-1] if path else ""


def norm_path(path):
    """Canonical form of a Windows file path for composite keys: quotes
    stripped, lowercased. Comparison key only; display keeps original case."""
    return (path or "").strip().strip('"').lower()


_SVC_GROUP_RE = re.compile(r"-k\s+(\S+)", re.IGNORECASE)


def _service_backing(svc_path):
    """(binary name, svchost -k group or None) identifying the process a
    Services row is backed by. Group-aware so killing one svchost instance
    only stops the services of that instance's -k group."""
    image = extract_image_path(svc_path) or ""
    name = _basename(image).lower()
    m = _SVC_GROUP_RE.search(svc_path)
    return name, (m.group(1).lower() if m else None)


def extract_image_path(command):
    """The executable path inside an autorun/service command line.
    Quoted -> the quoted span; else the first drive-letter .exe path."""
    if not command:
        return None
    s = command.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 1 else None
    m = _EXE_PATH_RE.search(s)
    if m:
        return m.group(0)
    first = s.split()[0] if s.split() else ""
    return first if "\\" in first else None


# --- overlay state -------------------------------------------------------------

def new_overlay():
    """Empty per-session action overlay. Guarded by the session io_lock."""
    return {
        "isolated": set(),       # hostnames currently isolated
        "killed": set(),         # (hostname, pid)
        "deleted_files": set(),  # (hostname, norm_path)
        "accounts": {},          # (domain_l, user_l) -> identity state dict
        "log": [],               # every attempt, append-only (Stage 3a.2)
        "seq": 0,
    }


def _identity_state():
    return {"disabled": False, "sessions_revoked": False, "password_reset": False}


def account_key(domain, username):
    return (str(domain or "").lower(), str(username or "").lower())


# --- entity registry -----------------------------------------------------------

def collect_env_accounts(env_accounts, concrete_env):
    """Fold a dripped scenario's concrete accounts into the session's
    account collection (domain-scope accounts; key -> display fields)."""
    for a in concrete_env.get("accounts", []):
        key = account_key(a.get("domain"), a.get("username"))
        if key not in env_accounts:
            env_accounts[key] = {"domain": a.get("domain", ""),
                                 "username": a.get("username", "")}


def build_entity_registry(world, env_accounts, session_seed):
    """Client id -> server-side entry for every actionable object in the
    base world. Pure derivation, sorted iteration: drip order and rebuild
    count never change an id or an entry."""
    reg = {}

    def put(kind, key_parts, entry):
        eid = entity_id(session_seed, kind, *key_parts)
        entry["kind"] = kind
        reg[eid] = entry
        return eid

    for hostname in sorted(world.get("hosts", {})):
        snap = world["hosts"][hostname]
        put("host", (hostname,), {"hostname": hostname})

        for p in sorted(snap["processes"], key=lambda p: (p["pid"], p["name"])):
            put("process", (hostname, p["pid"]),
                {"hostname": hostname, "pid": p["pid"], "name": p["name"]})

        files = {}
        for p in snap["processes"]:
            np = norm_path(p.get("path"))
            if np:
                files.setdefault(np, p["path"].strip().strip('"'))
        for a in snap["autoruns"]:
            image = extract_image_path(a.get("command") or "")
            np = norm_path(image)
            if np:
                files.setdefault(np, image)
        for np in sorted(files):
            put("file", (hostname, np),
                {"hostname": hostname, "path": np, "display": files[np]})

        for u in snap["users"]:
            dom, user = u.get("domain", ""), u["username"]
            key = account_key(dom, user)
            scope = "local" if str(dom).lower() == hostname.lower() else "domain"
            put("account", key,
                {"domain": dom, "username": user, "scope": scope})

    for key in sorted(env_accounts):
        disp = env_accounts[key]
        put("account", key,
            {"domain": disp["domain"], "username": disp["username"],
             "scope": "domain"})

    return reg


def resolve_account_key(account_str, registry):
    """Map a rendered account string (DOMAIN\\user, UPN, or bare username)
    to a registered account entity id, or None. UPN and bare forms resolve
    against domain-scope accounts only (a UPN never names a local SAM
    account); ambiguity resolves to None, never to a guess."""
    if not account_str:
        return None
    s = str(account_str).strip()
    if "\\" in s:
        dom, _, user = s.partition("\\")
        want = account_key(dom, user)
        for eid, e in registry.items():
            if e["kind"] == "account" and account_key(e["domain"], e["username"]) == want:
                return eid
        return None
    user = s.split("@", 1)[0].lower() if "@" in s else s.lower()
    hits = [eid for eid, e in registry.items()
            if e["kind"] == "account" and e["scope"] == "domain"
            and e["username"].lower() == user]
    return hits[0] if len(hits) == 1 else None


# --- overlay application -------------------------------------------------------

def apply_overlay(view, overlay):
    """Render one host's public snapshot as base+overlay. `view` must be a
    deep copy owned by the caller (the base world is never handed in);
    returns the same dict, adjusted. Historical surfaces never call this."""
    host = view["hostname"]
    isolated = host in overlay["isolated"]
    view["isolation"] = "isolated" if isolated else "not_isolated"

    killed = {pid for (h, pid) in overlay["killed"] if h == host}
    deleted = {p for (h, p) in overlay["deleted_files"] if h == host}

    if killed:
        base_processes = view["processes"]
        live = [p for p in base_processes if p["pid"] not in killed]
        for p in live:
            if p.get("ppid") in killed:
                # Orphaned by a response action: the PPID keeps rendering as
                # the original PID, annotated as terminated (real-EDR orphan
                # rendering). This marker is the SANCTIONED instance of the
                # terminated-parent PPID exception: the integrity suite
                # accepts it only when (host, ppid) really is in the
                # overlay's killed set, never for any other cause.
                p["parent_terminated"] = True
        view["processes"] = live
        for svc in view["services"]:
            name, group = _service_backing(svc.get("path") or "")
            if not name:
                continue

            def backs(proc):
                if proc["name"].lower() != name:
                    return False
                return group is None or group in (proc.get("cmdline") or "").lower()

            if any(backs(p) for p in base_processes) and not any(backs(p) for p in live):
                svc["status"] = "Stopped"
        view["network"]["connections"] = [
            c for c in view["network"]["connections"] if c.get("pid") not in killed]
        view["network"]["dns"] = [
            d for d in view["network"]["dns"] if d.get("pid") not in killed]

    if isolated:
        view["network"]["connections"] = [
            c for c in view["network"]["connections"] if c.get("state") == "LISTENING"]

    if deleted:
        view["autoruns"] = [
            a for a in view["autoruns"]
            if norm_path(extract_image_path(a.get("command") or "")) not in deleted]

    for u in view["users"]:
        state = overlay["accounts"].get(account_key(u.get("domain"), u["username"]))
        if state:
            u["identity_state"] = dict(state)
            if state["disabled"]:
                u["enabled"] = False

    return view


# --- action engine (Stage 3a.2) ------------------------------------------------

# Action name -> the entity kind its target must resolve to. The API rejects
# any id of another kind as a client error before the attempt exists.
ACTION_TARGET_KINDS = {
    "isolate_host": "host",
    "release_host": "host",
    "kill_process": "process",
    "delete_file": "file",
    "disable_account": "account",
    "revoke_sessions": "account",
    "force_password_reset": "account",
}

SUCCESS = "success"
NO_OP = "no_op"
FAILED = "failed_precondition"

# Identity action -> (state flag, no_op reason when already in target state)
_IDENTITY_ACTIONS = {
    "disable_account": ("disabled", "Account is already disabled."),
    "revoke_sessions": ("sessions_revoked",
                        "Sessions for this account are already revoked."),
    "force_password_reset": ("password_reset",
                             "A password reset has already been completed for this account."),
}


def _host_file_set(snap):
    """Every file path the base snapshot carries (process images plus
    autorun-borne executables), in composite-key form."""
    files = set()
    for p in snap["processes"]:
        np = norm_path(p.get("path"))
        if np:
            files.add(np)
    for a in snap["autoruns"]:
        np = norm_path(extract_image_path(a.get("command") or ""))
        if np:
            files.add(np)
    return files


def execute(world, overlay, entry, action):
    """One validated action attempt against the overlay (the base world is
    read, never written). Caller holds the session lock and has already
    resolved `entry` from the registry with the kind matched to `action`.
    Returns (outcome, reason); reason is the in-fiction explanation for
    no_op and failed_precondition outcomes, None on success.
    """
    if action in ("isolate_host", "release_host"):
        hostname = entry["hostname"]
        snap = world["hosts"].get(hostname)
        if action == "isolate_host":
            if snap is not None and snap.get("status") == "offline":
                return FAILED, ("Host is offline. The isolation command could "
                                "not be delivered to the endpoint agent.")
            if hostname in overlay["isolated"]:
                return NO_OP, "Host is already isolated."
            overlay["isolated"].add(hostname)
            return SUCCESS, None
        if hostname not in overlay["isolated"]:
            return FAILED, "Host is not isolated. There is nothing to release."
        overlay["isolated"].discard(hostname)
        return SUCCESS, None

    if action == "kill_process":
        hostname, pid = entry["hostname"], entry["pid"]
        if (hostname, pid) in overlay["killed"]:
            return NO_OP, "Process is already terminated."
        snap = world["hosts"].get(hostname)
        alive = snap is not None and any(
            p["pid"] == pid for p in snap["processes"])
        if not alive:
            return FAILED, (f"No running process with PID {pid} was found "
                            f"on {hostname}.")
        overlay["killed"].add((hostname, pid))
        return SUCCESS, None

    if action == "delete_file":
        hostname, path = entry["hostname"], entry["path"]
        if (hostname, path) in overlay["deleted_files"]:
            return NO_OP, "File is already deleted."
        snap = world["hosts"].get(hostname)
        if snap is None or path not in _host_file_set(snap):
            return FAILED, "File not found at the specified path."
        overlay["deleted_files"].add((hostname, path))
        return SUCCESS, None

    if action in _IDENTITY_ACTIONS:
        flag, already = _IDENTITY_ACTIONS[action]
        key = account_key(entry["domain"], entry["username"])
        state = overlay["accounts"].setdefault(key, _identity_state())
        if state[flag]:
            return NO_OP, already
        state[flag] = True
        return SUCCESS, None

    raise ValueError(f"unknown action {action!r}")  # route validates first


def target_label(entry):
    """Human display for an action target, composed of world-visible values
    only (the same values the endpoint and detection views already render)."""
    kind = entry["kind"]
    if kind == "host":
        return entry["hostname"]
    if kind == "process":
        return f"{entry['name']} (PID {entry['pid']}) on {entry['hostname']}"
    if kind == "file":
        return f"{entry['display']} on {entry['hostname']}"
    return f"{entry['domain']}\\{entry['username']}"


def record_attempt(overlay, started_at, action, target_id, entry, outcome, reason):
    """Append one attempt to the action log. Deterministic by construction:
    the logical timestamp is the frozen session clock plus the monotonic
    sequence number, never the wall clock, and the entry carries no random
    ids. Callers only reach this with a registry-validated target, and a
    non-empty registry implies the session world (and started_at) exists.
    """
    overlay["seq"] += 1
    ts = (datetime.fromisoformat(started_at)
          + timedelta(seconds=overlay["seq"])).replace(microsecond=0)
    log_entry = {
        "seq": overlay["seq"],
        "timestamp": ts.isoformat(),
        "action": action,
        "target": {"id": target_id, "kind": entry["kind"],
                   "label": target_label(entry)},
        "outcome": outcome,
        "reason": reason,
    }
    overlay["log"].append(log_entry)
    return log_entry


def sanitize_action_entry(log_entry):
    """Client-safe action log entry: the whitelist is the entire shape.
    Target serializes as id + kind + display label only; composite keys and
    registry internals never leave the server as machine-readable fields."""
    return {
        "seq": log_entry["seq"],
        "timestamp": log_entry["timestamp"],
        "action": log_entry["action"],
        "outcome": log_entry["outcome"],
        "reason": log_entry.get("reason"),
        "target": {"id": log_entry["target"]["id"],
                   "kind": log_entry["target"]["kind"],
                   "label": log_entry["target"]["label"]},
    }


def successful_executions(overlay, registry):
    """The scorer's view of the action log: successful entries only (the
    binding 3b rule: no_op and failed_precondition are score-neutral),
    each resolved to its server-side composite through the registry. Pure
    read; caller holds the session lock."""
    out = []
    for e in overlay["log"]:
        if e["outcome"] != SUCCESS:
            continue
        entry = registry.get(e["target"]["id"])
        if entry is None:
            continue  # registry always covers logged ids; guard for safety
        out.append({"seq": e["seq"], "action": e["action"], "target": entry})
    return out


def identity_state_for(overlay, domain, username):
    """The current identity state for an account, defaults when untouched.
    For rendering account chips wherever the account appears in current
    state."""
    state = overlay["accounts"].get(account_key(domain, username))
    return dict(state) if state else _identity_state()


def annotate_view(view, session_seed):
    """Attach client entity ids to a rendered (base+overlay) host view so
    the UI can address action targets. Ids only; composites never leave
    the server as machine-readable fields."""
    host = view["hostname"]
    view["entity_id"] = entity_id(session_seed, "host", host)
    for p in view.get("processes", []):
        p["entity_id"] = entity_id(session_seed, "process", host, p["pid"])
    for a in view.get("autoruns", []):
        image = extract_image_path(a.get("command") or "")
        np = norm_path(image)
        a["file_entity_id"] = entity_id(session_seed, "file", host, np) if np else None
    for u in view.get("users", []):
        dom, user = account_key(u.get("domain"), u["username"])
        u["entity_id"] = entity_id(session_seed, "account", dom, user)
    return view
