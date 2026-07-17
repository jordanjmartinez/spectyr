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
    kill (host, pid)   process row removed from live Processes; its live
                       network connections and DNS attributions removed;
                       children it leaves behind are marked parent_exited
                       (orphaned, the established dangling-parent
                       convention); a service whose binary's only live
                       process was the killed one shows Stopped
                       (svchost.exe is exempt: shared host process).
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
        base_names = {p["name"].lower() for p in view["processes"]}
        live = [p for p in view["processes"] if p["pid"] not in killed]
        for p in live:
            if p.get("ppid") in killed:
                # orphaned by a response action: same marked-dangling
                # convention as exited parents, so lineage never dangles
                p["parent_exited"] = True
        view["processes"] = live
        live_names = {p["name"].lower() for p in live}
        for svc in view["services"]:
            bname = _basename(extract_image_path(svc.get("path") or "") or "").lower()
            if bname and bname != "svchost.exe":
                if bname in base_names and bname not in live_names:
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
