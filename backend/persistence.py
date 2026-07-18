"""Persistence-artifact identity and correlation (Phase 2 Stage 3c.5).

A persistence artifact is a first-class, actionable object: a WMI event
subscription or a registry Run-key value. This module derives their stable
identities and correlates the raw Sysmon events into logical artifacts.
snapshot_generator materializes them onto the Autoruns surface;
action_overlay applies the dual-flag state model; the remove_persistence
verb targets them.

Design rules (3c.5 review):
- WMI identity is the CORRELATED TRIPLE, never the consumer name alone:
  host + normalized namespace + filter path + consumer path + binding
  path. Consumer name is display only.
- Run-key identity is host + normalized registry key + value name, never
  the image path alone; two values sharing a payload path stay distinct.
- Normalize namespaces, object paths, registry keys, and value names
  before deriving stable ids.
- Duplicate Sysmon events for the same complete subscription deduplicate
  to ONE entity. Conflicting correlations FAIL CLOSED (no actionable
  entity), never produce multiple removable copies.
- Incomplete or ambiguous triples are not actionable.
"""
import hashlib
import re

_WS_RE = re.compile(r"\s+")
# WMI reference: ClassName.Property="Value" (WMI object path to a named instance)
_WMI_REF_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*'
                         r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*)"\s*$')


def _digest(*parts):
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).digest()


def artifact_id_key(*parts):
    """Stable-key parts for a persistence artifact's client entity id. The
    caller feeds these to the same entity_id derivation the other kinds
    use, so persistence ids are shape-uniform with host/process/file/
    account ids."""
    return ("persistence",) + tuple(parts)


# --- normalization -------------------------------------------------------------

def norm_namespace(ns):
    """WMI namespaces are case-insensitive with '\\' separators. root\\CimV2
    and ROOT/cimv2 normalize identically."""
    if not ns:
        return ""
    return _WS_RE.sub("", str(ns)).replace("/", "\\").lower()


def norm_wmi_path(path):
    """Normalize a WMI object-path reference ClassName.Prop="Value". Class
    and property names are case-insensitive (lowercased); the instance
    value is case-preserving (a consumer Name is its identity) but
    whitespace-trimmed. Non-conforming strings normalize by whitespace +
    lowercasing so malformed refs still compare deterministically."""
    if not path:
        return ""
    m = _WMI_REF_RE.match(str(path))
    if not m:
        return _WS_RE.sub("", str(path)).lower()
    cls, prop, val = m.group(1), m.group(2), m.group(3)
    return f'{cls.lower()}.{prop.lower()}="{val.strip()}"'


def norm_reg_key(key):
    """Normalize a registry key path: hive/separator/case folded. Value
    names are handled separately (see split_run_key)."""
    if not key:
        return ""
    return _WS_RE.sub("", str(key)).replace("/", "\\").rstrip("\\").lower()


def norm_value_name(name):
    """Registry value names are case-insensitive; whitespace-trim + fold."""
    return _WS_RE.sub("", str(name or "")).lower()


def wmi_consumer_name(path):
    """Display name from a WMI consumer/filter object path, or None."""
    m = _WMI_REF_RE.match(str(path or ""))
    return m.group(3).strip() if m else None


# --- authored selectors (answer-key references) --------------------------------

def parse_selector(selector):
    """Canonicalize an authored persistence selector to a hashable key.

    A selector is the answer-key REFERENCE to a persistence artifact, never
    its identity: `wmi:<ConsumerName>` (resolved against the correlated
    subscriptions, fail-closed on an ambiguous name) or
    `run_key:<KeyPath\\ValueName>` (the identity is fully determined by the
    normalized key + value). Returns ("wmi_subscription", name) /
    ("run_key", (nkey, nvalue)), or None if malformed."""
    s = str(selector or "")
    kind, sep, rest = s.partition(":")
    if not sep:
        return None
    kind = kind.strip().lower()
    if kind == "wmi":
        name = rest.strip()
        return ("wmi_subscription", name) if name else None
    if kind == "run_key":
        parts = split_run_key(rest)
        if parts is None:
            return None
        nkey, _value, nvalue = parts
        if not nvalue:
            return None
        return ("run_key", (nkey, nvalue))
    return None


def resolve_selector(selector, autorun_rows):
    """Resolve an authored selector to EXACTLY ONE materialized persistence
    artifact's identity among a host's autorun rows. Fail closed (None) on a
    malformed selector or zero/multiple matches: a WMI consumer name shared
    by two distinct subscriptions never resolves to a guess."""
    parsed = parse_selector(selector)
    if parsed is None:
        return None
    ptype, key = parsed
    hits = []
    for a in autorun_rows:
        if a.get("persist_type") != ptype or not a.get("identity"):
            continue
        ident = tuple(a["identity"])
        if ptype == "wmi_subscription":
            if a.get("name") == key:  # consumer display name
                hits.append(ident)
        elif ident[2:] == key:        # run_key: (host, "run_key", nkey, nvalue)
            hits.append(ident)
    return hits[0] if len(hits) == 1 else None


def authored_selectors(host, filters, consumers, bindings, run_keys):
    """The set of canonical selectors a host's OWN authored events express
    (seed-independent: chain + supplemental only). run_keys is a list of
    (nkey, nvalue). WMI selectors come from correlating the authored WMI
    events, so an incomplete/ambiguous authored subscription yields no
    actionable selector (matching the runtime materialization exactly)."""
    sels = {("run_key", rk) for rk in run_keys}
    for art in correlate_wmi(host, filters, consumers, bindings):
        sels.add(("wmi_subscription", art["entry"]))
    return sels


# --- run-key artifacts ---------------------------------------------------------

def split_run_key(target_object):
    """A Run-key SetValue target_object is `<key path>\\<value name>`. Return
    (normalized key, raw value name, normalized value name) or None."""
    s = str(target_object or "")
    if "\\" not in s:
        return None
    key, _, value = s.rpartition("\\")
    return norm_reg_key(key), value, norm_value_name(value)


def run_key_artifact(host, target_object, payload_path, command):
    """A registry Run-key persistence artifact from an event_id 13 Run-key
    SetValue. Identity: host + normalized key + normalized value name (never
    the payload path). Returns the artifact dict, or None if not a value."""
    parts = split_run_key(target_object)
    if parts is None:
        return None
    nkey, value_name, nvalue = parts
    identity = (host, "run_key", nkey, nvalue)
    return {
        "persist_type": "run_key",
        "host": host,
        "entry": value_name,
        "location": target_object.rpartition("\\")[0],
        "command": command or payload_path or "",
        "file_path": payload_path,          # file-backed: gets the file flag
        "identity": identity,
        "id_parts": artifact_id_key(*identity),
    }


# --- WMI subscription correlation ----------------------------------------------

def correlate_wmi(host, filters, consumers, bindings):
    """Correlate Sysmon WMI events (19 filters, 20 consumers, 21 bindings)
    for one host into complete, actionable subscription artifacts.

    filters/consumers/bindings are lists of key_value_pairs dicts.

    A subscription is actionable only when a binding resolves to EXACTLY
    ONE complete filter and EXACTLY ONE complete consumer. Duplicate
    identical triples deduplicate to one artifact; ambiguous or conflicting
    correlations fail closed (produce no actionable artifact for that
    binding). Returns the list of actionable artifacts (deduped, sorted).
    """
    # index filters by normalized name; a name mapping to >1 distinct filter
    # (different namespace/query) is ambiguous.
    def index(items, name_key, distinct_keys):
        idx = {}
        for it in items:
            nm = str(it.get(name_key, "")).strip().lower()
            if not nm:
                continue
            sig = tuple(str(it.get(k, "")) for k in distinct_keys)
            idx.setdefault(nm, {}).setdefault(sig, it)
        return idx

    filt_idx = index(filters, "name", ("event_namespace", "query"))
    cons_idx = index(consumers, "name", ("type", "destination"))

    artifacts = {}
    for b in bindings:
        cons_ref = norm_wmi_path(b.get("consumer"))
        filt_ref = norm_wmi_path(b.get("filter"))
        cons_name = wmi_consumer_name(b.get("consumer"))
        filt_name = wmi_consumer_name(b.get("filter"))
        if not (cons_ref and filt_ref and cons_name and filt_name):
            continue  # incomplete binding
        cons_variants = cons_idx.get(cons_name.lower())
        filt_variants = filt_idx.get(filt_name.lower())
        # fail closed: the referenced consumer/filter must exist and be
        # unambiguous (exactly one distinct definition).
        if not cons_variants or len(cons_variants) != 1:
            continue
        if not filt_variants or len(filt_variants) != 1:
            continue
        consumer = next(iter(cons_variants.values()))
        filt = next(iter(filt_variants.values()))
        namespace = norm_namespace(filt.get("event_namespace"))
        identity = (host, "wmi_subscription", namespace, filt_ref, cons_ref)
        artifact = {
            "persist_type": "wmi_subscription",
            "host": host,
            "entry": cons_name,               # display only
            "location": f"{filt.get('event_namespace', '')}:"
                        f"__FilterToConsumerBinding",
            "command": consumer.get("destination", ""),
            "file_path": None,                # registration-only, no file flag
            "namespace": namespace,
            "filter_query": filt.get("query", ""),
            "identity": identity,
            "id_parts": artifact_id_key(*identity),
        }
        if identity in artifacts:
            # duplicate complete subscription -> dedup to one; a conflicting
            # command/query under the same identity fails closed.
            prev = artifacts[identity]
            if (prev["command"] != artifact["command"]
                    or prev["filter_query"] != artifact["filter_query"]):
                artifacts[identity] = None  # conflict marker
            continue
        artifacts[identity] = artifact
    return sorted((a for a in artifacts.values() if a is not None),
                  key=lambda a: a["identity"])
