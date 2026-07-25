"""YAML scenario loader, schema v2 (Phase 2 Stage 0) — behind SPECTYR_SCENARIO_SOURCE.

Schema v2 turns a scenario into a small simulated environment with the attack
chain inside it, instead of a bare chain:

    environment: org metadata + the hosts and accounts the scenario plays out on
    attack:      the v1 chain, each step tagged with a stable id and the
                 environment host (and account, when one applies) it occurs on
    noise:       per-host noise profile references (profiles land in Stage 1;
                 empty in every migrated scenario)
    answer_key:  classification, scope, root_cause, techniques, actions
                 (action grammar unlocked in Stage 3a: composite internal
                 targets, optional order sensitivity; content lands in 3c)

Dispatch: load_scenarios() reads backend/scenarios/v2/*.yaml and dispatches on
each file's schema_version — 2 goes through this module's validation, 1 (or
absent) goes through the untouched v1 validator in scenario_loader, so mixed
corpora stay loadable. The v1 loader and its corpus in backend/scenarios/
are NOT modified by this module: they remain the revert path, exactly like the
legacy NDJSON loader before them.

Catalog contract: a superset of the v1 loader's. The v1 keys (label, category,
difficulty, ticket_title, storyline, threat_pattern, entities, chain) carry
identical shapes — chain steps have the id/host/user tags stripped — so
app.py's chain renderer works on either catalog unchanged. v2 entries add:

    schema_version: 2
    environment:    the environment block, verbatim
    noise:          the noise block, verbatim
    answer_key:     the answer_key block, verbatim
    attack_meta:    per-step {"id", "host", "user"?}, positionally aligned
                    with chain (the stripped tags, for Stage 1+ consumers)

Nothing here mutates app state. Placeholders are resolved at runtime through
scenario_loader.resolve_entities/substitute_deep, same as v1.
"""
import json
import os
import re

import yaml
import jsonschema

import action_overlay
import persistence
import scenario_loader as v1
import snapshot_generator

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIO_V2_DIR = os.path.join(HERE, "scenarios", "v2")
SCHEMA_V2_PATH = os.path.join(HERE, "scenarios", "schema_v2.json")

# Per-step keys that are v2 tags, not renderable log content. Stripped from
# the catalog's chain so rendered logs stay byte-identical to the v1 source.
STEP_TAG_FIELDS = ("id", "host", "user")

ScenarioError = v1.ScenarioError


def _load_schema_v2():
    with open(SCHEMA_V2_PATH, encoding="utf-8") as f:
        return json.load(f)


def strip_step(step):
    """A v2 attack step minus its tags == the v1 chain step, key for key."""
    return {k: v for k, v in step.items() if k not in STEP_TAG_FIELDS}


def _synth_v1_doc(doc):
    """Project a v2 doc down to its embedded v1 scenario, so the untouched v1
    validator can enforce every chain-level rule (placeholder binding,
    employee fields, event-ID <-> channel pairing, trigger presence)."""
    return {
        "label": doc["label"],
        "category": doc["category"],
        "difficulty": doc["difficulty"],
        "threat_pattern": doc["threat_pattern"],
        "narrative": doc["narrative"],
        "entities": doc["entities"],
        "chain": [strip_step(s) for s in doc["attack"]],
        "triage_review": doc["triage_review"],
    }


def _dupes(ids):
    seen, dup = set(), []
    for i in ids:
        if i in seen:
            dup.append(i)
        else:
            seen.add(i)
    return dup


def validate_scenario_v2(doc, schema_v2, v1_schema, filename):
    """Schema + referential validation for one parsed v2 scenario.

    Every error is a ScenarioError naming the file and the violation, so a
    malformed file fails the boot loudly and actionably.
    """
    # Checked ahead of the schema so the author sees the reason, not just the
    # schema conditional's "None was expected". The schema's answer_key
    # allOf/if-then enforces the same invariant for schema-only consumers.
    ak = doc.get("answer_key")
    if (isinstance(ak, dict)
            and ak.get("classification") == "False Positive"
            and ak.get("root_cause") is not None):
        raise ScenarioError(
            f"{filename}: a False Positive scenario must have root_cause: null "
            f"(got {ak.get('root_cause')!r})"
        )

    # Same principle for action target shapes (Stage 3a): the schema's
    # per-action conditionals reject a wrong composite with a bare "False
    # schema does not allow" message, so the author-facing reason runs first.
    _pre_check_action_target_shapes(doc, filename)

    try:
        jsonschema.validate(doc, schema_v2)
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
        raise ScenarioError(f"{filename}: schema v2 violation at {loc}: {e.message}")

    # The embedded chain must still be a valid v1 chain; reuse the v1
    # validator verbatim rather than duplicating its rules here.
    v1.validate_scenario(_synth_v1_doc(doc), v1_schema, filename)

    env = doc["environment"]
    host_ids = [h["id"] for h in env["hosts"]]
    account_ids = [a["id"] for a in env["accounts"]]
    step_ids = [s["id"] for s in doc["attack"]]

    for name, ids in (("host", host_ids), ("account", account_ids), ("step", step_ids)):
        dup = _dupes(ids)
        if dup:
            raise ScenarioError(f"{filename}: duplicate {name} id(s): {sorted(set(dup))}")

    hosts = set(host_ids)
    accounts = set(account_ids)

    for a in env["accounts"]:
        if "host" in a and a["host"] not in hosts:
            raise ScenarioError(
                f"{filename}: account {a['id']!r} references unknown host {a['host']!r}"
            )

    for i, step in enumerate(doc["attack"]):
        if step["host"] not in hosts:
            raise ScenarioError(
                f"{filename}: attack step {i} ({step['id']}): host tag "
                f"{step['host']!r} is not a declared environment host"
            )
        if "user" in step and step["user"] not in accounts:
            raise ScenarioError(
                f"{filename}: attack step {i} ({step['id']}): user tag "
                f"{step['user']!r} is not a declared environment account"
            )

    # Supplemental events (Stage 2 density): authored benign telemetry with
    # sup* ids, sharing the id-space with attack steps.
    sup_events = doc.get("supplemental_events", [])
    sup_ids = [s["id"] for s in sup_events]
    dup = _dupes(step_ids + sup_ids)
    if dup:
        raise ScenarioError(
            f"{filename}: id collision between attack/supplemental events: "
            f"{sorted(set(dup))}")
    for i, sup in enumerate(sup_events):
        if sup["host"] not in hosts:
            raise ScenarioError(
                f"{filename}: supplemental event {sup['id']!r}: host "
                f"{sup['host']!r} is not a declared environment host")
        if "user" in sup and sup["user"] not in accounts:
            raise ScenarioError(
                f"{filename}: supplemental event {sup['id']!r}: user "
                f"{sup['user']!r} is not a declared environment account")

    sup_entity_ids = [e["id"] for e in doc.get("supplemental_entities", [])]
    dup = _dupes(sup_entity_ids)
    if dup:
        raise ScenarioError(
            f"{filename}: duplicate supplemental_entity id(s): {sorted(set(dup))}")

    # Placeholders in supplemental events bind to declared entities, infra, or
    # supplemental_entities. supplemental_entities are referenced by id.
    declared_all = set(doc["entities"]) | set(sup_entity_ids)
    sup_text = json.dumps(sup_events)
    for path, field in v1.PLACEHOLDER.findall(sup_text):
        if path.startswith("infra."):
            continue
        if path not in declared_all:
            raise ScenarioError(
                f"{filename}: supplemental event references undeclared entity "
                f"{{{path}.{field}}}")

    ak = doc["answer_key"]
    for hid in ak["scope"]["hosts"]:
        if hid not in hosts:
            raise ScenarioError(
                f"{filename}: answer_key.scope.hosts references unknown host {hid!r}"
            )
    for aid in ak["scope"]["accounts"]:
        if aid not in accounts:
            raise ScenarioError(
                f"{filename}: answer_key.scope.accounts references unknown account {aid!r}"
            )

    # Detections (Stage 2): ids unique, triggers reference real steps, and
    # the disposition must be consistent with the scenario kind.
    det_ids = [d["id"] for d in doc["detections"]]
    dup = _dupes(det_ids)
    if dup:
        raise ScenarioError(f"{filename}: duplicate detection id(s): {sorted(set(dup))}")
    # Detections trigger on attack step ids or supplemental event ids.
    triggerable = set(step_ids) | {s["id"] for s in doc.get("supplemental_events", [])}
    is_fp_scenario = ak["classification"] == "False Positive"
    has_true_positive = False
    for det in doc["detections"]:
        bad = [t for t in det["triggers"] if t not in triggerable]
        if bad:
            raise ScenarioError(
                f"{filename}: detection {det['id']!r} triggers on unknown "
                f"attack/supplemental event(s) {bad}"
            )
        if det["rule_type"] == "yara" and "yara_rule_name" not in det:
            raise ScenarioError(
                f"{filename}: yara detection {det['id']!r} needs a yara_rule_name"
            )
        if det["disposition"] == "true_positive":
            has_true_positive = True
            if is_fp_scenario:
                raise ScenarioError(
                    f"{filename}: a False Positive scenario cannot carry a "
                    f"true_positive detection ({det['id']!r})"
                )
    if not is_fp_scenario and not has_true_positive:
        raise ScenarioError(
            f"{filename}: an attack scenario needs at least one true_positive detection"
        )

    # Response actions (Stage 3a unlock): grammar is schema-enforced; the
    # loader adds the referential rules (targets resolve to environment
    # hosts/accounts; `after` references resolve, no self-reference, no
    # cycles). Content stays empty until Stage 3c authors it.
    _validate_answer_actions(ak["actions"], hosts, accounts, filename)

    # Stage 3c tri-state marker + achievability. Authored actions and the
    # reviewed flag flip together (one scenario per commit), so an authored
    # set without the flag is an inconsistent state, rejected loudly. A
    # reviewed scenario failing achievability is a hard validation error,
    # same severity as a schema violation.
    if ak["actions"] and not ak.get("actions_reviewed", False):
        raise ScenarioError(
            f"{filename}: authored answer_key.actions require "
            f"actions_reviewed: true (the 3c review flips both together)")
    _validate_answer_traps(ak, hosts, accounts, filename)
    if ak.get("actions_reviewed", False):
        _validate_action_achievability(doc, filename)

    root_cause = ak["root_cause"]
    if root_cause is not None and root_cause not in step_ids:
        raise ScenarioError(
            f"{filename}: answer_key.root_cause {root_cause!r} is not an attack step id"
        )
    if ak["classification"] == "False Positive":
        if root_cause is not None:
            raise ScenarioError(
                f"{filename}: a False Positive scenario must have root_cause: null "
                f"(got {root_cause!r})"
            )
        if ak["techniques"]:
            raise ScenarioError(
                f"{filename}: a False Positive scenario must have empty techniques "
                f"(got {ak['techniques']})"
            )
    else:
        if root_cause is None:
            raise ScenarioError(
                f"{filename}: an attack scenario requires answer_key.root_cause "
                f"(the step id of patient zero)"
            )
        if not ak["techniques"]:
            raise ScenarioError(
                f"{filename}: an attack scenario requires at least one ATT&CK "
                f"technique in answer_key.techniques"
            )

    for hid in (doc["noise"].get("host_profiles") or {}):
        if hid not in hosts:
            raise ScenarioError(
                f"{filename}: noise.host_profiles references unknown host {hid!r}"
            )

    # Placeholders used in the environment must bind to declared entities,
    # same grammar and rules as the chain (which the v1 validator covered).
    declared = set(doc["entities"])
    env_text = json.dumps(env)
    for path, field in v1.PLACEHOLDER.findall(env_text):
        if path.startswith("infra."):
            continue  # infra servers validated at resolution against SERVERS
        if path not in declared:
            raise ScenarioError(
                f"{filename}: environment references undeclared entity {{{path}.{field}}}"
            )
        if doc["entities"][path]["type"] == "employee" and field not in v1.EMPLOYEE_FIELDS:
            raise ScenarioError(
                f"{filename}: environment employee entity {path!r} has no field {field!r}"
            )


# Action -> exactly the composite target fields it takes. Mirrors the
# schema's per-action conditionals so loader errors stay actionable
# (the schema conditional's failure message names a boolean subschema).
_ACTION_TARGET_FIELDS = {
    "isolate_host": ("host",),
    "kill_process": ("host", "pid"),
    "delete_file": ("host", "path"),
    "disable_account": ("account",),
    "revoke_sessions": ("account",),
    "force_password_reset": ("account",),
    "remove_persistence": ("host", "persistence"),
}


def _pre_check_target_shapes(entries, label, filename):
    """Author-facing target-shape errors for a list of action/trap entries,
    raised ahead of the schema (which enforces the same shapes via
    per-action conditionals). Defensive on structure."""
    if not isinstance(entries, list):
        return
    for i, act in enumerate(entries):
        if not isinstance(act, dict):
            continue
        name = act.get("action")
        fields = _ACTION_TARGET_FIELDS.get(name)
        tgt = act.get("target")
        if fields is None or not isinstance(tgt, dict):
            continue
        missing = [f for f in fields if f not in tgt]
        extra = [f for f in tgt if f not in fields]
        if missing or extra:
            raise ScenarioError(
                f"{filename}: answer_key.{label}[{i}] ({name}): target takes "
                f"exactly {list(fields)}; missing {missing}, extra {extra}")


def _pre_check_action_target_shapes(doc, filename):
    ak = doc.get("answer_key")
    if not isinstance(ak, dict):
        return
    _pre_check_target_shapes(ak.get("actions"), "actions", filename)
    _pre_check_target_shapes(ak.get("traps"), "traps", filename)


def _target_key(action, target):
    """A hashable (action, target) identity for overlap checks, matching the
    scorer's composite match key."""
    if action in ("disable_account", "revoke_sessions", "force_password_reset"):
        return (action, target["account"])
    if action == "isolate_host":
        return (action, target["host"])
    if action == "kill_process":
        return (action, target["host"], target["pid"])
    if action == "remove_persistence":
        return (action, target["host"], persistence.parse_selector(target["persistence"]))
    return (action, target["host"], action_overlay.norm_path(target["path"]))


def _validate_answer_actions(actions, hosts, accounts, filename):
    """Referential rules for answer-key actions (shapes are handled by the
    schema and the pre-check above): unique ids, unique (action, target)
    pairs with no pair under both statuses, targets resolving to the
    environment, and order declarations on required actions referencing
    required actions only."""
    act_ids = [a["id"] for a in actions if "id" in a]
    dup = _dupes(act_ids)
    if dup:
        raise ScenarioError(
            f"{filename}: duplicate answer_key.actions id(s): {sorted(set(dup))}")
    known = set(act_ids)
    status_by_id = {a["id"]: a.get("status") for a in actions if "id" in a}

    seen_pairs = {}
    for i, act in enumerate(actions):
        name = act["action"]
        tgt = act["target"]
        pair = (name, tuple(sorted(tgt.items())))
        if pair in seen_pairs:
            prev_status = seen_pairs[pair]
            if prev_status != act.get("status"):
                raise ScenarioError(
                    f"{filename}: answer_key.actions[{i}] ({name}): the same "
                    f"action-target pair is declared under both statuses "
                    f"(required and acceptable)")
            raise ScenarioError(
                f"{filename}: answer_key.actions[{i}] ({name}): duplicate "
                f"expected action for the same target")
        seen_pairs[pair] = act.get("status")

        if "host" in tgt and tgt["host"] not in hosts:
            raise ScenarioError(
                f"{filename}: answer_key.actions[{i}] ({name}): target host "
                f"{tgt['host']!r} is not a declared environment host")
        if "account" in tgt and tgt["account"] not in accounts:
            raise ScenarioError(
                f"{filename}: answer_key.actions[{i}] ({name}): target account "
                f"{tgt['account']!r} is not a declared environment account")
        if act.get("after") and act.get("status") != "required":
            raise ScenarioError(
                f"{filename}: answer_key.actions[{i}] ({name}): order "
                f"declarations apply to required actions only")
        for ref in act.get("after", []):
            if ref not in known:
                raise ScenarioError(
                    f"{filename}: answer_key.actions[{i}] ({name}): after "
                    f"references unknown action id {ref!r}")
            if ref == act.get("id"):
                raise ScenarioError(
                    f"{filename}: answer_key.actions[{i}] ({name}): after "
                    f"references itself")
            if status_by_id.get(ref) != "required":
                raise ScenarioError(
                    f"{filename}: answer_key.actions[{i}] ({name}): after "
                    f"references {ref!r}, which is not a required action; "
                    f"credit cannot depend on optional actions")

    _validate_answer_actions_no_cycles(actions, filename)


def _validate_answer_traps(ak, hosts, accounts, filename):
    """Referential + no-overlap rules for answer_key.traps. Achievability
    (and the executable/reachable/collateral proof) is the fixed-seed
    harness's job, run only for reviewed scenarios; here we enforce that a
    declared trap resolves to the environment and does not overlap any
    required or acceptable action (a trap is off-list by definition)."""
    traps = ak.get("traps", [])
    if not traps:
        return
    if not ak.get("actions_reviewed", False):
        raise ScenarioError(
            f"{filename}: answer_key.traps require actions_reviewed: true "
            f"(traps are validated with the scenario's reviewed action set)")
    action_keys = {_target_key(a["action"], a["target"]) for a in ak["actions"]}
    seen = set()
    for i, trap in enumerate(traps):
        name, tgt = trap["action"], trap["target"]
        if "host" in tgt and tgt["host"] not in hosts:
            raise ScenarioError(
                f"{filename}: answer_key.traps[{i}] ({name}): target host "
                f"{tgt['host']!r} is not a declared environment host")
        if "account" in tgt and tgt["account"] not in accounts:
            raise ScenarioError(
                f"{filename}: answer_key.traps[{i}] ({name}): target account "
                f"{tgt['account']!r} is not a declared environment account")
        key = _target_key(name, tgt)
        if key in action_keys:
            raise ScenarioError(
                f"{filename}: answer_key.traps[{i}] ({name}): overlaps a "
                f"required or acceptable action; a trap must be off-list")
        if key in seen:
            raise ScenarioError(
                f"{filename}: answer_key.traps[{i}] ({name}): duplicate trap")
        seen.add(key)


def _validate_answer_actions_no_cycles(actions, filename):
    # No cycles in the order-sensitivity graph.
    edges = {a["id"]: list(a.get("after", [])) for a in actions if "id" in a}
    state = {}  # id -> 1 visiting, 2 done

    def visit(node, trail):
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            raise ScenarioError(
                f"{filename}: answer_key.actions order cycle: "
                f"{' -> '.join(trail + [node])}")
        state[node] = 1
        for nxt in edges.get(node, []):
            visit(nxt, trail + [node])
        state[node] = 2

    for node in edges:
        visit(node, [])


# Mirrors snapshot_generator.RUN_KEY_RE: only run-key SetValue events
# materialize autorun rows, so only those paths are deletable via autoruns.
_RUN_KEY_RE = re.compile(r"\\CurrentVersion\\Run\\", re.IGNORECASE)


def _authored_action_sources(doc):
    """Per environment host id: the authored PIDs and deletable file paths
    (canonical raw form, placeholders intact) that the world merger
    materializes from this scenario's own events.

    SEED INDEPENDENCE is structural: only the attack chain, supplemental
    events, and the canonical environment count as sources. Baselines and
    noise are seed-generated and never satisfy an answer-key target, so a
    validated target resolves identically under every seed (substitution
    is uniform across the answer key and the chain, so raw-string equality
    implies post-substitution equality).
    """
    pids, paths = {}, {}
    # Per host: authored persistence selectors, plus the WMI event buffers to
    # correlate afterwards (same fail-closed correlation as materialization).
    run_keys = {}                       # host -> set of ("run_key", (nkey, nvalue))
    wmi = {}                            # host -> {"filters":[],"consumers":[],"bindings":[]}

    def add_pid(host, value):
        v = str(value or "")
        if v.isdigit():
            pids.setdefault(host, set()).add(int(v))

    def add_path(host, value):
        p = action_overlay.norm_path(value)
        if p:
            paths.setdefault(host, set()).add(p)

    def wmi_buf(host):
        return wmi.setdefault(host, {"filters": [], "consumers": [], "bindings": []})

    for step in list(doc["attack"]) + list(doc.get("supplemental_events", [])):
        host = step["host"]
        kvp = step.get("key_value_pairs") or {}
        src = step.get("source_type")
        etype = step.get("event_type", "")
        event_id = str(kvp.get("event_id", ""))
        if src == "Sysmon" and event_id == "1":
            add_pid(host, kvp.get("process_id"))
            add_pid(host, kvp.get("parent_process_id"))
            add_path(host, kvp.get("image"))
            add_path(host, kvp.get("parent_image"))
        elif ((src == "Sysmon" and event_id == "3")
              or (src == "Firewall" and etype == "ALLOW")
              or (src == "Proxy" and (etype.startswith("HTTP_")
                                      or etype.startswith("SSL_")))):
            add_pid(host, kvp.get("process_id"))
            add_path(host, kvp.get("image"))
        elif src == "Sysmon" and event_id == "13":
            if _RUN_KEY_RE.search(kvp.get("target_object", "")):
                add_path(host, action_overlay.extract_image_path(
                    kvp.get("details", "")))
                parts = persistence.split_run_key(kvp.get("target_object", ""))
                if parts is not None:
                    nkey, _value, nvalue = parts
                    if nvalue:
                        run_keys.setdefault(host, set()).add(("run_key", (nkey, nvalue)))
        elif src == "Sysmon" and event_id in ("19", "20", "21"):
            bucket = {"19": "filters", "20": "consumers", "21": "bindings"}[event_id]
            wmi_buf(host)[bucket].append(kvp)

    persist = {}                        # host -> set of canonical selectors
    for host in set(run_keys) | set(wmi):
        buf = wmi.get(host, {"filters": [], "consumers": [], "bindings": []})
        persist[host] = persistence.authored_selectors(
            host, buf["filters"], buf["consumers"], buf["bindings"],
            {rk for (_k, rk) in run_keys.get(host, set())})
    return pids, paths, persist


def _validate_action_achievability(doc, filename):
    """Every required action must be executable from the scenario's INITIAL
    world state (enforced, not advisory): isolate needs a declared-online
    managed host; kill needs an authored (host, PID); delete needs an
    authored (host, path); identity needs an environment account (already
    referentially checked). Declared `after` orderings are satisfiable by
    construction once every action is achievable: the reference/cycle
    checks above guarantee a topological order exists.

    Consequence for the offline-host wrinkle: an offline host can never
    carry required-action credit; it may only appear as a tempting-but-
    wrong target or a factually surfaced failed attempt.
    """
    env_hosts = {h["id"]: h for h in doc["environment"]["hosts"]}
    pids, paths, persist = _authored_action_sources(doc)
    ak = doc["answer_key"]

    def check(entries, label, isolate_offline_fatal):
        for i, act in enumerate(entries):
            name = act["action"]
            tgt = act["target"]
            where = f"answer_key.{label}[{i}] ({name})"
            host = env_hosts.get(tgt.get("host")) if "host" in tgt else None
            if host is not None:
                if host["role"] in snapshot_generator.NON_ENDPOINT_ROLES:
                    raise ScenarioError(
                        f"{filename}: {where}: target host {host['id']!r} is a "
                        f"{host['role']} (log source, never a managed "
                        f"endpoint); the action is unachievable")
                if (name == "isolate_host" and host.get("status") == "offline"
                        and isolate_offline_fatal):
                    raise ScenarioError(
                        f"{filename}: {where}: host {host['id']!r} is declared "
                        f"offline; isolation cannot succeed, so it can never be "
                        f"a required action")
            if name == "kill_process" and tgt["pid"] not in pids.get(tgt["host"], set()):
                raise ScenarioError(
                    f"{filename}: {where}: pid {tgt['pid']} on host "
                    f"{tgt['host']!r} is not an authored process of this "
                    f"scenario (chain/supplemental); seed-generated noise "
                    f"never qualifies")
            if (name == "delete_file"
                    and action_overlay.norm_path(tgt["path"]) not in paths.get(tgt["host"], set())):
                raise ScenarioError(
                    f"{filename}: {where}: path {tgt['path']!r} on host "
                    f"{tgt['host']!r} is not an authored deletable file of this "
                    f"scenario (Sysmon image/parent_image or run-key autorun); "
                    f"seed-generated noise never qualifies")
            if name == "remove_persistence":
                parsed = persistence.parse_selector(tgt["persistence"])
                if parsed is None:
                    raise ScenarioError(
                        f"{filename}: {where}: persistence selector "
                        f"{tgt['persistence']!r} is malformed (expected "
                        f"'wmi:<ConsumerName>' or 'run_key:<KeyPath\\ValueName>')")
                if parsed not in persist.get(tgt["host"], set()):
                    raise ScenarioError(
                        f"{filename}: {where}: persistence {tgt['persistence']!r} on "
                        f"host {tgt['host']!r} is not an authored persistence "
                        f"artifact of this scenario (a run-key SetValue, or a "
                        f"complete WMI 19/20/21 subscription); seed-generated "
                        f"noise and incomplete/ambiguous subscriptions never qualify")

    # Required/acceptable actions: a required isolate on an offline host is
    # fatal (it can never earn credit). Traps face the same authored-source
    # bar; an offline-host isolate trap is left to the harness (it would fail
    # precondition and thus not grade collateral, which the harness rejects).
    check(ak["actions"], "actions", isolate_offline_fatal=True)
    check(ak.get("traps", []), "traps", isolate_offline_fatal=False)


def _catalog_entry_v2(doc):
    attack_meta = []
    for step in doc["attack"]:
        meta = {"id": step["id"], "host": step["host"]}
        if "user" in step:
            meta["user"] = step["user"]
        attack_meta.append(meta)
    return {
        "label": doc["label"],
        "category": doc["category"],
        "difficulty": doc["difficulty"],
        "ticket_title": doc["narrative"]["ticket_title"],
        "storyline": doc["narrative"]["storyline"],
        "threat_pattern": doc.get("threat_pattern", ""),
        "entities": doc["entities"],
        "chain": [strip_step(s) for s in doc["attack"]],
        "schema_version": 2,
        "environment": doc["environment"],
        "noise": doc["noise"],
        "supplemental_events": doc.get("supplemental_events", []),
        "supplemental_entities": doc.get("supplemental_entities", []),
        "detections": doc["detections"],
        "answer_key": doc["answer_key"],
        "attack_meta": attack_meta,
        "traps": doc["answer_key"].get("traps", []),
        # Stage 5 D2: the optional Tier 2 rationale paragraph (None until a
        # scenario's authored commit lands; ledger-ratcheted). Consumed only
        # at submit time (frozen as scenario_rationale), never pre-boundary.
        "expected_response": doc.get("expected_response"),
    }


def _catalog_entry_v1(doc):
    return {
        "label": doc["label"],
        "category": doc["category"],
        "difficulty": doc["difficulty"],
        "ticket_title": doc["narrative"]["ticket_title"],
        "storyline": doc["narrative"]["storyline"],
        "threat_pattern": doc.get("threat_pattern", ""),
        "entities": doc["entities"],
        "chain": doc["chain"],
        "schema_version": 1,
    }


def load_scenarios(directory=SCENARIO_V2_DIR):
    """Load + validate every *.yaml in the v2 directory, dispatching on each
    file's schema_version. Fails loudly at the first error."""
    schema_v2 = _load_schema_v2()
    v1_schema = v1._load_schema()
    catalog = {}
    triage_reviews = {}
    files = sorted(f for f in os.listdir(directory) if f.endswith(".yaml"))
    if not files:
        raise ScenarioError(f"no scenario files found in {directory}")

    for fname in files:
        with open(os.path.join(directory, fname), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if not isinstance(doc, dict):
            raise ScenarioError(f"{fname}: expected a mapping at the top level")

        version = doc.get("schema_version", 1)
        if version == 1:
            v1.validate_scenario(doc, v1_schema, fname)
            entry = _catalog_entry_v1(doc)
        elif version == 2:
            validate_scenario_v2(doc, schema_v2, v1_schema, fname)
            entry = _catalog_entry_v2(doc)
        else:
            raise ScenarioError(
                f"{fname}: unsupported schema_version {version!r} (expected 1 or 2)"
            )

        label = doc["label"]
        if label in catalog:
            raise ScenarioError(f"{fname}: duplicate label {label!r}")
        catalog[label] = entry
        triage_reviews[label] = doc["triage_review"]

    return catalog, triage_reviews
