"""YAML scenario loader, schema v2 (Phase 2 Stage 0) — behind SPECTYR_SCENARIO_SOURCE.

Schema v2 turns a scenario into a small simulated environment with the attack
chain inside it, instead of a bare chain:

    environment: org metadata + the hosts and accounts the scenario plays out on
    attack:      the v1 chain, each step tagged with a stable id and the
                 environment host (and account, when one applies) it occurs on
    noise:       per-host noise profile references (profiles land in Stage 1;
                 empty in every migrated scenario)
    answer_key:  classification, scope, root_cause, techniques, actions
                 (actions reserved for Stage 3 — must stay empty until then)

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

import yaml
import jsonschema

import scenario_loader as v1

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
