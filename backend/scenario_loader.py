"""YAML scenario loader (Phase 1) — behind SPECTYR_SCENARIO_SOURCE.

Loads backend/scenarios/*.yaml, validates each against scenarios/schema.json,
runs referential checks (label uniqueness, placeholder resolution, event-ID <->
channel pairing), and exposes the same in-memory shapes app.py builds from the
legacy sources so the rolling-queue code stays source-agnostic:

    load_scenarios() -> (catalog, triage_reviews)
      catalog: dict label -> {label, category, difficulty, ticket_title,
                              storyline, threat_pattern, entities, chain}
      triage_reviews: dict label -> triage_review block (matches TRIAGE_REVIEWS)

    resolve_entities(scenario, employees, servers, rng) -> resolved dict
    substitute(value, resolved)      -> str, strict placeholder resolver
    substitute_deep(obj, resolved)   -> substitute through nested structures

The default remains the NDJSON path in app.py; this module is only consulted
when SPECTYR_SCENARIO_SOURCE=yaml. Nothing here mutates app state.
"""
import json
import os
import re
import random

import yaml
import jsonschema

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIO_DIR = os.path.join(HERE, "scenarios")
SCHEMA_PATH = os.path.join(SCENARIO_DIR, "schema.json")

# Placeholder grammar:
#   {entity.field}            two identifiers  (victim.hostname, c2.ip)
#   {infra.<server>.field}    three, infra only (infra.dc.ip)
# The leading segment must start with a lowercase letter, so brace-wrapped
# GUIDs ({4d36e967-...}, {00000000-...}) and hyphenated hex never match and
# pass through verbatim.
PLACEHOLDER = re.compile(
    r"\{(infra\.[a-z][a-z0-9_]*|[a-z][a-z0-9_]*)\.([a-z_]+)\}"
)

# Fields an employee entity exposes.
EMPLOYEE_FIELDS = {"username", "hostname", "ip", "user_domain", "email", "full_name"}

# event_id -> required channel substring, keyed by source_type. This is the
# class of field-accuracy wince Phase 0 fixed by hand; enforced at load time
# so hand-authored scenarios can't reintroduce it.
CHANNEL_RULES = {
    "Windows Security": "WinEventLog:Security",
    "Sysmon": "Microsoft-Windows-Sysmon/Operational",
}


class ScenarioError(Exception):
    """Raised at load time; message names the file and the violation."""


def _load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def _lookup(path, field, resolved):
    """Resolve a single placeholder path/field against the resolved dict."""
    if path.startswith("infra."):
        server = path.split(".", 1)[1]
        infra = resolved.get("infra", {})
        if server not in infra:
            raise ScenarioError(f"unknown infra server in {{{path}.{field}}}")
        if field not in infra[server]:
            raise ScenarioError(f"infra.{server} has no field {field!r}")
        return str(infra[server][field])
    if path not in resolved:
        raise ScenarioError(f"unresolved entity reference {{{path}.{field}}}")
    if field not in resolved[path]:
        raise ScenarioError(f"entity {path!r} has no field {field!r}")
    return str(resolved[path][field])


def substitute(value, resolved):
    """Resolve placeholders in a single string; non-strings pass through.

    Only grammar-matching placeholders bound to a resolved entity are
    touched; an unresolved dotted ref raises (author typo); every other
    brace token (GUIDs, logon GUIDs) passes through verbatim.
    """
    if not isinstance(value, str):
        return value
    return PLACEHOLDER.sub(
        lambda m: _lookup(m.group(1), m.group(2), resolved), value
    )


def substitute_deep(obj, resolved):
    """substitute() applied recursively through dicts/lists."""
    if isinstance(obj, dict):
        return {k: substitute_deep(v, resolved) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_deep(v, resolved) for v in obj]
    return substitute(obj, resolved)


def resolve_entities(scenario, employees, servers, rng=random):
    """Resolve declared entities to concrete values for one run.

    - employee   -> a roster pick (all EMPLOYEE_FIELDS)
    - static     -> the literal fields it declared (external_ip/domain/...)
    - infra      -> built in, exposes each server's hostname + ip
    """
    resolved = {
        "infra": {
            key: {"hostname": srv["hostname"], "ip": srv["ip"]}
            for key, srv in servers.items()
        }
    }
    for name, spec in scenario["entities"].items():
        if spec["type"] == "employee":
            emp = rng.choice(employees)
            resolved[name] = {
                "username": emp["name"],
                "hostname": emp["workstation"],
                "ip": emp["ip"],
                "user_domain": f"ACME\\{emp['name']}",
                "email": emp["email"],
                "full_name": emp["full_name"],
            }
        else:
            resolved[name] = {k: v for k, v in spec.items() if k != "type"}
    return resolved


def validate_scenario(doc, schema, filename):
    """Schema + referential validation for one parsed scenario."""
    try:
        jsonschema.validate(doc, schema)
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
        raise ScenarioError(f"{filename}: schema violation at {loc}: {e.message}")

    declared = set(doc["entities"])

    # every placeholder in the chain must bind to a declared entity (or infra),
    # and employee refs must use known fields
    text = json.dumps(doc["chain"])
    referenced = set()
    for path, field in PLACEHOLDER.findall(text):
        if path.startswith("infra."):
            continue  # infra servers validated at resolution against SERVERS
        if path not in declared:
            raise ScenarioError(
                f"{filename}: chain references undeclared entity {{{path}.{field}}}"
            )
        referenced.add(path)
        etype = doc["entities"][path]["type"]
        if etype == "employee" and field not in EMPLOYEE_FIELDS:
            raise ScenarioError(
                f"{filename}: employee entity {path!r} has no field {field!r}"
            )

    # a declared-but-unreferenced entity is almost always an authoring mistake
    unused = declared - referenced
    if unused:
        raise ScenarioError(
            f"{filename}: entities declared but never referenced in the chain: "
            f"{sorted(unused)}"
        )

    # every scenario needs at least one trigger step for Analyst mode
    if not any(step.get("trigger") for step in doc["chain"]):
        raise ScenarioError(f"{filename}: no chain step marked trigger: true")

    # event_id <-> channel pairing
    for i, step in enumerate(doc["chain"]):
        kvp = step.get("key_value_pairs") or {}
        channel = str(kvp.get("channel", ""))
        rule = CHANNEL_RULES.get(step.get("source_type"))
        if rule and "event_id" in kvp and channel and rule not in channel:
            raise ScenarioError(
                f"{filename}: step {i} source_type {step.get('source_type')!r} "
                f"with channel {channel!r} (expected to contain {rule!r})"
            )


def load_scenarios():
    """Load + validate every scenarios/*.yaml. Fails loudly at the first error."""
    schema = _load_schema()
    catalog = {}
    triage_reviews = {}
    files = sorted(f for f in os.listdir(SCENARIO_DIR) if f.endswith(".yaml"))
    if not files:
        raise ScenarioError(f"no scenario files found in {SCENARIO_DIR}")

    for fname in files:
        with open(os.path.join(SCENARIO_DIR, fname), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        validate_scenario(doc, schema, fname)

        label = doc["label"]
        if label in catalog:
            raise ScenarioError(f"{fname}: duplicate label {label!r}")

        catalog[label] = {
            "label": label,
            "category": doc["category"],
            "difficulty": doc["difficulty"],
            "ticket_title": doc["narrative"]["ticket_title"],
            "storyline": doc["narrative"]["storyline"],
            "threat_pattern": doc.get("threat_pattern", ""),
            "entities": doc["entities"],
            "chain": doc["chain"],
        }
        triage_reviews[label] = doc["triage_review"]

    return catalog, triage_reviews
