"""Unit tests for the schema v2 scenario loader (Phase 2 Stage 0).

Run: python -m pytest test_scenario_loader_v2.py -q   (or python test_scenario_loader_v2.py)

Covers:
  - the migrated corpus loads, and is content-equal to the v1 corpus
    (chains, triage reviews, metadata) — the loader-level parity gate
  - answer_key/attack_meta referential integrity across the corpus
  - deliberately malformed fixtures fail with actionable ScenarioErrors
  - schema-version dispatch (a v1-shaped file loads through the v1 validator)
  - placeholder integrity: no static hostname/IP/username literals in the v2
    files beyond the explicitly grandfathered v1 carryovers
  - determinism: loading twice yields identical catalogs
"""
import ast
import copy
import json
import os
import re
import tempfile

import scenario_loader as v1
import scenario_loader_v2 as v2

HERE = os.path.dirname(os.path.abspath(__file__))

_SCHEMA_V2 = v2._load_schema_v2()
_SCHEMA_V1 = v1._load_schema()


def _load_corpus():
    return v2.load_scenarios()


def _one_valid_doc(label="lateral_movement_1"):
    import yaml
    with open(os.path.join(v2.SCENARIO_V2_DIR, f"{label}.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _expect_error(doc, fragment):
    try:
        v2.validate_scenario_v2(doc, _SCHEMA_V2, _SCHEMA_V1, "fixture.yaml")
    except v2.ScenarioError as e:
        msg = str(e)
        assert "fixture.yaml" in msg, f"error does not name the file: {msg}"
        assert fragment in msg, f"expected {fragment!r} in error: {msg}"
    else:
        raise AssertionError(f"expected ScenarioError containing {fragment!r}")


# --- corpus equivalence vs v1 -------------------------------------------------

def test_corpus_loads_20():
    catalog, reviews = _load_corpus()
    assert len(catalog) == 20 and len(reviews) == 20
    assert all(e["schema_version"] == 2 for e in catalog.values())


def test_corpus_matches_v1_content():
    """Loader-level parity: v2 chains (tags stripped) and metadata must equal
    the v1 loader's output exactly; parity_check_v2.py proves the render layer."""
    cat1, rev1 = v1.load_scenarios()
    cat2, rev2 = _load_corpus()
    assert set(cat1) == set(cat2)
    assert rev1 == rev2
    for label in cat1:
        for key in ("label", "category", "difficulty", "ticket_title",
                    "storyline", "threat_pattern", "entities", "chain"):
            assert cat1[label][key] == cat2[label][key], f"{label}.{key} diverged"


def test_attack_meta_alignment():
    catalog, _ = _load_corpus()
    for label, sc in catalog.items():
        meta = sc["attack_meta"]
        assert len(meta) == len(sc["chain"]), label
        ids = [m["id"] for m in meta]
        assert len(ids) == len(set(ids)), f"{label}: duplicate step ids"
        host_ids = {h["id"] for h in sc["environment"]["hosts"]}
        account_ids = {a["id"] for a in sc["environment"]["accounts"]}
        for m in meta:
            assert m["host"] in host_ids, f"{label}: {m}"
            if "user" in m:
                assert m["user"] in account_ids, f"{label}: {m}"


def test_answer_key_invariants():
    catalog, reviews = _load_corpus()
    for label, sc in catalog.items():
        ak = sc["answer_key"]
        assert ak["classification"] == sc["category"], label
        assert ak["actions"] == [], label
        step_ids = {m["id"] for m in sc["attack_meta"]}
        if sc["category"] == "False Positive":
            assert ak["root_cause"] is None and ak["techniques"] == [], label
        else:
            assert ak["root_cause"] in step_ids, label
            assert ak["techniques"] == [reviews[label]["mitre"]["id"]], label
        host_ids = {h["id"] for h in sc["environment"]["hosts"]}
        account_ids = {a["id"] for a in sc["environment"]["accounts"]}
        assert set(ak["scope"]["hosts"]) <= host_ids, label
        assert set(ak["scope"]["accounts"]) <= account_ids, label


# --- malformed fixtures -------------------------------------------------------

def test_rejects_wrong_schema_version():
    doc = _one_valid_doc()
    doc["schema_version"] = 3
    _expect_error(doc, "schema v2 violation")


def test_rejects_missing_environment():
    doc = _one_valid_doc()
    del doc["environment"]
    _expect_error(doc, "environment")


def test_rejects_unknown_host_in_scope():
    doc = _one_valid_doc()
    doc["answer_key"]["scope"]["hosts"] = ["ws_victim", "ghost"]
    _expect_error(doc, "unknown host 'ghost'")


def test_rejects_unknown_account_in_scope():
    doc = _one_valid_doc()
    doc["answer_key"]["scope"]["accounts"] = ["nobody"]
    _expect_error(doc, "unknown account 'nobody'")


def test_rejects_unknown_step_host_tag():
    doc = _one_valid_doc()
    doc["attack"][0]["host"] = "ghost"
    _expect_error(doc, "not a declared environment host")


def test_rejects_unknown_step_user_tag():
    doc = _one_valid_doc()
    doc["attack"][0]["user"] = "nobody"
    _expect_error(doc, "not a declared environment account")


def test_rejects_duplicate_step_ids():
    doc = _one_valid_doc()
    doc["attack"][1]["id"] = doc["attack"][0]["id"]
    _expect_error(doc, "duplicate step id")


def test_rejects_bad_root_cause():
    doc = _one_valid_doc()
    doc["answer_key"]["root_cause"] = "s99"
    _expect_error(doc, "not an attack step id")


def test_rejects_fp_with_root_cause():
    doc = _one_valid_doc("false_positive_veeam")
    doc["answer_key"]["root_cause"] = "s1"
    _expect_error(doc, "must have root_cause: null")


def test_rejects_attack_without_technique():
    doc = _one_valid_doc()
    doc["answer_key"]["techniques"] = []
    _expect_error(doc, "at least one ATT&CK technique")


def test_rejects_nonempty_actions_reserved_for_stage_3():
    doc = _one_valid_doc()
    doc["answer_key"]["actions"] = [{"action": "isolate_host", "target": "ws_victim"}]
    _expect_error(doc, "schema v2 violation")


def test_rejects_noise_profile_on_unknown_host():
    doc = _one_valid_doc()
    doc["noise"] = {"host_profiles": {"ghost": "workstation_baseline"}}
    _expect_error(doc, "unknown host 'ghost'")


def test_rejects_undeclared_entity_in_chain_via_v1_rules():
    doc = _one_valid_doc()
    doc["attack"][0]["message"] = "beacon to {attacker.ip}"
    _expect_error(doc, "undeclared entity")


def test_rejects_undeclared_entity_in_environment():
    doc = _one_valid_doc()
    doc["environment"]["hosts"][0]["hostname"] = "{ghost.hostname}"
    _expect_error(doc, "environment references undeclared entity")


def test_rejects_account_with_unknown_host():
    doc = _one_valid_doc()
    doc["environment"]["accounts"][0]["host"] = "ghost"
    _expect_error(doc, "unknown host 'ghost'")


# --- dispatch ------------------------------------------------------------------

def test_dispatch_loads_v1_shaped_file():
    """A file without schema_version goes through the untouched v1 validator."""
    import yaml
    with open(os.path.join(HERE, "scenarios", "malware_usb.yaml"), encoding="utf-8") as f:
        v1_text = f.read()
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "malware_usb.yaml"), "w", encoding="utf-8") as f:
            f.write(v1_text)
        catalog, reviews = v2.load_scenarios(directory=td)
    assert catalog["malware_usb"]["schema_version"] == 1
    assert "malware_usb" in reviews


def test_dispatch_rejects_unsupported_version():
    import yaml
    doc = _one_valid_doc()
    doc["schema_version"] = 9
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "bad.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f)
        try:
            v2.load_scenarios(directory=td)
        except v2.ScenarioError as e:
            assert "unsupported schema_version" in str(e) and "bad.yaml" in str(e)
        else:
            raise AssertionError("expected ScenarioError for schema_version 9")


# --- placeholder integrity -----------------------------------------------------

# Literals the v2 corpus is allowed to contain, all carried over from v1
# (grandfathered) or fixed by the reference environment. Anything else that
# looks like a workstation, server, subnet IP, or roster username is a
# placeholder-discipline violation.
GRANDFATHERED = {
    "ACME-FW01": None,               # reference environment: hardcoded firewall
    "10.0.1.254": None,              # firewall IP (environment metadata)
    "ACME-VEEAM01": "false_positive_veeam.yaml",   # v1 internal_host entity
    "10.0.1.210": "false_positive_veeam.yaml",     # v1 internal_host entity
    "dpark": "password_spray.yaml",                # v1 literal sprayed accounts
    "mjohnson": "password_spray.yaml",
    "bwilliams": "password_spray.yaml",
    "achen": "password_spray.yaml",
    "jkim": "password_spray.yaml",
    "lgreen": "password_spray.yaml",
    # v1 literals in the SSL inspection FP: the proxy's CA name and its
    # device name (which disagrees with the reference environment's
    # ACME-SVR06 proxy — flagged in the migration report)
    "ACME-PROXY-CA": "false_positive_ssl_inspection.yaml",
    "ACME-PROXY-01": "false_positive_ssl_inspection.yaml",
}


def _roster_usernames():
    """EMPLOYEES parsed from app.py without importing it (no boot side effects)."""
    tree = ast.parse(open(os.path.join(HERE, "app.py"), encoding="utf-8").read())
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "EMPLOYEES"):
            return [e["name"] for e in ast.literal_eval(node.value)]
    raise AssertionError("EMPLOYEES not found in app.py")


def test_no_static_values_in_v2_files():
    usernames = _roster_usernames()
    patterns = [re.compile(r"ACME-[A-Z0-9]+(?:-[A-Z0-9]+)*"),
                re.compile(r"10\.0\.1\.\d+")]
    patterns += [re.compile(rf"\b{re.escape(u)}\b") for u in usernames]
    violations = []
    for fname in sorted(os.listdir(v2.SCENARIO_V2_DIR)):
        if not fname.endswith(".yaml"):
            continue
        text = open(os.path.join(v2.SCENARIO_V2_DIR, fname), encoding="utf-8").read()
        for pat in patterns:
            for hit in set(pat.findall(text)):
                allowed_in = GRANDFATHERED.get(hit, "MISSING")
                if allowed_in is None or allowed_in == fname:
                    continue
                violations.append(f"{fname}: {hit!r}")
    assert not violations, f"static values leaked into v2 files: {violations}"


# --- determinism -----------------------------------------------------------------

def test_load_is_deterministic():
    a = v2.load_scenarios()
    b = v2.load_scenarios()
    assert a == b


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
