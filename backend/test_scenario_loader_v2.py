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

import scenario_corrections
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


def _corrected_v1_chain(label, chain):
    """The v1 chain with the approved step corrections applied — the exact
    content the v2 corpus is required to carry."""
    chain = copy.deepcopy(chain)
    for corr in scenario_corrections.for_label(label):
        if corr["kind"] != "step":
            continue
        step = chain[corr["step"]]
        if corr["field"].startswith("kvp."):
            key = corr["field"][4:]
            assert step["key_value_pairs"].get(key) == corr["v1"], (
                f"{label}: v1 no longer carries the correction precondition")
            step["key_value_pairs"][key] = corr["v2"]
        else:
            assert step.get(corr["field"]) == corr["v1"]
            step[corr["field"]] = corr["v2"]
    return chain


def _corrected_v1_entities(label, entities):
    """The v1 entities with the approved entity corrections applied."""
    entities = copy.deepcopy(entities)
    for corr in scenario_corrections.for_label(label):
        if corr["kind"] != "entity":
            continue
        spec = entities[corr["entity"]]
        assert spec.get(corr["field"]) == corr["v1"], (
            f"{label}: v1 no longer carries the correction precondition")
        spec[corr["field"]] = corr["v2"]
    return entities


def _corrected_v1_triage(label, review):
    """The v1 triage review with the approved triage corrections applied."""
    review = copy.deepcopy(review)
    for corr in scenario_corrections.for_label(label):
        if corr["kind"] != "triage":
            continue
        node = review
        *parents, leaf = corr["field"].split(".")
        for part in parents:
            node = node[part]
        assert node.get(leaf) == corr["v1"], (
            f"{label}: v1 no longer carries the triage correction precondition")
        node[leaf] = corr["v2"]
    return review


def test_corpus_matches_v1_content():
    """Loader-level parity: v2 chains (tags stripped) must equal the v1
    loader's output with exactly the approved corrections applied, and
    metadata must match verbatim; parity_check_v2.py proves the render layer."""
    cat1, rev1 = v1.load_scenarios()
    cat2, rev2 = _load_corpus()
    assert set(cat1) == set(cat2)
    for label in rev1:
        assert _corrected_v1_triage(label, rev1[label]) == rev2[label], \
            f"{label}: triage review diverged beyond approved corrections"
    for label in cat1:
        for key in ("label", "category", "difficulty", "ticket_title",
                    "storyline", "threat_pattern"):
            assert cat1[label][key] == cat2[label][key], f"{label}.{key} diverged"
        expected_entities = _corrected_v1_entities(label, cat1[label]["entities"])
        assert expected_entities == cat2[label]["entities"], f"{label}.entities diverged"
        expected = _corrected_v1_chain(label, cat1[label]["chain"])
        assert expected == cat2[label]["chain"], f"{label}.chain diverged"


def test_corrections_present_in_v2():
    """Each approved correction must actually be in the v2 corpus — a
    regression here means a regeneration silently dropped it."""
    catalog, _ = _load_corpus()
    assert scenario_corrections.CORRECTIONS, "corrections record unexpectedly empty"
    _, reviews = _load_corpus()
    for corr in scenario_corrections.CORRECTIONS:
        if corr["kind"] == "triage":
            node = reviews[corr["label"]]
            *parents, leaf = corr["field"].split(".")
            for part in parents:
                node = node[part]
            actual = node.get(leaf)
        elif corr["kind"] == "entity":
            actual = catalog[corr["label"]]["entities"][corr["entity"]].get(corr["field"])
        else:
            step = catalog[corr["label"]]["chain"][corr["step"]]
            if corr["field"].startswith("kvp."):
                actual = step["key_value_pairs"].get(corr["field"][4:])
            else:
                actual = step.get(corr["field"])
        assert actual == corr["v2"], (
            f"{corr['label']} {corr['field']}: "
            f"expected {corr['v2']!r}, found {actual!r}")


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


def test_schema_alone_rejects_fp_with_root_cause():
    """The FP root_cause invariant is a schema-level conditional, not only a
    loader check: raw jsonschema validation must reject the fixture too."""
    import jsonschema
    doc = _one_valid_doc("false_positive_veeam")
    doc["answer_key"]["root_cause"] = "s1"
    try:
        jsonschema.validate(doc, _SCHEMA_V2)
    except jsonschema.ValidationError as e:
        assert list(e.absolute_path)[:2] == ["answer_key", "root_cause"], (
            f"violation not anchored at answer_key/root_cause: {list(e.absolute_path)}")
    else:
        raise AssertionError("schema accepted a False Positive with non-null root_cause")


def test_rejects_attack_without_technique():
    doc = _one_valid_doc()
    doc["answer_key"]["techniques"] = []
    _expect_error(doc, "at least one ATT&CK technique")


def test_rejects_nonempty_actions_reserved_for_stage_3():
    doc = _one_valid_doc()
    doc["answer_key"]["actions"] = [{"action": "isolate_host", "target": "ws_victim"}]
    _expect_error(doc, "schema v2 violation")


def test_detections_load_and_reference_real_steps():
    catalog, _ = _load_corpus()
    for label, sc in catalog.items():
        dets = sc["detections"]
        assert dets, f"{label}: no detections"
        triggerable = ({m["id"] for m in sc["attack_meta"]}
                       | {s["id"] for s in sc.get("supplemental_events", [])})
        det_ids = [d["id"] for d in dets]
        assert len(det_ids) == len(set(det_ids)), f"{label}: dup detection ids"
        is_fp = sc["category"] == "False Positive"
        tp = 0
        for d in dets:
            assert set(d["triggers"]) <= triggerable, f"{label}/{d['id']}: bad triggers"
            assert d["severity"] in ("critical", "high", "medium")
            assert d["rule_type"] in ("sigma_behavioral", "yara")
            if d["rule_type"] == "yara":
                assert d.get("yara_rule_name"), f"{label}/{d['id']}: yara needs name"
            if d["disposition"] == "true_positive":
                tp += 1
                assert not is_fp, f"{label}: FP scenario has a TP detection"
        if not is_fp:
            assert tp >= 1, f"{label}: attack scenario needs a TP detection"


def test_registry_resolution_supplemental_hosts_and_accounts():
    """Every host and account a supplemental event references resolves to the
    scenario's declared environment (canonical) or supplemental_entities. No
    entity exists only inside an event string."""
    catalog, _ = _load_corpus()
    for label, sc in catalog.items():
        sups = sc.get("supplemental_events", [])
        if not sups:
            continue
        env_host_ids = {h["id"] for h in sc["environment"]["hosts"]}
        env_account_ids = {a["id"] for a in sc["environment"]["accounts"]}
        for sup in sups:
            assert sup["host"] in env_host_ids, \
                f"{label}: supplemental {sup['id']} host {sup['host']} unresolved"
            if "user" in sup:
                assert sup["user"] in env_account_ids, \
                    f"{label}: supplemental {sup['id']} user {sup['user']} unresolved"
        # supplemental entities carry a value and are actually referenced by a
        # supplemental event: no entity exists only in metadata (registry
        # resolution, forward direction).
        sup_blob = json.dumps(sups)
        for ent in sc.get("supplemental_entities", []):
            assert ent["value"], f"{label}: empty supplemental_entity value"
            assert ent["value"] in sup_blob, \
                f"{label}: supplemental_entity {ent['id']} value never referenced"


def test_supplemental_events_have_unique_ids_vs_attack():
    catalog, _ = _load_corpus()
    for label, sc in catalog.items():
        step_ids = {m["id"] for m in sc["attack_meta"]}
        sup_ids = [s["id"] for s in sc.get("supplemental_events", [])]
        assert all(s.startswith("sup") for s in sup_ids), f"{label}: sup id prefix"
        assert not (set(sup_ids) & step_ids), f"{label}: id collision"
        assert len(sup_ids) == len(set(sup_ids)), f"{label}: dup supplemental ids"


# Amendment 1 rule: a supplemental event within the attack's plausible
# correlation window must be a declared red herring. 30 min each side.
CORRELATION_WINDOW_S = 1800


def test_in_window_supplemental_events_are_declared_red_herrings():
    catalog, _ = _load_corpus()
    for label, sc in catalog.items():
        for sup in sc.get("supplemental_events", []):
            if abs(sup["offset"]) <= CORRELATION_WINDOW_S:
                assert sup.get("red_herring") is True, (
                    f"{label}/{sup['id']}: offset {sup['offset']}s is within the "
                    f"correlation window but not declared a red herring")


def test_detection_triggers_on_supplemental():
    """The lateral_movement_1 coexisting FP triggers on a supplemental event."""
    catalog, _ = _load_corpus()
    sc = catalog["lateral_movement_1"]
    sup_ids = {s["id"] for s in sc["supplemental_events"]}
    sweep = next(d for d in sc["detections"] if d["id"] == "det_scanner_sweep")
    assert set(sweep["triggers"]) <= sup_ids
    assert sweep["disposition"] == "false_positive"


def test_rejects_detection_triggering_unknown_supplemental():
    doc = _one_valid_doc()  # lateral_movement_1
    doc["detections"][-1]["triggers"] = ["sup_missing"]
    _expect_error(doc, "unknown")


def test_log_clearing_tp_detection_binds_to_1102_step():
    """Part 2 ruling (batch-4 density-safe): the log-clearing TP bound to s5
    (the 1102 step) still exists and carries T1070.001 / Defense Evasion. Batch
    4 adds a surrounding TP on the wevtutil exec (s4); the density additions
    surround the s5 binding, they must never replace it."""
    catalog, _ = _load_corpus()
    dets = catalog["defense_evasion_log_clearing"]["detections"]
    s5_tp = [d for d in dets
             if d["disposition"] == "true_positive" and d["triggers"] == ["s5"]]
    assert len(s5_tp) == 1, "the s5-bound TP must exist exactly once"
    assert s5_tp[0]["mitre"] == {"id": "T1070.001", "tactic": "Defense Evasion"}


def test_rejects_fp_scenario_with_true_positive_detection():
    doc = _one_valid_doc("false_positive_veeam")
    doc["detections"][0]["disposition"] = "true_positive"
    _expect_error(doc, "cannot carry a true_positive detection")


def test_rejects_attack_without_true_positive_detection():
    doc = _one_valid_doc()  # lateral_movement_1, an attack (multiple detections)
    for d in doc["detections"]:
        d["disposition"] = "benign_expected"
    _expect_error(doc, "needs at least one true_positive detection")


def test_rejects_detection_trigger_on_unknown_step():
    doc = _one_valid_doc()
    doc["detections"][0]["triggers"] = ["s99"]
    _expect_error(doc, "unknown attack/supplemental event")


def test_rejects_yara_without_rule_name():
    doc = _one_valid_doc()
    doc["detections"][0]["rule_type"] = "yara"
    doc["detections"][0].pop("yara_rule_name", None)
    _expect_error(doc, "needs a yara_rule_name")


def test_rejects_duplicate_detection_ids():
    doc = _one_valid_doc("malware_usb")
    # duplicate the single detection so two share an id
    dup = dict(doc["detections"][0])
    doc["detections"].append(dup)
    _expect_error(doc, "duplicate detection id")


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


def test_host_status_scenario_declared():
    """Stage 1 addendum note A: host status is authored (online/offline,
    default online), never generated. Invalid values fail loudly."""
    doc = _one_valid_doc()
    doc["environment"]["hosts"][0]["status"] = "offline"
    v2.validate_scenario_v2(doc, _SCHEMA_V2, _SCHEMA_V1, "fixture.yaml")  # valid
    doc["environment"]["hosts"][0]["status"] = "sleeping"
    _expect_error(doc, "schema v2 violation")


# Canonical ATT&CK display names, verified against attack.mitre.org
# 2026-07-16 (13 live-fetched during the follow-up 5 audit; T1562.001 and
# T1070.001 verified live by the reviewer the same day). If MITRE renames a
# technique again, this map is updated together with a triage correction,
# and this test fails loudly until both happen.
CANONICAL_TECHNIQUE_NAMES = {
    "T1091": "Replication Through Removable Media",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1046": "Network Service Discovery",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1110.001": "Brute Force: Password Guessing",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1074.001": "Data Staged: Local Data Staging",
    "T1486": "Data Encrypted for Impact",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    "T1110.003": "Brute Force: Password Spraying",
    "T1071.004": "Application Layer Protocol: DNS",
}


# CORRECTION (2026-07-16): an earlier guard here blacklisted "T1685.005" and
# "Defense Impairment" as NONEXISTENT strings. That was wrong. Both are REAL,
# current ATT&CK v19.1 identifiers, verified live on 2026-07-16:
#   - T1685.005 "Clear Windows Event Logs", sub-technique of T1685 "Disable or
#     Modify Tools", tactic Defense Impairment (TA0112).
#     https://attack.mitre.org/techniques/T1685/005/
#   - Defense Impairment (TA0112) https://attack.mitre.org/tactics/TA0112/
# ATT&CK v19.1 (2026-04-28, current) split Defense Evasion into Stealth (TA0005)
# and Defense Impairment (TA0112) and merged T1562/T1070.001 content under
# T1685. Refs: attack.mitre.org/resources/versions/ ,
# attack.mitre.org/resources/updates/updates-april-2026/ .
#
# Spectyr's corpus is deliberately PINNED to the pre-v19 baseline (v18.1
# semantics) until a scheduled, one-shot v19 migration. So the guard is no
# longer a blacklist of "fake" strings; it is a POSITIVE pin: every technique id
# and tactic name in the corpus must be a pinned-baseline string, so a v19
# successor (T1685.005, "Defense Impairment", "Stealth", ...) entering ahead of
# the migration fails loudly instead of drifting in. See
# docs/classification-rubrics.md (ATT&CK baseline + correction guard).

# v18.1 Enterprise tactic names (the pinned baseline). Every tactic string in
# the corpus must be one of these. "Stealth" and "Defense Impairment" are v19
# and are intentionally absent.
CANONICAL_TACTICS = frozenset({
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
})

# Pinned-baseline technique ids used in DETECTIONS mitre tags but not carried in
# any answer key (so absent from CANONICAL_TECHNIQUE_NAMES). Each is a real
# v18.1 technique; a new one is added deliberately, justified by a live
# technique-page URL (the standing live-URL rule).
PINNED_DETECTION_TECHNIQUES = frozenset({
    "T1218.011",  # System Binary Proxy Execution: Rundll32
    "T1490",      # Inhibit System Recovery
    "T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys
    "T1036.005",  # Masquerading: Match Legitimate Name or Location (v18.1)
    "T1566.002",  # Phishing: Spearphishing Link (also phishing_link's answer key;
                  # borrowed as a detection tag on phishing_1's credential POST)
    # 3d close-out: techniques FP / ambient detections RESEMBLE (mitre-leak fix).
    "T1078",      # Valid Accounts (risky-signin / OAuth FPs)
    "T1543.003",  # Create or Modify System Process: Windows Service (svc/psexec)
    "T1090",      # Proxy (SSL-inspection-bypass FP)
})


def test_corpus_strings_match_pinned_attack_baseline():
    """Pinned-baseline guard (replaces the retracted nonexistent-string guard).
    Every technique id and tactic name in the corpus must be a pinned v18.1
    string, so no v19.1 successor drifts in ahead of the deliberate migration.
    The log-clearing scenario keeps its pinned mapping (T1070.001 / Defense
    Evasion) until that migration."""
    catalog, reviews = _load_corpus()
    pinned_techs = set(CANONICAL_TECHNIQUE_NAMES) | set(PINNED_DETECTION_TECHNIQUES)
    for label, sc in catalog.items():
        for t in sc["answer_key"].get("techniques") or []:
            assert t in CANONICAL_TECHNIQUE_NAMES, (
                f"{label}: answer-key technique {t!r} is not a pinned-baseline id")
        for d in sc.get("detections") or []:
            m = d.get("mitre")
            if not m:
                continue
            assert m["id"] in pinned_techs, (
                f"{label}: detection technique {m['id']!r} is not pinned "
                f"(add to PINNED_DETECTION_TECHNIQUES with a live URL, or it is v19 drift)")
            assert m["tactic"] in CANONICAL_TACTICS, (
                f"{label}: detection tactic {m['tactic']!r} is not a pinned v18.1 tactic")
    for label, r in reviews.items():
        m = r.get("mitre")
        if not m:
            continue
        assert m["id"] in CANONICAL_TECHNIQUE_NAMES, f"{label}: review {m['id']} unpinned"
        assert m["tactic"] in CANONICAL_TACTICS, (
            f"{label}: review tactic {m['tactic']!r} is not a pinned v18.1 tactic")
    # the log-clearing scenario keeps its pinned mapping until the v19 migration
    lc = catalog["defense_evasion_log_clearing"]
    assert lc["answer_key"]["techniques"] == ["T1070.001"], lc["answer_key"]["techniques"]
    assert reviews["defense_evasion_log_clearing"]["mitre"]["id"] == "T1070.001"
    assert reviews["defense_evasion_log_clearing"]["mitre"]["tactic"] == "Defense Evasion"


def test_log_clearing_has_1102_step():
    """The classification_event binding target: the 1102 step must exist."""
    catalog, _ = _load_corpus()
    lc = catalog["defense_evasion_log_clearing"]
    ids_1102 = [m["id"] for m, step in zip(lc["attack_meta"], lc["chain"])
                if str((step.get("key_value_pairs") or {}).get("event_id")) == "1102"]
    assert ids_1102 == ["s5"], f"expected the 1102 step at s5, got {ids_1102}"


def test_technique_names_match_canonical_map():
    """Every stored MITRE display name matches the canonical map, so a future
    ATT&CK rename fails loudly instead of drifting silently."""
    _, reviews = _load_corpus()
    seen = set()
    for label, review in reviews.items():
        mitre = review.get("mitre")
        if not mitre:
            continue
        tid = mitre["id"]
        assert tid in CANONICAL_TECHNIQUE_NAMES, f"{label}: {tid} missing from map"
        assert mitre["name"] == CANONICAL_TECHNIQUE_NAMES[tid], (
            f"{label}: {tid} name {mitre['name']!r} != canonical "
            f"{CANONICAL_TECHNIQUE_NAMES[tid]!r}")
        seen.add(tid)
    assert seen == set(CANONICAL_TECHNIQUE_NAMES), "map and corpus out of sync"


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
    "ACME-VEEAM01": None,            # reference environment: canonical backup role
    "10.0.1.206": None,              # backup server IP (canonical)
    "dpark": "password_spray.yaml",                # v1 literal sprayed accounts
    "mjohnson": "password_spray.yaml",
    "bwilliams": "password_spray.yaml",
    "achen": "password_spray.yaml",
    "jkim": "password_spray.yaml",
    "lgreen": "password_spray.yaml",
    # The proxy's inspection CA name: an org naming choice, not a device
    # reference. The device literal ACME-PROXY-01 that used to sit beside it
    # was corrected to {infra.proxy.hostname} (scenario_corrections.py) and
    # must never reappear.
    "ACME-PROXY-CA": "false_positive_ssl_inspection.yaml",
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
