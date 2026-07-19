"""Stage 3.9B Step 3: permanent leak guard for the Guided catalog picker
(GET /api/guided-catalog). The picker must expose ONLY opaque handles and
player-visible symptom wording; never anything that reveals the classification
the player must make. This payload-level guard is permanent and does NOT replace
the C4 human prose review (nor is it replaced by it).

Guards (owner-specified, Step 3 authorization):
  1. exact field whitelist (entry + top-level)
  2. forbidden disclosures (no answer-key / linkage / category / verdict / ids)
  3. opaque selection identity (shape, not-equal-to-internal-id, resolves to one)
  4. permanent reviewed language denylist over every title + description

The intake-boundary guards (a created incident gets a SEPARATE opaque INC id,
assigned only at creation; the answer key never serializes through the intake
path) live in test_submission_gate.py / the Guided intake tests, added with the
intake itself in the following concern commit.
"""
import re
import sys
import app

ENTRY_KEYS = {"catalog_id", "title", "severity", "description", "difficulty"}
TOP_KEYS = {"catalog", "random_available"}
SEVERITIES = {"Low", "Medium", "High", "Critical"}

# Any of these keys serializing anywhere in the payload is a hard leak.
FORBIDDEN_KEYS = {
    "scenario_id", "label", "scenario_label", "category", "answer_key",
    "disposition", "classification", "verdict", "correct", "correct_answer",
    "tactic", "technique", "mitre", "targets", "required_actions", "actions",
    "answer", "grade", "score", "root_cause", "techniques",
}

# Reviewed denylist over titles + descriptions. Deliberately curated and verified
# to have ZERO false-positives on the approved strings (e.g. "execution" in
# "did not stop at execution" and "suspicious" in "Suspicious Password Reset
# Email" are approved wording and are NOT denied). A word that has a benign
# English meaning in an approved ticket is intentionally absent here.
DENY_TERMS = [
    # attack-category names / unambiguous multi-word tactic phrases
    "malware", "phishing", "ransomware", "lateral movement", "data exfiltration",
    "exfiltration", "command and control", "command-and-control", "brute force",
    "brute-force", "defense evasion", "privilege escalation", "credential access",
    "insider threat", "insider", "reconnaissance", "c2",
    # verdict language
    "false positive", "true positive", "benign", "malicious", "legitimate",
    "threat actor", "adversary", "attacker",
    # reviewed prejudgment terms (softened out of entries 9 / 11 / 17 / 20)
    "unauthorized", "rogue", "compromise", "compromised", "beacon", "beaconing",
]
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
CATALOG_ID = re.compile(r"^cat-[0-9a-f]{12}$")


def _payload():
    return app.app.test_client().get("/api/guided-catalog").get_json()


def _internal_labels_and_categories():
    labels, cats = set(), set()
    for grp in app.CAMPAIGN_LEVELS:
        for cat, sc in grp["scenarios"].items():
            labels.add(sc["scenario_label"])
            cats.add(cat)
    return labels, cats


def test_field_whitelist_exact():
    data = _payload()
    assert set(data.keys()) == TOP_KEYS, f"top-level keys: {set(data.keys())}"
    assert data["random_available"] is True
    assert isinstance(data["catalog"], list) and len(data["catalog"]) == 20
    for e in data["catalog"]:
        assert set(e.keys()) == ENTRY_KEYS, f"entry keys: {set(e.keys())}"
        assert e["severity"] in SEVERITIES, f"bad severity {e['severity']}"
        assert e["difficulty"] is None, "difficulty must be null (no rubric this stage)"
        assert isinstance(e["title"], str) and e["title"].strip()
        assert isinstance(e["description"], str) and e["description"].strip()


def test_no_forbidden_keys_anywhere():
    data = _payload()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                assert k not in FORBIDDEN_KEYS, f"forbidden key '{k}' serialized"
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)


def test_no_internal_label_or_category_in_values():
    data = _payload()
    labels, cats = _internal_labels_and_categories()
    blob = " ".join(
        f'{e["catalog_id"]} {e["title"]} {e["severity"]} {e["description"]}'
        for e in data["catalog"]).lower()
    for lbl in labels:
        assert lbl.lower() not in blob, f"internal label leaked: {lbl}"
    for cat in cats:
        assert not re.search(r"\b" + re.escape(cat.lower()) + r"\b", blob), \
            f"attack category leaked verbatim: {cat}"


def test_catalog_ids_opaque_unique_and_not_internal():
    data = _payload()
    labels, _ = _internal_labels_and_categories()
    ids = [e["catalog_id"] for e in data["catalog"]]
    assert len(set(ids)) == 20, "catalog_ids not unique"
    for cid in ids:
        assert CATALOG_ID.match(cid), f"catalog_id not opaque shape: {cid}"
        assert cid not in labels, "catalog_id equals an internal label"
        assert not any(lbl in cid for lbl in labels), "label is a substring of catalog_id"


def test_every_catalog_id_resolves_to_exactly_one_scenario():
    data = _payload()
    labels, _ = _internal_labels_and_categories()
    for e in data["catalog"]:
        assert app._resolve_catalog_id(e["catalog_id"]) in labels, \
            f"{e['catalog_id']} did not resolve to a scenario"
    resolved = {app._resolve_catalog_id(e["catalog_id"]) for e in data["catalog"]}
    assert len(resolved) == 20 == len(labels), "not a bijection to the 20 scenarios"
    assert app._resolve_catalog_id("cat-000000000000") is None
    assert app._resolve_catalog_id("") is None
    assert app._resolve_catalog_id(None) is None


def test_order_is_neutral_not_category_grouped():
    # Order is by opaque catalog_id; the FP scenarios (every 4th in CAMPAIGN_LEVELS)
    # must not land at fixed positions a player could learn.
    data = _payload()
    fp_labels = {sc["scenario_label"] for grp in app.CAMPAIGN_LEVELS
                 for cat, sc in grp["scenarios"].items() if cat == "False Positive"}
    positions = [i for i, e in enumerate(data["catalog"])
                 if app._resolve_catalog_id(e["catalog_id"]) in fp_labels]
    # not the CAMPAIGN_LEVELS 3,7,11,15,19 pattern
    assert positions != [3, 7, 11, 15, 19], "FP scenarios sit at their catalog positions"


def test_reviewed_language_denylist_clean():
    data = _payload()
    for e in data["catalog"]:
        text = e["title"] + " \n " + e["description"]
        assert not TECHNIQUE_ID.search(text), f"technique id in {e['catalog_id']}"
        for term in DENY_TERMS:
            assert not re.search(r"\b" + re.escape(term) + r"\b", text, re.I), \
                f"denylisted term '{term}' in {e['catalog_id']}: {e['title']}"


def test_picker_wording_equals_incident_briefing_source():
    # C4 amendment: picker and in-game briefing show identical wording because
    # both read CAMPAIGN_LEVELS ticket_title / storyline.
    data = _payload()
    by_id = {app._catalog_id_for(sc["scenario_label"]): sc
             for grp in app.CAMPAIGN_LEVELS for sc in grp["scenarios"].values()}
    for e in data["catalog"]:
        sc = by_id[e["catalog_id"]]
        assert e["title"] == sc["ticket_title"], f"title diverged for {e['catalog_id']}"
        assert e["description"] == sc["storyline"], f"description diverged for {e['catalog_id']}"


# --- Guided intake boundary (Stage 3.9B Step 3, commit 3/6) -----------------
# A Guided start builds EXACTLY ONE incident from the opaque catalog_id (or
# "random"); the incident's opaque INC id is a separate id space stamped only at
# creation (drip), never the catalog_id; the answer key never serializes through
# the intake response.

def _client_session():
    c = app.app.test_client()
    sid = c.get("/api/health").headers["X-Session-ID"]
    return c, sid, app.sessions[sid]


def _cleanup(sid):
    # Pause + pop so the daemon drip thread exits on its next loop. Do NOT delete
    # the session dir out from under a mid-write thread; the boot-time sweep
    # clears orphaned dirs (each gate file re-imports app, which sweeps).
    s = app.sessions.get(sid)
    if s:
        s["paused"] = True
    app.sessions.pop(sid, None)


def test_build_guided_queue_is_exactly_one_chosen_scenario():
    e = _payload()["catalog"][7]
    q = app.build_guided_queue(e["catalog_id"])
    assert isinstance(q, list) and len(q) == 1, "guided queue must be one scenario"
    entry = q[0]
    assert entry["scenario_label"] == app._resolve_catalog_id(e["catalog_id"])
    assert entry["queue_position"] == 1
    assert entry["scenario_id"] is None
    # no incident id at intake; the opaque INC-#### is stamped later at drip
    assert "incident_id" not in entry and "alert_id" not in entry
    for forbidden in ("answer_key", "disposition", "classification", "verdict",
                      "techniques", "actions", "root_cause", "correct"):
        assert forbidden not in entry, f"intake entry leaked {forbidden}"


def test_build_guided_queue_random_and_reject():
    assert len(app.build_guided_queue("random")) == 1
    assert app.build_guided_queue("cat-deadbeef0000") is None
    assert app.build_guided_queue("not-a-catalog-id") is None
    assert app.build_guided_queue(None) is None


def test_guided_start_creates_one_incident_and_leaks_no_answer_key():
    e = _payload()["catalog"][3]
    label = app._resolve_catalog_id(e["catalog_id"])
    c, sid, s = _client_session()
    try:
        r = c.post("/api/start-simulator", headers={"X-Session-ID": sid},
                   json={"game_mode": "guided", "catalog_id": e["catalog_id"],
                         "analyst_name": "T"})
        assert r.status_code == 200, r.status_code
        assert set(r.get_json().keys()) <= {"message", "game_mode"}, r.get_json()
        assert s["queue_length"] == 1 and len(s["alert_queue"]) == 1
        assert s["alert_queue"][0]["scenario_label"] == label
        assert s["game_mode"] == "guided"
    finally:
        _cleanup(sid)


def test_guided_start_unknown_catalog_id_is_400_and_starts_nothing():
    c, sid, s = _client_session()
    try:
        before = s.get("queue_length")
        r = c.post("/api/start-simulator", headers={"X-Session-ID": sid},
                   json={"game_mode": "guided", "catalog_id": "cat-000000000000"})
        assert r.status_code == 400
        assert s.get("queue_length") == before      # session untouched
        assert not s.get("alert_queue")              # no queue built
    finally:
        _cleanup(sid)


def test_inc_and_catalog_ids_are_disjoint_id_spaces():
    for e in _payload()["catalog"]:
        assert e["catalog_id"].startswith("cat-")
        assert not e["catalog_id"].startswith("INC-")  # INC-#### is the incident id space


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"  ok  {t.__name__}")
        except AssertionError as ex:
            failed += 1
            print(f"  FAIL {t.__name__}: {ex}")
    print(f"\n{len(TESTS) - failed}/{len(TESTS)} guided-catalog guard tests passed")
    sys.exit(1 if failed else 0)
