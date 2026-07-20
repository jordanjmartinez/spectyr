"""Stage 4 Phase 3: the query-and-snapshot backend suite (contract S17).

Covers GET /api/events/query (3.1): parse-error shape + the 300 cap, neutral
unknown/foreign incident 404s, empty results, canonical server order,
within-session byte-identical replay, whitelist + recursive planted-marker
leak guards, the structural no-answer-key guard, read-no-mutation, the
scope-subset + participant-host-constraint properties, the corrected
all-range with pre-epoch (negative-offset) events, and the observable
hostname catalog (accepted / suggested / never-revealed). Token validation
and new-count land in 3.2; the transitional route audit in 3.3.

Run: python test_query_read.py  (also: python -m pytest test_query_read.py -q)
"""
import inspect
import json
import os
import shutil
import sys
import time
from datetime import timedelta

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import detection_templates as dt  # noqa: E402
import sim_epoch  # noqa: E402

FEED = set(dt.FEED_EVENT_WHITELIST)
MARKER = "ZZZ_ANSWER_KEY_MARKER_ZZZ"
SID = "scenario-query-x"
INC = "INC-4242"
HOST_A = "ACME-WS12"
HOST_B = "ACME-WS23"


def _api_session():
    client = app.app.test_client()
    sid = client.get("/api/health").headers["X-Session-ID"]
    return client, sid, app.sessions[sid]


def _stop(sid, s):
    app.sessions.pop(sid, None)
    s["paused"] = True
    time.sleep(0.2)          # no writer thread was started in these tests
    shutil.rmtree(s.get("session_dir", ""), ignore_errors=True)


def _ev(i, hostname=HOST_A, ts=None, scenario_id=None, label="seeded_attack",
        **over):
    ev = {"id": f"qe-{i}", "label": label, "timestamp": ts,
          "event_type": "ProcessCreate", "source_type": "Sysmon",
          "severity": "high", "hostname": hostname, "source_ip": "10.0.1.12",
          "user_account": "ACME\\nkhan",
          "message": f"seeded event {i}",
          "key_value_pairs": {"image": "C:\\Windows\\System32\\cmd.exe"}}
    if scenario_id:
        ev["scenario_id"] = scenario_id
    ev.update(over)
    return ev


def _seed_pool(s, sid, n=4, hostname=HOST_A):
    """Seed n attack-shaped events through the PRODUCT append path (event_seq
    stamped, authored timestamps kept), spaced 10s apart from the epoch."""
    epoch = sim_epoch.epoch_dt(sid)
    out = []
    for i in range(n):
        ts = (epoch + timedelta(seconds=10 * (i + 1))).isoformat()
        out.append(app.append_pool_event(s, _ev(i, hostname=hostname, ts=ts)))
    return out


def _q(client, sid, q, scope=None):
    qs = {"q": q}
    if scope is not None:
        qs["scope"] = scope
    return client.get("/api/events/query", query_string=qs,
                      headers={"X-Session-ID": sid})


# --- error shapes ------------------------------------------------------------

def test_parse_error_shape_and_cap():
    client, sid, s = _api_session()
    try:
        r = _q(client, sid, "Sysmon | ProcessCreate")
        assert r.status_code == 400
        err = r.get_json()["error"]
        assert set(err) <= {"position", "reason", "suggestions"}
        assert isinstance(err["position"], int) and "segments" in err["reason"]

        r2 = _q(client, sid, "all | * | * | *" + " " * 300)
        assert r2.status_code == 400
        e2 = r2.get_json()["error"]
        assert e2["position"] == 300 and "300 character cap" in e2["reason"]
    finally:
        _stop(sid, s)


def test_unknown_and_foreign_incident_scope_neutral_404():
    client_a, sid_a, s_a = _api_session()
    client_b, sid_b, s_b = _api_session()
    try:
        s_b.setdefault("incident_index", {})["INC-9999"] = "scenario-b"
        unknown = _q(client_a, sid_a, "all | * | * | *", scope="INC-0000")
        foreign = _q(client_a, sid_a, "all | * | * | *", scope="INC-9999")
        assert unknown.status_code == foreign.status_code == 404
        assert unknown.data == foreign.data, \
            "foreign incident must be indistinguishable from unknown"
        assert unknown.get_json() == {"error": "Unknown incident"}
    finally:
        _stop(sid_a, s_a)
        _stop(sid_b, s_b)


def test_empty_result_is_200_with_token():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid)
        r = _q(client, sid, 'all | * | * | message contains "no-such-needle"')
        assert r.status_code == 200
        body = r.get_json()
        assert body["count"] == 0 and body["rows"] == []
        assert body["token"], "empty results still mint a valid token"
    finally:
        _stop(sid, s)


# --- canonical order and replay ----------------------------------------------

def test_rows_in_canonical_order():
    client, sid, s = _api_session()
    try:
        epoch = sim_epoch.epoch_dt(sid)
        same_ts = (epoch + timedelta(seconds=50)).isoformat()
        app.append_pool_event(s, _ev("a", ts=same_ts))               # seq 1
        app.append_pool_event(s, _ev("b", ts=same_ts))               # seq 2
        app.append_pool_event(
            s, _ev("c", ts=(epoch + timedelta(seconds=20)).isoformat()))
        body = _q(client, sid, "all | * | * | *").get_json()
        ids = [r["id"] for r in body["rows"]]
        # ts desc; within the tie, event_seq desc
        assert ids == ["qe-b", "qe-a", "qe-c"], ids
        seqs = [r["event_seq"] for r in body["rows"]]
        assert seqs == [2, 1, 3]
    finally:
        _stop(sid, s)


def test_identical_identity_replays_byte_identical():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid)
        q = '1h | Sysmon | ProcessCreate | message contains "seeded"'
        r1 = _q(client, sid, q)
        r2 = _q(client, sid, q)
        assert r1.status_code == r2.status_code == 200
        assert r1.data == r2.data, \
            "identical identity in a static session must replay byte-identical" \
            " (rows, identity, and token alike)"
    finally:
        _stop(sid, s)


# --- leak guards -------------------------------------------------------------

def _all_strings(obj):
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_all_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_all_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def test_rows_serialize_only_the_whitelist_and_no_planted_marker():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid, n=2)
        app.append_pool_event(s, _ev(
            "mark", ts=sim_epoch.epoch_iso(sid),
            category=MARKER, storyline=MARKER, threat_pattern=MARKER,
            level_name=MARKER, alert_id=INC, analyst_category=MARKER,
            __future_internal__=MARKER))
        body = _q(client, sid, "all | * | * | *").get_json()
        assert body["count"] == 3
        for row in body["rows"]:
            assert set(row) <= FEED, f"row leaked keys: {set(row) - FEED}"
        hits = [v for v in _all_strings(body) if MARKER in v]
        assert not hits, f"planted marker leaked: {hits}"
    finally:
        _stop(sid, s)


def test_query_read_structural_no_answer_key_inputs():
    """Same technique as test_incident_scope's structural guard: the query
    path references only observable inputs."""
    for fn in (app.query_events, app.query_new_count, app._visible_rows,
               app._match_rows, app._resolve_timeframe,
               app._observable_hostnames, app._order_rows,
               app._mint_snapshot_token, app._verify_snapshot_token):
        src = inspect.getsource(fn)
        for banned in ("expected_actions", "scenario_grading",
                       "_grading_record_for", "grading_rec", "answer_key"):
            assert banned not in src, f"{fn.__name__} references {banned}"


def test_query_read_does_not_mutate():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid)
        path = s["paths"]["generated_logs"]
        with open(path, "rb") as f:
            before = f.read()
        seq_before = s["event_seq"]
        for q in ("all | * | * | *", '1h | Sysmon | * | severity == "high"'):
            assert _q(client, sid, q).status_code == 200
        with open(path, "rb") as f:
            assert f.read() == before, "query reads must not touch the pool"
        assert s["event_seq"] == seq_before
    finally:
        _stop(sid, s)


# --- incident scope ----------------------------------------------------------

def test_scoped_results_subset_and_constraint_equals_participant_hosts():
    client, sid, s = _api_session()
    try:
        epoch = sim_epoch.epoch_dt(sid)
        s.setdefault("incident_index", {})[INC] = SID
        app.append_pool_event(s, _ev(
            "s1", hostname=HOST_A, scenario_id=SID,
            ts=(epoch + timedelta(seconds=10)).isoformat()))
        app.append_pool_event(s, _ev(
            "s2", hostname=HOST_A, scenario_id=SID,
            ts=(epoch + timedelta(seconds=20)).isoformat()))
        app.append_pool_event(s, _ev(
            "o1", hostname=HOST_B,
            ts=(epoch + timedelta(seconds=30)).isoformat()))
        q = "all | * | * | *"
        session_rows = _q(client, sid, q).get_json()["rows"]
        scoped = _q(client, sid, q, scope=INC).get_json()
        scoped_ids = {r["id"] for r in scoped["rows"]}
        assert scoped_ids <= {r["id"] for r in session_rows}, \
            "scoped result must be a subset of the session result"
        assert {r["hostname"] for r in scoped["rows"]} == {HOST_A}, \
            "the implicit constraint equals the participant hosts"
        assert "qe-o1" not in scoped_ids
        assert scoped["identity"]["scope"] == INC
        # Amendment E2: the executed participant-host set is frozen into the
        # identity, sorted and deduplicated; session-wide carries [].
        assert scoped["identity"]["resolved_scope_hosts"] == [HOST_A]
        session_wide = _q(client, sid, q).get_json()
        assert session_wide["identity"]["resolved_scope_hosts"] == []
    finally:
        _stop(sid, s)


# --- the corrected all-range (scaffold review correction 1) ------------------

def test_all_range_includes_negative_offset_supplemental():
    """Authored supplemental events carry negative offsets (proven on the
    live corpus by test_sim_epoch's negative-offset check: data_exfil_archive
    at -80s/-65s), so visible events can predate the epoch. The corrected
    `all` range starts at the MINIMUM visible occurrence, never the epoch;
    this fixture seeds a pre-epoch backstory event and proves
    `all | * | * | *` returns every visible event."""
    client, sid, s = _api_session()
    try:
        epoch = sim_epoch.epoch_dt(sid)
        pre = (epoch - timedelta(seconds=80)).isoformat()
        app.append_pool_event(s, _ev("pre", ts=pre))            # backstory
        app.append_pool_event(
            s, _ev("post", ts=(epoch + timedelta(seconds=30)).isoformat()))
        body = _q(client, sid, "all | * | * | *").get_json()
        assert body["count"] == 2, "the pre-epoch event must be included"
        assert {r["id"] for r in body["rows"]} == {"qe-pre", "qe-post"}
        rng = body["identity"]["resolved_range"]
        assert rng["start"] == pre, \
            "all-range must start at the minimum visible occurrence"
        assert rng["end"] == body["rows"][0]["timestamp"]
    finally:
        _stop(sid, s)


# --- observable hostname catalog (Phase 3 focus 5) ---------------------------

def test_observable_hostname_accepted():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid, hostname=HOST_A)
        r = _q(client, sid, f"all | {HOST_A} | * | *")
        assert r.status_code == 200
        assert r.get_json()["identity"]["canonical_query"] == \
            f"all | {HOST_A} | * | *"
        # case-insensitive resolution to the observable canonical spelling
        r2 = _q(client, sid, f"all | {HOST_A.lower()} | * | *")
        assert r2.status_code == 200
        assert r2.get_json()["identity"]["canonical_query"] == \
            f"all | {HOST_A} | * | *"
    finally:
        _stop(sid, s)


def test_misspelling_suggests_only_observable_hostnames():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid, hostname=HOST_A)          # ACME-WS12 observable
        r = _q(client, sid, "all | ACME-WS1Z | * | *")
        assert r.status_code == 400
        err = r.get_json()["error"]
        assert "unknown sensor" in err["reason"]
        sugg = [x.lower() for x in err.get("suggestions", [])]
        assert HOST_A.lower() in sugg, \
            "a misspelling may suggest an observable hostname"
        observable = {HOST_A.lower()}
        families = {f.lower() for f in
                    ("Sysmon", "Windows Security", "Proxy", "DNS", "Firewall",
                     "Azure AD", "Veeam", "Defender")}
        assert set(sugg) <= observable | families, \
            f"suggestions revealed non-observable names: {sugg}"
    finally:
        _stop(sid, s)


def test_unseen_repository_hostname_rejected_and_never_suggested():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid, hostname=HOST_A)
        # ACME-WS01 and ACME-VEEAM01 are real repository roster names the
        # session has never observed: they must neither parse nor surface.
        reasons = set()
        for unseen in ("ACME-WS01", "ACME-VEEAM01", "TOTALLY-FAKE-HOST"):
            r = _q(client, sid, f"all | {unseen} | * | *")
            assert r.status_code == 400, \
                f"unseen repository hostname {unseen} must not be accepted"
            body = r.get_json()
            strings = " ".join(_all_strings(body)).lower()
            assert unseen.lower() not in strings, \
                f"response revealed the unseen repository hostname {unseen}"
            reasons.add(body["error"]["reason"])
        assert len(reasons) == 1, \
            "unseen-real and gibberish sensors must be indistinguishable"
        # and a near-miss of an unseen name still only suggests observables
        r = _q(client, sid, "all | ACME-VEEAM0 | * | *")
        assert r.status_code == 400
        sugg = [x.lower() for x in r.get_json()["error"].get("suggestions", [])]
        assert "acme-veeam01" not in sugg
    finally:
        _stop(sid, s)


# --- Phase 3.2: token security and the refresh-now new-count ----------------

def _new_count(client, sid, token, extra=None):
    qs = {"token": token}
    if extra:
        qs.update(extra)
    return client.get("/api/events/query/new-count", query_string=qs,
                      headers={"X-Session-ID": sid})


def test_invalid_tokens_fail_neutrally_and_identically():
    """Every invalid-token class returns the byte-identical neutral 400:
    altered payload, altered MAC, garbage, empty, foreign-session,
    post-Reset, post-start (Practice Another's path), and the post-restart
    stale-session case, where the session middleware (get_session,
    app.py:224-229) auto-creates a FRESH session for a stale session id, so
    the stale token hits the MAC path under a brand-new secret and fails
    exactly like every other class."""
    client, sid, s = _api_session()
    client_b, sid_b, s_b = _api_session()
    fresh_sid = None
    try:
        _seed_pool(s, sid)
        _seed_pool(s_b, sid_b)
        token = _q(client, sid, "all | * | * | *").get_json()["token"]
        assert _new_count(client, sid, token).status_code == 200  # sane baseline
        p64, m64 = token.split(".")
        altered_payload = (("A" if p64[0] != "A" else "B") + p64[1:]) + "." + m64
        altered_mac = p64 + "." + (("A" if m64[0] != "A" else "B") + m64[1:])
        foreign = _q(client_b, sid_b, "all | * | * | *").get_json()["token"]

        bodies = []
        for tok in (altered_payload, altered_mac, "garbage", "", foreign):
            r = _new_count(client, sid, tok)
            assert r.status_code == 400
            bodies.append(r.data)

        # post-Reset: the same session rotates its secret
        assert client.post("/api/reset-simulator",
                           headers={"X-Session-ID": sid}).status_code == 200
        r = _new_count(client, sid, token)
        assert r.status_code == 400
        bodies.append(r.data)

        # post-start (the Practice Another path): rotate again
        _seed_pool(s, sid, n=1)
        token2 = _q(client, sid, "all | * | * | *").get_json()["token"]
        assert client.post(
            "/api/start-simulator",
            headers={"X-Session-ID": sid, "Content-Type": "application/json"},
            data=json.dumps({"game_mode": "guided", "catalog_id": "random",
                             "analyst_name": "Probe"})).status_code == 200
        r = _new_count(client, sid, token2)
        assert r.status_code == 400
        bodies.append(r.data)

        # post-'restart': drop the session (as a process restart would) and
        # present the stale sid + stale token. The middleware must
        # auto-create a fresh session (new id in the response header) and
        # the body must be the same neutral 400.
        app.sessions.pop(sid, None)
        s["paused"] = True
        r = _new_count(client, sid, token2)
        assert r.status_code == 400
        bodies.append(r.data)
        fresh_sid = r.headers["X-Session-ID"]
        assert fresh_sid != sid, "middleware must mint a fresh session id"
        assert fresh_sid in app.sessions, "the fresh session must exist"

        assert len(set(bodies)) == 1, \
            "all invalid-token classes must be byte-identical"
        assert json.loads(bodies[0]) == {"error": "Unknown token"}
    finally:
        time.sleep(1.2)          # the started writer thread drains
        shutil.rmtree(s.get("session_dir", ""), ignore_errors=True)
        _stop(sid_b, s_b)
        if fresh_sid and fresh_sid in app.sessions:
            _stop(fresh_sid, app.sessions[fresh_sid])


def test_new_count_matches_refresh_now_semantics_and_pool_growth():
    """R16 refresh-now: the count is what Refresh would add NOW -- TIMEFRAME
    re-resolved at count time -- so a matching event time-stamped BEYOND the
    token's original window end still counts (the strict-window meaning
    would report 0 for it). pool_growth is the all-events counter."""
    client, sid, s = _api_session()
    try:
        epoch = sim_epoch.epoch_dt(sid)
        _seed_pool(s, sid, n=3)                       # ts +10s..+30s, seq 1-3
        q = '1h | Sysmon | ProcessCreate | message contains "seeded"'
        minted = _q(client, sid, q).get_json()
        token = minted["token"]
        assert minted["identity"]["cutoff_seq"] == 3
        original_end = minted["identity"]["resolved_range"]["end"]

        # two matching + one non-matching arrival, all AFTER the original end
        for i, (msg, secs) in enumerate((("seeded late one", 40),
                                         ("seeded late two", 50),
                                         ("unrelated noise", 60))):
            app.append_pool_event(s, _ev(
                f"new-{i}", ts=(epoch + timedelta(seconds=secs)).isoformat(),
                message=msg))
        assert minted["identity"]["resolved_range"]["end"] == original_end

        body = _new_count(client, sid, token).get_json()
        assert body == {"new_count": 2, "pool_growth": 3}, body
        # deterministic and read-only: identical on a second call
        assert _new_count(client, sid, token).get_json() == body
    finally:
        _stop(sid, s)


def test_new_count_request_carries_token_only():
    """Edited bar text structurally cannot alter the count: extra q/scope
    parameters are ignored -- the response equals the token-only response."""
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid)
        token = _q(client, sid, "all | * | * | *").get_json()["token"]
        plain = _new_count(client, sid, token)
        noisy = _new_count(client, sid, token,
                           extra={"q": '1h | * | * | message contains "zz"',
                                  "scope": "INC-1111"})
        assert plain.status_code == noisy.status_code == 200
        assert plain.data == noisy.data
    finally:
        _stop(sid, s)


def test_new_count_does_not_mutate():
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid)
        token = _q(client, sid, "all | * | * | *").get_json()["token"]
        path = s["paths"]["generated_logs"]
        with open(path, "rb") as f:
            before = f.read()
        seq_before = s["event_seq"]
        assert _new_count(client, sid, token).status_code == 200
        with open(path, "rb") as f:
            assert f.read() == before
        assert s["event_seq"] == seq_before
    finally:
        _stop(sid, s)


def test_token_reexecution_equals_identity_reexecution():
    """The token identifies, it does not store: the displayed set the count
    read reconstructs from the token equals a fresh execution of the same
    canonical query (deterministic replay), evidenced by a zero count on an
    unchanged pool."""
    client, sid, s = _api_session()
    try:
        _seed_pool(s, sid)
        token = _q(client, sid, "all | * | * | *").get_json()["token"]
        assert _new_count(client, sid, token).get_json() == \
            {"new_count": 0, "pool_growth": 0}
    finally:
        _stop(sid, s)


# --- Phase 3.4 (Amendment E2): pre-seal incident-scope determinism -----------

def test_preseal_scope_growth_replay_and_refresh_semantics():
    """The narrow Amendment E2 battery, on the reviewer's exact scenario:

    A multi-host incident is snapshotted mid-chain when only Host A is
    observable, while sub-cutoff BACKGROUND events for the later Host B
    already sit in the pool. The drip then reveals Host B as a participant.
    Proves: (1) replay/reconstruction of the original identity is
    byte-identical and its baseline never changes (the frozen
    resolved_scope_hosts governs, never the grown current set); (2)
    new-count equals what a real Refresh now adds, INCLUDING the newly
    eligible sub-cutoff Host B background rows; (3) an actual Refresh mints
    a new identity whose resolved_scope_hosts includes Host B; (4) nothing
    hidden serializes (whitelist rows; the pre-growth scoped response never
    mentions Host B)."""
    client, sid, s = _api_session()
    try:
        epoch = sim_epoch.epoch_dt(sid)
        # started sessions carry the epoch in world.started_at; the append
        # helper stamps background occurrence times from it (product path)
        s["world"]["started_at"] = sim_epoch.epoch_iso(sid)
        s.setdefault("incident_index", {})[INC] = SID
        # sub-cutoff BACKGROUND event on the future participant Host B
        # (normal traffic never enters observable scope attribution); its
        # occurrence time is stamped by the product helper: epoch + 3s x 1
        app.append_pool_event(s, _ev(
            "bgB", hostname=HOST_B, label="normal_traffic", ts=None))  # seq 1
        # Host A's chain step -- the only participant so far
        app.append_pool_event(s, _ev(
            "s1", hostname=HOST_A, scenario_id=SID,
            ts=(epoch + timedelta(seconds=10)).isoformat()))           # seq 2

        q = "all | * | * | *"
        snap = _q(client, sid, q, scope=INC).get_json()
        token = snap["token"]
        assert snap["identity"]["resolved_scope_hosts"] == [HOST_A]
        assert snap["identity"]["cutoff_seq"] == 2
        assert [r["id"] for r in snap["rows"]] == ["qe-s1"], \
            "Host B's background row is out of scope pre-growth"
        pre_strings = " ".join(_all_strings(snap))
        assert HOST_B not in pre_strings, \
            "the pre-growth scoped response must not mention the future host"
        baseline_before = json.dumps(_reconstruct(s, sid, snap["identity"]),
                                     sort_keys=True)

        # the drip continues: Host B joins the incident's observable scope
        app.append_pool_event(s, _ev(
            "s2", hostname=HOST_B, scenario_id=SID,
            ts=(epoch + timedelta(seconds=20)).isoformat()))           # seq 3

        # (1) frozen-identity reconstruction is byte-identical after growth
        baseline_after = json.dumps(_reconstruct(s, sid, snap["identity"]),
                                    sort_keys=True)
        assert baseline_before == baseline_after, \
            "the reconstructed original baseline must never change"

        # (2) refresh-now counts the newly eligible rows: Host B's chain
        # step AND its SUB-CUTOFF background row (never displayed)
        counts = _new_count(client, sid, token).get_json()
        assert counts["pool_growth"] == 1
        assert counts["new_count"] == 2, counts

        # (3) a real Refresh re-resolves and freezes the grown host set
        refreshed = _q(client, sid, q, scope=INC).get_json()
        assert refreshed["identity"]["resolved_scope_hosts"] == \
            sorted([HOST_A, HOST_B])
        refreshed_ids = {r["id"] for r in refreshed["rows"]}
        assert refreshed_ids == {"qe-s1", "qe-s2", "qe-bgB"}
        # new-count == what the Refresh actually added
        displayed_ids = {r["id"] for r in snap["rows"]}
        assert counts["new_count"] == len(refreshed_ids - displayed_ids)

        # (4) whitelist discipline on every row of both snapshots
        for row in snap["rows"] + refreshed["rows"]:
            assert set(row) <= FEED
    finally:
        _stop(sid, s)


def _reconstruct(s, sid, identity):
    """White-box replay of a snapshot identity exactly as the count read
    reconstructs its displayed baseline: the FROZEN resolved_scope_hosts,
    the stored range, the stored cutoff."""
    rows, _cur, world_hosts = app._visible_rows(s)
    catalog = app._event_catalog().with_hostnames(
        app._observable_hostnames(rows, world_hosts))
    import lcql as _lcql
    query = _lcql.parse(identity["canonical_query"], catalog=catalog)
    frozen = (set(identity["resolved_scope_hosts"])
              if identity["scope"] != "session" else None)
    return app._order_rows(app._match_rows(
        rows, query,
        (identity["resolved_range"]["start"],
         identity["resolved_range"]["end"]),
        frozen, identity["cutoff_seq"]))


# --- Phase 3.3: transitional route audit -------------------------------------

def test_route_audit_single_event_query_path():
    """Transitional form (tightened at Phase 8 when /api/fake-events and
    /api/grouped-alerts retire): event ROWS are served by exactly two
    routes -- the legacy /api/fake-events and /api/events/query -- proven
    structurally: rows can only be emitted through the sanitize_feed_event
    serializer or the _visible_rows helper, and the only /api views
    referencing either are the audited set. The count read references
    _visible_rows but serializes counts only (no rows key in its source)."""
    import re
    views = {r.rule: app.app.view_functions[r.endpoint]
             for r in app.app.url_map.iter_rules()
             if r.rule.startswith("/api/")}
    emitters = sorted(
        rule for rule, fn in views.items()
        if re.search(r"sanitize_feed_event|_visible_rows",
                     inspect.getsource(fn)))
    assert emitters == ["/api/events/query", "/api/events/query/new-count",
                        "/api/fake-events"], \
        f"unexpected event-serving routes: {emitters}"
    src = inspect.getsource(app.query_new_count)
    assert '"rows"' not in src and "'rows'" not in src, \
        "the count read must never serialize rows"


def test_no_mode_specific_event_endpoint():
    """No event-pool route is mode-addressed: every /api route whose view
    touches the generated_logs pool or the event serializer has a mode-free
    path. (/api/guided-catalog is the mode PICKER; it does not read the
    pool and is not an event endpoint.)"""
    import re
    views = {r.rule: app.app.view_functions[r.endpoint]
             for r in app.app.url_map.iter_rules()
             if r.rule.startswith("/api/")}
    mode_words = re.compile(r"guided|analyst|hardcore|training|mode", re.I)
    pool_readers = [
        rule for rule, fn in views.items()
        if re.search(r"generated_logs|sanitize_feed_event|_visible_rows",
                     inspect.getsource(fn))]
    assert "/api/events/query" in pool_readers
    offenders = [r for r in pool_readers if mode_words.search(r)]
    assert not offenders, f"mode-addressed event routes: {offenders}"


if __name__ == "__main__":
    import traceback
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok  {name}")
        except Exception:
            failed += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
    if failed:
        print(f"[test_query_read] {failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"[test_query_read] all {len(tests)} passed")
