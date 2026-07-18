"""Engine tests for Stage 3c.5 (the remove_persistence increment).

Run: python test_persistence_response.py

These cover the persistence-response engine end to end, independent of any
scenario answer key (no scenario authors a persistence action until the
post-approval re-scaffold): WMI 19/20/21 materialize as ONE stable
persistence row; the dual-flag state model keeps a required action reachable
under either ordering; remove_persistence executes, scores, and is
UI-reachable; the raw correlated identity never serializes; and the loader's
achievability validator accepts only authored, complete subscriptions.
"""
import copy
import os

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402
import action_overlay as ao  # noqa: E402
import persistence as p  # noqa: E402
import scenario_loader_v2 as slv2  # noqa: E402
import snapshot_generator as sg  # noqa: E402

WS = "ACME-WS12"
SEED = "test-session-3c5"
STARTED = "2026-07-17T12:00:00+00:00"
RUN_KEY = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsServices"
PAYLOAD = r"C:\Users\Public\svchost32.exe"


# --- fixtures ------------------------------------------------------------------

def _host(hostname=WS):
    return {"id": "h_ws", "role": "workstation", "hostname": hostname,
            "ip": "10.0.1.12", "os": "Windows 11 Pro", "status": "online"}


def _tagged(kvp, host=WS):
    return ({"source_type": "Sysmon", "event_type": str(kvp["event_id"]),
             "key_value_pairs": kvp}, {"host": host})


def _wmi_events(consumer="WindowsUpdConsumer", filt="WindowsUpdFilter",
                dest="powershell.exe -enc AAAA", complete=True, host=WS):
    evs = [
        _tagged({"event_id": 19, "name": filt, "event_namespace": r"root\CimV2",
                 "query": "SELECT * FROM __InstanceModificationEvent"}, host),
        _tagged({"event_id": 20, "name": consumer,
                 "type": "CommandLineEventConsumer", "destination": dest}, host),
    ]
    if complete:
        evs.append(_tagged(
            {"event_id": 21,
             "consumer": f'CommandLineEventConsumer.Name="{consumer}"',
             "filter": f'__EventFilter.Name="{filt}"'}, host))
    return evs


def _run_key_event(key=RUN_KEY, payload=PAYLOAD, host=WS):
    return _tagged({"event_id": 13, "target_object": key, "details": payload}, host)


def _world(extra_events=None, hostname=WS):
    snap = sg.build_baseline(_host(hostname), {"username": "nkhan", "domain": "ACME"},
                             SEED, app.RESERVED_PIDS, app.SERVERS, STARTED)
    if extra_events:
        sg.merge_events(snap, extra_events, SEED)
        sg._sort_merged(snap)
    return {"hosts": {hostname: snap}, "started_at": STARTED}, snap


def _view(snap, overlay):
    return ao.apply_overlay(copy.deepcopy(sg.public_view(snap)), overlay)


def _persist_entry(reg, persist_type=None, entry_name=None):
    for e in reg.values():
        if e["kind"] != "persistence":
            continue
        if persist_type and e["persist_type"] != persist_type:
            continue
        if entry_name and e["entry"] != entry_name:
            continue
        return e
    return None


# --- WMI materialization -------------------------------------------------------

def test_wmi_events_materialize_one_persistence_row():
    _, snap = _world(extra_events=_wmi_events())
    wmi = [a for a in snap["autoruns"] if a.get("persist_type") == "wmi_subscription"]
    assert len(wmi) == 1
    row = wmi[0]
    assert row["name"] == "WindowsUpdConsumer"          # display name
    assert row["file_path"] is None                      # registration-only
    assert tuple(row["identity"])[:2] == (WS, "wmi_subscription")
    assert "powershell" in row["command"]


def test_duplicate_wmi_drips_dedup_to_one_row():
    ev = _wmi_events()
    _, snap = _world(extra_events=ev)
    sg.merge_events(snap, ev, SEED)   # a second identical drip
    sg._sort_merged(snap)
    wmi = [a for a in snap["autoruns"] if a.get("persist_type") == "wmi_subscription"]
    assert len(wmi) == 1, "an identical re-drip must not clone the persistence row"


def test_incomplete_wmi_subscription_materializes_no_row():
    _, snap = _world(extra_events=_wmi_events(complete=False))
    assert not any(a.get("persist_type") == "wmi_subscription" for a in snap["autoruns"])


def test_run_key_event_materializes_file_backed_persistence():
    _, snap = _world(extra_events=[_run_key_event()])
    row = next(a for a in snap["autoruns"] if a.get("name") == "WindowsServices")
    assert row["persist_type"] == "run_key"
    assert row["file_path"] == ao.norm_path(PAYLOAD)     # file-backed
    assert tuple(row["identity"])[:2] == (WS, "run_key")


# --- remove_persistence execute ------------------------------------------------

def test_remove_persistence_clears_wmi_row_and_repeats_no_op():
    world, snap = _world(extra_events=_wmi_events())
    reg = ao.build_entity_registry(world, {}, SEED)
    entry = _persist_entry(reg, "wmi_subscription")
    overlay = ao.new_overlay()
    assert ao.execute(world, overlay, entry, "remove_persistence")[0] == ao.SUCCESS
    assert ao.execute(world, overlay, entry, "remove_persistence")[0] == ao.NO_OP
    view = _view(snap, overlay)
    assert not any(a.get("persist_type") == "wmi_subscription" for a in view["autoruns"])


def test_remove_persistence_unknown_artifact_fails_precondition():
    world, snap = _world(extra_events=_wmi_events())
    entry = {"kind": "persistence", "hostname": WS, "persist_type": "wmi_subscription",
             "entry": "ghost", "identity": (WS, "wmi_subscription", "x", "y", "z")}
    outcome, reason = ao.execute(world, ao.new_overlay(), entry, "remove_persistence")
    assert outcome == ao.FAILED and "not found" in reason.lower()


# --- dual-flag state model (the GENERAL RULE) ----------------------------------

def test_dual_flag_both_orders_keep_the_other_action_reachable():
    """A file-backed Run key is required-delete + acceptable-remove. Under
    EITHER ordering the not-yet-taken action's row must still be live and
    executable: no acceptable action renders a required one unreachable."""
    world, snap = _world(extra_events=[_run_key_event()])
    reg = ao.build_entity_registry(world, {}, SEED)
    persist = _persist_entry(reg, "run_key", "WindowsServices")
    npath = ao.norm_path(PAYLOAD)
    file_entry = next(e for e in reg.values()
                      if e["kind"] == "file" and e["path"] == npath)

    def do(overlay, which):
        if which == "delete":
            return ao.execute(world, overlay, file_entry, "delete_file")
        return ao.execute(world, overlay, persist, "remove_persistence")

    for first, second in (("delete", "remove"), ("remove", "delete")):
        overlay = ao.new_overlay()
        assert do(overlay, first)[0] == ao.SUCCESS
        # the row still renders after the first action (one flag left)
        view = _view(snap, overlay)
        row = next((a for a in view["autoruns"] if a.get("name") == "WindowsServices"), None)
        assert row is not None, f"{first}-first dropped the row prematurely"
        # the second action still succeeds, then the row is gone
        assert do(overlay, second)[0] == ao.SUCCESS
        view2 = _view(snap, overlay)
        assert all(a.get("name") != "WindowsServices" for a in view2["autoruns"]), \
            f"{first}->{second}: row survived full neutralization"


# --- entity ids, reachability, leak guard --------------------------------------

def test_persistence_entity_ids_do_not_collide_on_colon_bearing_paths():
    """Safeguard: the client id is a length-prefixed digest of a structured
    field tuple, not a delimiter join, so two different WMI path combinations
    that a ':'-join would have merged still get distinct entity ids."""
    id1 = ao.entity_id(SEED, "persistence", "H", "wmi_subscription", r"root\cimv2", "a", "b:c")
    id2 = ao.entity_id(SEED, "persistence", "H", "wmi_subscription", r"root\cimv2", "a:b", "c")
    assert id1 != id2, "distinct field tuples must not collide"
    assert ao.ENTITY_ID_RE.match(id1) and ao.ENTITY_ID_RE.match(id2)


def test_persistence_ids_are_shape_uniform_and_resolve():
    world, snap = _world(extra_events=_wmi_events() + [_run_key_event()])
    reg = ao.build_entity_registry(world, {}, SEED)
    persistences = [e for e in reg.values() if e["kind"] == "persistence"]
    assert len(persistences) >= 2  # the WMI sub + Run keys (malicious + benign)
    for eid, e in reg.items():
        assert ao.ENTITY_ID_RE.match(eid)


def test_annotate_view_strips_identity_and_stamps_persistence_id():
    world, snap = _world(extra_events=_wmi_events() + [_run_key_event()])
    reg = ao.build_entity_registry(world, {}, SEED)
    view = ao.annotate_view(_view(snap, ao.new_overlay()), SEED)
    import json
    blob = json.dumps(view)
    assert "id_parts" not in blob, "server-side composite id_parts leaked"
    for a in view["autoruns"]:
        assert "identity" not in a and "id_parts" not in a
        pid = a["persistence_entity_id"]
        assert ao.ENTITY_ID_RE.match(pid)
        assert reg[pid]["kind"] == "persistence"


def test_ui_reachable_for_authored_persistence_target():
    world, snap = _world(extra_events=_wmi_events())
    row = next(a for a in snap["autoruns"] if a.get("persist_type") == "wmi_subscription")
    target = {"hostname": WS, "persistence": "wmi:WindowsUpdConsumer",
              "identity": list(row["identity"])}
    assert app.ui_reachable("remove_persistence", target, world, set())
    ghost = {"hostname": WS, "persistence": "wmi:none",
             "identity": [WS, "wmi_subscription", "n", "s", "e"]}
    assert not app.ui_reachable("remove_persistence", ghost, world, set())


# --- scoring -------------------------------------------------------------------

def _grading():
    return [{"scenario_id": "scenario-x", "reviewed": True,
             "hostnames": {WS}, "accounts": set()}]


def test_remove_persistence_scores_required_on_occurrence():
    ident = (WS, "wmi_subscription", r"root\cimv2",
             'commandlineeventconsumer.name="c"', '__eventfilter.name="f"')
    expected = [{"scenario_id": "scenario-x", "eid": "a1", "status": "required",
                 "action": "remove_persistence", "after": [],
                 "target": {"hostname": WS, "persistence": "wmi:c",
                            "identity": list(ident)}}]
    executed = [{"seq": 1, "action": "remove_persistence",
                 "target": {"hostname": WS, "identity": list(ident)}}]
    r = app.compute_action_score(expected, executed, set(), _grading())
    assert r["correct"] == 1 and r["missed"] == 0 and r["collateral"] == 0


def test_off_list_persistence_removal_is_collateral():
    other = (WS, "run_key", r"hkcu\software\microsoft\windows\currentversion\run",
             "onedrive")
    executed = [{"seq": 1, "action": "remove_persistence",
                 "target": {"hostname": WS, "identity": list(other)}}]
    r = app.compute_action_score([], executed, set(), _grading())
    assert r["collateral"] == 1


# --- selector resolution -------------------------------------------------------

def test_resolve_selector_ambiguous_wmi_fails_closed():
    arts = p.correlate_wmi(
        WS,
        [{"event_id": 19, "name": "F1", "event_namespace": r"root\CimV2", "query": "A"},
         {"event_id": 19, "name": "F2", "event_namespace": r"root\CimV2", "query": "B"}],
        [{"event_id": 20, "name": "C", "type": "CommandLineEventConsumer", "destination": "d"}],
        [{"event_id": 21, "consumer": 'CommandLineEventConsumer.Name="C"',
          "filter": '__EventFilter.Name="F1"'},
         {"event_id": 21, "consumer": 'CommandLineEventConsumer.Name="C"',
          "filter": '__EventFilter.Name="F2"'}])
    rows = [sg._wmi_row(WS, a) for a in arts]
    assert len(rows) == 2, "two distinct subscriptions share the consumer name C"
    assert p.resolve_selector("wmi:C", rows) is None, "ambiguous name must not resolve"


# --- loader achievability ------------------------------------------------------

def _doc(action_target, attack):
    return {
        "environment": {"hosts": [
            {"id": "ws", "role": "workstation", "hostname": WS, "status": "online"}]},
        "attack": attack,
        "answer_key": {"actions_reviewed": True, "traps": [], "actions": [
            {"id": "a1", "action": "remove_persistence", "status": "required",
             "target": action_target}]},
    }


def _wmi_attack(complete=True):
    steps = [
        {"id": "s1", "host": "ws", "source_type": "Sysmon", "event_type": "19",
         "key_value_pairs": {"event_id": 19, "name": "F", "event_namespace": r"root\CimV2",
                             "query": "Q"}},
        {"id": "s2", "host": "ws", "source_type": "Sysmon", "event_type": "20",
         "key_value_pairs": {"event_id": 20, "name": "C", "type": "CommandLineEventConsumer",
                             "destination": "p"}},
    ]
    if complete:
        steps.append(
            {"id": "s3", "host": "ws", "source_type": "Sysmon", "event_type": "21",
             "key_value_pairs": {"event_id": 21,
                                 "consumer": 'CommandLineEventConsumer.Name="C"',
                                 "filter": '__EventFilter.Name="F"'}})
    return steps


def _raises(fn):
    try:
        fn()
    except slv2.ScenarioError:
        return True
    return False


def test_loader_accepts_authored_complete_wmi_selector():
    doc = _doc({"host": "ws", "persistence": "wmi:C"}, _wmi_attack())
    slv2._validate_action_achievability(doc, "t.yaml")  # must not raise


def test_loader_rejects_unauthored_wmi_selector():
    doc = _doc({"host": "ws", "persistence": "wmi:Nope"}, _wmi_attack())
    assert _raises(lambda: slv2._validate_action_achievability(doc, "t.yaml"))


def test_loader_rejects_incomplete_wmi_subscription():
    doc = _doc({"host": "ws", "persistence": "wmi:C"}, _wmi_attack(complete=False))
    assert _raises(lambda: slv2._validate_action_achievability(doc, "t.yaml"))


def test_loader_accepts_and_rejects_run_key_selectors():
    attack = [{"id": "s1", "host": "ws", "source_type": "Sysmon", "event_type": "13",
               "key_value_pairs": {"event_id": 13, "target_object": RUN_KEY,
                                   "details": PAYLOAD}}]
    ok = _doc({"host": "ws", "persistence": f"run_key:{RUN_KEY}"}, attack)
    slv2._validate_action_achievability(ok, "t.yaml")  # must not raise
    bad_key = RUN_KEY.rsplit("\\", 1)[0] + r"\NotAuthored"
    bad = _doc({"host": "ws", "persistence": f"run_key:{bad_key}"}, attack)
    assert _raises(lambda: slv2._validate_action_achievability(bad, "t.yaml"))


def test_loader_rejects_malformed_selector():
    doc = _doc({"host": "ws", "persistence": "not-a-selector"}, _wmi_attack())
    assert _raises(lambda: slv2._validate_action_achievability(doc, "t.yaml"))


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
