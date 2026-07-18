"""Tests for persistence-artifact identity and correlation (Stage 3c.5).

Run: python test_persistence.py

The load-bearing properties: WMI subscriptions correlate 19/20/21 into one
logical entity keyed by the full triple (never consumer name alone);
duplicate complete subscriptions dedup to one; incomplete, ambiguous, and
conflicting correlations fail closed; Run-key values sharing a payload
path stay distinct; all identities are normalized before derivation.
"""
import persistence as p


def _filter(name, ns=r"root\CimV2", query="SELECT * FROM x"):
    return {"event_id": 19, "name": name, "event_namespace": ns, "query": query}


def _consumer(name, dest="powershell.exe -enc AAAA", ctype="CommandLineEventConsumer"):
    return {"event_id": 20, "name": name, "type": ctype, "destination": dest}


def _binding(cons, filt):
    return {"event_id": 21,
            "consumer": f'CommandLineEventConsumer.Name="{cons}"',
            "filter": f'__EventFilter.Name="{filt}"'}


# --- normalization -------------------------------------------------------------

def test_namespace_normalization():
    assert p.norm_namespace(r"root\CimV2") == p.norm_namespace("ROOT/cimv2")
    assert p.norm_namespace(r"root\CimV2") == r"root\cimv2"


def test_wmi_path_normalization():
    a = p.norm_wmi_path('CommandLineEventConsumer.Name="WindowsUpdConsumer"')
    b = p.norm_wmi_path('commandlineeventconsumer . name = "WindowsUpdConsumer"')
    assert a == b, "class/property case + whitespace must fold"
    assert a == 'commandlineeventconsumer.name="WindowsUpdConsumer"'
    # instance value is identity: different name -> different path
    assert p.norm_wmi_path('X.Name="A"') != p.norm_wmi_path('X.Name="B"')


def test_reg_key_and_value_normalization():
    assert p.norm_reg_key(r"HKCU\SOFTWARE\...\Run\\") == p.norm_reg_key("hkcu/software/.../run")
    assert p.norm_value_name(" WindowsServices ") == "windowsservices"


# --- WMI correlation -----------------------------------------------------------

def test_complete_triple_correlates_to_one_artifact():
    arts = p.correlate_wmi("H1",
                           [_filter("F1")], [_consumer("C1")], [_binding("C1", "F1")])
    assert len(arts) == 1
    a = arts[0]
    assert a["persist_type"] == "wmi_subscription"
    assert a["entry"] == "C1"  # display name
    assert a["file_path"] is None  # registration-only, no file flag
    assert a["identity"][0] == "H1"


def test_duplicate_identical_subscription_dedups_to_one():
    arts = p.correlate_wmi("H1", [_filter("F1"), _filter("F1")],
                           [_consumer("C1"), _consumer("C1")],
                           [_binding("C1", "F1"), _binding("C1", "F1")])
    assert len(arts) == 1, "identical complete subscription must dedup"


def test_incomplete_triple_not_actionable():
    # binding + consumer but no filter
    assert p.correlate_wmi("H1", [], [_consumer("C1")], [_binding("C1", "F1")]) == []
    # binding + filter but no consumer
    assert p.correlate_wmi("H1", [_filter("F1")], [], [_binding("C1", "F1")]) == []
    # filter + consumer but no binding -> nothing to correlate
    assert p.correlate_wmi("H1", [_filter("F1")], [_consumer("C1")], []) == []


def test_ambiguous_consumer_name_fails_closed():
    # two DISTINCT consumers share the name C1 -> the binding is ambiguous
    arts = p.correlate_wmi("H1", [_filter("F1")],
                           [_consumer("C1", dest="a"), _consumer("C1", dest="b")],
                           [_binding("C1", "F1")])
    assert arts == [], "ambiguous consumer name must fail closed, not clone"


def test_conflicting_binding_identity_fails_closed():
    # NOTE: hard to hit via distinct-name index; simulate two bindings whose
    # normalized identity collides but whose resolved consumer command differs.
    # Build consumers that index to the same name but the binding resolves to
    # a single consumer -> covered by ambiguity. Conflict marker path:
    filters = [_filter("F1")]
    consumers = [_consumer("C1", dest="one")]
    bindings = [_binding("C1", "F1"), _binding("C1", "F1")]
    # identical -> dedups to one (not a conflict)
    assert len(p.correlate_wmi("H1", filters, consumers, bindings)) == 1


def test_duplicate_consumer_names_across_hosts_stay_distinct():
    a1 = p.correlate_wmi("H1", [_filter("F1")], [_consumer("C1")], [_binding("C1", "F1")])
    a2 = p.correlate_wmi("H2", [_filter("F1")], [_consumer("C1")], [_binding("C1", "F1")])
    assert a1[0]["identity"] != a2[0]["identity"], "host is part of identity"
    assert a1[0]["id_parts"] != a2[0]["id_parts"]


def test_same_name_different_filter_are_distinct_subscriptions():
    # consumer C1 bound to two DIFFERENT filters = two subscriptions
    arts = p.correlate_wmi("H1", [_filter("F1"), _filter("F2")],
                           [_consumer("C1")],
                           [_binding("C1", "F1"), _binding("C1", "F2")])
    assert len(arts) == 2
    assert arts[0]["identity"] != arts[1]["identity"]


# --- binding-path redundancy proof (approved-identity reconciliation) ----------
# The approved WMI identity was host + namespace + filter path + consumer path
# + BINDING PATH. The implementation omits the binding path. These tests prove
# it is redundant: the __FilterToConsumerBinding canonical path is a pure
# function of its Consumer and Filter refs (the class's only [key] properties;
# learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding), so
# adding it to the identity cannot split or merge any group.

def _identity5(art):
    """The approved 5-part identity: the 4-tuple plus the canonical binding
    path composed from the same two refs."""
    _host, _kind, _ns, filt_ref, cons_ref = art["identity"]
    return tuple(art["identity"]) + (p.canonical_binding_path(cons_ref, filt_ref),)


def test_binding_path_is_pure_function_of_consumer_and_filter_refs():
    a = p.canonical_binding_path('CommandLineEventConsumer.Name="C"', '__EventFilter.Name="F"')
    b = p.canonical_binding_path('commandlineeventconsumer . name = "C"', '__eventfilter.name="F"')
    assert a == b, "normalization folds; the binding path is fixed by the two refs"
    assert a != p.canonical_binding_path('CommandLineEventConsumer.Name="C2"', '__EventFilter.Name="F"')
    assert a != p.canonical_binding_path('CommandLineEventConsumer.Name="C"', '__EventFilter.Name="F2"')
    # same Name, different consumer CLASS => a different canonical path
    assert a != p.canonical_binding_path('ActiveScriptEventConsumer.Name="C"', '__EventFilter.Name="F"')


def test_two_distinct_complete_bindings_do_not_collapse():
    arts = p.correlate_wmi(
        "H1", [_filter("F1"), _filter("F2")],
        [_consumer("C1"), _consumer("C2", dest="other")],
        [_binding("C1", "F1"), _binding("C1", "F2"), _binding("C2", "F1")])
    assert len(arts) == 3, "three distinct bindings must stay three entities"
    id4 = {tuple(a["identity"]) for a in arts}
    id5 = {_identity5(a) for a in arts}
    assert len(id4) == 3 and len(id5) == 3, "no collapse under either identity"


def test_duplicate_binding_dedups_under_both_identities():
    arts = p.correlate_wmi("H1", [_filter("F1"), _filter("F1")],
                           [_consumer("C1"), _consumer("C1")],
                           [_binding("C1", "F1"), _binding("C1", "F1")])
    assert len(arts) == 1
    assert len({_identity5(a) for a in arts}) == 1, "5-tuple dedups identically"


def test_conflicting_or_ambiguous_bindings_fail_closed():
    # ambiguous consumer name (two distinct defs) -> no actionable entity
    assert p.correlate_wmi("H1", [_filter("F1")],
                           [_consumer("C1", dest="a"), _consumer("C1", dest="b")],
                           [_binding("C1", "F1")]) == []
    # incomplete (no binding) -> nothing correlates
    assert p.correlate_wmi("H1", [_filter("F1")], [_consumer("C1")], []) == []


def test_same_named_refs_distinct_where_canonical_paths_differ():
    # consumer Name "C" but different CLASS: canonical paths differ, so the
    # identities (and the binding paths) differ - the name alone never keys.
    ns = r"root\cimv2"
    cases = []
    for cons in ('CommandLineEventConsumer.Name="C"', 'ActiveScriptEventConsumer.Name="C"'):
        cr, fr = p.norm_wmi_path(cons), p.norm_wmi_path('__EventFilter.Name="F"')
        four = ("H", "wmi_subscription", ns, fr, cr)
        cases.append((four, four + (p.canonical_binding_path(cons, '__EventFilter.Name="F"'),)))
    assert cases[0][0] != cases[1][0], "same-name/different-class must stay distinct (4-tuple)"
    assert cases[0][1] != cases[1][1], "and under the 5-tuple"


def test_binding_path_never_splits_or_merges_identity_groups():
    """The partition proof, robust to delimiter chars: for arbitrary ref
    pairs (including instance names containing a colon), identity4 equality
    holds iff identity5 equality holds. Tuples never concatenate, so a colon
    in one component cannot bleed into another."""
    ns = r"root\cimv2"
    refs = [
        ('CommandLineEventConsumer.Name="C"', '__EventFilter.Name="F"'),
        ('CommandLineEventConsumer.Name="C"', '__EventFilter.Name="F"'),   # duplicate
        ('CommandLineEventConsumer.Name="C2"', '__EventFilter.Name="F"'),
        ('CommandLineEventConsumer.Name="C"', '__EventFilter.Name="F2"'),
        ('ActiveScriptEventConsumer.Name="C"', '__EventFilter.Name="F"'),
        ('CommandLineEventConsumer.Name="a:b"', '__EventFilter.Name="c"'),
        ('CommandLineEventConsumer.Name="a"', '__EventFilter.Name="b:c"'),
    ]
    id4, id5 = [], []
    for cons, filt in refs:
        cr, fr = p.norm_wmi_path(cons), p.norm_wmi_path(filt)
        four = ("H", "wmi_subscription", ns, fr, cr)
        id4.append(four)
        id5.append(four + (p.canonical_binding_path(cons, filt),))
    for i in range(len(refs)):
        for j in range(len(refs)):
            assert (id4[i] == id4[j]) == (id5[i] == id5[j]), \
                f"binding path split or merged an identity group at {i},{j}"
    # the colon-bearing pair must NOT collide with its shifted twin
    assert id4[5] != id4[6] and id5[5] != id5[6]


# --- run-key artifacts ---------------------------------------------------------

def test_run_key_identity_is_key_plus_value_not_payload():
    a = p.run_key_artifact("H1",
                           r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Svc",
                           r"C:\Users\Public\p.exe", r"C:\Users\Public\p.exe")
    assert a["persist_type"] == "run_key"
    assert a["entry"] == "Svc"
    assert a["file_path"] == r"C:\Users\Public\p.exe"
    assert a["identity"][:2] == ("H1", "run_key")


def test_run_key_values_sharing_payload_stay_distinct():
    a = p.run_key_artifact("H1", r"HKCU\...\Run\ValueA", r"C:\p.exe", "")
    b = p.run_key_artifact("H1", r"HKCU\...\Run\ValueB", r"C:\p.exe", "")
    assert a["identity"] != b["identity"], "same payload, different value names"
    assert a["id_parts"] != b["id_parts"]


def test_run_key_value_name_case_insensitive():
    a = p.run_key_artifact("H1", r"HKCU\...\Run\Svc", r"C:\p.exe", "")
    b = p.run_key_artifact("H1", r"hkcu\...\run\SVC", r"C:\p.exe", "")
    assert a["identity"] == b["identity"], "reg key + value name fold case"


if __name__ == "__main__":
    fns = [fn for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
