"""Stage 4 Phase 2: the LCQL certification battery (contract Section 11).

Phase 2.1 covers the structural layer: segment splitting, the FILTERS
tokenizer, GD-3 precedence shape, GD-4 star/empty-segment rules, GD-5
escaping, the contract's labeled INVALID fixtures VERBATIM, error positions,
and canonical-formatting idempotence. Catalog resolution lands in 2.2 and
the evaluator + full pinned corpus in 2.3.

Run: python test_lcql.py   (also: python -m pytest test_lcql.py -q)
"""
import json
import os
import sys

os.environ.setdefault("SPECTYR_SCENARIO_SOURCE", "yaml_v2")
import app  # noqa: E402  (catalog inputs only; lcql itself stays pure)
import lcql  # noqa: E402
from lcql import LcqlError, Pred, canonical, parse  # noqa: E402

CATALOG = lcql.build_field_catalog(app.yaml_catalog, app.NORMAL_TRAFFIC_TEMPLATES,
                                   app.EMPLOYEES, app.SERVERS)


def _err(q, **kw):
    try:
        parse(q, **kw)
    except LcqlError as e:
        return e
    raise AssertionError(f"expected LcqlError for {q!r}")


# --- the contract's labeled INVALID fixtures, verbatim -----------------------

def test_contract_invalid_splunk_style_no_segments():
    q = "source_ip=10.0.1.24 event_type=4625"
    e = _err(q)
    assert "4 |-separated segments" in e.reason and "found 1" in e.reason
    assert isinstance(e.position, int) and e.position >= 0


def test_contract_invalid_two_segments():
    e = _err("Sysmon | ProcessCreate")
    assert "4 |-separated segments" in e.reason and "found 2" in e.reason


def test_contract_invalid_empty_filters():
    q = "1h | Sysmon | ProcessCreate |"
    e = _err(q)
    assert "empty FILTERS" in e.reason and "*" in e.reason
    assert e.position == len(q)


def test_contract_invalid_single_equals():
    q = '1h | Sysmon | ProcessCreate | x = "y"'
    e = _err(q)
    assert "single = is not an operator" in e.reason
    assert e.position == q.index(" = ") + 1, "position must point at the ="


# --- segment structure -------------------------------------------------------

def test_all_four_segments_required_and_star_tokens():
    q = parse("all | * | * | *")
    assert (q.timeframe, q.sensor, q.event_type, q.filters) == \
        ("all", "*", "*", ())


def test_too_many_segments_position_points_at_extra_pipe():
    q = "1h | Sysmon | ProcessCreate | * | extra"
    e = _err(q)
    assert "found 5" in e.reason
    assert q[e.position] == "|"


def test_empty_middle_segments_error():
    assert "empty SENSOR_SELECTOR" in _err("1h |  | * | *").reason
    assert "empty EVENT_TYPE" in _err("1h | * |  | *").reason
    assert "empty TIMEFRAME" in _err(" | * | * | *").reason


def test_unknown_timeframe_with_suggestions():
    e = _err("2h | * | * | *")
    assert "unknown TIMEFRAME" in e.reason
    assert e.position == 0
    assert e.suggestions, "near-match suggestions expected"


def test_timeframe_case_insensitive_and_canonical_lowercase():
    assert parse("ALL | * | * | *").timeframe == "all"
    assert parse("24H | * | * | *").timeframe == "24h"


def test_pipe_inside_quoted_value_does_not_split():
    q = parse('1h | * | * | message contains "a|b"')
    assert q.filters[0][0].value == "a|b"
    assert canonical(q) == '1h | * | * | message contains "a|b"'


# --- FILTERS structure: predicates, precedence, star -------------------------

def _flat(q):
    """[(field, op, value, quote)] per AND-group for shape assertions."""
    return [[(p.field, p.op, p.value, p.quote) for p in g] for g in q.filters]


def test_gd3_and_binds_tighter_than_or():
    q = parse('all | * | * | a == "1" and b == "2" or c == "3"')
    assert _flat(q) == [[("a", "==", "1", '"'), ("b", "==", "2", '"')],
                        [("c", "==", "3", '"')]]
    q2 = parse('all | * | * | a == "1" or b == "2" and c == "3"')
    assert _flat(q2) == [[("a", "==", "1", '"')],
                         [("b", "==", "2", '"'), ("c", "==", "3", '"')]]


def test_operators_parse_including_two_word_not_contains():
    q = parse("all | * | * | a == v1 and b != v2 and c contains v3 "
              "and d not contains v4")
    ops = [p.op for p in q.filters[0]]
    assert ops == ["==", "!=", "contains", "not contains"]


def test_not_without_contains_is_an_error():
    e = _err('all | * | * | a not == "x"')
    assert "expected 'contains' after 'not'" in e.reason


def test_star_must_stand_alone_in_filters():
    e = _err('all | * | * | * and a == "b"')
    assert "* stands alone" in e.reason


def test_unquoted_value_may_not_be_reserved_word():
    e = _err("all | * | * | a == and")
    assert "quote" in e.reason
    ok = parse('all | * | * | a == "and"')
    assert ok.filters[0][0].value == "and"


def test_invalid_field_name_rejected():
    e = _err('all | * | * | bad-name == "x"')
    # '-' breaks the word into 'bad' then '-name'; the parser sees a sound
    # field 'bad' and then a non-operator token
    assert "expected an operator" in e.reason or "invalid field name" in e.reason


def test_missing_operator_and_missing_value_positions():
    e = _err("all | * | * | a")
    assert "expected an operator" in e.reason
    e2 = _err("all | * | * | a ==")
    assert "expected a value" in e2.reason
    e3 = _err('all | * | * | a == "1" b == "2"')
    assert "expected 'and' or 'or'" in e3.reason


# --- GD-5 escaping and quote kinds -------------------------------------------

def test_escapes_inside_double_quotes():
    q = parse('all | * | * | message contains "say \\"hi\\""')
    p = q.filters[0][0]
    assert p.value == 'say "hi"'
    assert p.raw_value == '"say \\"hi\\""', "raw lexeme byte-preserved"
    assert canonical(q).endswith('message contains "say \\"hi\\""')


def test_escapes_inside_single_quotes_and_backslash():
    q = parse("all | * | * | image == 'C:\\\\Users\\\\x'")
    p = q.filters[0][0]
    assert p.value == "C:\\Users\\x"
    assert p.quote == "'"


def test_unterminated_quote_is_an_error_at_the_quote():
    q = 'all | * | * | a == "oops'
    e = _err(q)
    assert "unterminated" in e.reason
    assert e.position == q.index('"')


def test_quote_kind_recorded():
    q = parse("all | * | * | a == \"ci\" and b == 'cs' and c == bare")
    kinds = [p.quote for p in q.filters[0]]
    assert kinds == ['"', "'", ""]


# --- canonical formatting and idempotence ------------------------------------

def test_canonical_normalizes_spacing_and_operator_case():
    q = parse('1H|Sysmon|ProcessCreate|command_line CONTAINS "PowerShell"')
    assert canonical(q) == \
        '1h | Sysmon | ProcessCreate | command_line contains "PowerShell"'


def test_canonical_collapses_sensor_whitespace():
    q = parse("all |  Windows   Security  | * | *")
    assert canonical(q) == "all | Windows Security | * | *"


_IDEMPOTENCE_CORPUS = [
    "all | * | * | *",
    '1h | Sysmon | ProcessCreate | command_line contains "powershell"',
    '1H|Sysmon|ProcessCreate|command_line CONTAINS "PowerShell"',
    'all | * | * | a == "1" and b == "2" or c == "3"',
    "all | * | * | a == bare and b != x2",
    'all | * | * | message contains "a|b"',
    'all | * | * | message contains "say \\"hi\\""',
    "15m |  Proxy  | HTTP_CONNECT | url contains 'Login.Microsoft'",
    "all | * | * | d not contains v4",
]


def test_canonicalization_idempotent():
    for q in _IDEMPOTENCE_CORPUS:
        c1 = canonical(parse(q))
        c2 = canonical(parse(c1))
        assert c1 == c2, f"canonical not idempotent for {q!r}: {c1!r} -> {c2!r}"
        assert parse(c1) == parse(c2), "reparse must yield the identical AST"


def test_parse_is_deterministic():
    q = '4h | * | QUERY | query contains "telemetry-sync" or query contains "cdn-edge"'
    assert parse(q) == parse(q)
    assert canonical(parse(q)) == canonical(parse(q))


# --- Phase 2.2: catalog resolution (contract Section 10, GD-2) ---------------

# The contract Section 11 valid examples, VERBATIM. Each parses under the
# real repository catalog and is already in canonical form.
_CONTRACT_VALID_EXAMPLES = [
    '1h | Sysmon | ProcessCreate | command_line contains "powershell"',
    '24h | Windows Security | 4625 | user_account == "spatel" and source_ip contains "10.0."',
    'all | ACME-WS10 | * | *',
    "15m | Proxy | HTTP_CONNECT | url contains 'Login.Microsoft'",
    '4h | * | QUERY | query contains "telemetry-sync" or query contains "cdn-edge"',
]


def test_contract_valid_examples_parse():
    for q in _CONTRACT_VALID_EXAMPLES:
        parsed = parse(q, catalog=CATALOG)
        assert canonical(parsed) == q, \
            f"contract example must already be canonical: {q!r} -> " \
            f"{canonical(parsed)!r}"


def test_catalog_canonical_casing_applied():
    q = parse('1h | sysmon | processcreate | COMMAND_LINE contains "x"',
              catalog=CATALOG)
    assert q.sensor == "Sysmon"
    assert q.event_type == "ProcessCreate"
    assert q.filters[0][0].field == "command_line"
    assert canonical(q) == '1h | Sysmon | ProcessCreate | command_line contains "x"'


def test_sensor_family_and_hostname_resolution():
    assert parse("all | windows security | * | *",
                 catalog=CATALOG).sensor == "Windows Security"
    assert parse("all | acme-ws12 | * | *",
                 catalog=CATALOG).sensor == "ACME-WS12"
    e = _err("all | Nonexistent-Host | * | *", catalog=CATALOG)
    assert "unknown sensor" in e.reason and "source family" in e.reason


def test_unknown_event_type_error_with_suggestions():
    e = _err("all | * | ProcessCreat | *", catalog=CATALOG)
    assert "unknown event type" in e.reason
    assert "processcreate" in [s.lower() for s in e.suggestions]


def test_unknown_field_error_with_suggestions():
    e = _err('all | * | * | commandline == "x"', catalog=CATALOG)
    assert "unknown field" in e.reason
    assert "command_line" in e.suggestions


def test_kvp_case_insensitive_resolution():
    q = parse('all | Azure AD | SigninLogs | risklevel == "high"',
              catalog=CATALOG)
    p = q.filters[0][0]
    assert p.field == "RiskLevel" and p.addr == "kvp"


def test_shadowed_kvp_key_binds_top_level_first():
    # source_ip and event_type exist both top-level and as kvp keys; the
    # contract's resolution order binds the canonical top-level name.
    q = parse('all | * | * | source_ip == "10.0.1.5" and event_type == "4625"',
              catalog=CATALOG)
    assert [p.addr for p in q.filters[0]] == ["top", "top"]


def test_id_is_filterable_top_level():
    q = parse('all | * | * | id == "abc-123"', catalog=CATALOG)
    assert q.filters[0][0].addr == "top"


def test_event_seq_rejected_as_filter_field():
    e = _err('all | * | * | event_seq == "5"', catalog=CATALOG)
    assert "not a FILTERS field" in e.reason
    assert "event_seq" in e.reason
    assert e.position == 14, "position must point at the field name"


def test_catalog_build_sanity_and_collision_guard():
    # zero lowercase collisions in the live corpus (guarded at build time)
    assert "command_line" in CATALOG.kvp.values()
    assert "protocol" in CATALOG.kvp.values()          # OD-10 placement
    assert "ACME-WS10" in CATALOG.hostnames.values()   # the verbatim fixture host
    assert "4625" in CATALOG.event_types.values()
    # display-vs-filters split (review correction 8)
    assert "event_seq" not in CATALOG.filterable_top.values()
    assert "id" in CATALOG.filterable_top.values()
    try:
        lcql.Catalog(kvp_keys={"Status", "status"}, hostnames=set(),
                     event_types=set())
        assert False, "collision must raise"
    except ValueError as e:
        assert "collision" in str(e)


# --- Phase 2.3: evaluation (GD-1/GD-5), pivots corpus, OR-scan corpus --------

def _q(text):
    return parse(text, catalog=CATALOG)


_EV = {
    "id": "ev-1", "event_seq": 7, "timestamp": "2026-03-17T04:00:00+00:00",
    "event_type": "ProcessCreate", "source_type": "Sysmon",
    "severity": "high", "hostname": "ACME-WS12", "source_ip": "10.0.1.12",
    "user_account": "ACME\\nkhan",
    "message": "Process created: PowerShell.exe launched",
    "key_value_pairs": {"command_line": "PowerShell -enc AAA",
                        "image": "C:\\Windows\\System32\\PowerShell.exe",
                        "protocol": "tcp"},
}


def test_quote_case_matrix():
    # double quotes: case-insensitive
    assert lcql.matches(_EV, _q('all | * | * | command_line contains "powershell"'))
    assert lcql.matches(_EV, _q('all | * | * | severity == "HIGH"'))
    # unquoted: case-insensitive like double quotes (GD-1)
    assert lcql.matches(_EV, _q("all | * | * | severity == high"))
    assert lcql.matches(_EV, _q("all | * | * | command_line contains powershell"))
    # single quotes: case-sensitive
    assert lcql.matches(_EV, _q("all | * | * | command_line contains 'PowerShell'"))
    assert not lcql.matches(_EV, _q("all | * | * | command_line contains 'powershell'"))
    assert not lcql.matches(_EV, _q("all | * | * | severity == 'HIGH'"))
    # != and not contains under each quote kind
    assert not lcql.matches(_EV, _q('all | * | * | severity != "high"'))
    assert lcql.matches(_EV, _q("all | * | * | severity != 'HIGH'"))
    assert not lcql.matches(_EV, _q('all | * | * | command_line not contains "POWERSHELL"'))
    assert lcql.matches(_EV, _q("all | * | * | command_line not contains 'POWERSHELL'"))


def test_missing_field_evaluates_false_for_all_four_operators():
    for op_expr in ('destination_ip == "8.8.8.8"', 'destination_ip != "8.8.8.8"',
                    'destination_ip contains "8."',
                    'destination_ip not contains "8."'):
        assert not lcql.matches(_EV, _q(f"all | * | * | {op_expr}")), \
            f"missing-field predicate must be false: {op_expr}"


def test_precedence_evaluates_and_before_or():
    # (severity==low AND hostname==ACME-WS12) OR message contains powershell
    q = _q('all | * | * | severity == "low" and hostname == "ACME-WS12" '
           'or message contains "powershell"')
    assert lcql.matches(_EV, q), "the OR arm must rescue the failed AND group"
    q2 = _q('all | * | * | severity == "low" or hostname == "ACME-WS12" '
            'and message contains "powershell"')
    assert lcql.matches(_EV, q2), "AND binds tighter on the right arm too"
    q3 = _q('all | * | * | severity == "low" or hostname == "nope" '
            'and message contains "powershell"')
    assert not lcql.matches(_EV, q3)


def test_sensor_family_hostname_and_type_matching():
    assert lcql.matches(_EV, _q("all | Sysmon | * | *"))
    assert not lcql.matches(_EV, _q("all | DNS | * | *"))
    assert lcql.matches(_EV, _q("all | ACME-WS12 | * | *"))
    assert not lcql.matches(_EV, _q("all | ACME-WS10 | * | *"))
    assert lcql.matches(_EV, _q("all | * | ProcessCreate | *"))
    assert not lcql.matches(_EV, _q("all | * | 4625 | *"))
    # shadowed top-level binding evaluates the top-level value
    assert lcql.matches(_EV, _q('all | * | * | source_ip == "10.0.1.12"'))
    # kvp address evaluates inside key_value_pairs (OD-10 protocol placement)
    assert lcql.matches(_EV, _q('all | * | * | protocol == "tcp"'))


def test_resolved_range_is_inclusive_and_caller_supplied():
    q = _q("all | * | * | *")
    at = "2026-03-17T04:00:00+00:00"
    assert lcql.matches(_EV, q, resolved_range=(at, at)), "bounds inclusive"
    assert not lcql.matches(
        _EV, q, resolved_range=("2026-03-17T04:00:01+00:00",
                                "2026-03-17T05:00:00+00:00"))
    assert lcql.matches(_EV, q, resolved_range=None), "no range -> no bound"


def test_unresolved_query_refuses_evaluation():
    structural = parse('all | * | * | a == "x"')     # no catalog
    try:
        lcql.matches(_EV, structural)
        assert False, "unresolved predicates must fail loud"
    except ValueError as e:
        assert "catalog-resolved" in str(e)


# The documented Section 13 pivot/descent forms (values filled realistically,
# escaping per GD-5). Every form must parse under the real catalog and be
# byte-canonical. The frontend generator (Phase 6) must emit exactly these
# shapes; this is the backend half of the choke-point guarantee.
_PIVOT_DESCENT_FIXTURES = [
    "1h | ACME-WS10 | * | *",
    '1h | * | * | user_account == "spatel"',
    '1h | * | * | image == "C:\\\\Users\\\\Public\\\\winupdate.exe"',
    '1h | * | ProcessCreate | image contains "winupdate"',
    '1h | * | * | target_filename == "C:\\\\payload.docx"',
    '1h | * | * | source_ip == "203.0.113.50" or destination_ip == "203.0.113.50"',
    '1h | Proxy | * | url contains "evil.example"',
    '1h | DNS | QUERY | query contains "evil.example"',
    "1h | * | 4625 | *",
    "1h | Windows Security | * | *",
    "all | ACME-WS10 | * | *",
    "all | * | * | *",
]


def test_documented_pivot_and_descent_forms_parse():
    for q in _PIVOT_DESCENT_FIXTURES:
        parsed = _q(q)
        assert canonical(parsed) == q, \
            f"pivot form must be byte-canonical: {q!r} -> {canonical(parsed)!r}"
    # escaping round-trip: the escaped image path unescapes to real backslashes
    p = _q(_PIVOT_DESCENT_FIXTURES[2]).filters[0][0]
    assert p.value == "C:\\Users\\Public\\winupdate.exe"


def test_sidebar_conjunction_append_composes():
    base = '1h | * | ProcessCreate | image contains "winupdate"'
    appended = base + ' and hostname == "ACME-WS10"'
    q = _q(appended)
    assert lcql.conjunction_only(q)
    assert canonical(q) == appended


# The shared OR-scan fixture corpus (scaffold 2.15): FILTERS text + expected
# conjunction-only verdict. The frontend lexical scan (Phase 6) asserts the
# SAME corpus; the equivalence of lexical scan and AST verdict holds only
# while LCQL has no grouping/parentheses -- if grouping is introduced, the
# scan mechanism must be replaced, not patched.
OR_SCAN_CORPUS = [
    ("*", True),
    ('a == "x"', True),
    ('a == "x" and b == "y" and c == "z"', True),
    ('a == "x" or b == "y"', False),
    ('a == "x" and b == "y" or c == "z"', False),
    ('a == "x" or b == "y" or c == "z"', False),
    ('message contains "black or white"', True),
    ('message contains "say \\"or\\" nicely" and b == "y"', True),
    ("a == corridor and b == ORACLE", True),
    ("path == 'C:\\\\or\\\\bin'", True),
]


def test_or_scan_fixture_corpus_matches_ast_verdicts():
    for filters_text, expected_conj_only in OR_SCAN_CORPUS:
        q = parse(f"all | * | * | {filters_text}")   # structural: fields free
        assert lcql.conjunction_only(q) is expected_conj_only, \
            f"AST verdict diverges for FILTERS {filters_text!r}"


def test_full_idempotence_with_catalog():
    for q in list(_CONTRACT_VALID_EXAMPLES) + list(_PIVOT_DESCENT_FIXTURES):
        c1 = canonical(_q(q))
        assert canonical(_q(c1)) == c1


# The checked-in kvp catalog-order fixture (Phase 6.3 completion, owner
# ruling): frontend/src/components/kvpCatalogOrder.json is the ONE
# statement of "catalog order" for the inspector's Family-fields section
# (contract Section 12). A client-side copy of the order was rejected as a
# silent duplicate, and a catalog endpoint as an unauthorized surface
# addition -- instead the 6.1 shared-fixture pattern: one artifact, two
# consumers (the inspector imports it; this test pins it to repository
# truth), so drift fails loud in the battery. Byte equality modulo checkout
# line-ending policy only (core.autocrlf may materialize CRLF in a Windows
# working tree). Regenerate on an INTENTIONAL catalog change, from backend/:
#   python -c "import json, app, lcql; c = lcql.build_field_catalog(
#       app.yaml_catalog, app.NORMAL_TRAFFIC_TEMPLATES, app.EMPLOYEES,
#       app.SERVERS); open('../frontend/src/components/kvpCatalogOrder.json',
#       'w', newline='\n').write(json.dumps(sorted(c.kvp.values()),
#       indent=2) + '\n')"
_KVP_ORDER_FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "frontend", "src", "components", "kvpCatalogOrder.json")


def test_kvp_catalog_order_fixture_byte_equals_catalog_order():
    expected = json.dumps(sorted(CATALOG.kvp.values()), indent=2) + "\n"
    with open(_KVP_ORDER_FIXTURE, "rb") as f:
        raw = f.read().decode("utf-8")
    assert raw.replace("\r\n", "\n") == expected, (
        "kvpCatalogOrder.json has drifted from build_field_catalog's "
        "canonical kvp order -- regenerate it (command in the comment above)")


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
        print(f"[test_lcql] {failed}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"[test_lcql] all {len(tests)} passed")
