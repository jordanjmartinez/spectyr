"""Stage 4 Phase 2: the LCQL certification battery (contract Section 11).

Phase 2.1 covers the structural layer: segment splitting, the FILTERS
tokenizer, GD-3 precedence shape, GD-4 star/empty-segment rules, GD-5
escaping, the contract's labeled INVALID fixtures VERBATIM, error positions,
and canonical-formatting idempotence. Catalog resolution lands in 2.2 and
the evaluator + full pinned corpus in 2.3.

Run: python test_lcql.py   (also: python -m pytest test_lcql.py -q)
"""
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
