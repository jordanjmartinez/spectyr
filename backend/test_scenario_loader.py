"""Unit tests for the Phase 1 scenario loader.

Run: python -m pytest test_scenario_loader.py -q     (or python test_scenario_loader.py)
No app import — the loader is self-contained.
"""
import random

import scenario_loader as sl

# Minimal fixtures mirroring app.py's EMPLOYEES / SERVERS shape.
EMPLOYEES = [
    {"name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com",
     "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12"},
]
SERVERS = {
    "dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200"},
    "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201"},
    "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202"},
}


def _resolved():
    scenario = {"entities": {
        "victim": {"type": "employee"},
        "c2": {"type": "external_ip", "ip": "185.141.62.11"},
    }}
    return sl.resolve_entities(scenario, EMPLOYEES, SERVERS, rng=random.Random(1))


def test_guid_passes_through_untouched():
    r = _resolved()
    guid = "{4d36e967-e325-11ce-bfc1-08002be10318}"
    assert sl.substitute(guid, r) == guid
    logon_guid = "{00000000-0000-0000-0000-000000000000}"
    assert sl.substitute(logon_guid, r) == logon_guid
    hex_guid = "{a1b2c3d4-5e6f-7890-abcd-ef1234567890}"
    assert sl.substitute(hex_guid, r) == hex_guid


def test_two_part_entity_resolves():
    r = _resolved()
    assert sl.substitute("{victim.hostname}", r) == "ACME-WS12"
    assert sl.substitute("{victim.user_domain}", r) == "ACME\\nkhan"
    assert sl.substitute("{c2.ip}", r) == "185.141.62.11"


def test_infra_three_part_resolves():
    r = _resolved()
    assert sl.substitute("{infra.dc.ip}", r) == "10.0.1.200"
    assert sl.substitute("{infra.file.hostname}", r) == "ACME-SVR02"


def test_mixed_string():
    r = _resolved()
    s = "Outbound connection to {c2.ip}:443 from {victim.hostname}"
    assert sl.substitute(s, r) == "Outbound connection to 185.141.62.11:443 from ACME-WS12"


def test_guid_beside_placeholder():
    r = _resolved()
    s = "{4d36e967-e325-11ce-bfc1-08002be10318} on {victim.hostname}"
    assert sl.substitute(s, r) == "{4d36e967-e325-11ce-bfc1-08002be10318} on ACME-WS12"


def test_unresolved_entity_raises():
    r = _resolved()
    try:
        sl.substitute("{attacker.ip}", r)
    except sl.ScenarioError as e:
        assert "attacker" in str(e)
    else:
        raise AssertionError("expected ScenarioError for undeclared entity")


def test_bad_employee_field_raises():
    r = _resolved()
    try:
        sl.substitute("{victim.password}", r)
    except sl.ScenarioError as e:
        assert "password" in str(e)
    else:
        raise AssertionError("expected ScenarioError for unknown field")


def test_deep_substitution():
    r = _resolved()
    obj = {"a": "{victim.ip}", "b": ["{c2.ip}", 443, True, "{guid-not-a-ref}"]}
    out = sl.substitute_deep(obj, r)
    assert out == {"a": "10.0.1.12", "b": ["185.141.62.11", 443, True, "{guid-not-a-ref}"]}


def test_all_scenarios_load_and_validate():
    catalog, reviews = sl.load_scenarios()
    assert len(catalog) == 20
    assert len(reviews) == 20
    tiers = sorted(s["difficulty"] for s in catalog.values())
    assert tiers.count(1) == 5 and tiers.count(2) == 8 and tiers.count(3) == 7


def test_every_scenario_resolves_end_to_end():
    """Each scenario's whole chain resolves with no leftover entity placeholder."""
    catalog, _ = sl.load_scenarios()
    for label, sc in catalog.items():
        r = sl.resolve_entities(sc, EMPLOYEES, SERVERS, rng=random.Random(0))
        resolved_chain = sl.substitute_deep(sc["chain"], r)
        leftover = sl.PLACEHOLDER.findall(__import__("json").dumps(resolved_chain))
        assert not leftover, f"{label}: unresolved placeholders {leftover}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
