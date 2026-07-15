"""Migrate every v1 scenario YAML into schema v2 (Phase 2 Stage 0).

The migration WRAPS the v1 scenario, it never edits it: every line of the v1
file's narrative/entities/chain/triage_review sections is carried over
byte-for-byte. The only change inside the chain body is the injected per-step
id/host/user tag lines; the section is renamed chain: -> attack:. New sections
(schema_version, environment, noise, answer_key) are emitted around it with
convert.py's JSON-quoted scalar style so YAML type coercion cannot touch
type-sensitive values.

Inference is rule-based and conservative:
  - host tag = the environment host the activity OCCURRED ON (the actor),
    not the sensor that logged it. Endpoint telemetry (Sysmon, Windows
    Security) on a host tags that host; network sensor events (DNS, Proxy,
    Firewall) tag the host that originated the traffic, resolved from the
    step's source_ip placeholder.
  - user tag = the employee entity whose username/user_domain the step
    references. Literal (non-placeholder) accounts need an OVERRIDES entry.
  - environment hosts = every workstation/server/firewall the chain touches,
    placeholder-driven wherever the chain is placeholder-driven.
  - answer_key: classification = the v1 category (what classify scoring
    already grades against); techniques = the triage_review MITRE id; scope =
    the actor hosts plus attack-traffic source hosts, and the user-tagged
    accounts; root_cause = the first chain step for attacks, null for FPs.

Anything the rules cannot tag is a hard error listing the step — add an
explicit OVERRIDES entry instead of letting the script guess.

Each generated file is verified before writing:
  1. parsed attack steps minus tags == parsed v1 chain (deep equality)
  2. every verbatim section == its v1 original (deep equality)
  3. scenario_loader_v2.validate_scenario_v2 passes

Run from backend/:  python scenarios/migrate_v1_to_v2.py
Writes scenarios/v2/<label>.yaml and scenarios/v2/MIGRATION_REPORT.md.
Idempotent; overwrites previous output.
"""
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
V2_DIR = os.path.join(HERE, "v2")
sys.path.insert(0, BACKEND)

import scenario_loader as v1  # noqa: E402
import scenario_loader_v2 as v2  # noqa: E402

# --- reference environment (the plan's server mapping table) ---------------
# Emitted hostnames/ips stay in {infra.*} placeholder form; the literals here
# are only used in the migration report for reviewer context.
SERVER_TABLE = {
    "dc":    ("ACME-SVR01", "10.0.1.200", "Domain Controller"),
    "file":  ("ACME-SVR02", "10.0.1.201", "File Server"),
    "dns":   ("ACME-SVR03", "10.0.1.202", "DNS Server"),
    "print": ("ACME-SVR04", "10.0.1.203", "Print Server"),
    "web":   ("ACME-SVR05", "10.0.1.204", "Web Server"),
    "proxy": ("ACME-SVR06", "10.0.1.205", "Proxy Server"),
}
FW_HOSTNAME = "ACME-FW01"  # hardcoded per the reference environment
FW_IP = "10.0.1.254"

ORG_NAME = "ACME Corp"
ORG_DOMAIN = "acme.local"

# OS labels are simulation metadata (nothing renders them until Stage 1).
# ASSUMPTIONS — flagged in the report for review, not silently trusted:
WS_OS = "Windows 10 Enterprise"   # chains carry 10.0.19041.* binary versions
SRV_OS = "Windows Server 2019"
FW_OS = "PAN-OS"                  # firewall/proxy logs follow Palo Alto CIM

# Sources that are host-local telemetry: an event from one of these on host X
# means the activity occurred on X.
ENDPOINT_SOURCES = {"Sysmon", "Windows Security", "Windows Defender", "Defender", "Veeam"}
# Sources that observe traffic: the actor is whoever originated the traffic.
SENSOR_SOURCES = {"DNS", "Proxy", "Firewall"}

# --- per-scenario overrides (reviewed by hand, they ARE the decision record) -
# step_users / step_hosts are keyed by 0-based chain index.
OVERRIDES = {
    "password_spray": {
        # The spray's 4625/4624 account names are literal roster usernames in
        # the v1 chain (grandfathered; parity forbids touching them). Declare
        # them as environment accounts and tag each step with its target.
        "extra_accounts": [
            {"id": u, "username": u, "domain": "ACME", "type": "user"}
            for u in ("dpark", "mjohnson", "bwilliams", "achen", "jkim", "lgreen")
        ],
        "step_users": {0: "dpark", 1: "mjohnson", 2: "bwilliams", 3: "achen",
                       4: "jkim", 5: "lgreen"},
        "flags": [
            "Literal sprayed usernames (dpark, mjohnson, bwilliams, achen, jkim, "
            "lgreen) are pre-existing v1 chain content, grandfathered for parity. "
            "They are also roster employees, so the runtime victim pick can "
            "collide with a sprayed account (pre-existing v1 behavior).",
            "lgreen is the compromised account (4624 success); the other five "
            "were targeted but not breached. answer_key.scope treats all six "
            "as involved, matching the triage guidance to reset every "
            "targeted account.",
        ],
    },
    "false_positive_veeam": {
        "flags": [
            "backup_server (ACME-VEEAM01, 10.0.1.210) enters the environment "
            "from its v1 internal_host entity declaration; the environment "
            "entry references it through {backup_server.*} placeholders.",
        ],
    },
    "false_positive_robocopy": {
        "flags": [
            "Step 2's hostname field carries {infra.file.ip} (an IP in a "
            "hostname slot) in the v1 source. Preserved byte-for-byte for "
            "parity; flagged for the schema correction workflow.",
        ],
    },
    "false_positive_ssl_inspection": {
        "flags": [
            "v1 literals ACME-PROXY-CA (inspection CA name) and dvc "
            "ACME-PROXY-01 are preserved for parity. ACME-PROXY-01 disagrees "
            "with the reference environment, where the proxy is ACME-SVR06; "
            "flagged for the schema correction workflow.",
        ],
    },
}

GLOBAL_FLAGS = [
    "OS labels in environment.hosts are migration ASSUMPTIONS (workstations "
    "Windows 10 Enterprise per the 10.0.19041.* binaries authored in chains; "
    "servers Windows Server 2019; firewall PAN-OS). Nothing renders them until "
    "Stage 1 endpoint pages; review before Stage 1 ships.",
    "Server-side Sysmon steps (lateral_movement_1/2 net.exe on the file "
    "server) carry file_version 10.0.19041.1, a Windows 10 2004-era build, on "
    "a host labeled Windows Server 2019. Pre-existing v1 content; parity "
    "forbids changing it here. Flagged for the schema correction workflow.",
    "The proxy role (ACME-SVR06) is named like a Windows server while "
    "proxy/firewall log fields follow Palo Alto CIM. Which OS its Stage 1 "
    "endpoint page should show needs a call before Stage 1.",
    "root_cause is set to the FIRST chain step of every attack scenario "
    "(patient zero = earliest malicious event). Distinct from the trigger "
    "step, which is where the analyst ENTERS the scenario.",
]


def emit(v):
    return json.dumps(v)  # JSON escaping == YAML double-quoted scalar


# --- inference ---------------------------------------------------------------

def entity_sets(doc):
    employees = {n for n, s in doc["entities"].items() if s["type"] == "employee"}
    internals = {n: s for n, s in doc["entities"].items()
                 if s["type"] == "internal_host"}
    return employees, internals


def actor_from_source_ip(step, employees, internals):
    src = step.get("source_ip", "")
    m = re.fullmatch(r"\{([a-z][a-z0-9_]*)\.ip\}", src)
    if m:
        name = m.group(1)
        if name in employees:
            return f"ws_{name}"
        if name in internals:
            return name
    m = re.fullmatch(r"\{infra\.([a-z]+)\.ip\}", src)
    if m:
        return m.group(1)
    return None


def infer_step_tags(doc, label):
    """Per step: (step_id, host_tag, user_tag_or_None). Hard error on any step
    the rules cannot tag and no override covers."""
    employees, internals = entity_sets(doc)
    over = OVERRIDES.get(label, {})
    tags = []
    problems = []
    for i, step in enumerate(doc["chain"]):
        hn = step.get("hostname", "")
        st = step.get("source_type", "")

        host = over.get("step_hosts", {}).get(i)
        if host is None:
            m = re.fullmatch(r"\{([a-z][a-z0-9_]*)\.hostname\}", hn)
            if m and m.group(1) in employees:
                host = f"ws_{m.group(1)}"
            elif m and m.group(1) in internals:
                host = m.group(1)
            else:
                m = re.fullmatch(r"\{infra\.([a-z]+)\.(?:hostname|ip)\}", hn)
                if m and st in ENDPOINT_SOURCES:
                    host = m.group(1)
                elif m and st in SENSOR_SOURCES:
                    host = actor_from_source_ip(step, employees, internals)
                elif hn == FW_HOSTNAME:
                    host = actor_from_source_ip(step, employees, internals)
                else:
                    literal = next((n for n, s in internals.items()
                                    if s.get("hostname") == hn), None)
                    host = literal
        if host is None:
            problems.append(f"step {i}: hostname={hn!r} source_type={st!r}")
            tags.append((f"s{i+1}", None, None))
            continue

        user = over.get("step_users", {}).get(i)
        if user is None:
            text = json.dumps(step)
            hits = sorted(e for e in employees
                          if f"{{{e}.username}}" in text or f"{{{e}.user_domain}}" in text)
            if len(hits) > 1:
                problems.append(f"step {i}: multiple employee refs {hits}")
            user = hits[0] if len(hits) == 1 else None

        tags.append((f"s{i+1}", host, user))

    if problems:
        raise SystemExit(
            f"[FLAG] {label}: cannot infer tags, add an OVERRIDES entry:\n  "
            + "\n  ".join(problems)
        )
    return tags


def build_environment(doc, tags, label):
    """hosts + accounts inferred from what the chain references."""
    employees, internals = entity_sets(doc)
    over = OVERRIDES.get(label, {})
    chain_text = json.dumps(doc["chain"])
    tag_hosts = {h for _, h, _ in tags}

    hosts = []
    for name in doc["entities"]:  # declaration order
        if name not in employees:
            continue
        if (f"{{{name}.hostname}}" in chain_text or f"{{{name}.ip}}" in chain_text):
            hosts.append({
                "id": f"ws_{name}", "role": "workstation",
                "hostname": f"{{{name}.hostname}}", "ip": f"{{{name}.ip}}",
                "os": WS_OS, "desc": "User workstation",
            })
    for key, (_hn, _ip, desc) in SERVER_TABLE.items():
        if f"{{infra.{key}." in chain_text:
            hosts.append({
                "id": key, "role": key,
                "hostname": f"{{infra.{key}.hostname}}",
                "ip": f"{{infra.{key}.ip}}",
                "os": SRV_OS, "desc": desc,
            })
    if FW_HOSTNAME in chain_text:
        hosts.append({
            "id": "fw_perimeter", "role": "firewall",
            "hostname": FW_HOSTNAME, "ip": FW_IP,
            "os": FW_OS, "desc": "Perimeter Firewall",
        })
    for name in internals:
        hosts.append({
            "id": name, "role": "server",
            "hostname": f"{{{name}.hostname}}", "ip": f"{{{name}.ip}}",
            "os": SRV_OS, "desc": "Internal server",
        })

    host_ids = {h["id"] for h in hosts}
    missing = tag_hosts - host_ids
    if missing:
        raise SystemExit(f"[FLAG] {label}: step tags reference hosts not in the "
                         f"inferred environment: {sorted(missing)}")

    accounts = []
    for name in doc["entities"]:
        if name in employees:
            acct = {"id": name, "username": f"{{{name}.username}}",
                    "domain": "ACME", "type": "user"}
            if f"ws_{name}" in host_ids:
                acct["host"] = f"ws_{name}"
            accounts.append(acct)
    accounts.extend(over.get("extra_accounts", []))
    return hosts, accounts


def build_answer_key(doc, tags, label):
    employees, internals = entity_sets(doc)
    is_fp = doc["category"] == "False Positive"

    scope_hosts = []
    for _, h, _ in tags:
        if h not in scope_hosts:
            scope_hosts.append(h)
    # A host that only ever appears as the SOURCE of attack traffic (its own
    # telemetry never fires) is still involved — e.g. the workstation a
    # password spray originates from.
    for step in doc["chain"]:
        src_host = actor_from_source_ip(step, employees, internals)
        if src_host and src_host not in scope_hosts:
            scope_hosts.append(src_host)

    scope_accounts = []
    for _, _, u in tags:
        if u and u not in scope_accounts:
            scope_accounts.append(u)

    mitre_id = doc["triage_review"].get("mitre", {}).get("id")
    return {
        "classification": doc["category"],
        "scope": {"hosts": scope_hosts, "accounts": scope_accounts},
        "root_cause": None if is_fp else tags[0][0],
        "techniques": [] if is_fp else [mitre_id],
        "actions": [],
    }


# --- emission ---------------------------------------------------------------

def emit_environment(hosts, accounts):
    L = ["environment:"]
    L.append("  org:")
    L.append(f"    name: {emit(ORG_NAME)}")
    L.append(f"    domain: {emit(ORG_DOMAIN)}")
    L.append("  hosts:")
    for h in hosts:
        L.append(f"    - id: {emit(h['id'])}")
        for k in ("role", "hostname", "ip", "os", "desc"):
            L.append(f"      {k}: {emit(h[k])}")
    L.append("  accounts:")
    for a in accounts:
        L.append(f"    - id: {emit(a['id'])}")
        for k in ("username", "domain", "type", "host"):
            if k in a:
                L.append(f"      {k}: {emit(a[k])}")
    return L


def emit_answer_key(ak):
    L = ["answer_key:"]
    L.append(f"  classification: {emit(ak['classification'])}")
    L.append("  scope:")
    L.append(f"    hosts: {emit(ak['scope']['hosts'])}")
    L.append(f"    accounts: {emit(ak['scope']['accounts'])}")
    L.append(f"  root_cause: {'null' if ak['root_cause'] is None else emit(ak['root_cause'])}")
    L.append(f"  techniques: {emit(ak['techniques'])}")
    L.append("  actions: []")
    return L


def split_sections(lines):
    """Indices of the v1 file's top-level anchors. The v1 corpus is
    converter-emitted, so the layout is fixed: comments, label:..., chain:,
    triage_review:."""
    label_i = chain_i = triage_i = None
    for i, ln in enumerate(lines):
        if ln.startswith("label:"):
            label_i = i if label_i is None else label_i
        elif ln == "chain:":
            chain_i = i
        elif ln == "triage_review:":
            triage_i = i
    if None in (label_i, chain_i, triage_i):
        raise SystemExit(f"unexpected v1 layout (label/chain/triage_review anchors)")
    return label_i, chain_i, triage_i


def transform_chain_body(body_lines, tags):
    """Rename each step's leading '  - offset:' into the tag block + offset.
    Every other line passes through byte-for-byte."""
    out = []
    step = 0
    for ln in body_lines:
        if ln.startswith("  - offset:"):
            sid, host, user = tags[step]
            step += 1
            out.append(f"  - id: {emit(sid)}")
            out.append(f"    host: {emit(host)}")
            if user:
                out.append(f"    user: {emit(user)}")
            out.append("    " + ln[4:])  # '  - offset: X' -> '    offset: X'
        else:
            out.append(ln)
    if step != len(tags):
        raise SystemExit(f"step anchor mismatch: found {step}, expected {len(tags)}")
    return out


def migrate(fname, report):
    path = os.path.join(HERE, fname)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    doc = yaml.safe_load(text)
    label = doc["label"]
    lines = text.split("\n")

    tags = infer_step_tags(doc, label)
    hosts, accounts = build_environment(doc, tags, label)
    answer_key = build_answer_key(doc, tags, label)

    label_i, chain_i, triage_i = split_sections(lines)
    head = lines[label_i:chain_i]          # label: ... through entities block
    body = lines[chain_i + 1:triage_i]     # chain steps
    tail = lines[triage_i:]                # triage_review: ... to EOF
    while head and head[-1] == "":
        head.pop()
    while body and body[-1] == "":
        body.pop()

    L = []
    L.append("# Schema v2 (Phase 2 Stage 0). Migrated from scenarios/%s by" % fname)
    L.append("# scenarios/migrate_v1_to_v2.py; the attack steps are the v1 chain")
    L.append("# byte-for-byte plus id/host/user tags (parity_check_v2.py proves it).")
    L.append("# Edit this file, not the v1 copy, once the loader flag flips to yaml_v2.")
    L.append("schema_version: 2")
    L.extend(head)
    L.append("")
    L.extend(emit_environment(hosts, accounts))
    L.append("")
    L.append("attack:")
    L.extend(transform_chain_body(body, tags))
    L.append("")
    L.append("noise: {}")
    L.append("")
    L.extend(emit_answer_key(answer_key))
    L.append("")
    L.extend(tail)
    new_text = "\n".join(L)
    if not new_text.endswith("\n"):
        new_text += "\n"

    # --- verify before writing ---
    new_doc = yaml.safe_load(new_text)
    stripped = [v2.strip_step(s) for s in new_doc["attack"]]
    assert stripped == doc["chain"], f"{label}: attack != v1 chain after strip"
    for key in ("label", "category", "difficulty", "threat_pattern",
                "narrative", "entities", "triage_review"):
        assert new_doc[key] == doc[key], f"{label}: section {key} diverged"
    v2.validate_scenario_v2(new_doc, v2._load_schema_v2(), v1._load_schema(),
                            f"v2/{fname}")

    os.makedirs(V2_DIR, exist_ok=True)
    with open(os.path.join(V2_DIR, fname), "w", encoding="utf-8", newline="\n") as f:
        f.write(new_text)

    # --- report section ---
    report.append(f"## {label}")
    report.append("")
    report.append(f"- classification: `{answer_key['classification']}`"
                  f" | root_cause: `{answer_key['root_cause']}`"
                  f" | techniques: `{answer_key['techniques']}`")
    report.append(f"- scope.hosts: `{answer_key['scope']['hosts']}`"
                  f" | scope.accounts: `{answer_key['scope']['accounts']}`")
    report.append(f"- environment hosts: "
                  + ", ".join(f"`{h['id']}` ({h['role']})" for h in hosts))
    report.append(f"- environment accounts: "
                  + (", ".join(f"`{a['id']}`" for a in accounts) or "(none)"))
    report.append("")
    report.append("| step | event | source | hostname (v1 field) | host tag | user tag |")
    report.append("|---|---|---|---|---|---|")
    for i, step in enumerate(doc["chain"]):
        sid, host, user = tags[i]
        trig = " *(trigger)*" if step.get("trigger") else ""
        report.append(
            f"| {sid}{trig} | {step.get('event_type', '')} | "
            f"{step.get('source_type', '')} | `{step.get('hostname', '')}` | "
            f"`{host}` | `{user or '-'}` |"
        )
    for flag in OVERRIDES.get(label, {}).get("flags", []):
        report.append("")
        report.append(f"**FLAG:** {flag}")
    report.append("")


def main():
    files = sorted(f for f in os.listdir(HERE)
                   if f.endswith(".yaml"))
    report = [
        "# v1 -> v2 Migration Report (Phase 2 Stage 0)",
        "",
        "Generated by scenarios/migrate_v1_to_v2.py. Every scenario below wraps",
        "its v1 original: chain content is byte-identical (verified by deep",
        "equality here and by parity_check_v2.py at the render layer). Review",
        "the inferred tags, environments, and answer keys before Stage 1.",
        "",
        "## Global assumptions and flags",
        "",
    ]
    report.extend(f"- **FLAG:** {f}" for f in GLOBAL_FLAGS)
    report.append("")

    for fname in files:
        migrate(fname, report)
        print(f"migrated v2/{fname}")

    with open(os.path.join(V2_DIR, "MIGRATION_REPORT.md"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("\n".join(report) + "\n")
    print(f"\n{len(files)} scenarios migrated; report at scenarios/v2/MIGRATION_REPORT.md")


if __name__ == "__main__":
    main()
