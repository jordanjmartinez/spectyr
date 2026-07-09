"""Convert the legacy three-source scenario definitions into per-scenario YAML.

Sources (read via AST literal_eval, NOT import — importing app.py would run its
boot-time orphan sweep):
  - CAMPAIGN_LEVELS       (backend/app.py)  -> narrative + category
  - TRIAGE_REVIEWS        (backend/app.py)  -> triage_review
  - simulated_attack_logs.ndjson            -> chain steps

Every string scalar is emitted JSON-quoted (valid YAML double-quoted scalar) so
YAML type coercion cannot touch "110" / "0xC000006D" / "no"; genuine ints/bools
in the source data stay unquoted and typed.

Run from backend/:  python scenarios/convert.py
Idempotent; overwrites scenarios/<label>.yaml for every catalog entry.
"""
import ast
import json
import os

HERE = os.path.dirname(__file__)
BACKEND = os.path.dirname(HERE)

# --- load constants without importing app.py ---
tree = ast.parse(open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read())
CONSTS = {}
for node in ast.walk(tree):
    if (isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in ('CAMPAIGN_LEVELS', 'TRIAGE_REVIEWS', 'SERVERS')):
        CONSTS[node.targets[0].id] = ast.literal_eval(node.value)

CAMPAIGN_LEVELS = CONSTS['CAMPAIGN_LEVELS']
TRIAGE_REVIEWS = CONSTS['TRIAGE_REVIEWS']
SERVERS = CONSTS['SERVERS']

CHAINS = {}
for line in open(os.path.join(BACKEND, 'logs', 'simulated_attack_logs.ndjson'), encoding='utf-8'):
    if line.strip():
        log = json.loads(line)
        CHAINS.setdefault(log['label'], []).append(log)

META = {}
for level in CAMPAIGN_LEVELS:
    for category, sc in level['scenarios'].items():
        META[sc['scenario_label']] = {**sc, 'category': category}

# --- placeholder rewrites shared by every scenario ---
# victim (employee) + infra (SERVERS). Longer keys first so {user_domain} wins
# over {username}. infra hostnames map from the literal ACME-SVR0x names.
BASE_REWRITES = {
    '{user_domain}': '{victim.user_domain}',
    '{user_fullname}': '{victim.full_name}',
    '{user_email}': '{victim.email}',
    '{username}': '{victim.username}',
    '{hostname}': '{victim.hostname}',
    '{src_ip}': '{victim.ip}',
    '{dns_server}': '{infra.dns.ip}',
    '{file_server}': '{infra.file.ip}',
    '{dc_server}': '{infra.dc.ip}',
    '{print_server}': '{infra.print.ip}',
}
for key, srv in SERVERS.items():
    BASE_REWRITES[srv['hostname']] = f'{{infra.{key}.hostname}}'

# --- per-scenario spec: difficulty tier, extra named entities, offsets ---
# extra entities are {name: (type, {field: literal_value})}; the converter both
# declares them and rewrites their literal values to {name.field} in the chain.
# offsets: seconds after previous step; a [min,max] pair adds jitter. len must
# equal the chain length; first entry is 0.
def emp():
    return ('employee', {})

SPECS = {
    # ---- tier 1: unmistakable, single-host, loud ----
    'malware_usb': {
        'tier': 1,
        'entities': {'victim': emp(), 'c2': ('external_ip', {'ip': '185.141.62.11'})},
        'offsets': [0, [8, 20], [2, 5], [1, 3], [5, 15]],
    },
    'malware_ransomware': {
        'tier': 1,
        'entities': {'victim': emp()},
        'offsets': [0, [3, 8], [1, 3], [1, 2], [1, 2]],
    },
    'brute_force_attack': {
        'tier': 1,
        'entities': {'victim': emp(), 'attacker': ('external_ip', {'ip': '198.51.100.73'})},
        'offsets': [0, [2, 5], [2, 5], [2, 5], [3, 8]],
    },
    'phishing_1': {
        'tier': 1,
        'entities': {
            'victim': emp(),
            'lookalike': ('domain', {'value': 'micr0soft.com'}),
            'lure_ip': ('external_ip', {'ip': '185.234.72.19'}),
            'attacker': ('external_ip', {'ip': '91.204.227.15'}),
        },
        'offsets': [0, [3, 8], [20, 60], [5, 15]],
    },
    'false_positive_pentest': {
        'tier': 1,
        'entities': {
            'victim': emp(),
            'training': ('domain', {'value': 'acme-password-reset.com'}),
            'vendor_ip': ('external_ip', {'ip': '147.160.167.14'}),
        },
        'offsets': [0, [2, 6], [3, 10], [1, 3], [2, 8]],
    },

    # ---- tier 2: needs source correlation or context ----
    'defense_evasion': {
        'tier': 2,
        'entities': {'victim': emp(), 'c2': ('external_ip', {'ip': '91.204.227.15'})},
        'offsets': [0, [2, 5], [3, 8], [2, 6], [1, 3], [5, 15]],
    },
    'phishing_link': {
        'tier': 2,
        'entities': {
            'victim': emp(),
            'phish_domain': ('domain', {'value': 'docusign-portal.net'}),
            'phish_ip': ('external_ip', {'ip': '91.215.85.29'}),
        },
        'offsets': [0, [2, 5], [10, 30], [3, 8], [1, 3]],
    },
    'lateral_movement_1': {
        'tier': 2,
        'entities': {'victim': emp()},
        'offsets': [0, [5, 12], [1, 2], [2, 5], [2, 5], [3, 8]],
    },
    'c2_http': {
        'tier': 2,
        'entities': {
            'victim': emp(),
            'c2_domain': ('domain', {'value': 'microsoftonline.co'}),
            'c2_ip': ('external_ip', {'ip': '185.234.72.19'}),
        },
        'offsets': [0, [5, 15], [2, 5], [30, 60], [2, 5]],
    },
    'data_exfil_archive': {
        'tier': 2,
        'entities': {
            'victim': emp(),
            'exfil_domain': ('domain', {'value': 'mega.nz'}),
            'exfil_ip': ('external_ip', {'ip': '31.13.84.2'}),
        },
        'offsets': [0, [10, 30], [2, 5], [2, 5], [5, 15]],
    },
    'defense_evasion_log_clearing': {
        'tier': 2,
        'entities': {'victim': emp()},
        'offsets': [0, [1, 3], [1, 3], [3, 8], [2, 5], [2, 5]],
    },
    'false_positive_robocopy': {
        'tier': 2,
        'entities': {
            'victim': emp(),
            'sharepoint': ('domain', {'value': 'acme-my.sharepoint.com'}),
            'sharepoint_ip': ('external_ip', {'ip': '52.96.128.144'}),
        },
        'offsets': [0, [2, 5], [1, 3], [1, 3], [20, 45]],
    },
    'false_positive_veeam': {
        'tier': 2,
        'entities': {
            'victim': emp(),
            'backup_server': ('internal_host', {'hostname': 'ACME-VEEAM01', 'ip': '10.0.1.210'}),
        },
        'offsets': [0, [1, 3], [2, 5], [0, 1], [45, 90]],
    },

    # ---- tier 3: behavioral, cross-account / covert, judgment calls ----
    # NOTE: the spray originates from {src_ip} (the victim workstation) in the
    # source data, so there's no separate attacker entity to declare. Pivot is
    # on the workstation.
    'password_spray': {
        'tier': 3,
        'entities': {'victim': emp()},
        'offsets': [0, [2, 4], [2, 4], [2, 4], [2, 4], [3, 6]],
    },
    'c2_dns_tunnel': {
        'tier': 3,
        'entities': {
            'victim': emp(),
            'tunnel_domain': ('domain', {'value': 'cloudmetrics-sync.net'}),
        },
        'offsets': [0, [5, 15], [30, 60], [1, 3], [30, 60]],
    },
    'insider_staging': {
        'tier': 3,
        'entities': {
            'victim': emp(),
            'exfil_domain': ('domain', {'value': 'drive.google.com'}),
            'exfil_ip': ('external_ip', {'ip': '142.250.80.46'}),
        },
        'offsets': [0, [30, 90], [5, 15], [2, 5], [5, 15]],
    },
    'insider_shadow_it': {
        'tier': 3,
        'entities': {
            'victim': emp(),
            'cloud_domain': ('domain', {'value': 'd.dropbox.com'}),
            'cloud_ip': ('external_ip', {'ip': '162.125.64.18'}),
        },
        'offsets': [0, [10, 30], [2, 5], [3, 8], [5, 15]],
    },
    'lateral_movement_2': {
        'tier': 3,
        'entities': {'victim': emp()},
        'offsets': [0, [2, 5], [1, 3], [5, 12], [2, 5]],
    },
    'false_positive_oauth': {
        'tier': 3,
        'entities': {'victim': emp()},
        'offsets': [0, [2, 5], [30, 90], [5, 15]],
    },
    'false_positive_ssl_inspection': {
        'tier': 3,
        'entities': {
            'victim': emp(),
            'm365_endpoint': ('external_ip', {'ip': '52.96.84.228'}),
        },
        'offsets': [0, [5, 15], [2, 5], [3, 8], [10, 30]],
    },
}

# Trigger steps (0-based indices) per scenario: the event(s) a real detection
# rule fires on. This is the entry point analysts see in Analyst mode; the rest
# of the chain is found by pivoting on the shared entity. Chosen by hand because
# correlation-detected scenarios (password_spray, c2_dns_tunnel) fire on a
# specific anomalous event, not the loudest one. A fairness check
# (fairness_check.py) verifies every non-trigger step shares an entity value
# with a trigger, so the whole chain is always reachable by pivoting.
TRIGGERS = {
    'malware_usb': {1},                     # exec from removable media E:\
    'malware_ransomware': {2},              # first .locked file (mass encryption)
    'brute_force_attack': {4},              # 4740 account lockout
    'phishing_1': {3},                      # Entra impossible-travel risk event
    'false_positive_pentest': {2},          # credential-harvest POST (benign)
    'defense_evasion': {1},                 # 5007 Defender real-time protection off
    'phishing_link': {2},                   # payload process from the link
    'lateral_movement_1': {4},              # 4624 anomalous logon on the server
    'c2_http': {2},                         # beacon CONNECT to lookalike domain
    'data_exfil_archive': {4},              # outbound CONNECT to mega.nz
    'defense_evasion_log_clearing': {4},    # 1102 Security log cleared
    'insider_staging': {4},                 # exfil CONNECT to personal cloud
    'insider_shadow_it': {4},               # upload POST to unsanctioned cloud
    'lateral_movement_2': {1},              # ProcessAccess on lsass.exe
    'password_spray': {5},                  # 4624 success after the spray
    'c2_dns_tunnel': {2},                   # anomalous TXT queries to tunnel domain
    'false_positive_oauth': {3},            # impossible-travel risk event (benign)
    'false_positive_robocopy': {0},         # robocopy bulk-copy launch (benign)
    'false_positive_ssl_inspection': {1},   # repeated TLS handshake failures (benign)
    'false_positive_veeam': {2},            # periodic outbound to backup server (benign)
}

# fields copied from each source log into the chain step, in this order
STEP_FIELDS = ['event_type', 'source_type', 'log_source', 'severity',
               'hostname', 'source_ip', 'destination_ip', 'user_account', 'message']


def build_rewrites(spec):
    rw = dict(BASE_REWRITES)
    for name, (etype, fields) in spec['entities'].items():
        for field, literal in fields.items():
            rw[literal] = f'{{{name}.{field}}}'
    # apply longest literals first so substrings don't clobber
    return dict(sorted(rw.items(), key=lambda kv: -len(kv[0])))


def rewrite(value, rw):
    if not isinstance(value, str):
        return value
    for old, new in rw.items():
        value = value.replace(old, new)
    return value


def emit_scalar(v):
    return json.dumps(v)  # JSON string escaping == YAML double-quoted scalar


def emit_kvp(kvp, indent, rw):
    out = []
    pad = '  ' * indent
    for k, v in kvp.items():
        out.append(f'{pad}{k}: {emit_scalar(rewrite(v, rw))}')
    return out


def scenario_threat_pattern(chain):
    """threat_pattern is a scenario-level attribute the NDJSON stored per-log;
    one chain (pentest) has an inconsistent value across steps. Take the most
    common so the YAML normalizes it to a single stable value."""
    from collections import Counter
    counts = Counter(l.get('threat_pattern', '') for l in chain)
    return counts.most_common(1)[0][0]


def convert(label):
    spec = SPECS[label]
    meta = META[label]
    review = TRIAGE_REVIEWS[label]
    chain = CHAINS[label]
    rw = build_rewrites(spec)
    offsets = spec['offsets']
    assert len(offsets) == len(chain), f'{label}: {len(offsets)} offsets, {len(chain)} steps'

    L = []
    L.append('# Auto-generated by scenarios/convert.py from the legacy sources.')
    L.append('# Edit this file, not the NDJSON, once the loader flag flips to yaml.')
    L.append(f'label: {emit_scalar(label)}')
    L.append(f'category: {emit_scalar(meta["category"])}')
    L.append(f'difficulty: {spec["tier"]}')
    L.append(f'threat_pattern: {emit_scalar(scenario_threat_pattern(chain))}')
    L.append('')
    L.append('narrative:')
    L.append(f'  ticket_title: {emit_scalar(meta["ticket_title"])}')
    L.append(f'  storyline: {emit_scalar(meta["storyline"])}')
    L.append('')
    L.append('entities:')
    for name, (etype, fields) in spec['entities'].items():
        L.append(f'  {name}:')
        L.append(f'    type: {emit_scalar(etype)}')
        for field, literal in fields.items():
            L.append(f'    {field}: {emit_scalar(literal)}')
    L.append('')
    triggers = TRIGGERS.get(label, set())
    L.append('chain:')
    for i, step in enumerate(chain):
        L.append(f'  - offset: {json.dumps(offsets[i])}')
        if i in triggers:
            L.append('    trigger: true')
        for f in STEP_FIELDS:
            if f in step and step[f] not in (None, ''):
                L.append(f'    {f}: {emit_scalar(rewrite(step[f], rw))}')
        if step.get('key_value_pairs'):
            L.append('    key_value_pairs:')
            L.extend(emit_kvp(step['key_value_pairs'], 3, rw))
        if i < len(chain) - 1:
            L.append('')
    L.append('')
    L.append('triage_review:')
    if 'mitre' in review:
        L.append('  mitre:')
        for k, v in review['mitre'].items():
            L.append(f'    {k}: {emit_scalar(v)}')
    L.append('  what_is_it:')
    L.append(f'    title: {emit_scalar(review["what_is_it"]["title"])}')
    L.append(f'    description: {emit_scalar(review["what_is_it"]["description"])}')
    L.append('  response_actions:')
    for a in review['response_actions']:
        L.append(f'    - {emit_scalar(a)}')
    L.append('')

    path = os.path.join(HERE, f'{label}.yaml')
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(L))
    return path


if __name__ == '__main__':
    labels = sorted(CHAINS)
    assert set(labels) == set(SPECS), \
        f'spec/catalog mismatch: {set(labels) ^ set(SPECS)}'
    for label in labels:
        p = convert(label)
        print(f'wrote {os.path.relpath(p, BACKEND)}')
    print(f'\n{len(labels)} scenarios converted')
