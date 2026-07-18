# SPECTYR

A full-stack Security Information and Event Management (SIEM) simulation platform for training cybersecurity analysts and blue team professionals.

## Project Structure

```
├── backend/                 # Flask Python backend
│   ├── app.py              # Main application (all simulation logic, API endpoints)
│   ├── logs/               # Per-session NDJSON log directories (generated at runtime)
│   └── requirements.txt
├── frontend/               # React + Tailwind CSS frontend
│   ├── src/
│   │   ├── App.jsx         # Main app with routing + backend health check
│   │   ├── api.js          # API fetch wrapper with localStorage session persistence
│   │   ├── config.js       # API base URL from env
│   │   ├── pages/
│   │   │   └── Dashboard.jsx    # Main dashboard (simulation control, 4-tab view switching)
│   │   └── components/
│   │       ├── AlertTable.jsx       # Raw event log display with pagination
│   │       ├── GroupedAlerts.jsx    # Threat grouping, ring charts, scenario tracking, triage
│   │       ├── IncidentReportForm.jsx  # Create/edit incident report modal
│   │       ├── Reports.jsx          # Report management (table, PDF export)
│   │       ├── Analytics.jsx        # Analytics tab (aggregates sub-components)
│   │       ├── AnalystReportCard.jsx # Score table (Correct/Missed/FP/Overall)
│   │       ├── ActionHistory.jsx    # Triage Review panel with MITRE education
│   │       ├── PerformanceGrade.jsx # Results bar chart (4 metric bars)
│   │       ├── CampaignProgress.jsx # Level stepper with pass/fail indicators
│   │       ├── GameTimer.jsx        # Hardcore mode countdown (color-coded warnings)
│   │       ├── DifficultySelector.jsx # Mode selection + analyst name entry
│   │       ├── CategorySelector.jsx # Attack category picker (8 categories)
│   │       ├── FailureModal.jsx     # Hardcore failure screen with glitch effects
│   │       └── Navbar.jsx           # Top nav with SPECTYR logo
│   ├── package.json
│   └── tailwind.config.js
└── README.md
```

## Tech Stack

- **Backend**: Flask 3.1.1, flask-cors
- **Frontend**: React 19.1.0, Tailwind CSS 3.4.1, Recharts 2.15.3, jsPDF 3.0.1, react-toastify, react-router-dom 7.6.0, canvas-confetti, html2canvas
- **Data Storage**: NDJSON files in per-session directories under `backend/logs/<session-id>/`

## Key Concepts

### Session Management
- Sessions stored in-memory (`sessions` dict with threading lock)
- Session ID sent via `X-Session-ID` header and `spectyr_session` cookie
- Frontend persists session ID in `localStorage` (survives iOS tab kills)
- Sessions expire after 30 minutes of inactivity (daemon cleanup thread); orphaned session dirs from previous runs are swept at boot
- Each session has its own log directory under `backend/logs/<session-id>/`
- All session NDJSON file access goes through locked helpers (`read_ndjson`/`append_ndjson`) or explicit `session["io_lock"]` sections — the log-writer thread appends while request handlers rewrite the same files
- **Single worker process only** — sessions and writer threads are in-process; `gunicorn.conf.py` pins `workers = 1` (do not override with `-w`)

### Game Modes
- **Training Mode**: Unlimited time, no penalties
- **Hardcore Mode**: 15:00 session timer (`get_timer_duration(1)`) covering the whole queue; a wrong classification or timer expiry pauses the session and shows the FailureModal (retry restarts a fresh run — there is no reset-to-Level-1 despite older docs)

### Rolling Alert Queue (replaces the old 5-level campaign)
- `build_alert_queue(n=10, fp_min=1, fp_max=2)` samples **10 unique scenarios** from the full catalog of 20 (15 attacks + 5 FPs), with 1-2 false positives per run, shuffled
- Scenarios drip into the session 20-40s apart, max `CONCURRENT_QUEUE_CAP = 3` in flight (injected but unresolved) at once; the first drips immediately on start
- "Level" in code and API responses now means **queue position 1-10**
- Classifying (or report-resolving) a scenario marks its queue entry resolved; when all 10 resolve, the session completes and pauses
- Chain length is flexible per scenario
- **IMPORTANT**: `scenario_label` must be UNIQUE across the whole catalog

### Scenario Storage (YAML, schema v2 — Phase 2 Stage 0)
- Default source `SPECTYR_SCENARIO_SOURCE=yaml_v2`: `backend/scenarios/v2/*.yaml` validated against `scenarios/schema_v2.json` by `scenario_loader_v2.py` (dispatches per file on `schema_version`)
- Schema v2 sections: `environment` (org/hosts/accounts), `attack` (the chain, each step tagged with a stable `id` + the `host`/`user` it occurs on), `noise` (per-host profile refs, empty until Stage 1), `answer_key` (classification, scope, root_cause, techniques, actions — actions reserved empty until Stage 3)
- Revert paths, **do not modify or remove**: `yaml` = Phase 1 loader (`scenario_loader.py` + `backend/scenarios/*.yaml`), `ndjson` = legacy loader in app.py
- Gates (run from `backend/`): `python test_scenario_loader_v2.py`, `python parity_check_v2.py`, `python test_scenario_loader.py`, `python parity_check.py`, `python fairness_check.py`
- Migration + review artifact: `scenarios/migrate_v1_to_v2.py` regenerates `scenarios/v2/` and `scenarios/v2/MIGRATION_REPORT.md` (per-step tag tables, grandfathered literals, open flags). MIGRATION_REPORT.md is frozen as the Stage 0 artifact; Stage 1+ flags live in `scenarios/v2/ENVIRONMENT_REPORT.md`

### Identity-entity rule (detections)
- Identity-provider-sourced detections (source_type in `_IDENTITY_SOURCES`, e.g. `Azure AD`) resolve their entity to the **account** (UPN or `{user_domain}\{username}` per source), **never** to a host. An identity event's sign-in IP (ClientIP/IPAddress) is the origin, not an org endpoint, so it is never force-resolved to a host and the entity carries **no endpoint link** (frontend shows the account, unlinked). Host-local (Sysmon/Windows Security/Veeam/Defender) and sensor (Firewall/Proxy/DNS) detections resolve to a host as before.

### Detections Feed (Phase 2 Stage 2)
- Schema v2 `detections` per scenario: rule_name, rule_type (sigma_behavioral | yara), severity, triggers (step ids), optional mitre, description, and a server-side answer-key `disposition` (true_positive | false_positive | benign_expected). Authored in `migrate_v1_to_v2.DETECTIONS`; all rule text is original (no SigmaHQ content, so DRL attribution does not attach)
- `detection_templates.py`: ambient benign_expected detections per managed host (updaters, backup agents, admin tooling), stable-key generated; plus `build_scenario_detections`, `benign_detections_for_host`, and `sanitize_detection`
- **Leak discipline**: `disposition`/scenario linkage are server-side only. Every API payload goes through `sanitize_detection` (drops disposition, runs triggering events through the SIEM field whitelist). `test_detections.py` proves no forbidden field leaks
- Session state: `session["detections"]` (instances with dispositions + player_action) and `benign_hosts`, guarded by `io_lock`, reset with the session, materialized at drip. PAN-OS devices get no detections
- Scoring v1 (`compute_detection_score`): deterministic over (player_action, disposition); correct = promote TP / dismiss FP / dismiss benign; own commit. The dashboard radar still reads completed scenarios only — detections never feed it
- Frontend: `Detections.jsx` (feed + Threats toggle, triage) + `DetectionDetail.jsx` (Section 8 card: triggering-event + parent-process lineage, MITRE chips, SHA256 with copy, no VirusTotal link)
- **Density pass**: 2-4 authored detections per attack scenario (coexisting FPs), 2+ TP-looking FPs per FP scenario, so disposition is not inferable from count/severity/source. `supplemental_events` (schema v2, sibling to attack): authored benign telemetry with `sup*` ids, merged into the session pool (same seed/clock/placeholders/sanitization/integrity), referenceable by detections; `supplemental_entities` for one-off externals. Detections trigger on attack step ids or sup ids (`triggers` required). Timestamp placement authored; red herrings declared. Scaffold+approve per scenario, one scenario per commit (`scenarios/DETECTION_CANDIDATES.md`)

### Endpoint World (Phase 2 Stage 1)
- One world state per session (`session["world"]`, guarded by `io_lock`; frozen `started_at` timestamp): per-host EDR snapshots derived purely from environment + substituted event pool + `noise_profiles.py` role baselines by `snapshot_generator.py`
- Built/extended at drip time in `build_attack_chain_logs`; attack lineage keeps authored PIDs/PPIDs (all authored PIDs reserved corpus-wide); every generated value is stable-key derived (sha256 over session/host/identity/field), never draw-order
- Managed endpoints are Windows hosts only; the PAN-OS firewall is a log source, never an endpoint. Host `status` (online/offline) is scenario-declared in schema v2, default online
- Frontend: `Endpoints.jsx` (list) + `EndpointDetail.jsx` (two-pane, tabs Overview/Processes/Network/Services/Users/Autoruns); no polling, snapshot fetched on tab open/reset/pivot; hostname values in event detail views pivot to the endpoint page
- Gates: `python test_snapshot_generator.py` (backend), `CI=true npx react-scripts test --watchAll=false` (frontend render + em-dash copy scan)

### Response Actions (Phase 2 Stage 3a)
- Immutable base world + session-local action overlay (`action_overlay.py`): actions never mutate the world or event pool. Current-state surfaces (endpoint ENUMERATE tabs, status/isolation badges, identity state) render base+overlay at serialization time; historical surfaces (SIEM, detections, evidence, lineage) always render the base. Response changes the present, never the record
- Eight actions: `isolate_host`, `release_host`, `kill_process`, `delete_file`, `disable_account`, `revoke_sessions`, `force_password_reset`, `remove_persistence` (the last added in Stage 3c.5). All action APIs accept session-local client entity ids only (`ent-` + 12 hex, stable-key, shape-uniform across kinds); the registry (`session["entity_index"]`) resolves ids server-side and is rebuilt from the base world after each drip. Composite targets: process = (host, pid), file = (host, normalized path), account = (domain, username), persistence = the correlated artifact identity
- Cascade on kill: live process row removed (no Terminated row is retained), its network/DNS rows go with it, surviving children keep the original PPID annotated `parent_terminated` (the sanctioned terminated-parent PPID exception; the integrity suite accepts it only when the PPID is genuinely overlay-killed), services stop when their backing process (name + svchost `-k` group) has no live instance. Isolation severs non-listening connections; release restores. Deleted files leave autorun rows
- Action log: every valid attempt records seq, action, target {id, kind, label}, outcome (`success` / `no_op` / `failed_precondition`), in-fiction reason. Logical timestamp = frozen session clock + monotonic sequence, never wall clock; identical sequences yield byte-identical logs
- **Logging boundary (ruled):** rejected at the API and never logged: malformed, foreign-session, stale/unknown, and wrong-kind ids — all with an identical 400 body (foreign-session rejections are indistinguishable from unknown-id rejections; no cross-session existence leak). Logged `failed_precondition`: valid targets failing in-world preconditions (isolating an OFFLINE host is the live difficulty lever). Logged `no_op`: repeated valid actions
- **Scoring (see docs/action-scoring.md, the single reference):** every answer-key action carries an explicit `status` (`required` | `acceptable`, no default). Required earns credit, omission is a miss; acceptable is defensible-but-nonessential: never credit, never collateral, excluded from the denominator, surfaced factually if executed (unexecuted acceptable targets never serialize). `compute_action_score` consumes successful actions only. Isolation graded on END-STATE at submission (released required containment = forfeited credit, nothing stacked; ACCEPTABLE isolation neutral active-or-released; neither-list isolation collateral only while in effect); kill/delete/identity on OCCURRENCE. `release_host` globally score-neutral (absent from the grammar; only indirect effect = forfeiting required isolation credit). Taxonomy: neither-list success = collateral; failed_precondition = score-neutral, surfaced factually; no_op = score-neutral, surfaced factually; malformed/foreign/stale/wrong-kind = rejected, never logged, never scored. Loader rejects duplicate pairs and both-statuses conflicts; `after` on required actions referencing required actions only
- **Tri-state marker `answer_key.actions_reviewed` (server-side only, never serialized):** absent/false = scenario EXCLUDED from action scoring (its targets out of grading scope; Response renders `-` until a reviewed scenario drips); true + actions = graded; true + `[]` = intentional correct inaction (one graded unit, credited on clean hands, collateral also costs it). Collateral requires the target claimed by a reviewed scenario and NO unreviewed one (benefit of the doubt on shared targets until the 3d all-reviewed gate). Each 3c commit flips its scenario to true; authored actions without the flag are a loader error
- **Achievability (enforced, seed-independent):** every required action must be executable from the initial world state; targets may resolve only to AUTHORED sources (chain, supplemental events, canonical environment), never seed-generated noise. Loader rejects violations on reviewed scenarios as hard errors; the runtime harness re-executes every reviewed set across the fixed seed set. The offline-host wrinkle (max 1-2 scenarios) can only be a tempting-but-wrong target or a surfaced failed attempt, never required credit
- `answer_key.actions` grammar (schema `$defs/answer_action`): action + explicit `status` + composite internal target + optional `after` order-sensitivity ids; per-action conditionals forbid wrong composite fields; loader validates referential integrity and rejects cycles. 3c authoring cadence: batch scaffold in `scenarios/ACTION_CANDIDATES.md` -> owner approval -> one scenario per commit flipping `actions_reviewed: true`, ledger test tracks progress. Identity statuses follow the P1 rubric in docs/classification-rubrics.md (the response must evict what the evidence shows the attacker controls)
- **Expressibility rule (ruled):** a scenario implying a correct response outside the action vocabulary must be flagged in its scaffold; owner either reshapes the evidence or extends the vocabulary via a separate reviewed schema+engineering change (Stage 3c.5 `remove_persistence` was exactly such an increment — one verb, its own reviewed commit). Never stretch an existing action's meaning. Unresolved expressibility blocks implementation: the scenario must not be marked `actions_reviewed`
- **Report card (Option A, ruled):** classification keeps the headline grade; Response and Detections render as independent scored sections. BINDING for 3d: the close-out report MUST include action-score distributions from full-corpus scored runs and present 2-3 concrete composite weighting options with their letter-grade band interactions; the composite ruling is made at 3d and may not be deferred again
- **Stage 3d close-out (docs/stage-3-final-report.md):** 20/20 reviewed; full-corpus response baselines (20x5 seeds) = correct 100/100, act-on-nothing 13.3/30.0, act-on-everything 1.4/1.5 (both naive < correct on micro AND macro, no attack-scenario outliers); Chrome end-to-end verified (3+ workflows: host-malware/identity/correct-inaction, zero console errors, report-card numbers match backend, dual-flag persistence lifecycle live). Composite decision PRESENTED with options B 50/25/25, C 40/30/30, D 60/20/20 and a recommendation of C (owner ruling PENDING; UI keeps Option A until ruled). Backlog (`response-vocabulary-v2`, unbuilt): arbitrary-file delete, OAuth grant revocation, perimeter IP block, security-control re-enable. Known-actor prior = deliberately learnable, report-only; its compromised-trusted-actor counter is backlogged/unbuilt. Stage 3d is NOT closed and visual-polish has NOT begun until the report passes owner review
- UI: Isolate/Release in the endpoint Overview reserved area (button stays enabled on offline hosts; the server enforces), Kill on process rows, identity actions (Disable / Revoke / Reset PW) on account entities in the Threats view, Remove Persistence + Delete File on Autoruns persistence rows (per flag state), shared ConfirmDialog, Response Log as the third Detections view toggle

### Persistence Response (Phase 2 Stage 3c.5)
- Dedicated engineering increment adding exactly ONE verb, `remove_persistence`, so a compromised host's persistence is a first-class response object. Other response gaps stay in the backlog (`response-vocabulary-v2`); this is not a precedent for piecemeal verb additions
- `persistence.py`: correlation + identity. WMI subscriptions correlate Sysmon 19 (filter) / 20 (consumer) / 21 (binding) into ONE logical artifact, identity = structured tuple `(host, "wmi_subscription", normalized namespace, filter path, consumer path)` (consumer NAME is display only, never the key); duplicate complete subscriptions dedup, incomplete/ambiguous/conflicting ones fail closed (no removable copy). Run-key identity = host + normalized reg key + value name (never the payload path; two values sharing a payload stay distinct). Namespaces/object paths/reg keys/value names are normalized before id derivation. Identities are STRUCTURED TUPLES and the client id is a length-prefixed digest (`action_overlay._digest`), never a delimiter join, so different path combinations cannot collapse to one key
- WMI-identity binding-path reconciliation (deviation flagged 2026-07-17, resolution 2): the approved identity named a fifth component, the binding path; the implementation OMITS it as redundant because `__FilterToConsumerBinding` keys only on its Consumer + Filter references (both `[key]`; all other properties non-key — learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding), so the canonical binding path (`persistence.canonical_binding_path`) is a pure function of the filter + consumer paths already in the identity. `test_persistence.py` proves the 4-tuple partitions bindings identically to the 5-tuple (no split/merge, robust to delimiter chars), duplicates dedup, and conflicting/ambiguous fail closed
- Autoruns surface is a persistence-artifact view: every row carries `persist_type` (`run_key` | `wmi_subscription`), a WMI row must not read as a registry autorun. `snapshot_generator` materializes WMI rows via `_correlate_wmi_persistence` (idempotent rebuild from a per-host `_wmi_events` buffer) and stamps Run keys via `_annotate_run_key`
- **Dual-flag state model** (`action_overlay.apply_overlay`): registration flag (cleared by `remove_persistence`, overlay set `removed_persistence`) + file flag (cleared by `delete_file` of the payload). Row survives until BOTH neutralized (registration-only WMI needs registration alone). **GENERAL RULE:** no acceptable action may render a required action unreachable — the surviving flag keeps the other action's row live under either ordering (test: `test_dual_flag_both_orders_keep_the_other_action_reachable`)
- Entity registry adds kind `persistence` (client id from the artifact identity, shape-uniform); `annotate_view` stamps `persistence_entity_id` and STRIPS the raw `identity`/`id_parts` (leak guard). Answer keys reference an artifact by a selector `wmi:<ConsumerName>` / `run_key:<KeyPath\ValueName>`, resolved server-side to the correlated identity (fail-closed on ambiguity); achievability accepts only authored, complete subscriptions / Run-key SetValues (seed-independent). Scoring: occurrence-based, credit on required/acceptable, collateral off-list
- Gates: `python test_persistence.py`, `python test_persistence_response.py` (backend), plus the standard action-scoring/overlay/loader suites; frontend `endpoints.test.js` covers the persistence view + remove flow
- **Scenario answer keys unchanged by this increment** (engine only). The post-approval re-scaffold flips `defense_evasion_log_clearing` (D1: required `remove_persistence` on the WMI subscription, s5 1102 classification binding untouched, no ordering) and adds `defense_evasion` D2 (acceptable `remove_persistence` on the Run key; `delete_file` on svchost32 stays required) — each STOPPED for owner approval before the scenario changes

### Scenario Catalog (`CAMPAIGN_LEVELS`)
Despite the name, this is a flat catalog now — the level grouping only organizes the 20 definitions, it does not gate progression. Queue metadata (ticket_title/storyline) still comes from this dict; chains and triage reviews come from the YAML source:

| Group | Categories |
|-------|------------|
| 1 | Malware, Phishing, Defense Evasion, False Positive |
| 2 | Lateral Movement, C2, Brute Force, False Positive |
| 3 | Phishing, Data Exfiltration, Insider Threat, False Positive |
| 4 | Malware, Lateral Movement, Defense Evasion, False Positive |
| 5 | Insider Threat, Brute Force, C2, False Positive |

### False Positive Scenarios
Five FP scenarios simulate benign activity triggering alerts:
- `false_positive_pentest` — Security training generating test alerts
- `false_positive_robocopy` — Legitimate data migration
- `false_positive_veeam` — Backup software beaconing
- `false_positive_oauth` — Modern auth generating anomalies
- `false_positive_ssl_inspection` — Proxy SSL policy expansion

### Triage Review System

Educational content shown after analyst resolves a scenario. Stored in `TRIAGE_REVIEWS` dict in app.py.

**Structure:**
```python
TRIAGE_REVIEWS = {
    "scenario_label": {
        "mitre": {
            "id": "T1091",
            "name": "Replication Through Removable Media",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1091/"
        },
        "what_is_it": {
            "title": "USB-Based Malware",  # Attack technique name
            "description": "General educational description..."  # No "this scenario"
        },
        "response_actions": [
            "Step 1...",
            "Step 2..."
        ]
    }
}
```

**Guidelines for triage reviews:**
- `title`: Specific attack technique (not MITRE tactic)
- `description`: General education about the attack vector (never say "this scenario")
- `response_actions`: SOC playbook steps

**Completed triage reviews (all 20 scenarios — the 5 FP reviews have no `mitre` block):**
- Group 1: `malware_usb`, `phishing_1`, `defense_evasion`
- Group 2: `lateral_movement_1`, `c2_http`, `brute_force_attack`
- Group 3: `phishing_link`, `data_exfil_archive`, `insider_staging`
- Group 4: `malware_ransomware`, `lateral_movement_2`, `defense_evasion_log_clearing`
- Group 5: `insider_shadow_it`, `password_spray`, `c2_dns_tunnel`
- FPs: `false_positive_pentest`, `false_positive_robocopy`, `false_positive_veeam`, `false_positive_oauth`, `false_positive_ssl_inspection`

### Attack Log Injection

Attack logs are scattered among normal traffic (not batched):
- Normal traffic streams at ~1 event/sec while the session is running
- 2-3 normal logs between each attack event
- Attack chain timestamps: drip time + cumulative 3-8s offsets (a template may set `time_offset_seconds` to override; none currently do)
- Same employee/workstation/IP threads the entire chain (`chain_subs`)
- When a chain finishes writing, `finalize_chain` marks its logs `chain_complete`; only then does the scenario appear in the Alerts tab

### Dynamic Placeholders

Attack logs support placeholders that get substituted at runtime:
- `{username}` - Employee username
- `{hostname}` - Workstation name
- `{src_ip}` - Source IP
- `{user_domain}` - DOMAIN\username format

### Data Files (backend/logs/<session-id>/)
| File | Purpose |
|------|---------|
| `generated_logs.ndjson` | Simulated security events (attack + normal traffic) |
| `analyst_actions.ndjson` | User decisions (classify actions with category) |
| `incident_reports.ndjson` | Submitted incident reports |

Note: `simulated_attack_logs.ndjson` is at `backend/logs/` root (shared across sessions).

## API Endpoints (backend/app.py)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/health` | GET | Health check (frontend polls this on boot) |
| `/api/fake-events` | GET | Retrieve generated logs |
| `/api/reset-simulator` | POST | Clear logs, reset game state |
| `/api/current-level` | GET | Get current level, scenario history, level results |
| `/api/start-simulator` | POST | Start with selected game mode + analyst name |
| `/api/resume` | POST | Process analyst action (classify/resolve) |
| `/api/grouped-alerts` | GET | Get grouped threat scenarios with stats |
| `/api/reports` | GET/POST | Get/submit incident reports |
| `/api/reports/<id>` | PUT/DELETE | Update/delete reports |
| `/api/analytics/report_card` | GET | Get analyst performance metrics |
| `/api/analytics/action_history` | GET | Get last 10 classify actions with feedback |
| `/api/triage-review/<label>` | GET | Get educational content for scenario |
| `/api/endpoints` | GET | Endpoint list (session world summary rows + org) |
| `/api/endpoints/<hostname>` | GET | Full endpoint snapshot (all tabs), 404 unknown |
| `/api/analytics/attack_coverage` | GET | Dashboard radar: ATT&CK tactic coverage from completed scenarios only |
| `/api/detections` | GET | Detections feed (sanitized) + open/promoted/dismissed counts |
| `/api/detections/<id>` | GET | Detection detail (sanitized, whitelisted triggering events) |
| `/api/detections/<id>/disposition` | POST | Triage: promote / dismiss / open |
| `/api/threats` | GET | Promoted detections (Threats view) |
| `/api/analytics/detection_score` | GET | Disposition scoring v1 (deterministic, server-side) |
| `/api/analytics/action_score` | GET | Response-action scoring v1 (counts + grade only, no target detail) |
| `/api/actions` | POST | Execute one response action `{action, target: <ent-id>}` (Stage 3a) |
| `/api/actions` | GET | The session Response Log (whitelist-serialized attempts) |
| `/api/game-state` | GET | Get game mode, timer status, paused state |
| `/api/game-timeout` | POST | Hardcore timeout: pause session (FailureModal handles retry) |

## Running the Project

```bash
# Backend (runs on http://localhost:5000)
cd backend && pip install -r requirements.txt && python app.py

# Frontend (runs on http://localhost:3000)
cd frontend && npm install && npm start
```

## Event Log Format

```json
{
  "id": "unique-id",
  "timestamp": "ISO-8601",
  "event_type": "4624",
  "severity": "low|medium|high|critical",
  "hostname": "ACME-WS12",
  "source_ip": "10.10.10.21",
  "destination_ip": "10.10.1.10",
  "message": "Event description...",
  "label": "normal_traffic|malware_usb|phishing_1|...",
  "scenario_id": "scenario-xxx",
  "source_type": "Sysmon|Proxy|Windows Security|DNS|Firewall|Azure AD",
  "key_value_pairs": {},
  "status": "active|investigating|classified"
}
```

## Key Backend Variables (app.py)

- `CAMPAIGN_LEVELS`: scenario catalog — 5 groups of 4 (3 attacks + 1 FP); queue sampling ignores the grouping
- `TRIAGE_REVIEWS`: Educational content for each scenario (20 entries: 15 attacks + 5 FPs)
- `EMPLOYEES`: 45 realistic corporate employees across 8 departments
- `SERVERS`: 8 infrastructure hosts (DC, File, DNS, Print, Web at ACME-SVR01-05 / 10.0.1.200-204; Proxy at ACME-SVR06 / 10.0.1.205 is a PAN-OS VM-Series appliance, log source only, never a managed endpoint; Backup at ACME-VEEAM01 / 10.0.1.206; Scanner at ACME-SEC01 / 10.0.1.207, role `scanner`, managed). `SERVICE_ACCOUNTS`: canonical non-roster accounts (e.g. `svc_vulnscan`) referenced by supplemental telemetry
- `NORMAL_TRAFFIC_TEMPLATES`: 100+ templates for legitimate system events
- `TIMER_DURATIONS`: timer settings (only `get_timer_duration(1)` = 900s is used — one session timer, not per-level)
- `CONCURRENT_QUEUE_CAP`: max in-flight scenarios (3)

## Performance Grading

**Metrics tracked (4 buckets):**
- **Correct**: Real threats correctly classified
- **Missed**: Real threats with wrong category
- **FP Caught**: False positives correctly identified
- **FP Missed**: False positives incorrectly classified as threats

**Accuracy formula**: `(correct + fp_caught) / total_classifications * 100`

**Letter grade**: computed server-side in `report_card` (`grade` field, 10-point scale: A≥90, B≥80, C≥70, D≥60, F<60; `-` before any classification). Frontend components render `report.grade` — do not re-derive it client-side.

## Development Notes

### Adding New Scenarios (schema v2)
1. Author `backend/scenarios/v2/<label>.yaml` with `schema_version: 2` — narrative, entities, environment, attack (tagged chain), `noise: {}`, answer_key, triage_review; the loader validates schema + referential integrity at boot
2. Add the scenario to `CAMPAIGN_LEVELS` with the same unique `scenario_label` (still drives queue sampling + ticket metadata)
3. Run the gates: `python test_scenario_loader_v2.py` and `python fairness_check.py` from `backend/`
4. The legacy NDJSON file and `TRIAGE_REVIEWS` dict serve only the revert paths — do not extend them for new scenarios

### Scenario Label Convention
Each scenario label should be unique across the whole catalog. If a category repeats, use different attack variants:
- `malware_usb` vs `malware_ransomware`

### MITRE ATT&CK baseline (pinned to v19.1)
- Corpus mappings are pinned to **Enterprise ATT&CK v19.1** — migrated 2026-07-17 from the pre-v19 (v18.1) baseline and validated against the official v19.1 STIX dataset (github.com/mitre/cti tag `ATT&CK-v19.1`; `enterprise-attack.json` sha256 `fc783039…2cf1c97d`, recorded in `test_scenario_loader_v2.py`). v19 retired Defense Evasion, splitting it into **Stealth (TA0005)** + **Defense Impairment (TA0112)**, and merged `T1562`/`T1070.001` under **`T1685`**; the corpus carries `T1685`/`T1685.005` (Disable or Modify Tools family) accordingly. See `docs/classification-rubrics.md`.
- **Standing rule (any requester):** an ATT&CK version bump is **one deliberate migration** — pinned version + rebuilt canonical maps + all corpus values (answer keys, detection tags, triage via the correction registry, radar axes) migrated together, validated against that version's official STIX dataset (tag + file hash recorded). Never ambient drift; new detections are tagged against the pinned map (`CANONICAL_TECHNIQUE_NAMES` ∪ `PINNED_DETECTION_TECHNIQUES`), never leaving content untagged.
- **Migration boundary principle:** commit boundaries are drawn where the repository is internally consistent, as defined by its own invariant guards. The pin, name-match, and coverage tests couple the maps to the corpus by exact equality, so a guard that would be red at a proposed boundary means the boundary is wrong, not the guard — **never land a knowingly-red commit; never loosen a guard to tolerate a transition.** (Hence maps + values + radar migrate atomically.)
- `test_corpus_strings_match_pinned_attack_baseline` enforces the pin positively: every corpus technique ID / tactic name must be a pinned v19.1 string. (It once wrongly blacklisted `T1685.005`/"Defense Impairment" as nonexistent — retracted 2026-07-16; both are real, now-adopted v19.1 identifiers.)

### Deviation-flagging rule (process, ruled 2026-07-17)
- **Describing an implementation choice in a report is NOT the same as flagging a deviation.** Any divergence from an approved specification — including believed-equivalent narrowings ("this component is redundant", "this is equivalent to X") — must be explicitly called out as a DEVIATION, with its justification, AT THE TIME it is made (in the report and in the code/docs), not merely described in passing. The owner decides whether the narrowing is accepted; a silent-because-believed-equivalent change forfeits that review. Precedent: the 3c.5 WMI identity dropped the approved binding-path component as redundant and only described it — it should have been flagged as a deviation (reconciled 2026-07-17 via the `__FilterToConsumerBinding` key proof).

### Never-land-red gate enforcement
- **Principle:** a commit must never land with a known-red suite; a guard red at a commit boundary means the boundary is wrong, never the guard.
- **Mechanism (exact, ruled at the 3c Batch 1 review):** `python backend/run_gates.py` is the ONE canonical halt-on-failure gate command (exits at the first failed suite; `--frontend` / `--all` scope it). The versioned pre-commit hook `.githooks/pre-commit` invokes it scoped to the staged paths (backend/* triggers the backend battery, frontend/src/* the frontend suite; docs-only commits skip) and aborts the commit on failure. Enforcement is active in a clone only after the one-time setup `git config core.hooksPath .githooks` (already set in this repository). Never bypass with `--no-verify`; extend `run_gates.py`'s suite lists when a new suite becomes a gate.

### Deployment
- Backend must run as a **single worker** (`gunicorn.conf.py` pins `workers = 1`, `threads = 8`); sessions and log-writer threads live in-process

## UI Architecture

### Dashboard Tabs (Dashboard.jsx)
- 6 tabs: Alerts, SIEM, Detections, Endpoints, Metrics, Reports (SIEM was "Events" pre Stage 1.5; Detections added Stage 2)
- Counts always shown (Splunk-style): `Alerts 3`, `SIEM 12`, `Detections 5` (open count)
- Keyboard shortcuts: 1-6 to switch tabs
- Chart-bearing views (Alerts/GroupedAlerts, Metrics/Analytics) gate their Recharts on an `isVisible` prop so hidden charts don't mount at 0 size and flood console width(0) warnings

### SIEM Tab (Siem.jsx + SiemCards / SiemTable, Stage 1.5)
- Renamed from Events; card view (default, `SiemCards`) + table view (`SiemTable`) toggle, both over the cached session pool (`siemUtils.js` shared logic)
- Dropdown filters (Source/Platform/Event Type, values derived from the pool), free-text search, time presets anchored to the pool's latest timestamp (frozen scenario clock, never wall time)
- Raw-log JSON view renders `sanitizeEvent` output only (whitelist); simulation-internal fields never leak
- No query language (that is Stage 4 — see docs/stage4-query-grammar-notes.md)

### Dashboard Charts (GroupedAlerts.jsx, Stage 1.5)
- Queue donut + Severity bars + ATT&CK Coverage radar (Source/Category bars removed)
- Radar fed ONLY by `/api/analytics/attack_coverage` (completed scenarios' answer-key tactics); never reflects the in-progress scenario (answer-leak guard, `compute_attack_coverage` + `test_attack_coverage.py`)
- Radar is a fixed-size RadarChart (no ResponsiveContainer) to avoid poll-driven ResizeObserver thrash
- Dark table headers app-wide via the `.dark-thead` class (`index.css`); see docs/ui-design-notes.md
- GameTimer positioned above the main card, right-aligned
- Auto-detects incident completion (running->paused transition) and increments badge

### Table Components (AlertTable.jsx, Reports.jsx)
- Both use HTML table layout with expandable rows (chevron on left column)
- Expanded rows use CSS grid animation (`grid-rows-[1fr]`/`grid-rows-[0fr]`) for smooth open/close
- Search bars always render (visible in pre-data stage, not gated behind data count)
- Reports status dropdown uses `position: fixed` with `getBoundingClientRect()` to escape table overflow
- Reports supports PDF export via html2canvas + jsPDF

### Charts & Analytics (GroupedAlerts.jsx, PerformanceGrade.jsx)
- Ring charts: `w-36 h-36 sm:w-80 sm:h-80` with dashed border, center number
- Center overlay uses `pointer-events-none` so ring segment tooltips work; center number uses `pointer-events-auto`
- Custom `PieTooltip` component for ring chart segments (dark bg, "Name: value" format, `wrapperStyle={{ zIndex: 20 }}`)
- Results bar chart: 4 bars (Correct green, Missed red, FP Caught/Missed gray)
- Total Alerts ring: Active (light gray `#d1d5db`) + Completed (dark gray `#4b5563`)
- Legend shows inline layout (color dot + label + number)

### GroupedAlerts.jsx (Alerts Tab)
- Scenario tracking with Active/Completed filter (defaults Active only)
- Scenario history synced from backend `scenario_history` (source of truth)
- `scenario_start_time` tracked in backend for accurate relative timestamps
- Ring chart dashboard: Total Alerts / Alert Source toggle, Alert Severity / Alert Category toggle
- Notable Events section with per-scenario classify/FP/report buttons
- Fade-out animation when scenario completes with Completed filter off

### State Management Patterns
- `resetTrigger` counter: incremented on reset, children re-fetch in useEffect
- `setXCount` callbacks: children update parent tab counts
- Auto-refresh: most components poll every 2-3 seconds via `setInterval`
- Expandable rows: `useState({})` with grid animation toggle
- Disappearing items: `fadingOutId` + `setTimeout` + opacity transition
- Submitting guards: `Set()` of in-progress IDs to prevent double-submit
