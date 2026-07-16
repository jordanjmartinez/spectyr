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
- Migration + review artifact: `scenarios/migrate_v1_to_v2.py` regenerates `scenarios/v2/` and `scenarios/v2/MIGRATION_REPORT.md` (per-step tag tables, grandfathered literals, open flags)

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
- `SERVERS`: 7 infrastructure servers (DC, File, DNS, Print, Web, Proxy at ACME-SVR01-06 / 10.0.1.200-205; Backup at ACME-VEEAM01 / 10.0.1.206)
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

### Deployment
- Backend must run as a **single worker** (`gunicorn.conf.py` pins `workers = 1`, `threads = 8`); sessions and log-writer threads live in-process

## UI Architecture

### Dashboard Tabs (Dashboard.jsx)
- 4 tabs: Alerts, Events, Analytics, Reports
- CSS Grid layout: Mobile `grid-cols-4`, Desktop `grid-cols-[8rem_8rem_8.5rem_8rem]`
- Counts always shown (Splunk-style): `Alerts 3`, `Events 12`
- Keyboard shortcuts: 1-4 to switch tabs
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
