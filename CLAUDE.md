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
- Sessions expire after 30 minutes of inactivity (daemon cleanup thread)
- Each session has its own log directory under `backend/logs/<session-id>/`

### Game Modes
- **Training Mode**: Unlimited time, continuous feedback, no penalties
- **Hardcore Mode**: 15-minute global timer (900s per level), single-strike penalty (wrong classify = reset to Level 1)

### Campaign System
- 5 progressive levels with increasing difficulty
- Each level has 4 possible scenarios (3 attack categories + 1 false positive)
- One scenario is randomly selected per level
- Chain length is flexible per scenario (not tied to level number)
- **IMPORTANT**: Each level must have UNIQUE scenario_labels — no duplicates across levels

### Level Structure

| Level | Categories |
|-------|------------|
| 1 | Malware, Phishing, Defense Evasion, False Positive |
| 2 | Lateral Movement, C2, Brute Force, False Positive |
| 3 | Phishing, Data Exfiltration, Insider Threat, False Positive |
| 4 | Malware, Lateral Movement, Defense Evasion, False Positive |
| 5 | Insider Threat, Brute Force, C2, False Positive |

### False Positive Scenarios
Each level has one FP scenario that simulates benign activity triggering alerts:
- Level 1: `false_positive_pentest` — Security training generating test alerts
- Level 2: `false_positive_robocopy` — Legitimate data migration
- Level 3: `false_positive_veeam` — Backup software beaconing
- Level 4: `false_positive_oauth` — Modern auth generating anomalies
- Level 5: `false_positive_ssl_inspection` — Proxy SSL policy expansion

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

**Completed triage reviews (all 15 scenarios):**
- Level 1: `malware_usb`, `phishing_1`, `defense_evasion`
- Level 2: `lateral_movement_1`, `c2_http`, `brute_force_attack`
- Level 3: `phishing_link`, `data_exfil_archive`, `insider_staging`
- Level 4: `malware_ransomware`, `lateral_movement_2`, `defense_evasion_log_clearing`
- Level 5: `insider_shadow_it`, `password_spray`, `c2_dns_tunnel`

### Attack Log Injection

Attack logs are scattered among normal traffic (not batched):
- Random start position (3-15 logs into level)
- 2-3 normal logs between each attack event
- Progressive timestamps for attack chain
- 2-4 trailing normal logs before pause
- Same employee/workstation/IP used for entire chain

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
| `/api/current-scenario` | GET | Get active attack scenario |
| `/api/grouped-alerts` | GET | Get grouped threat scenarios with stats |
| `/api/reports` | GET/POST | Get/submit incident reports |
| `/api/reports/<id>` | PUT/DELETE | Update/delete reports |
| `/api/analytics` | GET | Get threat analytics (totals, severity, weekly) |
| `/api/analytics/report_card` | GET | Get analyst performance metrics |
| `/api/analytics/action_history` | GET | Get last 10 classify actions with feedback |
| `/api/triage-review/<label>` | GET | Get educational content for scenario |
| `/api/game-state` | GET | Get game mode, timer status, paused state |
| `/api/game-timeout` | POST | Handle hardcore mode timeout (reset to Level 1) |

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

- `CAMPAIGN_LEVELS`: 5-level progression system (4 scenarios each: 3 attacks + 1 FP)
- `TRIAGE_REVIEWS`: Educational content for each scenario (15 entries)
- `EMPLOYEES`: 45 realistic corporate employees across 8 departments
- `SERVERS`: 6 infrastructure servers (DC, File, DNS, Print, Web, Proxy)
- `NORMAL_TRAFFIC_TEMPLATES`: 100+ templates for legitimate system events
- `TIMER_DURATIONS`: Per-level timer settings (all 900s currently)

## Performance Grading

**Metrics tracked (4 buckets):**
- **Correct**: Real threats correctly classified
- **Missed**: Real threats with wrong category
- **FP Caught**: False positives correctly identified
- **FP Missed**: False positives incorrectly classified as threats

**Accuracy formula**: `(correct + fp_caught) / total_classifications * 100`

## Development Notes

### Adding New Scenarios
1. Create research document in `campaign/Level X/`
2. Add scenario to `CAMPAIGN_LEVELS` with unique `scenario_label`
3. Add attack log(s) to `simulated_attack_logs.ndjson` with dynamic placeholders
4. Add triage review to `TRIAGE_REVIEWS` dict
5. Test the full flow

### Scenario Label Convention
Each scenario label should be unique across ALL levels. If a category repeats in multiple levels, use different attack variants:
- Level 1 Malware: `malware_usb`
- Level 4 Malware: `malware_ransomware`

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

## Future Deployment: Hardcore Mode Redesign

### Overview
Transform Hardcore from "Training with timer + penalty" into a realistic SOC queue simulation with concurrent alerts and time pressure.

### Design (Not Yet Implemented)
- **Rolling queue**: 10 total alerts, steady drip (~1 per minute)
- **20-minute global timer**: All alerts injected by minute 10, last 10 minutes for resolution
- **3-strike policy**: 3 wrong classifications = game over (timer stops, FailureModal shown)
- **No level progression**: Scenarios randomly drawn from all 15 attack scenarios
- **No duplicate scenarios**: Each of the 10 alerts must be a unique scenario (no repeats in a single game)
- **FP injection**: 1-3 of the 10 alerts are false positives (max 3 FPs per game)
- **Concurrent alerts**: Multiple active alerts at once (not one-at-a-time)
- **Per-alert controls**: Each alert gets its own Classify / False Positive / Create Report buttons
- **Collapsible by Alert ID**: Logs grouped and expandable per alert
- **Triage reviews**: Available but dismissible (player can skip to maintain pace)
- **Level column**: Replace level number with alert indicator (e.g., ! icon)
- **Lives system**: Replace Simulation Progress with "Lives" — 3 dots, each wrong answer replaces a dot with the failure icon (same icon as GameTimer). 3 strikes = game over screen (existing FailureModal)

### Key Backend Changes Needed
- New queue injection system (time-based, not level-based)
- Random scenario selection from full pool (all 15 scenarios), with 1-3 randomly assigned as FPs
- 3-strike tracking in session state
- 20-minute global timer (replaces per-level timer)
- Game over trigger when strikes reach 3

### Key Frontend Changes Needed
- GroupedAlerts: support multiple concurrent active scenarios
- Per-alert action buttons (classify, FP, report)
- Alert ID-based log collapsing
- New Lives component (3 dots → failure icons on strike)
- Strike counter integrated with FailureModal trigger
