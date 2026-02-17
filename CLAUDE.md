# SPECTYR

A full-stack Security Information and Event Management (SIEM) simulation platform for training cybersecurity analysts and blue team professionals.

## Project Structure

```
├── backend/                 # Flask Python backend
│   ├── app.py              # Main application (all simulation logic, API endpoints)
│   ├── api/analytics/      # Analytics API blueprint
│   ├── logs/               # NDJSON log files (generated at runtime)
│   └── requirements.txt
├── frontend/               # React + Tailwind CSS frontend
│   ├── src/
│   │   ├── App.jsx         # Main app with routing
│   │   ├── pages/
│   │   │   └── Dashboard.jsx    # Main dashboard (simulation control, view switching)
│   │   └── components/
│   │       ├── AlertTable.jsx       # Raw event log display
│   │       ├── GroupedAlerts.jsx    # Threat pattern grouping
│   │       ├── IncidentReportForm.jsx
│   │       ├── Reports.jsx          # Report management + PDF export
│   │       ├── Analytics.jsx        # Threat dashboard
│   │       ├── AnalystReportCard.jsx # Performance scoring
│   │       ├── ActionHistory.jsx    # Triage Review panel with MITRE education
│   │       ├── GameTimer.jsx        # Hardcore mode countdown
│   │       ├── DifficultySelector.jsx
│   │       ├── CategorySelector.jsx
│   │       ├── CampaignProgress.jsx
│   │       ├── PerformanceGrade.jsx
│   │       ├── StatCards.jsx
│   │       └── Navbar.jsx
│   ├── package.json
│   └── tailwind.config.js
├── campaign/                # Research documents for scenario content
│   ├── Level 1/
│   ├── Level 2/
│   ├── Level 3/
│   ├── Level 4/
│   └── Level 5/
├── normal traffic/          # Reference docs for normal event generation
└── README.md
```

## Tech Stack

- **Backend**: Flask 3.1.1, Faker 37.3.0 (event generation), flask-cors
- **Frontend**: React 19.1.0, Tailwind CSS 3.4.1, Recharts 2.15.3, jsPDF 3.0.1, react-toastify, react-router-dom 7.6.0, canvas-confetti, html2canvas
- **Data Storage**: NDJSON files in `backend/logs/`

## Key Concepts

### Game Modes
- **Training Mode**: Unlimited time, continuous feedback
- **Hardcore Mode**: 2-minute timer per level, single-strike penalty

### Campaign System
- 5 progressive levels with increasing difficulty
- Each level has 3 possible attack scenarios (randomly selected)
- One scenario is randomly selected per level
- Chain length is flexible per scenario (not tied to level number)
- **IMPORTANT**: Each level must have UNIQUE scenario_labels — no duplicates across levels

### Level Structure

| Level | Categories |
|-------|------------|
| 1 | Malware, Phishing, Defense Evasion |
| 2 | Lateral Movement, C2, Brute Force |
| 3 | Phishing, Data Exfiltration, Insider Threat |
| 4 | Malware, Lateral Movement, Defense Evasion |
| 5 | Insider Threat, Brute Force, C2 |

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

**Completed triage reviews:**
- Level 1: `malware_usb`, `phishing_1`, `defense_evasion`

### Attack Log Injection

Attack logs are scattered among normal traffic (not batched):
- Random start position (3-15 logs into level)
- 2-3 normal logs between each attack event
- Progressive timestamps for attack chain
- 2-4 trailing normal logs before pause

### Dynamic Placeholders

Attack logs support placeholders that get substituted at runtime:
- `{username}` - Employee username
- `{hostname}` - Workstation name
- `{src_ip}` - Source IP
- `{user_domain}` - DOMAIN\username format

### Data Files (backend/logs/)
| File | Purpose |
|------|---------|
| `generated_logs.ndjson` | Simulated security events |
| `simulated_attack_logs.ndjson` | Pre-built attack scenario templates |
| `analyst_actions.ndjson` | User decisions (investigate/escalate/dismiss) |
| `incident_reports.ndjson` | Submitted incident reports |

## API Endpoints (backend/app.py)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/fake-events` | GET | Retrieve generated logs |
| `/api/reset-simulator` | POST | Clear logs, reset game state |
| `/api/current-level` | GET | Get current campaign level |
| `/api/start-simulator` | POST | Start with selected game mode |
| `/api/resume` | POST | Process analyst action |
| `/api/current-scenario` | GET | Get active attack scenario |
| `/api/grouped-alerts` | GET | Get grouped threat scenarios |
| `/api/reports` | GET/POST | Get/submit incident reports |
| `/api/reports/<id>` | PUT/DELETE | Update/delete reports |
| `/api/analytics` | GET | Get threat analytics |
| `/api/analytics/report_card` | GET | Get analyst performance metrics |
| `/api/analytics/action_history` | GET | Get analyst action history |
| `/api/triage-review/<label>` | GET | Get educational content for scenario |
| `/api/game-state` | GET | Get current game state |
| `/api/game-timeout` | POST | Handle hardcore mode timeout |

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
  "source_type": "Sysmon|Proxy|Windows Security Log|...",
  "key_value_pairs": {},
  "status": "pending|investigating|escalated|dismissed|classified"
}
```

## Key Backend Variables (app.py)

- `CAMPAIGN_LEVELS`: 5-level progression system
- `TRIAGE_REVIEWS`: Educational content for each scenario
- `EMPLOYEES`: 20 realistic corporate employees
- `SERVERS`: 10 infrastructure servers
- `NORMAL_EVENT_CONFIGS`: Templates for legitimate system events

## Performance Grading

- A: ≥90% accuracy
- B: 80-89%
- C: 70-79%
- D: 60-69%
- F: <60%

Metrics tracked: Threats Caught, Threats Missed

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
