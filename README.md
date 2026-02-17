# Spectyr

A full-stack **Security Information and Event Management (SIEM)** simulation platform for training cybersecurity analysts and blue team professionals.

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Installation & Setup](#installation--setup)
5. [Use Cases](#use-cases)

---

## Introduction

**Spectyr** is a SIEM simulation that replicates a real-world **Security Operations Center (SOC)** environment. It generates realistic security event logs from multiple sources, injects coordinated attack scenarios, and challenges analysts to detect, triage, and report threats — all within an interactive, dark-mode interface designed to mirror production SIEM platforms.

The platform is built for cybersecurity analyst training, blue team skill development, and hands-on portfolio projects in a home lab environment.

---

## Features

### Campaign System

Spectyr features a 5-level progressive campaign where each level presents a randomly selected attack scenario from a pool of three possible categories. Difficulty increases as analysts advance through levels, introducing more complex multi-step attack chains.

**Attack categories include:**

- Malware (USB-based, Ransomware)
- Phishing (Typosquatting, Spearphishing)
- Command & Control (HTTPS Beaconing, DNS Tunneling)
- Lateral Movement (Recon/Port Scanning, Credential Gathering)
- Brute Force (Dictionary Attack, Password Spraying)
- Data Exfiltration (Archive Upload)
- Insider Threat (Data Staging, Shadow IT)
- Defense Evasion (Disabling Security Tools, Log Clearing)

<!-- ![Campaign](./assets/campaign.png) -->

---

### Game Modes

- **Training Mode** — Unlimited time with continuous feedback. Ideal for learning SOC workflows at your own pace.
- **Hardcore Mode** — A 2-minute countdown timer per level with single-strike penalties. Designed to simulate the pressure of a real-time SOC environment.

<!-- ![Game Modes](./assets/game-modes.png) -->

---

### Simulated Live Alert Generation

Clicking **Simulate Events** generates a stream of security event logs from various sources (Sysmon, Windows Security, Firewall, Proxy, DNS), simulating normal background traffic observed in a real SIEM environment.

After several benign logs are generated, a coordinated attack scenario is injected among the normal traffic. False positives are intentionally mixed in to test the analyst's ability to differentiate between legitimate threats and benign activity.

<!-- ![Events Tab](./assets/events-tab.png) -->

---

### Grouped Threat Patterns & Analyst Triage

Related logs are automatically grouped into threat scenarios using a shared `scenario_id`, enabling detailed investigation of grouped threat patterns over isolated alerts.

- Groups are formed based on predefined attack sequences (e.g., initial access > command execution > data exfiltration)
- Each group is labeled with a **Notable Event** type and **severity level**
- Analysts can take decisive actions — **Investigate**, **Escalate**, or **Dismiss**:
  - **Investigate** — Opens the incident report workflow
  - **Escalate** — Flags the scenario as a confirmed threat
  - **Dismiss** — Marks the scenario as a false positive

The **Patterns Tab** includes a toggle between **Active Threats** (unresolved) and **Past Incidents** (resolved).

<!-- ![Patterns Tab](./assets/patterns-tab.png) -->

---

### Triage Reviews & MITRE ATT&CK Integration

After an analyst resolves a scenario, Spectyr presents an educational **Triage Review** that includes:

- **MITRE ATT&CK mapping** — Technique ID, name, tactic, and direct link to the MITRE knowledge base
- **Attack explanation** — What the attack technique is and how it works
- **Response actions** — SOC playbook steps for handling the threat in a real environment

<!-- ![Triage Review](./assets/triage-review.png) -->

---

### Incident Reporting & PDF Export

Analysts can submit detailed incident reports capturing investigation results, threat classification, and remediation steps.

Report fields include:
- Title, Description, Severity, Category
- Affected Hosts, Mitigation Steps, Status

Reports are stored in the **Reports Tab** where analysts can view, edit, delete, and **export reports as PDF** for documentation and tracking.

<!-- ![Reports Tab](./assets/reports-tab.png) -->

---

### Threat Analytics & Performance Scoring

A real-time analytics dashboard displays total alerts, critical alert counts, severity breakdowns, and analyst performance metrics.

The **Analyst Report Card** tracks:
- Dismissed False Positives
- Escalated True Threats
- Correct Investigations
- Misclassified Alerts
- Total Actions

**Performance Grade** uses an A-F scale:

| Grade | Accuracy |
|-------|----------|
| A     | >= 90%   |
| B     | 80-89%   |
| C     | 70-79%   |
| D     | 60-69%   |
| F     | < 60%    |

<!-- ![Analytics](./assets/analytics.png) -->

---

## Tech Stack

- **Backend**: Python, Flask, Faker (event generation), flask-cors
- **Frontend**: React, Tailwind CSS, Recharts (analytics charts), jsPDF (PDF export), react-toastify (notifications)
- **Data Storage**: NDJSON flat files

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/jordanjmartinez/spectyr.git
cd spectyr
```

### 2. Set Up the Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The backend runs on `http://localhost:5000`.

### 3. Set Up the Frontend

```bash
cd frontend
npm install
npm start
```

The frontend runs on `http://localhost:3000`.

### 4. Launch the Simulator

Open your browser and navigate to [http://localhost:3000](http://localhost:3000).

---

## Use Cases

**Spectyr** is built for cybersecurity students, entry-level analysts, and anyone looking to gain hands-on experience with real-world SOC workflows.

Whether you're preparing for a blue team role or building a cybersecurity portfolio, this platform helps you practice threat detection, incident triage, and reporting in a controlled, interactive environment.

- Practice analyst workflows in a simulated SOC environment
- Demonstrate threat detection and incident response skills
- Train new blue team members or students in realistic triage scenarios
- Showcase SOC analyst capabilities in a portfolio project
- Learn MITRE ATT&CK techniques through interactive triage reviews
