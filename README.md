# Spectyr
A SIEM simulation built for training cybersecurity analysts. It generates security event logs, injects attack scenarios into normal traffic, and lets you practice detecting, triaging, and reporting threats in a SOC-style interface.

<!-- ![Spectyr](./assets/spectyr-demo.png) -->

## Features

### Campaign System

5 levels, each with a randomly selected attack scenario from a pool of three categories. The scenarios get harder as you go.

**Categories:**

- Malware
- Phishing
- Command & Control
- Lateral Movement
- Brute Force
- Data Exfiltration
- Insider Threat
- Defense Evasion

<!-- ![Campaign](./assets/campaign.png) -->

### Game Modes

- **Training**: No time limit. Take as long as you need to work through each scenario.
- **Hardcore**: Timed countdown that scales with difficulty. 1 wrong classification or 3 wrong flags resets you to Level 1.

<!-- ![Game Modes](./assets/game-modes.png) -->

### Alert Generation

Hit **Start Training** and the simulator starts producing logs from different sources (Sysmon, Windows Security, Firewall, Proxy, DNS). After a few benign logs, an attack chain gets injected into the stream. False positives are mixed in to keep you on your toes.

<!-- ![Events Tab](./assets/events-tab.png) -->

### Incident Grouping & Classification

Related attack logs are grouped together by `scenario_id` so you can investigate them as a single incident instead of chasing individual alerts. Each group shows a Notable Event label. Your job is to classify it by picking the correct attack category.

<!-- ![Incidents Tab](./assets/incidents-tab.png) -->

### Triage Reviews

After you classify a scenario, you get a breakdown of what happened:

- **MITRE ATT&CK mapping** with technique ID, tactic, and a link to the MITRE page
- **Explanation** of the attack technique
- **Response actions** you'd take in a real SOC

<!-- ![Triage Review](./assets/triage-review.png) -->

### Incident Reports

You can write up incident reports with fields for title, description, severity, MITRE tactic, kill chain phase, affected hosts, mitigation steps, and status. Reports can be edited, deleted, or exported as PDF.

<!-- ![Reports Tab](./assets/reports-tab.png) -->

### Performance Scoring

Your report card tracks correct/wrong classifications, flag accuracy, and overall accuracy percentage.


<!-- ![Analytics](./assets/analytics.png) -->
