# Spectyr

A SIEM simulation platform for training cybersecurity analysts. Spectyr generates realistic security logs, injects attack scenarios into normal network traffic, and drops you into a SOC-style interface where you detect, triage, and report threats.

## Live Demo

[spectyr.dev](https://spectyr.dev)

---

## Features

### Rolling Alert Queue

Each run builds a randomized queue from the playable scenario catalog — currently five hand-picked incidents spanning ransomware, event-log clearing with WMI persistence, password spraying, DNS tunneling C2, and a security-training false positive, with more scenarios on the way — dripping into your queue with up to 3 incidents in flight at once, the way a real shift does. At least one is a false positive designed to test whether you can tell the difference.

**Attack Categories:** Malware, Phishing, Command & Control, Lateral Movement, Brute Force, Data Exfiltration, Insider Threat, Defense Evasion

**False Positives:** Not every alert is a real threat. Benign activity — security training tools, backup software, data migrations, OAuth flows — can look suspicious without being hostile. Identifying it correctly is part of your score.

### Game Modes

- **Guided** — Pick your scenario (or take a random one), no timer, optional Check Answer. Learn at your own pace and review feedback after each incident.
- **Hardcore** — 15-minute countdown for the whole queue. One wrong submission — or the clock hitting zero — ends the run.

### Log Generation

Start a simulation and logs begin streaming in from multiple sources — Sysmon, Windows Security, Firewall, Proxy, DNS, and Azure AD. An attack chain gets scattered into the normal traffic with realistic timing and spacing, just like it would in a real environment.

### Triage & Classification

Attack logs are grouped by scenario into a single incident view. Expand the event chain, review the details, and classify it — pick the correct attack category or flag it as a false positive. In Hardcore mode, you only get one shot.

### Post-Incident Review

After each classification, Spectyr provides a post-incident review for the scenario:

- **MITRE ATT&CK** technique ID, tactic, and a direct link to the framework
- **What happened** — a breakdown of the attack technique
- **Response playbook** — the steps a SOC analyst would take

All 15 attack scenarios include full post-incident reviews, covering everything from USB-based malware to DNS tunneling.

### Reports

Document your findings with structured reports — title, description, severity, MITRE tactic, kill chain phase, affected systems, and mitigation steps. Export any report as a PDF.

### Analytics

Track your performance across four metrics:

- **Correct** — threats you classified accurately
- **Missed** — threats you got wrong
- **FP Caught** — false positives you correctly identified
- **FP Missed** — false positives you mistook for real threats

Your results are shown in a bar chart alongside an overall accuracy percentage, with a full breakdown in the report card.
