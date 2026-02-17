# Ghost SIEM

## Table of Contents

### 1. [Introduction](#introduction)
### 2. [Features](#features)
### 3. [Installation & Setup](#installation--setup)
### 4. [Use Cases](#use-cases)

---

# 1. Introduction

**Ghost** is a full-stack **Security Information and Event Management** (SIEM) simulation that replicates a real-world **Security Operations Center** (SOC) environment.

The platform is designed for cybersecurity analyst training, blue team workflows, and hands-on portfolio development in a home lab environment.

---

# 2. Features 

**Ghost** includes a full suite of features designed to simulate a real-world SIEM environment. 

It supports simulated live alert generation, grouped threat patterns, analyst triage actions, incident reporting, threat analytics, and performance scoring

---

## **Simulated Live Alert Generation**

![Events Tab](./assets/ghost-siem-demo-1.png)

Clicking Simulate Events generates a stream of security event logs from various log sources (e.g., firewall, application, operating system), simulating normal background traffic commonly observed in a real SIEM environment.

After several benign logs are generated, a simulated attack scenario is injected to emulate a coordinated threat actor action.

![Attack Scenario](./assets/ghost-siem-demo-9.png)

These patterns are structured to resemble real-world hacker tactics, allowing analysts to practice identifying various threat types, including:

- **Brute Force Attacks**

- **Command & Control (C2)** 

- **Persistence Mechanisms**

- **Malware Execution**

- **Data Exfiltration**

- **Insider Threats**

False positives are intentionally injected into the log stream to assess the analyst’s ability to accurately differentiate between legitimate threats and benign activity.

---

## **Grouped Threat Patterns & Analyst Triage Actions**
**Ghost** automatically groups related logs into threat scenarios using a shared `scenario_id`, enabling more detailed investigations into grouped threat patterns over isolated alerts.

![Patterns Tab](./assets/ghost-siem-demo-4.png)

- Groups are formed based on predefined attack sequences, such as multi-step exploits: (e.g., initial access → command execution → data exfiltration).

- Each group is labeled with a **Notable Event** type and a **severity level** 

- Analysts can take decisive actions — **Investigate, Escalate, or Dismiss:**
  
  - **Investigate:** Opens the incident report workflow 

  - **Escalate:** Flags the scenario as a confirmed threat

  - **Dismiss:** Marks the scenario as a false positive

Grouped alerts appear in the **Patterns Tab**, which includes a toggle to switch between:
  
   - **Active Threats:** - Unresolved scenarios that require analyst attention
       
   - **Past Incidents:** - Resolved or reviewed scenarios for post-analysis

![Past Incidents](./assets/ghost-siem-demo-7.png)

---

## **Incident Reporting & Threat Categorization**
Allows analysts to submit detailed incident reports capturing investigation results, threat classification, and remediation steps.

![Incident Report](./assets/ghost-siem-demo-5.png)

Includes an **Incident Report Form** with the following fields:
  
   - Title
       
   - Description
       
   - Severity
       
   - Category
       
   - Affected Hosts
       
   - Mitigation Steps
       
   - Status

  ![Reports Tab](./assets/ghost-siem-demo-6.png)

Reports are stored and displayed in the **Reports Tab**, where analysts can:
   
   - View and manage reports
        
   - Edit report details
        
   - Export reports for documentation and tracking

---

## **Threat Analytics & Performance Scoring**

Includes a real-time analytics dashboard displaying total alerts, critical alert counts, high severity rates, and analyst performance metrics

![Analytics](./assets/ghost-siem-demo-3.png)
  
The **Analyst Report Card** displays:
     
  - Dismissed False Positives
    
  - Escalated True Threats

  - Correct Investigations
    
  - Misclassified Alerts
    
  - Total Actions
          
**Performance Grade** uses an A–F scale:

| Grade | Accuracy |
|-------|----------|
| A     | ≥ 90%    |
| B     | 80–89%   |
| C     | 70–79%   |
| D     | 60–69%   |
| F     | < 60%    |

Grades are calculated by comparing correct actions (escalate/investigate/dismiss) against misclassifications.

---

## **Interactive Analyst Experience with Real-Time Feedback**
Delivers a responsive, dark-mode UI that mimics the look and feel of modern SIEM platforms like Splunk.

- **Ghost-themed mascot** that guides the analyst and provides contextual feedback based on analyst performance
  
- **Interactive notifications and scenario indicators** offer real-time visual feedback
  
- **High-contrast SOC interface** designed for clarity, accessibility, and realistic analyst workflows

 ![Visual](./assets/ghost-siem-demo-10.png)

 ---

# 3. Installation & Setup

Follow these steps to run **Ghost** locally on your machine:

### 1. Clone the Repository
  
      git clone https://github.com/jordanjmartinez/ghost-siem-simulator.git
      cd ghost-siem-simulator

### 2. Set Up the Backend

      cd ghost-siem-simulator/backend
      pip install -r requirements.txt
      python app.py

### 3. Set Up the Frontend 

      cd ghost-siem-simulator/frontend
      npm install
      npm start
      
      
### 4. Launch the Simulator

Open your browser and navigate to: (http://localhost:3000)
      
 ---     

 # 4. Use Cases

**Ghost** is built for cybersecurity students, entry-level analysts, and anyone looking to gain hands-on experience with real-world SOC workflows. 

Whether you're preparing for a blue team role or building a cybersecurity portfolio, this simulation helps you practice threat detection, incident triage, and reporting in a controlled, interactive environment.

The project was built as a practical platform for learning and demonstrating cybersecurity skills, with key goals to:
 
- Practice analyst workflows in a simulated SOC environment
  
- Demonstrate threat detection and incident response skills
  
- Train new blue team members or students in realistic triage scenarios
  
- Showcase SOC analyst capabilities in a portfolio project
