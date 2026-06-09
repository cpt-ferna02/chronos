import os

BASE = "/home/cpt-ferna02/chronos/docs"

# ── Architecture Diagram (SVG) ─────────────────────────────────────────────────
svg = """<svg viewBox="0 0 900 620" xmlns="http://www.w3.org/2000/svg" style="background:#080c10;font-family:Segoe UI,sans-serif">
  <!-- Title -->
  <text x="450" y="38" text-anchor="middle" fill="#00d4ff" font-size="18" font-weight="bold" letter-spacing="3">CHRONOS — SYSTEM ARCHITECTURE</text>

  <!-- ATTACKER -->
  <rect x="30" y="70" width="160" height="64" rx="6" fill="#0b0f14" stroke="#ff4444" stroke-width="1.5"/>
  <text x="110" y="95" text-anchor="middle" fill="#ff4444" font-size="11" font-weight="bold">ATTACKER</text>
  <text x="110" y="113" text-anchor="middle" fill="#6b7280" font-size="10">BlackArch Linux VM</text>
  <text x="110" y="127" text-anchor="middle" fill="#6b7280" font-size="9">192.168.1.x</text>

  <!-- Arrow attacker -> victim -->
  <line x1="190" y1="102" x2="270" y2="102" stroke="#ff4444" stroke-width="1.5" stroke-dasharray="5,3" marker-end="url(#arrowRed)"/>
  <text x="230" y="95" text-anchor="middle" fill="#ff4444" font-size="8">attack</text>

  <!-- VICTIM -->
  <rect x="270" y="70" width="180" height="64" rx="6" fill="#0b0f14" stroke="#ffa500" stroke-width="1.5"/>
  <text x="360" y="95" text-anchor="middle" fill="#ffa500" font-size="11" font-weight="bold">VICTIM HOST</text>
  <text x="360" y="113" text-anchor="middle" fill="#6b7280" font-size="10">Windows 10/11 VM</text>
  <text x="360" y="127" text-anchor="middle" fill="#6b7280" font-size="9">Sysmon + Wazuh Agent</text>

  <!-- Arrow victim -> wazuh -->
  <line x1="360" y1="134" x2="360" y2="200" stroke="#ffa500" stroke-width="1.5" marker-end="url(#arrowOrange)"/>
  <text x="375" y="172" fill="#ffa500" font-size="8">events</text>

  <!-- WAZUH SERVER -->
  <rect x="240" y="200" width="240" height="64" rx="6" fill="#0b0f14" stroke="#00d4ff" stroke-width="1.5"/>
  <text x="360" y="225" text-anchor="middle" fill="#00d4ff" font-size="11" font-weight="bold">WAZUH MANAGER</text>
  <text x="360" y="243" text-anchor="middle" fill="#6b7280" font-size="10">Ubuntu Server VM</text>
  <text x="360" y="257" text-anchor="middle" fill="#6b7280" font-size="9">Alert correlation + rule engine</text>

  <!-- Arrow wazuh -> ingestor -->
  <line x1="360" y1="264" x2="360" y2="330" stroke="#00d4ff" stroke-width="1.5" marker-end="url(#arrowBlue)"/>
  <text x="375" y="302" fill="#00d4ff" font-size="8">alerts</text>

  <!-- INGESTOR -->
  <rect x="240" y="330" width="240" height="64" rx="6" fill="#0b0f14" stroke="#00cc66" stroke-width="1.5"/>
  <text x="360" y="355" text-anchor="middle" fill="#00cc66" font-size="11" font-weight="bold">LOG INGESTOR</text>
  <text x="360" y="373" text-anchor="middle" fill="#6b7280" font-size="10">Python — ingest.py</text>
  <text x="360" y="387" text-anchor="middle" fill="#6b7280" font-size="9">Sysmon · Wazuh · Security logs</text>

  <!-- Arrow ingestor -> postgres -->
  <line x1="360" y1="394" x2="360" y2="460" stroke="#00cc66" stroke-width="1.5" marker-end="url(#arrowGreen)"/>
  <text x="375" y="432" fill="#00cc66" font-size="8">store</text>

  <!-- POSTGRES -->
  <rect x="240" y="460" width="240" height="64" rx="6" fill="#0b0f14" stroke="#7ab8cc" stroke-width="1.5"/>
  <text x="360" y="485" text-anchor="middle" fill="#7ab8cc" font-size="11" font-weight="bold">POSTGRESQL</text>
  <text x="360" y="503" text-anchor="middle" fill="#6b7280" font-size="10">chronos database</text>
  <text x="360" y="517" text-anchor="middle" fill="#6b7280" font-size="9">raw_alerts · timeline · iocs · incidents</text>

  <!-- Arrow postgres -> chronos (right) -->
  <line x1="480" y1="492" x2="560" y2="492" stroke="#7ab8cc" stroke-width="1.5" marker-end="url(#arrowCyan)"/>
  <text x="515" y="485" text-anchor="middle" fill="#7ab8cc" font-size="8">query</text>

  <!-- CHRONOS MODULES box -->
  <rect x="560" y="200" width="300" height="360" rx="6" fill="#0b0f14" stroke="#00d4ff" stroke-width="1.5"/>
  <text x="710" y="228" text-anchor="middle" fill="#00d4ff" font-size="12" font-weight="bold">CHRONOS PLATFORM</text>

  <!-- modules -->
  <rect x="580" y="245" width="260" height="36" rx="4" fill="#0d1523" stroke="#1a2332"/>
  <text x="710" y="260" text-anchor="middle" fill="#00cc66" font-size="10" font-weight="bold">Timeline Engine</text>
  <text x="710" y="274" text-anchor="middle" fill="#4a5568" font-size="9">Reconstructs attack progression</text>

  <rect x="580" y="292" width="260" height="36" rx="4" fill="#0d1523" stroke="#1a2332"/>
  <text x="710" y="307" text-anchor="middle" fill="#00cc66" font-size="10" font-weight="bold">IOC Extractor</text>
  <text x="710" y="321" text-anchor="middle" fill="#4a5568" font-size="9">IPs · Hashes · Processes · Domains</text>

  <rect x="580" y="339" width="260" height="36" rx="4" fill="#0d1523" stroke="#1a2332"/>
  <text x="710" y="354" text-anchor="middle" fill="#00cc66" font-size="10" font-weight="bold">ATT&amp;CK Mapper</text>
  <text x="710" y="368" text-anchor="middle" fill="#4a5568" font-size="9">Maps events to MITRE techniques</text>

  <rect x="580" y="386" width="260" height="36" rx="4" fill="#0d1523" stroke="#1a2332"/>
  <text x="710" y="401" text-anchor="middle" fill="#00cc66" font-size="10" font-weight="bold">Incident Correlator</text>
  <text x="710" y="415" text-anchor="middle" fill="#4a5568" font-size="9">Groups alerts into incidents</text>

  <rect x="580" y="433" width="260" height="36" rx="4" fill="#0d1523" stroke="#1a2332"/>
  <text x="710" y="448" text-anchor="middle" fill="#00cc66" font-size="10" font-weight="bold">Flask Dashboard</text>
  <text x="710" y="462" text-anchor="middle" fill="#4a5568" font-size="9">Investigation UI · REST API</text>

  <rect x="580" y="480" width="260" height="36" rx="4" fill="#0d1523" stroke="#1a2332"/>
  <text x="710" y="495" text-anchor="middle" fill="#00cc66" font-size="10" font-weight="bold">Report Generator</text>
  <text x="710" y="509" text-anchor="middle" fill="#4a5568" font-size="9">Executive summary · Findings · IOCs</text>

  <!-- Arrow wazuh -> chronos (horizontal) -->
  <line x1="480" y1="232" x2="560" y2="300" stroke="#00d4ff" stroke-width="1" stroke-dasharray="4,3" marker-end="url(#arrowBlue)"/>

  <!-- Sigma label -->
  <rect x="30" y="200" width="160" height="64" rx="6" fill="#0b0f14" stroke="#7ab8cc" stroke-width="1.5"/>
  <text x="110" y="225" text-anchor="middle" fill="#7ab8cc" font-size="11" font-weight="bold">SIGMA RULES</text>
  <text x="110" y="243" text-anchor="middle" fill="#6b7280" font-size="10">Detection definitions</text>
  <text x="110" y="257" text-anchor="middle" fill="#6b7280" font-size="9">Mapped to ATT&amp;CK techniques</text>
  <line x1="190" y1="232" x2="240" y2="232" stroke="#7ab8cc" stroke-width="1" stroke-dasharray="4,3" marker-end="url(#arrowCyan)"/>

  <!-- Sysmon label -->
  <rect x="30" y="330" width="160" height="64" rx="6" fill="#0b0f14" stroke="#ffd700" stroke-width="1.5"/>
  <text x="110" y="355" text-anchor="middle" fill="#ffd700" font-size="11" font-weight="bold">SYSMON</text>
  <text x="110" y="373" text-anchor="middle" fill="#6b7280" font-size="10">Windows event telemetry</text>
  <text x="110" y="387" text-anchor="middle" fill="#6b7280" font-size="9">Process · File · Network · Registry</text>
  <line x1="190" y1="362" x2="240" y2="362" stroke="#ffd700" stroke-width="1" stroke-dasharray="4,3" marker-end="url(#arrowYellow)"/>

  <!-- Arrow markers -->
  <defs>
    <marker id="arrowRed" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#ff4444"/>
    </marker>
    <marker id="arrowOrange" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#ffa500"/>
    </marker>
    <marker id="arrowBlue" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#00d4ff"/>
    </marker>
    <marker id="arrowGreen" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#00cc66"/>
    </marker>
    <marker id="arrowCyan" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#7ab8cc"/>
    </marker>
    <marker id="arrowYellow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#ffd700"/>
    </marker>
  </defs>
</svg>"""

# ── README.md ──────────────────────────────────────────────────────────────────
readme = """# Chronos
### Security Timeline Reconstruction & Incident Investigation Platform

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue?style=flat-square)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Chronos is a DFIR-focused platform that ingests raw security telemetry, reconstructs attack timelines, extracts indicators of compromise, maps evidence to MITRE ATT&CK techniques, and presents everything through a professional investigation dashboard.

Built without LLMs or AI APIs — all correlation, mapping, and reconstruction logic is deterministic, evidence-based Python.

---

## What It Does

Most detection engineering projects answer: **did the alert fire?**

Chronos answers: **what happened after the alert fired?**

Given raw Sysmon events, Wazuh alerts, and Windows Security logs, Chronos reconstructs the full attack story — from initial access to lateral movement — as an investigable incident with a timeline, IOCs, and ATT&CK coverage map.

---

## Architecture

![Architecture Diagram](docs/architecture.svg)

| Component | Technology |
|---|---|
| Attacker VM | BlackArch Linux |
| Victim VM | Windows 10/11 + Sysmon + Wazuh Agent |
| SIEM | Wazuh Manager (Ubuntu Server) |
| Database | PostgreSQL |
| Backend | Python 3, Flask, SQLAlchemy |
| Frontend | Bootstrap 5, Chart.js |
| Detection | Sigma rules mapped to ATT&CK |

---

## Core Modules

### 1. Log Ingestor
Collects Sysmon XML events, Wazuh JSON alerts, and Windows Security logs. Normalizes and stores them in PostgreSQL across `raw_alerts`, `process_events`, `file_events`, and `network_events` tables.

### 2. Timeline Engine
The heart of the project. Converts raw telemetry into a chronological attack progression, identifying pivot events — moments where attacker behavior changed or escalated. Each event carries a confidence score and ATT&CK technique mapping.

### 3. IOC Extractor
Automatically identifies indicators from telemetry: file hashes (MD5/SHA256), process names, IP addresses, domains, usernames, and hostnames. Tracks hit counts and first/last seen timestamps.

### 4. ATT&CK Mapper
Maps timeline events to MITRE ATT&CK techniques using Sigma rule metadata and behavioral heuristics. Produces a per-incident technique coverage table with pivot counts.

### 5. Incident Correlator
Groups related alerts, processes, and IOCs into a single incident object. Instead of showing 840 raw alerts, it presents 1 incident containing everything linked to that intrusion.

### 6. Flask Dashboard
A dark-themed investigation UI with four views:
- **Dashboard** — incident overview with live stats
- **Incident** — timeline, ATT&CK map, IOCs, affected hosts
- **Alerts** — full raw alert feed with severity and MITRE tags
- **IOCs** — deduplicated indicator list with hit counts

---

## Lab Environment

BlackArch Linux VM  (Attacker)
|
| simulated attack traffic
v
Windows 10/11 VM   (Victim)

Sysmon v15
Wazuh Agent 4.x
|
| event forwarding
v
Ubuntu Server VM   (Detection + Analysis)
Wazuh Manager
PostgreSQL
Chronos Platform (Flask :5000)

---

## Attack Scenarios Tested

| Technique | ATT&CK ID | Description |
|---|---|---|
| Scheduled Task Persistence | T1053.005 | schtasks.exe persistence via Office hook |
| Ingress Tool Transfer | T1105 | PowerShell writing PS1 to SystemTemp |
| Process Discovery | T1057 | net.exe accounts enumeration |
| Account Discovery | T1087 | Local account enumeration |
| Process Injection | T1055 | Suspicious process ancestry |
| Security Software Discovery | T1518 | SecEdit.exe config export |
| Command & Scripting | T1059 | Abnormal cmd.exe child processes |

---

## Dashboard Screenshots

| View | Description |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | Main incident overview with live stats |
| ![Incident](docs/screenshots/incident.png) | Timeline reconstruction with ATT&CK mapping |
| ![Alerts](docs/screenshots/alerts.png) | Raw alert feed with severity classification |
| ![IOCs](docs/screenshots/iocs.png) | Extracted indicators of compromise |

---

## Running Chronos

### Prerequisites
- Python 3.10+
- PostgreSQL 15
- Wazuh Manager (for live ingestion)

### Setup

```bash
git clone https://github.com/yourusername/chronos
cd chronos
pip install -r requirements.txt
```

Configure database connection:
```bash
export DB_HOST=localhost
export DB_NAME=chronos
export DB_USER=chronos
export DB_PASS=yourpassword
```

Run the dashboard:
```bash
cd dashboard
python app.py
```

Access at `http://localhost:5000`

---

## Project Philosophy

This project was built to demonstrate that a student can build serious DFIR tooling — not just detections.

No Claude API. No ChatGPT. No LLMs.

Every correlation, every timeline reconstruction, every IOC extraction is deterministic logic written in Python — the same way real SOC and DFIR tools work.

---

## Skills Demonstrated

- Digital Forensics & Incident Response (DFIR)
- Security telemetry ingestion and normalization
- Attack timeline reconstruction from raw events
- IOC extraction and deduplication
- MITRE ATT&CK technique mapping
- Sigma rule integration
- Full-stack security tooling (Python + Flask + PostgreSQL)
- Detection Engineering
- Threat Hunting methodology

---

## Author

**Fernando** — Cybersecurity student specializing in Detection Engineering, SOC Operations, and DFIR.

> *"This student can investigate intrusions, reconstruct attack timelines, correlate telemetry, understand ATT&CK, and build security tooling that resembles what real SOC and DFIR teams use."*
"""

with open(os.path.join(BASE, "architecture.svg"), "w") as f:
    f.write(svg)
print("architecture.svg written OK")

with open("/home/cpt-ferna02/chronos/README.md", "w") as f:
    f.write(readme)
print("README.md written OK")
