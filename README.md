# Chronos
### Security Timeline Reconstruction & Incident Investigation Platform

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue?style=flat-square)
![Sysmon](https://img.shields.io/badge/Sysmon-v15-orange?style=flat-square)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Chronos is a DFIR-focused incident investigation platform that ingests raw security telemetry from Sysmon and Wazuh, reconstructs attack timelines, extracts indicators of compromise, maps evidence to MITRE ATT&CK techniques, and presents everything through a professional dark-themed investigation dashboard.

Built without LLMs or AI APIs. Every correlation, timeline reconstruction, and IOC extraction is deterministic, evidence-based Python — the same way real SOC and DFIR tools work.

---

## Demo

[![Chronos Demo](docs/screenshots/chronos-dashboard-incident-overview.png)](docs/chronos-demo-video.mp4)

> Click the image above to watch the full demo video, or [download it directly](docs/chronos-demo-video.mp4).

---

## Why This Project Exists

Most detection engineering projects answer one question: **did the alert fire?**

That is Tier 1 work.

Chronos answers a harder question: **what happened after the alert fired?**

When a real intrusion occurs, a Tier 2 or Tier 3 SOC analyst does not stare at 840 individual alerts. They reconstruct a story — what process ran, what it spawned, what files it touched, what credentials it accessed, what moved laterally. They build a timeline. They extract IOCs. They map the attacker's behavior to ATT&CK. They write an incident report.

That investigation workflow is what Chronos automates and demonstrates.

This project was built to fill a specific gap in a security portfolio: proving that the builder understands not just how to detect attacks, but how to investigate them from start to finish — the way real DFIR analysts work.

---

## What It Does

Given raw Sysmon events, Wazuh alerts, and Windows Security logs, Chronos:

1. Ingests and normalizes telemetry into a structured PostgreSQL database
2. Reconstructs a chronological attack timeline with confidence scores
3. Identifies pivot events — moments where attacker behavior escalated
4. Automatically extracts IOCs: file hashes, process names, IP addresses, usernames, hostnames
5. Maps every event to MITRE ATT&CK techniques using Sigma rule metadata
6. Correlates hundreds of alerts into a single investigable incident object
7. Presents everything through a dark-themed investigation dashboard

---

## Architecture

![Chronos System Architecture](docs/screenshots/chronos-system-architecture.png)

```
BlackArch Linux VM  (Attacker — 192.168.1.x)
        |
        |  simulated attack traffic
        v
Windows 10/11 VM   (Victim)
  ├── Sysmon v15 (SwiftOnSecurity config)
  └── Wazuh Agent 4.7.5
        |
        |  event forwarding over TCP 1514
        v
Arch Linux VM / Ubuntu Server  (Detection + Analysis)
  ├── Wazuh Manager 4.7.5 (Docker)
  ├── Wazuh Indexer / OpenSearch (Docker)
  ├── PostgreSQL 15
  └── Chronos Platform (Flask :5000)
```

| Component | Technology |
|---|---|
| Attacker VM | BlackArch Linux |
| Victim VM | Windows 10/11 + Sysmon v15 + Wazuh Agent |
| SIEM | Wazuh Manager 4.7.5 (Docker) |
| Database | PostgreSQL 15 |
| Backend | Python 3, Flask |
| Frontend | Bootstrap 5, Chart.js |
| Detection Framework | MITRE ATT&CK, Sigma |

---

## Core Modules

### 1. Log Ingestor (`ingest.py`)
Pulls Wazuh alerts from the OpenSearch indexer API. Normalizes Sysmon XML event data, Windows Security logs, and Wazuh alert JSON into structured PostgreSQL tables: `raw_alerts`, `process_events`, `file_events`, and `network_events`.

### 2. Timeline Engine
The heart of the project. Converts raw telemetry into a chronological attack progression. Assigns each event a confidence score and identifies pivot events — moments where the attacker's behavior changed or escalated. Output: a human-readable attack story sorted by timestamp.

### 3. IOC Extractor
Automatically identifies indicators of compromise from telemetry: MD5 and SHA256 file hashes, process names and command lines, IP addresses, domains, usernames, and hostnames. Tracks hit counts, first seen, and last seen timestamps. Deduplicates across events.

### 4. ATT&CK Mapper
Maps timeline events to MITRE ATT&CK techniques using Sigma rule metadata and behavioral heuristics. Produces a per-incident technique coverage table showing event counts and pivot counts per technique.

### 5. Incident Correlator
Groups related alerts, processes, file events, and IOCs into a single incident object. Instead of presenting 840 raw alerts, Chronos presents 1 incident containing everything linked to that intrusion — the same model used by real SIEM platforms.

### 6. Flask Dashboard
A dark-themed investigation UI with four views:
- **Dashboard** — live incident overview with stats: incidents, pivot events, raw alerts, IOCs, process events, file events
- **Incident** — full attack timeline with PIVOT tags, ATT&CK technique map, IOC panel, affected hosts
- **Alerts** — complete raw alert feed with severity levels and MITRE technique tags
- **IOCs** — deduplicated indicator list with type badges, hit counts, and first/last seen timestamps

---

## Attack Scenarios Tested

| Technique | ATT&CK ID | Description |
|---|---|---|
| Scheduled Task Persistence | T1053.005 | schtasks.exe persistence via Office hook |
| Ingress Tool Transfer | T1105 | PowerShell writing PS1 to SystemTemp |
| Process Discovery | T1057 | net.exe accounts enumeration |
| Account Discovery | T1087 | Local account enumeration |
| Process Injection | T1055 | Suspicious process ancestry chains |
| Security Software Discovery | T1518 | SecEdit.exe security config export |
| Command & Scripting Interpreter | T1059 | Abnormal cmd.exe child processes |
| PowerShell | T1059.001 | Encoded and plain PowerShell execution |

---

## Dashboard Screenshots

### Incident Overview — Live Stats
![Dashboard](docs/screenshots/chronos-dashboard-incident-overview.png)
840 raw alerts correlated into 1 incident. 27 pivot events identified. 15 IOCs extracted. 94 process events and 95 file events stored.

---

### Attack Timeline Reconstruction
![Timeline](docs/screenshots/chronos-incident-timeline-attack-reconstruction.png)
Each event carries a timestamp, event type, ATT&CK technique tag, confidence score, and PIVOT indicator. The timeline tells the full attack story chronologically — from scheduled task persistence through process discovery, ingress tool transfer, and account enumeration.

---

### Raw Alerts Feed
![Alerts](docs/screenshots/chronos-raw-alerts-mitre-classification.png)
200 most recent alerts with agent name, rule ID, severity level badge, description, and MITRE technique tag.

---

### IOC Extraction
![IOCs](docs/screenshots/chronos-ioc-extraction-indicators.png)
15 deduplicated indicators: MD5 hashes, SHA256 hashes, and process names — each linked to the incident that produced them, with hit counts and timestamps.

---

## Engineering Challenges & How They Were Solved

This section documents the real problems encountered during development and how each was resolved. These were not trivial configuration issues — they required diagnosis, creative workarounds, and methodical debugging.

---

### Challenge 1: CSS Embedded Inside Python — `SyntaxError: invalid decimal literal`

**What happened:**
During an early attempt to write `app.py` using a shell heredoc, CSS properties (`font-size: 14px;`) were accidentally embedded directly inside the Python file. Python tried to parse the CSS as source code and threw `SyntaxError: invalid decimal literal` at line 191. Nothing about the error message obviously pointed to CSS as the cause — it took deliberate inspection of the file to identify it.

**How it was solved:**
Deleted the corrupted file entirely with `rm app.py`. Instead of using heredocs or nano for large files, switched to a dedicated Python writer script (`write_app.py`) that stored the entire Flask application inside a raw triple-quoted string (`r'''...'''`). This approach is completely immune to shell interpretation of special characters and CSS-like content. Validated the output afterward using `python -c "import ast; ast.parse(open('app.py').read()); print('OK')"` before running anything.

**Lesson:** Large multi-line files should never be written via shell heredocs when the content contains special characters. Use Python writer scripts or an IDE instead.

---

### Challenge 2: zsh Heredoc Failures — `event not found` and Infinite `quote>` Prompts

**What happened:**
Every attempt to write files using zsh heredocs (`<< 'PYEOF'`) failed in one of two ways: the shell threw `zsh: event not found: /usr/bin/env` when it encountered certain characters inside the heredoc, or it entered an infinite `quote>` waiting state and never terminated. In both cases, the file either was never written or contained corrupted output.

**How it was solved:**
Abandoned heredocs entirely for any file larger than a few lines. All complex files were written either by opening nano and pasting content directly into the editor, or by using Python writer scripts with raw triple-quoted strings that bypass zsh interpretation completely. This became the standard pattern for the rest of the project.

**Lesson:** zsh heredocs are unreliable for large or complex file content. For anything beyond a few lines, use a proper editor or a Python writer script.

---

### Challenge 3: nano Silently Truncating Large Pastes

**What happened:**
When pasting large scripts into nano, the terminal silently cut off the content mid-file. The file appeared to save successfully, but running it would either fail immediately or produce no output. For example, `write_templates.py` ended up containing only `import os` after what appeared to be a successful paste and save — no error, no warning.

**How it was solved:**
Developed a consistent verification habit: always check both ends of a file after writing using `head -5` and `tail -20`. When truncation was detected, the fix was to split large scripts into smaller focused files (e.g., `t1.py`, `t2.py`, `t3.py`) that each handled a subset of the work and were small enough to paste reliably. This divide-and-conquer approach eliminated truncation for the rest of the project.

**Lesson:** Never assume a file was written correctly. Always verify with `head` and `tail`. Split large files rather than fighting paste limits.

---

### Challenge 4: Bootstrap Overriding Custom Dark Theme CSS

**What happened:**
After applying a full dark theme through custom CSS in `base.html`, Bootstrap's default stylesheet kept forcing white backgrounds onto table rows regardless of what was set in the custom styles. The custom CSS was correct and present, but Bootstrap's specificity was winning. Table cells rendered with bright white backgrounds, making the dashboard look inconsistent and broken.

**How it was solved:**
Identified the specific Bootstrap selectors winning the specificity battle: `.table>:not(caption)>*>*` was applying defaults to `tbody`, `td`, `tfoot`, `th`, `thead`, and `tr`. Overrode them explicitly with `!important` and `background-color: transparent` targeting those exact selectors. Also performed a hard refresh with `Ctrl+Shift+R` to bypass CDN caching, which had been serving stale Bootstrap styles even after fixes were applied.

**Lesson:** When a CSS framework overrides your styles, inspect the exact selector chain it uses and target it explicitly. CDN caching can hide your fixes — always hard refresh when debugging CSS.

---

### Challenge 5: Stale Content in nano — Editing the Wrong Script

**What happened:**
When attempting to create `t5.py`, nano opened with `t4.py`'s content still loaded from a previous session. Saving without noticing meant the wrong script ran, and the intended changes were never applied. This caused confusion when the expected output didn't appear and the previous script's behavior repeated instead.

**How it was solved:**
Established a clear file-clearing step before every new script: `cat /dev/null > filename.py` to empty the file completely before opening nano. This guaranteed a blank editor every time and eliminated the risk of stale content carrying over between sessions.

**Lesson:** Always clear a file before editing it in a terminal editor. Never assume an editor opens blank.

---

### Challenge 6: Wazuh Manager Not Found — Service on a Different Machine

**What happened:**
After completing Sysmon installation on the Windows 10 victim VM and updating the Wazuh agent config, the next step was to verify that Sysmon events were reaching Wazuh. Running `sudo tail -f /var/ossec/logs/alerts/alerts.json` on WSL2 Ubuntu returned `No such file or directory`. Running `sudo systemctl status wazuh-manager` on the Arch Linux VM returned `Unit wazuh-manager.service could not be found`.

The Wazuh manager wasn't where expected because it was running inside Docker containers, not as a native systemd service. Additionally, the Arch Linux VM had been powered off, making the agent's configured server IP (192.168.1.80) unreachable.

**How it was solved:**
Identified that the Wazuh stack was running in Docker by running `docker ps`, which revealed `wazuh/wazuh-manager:4.7.5`, `wazuh/wazuh-indexer:4.7.5`, and `wazuh/wazuh-dashboard:4.7.5` containers. Powered on the Arch Linux VM and confirmed its IP matched the agent config. Accessed the alerts log inside the container using `docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json`. Sysmon events appeared immediately.

**Lesson:** Know where every component of your stack is actually running. When a service isn't where expected, check containers before assuming a misconfiguration.

---

## Running Chronos

### Prerequisites
- Python 3.10+
- PostgreSQL 15
- Wazuh Manager (for live ingestion)

### Setup

```bash
git clone https://github.com/cpt-ferna02/chronos
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

Initialize the database schema:
```bash
python db/schema.py
```

Run the ingestor to pull Wazuh alerts:
```bash
python ingest.py
```

Run the dashboard:
```bash
cd dashboard
python app.py
```

Access at `http://localhost:5000`

---

## Skills Demonstrated

- **Digital Forensics & Incident Response (DFIR)** — attack timeline reconstruction, IOC extraction, evidence correlation
- **Security Telemetry Engineering** — Sysmon configuration, Wazuh agent deployment, log normalization
- **Detection Engineering** — Sigma rule integration, MITRE ATT&CK mapping, custom Wazuh rules
- **Database Engineering** — PostgreSQL schema design, multi-table joins, event storage and querying
- **Python Development** — log parsing, API integration, Flask routing, data normalization
- **Full-Stack Security Tooling** — end-to-end platform from raw telemetry to investigation UI
- **Systematic Debugging** — diagnosing and resolving real engineering problems across the stack
- **Threat Hunting Methodology** — pivot identification, behavioral pattern recognition, IOC deduplication

---

## Project Philosophy

This project was built to prove one thing:

**Fernando can investigate intrusions, reconstruct attack timelines, correlate raw telemetry, understand ATT&CK at an engineering level, and build security tooling that resembles what real SOC and DFIR teams use.**

No Claude API. No ChatGPT. No LLMs.

Every detection, every correlation, every timeline event is the result of deterministic logic written in Python — built from scratch, debugged from scratch, and working in a live lab environment.

---

## Author

**Fernando Cortez Jr.** — Cybersecurity student specializing in Detection Engineering, SOC Operations, and DFIR.

[GitHub](https://github.com/cpt-ferna02) · [LinkedIn](https://linkedin.com/in/fernando-cortezjr-a3529a313)
