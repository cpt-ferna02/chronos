#!/usr/bin/env python3
"""
Chronos Phase 3 — Wazuh Alert Ingester
Tails /var/ossec/logs/alerts/alerts.json and populates PostgreSQL.
"""

import json
import time
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import Json, execute_values

# ── Config ────────────────────────────────────────────────────────────────────

DB_CONFIG = {
    "dbname":   "chronos",
    "user":     "chronos",
    "password": "chronos_dev",
    "host":     "localhost",
    "port":     5432,
}

# Path INSIDE the Wazuh Docker container mapped to host — adjust if different
ALERTS_FILE = "/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"

POLL_INTERVAL   = 5     # seconds between reads
CURSOR_FILE     = Path(__file__).parent / ".last_position"  # tracks file offset

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("chronos.ingest")

# ── Graceful shutdown ─────────────────────────────────────────────────────────

_running = True

def _handle_signal(sig, frame):
    global _running
    log.info("Shutdown signal received — draining and exiting...")
    _running = False

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_cursor() -> int:
    """Return the last byte offset we read up to."""
    try:
        return int(CURSOR_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_cursor(offset: int):
    CURSOR_FILE.write_text(str(offset))


def parse_timestamp(ts: str) -> datetime:
    """Wazuh timestamps are ISO-8601; normalise to UTC."""
    if not ts:
        return datetime.now(timezone.utc)
    ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return datetime.now(timezone.utc)


def extract_mitre(alert: dict) -> list[str]:
    """Pull MITRE technique IDs out of the nested Wazuh structure."""
    techniques = []
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    # Wazuh stores them as {"id": ["T1059.001"], "technique": [...]}
    ids = mitre.get("id", [])
    if isinstance(ids, list):
        techniques.extend(ids)
    elif isinstance(ids, str):
        techniques.append(ids)
    return techniques


def sysmon_event_id(alert: dict) -> int | None:
    """Extract Sysmon EventID from the alert JSON."""
    try:
        data = alert.get("data", {})
        win  = data.get("win", {})
        sys  = win.get("system", {})
        eid  = sys.get("eventID")
        return int(eid) if eid else None
    except (TypeError, ValueError):
        return None


def get_win_event_data(alert: dict) -> dict:
    """Shortcut to the eventdata block."""
    return alert.get("data", {}).get("win", {}).get("eventdata", {})

# ── DB inserters ──────────────────────────────────────────────────────────────

def insert_raw_alert(cur, alert: dict) -> int | None:
    """
    Insert into raw_alerts. Returns new row id, or None if duplicate.
    """
    wazuh_id   = alert.get("id")
    agent      = alert.get("agent", {})
    rule       = alert.get("rule", {})
    event_time = parse_timestamp(alert.get("timestamp"))
    mitre_ids  = extract_mitre(alert)

    try:
        cur.execute("""
            INSERT INTO raw_alerts
                (wazuh_alert_id, agent_id, agent_name, rule_id, rule_level,
                 rule_desc, mitre_id, full_log, event_time)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (wazuh_alert_id) DO NOTHING
            RETURNING id
        """, (
            wazuh_id,
            agent.get("id", "unknown"),
            agent.get("name"),
            rule.get("id"),
            rule.get("level"),
            rule.get("description"),
            mitre_ids or None,
            Json(alert),
            event_time,
        ))
        row = cur.fetchone()
        return row[0] if row else None   # None = duplicate, skip
    except Exception as e:
        log.warning(f"raw_alerts insert failed: {e}")
        return None


def insert_process_event(cur, alert_id: int, alert: dict, ed: dict):
    """Sysmon Event ID 1 — Process Create."""
    cur.execute("""
        INSERT INTO process_events
            (alert_id, agent_name, event_time, pid, ppid,
             process_name, process_path, command_line,
             parent_name, parent_path, user_name, session_id,
             sha256, md5, signed, signature)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        alert_id,
        alert.get("agent", {}).get("name"),
        parse_timestamp(alert.get("timestamp")),
        _int(ed.get("processId")),
        _int(ed.get("parentProcessId")),
        ed.get("image", "").split("\\")[-1],   # basename
        ed.get("image"),
        ed.get("commandLine"),
        ed.get("parentImage", "").split("\\")[-1],
        ed.get("parentImage"),
        ed.get("user"),
        _int(ed.get("logonId")),
        ed.get("hashes", "").upper().split("SHA256=")[-1].split(",")[0] or None,
        ed.get("hashes", "").upper().split("MD5=")[-1].split(",")[0] or None,
        _bool(ed.get("signed")),
        ed.get("signature"),
    ))


def insert_network_event(cur, alert_id: int, alert: dict, ed: dict):
    """Sysmon Event ID 3 — Network Connect."""
    cur.execute("""
        INSERT INTO network_events
            (alert_id, agent_name, event_time, pid, process_name,
             src_ip, src_port, dst_ip, dst_port, protocol, initiated)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        alert_id,
        alert.get("agent", {}).get("name"),
        parse_timestamp(alert.get("timestamp")),
        _int(ed.get("processId")),
        ed.get("image", "").split("\\")[-1],
        ed.get("sourceIp")  or None,
        _int(ed.get("sourcePort")),
        ed.get("destinationIp") or None,
        _int(ed.get("destinationPort")),
        ed.get("protocol"),
        _bool(ed.get("initiated")),
    ))


def insert_file_event(cur, alert_id: int, alert: dict, ed: dict):
    """Sysmon Event ID 11 — File Create."""
    cur.execute("""
        INSERT INTO file_events
            (alert_id, agent_name, event_time, pid, process_name,
             target_filename, creation_utc)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (
        alert_id,
        alert.get("agent", {}).get("name"),
        parse_timestamp(alert.get("timestamp")),
        _int(ed.get("processId")),
        ed.get("image", "").split("\\")[-1],
        ed.get("targetFilename"),
        parse_timestamp(ed.get("creationUtcTime")),
    ))


def insert_registry_event(cur, alert_id: int, alert: dict, ed: dict, eid: int):
    """Sysmon Event ID 12/13 — Registry."""
    etype_map = {12: "CreateKey", 13: "SetValue", 14: "DeleteKey"}
    cur.execute("""
        INSERT INTO registry_events
            (alert_id, agent_name, event_time, event_type, pid,
             process_name, target_object, details)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        alert_id,
        alert.get("agent", {}).get("name"),
        parse_timestamp(alert.get("timestamp")),
        etype_map.get(eid, f"EventID_{eid}"),
        _int(ed.get("processId")),
        ed.get("image", "").split("\\")[-1],
        ed.get("targetObject"),
        ed.get("details"),
    ))

# ── Type coercers ─────────────────────────────────────────────────────────────

def _int(v) -> int | None:
    try:    return int(v)
    except: return None

def _bool(v) -> bool | None:
    if v is None:           return None
    if isinstance(v, bool): return v
    return str(v).lower() in ("true", "1", "yes")

# ── Routing ───────────────────────────────────────────────────────────────────

SYSMON_HANDLERS = {
    1:  insert_process_event,
    3:  insert_network_event,
    11: insert_file_event,
    12: insert_registry_event,
    13: insert_registry_event,
    14: insert_registry_event,
}

def process_alert(cur, alert: dict) -> bool:
    """Parse one alert and write to DB. Returns True if inserted."""
    alert_id = insert_raw_alert(cur, alert)
    if alert_id is None:
        return False    # duplicate

    eid = sysmon_event_id(alert)
    if eid in SYSMON_HANDLERS:
        ed = get_win_event_data(alert)
        try:
            if eid in (12, 13, 14):
                SYSMON_HANDLERS[eid](cur, alert_id, alert, ed, eid)
            else:
                SYSMON_HANDLERS[eid](cur, alert_id, alert, ed)
        except Exception as e:
            log.warning(f"Normalized insert failed (EventID {eid}): {e}")

    return True

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    log.info("Chronos ingester starting...")

    if not Path(ALERTS_FILE).exists():
        log.error(f"Alerts file not found: {ALERTS_FILE}")
        log.error("Check your Wazuh Docker volume path — see README.")
        sys.exit(1)

    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    log.info("PostgreSQL connected.")

    offset = load_cursor()
    log.info(f"Resuming from byte offset {offset}")

    while _running:
        try:
            with open(ALERTS_FILE, "r", errors="replace") as f:
                f.seek(offset)
                new_lines = f.readlines()
                new_offset = f.tell()

            inserted = dupes = errors = 0

            if new_lines:
                with conn.cursor() as cur:
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            alert = json.loads(line)
                        except json.JSONDecodeError:
                            errors += 1
                            continue

                        try:
                            if process_alert(cur, alert):
                                inserted += 1
                            else:
                                dupes += 1
                        except Exception as e:
                            log.warning(f"Alert processing error: {e}")
                            errors += 1

                conn.commit()
                save_cursor(new_offset)
                offset = new_offset

                if inserted:
                    log.info(f"Batch: +{inserted} inserted, {dupes} dupes, {errors} errors")

        except Exception as e:
            log.error(f"Ingester loop error: {e}")
            try:
                conn.rollback()
            except:
                pass

        time.sleep(POLL_INTERVAL)

    conn.close()
    log.info("Ingester shut down cleanly.")


if __name__ == "__main__":
    main()
