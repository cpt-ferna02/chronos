#!/usr/bin/env python3
"""
Chronos Phase 4 — Timeline Reconstruction Engine

Given a time window (and optionally an agent), pulls all related alerts,
enriches them from normalized tables, reconstructs process chains,
scores each event, and writes ordered rows into timeline_events.
"""

import argparse
import logging
import sys
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("chronos.timeline")

DB_CONFIG = {
    "dbname":   "chronos",
    "user":     "chronos",
    "password": "chronos_dev",
    "host":     "localhost",
    "port":     5432,
}

# ── ATT&CK context ────────────────────────────────────────────────────────────

MITRE_LABELS = {
    "T1053.005": ("Scheduled Task/Job",        "Persistence"),
    "T1057":     ("Process Discovery",          "Discovery"),
    "T1059":     ("Command & Scripting",        "Execution"),
    "T1059.001": ("PowerShell",                 "Execution"),
    "T1105":     ("Ingress Tool Transfer",      "C2"),
    "T1136":     ("Create Account",             "Persistence"),
    "T1547":     ("Boot/Logon Autostart",       "Persistence"),
    "T1548":     ("Abuse Elevation Control",    "Priv Esc"),
    "T1055":     ("Process Injection",          "Priv Esc"),
    "T1003":     ("OS Credential Dumping",      "Cred Access"),
    "T1021":     ("Remote Services",            "Lateral"),
    "T1560":     ("Archive Collected Data",     "Exfiltration"),
    "T1083":     ("File & Dir Discovery",       "Discovery"),
    "T1082":     ("System Info Discovery",      "Discovery"),
    "T1087":     ("Account Discovery",          "Discovery"),
}

# Rule IDs that are noise — include in raw_alerts but skip timeline
NOISE_RULES = {
    60642,   # Software protection scheduled
    60106,   # Windows logon success (too frequent)
    60137,   # Windows logoff
    750,     # Registry checksum changed (Wazuh internal)
    594,     # Registry key checksum changed
}

# Rule IDs that are HIGH signal — always flag as pivot
PIVOT_RULES = {
    92205,   # PowerShell dropped executable
    92213,   # Executable in malware folder
    92217,   # Executable in Windows root
    92052,   # cmd.exe abnormal parent
    100003,  # T1053.005 scheduled task
    100002,  # T1057 process discovery
}

# Confidence scoring weights
SCORE_MITRE       = 40   # has a MITRE technique mapped
SCORE_PIVOT_RULE  = 30   # matches a known high-signal rule
SCORE_PROCESS_CTX = 15   # has enriched process data
SCORE_NETWORK_CTX = 15   # has network context
SCORE_FILE_CTX    = 10   # has file context
SCORE_BASE        = 10   # everything gets this

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class TimelineEntry:
    alert_id:        int
    event_time:      datetime
    event_type:      str
    source_table:    str | None
    source_id:       int | None
    mitre_technique: str | None
    description:     str
    is_pivot:        bool
    confidence:      int
    rule_id:         int | None
    rule_desc:       str | None
    agent_name:      str | None
    raw:             dict = field(default_factory=dict)   # enrichment data

# ── DB helpers ────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)


def fetch_alerts(cur, start: datetime, end: datetime, agent: str | None) -> list[dict]:
    """Pull raw alerts in time window, excluding pure noise."""
    query = """
        SELECT id, wazuh_alert_id, agent_name, rule_id, rule_level,
               rule_desc, mitre_id, full_log, event_time
        FROM raw_alerts
        WHERE event_time BETWEEN %s AND %s
          AND rule_id::integer NOT IN %s
    """
    params = [start, end, tuple(NOISE_RULES)]

    if agent:
        query += " AND agent_name = %s"
        params.append(agent)

    query += " ORDER BY event_time ASC"
    cur.execute(query, params)
    return cur.fetchall()


def fetch_process_context(cur, alert_id: int) -> dict | None:
    cur.execute("""
        SELECT * FROM process_events WHERE alert_id = %s LIMIT 1
    """, (alert_id,))
    return cur.fetchone()


def fetch_network_context(cur, alert_id: int) -> dict | None:
    cur.execute("""
        SELECT * FROM network_events WHERE alert_id = %s LIMIT 1
    """, (alert_id,))
    return cur.fetchone()


def fetch_file_context(cur, alert_id: int) -> dict | None:
    cur.execute("""
        SELECT * FROM file_events WHERE alert_id = %s LIMIT 1
    """, (alert_id,))
    return cur.fetchone()


def fetch_process_chain(cur, pid: int, agent: str, event_time: datetime) -> list[dict]:
    """
    Walk up the process tree from pid, looking back 60s.
    Returns ancestor chain ordered root -> immediate parent.
    """
    chain = []
    current_pid = pid
    window_start = event_time - timedelta(seconds=60)

    for _ in range(8):   # max depth
        cur.execute("""
            SELECT process_name, process_path, command_line,
                   pid, ppid, user_name, sha256
            FROM process_events
            WHERE pid = %s
              AND agent_name = %s
              AND event_time BETWEEN %s AND %s
            ORDER BY event_time DESC
            LIMIT 1
        """, (current_pid, agent, window_start, event_time))
        row = cur.fetchone()
        if not row or row["ppid"] is None or row["ppid"] == current_pid:
            break
        chain.insert(0, dict(row))
        current_pid = row["ppid"]

    return chain

# ── Description builders ──────────────────────────────────────────────────────

def describe_process(alert: dict, proc: dict, chain: list[dict]) -> str:
    parts = []
    parts.append(f"Process: {proc['process_name'] or '?'}")
    if proc["command_line"]:
        cmd = proc["command_line"][:120]
        parts.append(f"CMD: {cmd}")
    if proc["user_name"]:
        parts.append(f"User: {proc['user_name']}")
    if chain:
        ancestry = " → ".join(p["process_name"] for p in chain if p.get("process_name"))
        if ancestry:
            parts.append(f"Chain: {ancestry} → {proc['process_name']}")
    if proc["sha256"]:
        parts.append(f"SHA256: {proc['sha256'][:16]}...")
    return " | ".join(parts)


def describe_network(alert: dict, net: dict) -> str:
    return (
        f"Network: {net['process_name'] or '?'} → "
        f"{net['dst_ip']}:{net['dst_port']} ({net['protocol'] or 'tcp'})"
    )


def describe_file(alert: dict, f: dict) -> str:
    return (
        f"File: {f['process_name'] or '?'} wrote "
        f"{f['target_filename'] or '?'}"
    )


def describe_generic(alert: dict) -> str:
    desc = alert["rule_desc"] or "Unknown event"
    mitre = alert["mitre_id"]
    if mitre:
        techniques = ", ".join(mitre) if isinstance(mitre, list) else mitre
        desc = f"[{techniques}] {desc}"
    return desc

# ── Scoring ───────────────────────────────────────────────────────────────────

def score_event(alert: dict, proc: dict | None, net: dict | None,
                f: dict | None) -> tuple[int, bool]:
    """Returns (confidence 1-100, is_pivot)."""
    score = SCORE_BASE
    pivot = False

    rule_id = int(alert["rule_id"]) if alert["rule_id"] else 0

    if alert["mitre_id"]:
        score += SCORE_MITRE

    if rule_id in PIVOT_RULES:
        score += SCORE_PIVOT_RULE
        pivot = True

    if proc:
        score += SCORE_PROCESS_CTX
    if net:
        score += SCORE_NETWORK_CTX
    if f:
        score += SCORE_FILE_CTX

    # High Wazuh rule level also bumps score
    level = int(alert["rule_level"]) if alert["rule_level"] else 0
    if level >= 12:
        score += 10
        pivot = True
    elif level >= 8:
        score += 5

    return min(score, 100), pivot

# ── Core engine ───────────────────────────────────────────────────────────────

def build_timeline(cur, alerts: list[dict]) -> list[TimelineEntry]:
    entries = []

    for alert in alerts:
        alert_id   = alert["id"]
        agent_name = alert["agent_name"]
        event_time = alert["event_time"]
        rule_id    = int(alert["rule_id"]) if alert["rule_id"] else None

        # Fetch enrichment
        proc = fetch_process_context(cur, alert_id)
        net  = fetch_network_context(cur, alert_id)
        f    = fetch_file_context(cur, alert_id)

        # Determine event type and source
        if proc:
            event_type   = "process"
            source_table = "process_events"
            source_id    = proc["id"]

            chain = fetch_process_chain(
                cur, proc["ppid"] or 0, agent_name, event_time
            ) if proc.get("ppid") else []

            description = describe_process(alert, proc, chain)

        elif net:
            event_type   = "network"
            source_table = "network_events"
            source_id    = net["id"]
            description  = describe_network(alert, net)

        elif f:
            event_type   = "file"
            source_table = "file_events"
            source_id    = f["id"]
            description  = describe_file(alert, f)

        else:
            event_type   = "alert"
            source_table = None
            source_id    = None
            description  = describe_generic(alert)

        # MITRE — take first technique if multiple
        mitre_ids = alert["mitre_id"]
        mitre_technique = None
        if mitre_ids:
            first = mitre_ids[0] if isinstance(mitre_ids, list) else mitre_ids
            label = MITRE_LABELS.get(first)
            mitre_technique = f"{first} ({label[0]})" if label else first

        confidence, is_pivot = score_event(alert, proc, net, f)

        entries.append(TimelineEntry(
            alert_id        = alert_id,
            event_time      = event_time,
            event_type      = event_type,
            source_table    = source_table,
            source_id       = source_id,
            mitre_technique = mitre_technique,
            description     = description,
            is_pivot        = is_pivot,
            confidence      = confidence,
            rule_id         = rule_id,
            rule_desc       = alert["rule_desc"],
            agent_name      = agent_name,
            raw             = dict(alert),
        ))

    return entries

# ── Incident writer ───────────────────────────────────────────────────────────

def create_incident(cur, name: str, description: str, severity: str) -> int:
    cur.execute("""
        INSERT INTO incidents (name, description, severity, status)
        VALUES (%s, %s, %s, 'investigating')
        RETURNING id
    """, (name, description, severity))
    return cur.fetchone()["id"]


def write_timeline(cur, incident_id: int, entries: list[TimelineEntry],
                   alerts: list[dict]):
    # Link alerts to incident
    if alerts:
        psycopg2.extras.execute_values(cur, """
            INSERT INTO incident_alerts (incident_id, alert_id)
            VALUES %s ON CONFLICT DO NOTHING
        """, [(incident_id, a["id"]) for a in alerts])

    # Write timeline rows
    if entries:
        psycopg2.extras.execute_values(cur, """
            INSERT INTO timeline_events
                (incident_id, event_time, event_type, source_table, source_id,
                 mitre_technique, description, is_pivot, confidence)
            VALUES %s
        """, [(
            incident_id,
            e.event_time,
            e.event_type,
            e.source_table,
            e.source_id,
            e.mitre_technique,
            e.description,
            e.is_pivot,
            e.confidence,
        ) for e in entries])

# ── Printer ───────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "\033[91m",   # red
    "high":     "\033[93m",   # yellow
    "medium":   "\033[94m",   # blue
    "low":      "\033[92m",   # green
}
RESET  = "\033[0m"
BOLD   = "\033[1m"
PIVOT  = "\033[91m★\033[0m"  # red star

def print_timeline(incident_id: int, incident_name: str,
                   entries: list[TimelineEntry]):
    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}  CHRONOS INCIDENT TIMELINE{RESET}")
    print(f"  Incident #{incident_id}: {incident_name}")
    print(f"  Events: {len(entries)}")
    pivots = sum(1 for e in entries if e.is_pivot)
    print(f"  Pivot points: {pivots}")
    if entries:
        print(f"  Window: {entries[0].event_time.strftime('%Y-%m-%d %H:%M:%S')} → "
              f"{entries[-1].event_time.strftime('%H:%M:%S')} UTC")
    print(f"{BOLD}{'═'*70}{RESET}\n")

    for e in entries:
        ts      = e.event_time.strftime("%H:%M:%S")
        pivot   = f" {PIVOT}" if e.is_pivot else "  "
        conf    = f"[{e.confidence:3d}%]"
        mitre   = f"{BOLD}{e.mitre_technique}{RESET}" if e.mitre_technique else "          "
        etype   = f"{e.event_type:<8}"

        print(f"  {ts}{pivot} {conf} {etype} {mitre}")
        print(f"           {e.description[:100]}")
        print()

    print(f"{BOLD}{'═'*70}{RESET}")
    print(f"  Written to DB as incident #{incident_id}")
    print(f"{BOLD}{'═'*70}{RESET}\n")

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Chronos timeline reconstruction engine"
    )
    p.add_argument("--start",    required=True,
                   help="Start time ISO format e.g. 2026-06-09T05:00:00")
    p.add_argument("--end",      required=True,
                   help="End time ISO format e.g. 2026-06-09T08:00:00")
    p.add_argument("--agent",    default=None,
                   help="Filter by agent name e.g. Windows11-Host")
    p.add_argument("--name",     default="Auto-generated incident",
                   help="Incident name")
    p.add_argument("--severity", default="medium",
                   choices=["low","medium","high","critical"])
    p.add_argument("--dry-run",  action="store_true",
                   help="Print timeline without writing to DB")
    return p.parse_args()


def main():
    args = parse_args()

    # Parse timestamps — assume UTC if no tz given
    def parse_ts(s):
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    start = parse_ts(args.start)
    end   = parse_ts(args.end)

    log.info(f"Building timeline: {start} → {end}"
             + (f" agent={args.agent}" if args.agent else ""))

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            alerts = fetch_alerts(cur, start, end, args.agent)
            log.info(f"Fetched {len(alerts)} alerts (noise filtered)")

            if not alerts:
                log.warning("No alerts in window — try a wider time range.")
                sys.exit(0)

            entries = build_timeline(cur, alerts)
            log.info(f"Built {len(entries)} timeline entries "
                     f"({sum(1 for e in entries if e.is_pivot)} pivots)")

            if args.dry_run:
                print_timeline(0, args.name, entries)
                log.info("Dry run — nothing written to DB.")
                return

            incident_id = create_incident(
                cur, args.name,
                f"Auto-reconstructed: {start} → {end}",
                args.severity
            )
            write_timeline(cur, incident_id, entries, alerts)
            conn.commit()

            print_timeline(incident_id, args.name, entries)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
