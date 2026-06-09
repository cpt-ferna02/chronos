#!/usr/bin/env python3
"""
Chronos Phase 6 — Incident Correlator

Compares a target incident against all others in the DB.
Scores overlap across IOCs, MITRE techniques, process chains,
and agent/host context. Writes correlation scores to a report
and flags linked incidents above a confidence threshold.
"""

import argparse
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime

import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("chronos.correlator")

DB_CONFIG = {
    "dbname":   "chronos",
    "user":     "chronos",
    "password": "chronos_dev",
    "host":     "localhost",
    "port":     5432,
}

# ── Scoring weights ───────────────────────────────────────────────────────────
# Each match type contributes points toward a 0-100 correlation score.

W_SHA256        = 40   # same hash = almost certainly same actor/tool
W_MD5           = 25   # same MD5
W_IP            = 30   # same external IP
W_DOMAIN        = 25   # same domain
W_FILENAME      = 15   # same suspicious filename
W_PROCESS       = 10   # same suspicious process name
W_MITRE_EXACT   = 12   # same technique ID
W_MITRE_TACTIC  = 5    # same tactic family (e.g. both Discovery)
W_SAME_AGENT    = 8    # both hit the same host
W_TIME_WINDOW   = 5    # incidents overlap in time (within 24h)

CORRELATION_THRESHOLD = 20   # minimum score to report a link

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class CorrelationResult:
    incident_id:   int
    incident_name: str
    severity:      str
    status:        str
    created_at:    datetime
    score:         int
    reasons:       list[str] = field(default_factory=list)
    shared_iocs:   list[dict] = field(default_factory=list)
    shared_mitre:  list[str]  = field(default_factory=list)
    shared_agents: list[str]  = field(default_factory=list)

# ── Fetchers ──────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(**DB_CONFIG,
                            cursor_factory=psycopg2.extras.RealDictCursor)


def fetch_incident(cur, incident_id: int) -> dict | None:
    cur.execute("""
        SELECT id, name, description, severity, status, created_at
        FROM incidents WHERE id = %s
    """, (incident_id,))
    return cur.fetchone()


def fetch_all_other_incidents(cur, incident_id: int) -> list[dict]:
    cur.execute("""
        SELECT id, name, severity, status, created_at
        FROM incidents
        WHERE id != %s
        ORDER BY created_at DESC
    """, (incident_id,))
    return cur.fetchall()


def fetch_iocs(cur, incident_id: int) -> list[dict]:
    cur.execute("""
        SELECT ioc_type, value, hit_count, notes
        FROM iocs
        WHERE incident_id = %s
    """, (incident_id,))
    return cur.fetchall()


def fetch_mitre_techniques(cur, incident_id: int) -> set[str]:
    cur.execute("""
        SELECT DISTINCT mitre_technique
        FROM timeline_events
        WHERE incident_id = %s
          AND mitre_technique IS NOT NULL
    """, (incident_id,))
    return {r["mitre_technique"] for r in cur.fetchall()}


def fetch_agents(cur, incident_id: int) -> set[str]:
    cur.execute("""
        SELECT DISTINCT ra.agent_name
        FROM raw_alerts ra
        JOIN incident_alerts ia ON ia.alert_id = ra.id
        WHERE ia.incident_id = %s
          AND ra.agent_name IS NOT NULL
    """, (incident_id,))
    return {r["agent_name"] for r in cur.fetchall()}


def fetch_pivot_commands(cur, incident_id: int) -> set[str]:
    """Get command lines from pivot process events for deep comparison."""
    cur.execute("""
        SELECT DISTINCT pe.command_line
        FROM process_events pe
        JOIN incident_alerts ia ON ia.alert_id = pe.alert_id
        JOIN timeline_events te ON te.incident_id = ia.incident_id
        WHERE ia.incident_id = %s
          AND te.is_pivot = TRUE
          AND pe.command_line IS NOT NULL
    """, (incident_id,))
    return {r["command_line"] for r in cur.fetchall()}

# ── Correlation engine ────────────────────────────────────────────────────────

def extract_tactic_family(technique: str) -> str:
    """
    T1057 (Process Discovery) → 'Process Discovery'
    T1059.001 (PowerShell)    → 'PowerShell'
    Falls back to technique prefix T1057 → 'T1057'
    """
    if "(" in technique:
        return technique.split("(")[1].rstrip(")")
    return technique.split(".")[0]


def correlate(
    target_id:      int,
    target_iocs:    list[dict],
    target_mitre:   set[str],
    target_agents:  set[str],
    target_created: datetime,
    other:          dict,
    other_iocs:     list[dict],
    other_mitre:    set[str],
    other_agents:   set[str],
) -> CorrelationResult | None:

    result = CorrelationResult(
        incident_id   = other["id"],
        incident_name = other["name"],
        severity      = other["severity"] or "unknown",
        status        = other["status"] or "unknown",
        created_at    = other["created_at"],
        score         = 0,
    )

    # ── IOC matching ──────────────────────────────────────────────────────────

    # Build lookup sets keyed by (type, normalized_value)
    target_ioc_set = {(i["ioc_type"], i["value"].lower()) for i in target_iocs}
    other_ioc_set  = {(i["ioc_type"], i["value"].lower()) for i in other_iocs}

    shared = target_ioc_set & other_ioc_set

    ioc_weights = {
        "hash_sha256":  W_SHA256,
        "hash_md5":     W_MD5,
        "ip":           W_IP,
        "domain":       W_DOMAIN,
        "filename":     W_FILENAME,
        "process_name": W_PROCESS,
        "registry_key": W_PROCESS,
    }

    for (ioc_type, value) in shared:
        weight = ioc_weights.get(ioc_type, 5)
        result.score += weight
        result.shared_iocs.append({"type": ioc_type, "value": value})
        result.reasons.append(
            f"Shared {ioc_type}: {value[:60]}{'...' if len(value)>60 else ''} (+{weight})"
        )

    # ── MITRE technique matching ──────────────────────────────────────────────

    shared_techniques = target_mitre & other_mitre
    for tech in shared_techniques:
        result.score += W_MITRE_EXACT
        result.shared_mitre.append(tech)
        result.reasons.append(f"Shared ATT&CK technique: {tech} (+{W_MITRE_EXACT})")

    # Tactic family overlap (even if different sub-techniques)
    target_families = {extract_tactic_family(t) for t in target_mitre}
    other_families  = {extract_tactic_family(t) for t in other_mitre}
    shared_families = target_families & other_families - \
                      {extract_tactic_family(t) for t in shared_techniques}

    for fam in shared_families:
        result.score += W_MITRE_TACTIC
        result.reasons.append(f"Shared ATT&CK tactic family: {fam} (+{W_MITRE_TACTIC})")

    # ── Host/agent overlap ────────────────────────────────────────────────────

    shared_agents = target_agents & other_agents
    for agent in shared_agents:
        result.score += W_SAME_AGENT
        result.shared_agents.append(agent)
        result.reasons.append(f"Same host targeted: {agent} (+{W_SAME_AGENT})")

    # ── Time proximity ────────────────────────────────────────────────────────

    delta = abs((target_created - other["created_at"]).total_seconds())
    if delta < 86400:   # within 24 hours
        result.score += W_TIME_WINDOW
        result.reasons.append(f"Incidents within 24h of each other (+{W_TIME_WINDOW})")

    # Cap at 100
    result.score = min(result.score, 100)

    if result.score >= CORRELATION_THRESHOLD:
        return result
    return None

# ── Printer ───────────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
DIM   = "\033[2m"
RESET = "\033[0m"

SEV_COLOR = {
    "critical": RED,
    "high":     RED,
    "medium":   YEL,
    "low":      GRN,
    "unknown":  DIM,
}

def score_bar(score: int) -> str:
    filled = score // 5
    bar = "█" * filled + "░" * (20 - filled)
    color = RED if score >= 70 else YEL if score >= 40 else GRN
    return f"{color}{bar}{RESET} {score:3d}/100"


def print_correlation_report(target: dict, results: list[CorrelationResult],
                              checked: int):
    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}  CHRONOS CORRELATION REPORT{RESET}")
    print(f"  Target: Incident #{target['id']} — {target['name']}")
    print(f"  Severity: {target['severity'] or 'unknown'}")
    print(f"  Incidents checked: {checked}")
    print(f"  Linked incidents found: {len(results)}")
    print(f"{BOLD}{'═'*70}{RESET}\n")

    if not results:
        print(f"  {GRN}No correlations above threshold ({CORRELATION_THRESHOLD}).{RESET}")
        print(f"  This incident appears isolated from prior activity.\n")
        print(f"{BOLD}{'═'*70}{RESET}\n")
        return

    # Sort by score descending
    results.sort(key=lambda r: r.score, reverse=True)

    for r in results:
        sev_color = SEV_COLOR.get(r.severity, DIM)
        print(f"  {BOLD}Incident #{r.incident_id}{RESET} — {r.incident_name}")
        print(f"  Severity: {sev_color}{r.severity}{RESET}  "
              f"Status: {r.status}  "
              f"Created: {r.created_at.strftime('%Y-%m-%d %H:%M')}")
        print(f"  Correlation score: {score_bar(r.score)}")
        print()

        if r.shared_iocs:
            print(f"    {BOLD}Shared IOCs ({len(r.shared_iocs)}){RESET}")
            for ioc in r.shared_iocs:
                print(f"      {RED}▸{RESET} [{ioc['type']}] {ioc['value'][:64]}")
            print()

        if r.shared_mitre:
            print(f"    {BOLD}Shared ATT&CK Techniques ({len(r.shared_mitre)}){RESET}")
            for tech in sorted(r.shared_mitre):
                print(f"      {YEL}▸{RESET} {tech}")
            print()

        if r.shared_agents:
            print(f"    {BOLD}Shared Hosts ({len(r.shared_agents)}){RESET}")
            for agent in r.shared_agents:
                print(f"      {YEL}▸{RESET} {agent}")
            print()

        print(f"    {DIM}Scoring breakdown:{RESET}")
        for reason in r.reasons:
            print(f"      {DIM}· {reason}{RESET}")
        print(f"\n  {'─'*66}\n")

    print(f"{BOLD}{'═'*70}{RESET}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Chronos incident correlator")
    p.add_argument("--incident", required=True, type=int,
                   help="Target incident ID to correlate against all others")
    p.add_argument("--threshold", type=int, default=CORRELATION_THRESHOLD,
                   help=f"Minimum correlation score to report (default {CORRELATION_THRESHOLD})")
    return p.parse_args()


def main():
    args = parse_args()
    incident_id = args.incident

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            target = fetch_incident(cur, incident_id)
            if not target:
                log.error(f"Incident #{incident_id} not found.")
                sys.exit(1)

            log.info(f"Correlating incident #{incident_id}: {target['name']}")

            # Load target's profile
            target_iocs   = fetch_iocs(cur, incident_id)
            target_mitre  = fetch_mitre_techniques(cur, incident_id)
            target_agents = fetch_agents(cur, incident_id)

            log.info(f"Target profile: {len(target_iocs)} IOCs, "
                     f"{len(target_mitre)} MITRE techniques, "
                     f"{len(target_agents)} agents")

            others = fetch_all_other_incidents(cur, incident_id)
            log.info(f"Checking against {len(others)} other incident(s)...")

            results = []
            for other in others:
                other_iocs   = fetch_iocs(cur, other["id"])
                other_mitre  = fetch_mitre_techniques(cur, other["id"])
                other_agents = fetch_agents(cur, other["id"])

                result = correlate(
                    target_id      = incident_id,
                    target_iocs    = target_iocs,
                    target_mitre   = target_mitre,
                    target_agents  = target_agents,
                    target_created = target["created_at"],
                    other          = other,
                    other_iocs     = other_iocs,
                    other_mitre    = other_mitre,
                    other_agents   = other_agents,
                )
                if result:
                    results.append(result)
                    log.info(f"  → Linked: Incident #{other['id']} "
                             f"'{other['name']}' (score={result.score})")

            print_correlation_report(target, results, len(others))

    finally:
        conn.close()


if __name__ == "__main__":
    main()
