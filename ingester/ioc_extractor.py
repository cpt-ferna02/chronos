#!/usr/bin/env python3
"""
Chronos Phase 5 — IOC Extractor + ATT&CK Mapper

Walks a committed incident's timeline and normalized tables,
extracts indicators of compromise, deduplicates them, and
writes to the iocs table. Also prints a hunt report.
"""

import argparse
import ipaddress
import logging
import re
import sys
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("chronos.ioc")

DB_CONFIG = {
    "dbname":   "chronos",
    "user":     "chronos",
    "password": "chronos_dev",
    "host":     "localhost",
    "port":     5432,
}

# ── Allowlists — skip these, they're known-good ───────────────────────────────

ALLOWED_PROCESSES = {
    "schtasks.exe", "net.exe", "net1.exe", "svchost.exe",
    "services.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "explorer.exe", "taskhostw.exe", "conhost.exe", "dllhost.exe",
    "RuntimeBroker.exe", "SearchHost.exe", "sihost.exe",
    "fontdrvhost.exe", "dwm.exe", "splunk-optimize.exe",
    "cmd.exe", "wsl.exe", "wscript.exe", "cscript.exe",
    "msiexec.exe", "regsvr32.exe", "rundll32.exe",
}

ALLOWED_IP_PREFIXES = (
    "127.", "0.0.0.", "255.255.", "::1",
    "192.168.",   # local lab network
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

ALLOWED_FILE_PATTERNS = [
    re.compile(r"__PSScriptPolicyTest_"),   # PowerShell policy tests
    re.compile(r"\.mui$"),
    re.compile(r"\.log$"),
    re.compile(r"AM_Delta_Patch_"),         # Windows Defender updates
    re.compile(r"SoftwareDistribution"),
    re.compile(r"GoogleUpdater"),           # Chrome updater
    re.compile(r"chrome_installer"),
]

# High-suspicion file locations
SUSPICIOUS_PATHS = [
    r"C:\Windows\Temp",
    r"C:\Windows\SystemTemp",
    r"C:\Users\.*\AppData\Local\Temp",
    r"C:\Users\.*\AppData\Roaming",
    r"C:\ProgramData",
]
SUSPICIOUS_PATH_RE = re.compile(
    "|".join(p.replace("\\", "\\\\").replace(".*", ".+") for p in SUSPICIOUS_PATHS),
    re.IGNORECASE,
)

# ── IOC collectors ────────────────────────────────────────────────────────────

def collect_process_iocs(cur, incident_id: int) -> list[dict]:
    """Extract hashes and suspicious process names from process_events."""
    cur.execute("""
        SELECT DISTINCT pe.process_name, pe.process_path, pe.sha256, pe.md5,
               pe.command_line, pe.user_name, pe.event_time,
               ra.mitre_id, ra.rule_desc
        FROM process_events pe
        JOIN incident_alerts ia ON ia.alert_id = pe.alert_id
        JOIN raw_alerts ra ON ra.id = pe.alert_id
        WHERE ia.incident_id = %s
          AND pe.sha256 IS NOT NULL
    """, (incident_id,))
    rows = cur.fetchall()

    iocs = []
    seen_hashes = set()

    for r in rows:
        sha = r["sha256"]
        md5 = r["md5"]
        name = (r["process_name"] or "").lower()

        # SHA256
        if sha and sha not in seen_hashes and len(sha) == 64:
            seen_hashes.add(sha)
            # Only flag if process is not in allowlist
            if name not in {p.lower() for p in ALLOWED_PROCESSES}:
                iocs.append({
                    "ioc_type":   "hash_sha256",
                    "value":      sha,
                    "first_seen": r["event_time"],
                    "last_seen":  r["event_time"],
                    "notes":      f"{r['process_name']} | {r['command_line'] or ''}".strip("| ")[:200],
                })

        # MD5
        if md5 and len(md5) == 32:
            if name not in {p.lower() for p in ALLOWED_PROCESSES}:
                iocs.append({
                    "ioc_type":   "hash_md5",
                    "value":      md5,
                    "first_seen": r["event_time"],
                    "last_seen":  r["event_time"],
                    "notes":      f"{r['process_name']} | MD5",
                })

        # Suspicious process names (not in allowlist, running as SYSTEM)
        if (name not in {p.lower() for p in ALLOWED_PROCESSES}
                and r["user_name"] and "SYSTEM" in r["user_name"].upper()):
            iocs.append({
                "ioc_type":   "process_name",
                "value":      r["process_name"],
                "first_seen": r["event_time"],
                "last_seen":  r["event_time"],
                "notes":      f"Running as SYSTEM | {r['command_line'] or ''}".strip()[:200],
            })

    return iocs


def collect_network_iocs(cur, incident_id: int) -> list[dict]:
    """Extract external IPs from network_events."""
    cur.execute("""
        SELECT DISTINCT ne.dst_ip, ne.dst_port, ne.process_name,
               ne.protocol, ne.event_time
        FROM network_events ne
        JOIN incident_alerts ia ON ia.alert_id = ne.alert_id
        WHERE ia.incident_id = %s
          AND ne.dst_ip IS NOT NULL
    """, (incident_id,))
    rows = cur.fetchall()

    iocs = []
    for r in rows:
        ip = str(r["dst_ip"])
        if any(ip.startswith(p) for p in ALLOWED_IP_PREFIXES):
            continue
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                continue
        except ValueError:
            continue

        iocs.append({
            "ioc_type":   "ip",
            "value":      ip,
            "first_seen": r["event_time"],
            "last_seen":  r["event_time"],
            "notes":      f"dst_port={r['dst_port']} proto={r['protocol']} process={r['process_name']}",
        })

    return iocs


def collect_file_iocs(cur, incident_id: int) -> list[dict]:
    """Extract suspicious file drops from file_events."""
    cur.execute("""
        SELECT DISTINCT fe.target_filename, fe.process_name,
               fe.event_time, ra.mitre_id, ra.rule_desc
        FROM file_events fe
        JOIN incident_alerts ia ON ia.alert_id = fe.alert_id
        JOIN raw_alerts ra ON ra.id = fe.alert_id
        WHERE ia.incident_id = %s
          AND fe.target_filename IS NOT NULL
    """, (incident_id,))
    rows = cur.fetchall()

    iocs = []
    for r in rows:
        path = r["target_filename"]

        # Skip known-good patterns
        if any(p.search(path) for p in ALLOWED_FILE_PATTERNS):
            continue

        # Only flag if in a suspicious location
        if not SUSPICIOUS_PATH_RE.search(path):
            continue

        iocs.append({
            "ioc_type":   "filename",
            "value":      path,
            "first_seen": r["event_time"],
            "last_seen":  r["event_time"],
            "notes":      f"Written by {r['process_name']} | {r['rule_desc'] or ''}".strip("| ")[:200],
        })

    return iocs


def collect_mitre_iocs(cur, incident_id: int) -> list[dict]:
    """
    Pull MITRE techniques from timeline and annotate high-signal ones
    as process_name IOCs where the process isn't in the allowlist.
    """
    cur.execute("""
        SELECT DISTINCT te.mitre_technique, te.description,
               te.event_time, te.is_pivot
        FROM timeline_events te
        WHERE te.incident_id = %s
          AND te.mitre_technique IS NOT NULL
          AND te.is_pivot = TRUE
        ORDER BY te.event_time
    """, (incident_id,))
    return cur.fetchall()

# ── Deduplication + DB write ──────────────────────────────────────────────────

def deduplicate(iocs: list[dict]) -> list[dict]:
    seen = {}
    for ioc in iocs:
        key = (ioc["ioc_type"], ioc["value"].lower())
        if key not in seen:
            seen[key] = ioc
        else:
            # Update last_seen and increment hit_count
            existing = seen[key]
            if ioc["last_seen"] > existing["last_seen"]:
                existing["last_seen"] = ioc["last_seen"]
            existing["hit_count"] = existing.get("hit_count", 1) + 1
    return list(seen.values())


def write_iocs(cur, incident_id: int, iocs: list[dict]):
    for ioc in iocs:
        cur.execute("""
            INSERT INTO iocs
                (incident_id, ioc_type, value, first_seen, last_seen,
                 hit_count, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT DO NOTHING
        """, (
            incident_id,
            ioc["ioc_type"],
            ioc["value"],
            ioc.get("first_seen"),
            ioc.get("last_seen"),
            ioc.get("hit_count", 1),
            ioc.get("notes"),
        ))

# ── Report printer ────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
RESET = "\033[0m"

TYPE_COLOR = {
    "hash_sha256":  RED,
    "hash_md5":     RED,
    "ip":           YEL,
    "filename":     YEL,
    "process_name": GRN,
    "registry_key": GRN,
    "domain":       YEL,
}

def print_report(incident_id: int, iocs: list[dict], pivots: list[dict]):
    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}  CHRONOS IOC REPORT — Incident #{incident_id}{RESET}")
    print(f"  Extracted: {len(iocs)} unique indicators")
    print(f"  ATT&CK pivot points: {len(pivots)}")
    print(f"{BOLD}{'═'*70}{RESET}\n")

    # Group by type
    by_type: dict[str, list] = {}
    for ioc in iocs:
        by_type.setdefault(ioc["ioc_type"], []).append(ioc)

    type_order = ["hash_sha256", "hash_md5", "ip", "domain",
                  "filename", "process_name", "registry_key"]

    for t in type_order:
        if t not in by_type:
            continue
        color = TYPE_COLOR.get(t, "")
        print(f"  {BOLD}{t.upper().replace('_',' ')}{RESET}")
        for ioc in by_type[t]:
            hits = ioc.get("hit_count", 1)
            val  = ioc["value"]
            note = (ioc.get("notes") or "")[:80]
            print(f"    {color}{val}{RESET}")
            if note:
                print(f"      → {note}")
            if hits > 1:
                print(f"      ↺ seen {hits}x")
        print()

    if pivots:
        print(f"  {BOLD}ATT&CK PIVOT POINTS{RESET}")
        for p in pivots:
            ts = p["event_time"].strftime("%H:%M:%S")
            print(f"    {ts}  {YEL}{p['mitre_technique']}{RESET}")
            desc = (p["description"] or "")[:80]
            if desc:
                print(f"           {desc}")
        print()

    print(f"{BOLD}{'═'*70}{RESET}")
    print(f"  IOCs written to DB — incident #{incident_id}")
    print(f"  Hunt with: psql -U chronos -d chronos -h localhost")
    print(f"  Query:     SELECT * FROM iocs WHERE incident_id={incident_id};")
    print(f"{BOLD}{'═'*70}{RESET}\n")

# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Chronos IOC extractor")
    p.add_argument("--incident", required=True, type=int,
                   help="Incident ID to extract IOCs from")
    p.add_argument("--dry-run", action="store_true",
                   help="Print report without writing to DB")
    return p.parse_args()


def main():
    args = parse_args()
    incident_id = args.incident

    conn = psycopg2.connect(**DB_CONFIG,
                            cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn.cursor() as cur:
            # Verify incident exists
            cur.execute("SELECT id, name FROM incidents WHERE id=%s",
                        (incident_id,))
            inc = cur.fetchone()
            if not inc:
                log.error(f"Incident #{incident_id} not found.")
                sys.exit(1)
            log.info(f"Extracting IOCs from incident #{incident_id}: {inc['name']}")

            # Collect
            process_iocs = collect_process_iocs(cur, incident_id)
            network_iocs = collect_network_iocs(cur, incident_id)
            file_iocs    = collect_file_iocs(cur, incident_id)
            all_iocs     = deduplicate(process_iocs + network_iocs + file_iocs)
            pivots       = collect_mitre_iocs(cur, incident_id)

            log.info(f"Found {len(process_iocs)} process, "
                     f"{len(network_iocs)} network, "
                     f"{len(file_iocs)} file IOCs → "
                     f"{len(all_iocs)} unique after dedup")

            print_report(incident_id, all_iocs, pivots)

            if not args.dry_run:
                write_iocs(cur, incident_id, all_iocs)
                conn.commit()
                log.info("IOCs committed to DB.")
            else:
                log.info("Dry run — nothing written.")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
