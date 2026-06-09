from flask import Flask, render_template, jsonify, abort
import psycopg2
import psycopg2.extras
import os

app = Flask(__name__)

DB = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "chronos"),
    "user": os.getenv("DB_USER", "chronos"),
    "password": os.getenv("DB_PASS", "chronos"),
}

def get_conn():
    return psycopg2.connect(**DB)

def query(sql, params=None):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()

def query_one(sql, params=None):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchone()

@app.route("/")
def index():
    incidents = query("""
        SELECT id, name, severity, status, created_at,
               (SELECT COUNT(*) FROM timeline_events WHERE incident_id = incidents.id) AS event_count
        FROM incidents
        ORDER BY created_at DESC
    """)
    stats = query_one("""
        SELECT
            (SELECT count(*) FROM raw_alerts)     AS total_alerts,
            (SELECT count(*) FROM process_events) AS process_events,
            (SELECT count(*) FROM file_events)    AS file_events,
            (SELECT count(*) FROM incidents)      AS total_incidents,
            (SELECT count(*) FROM iocs)           AS total_iocs,
            (SELECT count(*) FROM timeline_events WHERE is_pivot = TRUE) AS total_pivots
    """)
    return render_template("index.html", incidents=incidents, stats=stats)

@app.route("/incident/<int:incident_id>")
def incident(incident_id):
    inc = query_one("SELECT id, name, description, severity, status, created_at FROM incidents WHERE id = %s", (incident_id,))
    if not inc:
        abort(404)
    timeline = query("SELECT event_time, event_type, mitre_technique, description, is_pivot, confidence, source_table FROM timeline_events WHERE incident_id = %s ORDER BY event_time ASC", (incident_id,))
    iocs = query("SELECT ioc_type, value, hit_count, first_seen, last_seen, notes FROM iocs WHERE incident_id = %s ORDER BY ioc_type, hit_count DESC", (incident_id,))
    mitre = query("SELECT DISTINCT mitre_technique, COUNT(*) AS count, SUM(CASE WHEN is_pivot THEN 1 ELSE 0 END) AS pivot_count FROM timeline_events WHERE incident_id = %s AND mitre_technique IS NOT NULL GROUP BY mitre_technique ORDER BY count DESC", (incident_id,))
    agents = query("SELECT DISTINCT ra.agent_name, ra.agent_id, COUNT(*) AS alert_count FROM raw_alerts ra JOIN incident_alerts ia ON ia.alert_id = ra.id WHERE ia.incident_id = %s GROUP BY ra.agent_name, ra.agent_id", (incident_id,))
    return render_template("incident.html", inc=inc, timeline=timeline, iocs=iocs, mitre=mitre, agents=agents)

@app.route("/alerts")
def alerts():
    rows = query("SELECT id, agent_name, rule_id, rule_level, rule_desc, mitre_id, event_time FROM raw_alerts ORDER BY event_time DESC LIMIT 200")
    return render_template("alerts.html", alerts=rows)

@app.route("/iocs")
def iocs():
    rows = query("SELECT ioc.*, i.name AS incident_name, i.severity FROM iocs ioc JOIN incidents i ON i.id = ioc.incident_id ORDER BY ioc.hit_count DESC, ioc.last_seen DESC")
    return render_template("iocs.html", iocs=rows)

@app.route("/api/timeline/<int:incident_id>")
def api_timeline(incident_id):
    rows = query("SELECT event_time, event_type, mitre_technique, description, is_pivot, confidence FROM timeline_events WHERE incident_id = %s ORDER BY event_time ASC", (incident_id,))
    return jsonify([dict(r) for r in rows])

@app.route("/architecture")
def architecture():
    with open("/home/cpt-ferna02/chronos/docs/architecture.svg", "r") as f:
        svg = f.read()
    from flask import Response
    return Response(svg, mimetype="image/svg+xml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)