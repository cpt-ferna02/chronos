import os
BASE = "/home/cpt-ferna02/chronos/dashboard/templates"

incident_html = """{% extends "base.html" %}
{% block title %}{{ inc.name }}{% endblock %}
{% block content %}
<div class="d-flex align-items-center gap-3 mb-4">
  <a href="/" class="text-muted"><i class="bi bi-chevron-left"></i> Dashboard</a>
  <h4 class="mb-0">{{ inc.name }}</h4>
  {% if inc.severity == 'critical' %}<span class="badge badge-critical">CRITICAL</span>
  {% elif inc.severity == 'high' %}<span class="badge badge-high">HIGH</span>
  {% elif inc.severity == 'medium' %}<span class="badge badge-medium">MEDIUM</span>
  {% else %}<span class="badge badge-low">LOW</span>{% endif %}
  <span class="badge bg-secondary ms-1">{{ inc.status }}</span>
</div>
{% if inc.description %}<p class="text-muted mb-4">{{ inc.description }}</p>{% endif %}
<div class="row g-4">
  <div class="col-lg-7">
    <div class="card h-100">
      <div class="card-header"><i class="bi bi-clock-history me-2"></i>Attack Timeline</div>
      <div class="card-body" style="overflow-y:auto;max-height:520px;">
        {% for e in timeline %}
        <div class="timeline-item {% if e.is_pivot %}pivot{% endif %}">
          <div class="d-flex justify-content-between align-items-start">
            <div>
              <span class="fw-semibold" style="font-size:.9rem;">{{ e.event_type }}</span>
              {% if e.mitre_technique %}<span class="mitre-badge ms-2">{{ e.mitre_technique }}</span>{% endif %}
              {% if e.is_pivot %}<span class="badge bg-danger ms-1" style="font-size:.65rem;">PIVOT</span>{% endif %}
            </div>
            <span class="text-muted" style="font-size:.75rem;white-space:nowrap;">
              {{ e.event_time.strftime('%H:%M:%S') if e.event_time else '' }}
            </span>
          </div>
          <div class="text-muted mt-1" style="font-size:.82rem;">{{ e.description }}</div>
          {% if e.confidence %}<div style="font-size:.72rem;color:#6e7681;">confidence: {{ e.confidence }}</div>{% endif %}
        </div>
        {% else %}
        <p class="text-muted text-center py-4">No timeline events.</p>
        {% endfor %}
      </div>
    </div>
  </div>
  <div class="col-lg-5 d-flex flex-column gap-4">
    <div class="card">
      <div class="card-header"><i class="bi bi-diagram-3 me-2"></i>MITRE ATT&CK</div>
      <div class="card-body p-0">
        <table class="table mb-0" style="font-size:.85rem;">
          <thead><tr><th>Technique</th><th>Events</th><th>Pivots</th></tr></thead>
          <tbody>
          {% for m in mitre %}
          <tr>
            <td><span class="mitre-badge">{{ m.mitre_technique }}</span></td>
            <td>{{ m.count }}</td>
            <td>{% if m.pivot_count %}<span class="text-danger">{{ m.pivot_count }}</span>{% else %}--{% endif %}</td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="text-muted text-center py-3">No techniques mapped.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><i class="bi bi-shield-exclamation me-2"></i>Indicators of Compromise</div>
      <div class="card-body p-0" style="overflow-y:auto;max-height:240px;">
        <table class="table mb-0" style="font-size:.82rem;">
          <thead><tr><th>Type</th><th>Value</th><th>Hits</th></tr></thead>
          <tbody>
          {% for ioc in iocs %}
          <tr>
            <td><span class="badge bg-secondary">{{ ioc.ioc_type }}</span></td>
            <td class="ioc-value">{{ ioc.value }}</td>
            <td>{{ ioc.hit_count }}</td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="text-muted text-center py-3">No IOCs extracted.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><i class="bi bi-hdd-network me-2"></i>Affected Hosts</div>
      <div class="card-body p-0">
        <table class="table mb-0" style="font-size:.85rem;">
          <thead><tr><th>Agent</th><th>ID</th><th>Alerts</th></tr></thead>
          <tbody>
          {% for a in agents %}
          <tr>
            <td>{{ a.agent_name }}</td>
            <td class="text-muted">{{ a.agent_id }}</td>
            <td>{{ a.alert_count }}</td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="text-muted text-center py-3">No agents.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
{% endblock %}"""

alerts_html = """{% extends "base.html" %}
{% block title %}Alerts{% endblock %}
{% block content %}
<div class="card">
  <div class="card-header"><i class="bi bi-bell me-2"></i>Raw Alerts <span class="badge bg-secondary ms-2">{{ alerts|length }}</span></div>
  <div class="card-body p-0">
    <table class="table mb-0" style="font-size:.83rem;">
      <thead><tr><th>Time</th><th>Agent</th><th>Rule</th><th>Level</th><th>Description</th><th>MITRE</th></tr></thead>
      <tbody>
      {% for a in alerts %}
      <tr>
        <td class="text-muted" style="white-space:nowrap;">{{ a.event_time.strftime('%Y-%m-%d %H:%M:%S') if a.event_time else '' }}</td>
        <td>{{ a.agent_name }}</td>
        <td class="text-muted">{{ a.rule_id }}</td>
        <td>
          {% if a.rule_level >= 12 %}<span class="badge badge-critical">{{ a.rule_level }}</span>
          {% elif a.rule_level >= 9 %}<span class="badge badge-high">{{ a.rule_level }}</span>
          {% elif a.rule_level >= 6 %}<span class="badge badge-medium">{{ a.rule_level }}</span>
          {% else %}<span class="badge bg-secondary">{{ a.rule_level }}</span>{% endif %}
        </td>
        <td>{{ a.rule_desc }}</td>
        <td>{% if a.mitre_id %}<span class="mitre-badge">{{ a.mitre_id }}</span>{% else %}--{% endif %}</td>
      </tr>
      {% else %}
      <tr><td colspan="6" class="text-center text-muted py-4">No alerts.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}"""

iocs_html = """{% extends "base.html" %}
{% block title %}IOCs{% endblock %}
{% block content %}
<div class="card">
  <div class="card-header"><i class="bi bi-shield-exclamation me-2"></i>Indicators of Compromise <span class="badge bg-secondary ms-2">{{ iocs|length }}</span></div>
  <div class="card-body p-0">
    <table class="table mb-0" style="font-size:.83rem;">
      <thead><tr><th>Type</th><th>Value</th><th>Incident</th><th>Severity</th><th>Hits</th><th>First Seen</th><th>Last Seen</th><th>Notes</th></tr></thead>
      <tbody>
      {% for ioc in iocs %}
      <tr>
        <td><span class="badge bg-secondary">{{ ioc.ioc_type }}</span></td>
        <td class="ioc-value">{{ ioc.value }}</td>
        <td><a href="/incident/{{ ioc.incident_id }}">{{ ioc.incident_name }}</a></td>
        <td>
          {% if ioc.severity == 'critical' %}<span class="badge badge-critical">CRITICAL</span>
          {% elif ioc.severity == 'high' %}<span class="badge badge-high">HIGH</span>
          {% elif ioc.severity == 'medium' %}<span class="badge badge-medium">MEDIUM</span>
          {% else %}<span class="badge badge-low">LOW</span>{% endif %}
        </td>
        <td>{{ ioc.hit_count }}</td>
        <td class="text-muted" style="white-space:nowrap;">{{ ioc.first_seen.strftime('%Y-%m-%d %H:%M') if ioc.first_seen else '' }}</td>
        <td class="text-muted" style="white-space:nowrap;">{{ ioc.last_seen.strftime('%Y-%m-%d %H:%M') if ioc.last_seen else '' }}</td>
        <td class="text-muted">{{ ioc.notes or '' }}</td>
      </tr>
      {% else %}
      <tr><td colspan="8" class="text-center text-muted py-4">No IOCs yet.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}"""

open(os.path.join(BASE, "incident.html"), "w").write(incident_html)
open(os.path.join(BASE, "alerts.html"), "w").write(alerts_html)
open(os.path.join(BASE, "iocs.html"), "w").write(iocs_html)
print("incident.html, alerts.html, iocs.html written OK")
