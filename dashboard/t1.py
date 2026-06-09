import os
BASE = "/home/cpt-ferna02/chronos/dashboard/templates"

base_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Chronos - {% block title %}{% endblock %}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <style>
    body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',sans-serif}
    .navbar{background:#161b22!important;border-bottom:1px solid #30363d}
    .navbar-brand{color:#58a6ff!important;font-weight:700;letter-spacing:1px}
    .nav-link{color:#8b949e!important}
    .nav-link:hover,.nav-link.active{color:#58a6ff!important}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px}
    .card-header{background:#1c2128;border-bottom:1px solid #30363d;font-weight:600}
    .table{color:#c9d1d9}
    .table thead th{background:#1c2128;border-color:#30363d;color:#8b949e;font-size:.75rem;text-transform:uppercase}
    .table tbody td{border-color:#21262d;vertical-align:middle}
    .table tbody tr:hover{background:#1c2128}
    .badge-critical{background:#da3633}
    .badge-high{background:#d29922}
    .badge-medium{background:#388bfd}
    .badge-low{background:#3fb950}
    .stat-card{border-left:3px solid #58a6ff}
    .stat-number{font-size:2rem;font-weight:700;color:#58a6ff}
    .stat-label{font-size:.8rem;color:#8b949e;text-transform:uppercase}
    .timeline-item{position:relative;padding-left:2rem;border-left:2px solid #30363d;margin-bottom:1rem}
    .timeline-item::before{content:'';position:absolute;left:-6px;top:4px;width:10px;height:10px;border-radius:50%;background:#30363d}
    .timeline-item.pivot::before{background:#f78166;box-shadow:0 0 6px #f78166}
    .timeline-item.pivot{border-left-color:#f78166}
    .mitre-badge{font-size:.7rem;font-family:monospace;background:#0d419d;color:#79c0ff;border-radius:4px;padding:2px 6px}
    .ioc-value{font-family:monospace;font-size:.85rem}
    a{color:#58a6ff;text-decoration:none}
    a:hover{color:#79c0ff}
  </style>
  {% block head %}{% endblock %}
</head>
<body>
<nav class="navbar navbar-expand-lg">
  <div class="container-fluid px-4">
    <a class="navbar-brand" href="/"><i class="bi bi-clock-history me-2"></i>CHRONOS</a>
    <div class="navbar-nav ms-4">
      <a class="nav-link" href="/"><i class="bi bi-speedometer2 me-1"></i>Dashboard</a>
      <a class="nav-link" href="/alerts"><i class="bi bi-bell me-1"></i>Alerts</a>
      <a class="nav-link" href="/iocs"><i class="bi bi-shield-exclamation me-1"></i>IOCs</a>
    </div>
    <span class="ms-auto text-muted" style="font-size:.75rem;">
      <i class="bi bi-circle-fill text-success me-1" style="font-size:.5rem;"></i>Live
    </span>
  </div>
</nav>
<div class="container-fluid px-4 py-4">
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
{% block scripts %}{% endblock %}
</body>
</html>"""

index_html = """{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div class="row g-3 mb-4">
  {% set s = stats %}
  <div class="col-6 col-md-2">
    <div class="card stat-card p-3">
      <div class="stat-number">{{ s.total_incidents }}</div>
      <div class="stat-label">Incidents</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="card stat-card p-3" style="border-color:#f78166">
      <div class="stat-number" style="color:#f78166">{{ s.total_pivots }}</div>
      <div class="stat-label">Pivot Events</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="card stat-card p-3" style="border-color:#d29922">
      <div class="stat-number" style="color:#d29922">{{ s.total_alerts }}</div>
      <div class="stat-label">Raw Alerts</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="card stat-card p-3" style="border-color:#3fb950">
      <div class="stat-number" style="color:#3fb950">{{ s.total_iocs }}</div>
      <div class="stat-label">IOCs</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="card stat-card p-3" style="border-color:#8b949e">
      <div class="stat-number" style="color:#8b949e">{{ s.process_events }}</div>
      <div class="stat-label">Process Events</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="card stat-card p-3" style="border-color:#8b949e">
      <div class="stat-number" style="color:#8b949e">{{ s.file_events }}</div>
      <div class="stat-label">File Events</div>
    </div>
  </div>
</div>
<div class="card">
  <div class="card-header d-flex align-items-center gap-2">
    <i class="bi bi-fire text-danger"></i> Active Incidents
  </div>
  <div class="card-body p-0">
    <table class="table mb-0">
      <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Status</th><th>Events</th><th>Created</th><th></th></tr></thead>
      <tbody>
      {% for i in incidents %}
      <tr>
        <td class="text-muted">#{{ i.id }}</td>
        <td><a href="/incident/{{ i.id }}">{{ i.name }}</a></td>
        <td>
          {% if i.severity == 'critical' %}<span class="badge badge-critical">CRITICAL</span>
          {% elif i.severity == 'high' %}<span class="badge badge-high">HIGH</span>
          {% elif i.severity == 'medium' %}<span class="badge badge-medium">MEDIUM</span>
          {% else %}<span class="badge badge-low">LOW</span>{% endif %}
        </td>
        <td><span class="badge bg-secondary">{{ i.status }}</span></td>
        <td>{{ i.event_count }}</td>
        <td class="text-muted" style="font-size:.85rem;">{{ i.created_at.strftime('%Y-%m-%d %H:%M') if i.created_at else '' }}</td>
        <td><a href="/incident/{{ i.id }}" class="btn btn-sm btn-outline-secondary">Investigate <i class="bi bi-arrow-right"></i></a></td>
      </tr>
      {% else %}
      <tr><td colspan="7" class="text-center text-muted py-4">No incidents yet.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}"""

open(os.path.join(BASE, "base.html"), "w").write(base_html)
open(os.path.join(BASE, "index.html"), "w").write(index_html)
print("base.html and index.html written OK")

