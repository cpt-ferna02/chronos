PATH = "/home/cpt-ferna02/chronos/dashboard/templates/incident.html"
with open(PATH, "r") as f:
    content = f.read()
content = content.replace('<span class="fw-semibold" style="font-size:.9rem;">{{ e.event_type }}</span>', '<span class="event-type">{{ e.event_type }}</span>')
content = content.replace('<div class="text-muted mt-1" style="font-size:.82rem;">{{ e.description }}</div>', '<div class="event-desc">{{ e.description }}</div>')
content = content.replace('{% if e.confidence %}<div style="font-size:.72rem;color:#6e7681;">confidence: {{ e.confidence }}</div>{% endif %}', '{% if e.confidence %}<div class="event-conf">conf: {{ e.confidence }}</div>{% endif %}')
with open(PATH, "w") as f:
    f.write(content)
print("incident.html patched OK")
