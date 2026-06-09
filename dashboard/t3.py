BASE = "/home/cpt-ferna02/chronos/dashboard/templates/base.html"

with open(BASE, "r") as f:
    content = f.read()

old = "    .timeline-item{position:relative;padding-left:2rem;border-left:2px solid #30363d;margin-bottom:1rem}"
new = """    .timeline-item{position:relative;padding-left:2rem;border-left:2px solid #30363d;margin-bottom:1rem}
    .timeline-item .fw-semibold{color:#e6edf3}
    .timeline-item .text-muted{color:#8b949e!important}
    .card-header{color:#e6edf3}
    .table tbody td{color:#c9d1d9}
    th{color:#8b949e!important}
    .text-muted{color:#8b949e!important}
    h4{color:#e6edf3}
    p{color:#c9d1d9}"""

content = content.replace(old, new)

with open(BASE, "w") as f:
    f.write(content)
print("base.html patched OK")
