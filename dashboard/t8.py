PATH = "/home/cpt-ferna02/chronos/dashboard/app.py"
with open(PATH, "r") as f:
    content = f.read()

old = 'if __name__ == "__main__":'
new = '''@app.route("/architecture")
def architecture():
    with open("/home/cpt-ferna02/chronos/docs/architecture.svg", "r") as f:
        svg = f.read()
    from flask import Response
    return Response(svg, mimetype="image/svg+xml")

if __name__ == "__main__":'''

content = content.replace(old, new)
with open(PATH, "w") as f:
    f.write(content)
print("OK")
