BASE = "/home/cpt-ferna02/chronos/dashboard/templates/base.html"
with open(BASE, "r") as f:
    content = f.read()

old = "    ::-webkit-scrollbar-thumb:hover{background:#243040}"
new = """    ::-webkit-scrollbar-thumb:hover{background:#243040}
    .table>:not(caption)>*>*{background-color:transparent!important;color:#8892a0}
    .table-striped>tbody>tr:nth-of-type(odd)>*{background-color:transparent!important}
    tbody,td,tfoot,th,thead,tr{border-color:#111820!important;background-color:transparent!important}
    .table tbody tr:hover>td{background-color:#0d1523!important;color:#c0cad8!important}"""

content = content.replace(old, new)
with open(BASE, "w") as f:
    f.write(content)
print("OK")
