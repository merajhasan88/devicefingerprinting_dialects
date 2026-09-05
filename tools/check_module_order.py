"""Catch module-level names used before they are defined.

Python only raises this at import time, which on a 3,100-line single-file
server means discovering it on the deployed host. This finds it locally.
"""
import ast, io, sys

tree = ast.parse(io.open(sys.argv[1], encoding="utf-8").read())
defined_at = {}
for node in tree.body:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        defined_at.setdefault(node.name, node.lineno)
    elif isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name):
                defined_at.setdefault(t.id, node.lineno)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        for a in node.names:
            defined_at.setdefault((a.asname or a.name).split(".")[0], node.lineno)

problems = []
for node in tree.body:                      # module level only
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        continue                            # bodies run later, not at import
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            first = defined_at.get(sub.id)
            if first is not None and first > node.lineno:
                problems.append((sub.id, node.lineno, first))
for name, used, defined in sorted(set(problems)):
    print("USED BEFORE DEFINED: %s used at line %d, defined at line %d" % (name, used, defined))
print("module-level ordering: %s" % ("OK" if not problems else "%d PROBLEM(S)" % len(set(problems))))
sys.exit(1 if problems else 0)
