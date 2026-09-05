#!/usr/bin/env python3
"""Translate every literal SQL statement in the server through the SQL Server
dialect and fail if any PostgreSQL-only syntax survives.

The dialect layer translates some constructs by token substitution and leaves
others to explicit per-call-site branches. That split is easy to break: adding
one more `LIMIT 1` or `ON CONFLICT` to a query is natural when developing
against PostgreSQL and would fail only at runtime, on a customer's SQL Server.
This check catches it in the repository instead.

Run it with the server's own interpreter, since it imports the module:

    DB_ENGINE=sqlserver DB_USERNAME=x DB_PASSWORD=y \
    DEVICE_ID_MASTER_SECRET=<40 chars> \
    python3 tools/check_sqlserver_translation.py device_trust_server.py
"""
import ast
import io
import os
import re
import sys

FORBIDDEN = [
    (re.compile(r"\bLIMIT\s+\d+", re.I), "LIMIT survived translation"),
    (re.compile(r"\bNOW\(\)", re.I), "NOW() survived translation"),
    (re.compile(r"\bINTERVAL\b", re.I), "INTERVAL survived translation"),
    (re.compile(r"%s"), "%s placeholder survived translation"),
    (re.compile(r"\bON\s+CONFLICT\b", re.I), "ON CONFLICT survived translation"),
    (re.compile(r"\bRETURNING\b", re.I), "RETURNING survived translation"),
    (re.compile(r"\bFOR\s+UPDATE\b", re.I), "FOR UPDATE survived translation"),
    (re.compile(r"\bSERIAL\b", re.I), "SERIAL survived translation"),
    (re.compile(r"\bJSONB\b", re.I), "JSONB survived translation"),
    # PostgreSQL accepts "DELETE FROM t AS alias"; SQL Server rejects it and
    # wants "DELETE alias FROM t AS alias". Dropping the alias suits both.
    (
        re.compile(
            r"\bDELETE\s+FROM\s+\w+\s+(?:AS\s+)?(?!WHERE\b|OUTPUT\b|FROM\b)\w+",
            re.I,
        ),
        "aliased DELETE target",
    ),
]
STATEMENT = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.I)
# Statements are sometimes built by concatenating fragments, so a literal need
# not start with a keyword to be worth checking. Two things must be excluded
# though, or they report themselves: docstrings that merely discuss the
# dialect, and the short lock fragments the dialect returns on purpose.
MIN_LENGTH = 20


def _docstring_nodes(tree):
    """Node ids of every docstring, which are prose and not SQL."""
    found = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            found.add(id(first.value))
    return found


def main(path):
    os.environ.setdefault("DB_ENGINE", "sqlserver")
    os.environ.setdefault("DB_USERNAME", "check")
    os.environ.setdefault("DB_PASSWORD", "check")
    os.environ.setdefault("DEVICE_ID_MASTER_SECRET", "c" * 40)
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)) or ".")

    module = __import__(os.path.basename(path)[:-3])
    dialect = module.DIALECT
    if dialect.name != "sqlserver":
        print("expected the SQL Server dialect, got %r" % dialect.name)
        return 2

    source = io.open(path, encoding="utf-8").read()
    tree = ast.parse(source)
    docstrings = _docstring_nodes(tree)
    checked, problems = 0, []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in docstrings or len(node.value) < MIN_LENGTH:
            continue
        if not STATEMENT.search(node.value):
            continue
        checked += 1
        translated = dialect.sql(node.value)
        for pattern, label in FORBIDDEN:
            if pattern.search(translated):
                problems.append(
                    (node.lineno, label, " ".join(translated.split())[:110])
                )

    if problems:
        print("SQL Server translation: FAIL (%d problem(s))" % len(problems))
        for lineno, label, snippet in problems:
            print("  %s:%d  %s\n      %s" % (path, lineno, label, snippet))
        return 1
    print("SQL Server translation: OK (%d statements checked)" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "device_trust_server.py"))
