"""The settings reference, rendered from the migrations (DESIGN.md 79, G7).

Every risk_policy_settings row a migration seeds -- its key, the owner's
default and the row's own description -- grouped by migration. A row a later
migration seeds again (for a new description: migrations never overwrite a
tuned value) is shown once, as the later migration describes it. The documents
carry it between two markers; nobody edits it by hand.

    python3 tools/settings_reference.py            # print it
    python3 tools/settings_reference.py --write    # replace it in the documents

The gate fails when a document's block differs from what this renders, or
when the SQL Server migrations seed other keys, defaults or descriptions than
the PostgreSQL ones.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "<!-- settings-reference:begin (tools/settings_reference.py --write; do not edit by hand) -->"
END = "<!-- settings-reference:end -->"
DOCUMENTS = ("INTEGRATION_GUIDE.md", "WHO_CONFIGURES_WHAT.md")

_ROW = re.compile(r"\(\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'\s*\)")


def _unquote(text):
    return text.replace("''", "'")


def seeded_settings(engine="postgresql"):
    """[(migration number, title, [(key, default, description), ...]), ...]"""
    migrations = []
    for path in sorted((ROOT / "migrations" / engine).glob("[0-9][0-9][0-9]_*.sql")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        title = ""
        for index, line in enumerate(lines):
            match = re.match(r"--\s*Migration \d+:\s*(.*)", line)
            if match:
                parts = [match.group(1).strip()]
                for following in lines[index + 1:]:
                    if not following.startswith("-- ") or not following[3:].strip():
                        break
                    parts.append(following[3:].strip())
                title = " ".join(parts)
                break
        start = text.find("risk_policy_settings AS t") if engine == "sqlserver" else text.find(
            "INSERT INTO risk_policy_settings")
        if start < 0:
            continue
        end = text.find("ON CONFLICT", start) if engine == "postgresql" else text.find(
            ") AS s(", start)
        rows = [tuple(_unquote(part) for part in found)
                for found in _ROW.findall(text[start:end])]
        if rows:
            migrations.append((int(path.name[:3]), title, rows))
    return migrations


def effective_settings(engine="postgresql"):
    """seeded_settings with each key kept only where it was last seeded:
    [(migration number, title, [(key, default, description, first seeded by), ...]), ...]"""
    migrations = seeded_settings(engine)
    first, last = {}, {}
    for number, _, rows in migrations:
        for key, _, _ in rows:
            first.setdefault(key, number)
            last[key] = number
    return [(number, title, [(key, value, description, first[key])
                             for key, value, description in rows if last[key] == number])
            for number, title, rows in migrations]


def setting_count(engine="postgresql"):
    return len({key for _, _, rows in seeded_settings(engine) for key, _, _ in rows})


def _cell(text):
    return text.replace("|", "\\|")


def render():
    migrations = effective_settings()
    out = ["%d settings, seeded by migrations %03d-%03d with the owner's defaults; each row's own "
           "description." % (setting_count(), migrations[0][0], migrations[-1][0]), ""]
    for number, title, rows in migrations:
        if not rows:
            continue
        out += ["**Migration %03d** — %s" % (number, title), "",
                "| Setting | Default | What it decides |", "|---|---|---|"]
        for key, value, description, first in rows:
            shown = "`%s`" % value if value != "" else "*(empty)*"
            if first != number:
                description += " *(Seeded by migration %03d; this migration describes it.)*" % first
            out.append("| `%s` | %s | %s |" % (key, _cell(shown), _cell(description)))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def block_in(document_text):
    """The text between the markers, or None when they are missing."""
    start = document_text.find(BEGIN)
    end = document_text.find(END)
    if start < 0 or end < start:
        return None
    return document_text[start + len(BEGIN):end].strip("\n") + "\n"


def write():
    rendered = render()
    for name in DOCUMENTS:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        start, end = text.find(BEGIN), text.find(END)
        if start < 0 or end < start:
            raise SystemExit("%s has no settings-reference markers" % name)
        path.write_text(text[:start + len(BEGIN)] + "\n" + rendered + text[end:],
                        encoding="utf-8")
        print("wrote %s" % name)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        write()
    else:
        sys.stdout.write(render())
