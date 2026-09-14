"""Exercise the iOS integrity scorer without a server, a database or AWS.

Scoring rules were previously only testable through `conformance_suite.py`,
which needs a running server and therefore a live RDS instance. That made the
cheapest possible check of a scoring change cost real money and several
minutes, which is the wrong shape for a pure function.

`_score_ios_integrity` takes probe output and returns (score, hard_block,
reasons). Nothing in it touches the network. This imports the server with its
third-party dependencies stubbed out -- Flask, PyCryptodome, bcrypt and
psycopg2 are needed to *import* the module but not to run the scorer -- so the
whole file stays standard-library only, like the other tools here.

    python3 tools/check_ios_scoring_rules.py [device_trust_server.py]

Covers DESIGN.md 35.5 and 35.6: the structural identifier-invariant rule, the
weaker team-marker name match, both report-only defaults, and -- most
importantly -- the false-positive guards, since a rule that fires on a
legitimately signed application would be worse than no rule at all.
"""
import importlib.util, os, sys, types


def _stub_imports():
    """Satisfy the server's imports without installing anything.

    Every attribute access returns another permissive stub, and calling one
    returns a stub too, which is enough for `Flask(__name__)` and for the
    route decorators applied at import time.
    """
    class Stub(types.ModuleType):
        def __init__(self, name="stub"):
            super().__init__(name)
        def __getattr__(self, name):
            return Stub(name)
        def __call__(self, *args, **kwargs):
            # Used both as Flask(__name__) and as @app.post("/x"), so a call
            # must return something that is itself callable and returns its
            # argument unchanged when used as a decorator.
            if len(args) == 1 and callable(args[0]) and not kwargs:
                return args[0]
            return Stub("called")
        def __iter__(self):
            return iter(())
        # The server configures Flask with app.config[...] = ... at import.
        def __setitem__(self, key, value):
            pass
        def __getitem__(self, key):
            return Stub("item")
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def __bool__(self):
            return False

    for name in ("flask", "flask_jwt_extended",
                 "werkzeug", "werkzeug.exceptions",
                 "bcrypt", "redis",
                 "psycopg2", "psycopg2.errors", "psycopg2.extras", "pyodbc",
                 "Crypto", "Crypto.Hash", "Crypto.PublicKey", "Crypto.Signature"):
        sys.modules.setdefault(name, Stub(name))


def load(path):
    _stub_imports()
    # The scorer reads these at import; values are irrelevant to it.
    os.environ.setdefault("DB_USERNAME", "unused")
    os.environ.setdefault("DB_PASSWORD", "unused")
    os.environ.setdefault("DEVICE_ID_MASTER_SECRET", "0" * 64)
    spec = importlib.util.spec_from_file_location("device_trust_server", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUNDLE = "com.example.devicefingerprinting"

# Exactly what a TrollStore-installed build reported on the iPhone 7, recorded
# verbatim in DESIGN.md 35.4. An observation, not a model of the exploit.
TROLLSTORE = {
    "signing_identifier": "com.icraze.gtatracker",
    "team_identifier": "TROLLTROLL",
}


def probes(code_integrity=None, **signing):
    base = {
        "status": "ok",
        "signed": True,
        "signing_identifier": BUNDLE,
        "team_identifier": "ABCDE12345",
        "get_task_allow": False,
    }
    base.update(signing)
    result = {
        "app_identity": {"status": "ok", "bundle_id": BUNDLE,
                         "executable_sha256": "ab" * 32},
        "code_signing": base,
        "debugger": {"status": "ok", "traced": False},
        "jailbreak_files": {"status": "ok", "found_paths": []},
        "sandbox": {"status": "ok", "write_outside_sandbox_succeeded": False},
        "dyld_images": {"status": "ok", "suspicious_tokens": []},
        "environment": {"status": "ok", "dyld_insert_libraries": ""},
        "simulator": {"status": "ok", "is_simulator": False},
    }
    if code_integrity is not None:
        result["code_integrity"] = code_integrity
    return result


MISMATCH = "ios_signing_identifier_bundle_mismatch"
FAKE_TEAM = "ios_known_fake_team_identifier"

failures = []


def check(name, condition, detail=""):
    print(("PASS  " if condition else "FAIL  ") + name +
          ("" if condition else "\n        " + str(detail)))
    if not condition:
        failures.append(name)


def reason(reasons, code):
    return next((r for r in reasons if r["code"] == code), None)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "device_trust_server.py"

    # --- default: both rules ship visible but inert -----------------------
    os.environ.pop("INTEGRITY_SCORE_IOS_FAKE_SIGNATURE", None)
    server = load(path)
    check("default is report-only (flag off)",
          server.INTEGRITY_SCORE_IOS_FAKE_SIGNATURE is False)

    score, hard, reasons = server._score_ios_integrity(probes(**TROLLSTORE))
    mismatch, fake_team = reason(reasons, MISMATCH), reason(reasons, FAKE_TEAM)

    check("a fake signature raises the identifier-invariant rule",
          mismatch is not None, sorted(r["code"] for r in reasons))
    check("the TrollStore team marker raises the name-match rule",
          fake_team is not None, sorted(r["code"] for r in reasons))
    if mismatch:
        check("the invariant rule is marked report_only",
              mismatch.get("report_only") is True, mismatch)
        check("a report-only reason contributes no points",
              mismatch["points"] == 0, mismatch)
        check("it still declares what enabling it would cost",
              mismatch.get("proposed_points") == 90, mismatch)
        check("a report-only reason can never hard-block",
              mismatch["hard"] is False, mismatch)
    if fake_team:
        check("the name-match rule is weighted low (25)",
              fake_team.get("proposed_points") == 25, fake_team)
    check("report-only leaves the score untouched", score == 0, score)
    check("report-only does not hard-block", hard is False, hard)

    # --- false-positive guards -------------------------------------------
    # If any of these fail, the invariant claimed in 35.5 is wrong and the
    # rule must not be promoted to scoring.
    score, _, reasons = server._score_ios_integrity(probes())
    check("a correctly signed app does not trip the invariant",
          reason(reasons, MISMATCH) is None, sorted(r["code"] for r in reasons))
    check("an ordinary team identifier is not a fake marker",
          reason(reasons, FAKE_TEAM) is None, sorted(r["code"] for r in reasons))
    check("a correctly signed clean app scores 0", score == 0, score)

    # The .NET collector reports the application-identifier entitlement,
    # "TEAMID.bundleid", where the Swift collector reports the CodeDirectory
    # identifier. Both are legitimate and neither may raise the rule.
    score, _, reasons = server._score_ios_integrity(
        probes(signing_identifier="ABCDE12345." + BUNDLE))
    check("a TEAMID-prefixed identifier (the .NET convention) is accepted",
          reason(reasons, MISMATCH) is None, sorted(r["code"] for r in reasons))
    check("and still scores 0", score == 0, score)

    # ...but a fake signature must not be able to hide behind that shape.
    score, _, reasons = server._score_ios_integrity(
        probes(signing_identifier="TROLLTROLL.com.someone.else"))
    check("a TEAMID-prefixed FAKE identifier is still caught",
          reason(reasons, MISMATCH) is not None, sorted(r["code"] for r in reasons))

    score, _, reasons = server._score_ios_integrity(
        probes(signed=False, signing_identifier="", team_identifier=""))
    check("an UNSIGNED build is not mistaken for a fake signature",
          reason(reasons, MISMATCH) is None, sorted(r["code"] for r in reasons))
    check("an unsigned build scores 0", score == 0, score)

    bare = probes()
    bare["code_signing"] = {"status": "ok"}
    score, _, reasons = server._score_ios_integrity(bare)
    check("a client omitting the fields entirely raises nothing",
          reason(reasons, MISMATCH) is None and reason(reasons, FAKE_TEAM) is None,
          sorted(r["code"] for r in reasons))

    # --- code integrity, app bucket (battery item 16) ---------------------
    clean_ci = {"status": "ok", "checked": True,
                "app_compared_bytes": 900000, "app_diff_bytes": 0,
                "system_images_unreadable": 312}
    score, _, reasons = server._score_ios_integrity(probes(code_integrity=clean_ci))
    check("a clean app bucket raises nothing",
          reason(reasons, "ios_app_code_modified") is None, sorted(r["code"] for r in reasons))
    check("and unreadable system images are not a finding", score == 0, score)

    hooked_ci = dict(clean_ci, app_diff_bytes=108, app_libs_diff=1,
                     diffed_libs="App")
    score, _, reasons = server._score_ios_integrity(probes(code_integrity=hooked_ci))
    modified = reason(reasons, "ios_app_code_modified")
    check("a modified app bucket raises ios_app_code_modified",
          modified is not None, sorted(r["code"] for r in reasons))
    check("and it ships report-only by default",
          modified is not None and modified.get("report_only") is True, modified)
    check("contributing 0 while report-only", score == 0, score)

    # The inert-vs-clean distinction, which is the whole reason `checked` exists.
    inert_ci = {"status": "ok", "checked": False,
                "app_compared_bytes": 0, "app_diff_bytes": 108}
    score, _, reasons = server._score_ios_integrity(probes(code_integrity=inert_ci))
    check("an UNCHECKED bucket is not scored, even reporting a diff",
          reason(reasons, "ios_app_code_modified") is None, sorted(r["code"] for r in reasons))

    score, _, reasons = server._score_ios_integrity(probes())
    check("a client that sends no code_integrity at all raises nothing",
          reason(reasons, "ios_app_code_modified") is None, sorted(r["code"] for r in reasons))

    # A sub-instruction diff is below the one-arm64-branch floor.
    tiny_ci = dict(clean_ci, app_diff_bytes=3)
    score, _, reasons = server._score_ios_integrity(probes(code_integrity=tiny_ci))
    check("a 3-byte diff is below the 4-byte inline-hook floor",
          reason(reasons, "ios_app_code_modified") is None, sorted(r["code"] for r in reasons))

    # --- the same input with scoring enabled ------------------------------
    os.environ["INTEGRITY_SCORE_IOS_FAKE_SIGNATURE"] = "1"
    os.environ["INTEGRITY_SCORE_IOS_CODE_INTEGRITY"] = "1"
    scoring = load(path)
    score, _, reasons = scoring._score_ios_integrity(probes(code_integrity=hooked_ci))
    modified = reason(reasons, "ios_app_code_modified")
    check("enabled: a modified app bucket scores its full 90",
          modified is not None and modified["points"] == 90 and score == 90,
          (modified, score))
    check("the flag switches scoring on",
          scoring.INTEGRITY_SCORE_IOS_FAKE_SIGNATURE is True)

    score, hard, reasons = scoring._score_ios_integrity(probes(**TROLLSTORE))
    mismatch = reason(reasons, MISMATCH)
    check("enabled: the invariant rule carries its real weight",
          mismatch is not None and mismatch["points"] == 90, mismatch)
    check("enabled: no report_only marker is left behind",
          mismatch is not None and "report_only" not in mismatch, mismatch)
    check("enabled: 90 + 25 scores 115", score == 115, score)
    check("enabled: neither rule hard-blocks", hard is False, hard)

    # The real device, both ways round.
    live, _, _ = scoring._score_ios_integrity(probes(get_task_allow=True, **TROLLSTORE))
    inert, _, _ = server._score_ios_integrity(probes(get_task_allow=True, **TROLLSTORE))
    check("the observed iPhone 7 would score 150 with the rules enabled",
          live == 150, live)
    check("and still scores only 35 while they are report-only",
          inert == 35, inert)

    print("\nios scoring rules: %s" %
          ("OK" if not failures else "%d FAILURE(S)" % len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
