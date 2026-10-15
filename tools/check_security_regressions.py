"""Security regression gate for the 2026-09-29 critical review (DESIGN.md 63).

The external review shipped a harness that reproduced each finding by
asserting the VULNERABLE behaviour. This is that harness with every assertion
inverted to the repaired behaviour, its negative controls kept, and checks
added for the repairs the review asked for. Run it before every server change;
it needs no database, network, phone or AWS.

It imports the real server and drives real Flask routing, JWT validation and
ECDSA verification. Only the storage boundary is replaced -- a scripted cursor
that answers the handful of statements each check reaches and rejects any
other SQL, so a check cannot pass by silently skipping a query. For the
step-up checks the downstream integrity and relationship gates are stubbed, to
isolate the binding under test. Database transaction semantics are NOT covered
here: those need the conformance suite against a live engine. The R4 checks are
the one exception to the scripted cursor: which integrity reports reach an
installation is decided in SQL, so they run the server's own statements on an
in-memory SQLite database (stdlib) -- a check of the predicate's logic, not of
PostgreSQL or SQL Server.

    python3 tools/check_security_regressions.py [path/to/repo]

Needs the server's own dependencies plus `cryptography` (via the conformance
suite's software key), exactly like conformance_suite.py.
"""
import ast
import json
import os
import random
import re
import sqlite3
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Deterministic local configuration; never inherit a real database, Redis or
# deployment scoring switch into this fixture-driven harness.
for _name in list(os.environ):
    if _name.startswith(("DB_", "INTEGRITY_", "POLICY_", "RATE_LIMIT_", "REDIS_",
                         "NONCE_", "RISK_SETTINGS_", "TRUSTED_PROXY", "MAX_REQUEST")):
        del os.environ[_name]
os.environ["DEVICE_ID_MASTER_SECRET"] = "local-regression-only-secret-never-deploy-" * 2
os.environ["DB_USERNAME"] = "unused"
os.environ["DB_PASSWORD"] = "unused"
os.environ["DB_ENGINE"] = "postgresql"
os.environ["NONCE_BACKEND"] = "database"
os.environ["REQUIRE_HTTPS"] = "0"
os.environ["INTEGRITY_MODE"] = "enforce"
os.environ["DEVICE_POLICY_MODE"] = "enforce"

REPO = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
# The documents always come from this tool's own repository, even when REPO
# names another server file (a mutation run).
DOCS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import device_trust_server as s  # noqa: E402
import conformance_suite as c  # noqa: E402
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402

inst = c.Installation()
inst.device_id = str(uuid.uuid4())
step = c.Installation()
account = str(uuid.uuid4())
SENSITIVE = "/v1/account/sensitive-echo"
SETTINGS = {
    "stepup_required_paths": SENSITIVE,
    "stepup_factor": "passcode",
    "stepup_mode": "per_use",
    # The checks of the screen-lock key run under that method; the owner's
    # default is the app PIN (DESIGN.md 78), checked on its own below.
    "stepup_method": "screen_lock",
}


class Rows(object):
    """The storage boundary. Answers what each check reaches; rejects the rest."""

    def __init__(self):
        self.nonces = set()
        self.report_row = None
        self.reenrol_row = None
        self.writes = []
        self.statements = []
        self.step_factor = "passcode"
        self.step_jwk = step.jwk
        self.hardware_backed = None
        self.fail_settings = False
        self.settings = dict(SETTINGS)
        self.consumed = set()
        self.refresh_row = None
        self.other_full_session = None
        self.account_row = None
        self.revoked_families = set()
        self.link_exists = False
        self.link_counts = (0, 0)
        self.recent_qualities = []
        self.acceptances = {}
        self.lapses = set()
        self.request_scope = None
        self.observations = []
        self.fail_observations = False
        self.approval_requests_last_hour = 0
        self.budget_oldest = None
        self.app_pins = {}
        self.password_hash = None
        self.family_started = None

    def execute(self, sql, params=None):
        q = " ".join(sql.split())
        self.statements.append(q)
        self.result = None
        self.rowcount = 1
        if q == "SELECT 1":
            self.result = (1,)
        elif q.startswith("SELECT i.key_algorithm, i.public_key_jwk, i.device_id, i.key_thumbprint"):
            self.result = ("ES256", inst.jwk, inst.device_id,
                           s._parse_public_key(inst.jwk)["thumbprint"], "active", "active")
        elif q.startswith("SELECT i.key_algorithm, i.public_key_jwk"):
            self.result = ("ES256", inst.jwk, inst.device_id, "active", "active")
        elif q.startswith("SELECT c.installation_id, c.device_id, c.platform"):
            self.result = self.report_row
        elif q.startswith("SELECT d.platform, i.status, d.status FROM app_installations i"):
            self.result = ("android", "active", "active")
        elif q.startswith(("INSERT INTO integrity_challenges", "DELETE FROM integrity_challenges")):
            self.writes.append((q, params))
        elif q.startswith("SELECT key_hardware_backed FROM app_installations"):
            self.result = (self.hardware_backed,)
        elif q.startswith("SELECT stepup_public_key_jwk"):
            self.result = (self.step_jwk, "ES256", self.step_factor, "per_use", 0, None,
                           s._parse_public_key(inst.jwk)["thumbprint"])
        elif q.startswith("SELECT installation_id, device_id, registration_method"):
            self.result = self.reenrol_row
        elif q.startswith("SELECT family_id, account_id, device_id, installation_id, expires_at, revoked_at, scope, limited_causes, accepted_causes, accepted_until, acceptance_id FROM refresh_sessions"):
            row = self.refresh_row
            self.result = row + (None,) if row is not None and len(row) == 10 else row
        elif q.startswith("INSERT INTO refresh_sessions"):
            self.writes.append((q, params))
        elif q.startswith("SELECT r.session_id FROM refresh_sessions r"):
            self.result = self.other_full_session
        elif q.startswith("SELECT COUNT(*) FROM refresh_sessions WHERE family_id"):
            self.result = (0 if params[0] in self.revoked_families else 1,)
        elif q.startswith(("SELECT account_id FROM demo_accounts",
                           "SELECT device_id FROM recognized_devices")):
            self.result = (params[0],)  # the anchor row; locking is the engine's job
        elif q.startswith("SELECT acceptance_id, family_id, account_id, installation_id, causes"):
            self.result = self.acceptances.get(params[0])
        elif q.startswith("INSERT INTO session_acceptances"):
            self.writes.append((q, params))
            if len(params) == 13:  # a carried-over pre-016 approval
                row = (params[0], params[1], params[2], params[4], params[6], params[7],
                       params[8], params[9], params[12])
            else:
                row = (params[0], params[1], params[2], params[4], params[8], params[9],
                       params[10], params[11], params[15])
            if row[0] in self.acceptances:
                raise s.DIALECT._driver.errors.UniqueViolation("duplicate acceptance")
            self.acceptances[row[0]] = row[:5] + (getattr(row[5], "adapted", row[5]),) + row[6:] + (None,)
        elif q.startswith(("UPDATE session_acceptances", "UPDATE risk_policy_decisions")):
            self.writes.append((q, params))
        elif q.startswith(("SAVEPOINT ", "RELEASE SAVEPOINT ", "ROLLBACK TO SAVEPOINT ")):
            pass
        elif q.startswith("SELECT 1 FROM acceptance_lapses"):
            self.result = (1,) if (params[0], params[1]) in self.lapses else None
        elif q.startswith("INSERT INTO acceptance_lapses"):
            self.writes.append((q, params))
            self.lapses.add((params[0], params[1]))
        elif q.startswith("SELECT causes, reasons, device_accounts, account_devices, approved_by_installation"):
            self.result = self.request_scope
        elif q.startswith("SELECT probe_results FROM integrity_reports WHERE report_id"):
            self.result = None
        elif q.startswith("SELECT evidence_quality FROM integrity_reports WHERE installation_id"):
            self.result = [(quality,) for quality in self.recent_qualities]
        elif q.startswith("SELECT 1 FROM device_account_links WHERE device_id"):
            self.result = (1,) if self.link_exists else None
        elif q.startswith("SELECT COUNT(*) FROM device_account_links WHERE device_id"):
            self.result = (self.link_counts[0],)
        elif q.startswith("SELECT COUNT(DISTINCT device_id) FROM device_account_links"):
            self.result = (self.link_counts[1],)
        elif q.startswith("UPDATE session_upgrade_requests"):
            self.writes.append((q, params))
        elif q.startswith("SELECT stepup_key_account_id, stepup_public_key_jwk"):
            self.result = (None, self.step_jwk)
        elif q.startswith("SELECT account_id, password_hash FROM demo_accounts"):
            self.result = self.account_row
        elif q.startswith(("UPDATE device_account_links", "INSERT INTO demo_accounts")):
            self.writes.append((q, params))
        elif q.startswith("SELECT i.status, d.status FROM app_installations i"):
            self.result = ("active", "active")
        elif q.startswith("INSERT INTO installation_challenges"):
            if params[0] in self.consumed:
                raise s.DIALECT._driver.errors.UniqueViolation("challenge already consumed")
            self.consumed.add(params[0])
            self.writes.append((q, params))
        elif q.startswith("DELETE FROM installation_challenges"):
            self.writes.append((q, params))
        elif q.startswith("SELECT setting_key, setting_value"):
            if self.fail_settings:
                raise RuntimeError("simulated policy-table permission/read failure")
            self.result = list(self.settings.items())
        elif q.startswith("INSERT INTO access_proof_nonces"):
            if params[0] in self.nonces:
                raise s.DIALECT._driver.errors.UniqueViolation("duplicate nonce")
            self.nonces.add(params[0])
        elif q.startswith("INSERT INTO integrity_reports"):
            self.writes.append((q, params))
        elif q.startswith("INSERT INTO server_observations"):
            if self.fail_observations:
                raise RuntimeError("simulated observation write failure")
            if params[0] in {row[0] for row in self.observations}:
                raise s.DIALECT._driver.errors.UniqueViolation("duplicate observation")
            self.writes.append((q, params))
            self.observations.append(params)
        elif q.startswith("SELECT COUNT(*), MIN(created_at) FROM session_upgrade_requests "
                          "WHERE account_id"):
            self.result = (self.approval_requests_last_hour, self.budget_oldest)
        elif q.startswith("UPDATE app_pins SET failures = failures + 1"):
            pin = self.app_pins.get(params[0])
            self.rowcount = 0
            if (pin and pin["locked_at"] is None and pin["failures"] < params[1]
                    and (pin["hash"] is not None or "pin_hash IS NOT NULL" not in q)):
                pin["failures"] += 1
                self.rowcount = 1
        elif q.startswith("SELECT pin_hash, failures, locked_at FROM app_pins"):
            pin = self.app_pins.get(params[0])
            self.result = (pin["hash"], pin["failures"], pin["locked_at"]) if pin else None
        elif q.startswith("SELECT pin_hash, locked_at, reset_until FROM app_pins"):
            pin = self.app_pins.get(params[0])
            self.result = (pin["hash"], pin["locked_at"], pin.get("reset_until")) if pin else None
        elif q.startswith("SELECT pin_hash, locked_at FROM app_pins"):
            pin = self.app_pins.get(params[0])
            self.result = (pin["hash"], pin["locked_at"]) if pin else None
        elif q.startswith("SELECT reset_until FROM app_pins"):
            pin = self.app_pins.get(params[0])
            self.result = (pin.get("reset_until"),) if pin else None
        elif q.startswith("UPDATE app_pins SET failures = 0, locked_at = NULL, reset_until = %s"):
            pin = self.app_pins.get(params[1])
            self.rowcount = 0
            if pin is not None:
                pin.update(failures=0, locked_at=None, reset_until=params[0])
                self.rowcount = 1
        elif q.startswith("UPDATE app_pins SET failures = 0, locked_at = NULL"):
            pin = self.app_pins.get(params[0])
            self.rowcount = 0
            if pin is not None and (pin["hash"] is not None or "pin_hash IS NOT NULL" not in q):
                pin.update(failures=0, locked_at=None)
                self.rowcount = 1
        elif q.startswith("UPDATE app_pins SET failures = 0"):
            self.app_pins[params[0]]["failures"] = 0
        elif q.startswith("UPDATE app_pins SET locked_at = NOW()"):
            pin = self.app_pins[params[0]]
            self.rowcount = 0
            if pin["locked_at"] is None:
                pin["locked_at"] = s._utc_now()
                self.rowcount = 1
        elif q.startswith("UPDATE app_pins SET pin_hash"):
            pin = self.app_pins.get(params[2])
            self.rowcount = 0
            if pin is not None and (len(params) == 3 or (
                    pin.get("reset_until") is not None and pin["reset_until"] > params[3])):
                pin.update(hash=params[0], failures=0, locked_at=None, by=params[1])
                if "reset_until = NULL" in q:
                    pin["reset_until"] = None
                self.rowcount = 1
        elif q.startswith("INSERT INTO app_pins (account_id, pin_hash, reset_until)"):
            if params[0] in self.app_pins:
                raise s.DIALECT._driver.errors.UniqueViolation("duplicate app pin")
            self.app_pins[params[0]] = {"hash": None, "failures": 0, "locked_at": None,
                                        "by": None, "reset_until": params[1]}
        elif q.startswith("INSERT INTO app_pins"):
            if params[0] in self.app_pins:
                raise s.DIALECT._driver.errors.UniqueViolation("duplicate app pin")
            self.app_pins[params[0]] = {"hash": params[1], "failures": 0, "locked_at": None,
                                        "by": params[2]}
        elif q.startswith("SELECT MIN(created_at) FROM refresh_sessions WHERE family_id"):
            self.result = (self.family_started,)
        elif q.startswith("SELECT password_hash FROM demo_accounts WHERE account_id"):
            self.result = (self.password_hash,) if self.password_hash else None
        elif q.startswith("INSERT INTO session_upgrade_requests"):
            self.writes.append((q, params))
        elif q.startswith(("DELETE FROM access_proof_nonces", "UPDATE app_installations",
                           "UPDATE recognized_devices", "UPDATE integrity_challenges",
                           "UPDATE refresh_sessions")):
            self.writes.append((q, params))
        else:
            raise AssertionError("Unmodeled SQL: " + q)

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


db = Rows()


@contextmanager
def cursor(commit=False):
    yield db


real_settings_reader = s._risk_policy_settings
s._cursor = cursor
s._get_schema_state = lambda: {"ok": True, "found": 7, "required": 7}
s._get_backend_identity = lambda: {"engine": "fixture-postgresql", "supported": True}
s._redis_status = lambda: {"configured": False}
client = s.app.test_client()
with s.app.app_context():
    device_token = s._issue_device_token(
        inst.installation_id, inst.device_id, s._parse_public_key(inst.jwk)["thumbprint"])
    token = s.create_access_token(identity=account, additional_claims={
        "role": "account", "iid": inst.installation_id, "did": inst.device_id,
        "sid": str(uuid.uuid4()), "family": str(uuid.uuid4())})


def encode(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def fresh_nonce():
    return c.b64u(os.urandom(32))


def access_headers(method, path, body=b"", bearer=None, nonce=None, version=2, query="",
                   signer=None):
    bearer = bearer or token
    proof = {"version": version, "installation_id": inst.installation_id,
             "method": method, "path": path, "body_sha256": c.sha256_hex(body),
             "access_token_sha256": c.sha256_hex(bearer.encode()),
             "timestamp": int(time.time()), "nonce": nonce or fresh_nonce()}
    if version >= 2:
        proof["query"] = query
    raw = c.b64u(encode(proof))
    return {"Authorization": "Bearer " + bearer, "X-Access-Proof": raw,
            "X-Access-Signature": (signer or inst).sign_b64(raw),
            "Content-Type": "application/json"}


def stepup_headers(method, route, body, nonce, factor="passcode", signer=None,
                   bearer=None, overrides=None):
    proof = {"version": 2, "purpose": "stepup",
             "installation_id": inst.installation_id,
             "access_token_sha256": c.sha256_hex((bearer or token).encode()),
             "method": method, "path": route, "query": "",
             "body_sha256": c.sha256_hex(body), "factor": factor,
             "nonce": nonce, "timestamp": int(time.time())}
    proof.update(overrides or {})
    raw = c.b64u(encode(proof))
    return {"X-Step-Up-Proof": raw, "X-Step-Up-Signature": (signer or step).sign_b64(raw)}


def send_report(platform, probes, collector_version=None):
    if collector_version is None:
        collector_version = s._EVIDENCE_CONTRACT_VERSION.get(platform, 1)
    required = s._integrity_probe_plan(platform)
    nonce = os.urandom(32)
    db.report_row = (inst.installation_id, inst.device_id, platform, c.sha256_hex(nonce),
                     required, s._utc_now() + s.INTEGRITY_CHALLENGE_LIFETIME, None,
                     "ES256", inst.jwk, "active", "active")
    report = {"version": 1, "installation_id": inst.installation_id,
              "challenge_id": str(uuid.uuid4()), "platform": platform,
              "challenge_nonce": c.b64u(nonce), "collected_at": int(time.time()),
              "collector_version": collector_version, "probe_results": probes}
    raw = c.b64u(encode(report))
    body = encode({"report_payload": raw, "report_signature": inst.sign_b64(raw)})
    path = "/v1/integrity/report"
    reply = client.post(path, data=body, headers=access_headers("POST", path, body, device_token))
    return reply.status_code, reply.get_json()


def clean(platform):
    return c.clean_probes(s._integrity_probe_plan(platform), platform=platform)


def codes(payload):
    return {r["code"] for r in payload["integrity"]["reasons"]}


def error_code(reply):
    payload = reply.get_json() or {}
    return (payload.get("error") or {}).get("code")


CHECKS = []


def check(function):
    CHECKS.append(function)
    return function


def expect(condition, detail):
    if not condition:
        raise AssertionError(detail)


# ---------------------------------------------------------------------------
# F2 -- missing or malformed evidence is never scored as clean
# ---------------------------------------------------------------------------


@check
def empty_ok_probes_are_incomplete_not_trusted():
    for platform in ("android", "ios"):
        required = s._integrity_probe_plan(platform)
        status, payload = send_report(platform, {n: {"status": "ok"} for n in required})
        expect(status == 200, "%s: expected 200, got %s %s" % (platform, status, payload))
        decision = payload["integrity"]
        expect(decision["verdict"] != "trusted",
               "%s: empty ok probes scored trusted (%s)" % (platform, decision["score"]))
        missing = {n for n in required if "integrity_probe_incomplete:%s" % n not in codes(payload)}
        expect(not missing, "%s: no incomplete reason for %s" % (platform, sorted(missing)))


@check
def empty_probes_with_app_pins_are_not_trusted():
    probes = {n: {"status": "ok"} for n in s._integrity_probe_plan("android")}
    identity = c.clean_probes(["app_identity"])["app_identity"]
    probes["app_identity"] = identity
    saved = (s.EXPECTED_ANDROID_PACKAGE, s.EXPECTED_ANDROID_CERT_SHA256, s.EXPECTED_ANDROID_APK_SHA256)
    s.EXPECTED_ANDROID_PACKAGE = identity["package_name"]
    s.EXPECTED_ANDROID_CERT_SHA256 = set(identity["cert_sha256"])
    s.EXPECTED_ANDROID_APK_SHA256 = {identity["apk_sha256"]}
    try:
        status, payload = send_report("android", probes)
    finally:
        (s.EXPECTED_ANDROID_PACKAGE, s.EXPECTED_ANDROID_CERT_SHA256,
         s.EXPECTED_ANDROID_APK_SHA256) = saved
    expect(status == 200 and payload["integrity"]["verdict"] != "trusted",
           "pinned identity plus empty probes scored %s" % payload)


@check
def clean_reports_still_score_zero():
    for platform in ("android", "ios"):
        status, payload = send_report(platform, clean(platform))
        expect(status == 200 and payload["integrity"]["score"] == 0,
               "%s: a complete clean report must score 0, got %s %s" % (platform, status, payload))


@check
def malformed_numeric_field_is_a_400():
    probes = clean("android")
    probes["code_integrity"]["app_diff_bytes"] = "not-a-number"
    status, payload = send_report("android", probes)
    expect(status == 400 and payload["error"]["code"] == "invalid_integrity_probe",
           "expected 400 invalid_integrity_probe, got %s %s" % (status, payload))
    probes = clean("android")
    probes["tracer"]["tracer_pid"] = True
    status, payload = send_report("android", probes)
    expect(status == 400, "a boolean where an integer belongs must be a 400, got %s" % status)


@check
def unsupported_collector_version_is_a_400():
    for version in (-1, 0):
        status, payload = send_report("android", clean("android"), collector_version=version)
        expect(status == 400 and payload["error"]["code"] == "invalid_integrity_collector",
               "collector_version %s expected 400, got %s %s" % (version, status, payload))


@check
def native_measurement_unavailable_is_incomplete():
    probes = clean("android")
    probes["code_integrity"] = {"status": "ok", "checked": False, "reason": "native_unavailable"}
    status, payload = send_report("android", probes)
    expect(status == 200 and "integrity_probe_incomplete:code_integrity" in codes(payload)
           and payload["integrity"]["score"] >= 30,
           "checked=false must be incomplete evidence, got %s" % payload)


@check
def zero_coverage_is_incomplete_not_clean():
    """Joint review R3: checked=true with nothing compared scored 0/trusted."""
    probes = clean("android")
    probes["code_integrity"].update(core_compared_bytes=0, ext_compared_bytes=0, app_compared_bytes=0)
    status, payload = send_report("android", probes)
    expect(status == 200 and "integrity_probe_incomplete:code_integrity" in codes(payload)
           and payload["integrity"]["score"] >= 30,
           "android checked=true with zero coverage must be incomplete, got %s" % payload)
    for bucket in ("core", "ext", "app"):
        probes = clean("android")
        probes["code_integrity"]["%s_compared_bytes" % bucket] = 0
        status, payload = send_report("android", probes)
        expect("integrity_probe_incomplete:code_integrity" in codes(payload),
               "android %s bucket with zero coverage passed as clean" % bucket)
    saved = s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY
    try:
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = True
        probes = clean("ios")
        status, payload = send_report("ios", probes)
        expect(status == 200 and payload["integrity"]["score"] == 0,
               "control: iOS system buckets at 0 are the platform, not a failure: %s" % payload)
        probes = clean("ios")
        probes["code_integrity"]["app_compared_bytes"] = 0
        status, payload = send_report("ios", probes)
        expect("integrity_probe_incomplete:code_integrity" in codes(payload),
               "iOS app bucket with zero coverage passed as clean: %s" % payload)
    finally:
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = saved


@check
def explicit_probe_error_control():
    probes = clean("android")
    probes["runtime_maps"] = {"status": "error"}
    status, payload = send_report("android", probes)
    expect(status == 200 and payload["integrity"]["score"] == 30,
           "an explicit error must still score 30, got %s" % payload)


@check
def ios_code_integrity_is_required_when_scored():
    saved = s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY
    try:
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = True
        expect("code_integrity" in s._integrity_probe_plan("ios"),
               "iOS code_integrity scoring is on but the probe is not required")
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = False
        expect("code_integrity" not in s._integrity_probe_plan("ios"),
               "report-only iOS code_integrity must stay optional")
    finally:
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = saved


@check
def the_apps_own_recompiled_code_is_advisory_and_nothing_else_is():
    """DESIGN.md 75. Android recompiles an app after an install or update and
    replaces its oat files under the running process (the Huawei, 2026-10-13).
    The collector counts those deleted mappings apart and they are advisory;
    any other deleted executable mapping still costs 55, and so does an older
    collector's report, which cannot tell them apart."""
    def decision(**shape):
        probes = clean("android")
        probes["exec_mappings"].update(shape)
        status, payload = send_report("android", probes)
        expect(status == 200, "report failed: %s %s" % (status, payload))
        return payload["integrity"]

    own = decision(deleted_exec_mappings=0, deleted_exec_own_code=1)
    expect(own["score"] == 0 and points_of(own).get("android_app_code_recompiled") == 0,
           "the app's own recompiled code must be advisory, got %s" % own)
    both = decision(deleted_exec_mappings=1, deleted_exec_own_code=1)
    expect(both["score"] == 55 and points_of(both).get("android_deleted_code_mapping") == 55,
           "any other deleted executable mapping must still cost 55, got %s" % both)
    old = decision(deleted_exec_mappings=1)
    expect(old["score"] == 55, "an older collector's deleted mapping must still cost 55, got %s" % old)


@check
def inconsistent_wx_shape_earns_no_baseline_allowance():
    probes = clean("android")
    apk = probes["app_identity"]["apk_sha256"]
    saved = dict(s.ANDROID_WX_BASELINES)
    s.ANDROID_WX_BASELINES[apk] = (1048576, 65536)
    try:
        def score(shape):
            p = clean("android")
            p["exec_mappings"].update(shape)
            status, payload = send_report("android", p)
            expect(status == 200, "report failed: %s %s" % (status, payload))
            return payload["integrity"]["score"], codes(payload)
        honest = {"wx_mappings": 16, "wx_bytes": 1048576, "wx_size_classes": "65536:16",
                  "wx_smallest_bytes": 65536, "wx_largest_bytes": 65536}
        points, found = score(honest)
        expect(points == 0, "the measured .NET shape must score 0, got %s %s" % (points, found))
        # Joint review R8: fourteen classes, one of them a size the runtime never
        # allocates, listed in full (caught) and cut to the twelve largest with
        # the totals kept (used to pass as clean).
        big = dict(honest)
        sizes = [65536 * n for n in range(14, 2, -1)] + [98304, 65536]
        full = ",".join("%d:1" % size for size in sizes)
        big.update(wx_mappings=len(sizes), wx_bytes=sum(sizes), wx_size_classes=full,
                   wx_smallest_bytes=min(sizes), wx_largest_bytes=max(sizes))
        s.ANDROID_WX_BASELINES[apk] = (65536 * 128, 65536)
        points, found = score(big)
        expect("android_wx_foreign_allocator" in found,
               "control: the full list must expose the foreign size, got %s %s" % (points, found))
        big["wx_size_classes"] = ",".join(full.split(",")[:12])
        points, found = score(big)
        expect("android_wx_memory" in found and points >= 60,
               "a list cut to twelve classes earned the allowance (%s %s)" % (points, found))
        s.ANDROID_WX_BASELINES[apk] = (1048576, 65536)
        for lie in ({"wx_mappings": 40},                       # count disagrees with the classes
                    {"wx_bytes": 65536},                       # bytes disagree with the classes
                    {"wx_mappings": 0},                        # bytes without mappings
                    {"wx_largest_bytes": 4096},                # largest below a listed class
                    {"wx_size_classes": "65536:16,4096:0"}):   # an empty class
            shape = dict(honest)
            shape.update(lie)
            points, found = score(shape)
            expect("android_wx_memory" in found and points >= 60,
                   "inconsistent shape %s earned the allowance (%s %s)" % (lie, points, found))
    finally:
        s.ANDROID_WX_BASELINES.clear()
        s.ANDROID_WX_BASELINES.update(saved)


@check
def hardware_backing_required_needs_a_claim():
    saved = s.INTEGRITY_HARDWARE_BACKING_POLICY
    try:
        s.INTEGRITY_HARDWARE_BACKING_POLICY = "required"
        for stored, blocked in ((None, True), (False, True), (True, False)):
            db.hardware_backed = stored
            status, payload = send_report("android", clean("android"))
            got = payload["integrity"]["verdict"] == "block"
            expect(status == 200 and got is blocked,
                   "required mode, stored hardware_backed=%r: expected block=%s, got %s"
                   % (stored, blocked, payload["integrity"]))
        s.INTEGRITY_HARDWARE_BACKING_POLICY = "advisory"
        db.hardware_backed = None
        status, payload = send_report("android", clean("android"))
        expect(payload["integrity"]["score"] == 0,
               "advisory mode must not penalise an unreported claim, got %s" % payload)
        # DESIGN.md 79: the DBA's row decides; the environment only answers a
        # missing row.
        with policy(hardware_backing_policy="required"):
            status, payload = send_report("android", clean("android"))
        expect(payload["integrity"]["verdict"] == "block",
               "the DBA's required must apply over the environment's advisory: %s" % payload)
    finally:
        s.INTEGRITY_HARDWARE_BACKING_POLICY = saved
        db.hardware_backed = None


# ---------------------------------------------------------------------------
# F4 -- any changed byte in immutable code counts
# ---------------------------------------------------------------------------


@check
def one_changed_byte_is_detected():
    saved = s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY
    try:
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = True
        for platform in ("android", "ios"):
            scores = []
            for count in (0, 1, 2, 3, 4):
                probes = clean(platform)
                probes.setdefault("code_integrity", {"status": "ok", "checked": True,
                                                     "app_compared_bytes": 4096})
                probes["code_integrity"].update({"checked": True, "app_diff_bytes": count,
                                                 "app_compared_bytes": 4096})
                if "app_expected_bytes" in probes["code_integrity"]:  # contract-3 coverage
                    probes["code_integrity"]["app_expected_bytes"] = 4096
                status, payload = send_report(platform, probes)
                expect(status == 200, "%s report failed: %s %s" % (platform, status, payload))
                scores.append(payload["integrity"]["score"])
            expect(scores == [0, 90, 90, 90, 90],
                   "%s: app diffs 0..4 scored %s, expected [0, 90, 90, 90, 90]" % (platform, scores))
    finally:
        s.INTEGRITY_SCORE_IOS_CODE_INTEGRITY = saved


def coverage(probes, core=(614400, 0, 0), ext=(2097152, 0, 0), app=(4194304, 0, 0)):
    """Add native coverage: (compared, skipped, unreadable) per bucket."""
    ci = probes["code_integrity"]
    for bucket, (compared, skipped, unreadable) in (("core", core), ("ext", ext), ("app", app)):
        expected = compared + skipped + unreadable
        ci.update({"%s_compared_bytes" % bucket: compared,
                   "%s_expected_bytes" % bucket: expected,
                   "%s_skipped_bytes" % bucket: skipped,
                   "%s_unreadable_bytes" % bucket: unreadable,
                   "%s_complete" % bucket: expected > 0 and compared == expected})
    ci["protect_restore_failures"] = 0
    return probes


@check
def code_coverage_is_reported_and_checked():
    status, payload = send_report("android", coverage(clean("android")))
    expect(status == 200 and payload["integrity"]["score"] == 0 and not codes(payload),
           "complete coverage must score 0 with no reason, got %s" % payload)
    status, payload = send_report("android", coverage(clean("android"), core=(614400, 0, 65536)))
    partial = [r for r in payload["integrity"]["reasons"] if r["code"] == "android_code_integrity_partial"]
    expect(status == 200 and partial and partial[0].get("report_only")
           and payload["integrity"]["score"] == 0,
           "partial coverage must be visible and report-only, got %s" % payload)
    probes = coverage(clean("android"))
    probes["code_integrity"]["app_expected_bytes"] = 8388608   # does not add up
    status, payload = send_report("android", probes)
    expect(status == 200 and "integrity_evidence_invalid:code_integrity" in codes(payload),
           "coverage that does not add up must be invalid evidence, got %s" % payload)
    probes = coverage(clean("android"))
    probes["code_integrity"]["protect_restore_failures"] = 1
    status, payload = send_report("android", probes)
    expect("android_code_integrity_restore_failed" in codes(payload),
           "a failed protection restore must be reported, got %s" % codes(payload))


# ---------------------------------------------------------------------------
# F1 -- a step-up approval authorises exactly one request
# ---------------------------------------------------------------------------

_real_integrity_gate = s._enforce_integrity_gate
_real_risk_policy = s._evaluate_risk_policy


@contextmanager
def isolated_stepup():
    s._enforce_integrity_gate = lambda *a, **k: {"score": 0, "verdict": "trusted", "fresh": True}
    s._evaluate_risk_policy = lambda *a, **k: {"effective_action": "allow"}
    try:
        yield
    finally:
        s._enforce_integrity_gate = _real_integrity_gate
        s._evaluate_risk_policy = _real_risk_policy
        db.step_factor = "passcode"
        db.step_jwk = step.jwk


INTENDED = encode({"amount": 1, "payee": "intended-demo-payee"})
CHANGED = encode({"amount": 999, "payee": "different-demo-payee"})


def sensitive(body, headers):
    return client.post(SENSITIVE, data=body, headers=headers)


@check
def stepup_valid_request_and_replay_control():
    with isolated_stepup():
        nonce = fresh_nonce()
        head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
        head.update(stepup_headers("POST", SENSITIVE, INTENDED, nonce))
        reply = sensitive(INTENDED, head)
        expect(reply.status_code == 200 and reply.get_json()["step_up"] == "verified",
               "a correctly bound step-up must pass: %s %s" % (reply.status_code, reply.get_json()))
        replay = sensitive(INTENDED, head)
        expect(replay.status_code == 401 and error_code(replay) == "access_proof_replay",
               "exact replay must fail as a replay, got %s %s" % (replay.status_code, error_code(replay)))


@check
def stepup_cannot_be_retargeted():
    with isolated_stepup():
        nonce = fresh_nonce()
        approval = stepup_headers("POST", SENSITIVE, INTENDED, nonce)
        head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
        head.update(approval)
        reply = sensitive(CHANGED, head)
        expect(reply.status_code == 401 and error_code(reply) == "access_proof_body_mismatch",
               "control: a changed body under the old access proof, got %s" % error_code(reply))
        head = access_headers("POST", SENSITIVE, CHANGED, nonce=nonce)
        head.update(approval)
        reply = sensitive(CHANGED, head)
        expect(reply.status_code == 403 and error_code(reply) == "stepup_binding_mismatch",
               "a re-signed access proof must not carry the approval to another body: %s %s"
               % (reply.status_code, reply.get_json()))
        other_token = None
        with s.app.app_context():
            other_token = s.create_access_token(identity=str(uuid.uuid4()), additional_claims={
                "role": "account", "iid": inst.installation_id, "did": inst.device_id,
                "sid": str(uuid.uuid4()), "family": str(uuid.uuid4())})
        for label, overrides, bearer in (
                ("path", {"path": "/v1/account/protected-echo"}, None),
                ("method", {"method": "PUT"}, None),
                ("query", {"query": "to=someone-else"}, None),
                ("token", {}, other_token)):
            nonce = fresh_nonce()
            head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce, bearer=bearer)
            head.update(stepup_headers("POST", SENSITIVE, INTENDED, nonce, overrides=overrides))
            reply = sensitive(INTENDED, head)
            expect(reply.status_code == 403 and error_code(reply) == "stepup_binding_mismatch",
                   "an approval for another %s passed: %s %s" % (label, reply.status_code, error_code(reply)))


@check
def stepup_v1_proof_is_refused():
    with isolated_stepup():
        nonce = fresh_nonce()
        raw = c.b64u(encode({"version": 1, "installation_id": inst.installation_id,
                             "factor": "passcode", "nonce": nonce, "timestamp": int(time.time())}))
        head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
        head.update({"X-Step-Up-Proof": raw, "X-Step-Up-Signature": step.sign_b64(raw)})
        reply = sensitive(INTENDED, head)
        expect(reply.status_code == 403 and error_code(reply) == "stepup_proof_version_unsupported",
               "a v1 step-up proof must be refused, got %s %s" % (reply.status_code, error_code(reply)))
        nonce = fresh_nonce()
        head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
        head.update(stepup_headers("POST", SENSITIVE, INTENDED, nonce,
                                   overrides={"purpose": "stepup_reenrol"}))
        reply = sensitive(INTENDED, head)
        expect(reply.status_code == 403 and error_code(reply) == "stepup_proof_version_unsupported",
               "a proof for another purpose must be refused, got %s" % error_code(reply))


@check
def stepup_stored_factor_must_match_policy():
    with isolated_stepup():
        for stored in ("biometric", None):
            db.step_factor = stored
            nonce = fresh_nonce()
            head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
            head.update(stepup_headers("POST", SENSITIVE, INTENDED, nonce, factor="passcode"))
            reply = sensitive(INTENDED, head)
            expect(reply.status_code == 403 and error_code(reply) == "stepup_factor_mismatch",
                   "stored factor %r under a passcode policy passed: %s %s"
                   % (stored, reply.status_code, error_code(reply)))


@check
def stepup_key_must_differ_from_installation_key():
    with isolated_stepup():
        db.step_jwk = inst.jwk
        nonce = fresh_nonce()
        head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
        head.update(stepup_headers("POST", SENSITIVE, INTENDED, nonce, signer=inst))
        reply = sensitive(INTENDED, head)
        expect(reply.status_code == 403 and error_code(reply) == "stepup_key_not_independent",
               "the installation key passed as its own step-up key: %s %s"
               % (reply.status_code, error_code(reply)))
    db.reenrol_row = None
    same = {"installation_id": str(uuid.uuid4()), "platform": "android", "public_key": inst.jwk,
            "stepup_public_key": inst.jwk,
            "stepup_key_auth": {"factor": "passcode", "mode": "per_use", "window_seconds": 0}}
    reply = client.post("/v1/installations/register", json=same)
    expect(reply.status_code == 400 and error_code(reply) == "invalid_stepup_key",
           "registering the installation key as the step-up key must be a 400, got %s %s"
           % (reply.status_code, error_code(reply)))
    no_auth = dict(same, stepup_public_key=step.jwk)
    del no_auth["stepup_key_auth"]
    reply = client.post("/v1/installations/register", json=no_auth)
    expect(reply.status_code == 400 and error_code(reply) == "invalid_stepup_key_auth",
           "a step-up key without its auth block must be a 400, got %s %s"
           % (reply.status_code, error_code(reply)))


# ---------------------------------------------------------------------------
# Backlog -- the access proof binds the query string (v2)
# ---------------------------------------------------------------------------

ECHO = "/v1/account/protected-echo"


@check
def access_proof_binds_the_query_string():
    body = encode({"x": 1})
    with isolated_stepup():
        reply = client.post(ECHO, data=body, headers=access_headers("POST", ECHO, body))
        expect(reply.status_code == 200, "control: a v2 proof must pass, got %s %s"
               % (reply.status_code, reply.get_json()))
        reply = client.post(ECHO + "?to=someone-else", data=body,
                            headers=access_headers("POST", ECHO, body))
        expect(reply.status_code == 401 and error_code(reply) == "access_proof_query_mismatch",
               "a query string added after signing passed: %s %s"
               % (reply.status_code, error_code(reply)))
        reply = client.post(ECHO + "?to=me", data=body,
                            headers=access_headers("POST", ECHO, body, query="to=me"))
        expect(reply.status_code == 200, "a signed query must pass, got %s %s"
               % (reply.status_code, reply.get_json()))


@check
def access_proof_v1_only_by_setting_and_never_with_a_query():
    body = encode({"x": 1})
    saved = s.ACCESS_PROOF_MIN_VERSION
    try:
        with isolated_stepup():
            reply = client.post(ECHO, data=body, headers=access_headers("POST", ECHO, body, version=1))
            expect(reply.status_code == 400 and error_code(reply) == "unsupported_access_proof_version",
                   "by default a v1 proof must be refused, got %s %s"
                   % (reply.status_code, error_code(reply)))
            s.ACCESS_PROOF_MIN_VERSION = 1
            reply = client.post(ECHO, data=body, headers=access_headers("POST", ECHO, body, version=1))
            expect(reply.status_code == 200,
                   "with the transition setting a v1 proof without a query must pass, got %s"
                   % reply.status_code)
            reply = client.post(ECHO + "?to=x", data=body,
                                headers=access_headers("POST", ECHO, body, version=1))
            expect(reply.status_code == 401 and error_code(reply) == "access_proof_query_mismatch",
                   "a v1 proof must never cover a query string, got %s %s"
                   % (reply.status_code, error_code(reply)))
    finally:
        s.ACCESS_PROOF_MIN_VERSION = saved


# ---------------------------------------------------------------------------
# F11 -- an elevated integrity verdict can be satisfied, where that is possible
# ---------------------------------------------------------------------------


@contextmanager
def elevated_integrity():
    saved = (s._latest_integrity_state, s._device_integrity_memory, s._evaluate_risk_policy)
    s._latest_integrity_state = lambda iid: {"score": 30, "verdict": "elevated", "fresh": True}
    s._device_integrity_memory = lambda did, iid: None
    s._evaluate_risk_policy = lambda *a, **k: {"effective_action": "allow"}
    try:
        yield
    finally:
        s._latest_integrity_state, s._device_integrity_memory, s._evaluate_risk_policy = saved


@check
def elevated_integrity_is_satisfied_by_a_step_up_proof():
    body = encode({"x": 1})
    with elevated_integrity():
        reply = client.post(ECHO, data=body, headers=access_headers("POST", ECHO, body))
        expect(reply.status_code == 403 and error_code(reply) == "integrity_step_up_required",
               "elevated without step-up expected 403 integrity_step_up_required, got %s %s"
               % (reply.status_code, error_code(reply)))
        nonce = fresh_nonce()
        head = access_headers("POST", ECHO, body, nonce=nonce)
        head.update(stepup_headers("POST", ECHO, body, nonce))
        reply = client.post(ECHO, data=body, headers=head)
        integrity = (reply.get_json() or {}).get("integrity") or {}
        expect(reply.status_code == 200 and integrity.get("satisfied_by_step_up") is True,
               "a valid step-up proof must satisfy an elevated verdict, got %s %s"
               % (reply.status_code, reply.get_json()))
        nonce = fresh_nonce()
        head = access_headers("POST", ECHO, body, nonce=nonce)
        head.update(stepup_headers("POST", ECHO, body, nonce, signer=c.Installation()))
        reply = client.post(ECHO, data=body, headers=head)
        expect(reply.status_code == 403 and error_code(reply) == "stepup_signature_invalid",
               "an invalid offered step-up proof must refuse, not be ignored: %s %s"
               % (reply.status_code, error_code(reply)))
        # Where no step-up is accepted and the DBA has not made elevated a
        # limited-session outcome (DESIGN.md 70), the code must say so.
        with policy(limited_session_integrity_verdicts=""):
            login = encode({"handle": "someone", "password": "Passw0rd123"})
            reply = client.post("/v1/accounts/login", data=login,
                                headers=access_headers("POST", "/v1/accounts/login", login,
                                                       device_token))
            expect(reply.status_code == 403 and error_code(reply) == "integrity_elevated",
                   "where no step-up is accepted the code must say so, got %s %s"
                   % (reply.status_code, error_code(reply)))


# ---------------------------------------------------------------------------
# F7 -- unauthenticated re-registration cannot rewrite key-security metadata
# ---------------------------------------------------------------------------


@check
def reregistration_cannot_upgrade_key_security():
    db.reenrol_row = (inst.installation_id, inst.device_id, "new_device", "new", "ES256",
                      "software", False, "software-test", None, None, None, None)
    db.writes = []
    claim = {"installation_id": str(uuid.uuid4()), "platform": "android", "public_key": inst.jwk,
             "key_security": {"security_level": "strongbox", "hardware_backed": True,
                              "provider": "claim-without-signature"}}
    reply = client.post("/v1/installations/register", json=claim)
    block = (reply.get_json() or {}).get("key_security") or {}
    expect(reply.status_code == 200 and block.get("hardware_backed") is False
           and block.get("security_level") == "software",
           "an unsigned claim changed stored key security: %s %s" % (reply.status_code, block))
    touched = [q for q, _ in db.writes if "key_security_level" in q or "key_hardware_backed" in q]
    expect(not touched, "re-registration wrote key-security columns: %s" % touched)
    db.reenrol_row = None


# ---------------------------------------------------------------------------
# F8 -- transport: forwarded headers only from a configured proxy; body limit
# ---------------------------------------------------------------------------


@check
def forwarded_proto_is_ignored_without_a_trusted_proxy():
    registration = {"installation_id": str(uuid.uuid4()), "platform": "android",
                    "public_key": inst.jwk}
    saved = s.REQUIRE_HTTPS
    s.REQUIRE_HTTPS = True
    try:
        plain = client.post("/v1/installations/register", json=registration)
        forged = client.post("/v1/installations/register", json=registration,
                             headers={"X-Forwarded-Proto": "https"})
        expect(plain.status_code == 426 and forged.status_code == 426,
               "a client-supplied X-Forwarded-Proto passed the HTTPS guard: %s/%s"
               % (plain.status_code, forged.status_code))
        original = s.app.wsgi_app
        s.app.wsgi_app = ProxyFix(original, x_proto=1)
        try:
            db.reenrol_row = (inst.installation_id, inst.device_id, "new_device", "new", "ES256",
                              None, None, None, None, None, None, None)
            proxied = client.post("/v1/installations/register", json=registration,
                                  headers={"X-Forwarded-Proto": "https"})
            expect(proxied.status_code == 200,
                   "behind a configured proxy an https request must pass, got %s" % proxied.status_code)
        finally:
            s.app.wsgi_app = original
            db.reenrol_row = None
    finally:
        s.REQUIRE_HTTPS = saved


@check
def oversized_body_is_refused():
    limit = s.app.config.get("MAX_CONTENT_LENGTH")
    expect(isinstance(limit, int) and 0 < limit <= 1 << 20,
           "MAX_CONTENT_LENGTH must be set to a bounded size, got %r" % limit)
    reply = client.post("/v1/installations/register", data=b"{" + b" " * (limit + 1) + b"}",
                        headers={"Content-Type": "application/json"})
    expect(reply.status_code == 413, "an oversized body got %s, expected 413" % reply.status_code)


# ---------------------------------------------------------------------------
# F3 -- policy and readiness fail closed
# ---------------------------------------------------------------------------


@contextmanager
def real_policy_reader():
    s._risk_policy_settings = real_settings_reader
    s._risk_settings_cache.update(at=0.0, values=None, failed_at=None, error=None)
    try:
        yield
    finally:
        db.fail_settings = False
        db.settings = dict(SETTINGS)
        s._risk_settings_cache.update(at=0.0, values=None, failed_at=None, error=None)


@check
def cold_policy_failure_refuses_instead_of_dropping_stepup():
    with real_policy_reader(), isolated_stepup():
        db.fail_settings = True
        try:
            paths = s._stepup_required_paths()
        except s.ApiProblem as problem:
            expect(problem.status == 503 and problem.code == "risk_policy_unavailable",
                   "unexpected refusal %s %s" % (problem.status, problem.code))
        else:
            raise AssertionError("an unreadable policy produced step-up paths %s" % paths)
        body = encode({"amount": 1})
        reply = sensitive(body, access_headers("POST", SENSITIVE, body))
        expect(reply.status_code == 503 and error_code(reply) == "risk_policy_unavailable",
               "a sensitive request without step-up under an unreadable policy got %s %s"
               % (reply.status_code, reply.get_json()))


@check
def warm_policy_serves_stale_within_bound_only():
    with real_policy_reader(), isolated_stepup():
        expect(s._stepup_required_paths() == {SENSITIVE}, "policy did not load")
        db.fail_settings = True
        cache = s._risk_settings_cache
        cache["at"] = time.monotonic() - s.RISK_SETTINGS_CACHE_TTL_SECONDS - 1
        cache["failed_at"] = None
        expect(s._stepup_required_paths() == {SENSITIVE},
               "a transient failure inside the stale bound must keep the last valid policy")
        cache["at"] = time.monotonic() - s.RISK_SETTINGS_MAX_STALE_SECONDS - 1
        cache["failed_at"] = None
        try:
            s._stepup_required_paths()
        except s.ApiProblem as problem:
            expect(problem.status == 503, "expected 503 past the stale bound, got %s" % problem.status)
        else:
            raise AssertionError("a policy older than the stale bound was still served")


@check
def invalid_or_missing_policy_rows_are_refused():
    for broken in ({"stepup_factor": "fingerprint"}, {"device_accounts_block_count": "four"},
                   {"stepup_required_paths": "v1/no-leading-slash"}, {"stepup_required_paths": None}):
        with real_policy_reader():
            for key, value in broken.items():
                if value is None:
                    db.settings.pop(key, None)
                else:
                    db.settings[key] = value
            try:
                s._risk_policy_settings()
            except s.ApiProblem as problem:
                expect(problem.code == "risk_policy_unavailable", "unexpected %s" % problem.code)
            else:
                raise AssertionError("an invalid snapshot %s was accepted" % broken)
    with real_policy_reader():
        db.settings["stepup_required_paths"] = ""
        expect(s._stepup_required_paths() == set(),
               "an explicitly empty sensitive set is a valid configuration")


@check
def readiness_reports_not_ready():
    saved = s._get_schema_state
    try:
        s._get_schema_state = lambda: {"ok": False, "found": 6, "required": 7}
        reply = client.get("/health/ready")
        payload = reply.get_json()
        expect(reply.status_code == 503 and payload["status"] == "not_ready"
               and "schema_version_mismatch" in payload["problems"],
               "an incompatible schema answered %s %s" % (reply.status_code, payload.get("status")))
    finally:
        s._get_schema_state = saved
    with real_policy_reader():
        db.fail_settings = True
        reply = client.get("/health/ready")
        expect(reply.status_code == 503
               and "risk_policy_unavailable" in reply.get_json()["problems"],
               "an unloadable policy answered %s" % reply.status_code)
    reply = client.get("/health/ready")
    expect(reply.status_code == 200 and reply.get_json()["status"] == "ready",
           "a healthy worker must answer 200 ready, got %s %s" % (reply.status_code, reply.get_json()))
    live = client.get("/health/live")
    expect(live.status_code == 200, "liveness must stay independent of readiness")


# ---------------------------------------------------------------------------
# F9 -- admission: budgets, a challenge flood cannot lock a client out
# ---------------------------------------------------------------------------


class FakeRedis(object):
    def __init__(self):
        self.counts = {}

    def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    def expire(self, key, seconds):
        return True


@check
def challenge_flood_cannot_cancel_a_pending_challenge():
    """Joint review R5: five public challenge requests used to drop the owner's
    pending challenge. Challenges are now stateless until consumed."""
    db.writes = []
    route = "/v1/installations/challenge"
    owner = client.post(route, json={"installation_id": inst.installation_id}).get_json()
    for _ in range(12):
        reply = client.post(route, json={"installation_id": inst.installation_id})
        expect(reply.status_code == 200, "a challenge request was refused: %s" % reply.status_code)
    expect(not [q for q, _ in db.writes if "installation_challenges" in q],
           "issuing a challenge must store nothing, writes were %s" % db.writes)
    proof = {"installation_id": inst.installation_id, "challenge_id": owner["challenge_id"],
             "payload": owner["payload"], "signature": inst.sign_b64(owner["payload"])}
    reply = client.post("/v1/installations/verify", json=proof)
    expect(reply.status_code == 200 and "device_token" in (reply.get_json() or {}),
           "the owner's challenge must survive a flood: %s %s" % (reply.status_code, reply.get_json()))
    replay = client.post("/v1/installations/verify", json=proof)
    expect(replay.status_code == 401 and error_code(replay) == "challenge_used",
           "a consumed challenge must not verify twice: %s %s" % (replay.status_code, error_code(replay)))


@check
def challenges_are_bound_by_the_server_mac():
    route = "/v1/installations/challenge"
    issued = client.post(route, json={"installation_id": inst.installation_id}).get_json()
    payload = json.loads(c.b64u_decode(issued["payload"]))

    def verify(fields, challenge_id=None):
        raw = c.b64u(encode(fields))
        return client.post("/v1/installations/verify", json={
            "installation_id": inst.installation_id,
            "challenge_id": challenge_id or fields.get("challenge_id"),
            "payload": raw, "signature": inst.sign_b64(raw)})

    for label, change in (("nonce", {"nonce": c.b64u(os.urandom(32))}),
                          ("expiry", {"expires_at": "2099-01-01T00:00:00Z"}),
                          ("purpose", {"purpose": "refresh:someone-else"})):
        reply = verify(dict(payload, **change))
        expect(reply.status_code == 401 and error_code(reply) == "challenge_payload_mismatch",
               "a payload with a changed %s verified: %s %s" % (label, reply.status_code, error_code(reply)))
    forged = dict(payload, challenge_id=str(uuid.uuid4()), mac="A" * 43)
    reply = verify(forged)
    expect(reply.status_code == 401 and error_code(reply) == "challenge_payload_mismatch",
           "a challenge the server never issued verified: %s" % error_code(reply))
    saved = s.CHALLENGE_LIFETIME
    try:
        s.CHALLENGE_LIFETIME = s.timedelta(seconds=-1)
        stale = client.post(route, json={"installation_id": inst.installation_id}).get_json()
    finally:
        s.CHALLENGE_LIFETIME = saved
    reply = verify(json.loads(c.b64u_decode(stale["payload"])))
    expect(reply.status_code == 401 and error_code(reply) == "challenge_expired",
           "an expired challenge verified: %s %s" % (reply.status_code, error_code(reply)))


@check
def a_keyless_reuse_cannot_revoke_the_family():
    """Joint review R7: the challenge step revoked a refresh family on an old
    rotated token alone. It now issues a challenge and changes nothing."""
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    with s.app.app_context():
        old = s.create_refresh_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": session, "family": family})
    db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                      s._utc_now() + s.REFRESH_TOKEN_LIFETIME, s._utc_now(), "full", None, None, None)
    db.writes = []
    try:
        reply = client.post("/v1/auth/refresh/challenge", headers={"Authorization": "Bearer " + old})
        expect(reply.status_code == 200 and "payload" in (reply.get_json() or {}),
               "the challenge step must only issue a challenge: %s %s"
               % (reply.status_code, reply.get_json()))
        revoked = [q for q, _ in db.writes if q.startswith("UPDATE refresh_sessions")]
        expect(not revoked, "the challenge step revoked a family without key proof: %s" % revoked)
    finally:
        db.refresh_row = None


@check
def login_attempts_are_budgeted_per_handle_and_source():
    saved = (s.RATE_LIMIT_ENABLED, s.REDIS_URL, s._REDIS_CLIENT, s._enforce_integrity_gate)
    fake = FakeRedis()
    s.RATE_LIMIT_ENABLED, s.REDIS_URL, s._REDIS_CLIENT = True, "redis://fixture", fake

    def stop(*a, **k):
        raise s.ApiProblem("stop", 418, "fixture_stop")
    s._enforce_integrity_gate = stop
    login = encode({"handle": "victim-handle", "password": "Passw0rd123"})
    path = "/v1/accounts/login"
    try:
        reply = client.post(path, data=login, headers=access_headers("POST", path, login, device_token))
        expect(reply.status_code == 418, "setup: expected the fixture stop, got %s" % reply.status_code)
        handle_key = "dt:rate:accounts_login_handle:%s" % s._handle_lookup("victim-handle")
        expect(handle_key in fake.counts and any(k.startswith("dt:rate:accounts_login_source:")
                                                 for k in fake.counts),
               "login must consult per-handle and per-source budgets, keys were %s" % sorted(fake.counts))
        fake.counts[handle_key] = s.RATE_LIMIT_MAX_ATTEMPTS
        reply = client.post(path, data=login, headers=access_headers("POST", path, login, device_token))
        expect(reply.status_code == 429 and error_code(reply) == "rate_limited",
               "an exhausted handle budget must refuse, got %s %s" % (reply.status_code, error_code(reply)))
    finally:
        s.RATE_LIMIT_ENABLED, s.REDIS_URL, s._REDIS_CLIENT, s._enforce_integrity_gate = saved


@check
def housekeeping_runs_at_most_once_per_interval():
    name = "fixture-%s" % uuid.uuid4()
    expect(s._maintenance_due(name) is True and s._maintenance_due(name) is False,
           "a cleanup must not run on every request")


# ---------------------------------------------------------------------------
# F10 -- a lost first-link race must not abort the caller's transaction
# ---------------------------------------------------------------------------


@check
def link_race_rolls_back_to_a_savepoint():
    class RaceCursor(object):
        def __init__(self):
            self.statements = []
            self.rowcount = 0

        def execute(self, sql, params=None):
            q = " ".join(sql.split())
            self.statements.append(q)
            self.rowcount = 0
            if q.startswith("INSERT INTO device_account_links"):
                raise s.DIALECT._driver.errors.UniqueViolation("concurrent first link")

    race = RaceCursor()
    s._link_device_account(race, inst.device_id, account, inst.installation_id)
    kinds = [q.split(" ")[0] + (" TO" if q.startswith("ROLLBACK TO") else "") for q in race.statements]
    expect("SAVEPOINT" in kinds and "ROLLBACK TO" in kinds,
           "a lost INSERT race must roll back to a savepoint, statements were %s" % race.statements)
    expect(kinds.index("SAVEPOINT") < kinds.index("INSERT") < kinds.index("ROLLBACK TO"),
           "savepoint ordering wrong: %s" % kinds)


# ---------------------------------------------------------------------------
# R1 (joint review 2026-10-05) -- runtime growth, developer settings, eligibility
# ---------------------------------------------------------------------------


@contextmanager
def policy(**values):
    """Run with these risk_policy_settings rows and a cold settings cache."""
    with real_policy_reader():
        db.settings.update({key: str(value) for key, value in values.items()})
        s._risk_settings_cache.update(at=0.0, values=None, failed_at=None, error=None)
        yield


R1_ENVELOPE = (3735552, 65536)  # a .NET build's pinned shape (57 granules)
R1_CASES = (
    # the five cases put to the owner, with the score each must now get
    ("A genuine warm .NET session, 4,194,304 bytes", "196608:5,131072:4,65536:41", None, 0),
    ("B gadget shape, 4 KiB and 28 KiB pieces", "196608:1,131072:7,65536:45,28672:1,4096:1",
     None, 45),
    ("C runtime-shaped copycat, 3,932,160 bytes", "65536:60", None, 0),
    ("D runtime-shaped copycat, 9,437,184 bytes", "65536:144", None, 40),
    ("E inline hook in libc", "65536:57",
     lambda p: p["code_integrity"].update(diff_bytes=71, core_diff_bytes=71), 90),
)


def r1_decision(classes, developer=False, extra=None):
    probes = clean("android")
    apk = probes["app_identity"]["apk_sha256"]
    pairs = [tuple(int(part) for part in item.split(":")) for item in classes.split(",")]
    probes["exec_mappings"].update(
        wx_mappings=sum(n for _, n in pairs), wx_bytes=sum(size * n for size, n in pairs),
        wx_size_classes=classes, wx_smallest_bytes=min(size for size, _ in pairs),
        wx_largest_bytes=max(size for size, _ in pairs))
    probes["developer_settings"].update(developer_options_enabled=developer,
                                        adb_enabled=developer)
    if extra:
        extra(probes)
    saved = dict(s.ANDROID_WX_BASELINES)
    s.ANDROID_WX_BASELINES[apk] = R1_ENVELOPE
    try:
        status, payload = send_report("android", probes)
    finally:
        s.ANDROID_WX_BASELINES.clear()
        s.ANDROID_WX_BASELINES.update(saved)
    expect(status == 200, "report failed: %s %s" % (status, payload))
    return payload["integrity"]


def points_of(decision):
    return {reason["code"]: reason["points"] for reason in decision["reasons"]}


@check
def runtime_growth_is_advisory_up_to_the_allowance():
    """The owner-approved R1 table (DESIGN.md 69), at the default 200 %: growth
    inside twice the envelope scores nothing but stays visible; the copycat
    beyond it keeps +40; shape and code checks are unchanged; developer options
    and ADB add nothing to any case."""
    with policy():
        for name, classes, extra, expected in R1_CASES:
            for developer in (False, True):
                decision = r1_decision(classes, developer, extra)
                expect(decision["score"] == expected,
                       "%s, developer settings %s: expected %d, got %d %s"
                       % (name, "on" if developer else "off", expected,
                          decision["score"], points_of(decision)))
        found = points_of(r1_decision(R1_CASES[0][1], developer=True))
        expect(found.get("android_wx_above_baseline") == 0,
               "growth inside the allowance must stay visible at 0 points: %s" % found)
        expect(found.get("android_developer_options") == 0 and found.get("android_adb_enabled") == 0,
               "developer options and ADB must be advisory: %s" % found)


@check
def the_growth_allowance_follows_the_dba_setting():
    granules = R1_ENVELOPE[0] // R1_ENVELOPE[1]
    with policy(wx_far_above_baseline_percent=300):
        decision = r1_decision(R1_CASES[3][1])
        expect(decision["score"] == 0, "at 300 %% the 253 %% copycat must be advisory, got %s %s"
               % (decision["score"], points_of(decision)))
    with policy(wx_far_above_baseline_percent=100):
        decision = r1_decision(R1_CASES[0][1])
        expect(decision["score"] == 40, "at 100 %% any growth must score +40, got %s %s"
               % (decision["score"], points_of(decision)))
    with policy():
        at = r1_decision("65536:%d" % (2 * granules))
        over = r1_decision("65536:%d" % (2 * granules + 1))
        expect(at["score"] == 0 and over["score"] == 40,
               "exactly 200 %% is within the allowance and one granule more is not: %s / %s"
               % (at["score"], over["score"]))
    for value, valid in (("100", True), ("250", True), ("99", False), ("two", False), ("", False)):
        try:
            s._validate_risk_settings(dict(SETTINGS, wx_far_above_baseline_percent=value))
            accepted = True
        except ValueError:
            accepted = False
        expect(accepted == valid, "wx_far_above_baseline_percent=%r: accepted=%s" % (value, accepted))


@check
def eligibility_rules_refuse_with_their_own_code_only_when_set():
    """Developer options and ADB never cost points; a deployment that wants them
    off sets an eligibility rule, refused in enforce mode with
    integrity_device_ineligible and a remedy, and shown in observe mode."""
    def state_with(*found):
        return lambda iid: {"score": 0, "verdict": "trusted", "fresh": True,
                            "reasons": [{"code": code, "points": 0} for code in found]}

    def gate():
        try:
            return s._enforce_integrity_gate(inst.device_id, inst.installation_id), None
        except s.ApiProblem as problem:
            return None, problem

    expect("developer_settings" in s._integrity_probe_plan("android"),
           "developer settings must be measured on every Android scan")
    saved = (s._latest_integrity_state, s._device_integrity_memory, s.INTEGRITY_MODE)
    s._device_integrity_memory = lambda did, iid: None
    both = ("android_developer_options", "android_adb_enabled")
    try:
        s._latest_integrity_state = state_with(*both)
        with policy():
            state, problem = gate()
            expect(problem is None and "eligibility" not in state,
                   "no rule set, but refused or flagged: %s %s" % (problem and problem.code, state))
        for rule, expected in (("developer_options_refuses", "android_developer_options"),
                               ("adb_enabled_refuses", "android_adb_enabled")):
            with policy(**{rule: 1}):
                state, problem = gate()
                expect(problem is not None and problem.code == "integrity_device_ineligible"
                       and [e["reason"] for e in problem.details["eligibility"]] == [expected]
                       and problem.details["eligibility"][0]["remedy"],
                       "%s=1 must refuse with its own code and remedy, got %s"
                       % (rule, problem and (problem.code, problem.details.get("eligibility"))))
                s.INTEGRITY_MODE = "observe"
                state, problem = gate()
                s.INTEGRITY_MODE = "enforce"
                expect(problem is None and [e["rule"] for e in state.get("eligibility", [])] == [rule],
                       "observe mode must report, not refuse: %s %s" % (problem, state))
        with policy(developer_options_refuses=1, adb_enabled_refuses=1):
            s._latest_integrity_state = state_with()
            state, problem = gate()
            expect(problem is None, "both settings off on the phone must pass, got %s"
                   % (problem and problem.code))
    finally:
        s._latest_integrity_state, s._device_integrity_memory, s.INTEGRITY_MODE = saved


# ---------------------------------------------------------------------------
# R4 (joint review 2026-10-05) -- an integrity block spreads one way only
# ---------------------------------------------------------------------------

LITE_SCHEMA = """
CREATE TABLE app_installations (
    installation_id     TEXT PRIMARY KEY,
    device_id           TEXT NOT NULL,
    registration_method TEXT NOT NULL,
    created_at          TSZ NOT NULL,
    device_confirmed_at TSZ
);
CREATE TABLE integrity_reports (
    report_id        TEXT PRIMARY KEY,
    installation_id  TEXT NOT NULL REFERENCES app_installations(installation_id),
    device_id        TEXT NOT NULL,
    score            INTEGER NOT NULL,
    verdict          TEXT NOT NULL,
    hard_block       BOOLEAN NOT NULL,
    created_at       TSZ NOT NULL,
    evidence_quality TEXT,
    finding_score    INTEGER
);
CREATE TABLE device_account_links (
    device_id             TEXT NOT NULL,
    account_id            TEXT NOT NULL,
    first_installation_id TEXT NOT NULL REFERENCES app_installations(installation_id),
    PRIMARY KEY (device_id, account_id)
);
"""

# The device memory before R4, verbatim but for placeholders: the worst report
# of every installation on the device. The one-directional rule must never be
# stricter than this, for any installation.
DEVICE_WIDE_MEMORY_SQL = """
    SELECT report_id, installation_id, score, verdict, hard_block, created_at
    FROM integrity_reports
    WHERE device_id = ? AND created_at >= ?
    ORDER BY hard_block DESC, score DESC, created_at DESC
    LIMIT 1
"""

sqlite3.register_adapter(
    datetime, lambda d: d.astimezone(timezone.utc).isoformat(timespec="microseconds"))
sqlite3.register_converter("TSZ", lambda raw: datetime.fromisoformat(raw.decode()))


class LiteCursor(object):
    """The server's own SQL on SQLite: only placeholders and NOW() adapted."""

    def __init__(self, connection):
        self.cursor = connection.cursor()
        self.rowcount = 0

    def execute(self, sql, params=()):
        # SQLite has one writer at a time and no row locks to request.
        sql = sql.replace(" FOR UPDATE", "")
        self.cursor.execute(sql.replace("%s", "?").replace("NOW()", "CURRENT_TIMESTAMP"),
                            tuple(params or ()))
        self.rowcount = self.cursor.rowcount

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


@contextmanager
def lite_store():
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(LITE_SCHEMA)

    @contextmanager
    def lite_cursor(commit=False):
        yield LiteCursor(connection)
        connection.commit()

    saved = (s._cursor, s._latest_integrity_state)
    # The settings snapshot comes from the fixture, not from SQLite.
    s._risk_settings_cache.update(values=dict(db.settings), at=time.monotonic(),
                                  failed_at=None, error=None)
    s._cursor = lite_cursor
    # Each installation's own latest scan is clean and fresh, so the gate
    # reaches the device memory -- the only thing these checks vary.
    s._latest_integrity_state = lambda iid: {"score": 0, "verdict": "trusted", "fresh": True}
    try:
        yield connection
    finally:
        s._cursor, s._latest_integrity_state = saved
        connection.close()


def lite_installation(connection, device_id, method, confirmed=False):
    installation_id = str(uuid.uuid4())
    now = s._utc_now()
    connection.execute("INSERT INTO app_installations VALUES (?, ?, ?, ?, ?)",
                       (installation_id, device_id, method, now, now if confirmed else None))
    return installation_id


def lite_report(connection, installation_id, device_id, score, hard_block=False, age_hours=0.0,
                finding_score=None):
    """finding_score None: a report stored before migration 015."""
    connection.execute(
        "INSERT INTO integrity_reports (report_id, installation_id, device_id, score, verdict, "
        "hard_block, created_at, finding_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), installation_id, device_id, score,
         s._integrity_verdict(score, hard_block), hard_block,
         s._utc_now() - timedelta(hours=age_hours), finding_score))


def memory_outcome(device_id, installation_id):
    """(the gate refuses on device memory, the policy adds +50, the report used)
    under the server's current rule. The refusal is the real gate's; +50 mirrors
    _evaluate_risk_policy's condition, a block from another installation."""
    try:
        s._enforce_integrity_gate(device_id, installation_id)
        refused = False
    except s.ApiProblem as problem:
        expect(problem.code == "integrity_device_blocked_recently",
               "unexpected gate refusal %s" % problem.code)
        refused = True
    memory = s._device_integrity_memory(device_id, installation_id)
    blocked = memory is not None and memory["finding_verdict"] == "block"
    expect(blocked == refused, "gate and memory disagree: %s %s" % (refused, memory))
    plus50 = blocked and memory["installation_id"] != installation_id
    return refused, plus50, memory and memory["report_id"]


def device_wide_outcome(connection, device_id, installation_id):
    cutoff = s._utc_now() - timedelta(hours=s.INTEGRITY_DEVICE_MEMORY_HOURS)
    row = connection.execute(DEVICE_WIDE_MEMORY_SQL, (device_id, cutoff)).fetchone()
    blocked = row is not None and (bool(row[4]) or row[3] == "block")
    return blocked, blocked and row[1] != installation_id, row and row[0]


@check
def an_unconfirmed_reinstall_cannot_spread_its_block():
    with lite_store() as db_:
        device = str(uuid.uuid4())
        owner = lite_installation(db_, device, "new_device")
        lite_report(db_, owner, device, 18)
        intruder = lite_installation(db_, device, "reinstall_hint")
        lite_report(db_, intruder, device, 100, hard_block=True)
        refused, plus50, _ = memory_outcome(device, owner)
        expect(not refused and not plus50,
               "a block from an unconfirmed hint-linked installation reached the "
               "device's original installation: refused=%s +50=%s" % (refused, plus50))
        refused, plus50, _ = memory_outcome(device, intruder)
        expect(refused and not plus50,
               "an installation's own block must still refuse it, without +50: %s %s"
               % (refused, plus50))


@check
def an_established_block_still_follows_the_device():
    with lite_store() as db_:
        device = str(uuid.uuid4())
        owner = lite_installation(db_, device, "new_device")
        lite_report(db_, owner, device, 95)
        reinstall = lite_installation(db_, device, "reinstall_hint")
        lite_report(db_, reinstall, device, 0)
        refused, plus50, _ = memory_outcome(device, reinstall)
        expect(refused and plus50,
               "the original installation's block must reach a reinstall: %s %s"
               % (refused, plus50))
        other = str(uuid.uuid4())
        first = lite_installation(db_, other, "new_device")
        confirmed = lite_installation(db_, other, "reinstall_hint", confirmed=True)
        lite_report(db_, confirmed, other, 90)
        refused, plus50, _ = memory_outcome(other, first)
        expect(refused and plus50,
               "a confirmed reinstall's block must reach the rest of the device: %s %s"
               % (refused, plus50))


@check
def reports_outside_the_memory_window_never_count():
    with lite_store() as db_:
        device = str(uuid.uuid4())
        owner = lite_installation(db_, device, "new_device")
        lite_report(db_, owner, device, 100, hard_block=True,
                    age_hours=s.INTEGRITY_DEVICE_MEMORY_HOURS + 0.5)
        reinstall = lite_installation(db_, device, "reinstall_hint")
        for installation in (owner, reinstall):
            refused, plus50, _ = memory_outcome(device, installation)
            old_refused, old_plus50, _ = device_wide_outcome(db_, device, installation)
            expect(not (refused or plus50 or old_refused or old_plus50),
                   "a block older than %d h must not count under either rule"
                   % s.INTEGRITY_DEVICE_MEMORY_HOURS)


@check
def only_an_account_from_an_established_installation_confirms_a_reinstall():
    def link(db_, device, account_id, first):
        db_.execute("INSERT INTO device_account_links VALUES (?, ?, ?)", (device, account_id, first))

    def login(db_, device, account_id, installation):
        s._confirm_hint_installation(LiteCursor(db_), device, account_id, installation)
        db_.commit()
        return db_.execute("SELECT device_confirmed_at FROM app_installations "
                           "WHERE installation_id = ?", (installation,)).fetchone()[0] is not None

    with lite_store() as db_:
        device, elsewhere = str(uuid.uuid4()), str(uuid.uuid4())
        owner = lite_installation(db_, device, "new_device")
        b, c, d, e = (lite_installation(db_, device, "reinstall_hint") for _ in range(4))
        other_owner = lite_installation(db_, elsewhere, "new_device")
        returning, own_made, foreign = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        link(db_, device, returning, owner)
        link(db_, device, own_made, c)
        link(db_, elsewhere, foreign, other_owner)
        expect(not login(db_, device, str(uuid.uuid4()), b),
               "a first login on the installation itself must not confirm it")
        expect(not login(db_, device, own_made, c),
               "an account first linked through the installation itself must not confirm it")
        expect(not login(db_, device, own_made, d),
               "an account first linked through an unconfirmed reinstall must not confirm another")
        expect(not login(db_, device, foreign, e),
               "an account linked only to another device must not confirm this one")
        expect(login(db_, device, returning, b),
               "an account first linked through the original installation must confirm a reinstall")
        expect(not login(db_, device, returning, owner),
               "the original installation is established already and must not be rewritten")
        chained = str(uuid.uuid4())
        link(db_, device, chained, b)
        expect(login(db_, device, chained, e),
               "an account first linked through a confirmed reinstall must confirm the next one")


@check
def one_directional_memory_is_never_stricter_than_device_wide():
    """For every installation of 500 random device histories: the new rule
    refuses, or adds +50, only where the device-wide rule already did; and on a
    device whose installations are all established -- every row existing when
    migration 009 ran -- it picks the very same report."""
    rng = random.Random(20261007)
    window = s.INTEGRITY_DEVICE_MEMORY_HOURS
    lifted = identical = 0
    with lite_store() as db_:
        for _ in range(500):
            device = str(uuid.uuid4())
            all_established = rng.random() < 0.3
            installations = [lite_installation(db_, device, "new_device")]
            for _ in range(rng.randint(0, 4)):
                installations.append(lite_installation(
                    db_, device, "reinstall_hint",
                    confirmed=all_established or rng.random() < 0.4))
            ages = rng.sample(range(0, int((window + 6) * 3600)), 15)
            for installation in installations:
                for _ in range(rng.randint(0, 3)):
                    hard = rng.random() < 0.1
                    lite_report(db_, installation, device,
                                100 if hard else rng.choice([0, 8, 18, 30, 45, 60, 75, 90, 100]),
                                hard_block=hard, age_hours=ages.pop() / 3600.0)
            for installation in installations:
                new = memory_outcome(device, installation)
                old = device_wide_outcome(db_, device, installation)
                expect(not (new[0] and not old[0]) and not (new[1] and not old[1]),
                       "stricter than device-wide for %s on %s: new=%s old=%s"
                       % (installation, device, new, old))
                if all_established:
                    expect(new == old, "an all-established device must behave exactly as "
                           "before: new=%s old=%s" % (new, old))
                    identical += 1
                lifted += (old[0] and not new[0]) or (old[1] and not new[1])
    expect(identical > 0 and lifted > 0,
           "the sample exercised neither case: identical=%d lifted=%d" % (identical, lifted))


# ---------------------------------------------------------------------------
# Limited sessions (DESIGN.md 67, 70)
# ---------------------------------------------------------------------------


def _verdict_state(verdict, *codes):
    score = {"trusted": 0, "elevated": 30, "review": 60, "block": 95}[verdict]
    return lambda iid: {"score": score, "verdict": verdict, "fresh": True,
                        "reasons": [{"code": code, "points": 0} for code in codes]}


def _refused(call):
    try:
        call()
    except s.ApiProblem as problem:
        return problem.code
    return None


@check
def soft_outcomes_defer_only_where_the_dba_lists_them():
    """Only the DBA-listed soft outcomes defer to a limited session; block, an
    unlisted review, eligibility and device memory still refuse in the gate,
    before any password is compared."""
    did, iid = inst.device_id, inst.installation_id
    gate = lambda limited_ok=True: s._enforce_integrity_gate(did, iid, limited_ok=limited_ok)
    saved = (s._latest_integrity_state, s._device_integrity_memory)
    s._device_integrity_memory = lambda d, i: None
    try:
        with policy():
            s._latest_integrity_state = _verdict_state("elevated")
            expect(gate().get("limited_cause") == "integrity_elevated",
                   "an elevated verdict must defer to a limited session by default")
            expect(_refused(lambda: gate(limited_ok=False)) == "integrity_elevated",
                   "without limited_ok an elevated verdict must still refuse")
            for verdict, code in (("review", "integrity_review_required"),
                                  ("block", "integrity_blocked")):
                s._latest_integrity_state = _verdict_state(verdict)
                expect(_refused(gate) == code, "%s must refuse with %s by default" % (verdict, code))
            s._latest_integrity_state = _verdict_state("elevated")
            s._device_integrity_memory = lambda d, i: {"verdict": "block", "hard_block": True,
                                                      "finding_verdict": "block",
                                                      "installation_id": str(uuid.uuid4())}
            expect(_refused(gate) == "integrity_device_blocked_recently",
                   "a device-memory block must refuse even when the verdict is soft")
            s._device_integrity_memory = lambda d, i: None
        with policy(developer_options_refuses=1):
            s._latest_integrity_state = _verdict_state("elevated", "android_developer_options")
            expect(_refused(gate) == "integrity_device_ineligible",
                   "an eligibility rule must refuse even when the verdict is soft")
        with policy(limited_session_integrity_verdicts="elevated,review"):
            s._latest_integrity_state = _verdict_state("review")
            expect(gate().get("limited_cause") == "integrity_review",
                   "a DBA-listed review must defer")
        with policy(limited_session_integrity_verdicts=""):
            s._latest_integrity_state = _verdict_state("elevated")
            expect(_refused(gate) == "integrity_elevated", "an empty list must restore the refusal")
        risk = lambda action, limited_ok=True: s._enforce_risk_policy(
            {"effective_action": action}, limited_ok=limited_ok)
        with policy():
            expect(risk("review") == "risk_review", "a relationship review must defer by default")
            expect(_refused(lambda: risk("block")) == "risk_policy_blocked", "a block must refuse")
            expect(risk("step_up") is None, "step_up refuses only with elevated_risk_refuses=1")
            expect(_refused(lambda: risk("review", limited_ok=False)) == "risk_review_required",
                   "without limited_ok a review must still refuse")
        with policy(elevated_risk_refuses=1):
            expect(risk("step_up") == "risk_step_up", "a refusing step_up must defer when listed")
        with policy(limited_session_policy_actions=""):
            expect(_refused(lambda: risk("review")) == "risk_review_required",
                   "an empty list must restore the refusal")
    finally:
        s._latest_integrity_state, s._device_integrity_memory = saved


@check
def a_soft_login_is_deferred_past_the_gate_and_a_hard_one_is_not():
    login = encode({"handle": "someone", "password": "Passw0rd123"})

    def attempt():
        return client.post("/v1/accounts/login", data=login,
                           headers=access_headers("POST", "/v1/accounts/login", login, device_token))
    with elevated_integrity(), policy():
        reply = attempt()
        expect(reply.status_code == 401 and error_code(reply) == "invalid_credentials",
               "a soft verdict must reach the password check, got %s %s"
               % (reply.status_code, error_code(reply)))
        s._latest_integrity_state = _verdict_state("block")
        reply = attempt()
        expect(reply.status_code == 403 and error_code(reply) == "integrity_blocked",
               "a block must refuse before the password check, got %s %s"
               % (reply.status_code, error_code(reply)))


@check
def a_limited_session_is_written_into_both_tokens_and_its_row():
    from flask_jwt_extended import decode_token
    db.writes = []
    with s.app.app_context():
        tokens = s._issue_account_tokens(db, account, inst.device_id, inst.installation_id,
                                         limited_causes=["risk_review", "integrity_elevated"])
        access, refresh = decode_token(tokens["access_token"]), decode_token(tokens["refresh_token"])
        full = s._issue_account_tokens(db, account, inst.device_id, inst.installation_id)
        full_access = decode_token(full["access_token"])
    expect(tokens["scope"] == "limited" and access.get("scope") == "limited"
           and refresh.get("scope") == "limited"
           and access.get("limited") == ["integrity_elevated", "risk_review"]
           and tokens.get("limited_causes") == ["integrity_elevated", "risk_review"]
           and tokens.get("upgrade_routes") == [],
           "a limited session must say so in both tokens and the response: %s %s" % (tokens, access))
    rows = [params for q, params in db.writes if q.startswith("INSERT INTO refresh_sessions")]
    expect(rows[0][6:8] == ("limited", "integrity_elevated,risk_review") and rows[1][6:8] == ("full", None),
           "the refresh session row must carry the scope and causes: %s" % rows)
    expect(full["scope"] == "full" and full_access.get("scope") == "full"
           and "limited_causes" not in full and "limited" not in full_access,
           "a full session must not carry limited claims: %s" % full)


@check
def a_limited_token_reaches_only_its_paths():
    with s.app.app_context():
        limited = s.create_access_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": str(uuid.uuid4()), "family": str(uuid.uuid4()),
            "scope": "limited", "limited": ["integrity_elevated"]})
    me = "/v1/account/me"
    with elevated_integrity(), policy():
        s._latest_integrity_state = _verdict_state("trusted")
        reply = client.get(me, headers=access_headers("GET", me, bearer=limited))
        details = ((reply.get_json() or {}).get("error") or {}).get("details") or {}
        expect(reply.status_code == 403 and error_code(reply) == "session_limited"
               and details.get("limited_causes") == ["integrity_elevated"]
               and details.get("upgrade_routes") == [],
               "a limited token off its paths must get session_limited, got %s %s"
               % (reply.status_code, reply.get_json()))
        reply = client.get(me, headers=access_headers("GET", me))
        expect(reply.status_code == 200, "a full token must pass, got %s %s"
               % (reply.status_code, error_code(reply)))
    with elevated_integrity(), policy(limited_session_paths="/v1/policy/me, /v1/account/me"):
        s._latest_integrity_state = _verdict_state("trusted")
        reply = client.get(me, headers=access_headers("GET", me, bearer=limited))
        expect(reply.status_code == 200, "a DBA-listed path must be reachable, got %s %s"
               % (reply.status_code, error_code(reply)))
    with policy():
        for path in ("/v1/auth/upgrade", "/v1/auth/upgrade/request", "/v1/integrity/challenge",
                     "/v1/integrity/report", "/v1/integrity/me"):
            with s.app.test_request_context(path):
                s._require_limited_session_path({"limited": ["integrity_elevated"]})
    for key, value, valid in (
            ("limited_session_integrity_verdicts", "elevated,review", True),
            ("limited_session_integrity_verdicts", "", True),
            ("limited_session_integrity_verdicts", "block", False),
            ("limited_session_policy_actions", "review, block", False),
            ("limited_session_paths", "v1/no-slash", False),
            ("upgrade_request_ttl_seconds", "29", False),
            ("upgrade_request_ttl_seconds", "30", True)):
        try:
            s._validate_risk_settings(dict(SETTINGS, **{key: value}))
            accepted = True
        except ValueError:
            accepted = False
        expect(accepted == valid, "%s=%r: accepted=%s" % (key, value, accepted))


def _limited_session(*causes):
    """A limited access token and its refresh-session row in the fixture."""
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    with s.app.app_context():
        bearer = s.create_access_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": session, "family": family, "scope": "limited", "limited": list(causes)})
    db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                      s._utc_now() + s.REFRESH_TOKEN_LIFETIME, None, "limited", ",".join(causes),
                      None, None)
    return bearer


def _upgrade(bearer, body, stepup=False):
    raw = encode(body)
    path = "/v1/auth/upgrade"
    nonce = fresh_nonce()
    head = access_headers("POST", path, raw, bearer=bearer, nonce=nonce)
    if stepup:
        head.update(stepup_headers("POST", path, raw, nonce, bearer=bearer))
    return client.post(path, data=raw, headers=head)


@check
def a_limited_session_upgrades_only_through_an_open_route():
    """Recheck needs no proof once the cause is gone; while it remains, route 1
    (same-phone step-up) works only where the DBA enabled it, only for
    integrity causes, and only with a valid step-up proof for this request."""
    db.writes = []
    try:
        with elevated_integrity(), policy():
            s._latest_integrity_state = _verdict_state("trusted")
            reply = _upgrade(_limited_session("integrity_elevated"), {})
            payload = reply.get_json() or {}
            expect(reply.status_code == 200 and payload.get("scope") == "full"
                   and payload.get("upgraded_by") == "recheck",
                   "with the cause cleared the upgrade must need no proof: %s %s"
                   % (reply.status_code, payload))
            s._latest_integrity_state = _verdict_state("elevated")
            for body, code in (({}, "upgrade_proof_required"),
                               ({"route": "stepup"}, "upgrade_route_unavailable")):
                reply = _upgrade(_limited_session("integrity_elevated"), body)
                expect(reply.status_code == 403 and error_code(reply) == code,
                       "route 1 off: %s must answer %s, got %s %s"
                       % (body, code, reply.status_code, error_code(reply)))
        with elevated_integrity(), policy(upgrade_stepup_same_device=1):
            s._latest_integrity_state = _verdict_state("elevated")
            reply = _upgrade(_limited_session("integrity_elevated"), {"route": "stepup"})
            expect(reply.status_code == 403 and error_code(reply) == "stepup_required",
                   "route 1 without a step-up proof must be refused, got %s %s"
                   % (reply.status_code, error_code(reply)))
            reply = _upgrade(_limited_session("integrity_elevated"), {"route": "stepup"}, stepup=True)
            payload = reply.get_json() or {}
            expect(reply.status_code == 200 and payload.get("upgraded_by") == "stepup"
                   and payload.get("scope") == "full",
                   "route 1 with a valid step-up proof must upgrade, got %s %s"
                   % (reply.status_code, payload))
            s._evaluate_risk_policy = lambda *a, **k: {"effective_action": "review"}
            reply = _upgrade(_limited_session("integrity_elevated", "risk_review"),
                             {"route": "stepup"}, stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "upgrade_route_unavailable",
                   "route 1 must never clear relationship risk, got %s %s"
                   % (reply.status_code, error_code(reply)))
    finally:
        db.refresh_row = None


UPGRADE_LITE_SCHEMA = """
CREATE TABLE app_installations (
    installation_id TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL,
    status          TEXT NOT NULL
);
CREATE TABLE refresh_sessions (
    session_id      TEXT PRIMARY KEY,
    family_id       TEXT NOT NULL,
    account_id      TEXT NOT NULL,
    installation_id TEXT NOT NULL REFERENCES app_installations(installation_id),
    expires_at      TSZ NOT NULL,
    revoked_at      TSZ,
    scope           TEXT NOT NULL
);
CREATE TABLE session_upgrade_requests (
    request_id               TEXT PRIMARY KEY,
    route                    TEXT NOT NULL,
    account_id               TEXT NOT NULL,
    installation_id          TEXT NOT NULL,
    family_id                TEXT NOT NULL,
    expires_at               TSZ NOT NULL,
    approved_by_installation TEXT,
    approved_at              TSZ,
    denied_at                TSZ,
    consumed_at              TSZ,
    superseded_at            TSZ,
    nonce_sha256             TEXT,
    assertion_method         TEXT
);
"""


@check
def approvals_come_from_another_installation_of_the_account_and_are_single_use():
    """Route 2's conditions are SQL, so they run on SQLite like R4's: who may
    approve, which session may use an approval, once, before it expires."""
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(UPGRADE_LITE_SCHEMA)
    cur = LiteCursor(connection)
    now = s._utc_now()
    acct, stranger = str(uuid.uuid4()), str(uuid.uuid4())
    phone, other, dead = (str(uuid.uuid4()) for _ in range(3))
    for iid, status in ((phone, "active"), (other, "active"), (dead, "revoked")):
        connection.execute("INSERT INTO app_installations VALUES (?, ?, ?)", (iid, "d", status))

    def session(iid, scope="full", revoked=None, expires=now + timedelta(days=1), who=acct):
        connection.execute("INSERT INTO refresh_sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (str(uuid.uuid4()), str(uuid.uuid4()), who, iid, expires, revoked, scope))

    for kwargs in ({"iid": other, "scope": "limited"}, {"iid": other, "revoked": now},
                   {"iid": other, "expires": now - timedelta(seconds=1)}, {"iid": dead},
                   {"iid": other, "who": stranger}):
        session(**kwargs)
    expect(not s._has_other_full_session(cur, acct, phone),
           "limited, revoked, expired, inactive or foreign sessions must not count as an approver")
    session(other)
    expect(s._has_other_full_session(cur, acct, phone) and not s._has_other_full_session(cur, acct, other),
           "only ANOTHER installation's current full session counts")

    family = str(uuid.uuid4())

    def request(expires=now + timedelta(minutes=5)):
        rid = str(uuid.uuid4())
        connection.execute("INSERT INTO session_upgrade_requests (request_id, route, account_id, "
                           "installation_id, family_id, expires_at) VALUES (?, 'approval', ?, ?, ?, ?)",
                           (rid, acct, phone, family, expires))
        return rid

    mine = {"account_id": acct, "installation_id": phone, "family_id": family}
    state = lambda rid, fam=family: s._approval_state(cur, {"request_id": rid}, {"family": fam}, acct, phone)
    rid = request()
    expect(state(rid) == "pending" and s._consume_approval(cur, rid, mine) == 0,
           "a pending request must not be usable")
    expect(s._grant_approval(cur, rid, acct, phone) == 0, "the requester must not approve itself")
    expect(s._grant_approval(cur, rid, stranger, other) == 0, "another account must not approve")
    expect(s._grant_approval(cur, rid, acct, other) == 1, "another installation of the account approves")
    expect(s._grant_approval(cur, rid, acct, other) == 0, "an approval is granted once")
    expect(state(rid) == "approved" and state(rid, str(uuid.uuid4())) == "unknown",
           "an approval belongs to its own session family")
    for wrong in ({"installation_id": other}, {"family_id": str(uuid.uuid4())}, {"account_id": stranger}):
        expect(s._consume_approval(cur, rid, dict(mine, **wrong)) == 0,
               "an approval must not be usable by %s" % wrong)
    expect(s._consume_approval(cur, rid, mine) == 1 and s._consume_approval(cur, rid, mine) == 0
           and state(rid) == "used", "an approval upgrades exactly once")
    late = request(expires=now - timedelta(seconds=1))
    expect(s._grant_approval(cur, late, acct, other) == 0 and state(late) == "expired",
           "an expired request must not be approved")
    denied = request()
    expect(s._deny_approval(cur, denied, acct, other) == 1 and s._grant_approval(cur, denied, acct, other) == 0
           and s._consume_approval(cur, denied, mine) == 0 and state(denied) == "denied",
           "a denied request stays denied")
    expect(s._deny_approval(cur, request(), acct, phone) == 0, "the requester must not deny its own request")
    connection.close()


@check
def a_new_approval_request_supersedes_only_the_same_phones_pending_ones():
    """DESIGN.md 75. Asking again replaces the phone's own pending requests for
    the account -- never another phone's, another account's, an assertion's or
    one already answered -- and a replaced request can be neither approved,
    denied nor used; only the account's approvers learn it was replaced."""
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(UPGRADE_LITE_SCHEMA)
    cur = LiteCursor(connection)
    now = s._utc_now()
    acct, stranger = str(uuid.uuid4()), str(uuid.uuid4())
    phone, other, approver = (str(uuid.uuid4()) for _ in range(3))
    family = str(uuid.uuid4())

    def request(iid=phone, who=acct, route="approval"):
        rid = str(uuid.uuid4())
        connection.execute("INSERT INTO session_upgrade_requests (request_id, route, account_id, "
                           "installation_id, family_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                           (rid, route, who, iid, family, now + timedelta(minutes=5)))
        return rid

    def state(rid, iid=phone, who=acct):
        return s._approval_state(cur, {"request_id": rid}, {"family": family}, who, iid)

    old, answered = request(), request()
    others, foreign, assertion = request(iid=other), request(who=stranger), request(route="assertion")
    expect(s._grant_approval(cur, answered, acct, approver) == 1, "setup: one request approved")
    expect(s._supersede_pending_requests(cur, acct, phone) == 1,
           "exactly the phone's one pending approval request is superseded")
    expect(state(old) == "superseded", "the replaced request reads as superseded")
    expect(state(others, iid=other) == "pending" and state(foreign, who=stranger) == "pending",
           "another phone's or another account's request is untouched")
    expect(state(answered) == "approved", "an answered request keeps its state")
    expect(connection.execute("SELECT superseded_at FROM session_upgrade_requests WHERE request_id = ?",
                              (assertion,)).fetchone()[0] is None,
           "an assertion request is untouched")
    expect(s._grant_approval(cur, old, acct, approver) == 0 and s._deny_approval(cur, old, acct, approver) == 0,
           "a superseded request can be neither approved nor denied")
    expect(s._approval_superseded(cur, old, acct, approver)
           and not s._approval_superseded(cur, old, stranger, approver)
           and not s._approval_superseded(cur, old, acct, phone)
           and not s._approval_superseded(cur, others, acct, approver),
           "only the account's approvers learn that a request was superseded")
    mine = {"account_id": acct, "installation_id": phone, "family_id": family}
    expect(s._consume_approval(cur, answered, mine) == 1,
           "an approval granted before the phone asked again still upgrades, once")
    expect(s._supersede_pending_requests(cur, acct, phone) == 0, "nothing is left to supersede")
    connection.close()


@check
def approving_needs_a_current_full_session_and_a_step_up():
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    with s.app.app_context():
        full = s.create_access_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": session, "family": family, "scope": "full"})
    rid = str(uuid.uuid4())
    path = "/v1/auth/approvals/%s/approve" % rid

    def approve(bearer, stepup=False):
        raw = encode({})
        nonce = fresh_nonce()
        head = access_headers("POST", path, raw, bearer=bearer, nonce=nonce)
        if stepup:
            head.update(stepup_headers("POST", path, raw, nonce, bearer=bearer))
        return client.post(path, data=raw, headers=head)

    db.writes = []
    try:
        with elevated_integrity(), policy():
            s._latest_integrity_state = _verdict_state("trusted")
            reply = approve(_limited_session("integrity_elevated"), stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "session_limited",
                   "a limited session must not approve, got %s %s" % (reply.status_code, error_code(reply)))
            db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                              s._utc_now() + s.REFRESH_TOKEN_LIFETIME, s._utc_now(), "full", None,
                              None, None)
            reply = approve(full, stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "full_session_required",
                   "a rotated or revoked session must not approve, got %s %s"
                   % (reply.status_code, error_code(reply)))
            db.refresh_row = db.refresh_row[:5] + (None, "full", None, None, None)
            reply = approve(full)
            expect(reply.status_code == 403 and error_code(reply) == "stepup_required",
                   "approving must need a step-up proof, got %s %s" % (reply.status_code, error_code(reply)))
            s._latest_integrity_state = _verdict_state("elevated")
            reply = approve(full, stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "integrity_elevated",
                   "an elevated approver must not approve, even with step-up, got %s %s"
                   % (reply.status_code, error_code(reply)))
            s._latest_integrity_state = _verdict_state("trusted")
            reply = approve(full, stepup=True)
            granted = [p for q, p in db.writes if q.startswith("UPDATE session_upgrade_requests")]
            expect(reply.status_code == 200 and granted and granted[-1][1] == rid
                   and granted[-1][0] == inst.installation_id,
                   "a current full session with step-up must approve, got %s %s"
                   % (reply.status_code, reply.get_json()))
    finally:
        db.refresh_row = None



@contextmanager
def assertion_keys(**keys):
    saved = dict(s._upgrade_assertion_cache)
    s._upgrade_assertion_cache.clear()
    s._upgrade_assertion_cache.update(
        keys={kid: s._parse_public_key(jwk)["key"] for kid, jwk in keys.items()}, error=None)
    try:
        yield
    finally:
        s._upgrade_assertion_cache.clear()
        s._upgrade_assertion_cache.update(saved)


def es256_jws(private_key, header, payload, raw=True):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    head = c.b64u(json.dumps(header, separators=(",", ":")).encode())
    body = c.b64u(json.dumps(payload, separators=(",", ":")).encode())
    der = private_key.sign((head + "." + body).encode(), ec.ECDSA(hashes.SHA256()))
    if raw:
        r, s_ = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s_.to_bytes(32, "big")
    else:
        signature = der
    return head + "." + body + "." + c.b64u(signature)


@check
def upgrade_assertions_are_verified_exactly():
    """Route 3: only an ES256 JWS with a raw signature, by a configured key,
    naming this audience, account, installation and request, with a nonce and
    at most ten minutes of life."""
    good_key, good_jwk = c.stepup_jwk_pair()
    other_key, _ = c.stepup_jwk_pair()
    rid, now = str(uuid.uuid4()), int(time.time())
    base = {"aud": s.UPGRADE_ASSERTION_AUDIENCE, "sub": account, "iid": inst.installation_id,
            "rid": rid, "nonce": "n0nce", "iat": now, "exp": now + 300, "amr": ["otp"]}

    def verdict(token):
        try:
            s._verify_upgrade_assertion(token, account, inst.installation_id, rid)
            return "ok"
        except s.ApiProblem as problem:
            return (problem.details or {}).get("field") or problem.code

    with assertion_keys(k1=good_jwk):
        cases = [
            ("valid with kid", es256_jws(good_key, {"alg": "ES256", "kid": "k1"}, base), "ok"),
            ("valid without kid", es256_jws(good_key, {"alg": "ES256"}, base), "ok"),
            ("audience in a list", es256_jws(good_key, {"alg": "ES256"},
                                             dict(base, aud=["x", s.UPGRADE_ASSERTION_AUDIENCE])), "ok"),
            ("unknown kid", es256_jws(good_key, {"alg": "ES256", "kid": "k2"}, base), "signature"),
            ("another key", es256_jws(other_key, {"alg": "ES256"}, base), "signature"),
            ("DER signature", es256_jws(good_key, {"alg": "ES256"}, base, raw=False), "signature"),
            ("alg none", es256_jws(good_key, {"alg": "none"}, base), "alg"),
            ("alg HS256", es256_jws(good_key, {"alg": "HS256"}, base), "alg"),
            ("crit header", es256_jws(good_key, {"alg": "ES256", "crit": ["x"]}, base), "alg"),
            ("wrong audience", es256_jws(good_key, {"alg": "ES256"}, dict(base, aud="other")), "aud"),
            ("other account", es256_jws(good_key, {"alg": "ES256"}, dict(base, sub="x")), "sub"),
            ("other installation", es256_jws(good_key, {"alg": "ES256"}, dict(base, iid="x")), "iid"),
            ("other request", es256_jws(good_key, {"alg": "ES256"}, dict(base, rid="x")), "rid"),
            ("expired", es256_jws(good_key, {"alg": "ES256"}, dict(base, exp=now - 1)), "exp"),
            ("too long-lived", es256_jws(good_key, {"alg": "ES256"},
                                         dict(base, exp=now + s.UPGRADE_ASSERTION_MAX_LIFETIME_SECONDS + 1)), "exp"),
            ("issued in the future", es256_jws(good_key, {"alg": "ES256"},
                                               dict(base, iat=now + 600, exp=now + 900)), "exp"),
            ("no nonce", es256_jws(good_key, {"alg": "ES256"},
                                   {k: v for k, v in base.items() if k != "nonce"}), "nonce"),
            ("not a JWS", "abc.def", "format"),
        ]
        for name, token, expected in cases:
            got = verdict(token)
            expect(got == expected, "%s: expected %s, got %s" % (name, expected, got))
        saved_issuer = s.UPGRADE_ASSERTION_ISSUER
        s.UPGRADE_ASSERTION_ISSUER = "https://idp.example"
        try:
            expect(verdict(es256_jws(good_key, {"alg": "ES256"}, base)) == "iss",
                   "a pinned issuer must be required")
            expect(verdict(es256_jws(good_key, {"alg": "ES256"}, dict(base, iss="https://idp.example"))) == "ok",
                   "the pinned issuer must be accepted")
        finally:
            s.UPGRADE_ASSERTION_ISSUER = saved_issuer


@check
def assertion_requests_are_single_use_and_bound():
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(UPGRADE_LITE_SCHEMA)
    cur = LiteCursor(connection)
    now = s._utc_now()
    acct, phone, family = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    mine = {"account_id": acct, "installation_id": phone, "family_id": family}
    nonce = "n-%s" % uuid.uuid4()

    def request(route="assertion", expires=now + timedelta(minutes=5)):
        rid = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO session_upgrade_requests (request_id, route, account_id, installation_id, "
            "family_id, expires_at, nonce_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rid, route, acct, phone, family, expires,
             __import__("hashlib").sha256(nonce.encode()).hexdigest()))
        return rid

    rid = request()
    good = {"nonce": nonce, "amr": ["otp", "sms"]}
    expect(s._consume_assertion(cur, rid, mine, {"nonce": "other"}) == 0, "the nonce must match")
    for wrong in ({"installation_id": str(uuid.uuid4())}, {"family_id": str(uuid.uuid4())},
                  {"account_id": str(uuid.uuid4())}):
        expect(s._consume_assertion(cur, rid, dict(mine, **wrong), good) == 0,
               "an assertion request must not be usable by %s" % wrong)
    expect(s._consume_assertion(cur, request(route="approval"), mine, good) == 0,
           "an approval request is not an assertion request")
    expect(s._consume_assertion(cur, request(expires=now - timedelta(seconds=1)), mine, good) == 0,
           "an expired request must not be usable")
    expect(s._consume_assertion(cur, rid, mine, good) == 1 and s._consume_assertion(cur, rid, mine, good) == 0,
           "an assertion request is used exactly once")
    method = connection.execute("SELECT assertion_method FROM session_upgrade_requests "
                                "WHERE request_id = ?", (rid,)).fetchone()[0]
    expect(method == "otp,sms", "the MFA method must be recorded, got %r" % method)
    connection.close()


@check
def a_limited_session_upgrades_with_an_assertion_only_where_enabled():
    key, jwk = c.stepup_jwk_pair()
    rid, now = str(uuid.uuid4()), int(time.time())
    payload = {"aud": s.UPGRADE_ASSERTION_AUDIENCE, "sub": account, "iid": inst.installation_id,
               "rid": rid, "nonce": "n0nce", "iat": now, "exp": now + 300}
    token = es256_jws(key, {"alg": "ES256"}, payload)
    body = {"route": "assertion", "request_id": rid, "assertion": token}
    db.writes = []
    try:
        with elevated_integrity():
            s._latest_integrity_state = _verdict_state("elevated")
            with policy(), assertion_keys(k1=jwk):
                reply = _upgrade(_limited_session("integrity_elevated"), body)
                expect(reply.status_code == 403 and error_code(reply) == "upgrade_route_unavailable",
                       "route 3 is off by default, got %s %s" % (reply.status_code, error_code(reply)))
            with policy(upgrade_mfa_assertion=1), assertion_keys():
                reply = _upgrade(_limited_session("integrity_elevated"), body)
                expect(reply.status_code == 403 and error_code(reply) == "upgrade_route_unavailable",
                       "route 3 without configured keys must be unavailable, got %s %s"
                       % (reply.status_code, error_code(reply)))
            with policy(upgrade_mfa_assertion=1), assertion_keys(k1=jwk):
                forged = dict(body, assertion=es256_jws(key, {"alg": "ES256"}, dict(payload, sub="x")))
                reply = _upgrade(_limited_session("integrity_elevated"), forged)
                expect(reply.status_code == 403 and error_code(reply) == "upgrade_assertion_invalid",
                       "an assertion for another account must be refused, got %s %s"
                       % (reply.status_code, error_code(reply)))
                reply = _upgrade(_limited_session("integrity_elevated", "risk_review"), body)
                payload_out = reply.get_json() or {}
                consumed = [p for q, p in db.writes if q.startswith("UPDATE session_upgrade_requests")]
                expect(reply.status_code == 200 and payload_out.get("upgraded_by") == "assertion"
                       and consumed and consumed[-1][1] == rid,
                       "a valid assertion must upgrade, relationship risk included: %s %s"
                       % (reply.status_code, payload_out))
    finally:
        db.refresh_row = None



@check
def relationship_risk_admits_a_first_sign_in_only_within_the_counts():
    """DESIGN.md 72 (owner decision): a first sign-in writes a permanent link, so
    under relationship risk it is refused if that link would make the phone's
    third account or the account's third device (the DBA's review counts; the
    elevated counts where elevated_risk_refuses is set) -- anyone holding only a
    password could otherwise do it from a fresh phone. Within the counts it gets
    a limited session; a new account under relationship risk is always refused."""
    import bcrypt as _bcrypt
    login = encode({"handle": "someone", "password": "Passw0rd123"})
    signup = encode({"handle": "newcomer", "password": "Passw0rd123"})

    def post(path, raw):
        return client.post(path, data=raw, headers=access_headers("POST", path, raw, device_token))

    def review(linked=False, accounts=2, devices=2):
        new = 0 if linked else 1
        return lambda *a, **k: {"effective_action": "review", "recommended_action": "review",
                                "context": {"account_already_linked_to_device": linked,
                                            "device_account_count": accounts - new,
                                            "account_device_count": devices - new,
                                            "projected_device_account_count": accounts,
                                            "projected_account_device_count": devices}}

    def outcome():
        reply = post("/v1/accounts/login", login)
        payload = reply.get_json() or {}
        if reply.status_code == 200:
            return payload.get("scope")
        return error_code(reply)

    db.account_row = (account, _bcrypt.hashpw(b"Passw0rd123", _bcrypt.gensalt(4)))
    db.writes = []
    try:
        with elevated_integrity(), policy():
            s._latest_integrity_state = _verdict_state("trusted")
            for kwargs, expected, why in (
                    ({"accounts": 2, "devices": 2}, "limited", "two people sharing / a second phone"),
                    ({"linked": True, "accounts": 3, "devices": 3}, "limited", "an already-linked account"),
                    ({"accounts": 3, "devices": 2}, "risk_review_required", "the phone's third account"),
                    ({"accounts": 1, "devices": 3}, "risk_review_required", "the account's third device")):
                s._evaluate_risk_policy = review(**kwargs)
                got = outcome()
                expect(got == expected, "%s: expected %s, got %s" % (why, expected, got))
            s._evaluate_risk_policy = review(accounts=1, devices=1)
            reply = post("/v1/accounts/register", signup)
            expect(reply.status_code == 403 and error_code(reply) == "risk_review_required"
                   and not [q for q, _ in db.writes if q.startswith("INSERT INTO demo_accounts")],
                   "a new account under relationship review must be refused and not created, got %s %s"
                   % (reply.status_code, error_code(reply)))
        with elevated_integrity(), policy(device_accounts_review_count=4, account_devices_review_count=4):
            s._latest_integrity_state = _verdict_state("trusted")
            s._evaluate_risk_policy = review(accounts=3, devices=3)
            expect(outcome() == "limited", "raised counts must let a third account or device in")
        with elevated_integrity(), policy(elevated_risk_refuses=1):
            s._latest_integrity_state = _verdict_state("trusted")
            s._evaluate_risk_policy = review(accounts=2, devices=1)
            expect(outcome() == "risk_review_required",
                   "where elevated refuses, the elevated counts are the limits")
    finally:
        db.account_row = None



# ---------------------------------------------------------------------------
# Relationship bands and devices per account are the DBA's (migration 012)
# ---------------------------------------------------------------------------


@check
def relationship_bands_follow_the_dba_settings():
    with policy():
        actions = [s._policy_action(score) for score in (29, 30, 59, 60, 89, 90)]
        expect(actions == ["allow", "step_up", "step_up", "review", "review", "block"],
               "the owner's default bands are 30 / 60 / 90, got %s" % actions)
        expect(s._policy_action(0, hard_block=True) == "block", "a hard reason always blocks")
    with policy(policy_step_up_score=40, policy_review_score=70, policy_block_score=95):
        actions = [s._policy_action(score) for score in (39, 40, 69, 70, 94, 95)]
        expect(actions == ["allow", "step_up", "step_up", "review", "review", "block"],
               "retuned bands must apply, got %s" % actions)
    for values, valid in (({"policy_review_score": "65"}, True),
                          ({"policy_review_score": "95"}, False),
                          ({"policy_step_up_score": "60"}, False),
                          ({"policy_step_up_score": "0"}, False),
                          ({"policy_block_score": "eighty"}, False)):
        try:
            s._validate_risk_settings(dict(SETTINGS, **values))
            accepted = True
        except ValueError:
            accepted = False
        expect(accepted == valid, "bands %s: accepted=%s" % (values, accepted))


@check
def devices_per_account_follow_the_dba_settings():
    def score(count):
        reasons = []
        points, hard = s._account_device_points(reasons, count)
        return points, hard, [r["code"] for r in reasons]

    with policy():
        expect(score(1) == (0, False, []), "one device scores nothing")
        expect(score(2) == (35, False, ["account_has_multiple_devices"]), "a second device: +35")
        expect(score(3)[:2] == (60, False) and score(4)[:2] == (60, False),
               "a third or fourth device: +60, review")
        expect(score(5) == (0, True, ["account_device_count_block_threshold"]), "a fifth device blocks")
        expect(s._policy_action(score(3)[0]) == "review",
               "by default a third device must reach the review band (refused in enforce mode)")
    with policy(account_devices_review_count=4, account_devices_review_points=60,
                account_devices_block_count=6):
        expect(score(3)[:2] == (35, False) and s._policy_action(score(3)[0]) == "step_up",
               "a business may let a third device through: %s" % (score(3),))
        expect(score(6)[1] is True, "and still block at its own count")
    with policy(account_devices_elevated_count=0, account_devices_review_count=0,
                account_devices_block_count=0):
        expect(score(9) == (0, False, []), "0 switches each count off")



# ---------------------------------------------------------------------------
# An upgrade's acceptance (DESIGN.md 72)
# ---------------------------------------------------------------------------


def _full_token(accepted=(), until=None, scope="full"):
    claims = {"role": "account", "iid": inst.installation_id, "did": inst.device_id,
              "sid": str(uuid.uuid4()), "family": str(uuid.uuid4()), "scope": scope}
    if accepted:
        claims["accepted"] = sorted(accepted)
        claims["accepted_until"] = int(until if until is not None else time.time() + 3600)
    with s.app.app_context():
        return s.create_access_token(identity=account, additional_claims=claims)


WX = {"code": "android_wx_far_above_baseline", "points": 40, "source": "integrity"}
TRACER = {"code": "android_process_traced", "points": 55}
MULTI = {"code": "account_has_multiple_devices", "points": 35, "source": "relationship"}


def _accepted_token(causes, reasons, device_accounts=None, account_devices=None,
                    revoked=None, with_record=True):
    """A full access token whose upgrade accepted these reasons, and its record."""
    family, acceptance_id = str(uuid.uuid4()), str(uuid.uuid4())
    if with_record:
        db.acceptances[acceptance_id] = (acceptance_id, family, account, inst.installation_id,
                                         ",".join(causes), list(reasons), device_accounts,
                                         account_devices, s._utc_now() + timedelta(days=5), revoked)
    claims = {"role": "account", "iid": inst.installation_id, "did": inst.device_id,
              "sid": str(uuid.uuid4()), "family": family, "scope": "full",
              "accepted": sorted(causes), "accepted_until": int(time.time() + 3600)}
    if with_record:
        claims["acc"] = acceptance_id  # a token from before migration 016 has none
    with s.app.app_context():
        return s.create_access_token(identity=account, additional_claims=claims), acceptance_id


def _integrity_now(verdict, *reasons):
    score = {"trusted": 0, "elevated": 40, "review": 60}[verdict]
    return lambda iid: {"score": score, "verdict": verdict, "fresh": True,
                        "reasons": [dict(r, message="m") for r in reasons]}


def _risk_now(action, *reasons, **context):
    return lambda *a, **k: {"effective_action": action, "decision_id": "not-persisted",
                            "reasons": [dict(r, message="m") for r in reasons],
                            "context": dict({"device_account_count": 1,
                                             "account_device_count": 2}, **context)}


@check
def an_upgrade_acceptance_covers_what_was_approved_and_nothing_else():
    """Review R1 (DESIGN.md 76, owner decision 2026-10-13). An approval for
    runtime growth used to cover a later tracer, in the same band, for a
    month. Now an acceptance covers the reasons it approved -- same code, no
    more points; relationship counts up to those approved -- and the DBA's
    auto-cover list (a business decision). Collection problems never; a
    revoked record or a pre-016 acceptance covers nothing. Each new reason is
    recorded once as a lapse."""
    me = "/v1/account/me"

    def get(bearer):
        reply = client.get(me, headers=access_headers("GET", me, bearer=bearer))
        return reply.status_code, (error_code(reply) if reply.status_code != 200 else reply.get_json())

    quality = {"code": "integrity_evidence_incomplete", "points": 30}
    try:
        with elevated_integrity(), policy():
            s._evaluate_risk_policy = _risk_now("allow")
            token, acc = _accepted_token(["integrity_elevated"], [WX])
            s._latest_integrity_state = _integrity_now("elevated", WX)
            status, payload = get(token)
            expect(status == 200 and payload["integrity"].get("acceptance_id") == acc,
                   "the approved reason must pass, marked with its acceptance: %s %s" % (status, payload))
            for now, why in (((TRACER,), "a different finding in the same band"),
                             ((WX, TRACER), "a new finding beside the approved one"),
                             ((dict(WX, points=45),), "more points than approved"),
                             ((WX, quality), "a collection problem")):
                s._latest_integrity_state = _integrity_now("elevated", *now)
                got = get(token)
                expect(got == (403, "integrity_step_up_required"),
                       "%s must not be covered, got %s" % (why, got))
            expect((acc, "android_process_traced") in db.lapses
                   and (acc, "integrity_evidence_incomplete") in db.lapses,
                   "each new reason must be recorded once as a lapse: %s" % db.lapses)
            with policy(acceptance_auto_cover_reasons="android_process_traced,integrity_evidence_incomplete"):
                s._latest_integrity_state = _integrity_now("elevated", WX, TRACER)
                expect(get(token)[0] == 200, "the DBA's auto-cover list covers a new reason")
                s._latest_integrity_state = _integrity_now("elevated", WX, quality)
                expect(get(token) == (403, "integrity_step_up_required"),
                       "a collection problem is never auto-covered")
            s._latest_integrity_state = _integrity_now("elevated", WX)
            expect(get(_accepted_token(["integrity_elevated"], [WX], revoked=s._utc_now())[0])
                   == (403, "integrity_step_up_required"), "a revoked acceptance must cover nothing")
            # An approval from before migration 016 carries causes, no record
            # (owner decision 2026-10-13): carried over at its first use as
            # what it covers then, or nothing under legacy_acceptances = drop.
            with policy(legacy_acceptances="drop"):
                for token_, why in ((_accepted_token(["integrity_elevated"], [WX], with_record=False)[0],
                                     "an approval from before migration 016"),
                                    (_full_token(["integrity_elevated"]), "causes without a record")):
                    expect(get(token_) == (403, "integrity_step_up_required"),
                           "%s must cover nothing under drop" % why)
            db.writes = []
            old = _full_token(["integrity_elevated"])
            status, payload = get(old)
            carried = [p for q, p in db.writes if q.startswith("INSERT INTO session_acceptances")]
            reasons = getattr(carried[-1][7], "adapted", carried[-1][7]) if carried else None
            expect(status == 200 and payload["integrity"].get("accepted_by_upgrade") is True
                   and carried and carried[-1][5] == "legacy"
                   and [r["code"] for r in reasons] == [WX["code"]],
                   "carry must keep a pre-016 approval as what it covers now: %s %s %s"
                   % (status, payload, reasons))
            expect(get(old)[0] == 200 and len([q for q, _ in db.writes
                                               if q.startswith("INSERT INTO session_acceptances")]) == 1,
                   "a carried-over approval is recorded once")
            s._latest_integrity_state = _integrity_now("elevated", WX, TRACER)
            expect(get(old) == (403, "integrity_step_up_required"),
                   "after carrying over, a new reason needs a new decision")
            s._latest_integrity_state = _integrity_now("elevated", {"code": "integrity_evidence_incomplete",
                                                                    "points": 30})
            expect(get(_full_token(["integrity_elevated"])) == (403, "integrity_step_up_required"),
                   "a collection problem is never carried over")
            s._latest_integrity_state = _verdict_state("trusted")
            token, acc = _accepted_token(["risk_review"], [MULTI], device_accounts=1, account_devices=2)
            s._evaluate_risk_policy = _risk_now("review", MULTI)
            expect(get(token)[0] == 200, "the approved relationship reason and counts pass")
            s._evaluate_risk_policy = _risk_now("review", dict(MULTI, code="account_has_many_devices",
                                                               points=60), account_device_count=3)
            expect(get(token) == (403, "risk_review_required"), "a third device is not covered")
            s._evaluate_risk_policy = _risk_now("review", MULTI, {"code": "request_rate_anomaly",
                                                                  "points": 25,
                                                                  "source": "relationship"})
            expect(get(token) == (403, "risk_review_required"), "a new relationship reason is not covered")
    finally:
        db.acceptances.clear()
        db.lapses.clear()


@check
def an_upgrade_records_its_acceptance():
    from flask_jwt_extended import decode_token
    db.writes = []
    try:
        with elevated_integrity(), policy(upgrade_stepup_same_device=1):
            quality = {"code": "integrity_evidence_incomplete", "points": 30}
            s._latest_integrity_state = _integrity_now("elevated", WX, quality)
            reply = _upgrade(_limited_session("integrity_elevated"), {"route": "stepup"}, stepup=True)
            payload = reply.get_json() or {}
            with s.app.app_context():
                claims = decode_token(payload.get("access_token", ""))
            row = [p for q, p in db.writes if q.startswith("INSERT INTO refresh_sessions")][-1]
            record = [p for q, p in db.writes if q.startswith("INSERT INTO session_acceptances")][-1]
            reasons = getattr(record[9], "adapted", record[9])
            expect(reply.status_code == 200 and payload.get("accepted_causes") == ["integrity_elevated"]
                   and claims.get("accepted") == ["integrity_elevated"]
                   and claims.get("accepted_until", 0) > time.time() + 29 * 86400
                   and claims.get("acc") == record[0] == row[10]
                   and [r["code"] for r in reasons] == [WX["code"]],
                   "a proof upgrade must record what it accepted, collection problems "
                   "excepted: %s %s %s" % (payload, claims, reasons))
            s._latest_integrity_state = _integrity_now("elevated", quality)
            reply = _upgrade(_limited_session("integrity_elevated"), {"route": "stepup"}, stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "complete_scan_required",
                   "collection problems alone cannot be approved: %s %s"
                   % (reply.status_code, error_code(reply)))
        with elevated_integrity(), policy(upgrade_stepup_same_device=1, upgrade_acceptance_hours=0):
            s._latest_integrity_state = _verdict_state("elevated")
            reply = _upgrade(_limited_session("integrity_elevated"), {"route": "stepup"}, stepup=True)
            expect(reply.status_code == 200 and "accepted_causes" not in (reply.get_json() or {}),
                   "upgrade_acceptance_hours=0 must record no acceptance")
        with elevated_integrity(), policy():
            s._latest_integrity_state = _verdict_state("trusted")
            reply = _upgrade(_limited_session("integrity_elevated"), {})
            expect(reply.status_code == 200 and "accepted_causes" not in (reply.get_json() or {}),
                   "a recheck needs no proof and accepts nothing")
    finally:
        db.refresh_row = None


@check
def a_refresh_keeps_an_accepted_session_full_only_while_covered():
    """A refresh keeps an accepted session full only while every cause found
    now is covered by what was approved, reason by reason (DESIGN.md 76)."""
    def refresh(accepted, until, now, action, with_record=True, settings=None):
        family, session, acc = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        with s.app.app_context():
            token = s.create_refresh_token(identity=account, additional_claims={
                "role": "account", "iid": inst.installation_id, "did": inst.device_id,
                "sid": session, "family": family, "scope": "full"})
        if with_record and accepted:
            db.acceptances[acc] = (acc, family, account, inst.installation_id, ",".join(accepted),
                                   [WX], None, None, s._utc_now() + timedelta(days=5), None)
        db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                          s._utc_now() + s.REFRESH_TOKEN_LIFETIME, None, "full", None,
                          ",".join(accepted) or None, until,
                          acc if accepted and with_record else None)
        s._latest_integrity_state = now
        s._evaluate_risk_policy = _risk_now(action)
        challenge = client.post("/v1/auth/refresh/challenge",
                                headers={"Authorization": "Bearer " + token}).get_json()
        reply = client.post("/v1/auth/refresh", json={
            "challenge_id": challenge["challenge_id"], "payload": challenge["payload"],
            "signature": inst.sign_b64(challenge["payload"])},
            headers={"Authorization": "Bearer " + token})
        payload = reply.get_json() or {}
        expect(reply.status_code == 200, "refresh failed: %s %s" % (reply.status_code, payload))
        return payload.get("scope"), payload.get("accepted_causes")

    later, earlier = s._utc_now() + timedelta(days=5), s._utc_now() - timedelta(seconds=1)
    covered, traced = _integrity_now("elevated", WX), _integrity_now("elevated", WX, TRACER)
    try:
        with elevated_integrity(), policy():
            for args, kwargs, expected, why in (
                    ((["integrity_elevated"], later, covered, "allow"), {},
                     ("full", ["integrity_elevated"]), "an approved reason keeps the session full"),
                    ((["integrity_elevated"], later, traced, "allow"), {},
                     ("limited", None), "a new reason narrows it and drops the acceptance"),
                    ((["integrity_elevated"], later, covered, "review"), {},
                     ("limited", None), "a cause beyond the acceptance narrows it"),
                    ((["integrity_elevated"], earlier, covered, "allow"), {},
                     ("limited", None), "an expired acceptance narrows"),
                    (([], None, covered, "allow"), {}, ("limited", None),
                     "without acceptance a soft cause narrows"),
                    ((["integrity_elevated"], later, covered, "allow"), {"with_record": False},
                     ("full", ["integrity_elevated"]), "a pre-016 acceptance is carried over"),
                    ((["integrity_elevated"], later, _verdict_state("trusted"), "allow"), {},
                     ("full", ["integrity_elevated"]), "with no cause left it stays full")):
                got = refresh(*args, **kwargs)
                expect(got == expected, "%s: expected %s, got %s" % (why, expected, got))
        with elevated_integrity(), policy(legacy_acceptances="drop"):
            got = refresh(["integrity_elevated"], later, covered, "allow", with_record=False)
            expect(got == ("limited", None), "under drop a pre-016 acceptance narrows, got %s" % (got,))
    finally:
        db.refresh_row = None
        db.acceptances.clear()
        db.lapses.clear()


@check
def a_signed_out_or_revoked_family_reaches_nothing():
    """Review R6 (DESIGN.md 76). An access token outlives its refresh family by
    up to ten minutes; account requests now check that the family still has a
    current session, so a sign-out or a reuse revocation takes effect at once.
    A routine rotation leaves the newest session current, so in-flight tokens
    survive it. /v1/auth/logout revokes the family, and a limited session may
    call it."""
    me, out = "/v1/account/me", "/v1/auth/logout"
    family = str(uuid.uuid4())

    def bearer(scope="full"):
        claims = {"role": "account", "iid": inst.installation_id, "did": inst.device_id,
                  "sid": str(uuid.uuid4()), "family": family, "scope": scope}
        if scope == "limited":
            claims["limited"] = ["integrity_elevated"]
        with s.app.app_context():
            return s.create_access_token(identity=account, additional_claims=claims)

    def get(token):
        reply = client.get(me, headers=access_headers("GET", me, bearer=token))
        return reply.status_code, error_code(reply)

    with elevated_integrity():
        s._latest_integrity_state = _verdict_state("trusted")
        status, code = get(bearer())
        expect(status == 200, "a current family must pass, got %s %s" % (status, code))
        db.revoked_families.add(family)
        try:
            status, code = get(bearer())
            expect(status == 401 and code == "session_revoked",
                   "a revoked family must not reach a protected path, got %s %s" % (status, code))
        finally:
            db.revoked_families.discard(family)
    for scope in ("full", "limited"):
        db.writes = []
        body = encode({})
        token = bearer(scope)
        reply = client.post(out, data=body, headers=access_headers("POST", out, body, bearer=token))
        revoked = [p for q, p in db.writes if q.startswith("UPDATE refresh_sessions SET revoked_at")]
        accepted = [p for q, p in db.writes if q.startswith("UPDATE session_acceptances SET revoked_at")]
        expect(reply.status_code == 200 and revoked and revoked[-1][0] == family
               and accepted and accepted[-1][0] == family,
               "a %s session's logout must revoke its family and its acceptances, got %s %s %s"
               % (scope, reply.status_code, reply.get_json(), revoked))


ADMISSION_LITE_SCHEMA = """
CREATE TABLE demo_accounts (account_id TEXT PRIMARY KEY);
CREATE TABLE recognized_devices (device_id TEXT PRIMARY KEY);
CREATE TABLE device_account_links (
    device_id             TEXT NOT NULL,
    account_id            TEXT NOT NULL,
    first_installation_id TEXT NOT NULL,
    first_seen_at         TSZ DEFAULT CURRENT_TIMESTAMP,
    last_seen_at          TSZ DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, account_id)
);
"""


@check
def sign_ins_decided_together_cannot_exceed_the_counts_they_saw():
    """Review R2 (DESIGN.md 76), the server's own SQL on SQLite. Four sign-ins of
    one account from four new phones are all decided before any link is
    written, each seeing one device on the account. Without the recheck all
    four link (five devices). With it the first links and the other three get
    relationship_changed; the same holds for accounts on one phone. A pair
    already linked is always admitted; a decision without counts is refused."""
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(ADMISSION_LITE_SCHEMA)
    cur = LiteCursor(connection)
    acct, first = str(uuid.uuid4()), str(uuid.uuid4())
    phones = [str(uuid.uuid4()) for _ in range(4)]
    others = [str(uuid.uuid4()) for _ in range(2)]
    for account_id in [acct] + others:
        connection.execute("INSERT INTO demo_accounts VALUES (?)", (account_id,))
    for device_id in [first] + phones:
        connection.execute("INSERT INTO recognized_devices VALUES (?)", (device_id,))
    s._link_device_account(cur, first, acct, str(uuid.uuid4()))

    def attempt(device_id, account_id, accounts_seen, devices_seen):
        decided = {"context": {"device_account_count": accounts_seen,
                               "account_device_count": devices_seen}}
        try:
            s._admit_link(cur, device_id, account_id, decided)
        except s.ApiProblem as problem:
            return problem.code
        s._link_device_account(cur, device_id, account_id, str(uuid.uuid4()))
        return "linked"

    outcomes = [attempt(phone, acct, 0, 1) for phone in phones]
    links = connection.execute("SELECT COUNT(*) FROM device_account_links WHERE account_id = ?",
                               (acct,)).fetchone()[0]
    expect(outcomes == ["linked"] + ["relationship_changed"] * 3 and links == 2,
           "four sign-ins decided on one device must link one more, got %s, %d links"
           % (outcomes, links))
    # The phone side: two other accounts decided against the phone that now holds one.
    outcomes = [attempt(first, account_id, 1, 0) for account_id in others]
    expect(outcomes == ["linked", "relationship_changed"],
           "two accounts decided on one account per phone must add one, got %s" % outcomes)
    expect(attempt(phones[0], acct, 0, 1) == "linked",
           "an already-linked pair adds nothing and must be admitted")
    expect(_refused(lambda: s._admit_link(cur, phones[1], acct, {"context": {}}))
           == "admission_unverifiable", "a decision without its counts must be refused")
    connection.close()


@check
def login_and_registration_recheck_the_counts_before_linking():
    """Review R2 at the endpoints: when the links counted now exceed what the
    decision saw, login and registration answer 409 relationship_changed."""
    import bcrypt as _bcrypt
    allow = lambda *a, **k: {"effective_action": "allow", "recommended_action": "allow",
                             "context": {"device_account_count": 0, "account_device_count": 1}}
    db.account_row = (account, _bcrypt.hashpw(b"Passw0rd123", _bcrypt.gensalt(4)))
    try:
        with elevated_integrity(), policy():
            s._latest_integrity_state = _verdict_state("trusted")
            s._evaluate_risk_policy = allow
            for path, handle in (("/v1/accounts/login", "someone"), ("/v1/accounts/register", "fresh")):
                raw = encode({"handle": handle, "password": "Passw0rd123"})
                for counts, expected in (((0, 1), (200, 201)), ((0, 2), (409,)), ((1, 1), (409,))):
                    db.link_counts = counts
                    reply = client.post(path, data=raw,
                                        headers=access_headers("POST", path, raw, device_token))
                    expect(reply.status_code in expected
                           and (reply.status_code != 409
                                or error_code(reply) == "relationship_changed"),
                           "%s with links now %s against decided (0, 1): expected %s, got %s %s"
                           % (path, counts, expected, reply.status_code, error_code(reply)))
    finally:
        db.account_row, db.link_counts = None, (0, 0)


@check
def collection_problems_count_once_and_never_follow_the_device():
    """Review R3 (DESIGN.md 76, owner decision 2026-10-13). One collection
    problem can break three probes at once; that used to add 3 x 30 = 90, a
    block, remembered for every account on the phone for a day. Now each
    failed probe is listed at 0 points and together they add +30 once; the
    findings score stays 0, so nothing enters the device memory. A DBA who
    sets collection_problems_block = 1 gets the earlier rule back, memory
    included. Reports from before migration 015 are judged by their score."""
    probes = clean("android")
    for name in ("runtime_maps", "tracer", "debug_state"):  # always requested on Android
        probes[name] = {"status": "error", "error": "permission denied"}
    status, payload = send_report("android", probes)
    decision = (payload or {}).get("integrity") or {}
    points = points_of(decision) if decision else {}
    expect(status == 200 and decision.get("score") == 30 and decision.get("verdict") == "elevated"
           and decision.get("finding_score") == 0
           and decision.get("evidence_quality") == "incomplete"
           and points.get("integrity_evidence_incomplete") == 30
           and points.get("integrity_probe_failed:tracer") == 0,
           "three failed probes must cost +30 once, with no finding: %s %s" % (status, decision))
    with policy(collection_problems_block=1):
        status, payload = send_report("android", probes)
        decision = payload["integrity"]
        expect(decision["score"] == 90 and decision["verdict"] == "block"
               and decision["finding_score"] == 90,
               "collection_problems_block=1 must restore +30 each, as a finding: %s" % decision)
    status, payload = send_report("android", clean("android"))
    expect(payload["integrity"].get("evidence_quality") == "complete"
           and payload["integrity"]["score"] == 0, "a clean scan is complete: %s" % payload)
    with lite_store() as db_:
        device = str(uuid.uuid4())
        phone = lite_installation(db_, device, "new_device")
        lite_report(db_, phone, device, 90, finding_score=0, age_hours=1)
        refused, _, _ = memory_outcome(device, phone)
        expect(not refused, "a block made of collection problems must not follow the device")
        old = str(uuid.uuid4())
        legacy = lite_installation(db_, old, "new_device")
        lite_report(db_, legacy, old, 90, age_hours=1)  # stored before migration 015
        refused, _, _ = memory_outcome(old, legacy)
        expect(refused, "a pre-015 block must keep its memory until it ages out")
        found = str(uuid.uuid4())
        tampered = lite_installation(db_, found, "new_device")
        lite_report(db_, tampered, found, 95, finding_score=95, age_hours=1)
        lite_report(db_, tampered, found, 0, finding_score=0)
        refused, _, _ = memory_outcome(found, tampered)
        expect(refused, "a real finding must still follow the device after a clean scan")


def v3(probes):
    """A report under the Android evidence contract 3 (DESIGN.md 76)."""
    for name in ("runtime_maps", "exec_mappings"):
        if name in probes:
            probes[name].setdefault("maps_lines", 412)
    if "exec_mappings" in probes:
        probes["exec_mappings"].setdefault("deleted_exec_own_code", 0)
    if "code_integrity" in probes and "core_expected_bytes" not in probes["code_integrity"]:
        coverage(probes)
    return probes


@check
def weak_or_contradictory_evidence_is_never_complete():
    """Review R4 (DESIGN.md 76, owner decision 2026-10-13). Evidence that cannot
    all be true is invalid (+30, labelled invalid), not clean; a measurement
    the collector could not make is incomplete; a wrongly typed field is a
    malformed report (400); a collector below its platform's evidence
    contract is labelled legacy, never complete."""
    def send(probes, version=3):
        status, payload = send_report("android", probes, collector_version=version)
        return status, (payload or {}).get("integrity") or (payload or {}).get("error") or {}

    status, decision = send(v3(clean("android")))
    expect(status == 200 and decision.get("evidence_quality") == "complete"
           and decision.get("score") == 0, "control: a v3 clean scan is complete: %s" % decision)
    status, decision = send(clean("android"), version=2)
    expect(status == 200 and decision.get("evidence_quality") == "legacy"
           and decision.get("score") == 0, "a v2 clean scan is legacy, not complete: %s" % decision)
    for label, mutate, quality in (
            ("zero W+X mappings with a size listed",
             lambda p: p["exec_mappings"].update(wx_mappings=0, wx_bytes=0, wx_size_classes="4096:1"),
             "invalid"),
            ("coverage figures that do not add up",
             lambda p: p["code_integrity"].update(app_expected_bytes=8388608), "invalid"),
            ("no thread enumerated", lambda p: p["instrumentation_threads"].update(thread_count=0),
             "incomplete"),
            ("an unreadable process map", lambda p: p["runtime_maps"].update(maps_lines=0),
             "incomplete"),
            ("coverage totals omitted under contract 3",
             lambda p: [p["code_integrity"].pop("%s_expected_bytes" % b) for b in ("core", "ext", "app")],
             "incomplete")):
        probes = v3(clean("android"))
        probes.setdefault("instrumentation_threads",
                          c.clean_probes(["instrumentation_threads"])["instrumentation_threads"])
        probes.setdefault("exec_mappings", v3(c.clean_probes(["exec_mappings"]))["exec_mappings"])
        mutate(probes)
        status, decision = send(probes)
        expect(status == 200 and decision.get("evidence_quality") == quality
               and decision.get("verdict") != "trusted" and decision.get("finding_score") == 0,
               "%s must be %s, never trusted: %s %s" % (label, quality, status, decision))
    probes = v3(clean("android"))
    probes.setdefault("exec_mappings", v3(c.clean_probes(["exec_mappings"]))["exec_mappings"])
    probes["exec_mappings"]["deleted_exec_own_code"] = "1"
    status, error = send(probes)
    expect(status == 400 and error.get("code") == "invalid_integrity_probe",
           "a wrongly typed own-code count must be malformed, not ignored: %s %s" % (status, error))


@check
def complete_evidence_paths_refuse_anything_but_a_fresh_complete_scan():
    """Owner decision of 2026-10-13 (DESIGN.md 76): on the DBA's
    complete_evidence_paths only a fresh scan that measured everything will do
    -- incomplete, invalid, partial or legacy evidence is refused whatever the
    verdict, step-up or acceptance; elsewhere nothing changes."""
    body = encode({"x": 1})

    def post(quality, age=10):
        s._latest_integrity_state = lambda iid: {"score": 0, "verdict": "trusted", "fresh": True,
                                                 "evidence_quality": quality, "age_seconds": age}
        reply = client.post(ECHO, data=body, headers=access_headers("POST", ECHO, body))
        return reply.status_code, error_code(reply)

    with elevated_integrity():
        with policy():
            expect(post("legacy") == (200, None), "with no paths listed nothing changes")
        with policy(complete_evidence_paths=ECHO):
            expect(post("complete") == (200, None), "a fresh complete scan passes")
            for quality in ("incomplete", "invalid", "partial", "legacy", None):
                got = post(quality)
                expect(got == (403, "integrity_complete_evidence_required"),
                       "%s evidence must be refused on a listed path, got %s" % (quality, got))
            got = post("complete", age=700)
            expect(got == (403, "integrity_complete_evidence_required"),
                   "a complete scan older than the default 600 s must be refused, got %s" % (got,))
        with policy(complete_evidence_paths=ECHO, complete_evidence_max_age_seconds=900):
            expect(post("complete", age=700) == (200, None), "the DBA's max age applies")


@check
def evidence_that_stays_incomplete_escalates_to_review():
    """Owner decision of 2026-10-13 (DESIGN.md 76): incomplete_evidence_review_after
    (3) incomplete or invalid scans in a row add +30 more -- review, with no
    finding and nothing for the device memory; a legacy or complete scan in
    between resets the count; 0 turns it off."""
    probes = clean("android")
    probes["tracer"] = {"status": "error", "error": "permission denied"}

    def send(previous, **settings):
        db.recent_qualities = previous
        try:
            with policy(**settings):
                status, payload = send_report("android", probes)
        finally:
            db.recent_qualities = []
        return payload["integrity"]

    third = send(["incomplete", "invalid"])
    expect(third["verdict"] == "review" and third["score"] == 60 and third["finding_score"] == 0
           and "integrity_evidence_persistently_incomplete" in {r["code"] for r in third["reasons"]},
           "the third incomplete scan in a row must escalate to review: %s" % third)
    for previous, settings, why in ((["incomplete"], {}, "only two in a row"),
                                    (["incomplete", "legacy"], {}, "a legacy scan resets the count"),
                                    (["complete", "incomplete"], {}, "a complete scan resets it"),
                                    (["incomplete", "invalid"], {"incomplete_evidence_review_after": 0},
                                     "0 turns it off")):
        got = send(previous, **settings)
        expect(got["verdict"] == "elevated" and got["score"] == 30,
               "%s: expected elevated 30, got %s" % (why, got))


@check
def an_approval_accepts_what_its_request_showed():
    """DESIGN.md 76. A request records the reasons the approver is shown; the
    upgrade accepts those, and refuses with upgrade_scope_changed when a new
    reason or more points or a higher count appeared after the request.
    Collection problems are left out of the comparison (never accepted
    either), and a cause made of them alone cannot be requested at all."""
    elevated = lambda *reasons: {"verdict": "elevated", "reasons": list(reasons)}
    policy_ = {"reasons": [MULTI], "context": {"device_account_count": 1, "account_device_count": 2}}
    with policy():
        reasons, accounts, devices = s._acceptance_snapshot(
            ["integrity_elevated", "risk_review"],
            elevated(WX, {"code": "integrity_evidence_incomplete", "points": 30}), policy_)
        expect([r["code"] for r in reasons] == [WX["code"], MULTI["code"]]
               and (accounts, devices) == (1, 2),
               "the snapshot keeps the approvable reasons and the counts: %s" % reasons)
        expect(_refused(lambda: s._acceptance_snapshot(
            ["integrity_elevated"], elevated({"code": "integrity_probe_failed:tracer", "points": 30},
                                             {"code": "integrity_evidence_incomplete", "points": 30}),
            policy_)) == "complete_scan_required",
            "collection problems alone cannot be requested or approved")
        scope = {"request_id": str(uuid.uuid4()), "causes": ["integrity_elevated", "risk_review"],
                 "reasons": reasons, "device_accounts": 1, "account_devices": 2,
                 "approved_by_installation": None}
        within = lambda integrity, policy_now: _refused(
            lambda: s._require_within_scope(scope, ["integrity_elevated", "risk_review"],
                                            integrity, policy_now))
        expect(within(elevated(WX), policy_) is None, "the same reasons are within the request")
        expect(within(elevated(WX, {"code": "integrity_evidence_incomplete", "points": 30}),
                      policy_) is None, "a collection problem is not a change of scope")
        for integrity, policy_now, why in (
                (elevated(WX, TRACER), policy_, "a new finding"),
                (elevated(dict(WX, points=45)), policy_, "more points"),
                (elevated(WX), {"reasons": [dict(MULTI, code="account_has_many_devices", points=60)],
                                "context": {"device_account_count": 1, "account_device_count": 3}},
                 "a third device")):
            expect(within(integrity, policy_now) == "upgrade_scope_changed",
                   "%s after the request must change its scope" % why)


BUSINESS_LITE_SCHEMA = """
CREATE TABLE demo_accounts (account_id TEXT PRIMARY KEY, handle_lookup TEXT, created_at TSZ);
CREATE TABLE recognized_devices (device_id TEXT PRIMARY KEY, platform TEXT, status TEXT,
                                 created_at TSZ, last_seen_at TSZ);
CREATE TABLE app_installations (installation_id TEXT PRIMARY KEY, device_id TEXT,
                                registration_method TEXT, created_at TSZ, device_confirmed_at TSZ);
CREATE TABLE device_account_links (device_id TEXT, account_id TEXT, first_installation_id TEXT,
                                   first_seen_at TSZ, last_seen_at TSZ,
                                   PRIMARY KEY (device_id, account_id));
CREATE TABLE integrity_reports (report_id TEXT PRIMARY KEY, installation_id TEXT, device_id TEXT,
                                score INTEGER, verdict TEXT, hard_block BOOLEAN, created_at TSZ,
                                evidence_quality TEXT, finding_score INTEGER, platform TEXT,
                                collector_version INTEGER, reasons TEXT, probe_results TEXT,
                                report_sha256 TEXT);
CREATE TABLE business_events (event_id TEXT PRIMARY KEY,
                              account_id TEXT NOT NULL REFERENCES demo_accounts(account_id),
                              event_type TEXT NOT NULL, occurred_at TSZ NOT NULL,
                              received_at TSZ DEFAULT CURRENT_TIMESTAMP, amount_minor INTEGER,
                              currency TEXT, outcome TEXT, subject_hash TEXT);
CREATE TABLE acceptance_lapses (acceptance_id TEXT, reason_code TEXT, source TEXT, points INTEGER,
                                account_id TEXT, installation_id TEXT, event_type TEXT,
                                occurred_at TSZ, PRIMARY KEY (acceptance_id, reason_code));
CREATE TABLE server_observations (observation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, code TEXT,
                                  account_id TEXT, device_id TEXT, installation_id TEXT,
                                  occurred_at TSZ NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE app_pins (account_id TEXT PRIMARY KEY, pin_hash BLOB,
                       failures INTEGER NOT NULL DEFAULT 0, locked_at TSZ, reset_until TSZ,
                       set_at TSZ, set_by_installation TEXT);
CREATE TABLE session_upgrade_requests (request_id TEXT PRIMARY KEY, device_id TEXT, denied_at TSZ);
"""
BUSINESS_TOKEN = "business-token-for-the-gate"


@contextmanager
def business_store(configured=True):
    """The business API over the server's own SQL on SQLite (DESIGN.md 76)."""
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(BUSINESS_LITE_SCHEMA)

    @contextmanager
    def lite_cursor(commit=False):
        yield LiteCursor(connection)
        connection.commit()

    saved = (s._cursor, s.BUSINESS_API_TOKEN_SHA256)
    s._risk_settings_cache.update(values=dict(db.settings), at=time.monotonic(),
                                  failed_at=None, error=None)
    s._cursor = lite_cursor
    s.BUSINESS_API_TOKEN_SHA256 = (
        (c.sha256_hex(BUSINESS_TOKEN.encode()),) if configured else ())
    real_unique = s.DIALECT.is_unique_violation
    s.DIALECT.is_unique_violation = lambda error: (isinstance(error, sqlite3.IntegrityError)
                                                   or real_unique(error))
    try:
        yield connection
    finally:
        s._cursor, s.BUSINESS_API_TOKEN_SHA256 = saved
        del s.DIALECT.is_unique_violation
        connection.close()


@contextmanager
def business_policy(**values):
    """Settings for a business check: the snapshot is primed, never read from
    SQLite, which has no settings table."""
    saved = dict(db.settings)
    db.settings.update({key: str(value) for key, value in values.items()})
    s._risk_settings_cache.update(values=dict(db.settings), at=time.monotonic(),
                                  failed_at=None, error=None)
    try:
        yield
    finally:
        db.settings.clear()
        db.settings.update(saved)
        s._risk_settings_cache.update(values=dict(db.settings), at=time.monotonic(),
                                      failed_at=None, error=None)


def business_call(method, path, body=None, token=BUSINESS_TOKEN, query=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    if method == "POST":
        reply = client.post(path, json=body, headers=headers)
    else:
        reply = client.get(path, query_string=query or {}, headers=headers)
    return reply.status_code, reply.get_json() or {}


def business_account(connection, handle):
    account_id = str(uuid.uuid4())
    connection.execute("INSERT INTO demo_accounts VALUES (?, ?, ?)",
                       (account_id, s._handle_lookup(handle), s._utc_now()))
    return account_id


def business_link(connection, device_id, account_id):
    now = s._utc_now()
    connection.execute("INSERT OR IGNORE INTO recognized_devices VALUES (?, 'android', 'active', ?, ?)",
                       (device_id, now, now))
    connection.execute("INSERT INTO device_account_links VALUES (?, ?, ?, ?, ?)",
                       (device_id, account_id, str(uuid.uuid4()), now, now))


@check
def the_business_api_is_off_until_configured_and_needs_its_token():
    """DESIGN.md 76: server to server only. Unconfigured, the business API does
    not exist (404); configured, it needs one of the configured tokens."""
    event = {"events": [{"event_id": "e1", "account_id": str(uuid.uuid4()), "type": "advance",
                         "occurred_at": "2026-10-01T00:00:00Z"}]}
    with business_store(configured=False):
        status, payload = business_call("POST", "/v1/business/events", event)
        expect(status == 404, "an unconfigured business API must not exist, got %s" % status)
    with business_store():
        for token in ("", "wrong-token", device_token):
            status, payload = business_call("POST", "/v1/business/events", event, token=token)
            expect(status == 401 and payload["error"]["code"] == "business_token_invalid",
                   "token %r must be refused, got %s %s" % (token[:12], status, payload))
        status, payload = business_call("POST", "/v1/business/events", event)
        expect(status == 200, "the configured token must be accepted, got %s %s" % (status, payload))


@check
def business_events_are_minimal_validated_and_recorded_once():
    """DESIGN.md 76. An event names an account by its opaque ID or a handle
    (resolved, never stored), carries short codes and an optional amount; a
    subject reference is stored only as a keyed hash; any other field, free
    text, an amount without its currency or a future time is refused; an
    event_id is recorded once; an unknown account is rejected, never created."""
    with business_store() as conn:
        alice = business_account(conn, "alice")
        good = {"event_id": "adv-1", "account_id": alice, "type": "advance_disbursed",
                "occurred_at": "2026-10-12T10:00:00+05:00", "amount_minor": 5000,
                "currency": "USD", "outcome": "ok", "subject_ref": "IBAN DE00 1234"}
        by_handle = {"event_id": "adv-2", "handle": "Alice", "type": "repayment_failed",
                     "occurred_at": "2026-10-12T11:00:00Z"}
        stranger = {"event_id": "adv-3", "handle": "nobody", "type": "advance_disbursed",
                    "occurred_at": "2026-10-12T11:00:00Z"}
        status, payload = business_call("POST", "/v1/business/events",
                                        {"events": [good, by_handle, stranger, good]})
        statuses = [r["status"] for r in payload.get("results", [])]
        expect(status == 200 and statuses == ["accepted", "accepted", "rejected", "duplicate"],
               "expected accepted, accepted, rejected, duplicate; got %s %s" % (status, payload))
        rows = conn.execute("SELECT event_id, account_id, subject_hash FROM business_events "
                            "ORDER BY event_id").fetchall()
        expect([r[1] for r in rows] == [alice, alice] and rows[0][2]
               and len(rows[0][2]) == 64 and "1234" not in rows[0][2],
               "events must land on the account, the subject only as a keyed hash: %s" % rows)
        for change, field in (({"note": "free text"}, "note"),
                              ({"outcome": "Paid in full"}, "outcome"),
                              ({"type": "Advance"}, "type"),
                              ({"currency": None}, "currency"),
                              ({"occurred_at": "2099-01-01T00:00:00Z"}, "occurred_at"),
                              ({"occurred_at": "2026-10-12T10:00:00"}, "occurred_at"),
                              ({"handle": "alice"}, "account_id")):
            event = dict(good, event_id="bad", **change)
            if change.get("currency", 1) is None:
                event.pop("currency")
            status, payload = business_call("POST", "/v1/business/events", {"events": [event]})
            expect(status == 400 and payload["error"]["details"]["field"] == field,
                   "%s must be refused on %s, got %s %s" % (change, field, status, payload))
        with business_policy(business_event_types="advance_disbursed"):
            status, payload = business_call("POST", "/v1/business/events", {"events": [
                dict(by_handle, event_id="adv-4")]})
            expect(status == 400, "a type outside the DBA's list must be refused, got %s" % status)


@check
def the_business_graph_combines_links_and_events():
    """DESIGN.md 76. From one account the graph walks to its phones and the
    accounts on them, to the DBA's depth and node cap, with each account's
    events by window and amount, how many other accounts share a subject,
    each phone's latest integrity, and component totals."""
    with business_store() as conn:
        alice, bob, carol = (business_account(conn, name) for name in ("alice", "bob", "carol"))
        phone = str(uuid.uuid4())
        business_link(conn, phone, alice)
        business_link(conn, phone, bob)
        now = s._utc_now()
        events = [{"event_id": "a1", "account_id": alice, "type": "repayment_failed",
                   "occurred_at": s._iso_z(now - timedelta(hours=2)), "subject_ref": "payee-9"},
                  {"event_id": "a2", "account_id": alice, "type": "repayment_failed",
                   "occurred_at": s._iso_z(now - timedelta(days=3)), "amount_minor": 700,
                   "currency": "USD"},
                  {"event_id": "b1", "account_id": bob, "type": "repayment_failed",
                   "occurred_at": s._iso_z(now - timedelta(days=10))},
                  {"event_id": "c1", "account_id": carol, "type": "advance_disbursed",
                   "occurred_at": s._iso_z(now - timedelta(days=1)), "subject_ref": "payee-9"}]
        status, payload = business_call("POST", "/v1/business/events", {"events": events})
        expect(status == 200 and payload["accepted"] == 4, "setup failed: %s %s" % (status, payload))
        status, graph = business_call("GET", "/v1/business/graph", query={"account_id": alice})
        accounts = {a["account_id"]: a for a in graph.get("accounts", [])}
        alice_events = (accounts.get(alice) or {}).get("business_events", {}).get("repayment_failed", {})
        expect(status == 200 and set(accounts) == {alice, bob}
               and [d["device_id"] for d in graph["devices"]] == [phone]
               and len(graph["links"]) == 2 and graph["truncated"] is False
               and alice_events.get("1d") == 1 and alice_events.get("7d") == 2
               and alice_events.get("30d") == 2 and alice_events.get("amount_30d") == {"USD": 700}
               and accounts[alice]["accounts_sharing_a_subject_30d"] == 1
               and graph["component_business_events_30d"]["repayment_failed"]
               == {"events_30d": 3, "accounts_30d": 2},
               "the graph must combine links and events: %s %s" % (status, graph))
        with business_policy(business_graph_depth=1):
            status, graph = business_call("GET", "/v1/business/graph", query={"handle": "alice"})
            expect({a["account_id"] for a in graph["accounts"]} == {alice} and graph["devices"],
                   "depth 1 stops at the account's phones: %s" % graph)
        with business_policy(business_graph_max_nodes=2):
            status, graph = business_call("GET", "/v1/business/graph", query={"device_id": phone})
            expect(graph["truncated"] is True and len(graph["accounts"]) + len(graph["devices"]) == 2,
                   "the node cap must cut and say so: %s" % graph)
        counts = s._business_event_counts(phone, alice)
        expect(counts == {"account": {"repayment_failed": 2},
                          "device": {"repayment_failed": 3}},
               "decision context counts by account and by phone: %s" % counts)


@check
def the_business_graph_carries_what_the_server_saw():
    """DESIGN.md 77: the measurements are the business's to act on. Each
    account and phone in the graph carries the server's own observations by
    kind and window -- a phone's denied approval requests among them -- and
    nothing older than 30 days."""
    with business_store() as conn:
        alice = business_account(conn, "alice")
        phone, other = str(uuid.uuid4()), str(uuid.uuid4())
        business_link(conn, phone, alice)
        now = s._utc_now()
        for kind, device_id, account_id, age in (
                ("sign_in_failed", other, alice, timedelta(hours=2)),
                ("sign_in_failed", other, alice, timedelta(days=3)),
                ("sign_in_failed", other, alice, timedelta(days=40)),
                ("stepup_failed", phone, alice, timedelta(days=10)),
                ("sign_in_unknown_account", phone, None, timedelta(hours=1))):
            conn.execute("INSERT INTO server_observations VALUES (?, ?, 'test', ?, ?, ?, ?)",
                         (str(uuid.uuid4()), kind, account_id, device_id, str(uuid.uuid4()),
                          now - age))
        conn.execute("INSERT INTO session_upgrade_requests VALUES (?, ?, ?)",
                     (str(uuid.uuid4()), phone, now - timedelta(days=2)))
        status, graph = business_call("GET", "/v1/business/graph", query={"account_id": alice})
        account_node = graph["accounts"][0]["server_observations"]
        device_node = graph["devices"][0]["server_observations"]
        expect(status == 200 and account_node == {
            "sign_in_failed": {"1d": 1, "7d": 2, "30d": 2},
            "stepup_failed": {"1d": 0, "7d": 0, "30d": 1}},
            "the account's observations, from every phone: %s" % account_node)
        expect(device_node == {
            "stepup_failed": {"1d": 0, "7d": 0, "30d": 1},
            "sign_in_unknown_account": {"1d": 1, "7d": 1, "30d": 1},
            "approval_denied": {"1d": 0, "7d": 1, "30d": 1}},
            "the phone's observations, for every account: %s" % device_node)


@check
def acceptance_lapses_are_read_in_order():
    """DESIGN.md 76: the business reads when an approved session met a new
    reason, oldest first, paging with next_cursor -- which carries the last
    row's time and key, so rows sharing one instant at a page edge are never
    skipped; since= is exclusive."""
    with business_store() as conn:
        base = s._utc_now() - timedelta(hours=3)
        tie = base + timedelta(minutes=20)
        acc_a, acc_b = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
        for when, acc, code in ((base + timedelta(minutes=10), acc_a, "android_process_traced"),
                                (tie, acc_a, "request_rate_anomaly"),
                                (tie, acc_b, "android_root_artifact"),
                                (base + timedelta(minutes=30), acc_b, "new_device")):
            conn.execute("INSERT INTO acceptance_lapses VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (acc, code, "integrity", 50, "acct", "inst", "refresh", when))
        seen, cursor_ = [], None
        for _ in range(5):
            query = {"limit": "2"}
            if cursor_:
                query["cursor"] = cursor_
            status, page = business_call("GET", "/v1/business/acceptance-lapses", query=query)
            expect(status == 200, "lapse page failed: %s %s" % (status, page))
            if not page["lapses"]:
                break
            seen += [l["reason_code"] for l in page["lapses"]]
            cursor_ = page["next_cursor"]
        expect(seen == ["android_process_traced", "request_rate_anomaly", "android_root_artifact",
                        "new_device"],
               "every lapse once, oldest first, ties kept across the page edge: %s" % seen)
        status, page = business_call("GET", "/v1/business/acceptance-lapses",
                                     query={"since": s._iso_z(tie)})
        expect([l["reason_code"] for l in page["lapses"]] == ["new_device"],
               "since= is exclusive: %s" % page)


# ---------------------------------------------------------------------------
# The server's own observations (DESIGN.md 77)
# ---------------------------------------------------------------------------


class _DepthCursor(object):
    """Notes how many units of work were open at each observation insert."""

    def __init__(self, inner, depth, seen):
        self.inner, self.depth, self.seen = inner, depth, seen

    def execute(self, sql, params=None):
        if " ".join(sql.split()).startswith("INSERT INTO server_observations"):
            self.seen.append((self.depth[0], tuple(params)))
        return self.inner.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self.inner, name)


@contextmanager
def unit_depths():
    """Each server_observations insert as (open units, params). Depth 1 is a
    unit of its own: the refused one had already closed (and rolled back)."""
    depth, seen, real = [0], [], s._cursor

    @contextmanager
    def tracked(commit=False):
        depth[0] += 1
        try:
            with real(commit=commit) as inner:
                yield _DepthCursor(inner, depth, seen)
        finally:
            depth[0] -= 1

    s._cursor = tracked
    try:
        yield seen
    finally:
        s._cursor = real


def _observed(seen):
    """(kind, code, account, device, installation) of each insert."""
    return [params[1:] for _, params in seen]


@check
def failed_sign_ins_are_recorded_against_the_account_and_the_phone():
    """DESIGN.md 77. A wrong password is the server's own observation, written
    against the account and the phone whose key asked, in a unit of its own; a
    handle no account has is recorded without an account; the answer is the
    same 401 either way. A right password records nothing, and a record that
    cannot be written leaves the 401 a 401."""
    import bcrypt as _bcrypt
    path = "/v1/accounts/login"
    hashed = _bcrypt.hashpw(b"Passw0rd123", _bcrypt.gensalt(4))

    def login(password, handle="someone"):
        raw = encode({"handle": handle, "password": password})
        return client.post(path, data=raw, headers=access_headers("POST", path, raw, device_token))

    try:
        with elevated_integrity(), policy(), unit_depths() as seen:
            s._latest_integrity_state = _verdict_state("trusted")
            s._evaluate_risk_policy = lambda *a, **k: {
                "effective_action": "allow", "recommended_action": "allow",
                "context": {"device_account_count": 0, "account_device_count": 1}}
            db.link_counts = (0, 1)
            db.account_row = (account, hashed)
            reply = login("not-the-password")
            expect(reply.status_code == 401 and error_code(reply) == "invalid_credentials",
                   "a wrong password must stay 401, got %s %s" % (reply.status_code, error_code(reply)))
            db.account_row = None
            reply = login("anything-at-all", handle="nobody-has-this")
            expect(reply.status_code == 401 and error_code(reply) == "invalid_credentials",
                   "an unknown handle must answer the same 401, got %s" % reply.status_code)
            expect(_observed(seen) == [
                ("sign_in_failed", "invalid_credentials", account, inst.device_id, inst.installation_id),
                ("sign_in_unknown_account", "invalid_credentials", None, inst.device_id,
                 inst.installation_id)],
                "each failure is recorded against the account and the phone: %s" % _observed(seen))
            expect([depth for depth, _ in seen] == [1, 1],
                   "each record is a unit of its own, outside the refused one: %s" % seen)
            db.account_row = (account, hashed)
            reply = login("Passw0rd123")
            expect(reply.status_code == 200 and len(seen) == 2,
                   "a right password must record nothing, got %s, %d records"
                   % (reply.status_code, len(seen)))
            db.fail_observations = True
            reply = login("still-wrong")
            expect(reply.status_code == 401 and error_code(reply) == "invalid_credentials",
                   "an unwritable record must leave the 401 alone, got %s %s"
                   % (reply.status_code, error_code(reply)))
    finally:
        db.account_row, db.link_counts, db.fail_observations = None, (0, 0), False


@check
def failed_step_up_proofs_are_recorded_and_a_missing_one_is_not():
    """DESIGN.md 77. A step-up proof that does not verify -- bound to another
    body, or signed by a key that is not the step-up key -- is recorded against
    the phone with its refusal code. No proof at all (the ordinary first leg,
    after which the app asks for the screen lock) and a valid proof record
    nothing."""
    with isolated_stepup(), unit_depths() as seen:
        reply = sensitive(INTENDED, access_headers("POST", SENSITIVE, INTENDED))
        expect(reply.status_code == 403 and error_code(reply) == "stepup_required",
               "no proof: expected stepup_required, got %s %s" % (reply.status_code, error_code(reply)))
        for body_signed, signer, code in ((CHANGED, None, "stepup_binding_mismatch"),
                                          (INTENDED, inst, "stepup_signature_invalid")):
            nonce = fresh_nonce()
            head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
            head.update(stepup_headers("POST", SENSITIVE, body_signed, nonce, signer=signer))
            reply = sensitive(INTENDED, head)
            expect(reply.status_code == 403 and error_code(reply) == code,
                   "expected %s, got %s %s" % (code, reply.status_code, error_code(reply)))
        nonce = fresh_nonce()
        head = access_headers("POST", SENSITIVE, INTENDED, nonce=nonce)
        head.update(stepup_headers("POST", SENSITIVE, INTENDED, nonce))
        expect(sensitive(INTENDED, head).status_code == 200, "a valid proof must pass")
    expect(_observed(seen) == [
        ("stepup_failed", "stepup_binding_mismatch", account, inst.device_id, inst.installation_id),
        ("stepup_failed", "stepup_signature_invalid", account, inst.device_id, inst.installation_id)],
        "exactly the two failed proofs are recorded: %s" % _observed(seen))


@check
def an_exhausted_approval_budget_is_recorded_after_its_refusal():
    """DESIGN.md 77. An approval request refused because the account's hourly
    budget is spent answers 429 as before, and the refusal is recorded against
    the asking phone in a unit of its own -- after the refused transaction,
    which held the account row's lock, has closed -- once per budget period:
    asking again in the same period adds nothing, a new period adds one."""
    path = "/v1/auth/upgrade/request"
    raw = encode({"route": "approval"})
    db.observations = []
    try:
        with elevated_integrity(), policy(upgrade_other_device_approval=1), unit_depths() as seen:
            s._latest_integrity_state = _verdict_state("elevated")
            bearer = _limited_session("integrity_elevated")
            db.other_full_session = ("approver-session",)
            first_period = s._utc_now() - timedelta(minutes=50)
            for spent, oldest, status in ((3, first_period, 429), (3, first_period, 429),
                                          (2, first_period, 201),
                                          (3, s._utc_now() - timedelta(minutes=5), 429)):
                db.approval_requests_last_hour, db.budget_oldest = spent, oldest
                reply = client.post(path, data=raw, headers=access_headers("POST", path, raw,
                                                                           bearer=bearer))
                expect(reply.status_code == status,
                       "with %d requests this hour expected %s, got %s %s"
                       % (spent, status, reply.status_code, reply.get_json()))
            stored = [p[1:] for p in db.observations if p[1] == "approval_budget_exhausted"]
            expect(stored == [("approval_budget_exhausted", "upgrade_budget_exhausted",
                               account, inst.device_id, inst.installation_id)] * 2
                   and all(depth == 1 for depth, _ in seen),
                   "one record per budget period, each in its own unit: %s %s" % (stored, seen))
    finally:
        db.refresh_row, db.other_full_session, db.approval_requests_last_hour = None, None, 0
        db.budget_oldest = None


OBSERVATION_LITE_SCHEMA = """
CREATE TABLE recognized_devices (
    device_id  TEXT PRIMARY KEY,
    platform   TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TSZ NOT NULL
);
CREATE TABLE app_installations (
    installation_id         TEXT PRIMARY KEY,
    device_id               TEXT NOT NULL,
    status                  TEXT NOT NULL,
    registration_method     TEXT NOT NULL,
    registration_confidence TEXT,
    created_at              TSZ NOT NULL,
    verified_at             TSZ,
    device_confirmed_at     TSZ
);
CREATE TABLE device_account_links (
    device_id     TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    first_seen_at TSZ NOT NULL,
    PRIMARY KEY (device_id, account_id)
);
CREATE TABLE session_upgrade_requests (
    request_id TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL,
    account_id TEXT NOT NULL,
    denied_at  TSZ
);
CREATE TABLE server_observations (
    observation_id  TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    code            TEXT,
    account_id      TEXT,
    device_id       TEXT,
    installation_id TEXT,
    occurred_at     TSZ NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now'))
);
"""


class ObservationStore(object):
    """The server's own SQL for decisions on SQLite: phones, links, and what
    the server observed. Each phone's latest scan is a clean, fresh report --
    the faked clean report the cross-checks exist to see past."""

    def __init__(self):
        self.connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
        self.connection.executescript(OBSERVATION_LITE_SCHEMA)
        self.now = s._utc_now()

    def phone(self, age_days=30):
        device, installation = str(uuid.uuid4()), str(uuid.uuid4())
        created = self.now - timedelta(days=age_days)
        self.connection.execute("INSERT INTO recognized_devices VALUES (?, 'android', 'active', ?)",
                                (device, created))
        self.connection.execute(
            "INSERT INTO app_installations VALUES (?, ?, 'active', 'new_device', 'new', ?, ?, NULL)",
            (installation, device, created, created))
        return device, installation

    def reinstall(self, phone):
        """Another installation of the app on the same phone."""
        installation = str(uuid.uuid4())
        self.connection.execute(
            "INSERT INTO app_installations VALUES (?, ?, 'active', 'reinstall_hint', 'hint', ?, ?, NULL)",
            (installation, phone[0], self.now, self.now))
        return phone[0], installation

    def link(self, device, account_id, age_days):
        self.connection.execute("INSERT INTO device_account_links VALUES (?, ?, ?)",
                                (device, account_id, self.now - timedelta(days=age_days)))

    def observe(self, kind, phone, account_id=None, times=1, age_hours=0.0):
        for _ in range(times):
            self.connection.execute(
                "INSERT INTO server_observations VALUES (?, ?, 'test', ?, ?, ?, ?)",
                (str(uuid.uuid4()), kind, account_id, phone[0], phone[1],
                 self.now - timedelta(hours=age_hours)))

    def denied(self, phone, account_id, times=1):
        for _ in range(times):
            self.connection.execute("INSERT INTO session_upgrade_requests VALUES (?, ?, ?, ?)",
                                    (str(uuid.uuid4()), phone[0], account_id,
                                     self.now - timedelta(hours=1)))

    def decide(self, phone, account_id=None, pending=False, scan="fresh", memory=None,
               **settings):
        """The real _evaluate_risk_policy, not persisted, under these settings,
        with the latest scan fresh and clean (or "missing", or "stale") and
        the device memory given."""
        values = dict(db.settings, **{key: str(value) for key, value in settings.items()})
        saved = (s._cursor, s._latest_integrity_state, s._device_integrity_memory)
        connection = self.connection

        @contextmanager
        def lite_cursor(commit=False):
            yield LiteCursor(connection)
            connection.commit()

        s._risk_settings_cache.update(values=values, at=time.monotonic(), failed_at=None, error=None)
        s._cursor = lite_cursor
        s._latest_integrity_state = lambda iid: (
            None if scan == "missing"
            else {"score": 0, "verdict": "trusted", "fresh": scan == "fresh"})
        s._device_integrity_memory = lambda did, iid: memory
        try:
            return s._evaluate_risk_policy("account_login", phone[0], phone[1], account_id=account_id,
                                           account_link_pending=pending, persist=False)
        finally:
            s._cursor, s._latest_integrity_state, s._device_integrity_memory = saved
            s._risk_settings_cache.update(values=dict(db.settings), at=time.monotonic(),
                                          failed_at=None, error=None)


def _cross(decision):
    return {r["code"]: (r["points"], r.get("count")) for r in decision["reasons"]
            if r["code"] in {rule[0] for rule in s._CROSS_CHECK_RULES}}


@check
def what_the_server_saw_is_measured_always_and_scored_only_when_enabled():
    """DESIGN.md 77. Reproduced first: before 019 a phone with a faked clean
    report signed in to an account right after other phones had failed its
    password five times, and the decision held no trace of them. Now every
    decision carries the counts; with cross_checks_enabled off (the owner's
    default) nothing scores, and on, the DBA's counts and points apply."""
    store = ObservationStore()
    acct = str(uuid.uuid4())
    newcomer = store.phone(age_days=0)
    for _ in range(5):
        store.observe("sign_in_failed", store.phone(), acct)
    observe_only = store.decide(newcomer, acct, pending=True)
    measured = observe_only["context"]["server_observations"]
    expect(measured["account"]["sign_in_failed"] == 5
           and measured["account"]["sign_in_failed_elsewhere"] == 5
           and measured["account"]["sign_in_failed_installations"] == 5
           and measured["newcomer"]["sign_in_failed_elsewhere_before"] == 5
           and measured["scored"] is False and measured["window_hours"] == 24,
           "the decision must carry what the server saw: %s" % measured)
    expect(not _cross(observe_only) and observe_only["score"] == 10,
           "observe first: nothing may score while cross_checks_enabled is off, got %s %s"
           % (observe_only["score"], observe_only["reasons"]))
    scored = store.decide(newcomer, acct, pending=True, cross_checks_enabled=1)
    expect(_cross(scored) == {"account_sign_in_failures_elsewhere": (30, 5)}
           and scored["score"] == 40,
           "enabled, five failures from elsewhere add the owner's default +30: %s"
           % scored["reasons"])
    tuned = store.decide(newcomer, acct, pending=True, cross_checks_enabled=1,
                         account_sign_in_failures_elsewhere_count=6)
    expect(not _cross(tuned), "a count the DBA raised past five must not fire: %s" % tuned["reasons"])
    tuned = store.decide(newcomer, acct, pending=True, cross_checks_enabled=1,
                         account_sign_in_failures_elsewhere_points=60)
    expect(_cross(tuned) == {"account_sign_in_failures_elsewhere": (60, 5)}
           and tuned["recommended_action"] == "review",
           "the DBA's points apply: %s" % tuned["reasons"])
    off = store.decide(newcomer, acct, pending=True, cross_checks_enabled=1,
                       account_sign_in_failures_elsewhere_count=0)
    expect(not _cross(off), "a count of 0 switches the rule off: %s" % off["reasons"])
    store.observe("sign_in_failed", store.phone(), acct, times=3, age_hours=30)
    later = store.decide(newcomer, acct, pending=True, cross_checks_enabled=1)
    expect(later["context"]["server_observations"]["account"]["sign_in_failed"] == 5,
           "failures older than the window must not count: %s"
           % later["context"]["server_observations"])


@check
def an_accounts_failures_judge_a_newcomer_never_a_phone_it_already_used():
    """DESIGN.md 77, the false-positive rule first. A user mistyping on their
    own phone is not counted against anyone -- nor after reinstalling the app
    there: the account's rule counts other phones only. Failures someone causes on an account never restrict a
    phone that was there before them -- long-standing, or the phone that opened
    the account this morning. Only a phone that joined after them, or is
    joining now, is judged, by the failures in the window before it joined."""
    store = ObservationStore()
    acct = str(uuid.uuid4())
    owner, opener, late, joining = (store.phone(), store.phone(), store.phone(),
                                    store.phone(age_days=0))
    store.link(owner[0], acct, age_days=200)
    store.link(opener[0], acct, age_days=0.5)
    store.observe("sign_in_failed", store.reinstall(joining), acct, times=4)
    store.observe("sign_in_failed", joining, acct, times=5)
    mine = store.decide(joining, acct, pending=True, cross_checks_enabled=1)
    expect(mine["context"]["server_observations"]["newcomer"]["sign_in_failed_elsewhere_before"]
           == 0 and not _cross(mine),
           "nine mistypes on the phone now signing in, four of them before a reinstall, must "
           "not count: %s" % mine["reasons"])
    for _ in range(5):
        store.observe("sign_in_failed", store.phone(), acct, age_hours=2)
    store.link(late[0], acct, age_days=1.0 / 24)
    incumbent = store.decide(owner, acct, cross_checks_enabled=1)
    expect(incumbent["context"]["server_observations"]["newcomer"] is None
           and not _cross(incumbent),
           "a phone the account used long before must not be judged: %s" % incumbent["reasons"])
    opened = store.decide(opener, acct, cross_checks_enabled=1)
    expect(opened["context"]["server_observations"]["newcomer"]["sign_in_failed_elsewhere_before"]
           == 0 and not _cross(opened),
           "the phone that opened the account before the failures must not be judged: %s"
           % opened["context"]["server_observations"])
    for phone, pending in ((late, False), (joining, True)):
        decision = store.decide(phone, acct, pending=pending, cross_checks_enabled=1)
        expect(_cross(decision).get("account_sign_in_failures_elsewhere") == (30, 5),
               "a phone that joined after five failures is judged: %s" % decision["reasons"])


@check
def a_phones_own_observations_score_against_that_phone():
    """DESIGN.md 77. Wrong passwords to three accounts, sign-ins to accounts
    that do not exist, step-up proofs that did not verify, denied approval
    requests, an exhausted approval budget and re-enrolled step-up keys each
    count against the phone that caused them -- and only that phone."""
    store = ObservationStore()
    victims = [str(uuid.uuid4()) for _ in range(3)]
    stuffer, clean_phone = store.phone(), store.phone()
    for victim in victims:
        store.observe("sign_in_failed", stuffer, victim)
    store.observe("sign_in_unknown_account", stuffer, times=5)
    store.observe("stepup_failed", stuffer, victims[0], times=3)
    store.denied(stuffer, victims[0])
    store.observe("approval_budget_exhausted", stuffer, victims[0], times=2)
    store.observe("stepup_reenrolled", stuffer, victims[0], times=2)
    decision = store.decide(stuffer, victims[0], cross_checks_enabled=1)
    expect(_cross(decision) == {
        "device_sign_in_failures_many_accounts": (60, 3),
        "device_sign_in_unknown_accounts": (30, 5),
        "device_stepup_failures": (30, 3),
        "device_approvals_denied": (30, 1),
        "device_approval_budget_exhausted": (30, 2),
        "device_stepup_reenrolments": (30, 2)},
        "each of the phone's own rules at the owner's defaults: %s" % decision["reasons"])
    expect(decision["recommended_action"] == "block",
           "together they are well past the block band: %s" % decision["score"])
    expect(not _cross(store.decide(clean_phone, cross_checks_enabled=1)),
           "another phone is untouched")


@check
def a_denied_phone_is_held_limited_and_never_blocked_by_the_denial_alone():
    """Owner decision of 2026-10-14 (DESIGN.md 77). With the default effect,
    limit, a phone the account's other phone denied is held at review -- a
    limited session -- for the window: scoring low, it is raised to review;
    scoring high, the denial's points never take it to block. Whatever blocks
    without the denial still blocks. With effect points the points are simply
    added, and can block."""
    store = ObservationStore()
    acct = str(uuid.uuid4())
    quiet, busy, blocked = store.phone(), store.phone(), store.phone()
    for phone in (quiet, busy, blocked):
        store.denied(phone, acct)
    store.observe("sign_in_unknown_account", busy, times=5)
    store.observe("stepup_failed", busy, str(uuid.uuid4()), times=3)
    for victim in (str(uuid.uuid4()) for _ in range(3)):
        store.observe("sign_in_failed", blocked, victim)
    store.observe("sign_in_unknown_account", blocked, times=5)
    for phone, action, score, held in ((quiet, "review", 30, True), (busy, "review", 90, True),
                                       (blocked, "block", 120, False)):
        decision = store.decide(phone, acct, cross_checks_enabled=1)
        expect(decision["recommended_action"] == action and decision["score"] == score
               and decision["context"]["held_by_denial"] is held
               and _cross(decision).get("device_approvals_denied") == (30, 1),
               "limit: expected %s at %d (held %s), got %s at %s: %s"
               % (action, score, held, decision["recommended_action"], decision["score"],
                  decision["reasons"]))
    for phone, action in ((quiet, "step_up"), (busy, "block")):
        decision = store.decide(phone, acct, cross_checks_enabled=1,
                                device_approvals_denied_effect="points")
        expect(decision["recommended_action"] == action
               and decision["context"]["held_by_denial"] is False,
               "points: expected %s, got %s" % (action, decision["recommended_action"]))


@check
def what_one_account_did_on_a_shared_phone_never_counts_against_another():
    """DESIGN.md 77, found in review: two people share a phone (the owner's
    own legitimate case). Person A's new sign-in is denied by A's other phone,
    A exhausts A's approval budget and re-enrols A's step-up key twice; person
    B, long established on the same phone, carries none of it -- no denial
    hold, no points -- while A's decisions carry all three."""
    store = ObservationStore()
    alice, bob = str(uuid.uuid4()), str(uuid.uuid4())
    shared = store.phone()
    store.link(shared[0], bob, age_days=200)
    store.link(shared[0], alice, age_days=0.1)
    store.denied(shared, alice)
    store.observe("approval_budget_exhausted", shared, alice, times=2)
    store.observe("stepup_reenrolled", shared, alice, times=2)
    mine = store.decide(shared, alice, cross_checks_enabled=1)
    expect(_cross(mine) == {"device_approvals_denied": (30, 1),
                            "device_approval_budget_exhausted": (30, 2),
                            "device_stepup_reenrolments": (30, 2)},
           "the account that was denied carries its own events: %s" % mine["reasons"])
    theirs = store.decide(shared, bob, cross_checks_enabled=1)
    expect(not _cross(theirs) and theirs["context"]["held_by_denial"] is False
           and theirs["context"]["server_observations"]["device"]["approval_denied"] == 1,
           "the other account on the phone must carry none of it, though the phone's own "
           "measurements show it: %s %s" % (theirs["reasons"],
                                            theirs["context"]["server_observations"]))


@check
def a_token_used_without_its_key_is_recorded_once_per_token():
    """DESIGN.md 77, owner decision of 2026-10-14. A token presented with a
    proof its installation's key did not sign -- an access token or a refresh
    token copied to another phone -- is refused as before (401
    invalid_installation_signature) and recorded against the account and the
    phone it belongs to, once per token: three tries add one row, a second
    token one more, so a stolen token cannot flood the table. A signed request
    sent again is recorded once per request (access_proof_replay). Nothing is
    recorded for the public installation verify step, where anyone may name
    any installation."""
    thief = c.Installation()
    db.observations = []
    with isolated_stepup():
        for bearer in (token, token, token, None):
            if bearer is None:
                with s.app.app_context():
                    bearer = s.create_access_token(identity=account, additional_claims={
                        "role": "account", "iid": inst.installation_id, "did": inst.device_id,
                        "sid": str(uuid.uuid4()), "family": str(uuid.uuid4())})
            reply = client.get("/v1/account/me", headers=access_headers(
                "GET", "/v1/account/me", bearer=bearer, signer=thief))
            expect(reply.status_code == 401 and error_code(reply) == "invalid_installation_signature",
                   "a token without its key must stay a 401, got %s %s"
                   % (reply.status_code, error_code(reply)))
        stolen = [p[1:] for p in db.observations if p[1] == "token_without_key"]
        expect(stolen == [("token_without_key", "invalid_installation_signature", account,
                           inst.device_id, inst.installation_id)] * 2,
               "one row per stolen token, against its own account and phone: %s" % stolen)
        head = access_headers("GET", "/v1/account/me")
        expect(client.get("/v1/account/me", headers=head).status_code == 200, "setup: a valid request")
        for _ in range(2):
            reply = client.get("/v1/account/me", headers=head)
            expect(reply.status_code == 401 and error_code(reply) == "access_proof_replay",
                   "a replay must stay a 401, got %s %s" % (reply.status_code, error_code(reply)))
        replays = [p[1:3] for p in db.observations if p[1] == "request_replayed"]
        expect(replays == [("request_replayed", "access_proof_replay")],
               "one row per replayed request: %s" % replays)
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    with s.app.app_context():
        refresh = s.create_refresh_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": session, "family": family})
    db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                      s._utc_now() + s.REFRESH_TOKEN_LIFETIME, None, "full", None, None, None)
    try:
        for _ in range(2):
            challenge = client.post("/v1/auth/refresh/challenge",
                                    headers={"Authorization": "Bearer " + refresh}).get_json()
            reply = client.post("/v1/auth/refresh", headers={"Authorization": "Bearer " + refresh},
                                json={"challenge_id": challenge["challenge_id"],
                                      "payload": challenge["payload"],
                                      "signature": thief.sign_b64(challenge["payload"])})
            expect(reply.status_code == 401 and error_code(reply) == "invalid_installation_signature",
                   "a refresh token without its key must stay a 401, got %s %s"
                   % (reply.status_code, error_code(reply)))
    finally:
        db.refresh_row = None
    stolen = [p for p in db.observations if p[1] == "token_without_key"]
    expect(len(stolen) == 3 and stolen[-1][3] == account,
           "a stolen refresh token is recorded once too: %s" % stolen)
    before = len(db.observations)
    payload = client.post("/v1/installations/challenge",
                          json={"installation_id": inst.installation_id}).get_json()
    client.post("/v1/installations/verify", json={
        "installation_id": inst.installation_id, "challenge_id": payload["challenge_id"],
        "payload": payload["payload"], "signature": thief.sign_b64(payload["payload"])})
    expect(len(db.observations) == before,
           "the public verify step must record nothing: %s" % db.observations[before:])


# ---------------------------------------------------------------------------
# The app PIN and the DBA's step-up method (DESIGN.md 78)
# ---------------------------------------------------------------------------

PIN = "246810"


def pin_store(pin=PIN, failures=0, locked=False):
    """This account's app PIN in the fixture, as the server would store it."""
    db.app_pins = {account: {
        "hash": s._bcrypt_hash_bytes(s._app_pin_material(account, pin)),
        "failures": failures, "locked_at": s._utc_now() if locked else None, "by": None}}


def pin_call(path, body, bearer=None, stepup=False, pin=None):
    raw = encode(body)
    nonce = fresh_nonce()
    head = access_headers("POST", path, raw, bearer=bearer, nonce=nonce)
    if stepup:
        head.update(stepup_headers("POST", path, raw, nonce, bearer=bearer))
    if pin is not None:
        head["X-App-PIN"] = pin
    return client.post(path, data=raw, headers=head)


def _full_session():
    """A full access token and the refresh-session row it belongs to."""
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    with s.app.app_context():
        bearer = s.create_access_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": session, "family": family, "scope": "full"})
    db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                      s._utc_now() + s.REFRESH_TOKEN_LIFETIME, None, "full", None, None, None)
    return bearer


def _needs(reply):
    return (((reply.get_json() or {}).get("error") or {}).get("details") or {}).get(
        "step_up", {}).get("needs")


@check
def the_step_up_method_is_the_dbas_choice():
    """DESIGN.md 78 (owner, 2026-10-14: build every option, the DBA chooses).
    On a step-up path, screen_lock needs the screen-lock key's proof, app_pin
    the app PIN the server checks, screen_lock_and_app_pin both; a refusal for
    a missing factor names every factor needed. app_pin_required_paths add the
    PIN on top of any method. The interim default is screen_lock."""
    pin_store()
    try:
        with isolated_stepup():
            expect(s._stepup_factors() == (True, False), "the fixture runs under screen_lock")
            with real_policy_reader():
                db.settings.pop("stepup_method")
                s._risk_settings_cache.update(at=0.0, values=None, failed_at=None, error=None)
                expect(s._stepup_factors() == (False, True),
                       "without the row the owner's default, the app PIN, applies")
            for method, factors, outcome in (
                    ("screen_lock", {"stepup": True}, 200),
                    ("screen_lock", {"pin": PIN}, ("stepup_required", ["screen_lock"])),
                    ("app_pin", {"pin": PIN}, 200),
                    ("app_pin", {"stepup": True}, ("app_pin_required", ["app_pin"])),
                    ("screen_lock_and_app_pin", {"stepup": True, "pin": PIN}, 200),
                    ("screen_lock_and_app_pin", {"stepup": True},
                     ("app_pin_required", ["screen_lock", "app_pin"])),
                    ("screen_lock_and_app_pin", {"pin": PIN},
                     ("stepup_required", ["screen_lock", "app_pin"]))):
                with policy(stepup_method=method):
                    reply = pin_call(SENSITIVE, {"amount": 1}, **factors)
                if outcome == 200:
                    payload = reply.get_json() or {}
                    expect(reply.status_code == 200 and payload.get("step_up") == "verified"
                           and payload.get("app_pin") == ("verified" if "pin" in factors
                                                          else "not_required"),
                           "%s with %s must pass, got %s %s"
                           % (method, sorted(factors), reply.status_code, payload))
                else:
                    expect(reply.status_code == 403 and error_code(reply) == outcome[0]
                           and _needs(reply) == outcome[1],
                           "%s with %s must answer %s naming %s, got %s %s %s"
                           % (method, sorted(factors), outcome[0], outcome[1],
                              reply.status_code, error_code(reply), _needs(reply)))
            # Neither factor is required where it is itself replaced: a dead key
            # or a locked PIN could otherwise never be.
            with policy(stepup_method="screen_lock_and_app_pin",
                        stepup_required_paths="/v1/installations/stepup-key,/v1/account/app-pin"):
                for path, needs in (("/v1/installations/stepup-key", ["app_pin"]),
                                    ("/v1/account/app-pin", ["screen_lock"])):
                    with s.app.test_request_context(path, method="POST"):
                        try:
                            s._enforce_step_up(inst.installation_id, account)
                            got = None
                        except s.ApiProblem as problem:
                            got = ((problem.details or {}).get("step_up") or {}).get("needs")
                    expect(got == needs, "on %s only %s may be required, got %s"
                           % (path, needs, got))
            with policy(app_pin_required_paths=ECHO):
                reply = pin_call(ECHO, {"x": 1})
                expect(reply.status_code == 403 and error_code(reply) == "app_pin_required",
                       "a path listed for the PIN needs it under screen_lock too, got %s %s"
                       % (reply.status_code, error_code(reply)))
                expect(pin_call(ECHO, {"x": 1}, pin=PIN).status_code == 200,
                       "and passes with it")
    finally:
        db.app_pins = {}


class _CountingBcrypt(object):
    """bcrypt, noting how many units of work were open at each comparison."""

    def __init__(self, real, depth, order):
        self.real, self.depth, self.order = real, depth, order

    def checkpw(self, password, hashed):
        self.order.append(("bcrypt", self.depth[0]))
        return self.real.checkpw(password, hashed)

    def __getattr__(self, name):
        return getattr(self.real, name)


@check
def an_app_pin_attempt_is_claimed_before_it_is_compared():
    """DESIGN.md 78. Each attempt is claimed by one atomic UPDATE before the
    PIN is compared, and bcrypt runs outside any unit of work (on SQL Server a
    unit holds the worker's lock); wrong PINs count down, the last one locks
    the PIN -- which then refuses even the right PIN -- and each wrong PIN is
    the server's own observation. A new PIN set with the password unlocks it."""
    import bcrypt as _bcrypt
    pin_store()
    db.observations = []
    depth, order, real_cursor, real_bcrypt = [0], [], s._cursor, s.bcrypt

    @contextmanager
    def tracked(commit=False):
        depth[0] += 1
        try:
            with real_cursor(commit=commit) as inner:
                yield _ClaimCursor(inner, depth, order)
        finally:
            depth[0] -= 1

    s._cursor, s.bcrypt = tracked, _CountingBcrypt(real_bcrypt, depth, order)
    db.password_hash = _bcrypt.hashpw(b"Passw0rd123", _bcrypt.gensalt(4))
    try:
        with isolated_stepup(), policy(stepup_method="app_pin", app_pin_max_failures=3):
            answers = []
            for _ in range(3):
                reply = pin_call(SENSITIVE, {"amount": 1}, pin="135799")
                error = (reply.get_json() or {}).get("error") or {}
                answers.append((error_code(reply), (error.get("details") or {}).get("attempts_left")))
            expect(answers == [("app_pin_invalid", 2), ("app_pin_invalid", 1),
                               ("app_pin_locked", None)],
                   "three wrong PINs with a maximum of 3: %s" % answers)
            claims_then_compares = [kind for kind, _ in order if kind in ("claim", "bcrypt")]
            expect(claims_then_compares[:2] == ["claim", "bcrypt"]
                   and all(d == 0 for kind, d in order if kind == "bcrypt"),
                   "the attempt must be claimed first, and bcrypt run outside any unit: %s"
                   % order)
            reply = pin_call(SENSITIVE, {"amount": 1}, pin=PIN)
            expect(error_code(reply) == "app_pin_locked",
                   "a locked PIN refuses even the right PIN, got %s" % error_code(reply))
            failed = [p[2] for p in db.observations if p[1] == "app_pin_failed"]
            expect(failed == ["app_pin_invalid", "app_pin_invalid", "app_pin_locked"],
                   "each wrong PIN is recorded: %s" % failed)
            reply = pin_call("/v1/account/app-pin", {"password": "Passw0rd123", "pin": PIN},
                             bearer=_full_session())
            expect(reply.status_code == 200, "a new PIN with the password: %s %s"
                   % (reply.status_code, reply.get_json()))
            expect(pin_call(SENSITIVE, {"amount": 1}, pin=PIN).status_code == 200,
                   "the new PIN unlocks")
    finally:
        s._cursor, s.bcrypt = real_cursor, real_bcrypt
        db.app_pins, db.password_hash, db.refresh_row = {}, None, None


class _ClaimCursor(_DepthCursor):
    def execute(self, sql, params=None):
        if " ".join(sql.split()).startswith("UPDATE app_pins SET failures = failures + 1"):
            self.seen.append(("claim", self.depth[0]))
        return self.inner.execute(sql, params)


@check
def only_a_full_session_with_the_password_sets_an_app_pin():
    """DESIGN.md 78. A limited session never sets a PIN; a full one needs the
    account password now (a wrong one is a failed sign-in, recorded) and a
    PIN of the DBA's length. Only a verifier is stored -- bcrypt over an HMAC
    keyed by the root secret, so neither the PIN nor its plain hash checks
    against it -- and the change is recorded. Setting a PIN never needs one,
    or a locked PIN could never be replaced."""
    import bcrypt as _bcrypt
    db.app_pins, db.observations = {}, []
    db.password_hash = _bcrypt.hashpw(b"Passw0rd123", _bcrypt.gensalt(4))
    path = "/v1/account/app-pin"
    try:
        with isolated_stepup():
            reply = pin_call(path, {"password": "Passw0rd123", "pin": PIN},
                             bearer=_limited_session("integrity_elevated"))
            expect(reply.status_code == 403 and error_code(reply) == "session_limited",
                   "a limited session must not set a PIN, got %s %s"
                   % (reply.status_code, error_code(reply)))
            with policy(limited_session_paths=path):
                reply = pin_call(path, {"password": "Passw0rd123", "pin": PIN},
                                 bearer=_limited_session("integrity_elevated"))
            expect(reply.status_code == 403 and error_code(reply) == "full_session_required",
                   "nor where a DBA lets limited sessions reach the path, got %s %s"
                   % (reply.status_code, error_code(reply)))
            full = _full_session()
            reply = pin_call(path, {"password": "Wrong-Passw0rd", "pin": PIN}, bearer=full)
            expect(reply.status_code == 401 and error_code(reply) == "invalid_credentials"
                   and [p[1:3] for p in db.observations]
                   == [("sign_in_failed", "app_pin_set_invalid_credentials")],
                   "a wrong password is refused and recorded: %s %s"
                   % (reply.status_code, db.observations))
            for bad in ("12ab56", "123", "1234567", 246810):
                reply = pin_call(path, {"password": "Passw0rd123", "pin": bad}, bearer=full)
                expect(reply.status_code == 400 and error_code(reply) == "invalid_app_pin",
                       "PIN %r must be refused, got %s %s" % (bad, reply.status_code,
                                                             error_code(reply)))
            with policy(stepup_method="app_pin", stepup_required_paths=path + "," + SENSITIVE,
                        app_pin_required_paths=path):
                reply = pin_call(path, {"password": "Passw0rd123", "pin": PIN}, bearer=full)
            expect(reply.status_code == 200 and reply.get_json()["step_up"]["app_pin_set"] is True,
                   "a full session with the password sets the PIN, and needs none to do it: "
                   "%s %s" % (reply.status_code, reply.get_json()))
            stored = db.app_pins[account]["hash"]
            expect(stored.startswith(b"$2") and PIN.encode() not in stored
                   and _bcrypt.checkpw(s._app_pin_material(account, PIN), stored)
                   and not _bcrypt.checkpw(PIN.encode(), stored),
                   "only bcrypt over the keyed HMAC may be stored: %r" % stored[:7])
            expect(db.app_pins[account]["by"] == inst.installation_id
                   and [p[1] for p in db.observations][-1] == "app_pin_set",
                   "the change is recorded with the phone that made it: %s" % db.observations)
    finally:
        db.app_pins, db.password_hash, db.refresh_row = {}, None, None


@check
def approving_and_the_same_phone_route_follow_the_method():
    """DESIGN.md 78. Approving another phone's request, and route 1 (the
    same-phone upgrade), prove the DBA's stepup_method like a step-up path:
    under app_pin the PIN, not the screen-lock key."""
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    with s.app.app_context():
        full = s.create_access_token(identity=account, additional_claims={
            "role": "account", "iid": inst.installation_id, "did": inst.device_id,
            "sid": session, "family": family, "scope": "full"})
    rid = str(uuid.uuid4())
    approve = "/v1/auth/approvals/%s/approve" % rid
    pin_store()
    try:
        with elevated_integrity(), policy(stepup_method="app_pin", upgrade_stepup_same_device=1):
            s._latest_integrity_state = _verdict_state("trusted")
            db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                              s._utc_now() + s.REFRESH_TOKEN_LIFETIME, None, "full", None,
                              None, None)
            reply = pin_call(approve, {}, bearer=full, stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "app_pin_required",
                   "under app_pin a screen-lock proof alone must not approve, got %s %s"
                   % (reply.status_code, error_code(reply)))
            reply = pin_call(approve, {}, bearer=full, pin=PIN)
            expect(reply.status_code == 200, "the PIN approves, got %s %s"
                   % (reply.status_code, reply.get_json()))
            s._latest_integrity_state = _verdict_state("elevated")
            limited = _limited_session("integrity_elevated")
            reply = pin_call("/v1/auth/upgrade", {"route": "stepup"}, bearer=limited, stepup=True)
            expect(reply.status_code == 403 and error_code(reply) == "app_pin_required",
                   "route 1 under app_pin needs the PIN, got %s %s"
                   % (reply.status_code, error_code(reply)))
            reply = pin_call("/v1/auth/upgrade", {"route": "stepup"}, bearer=limited, pin=PIN)
            expect(reply.status_code == 200 and (reply.get_json() or {}).get("scope") == "full",
                   "route 1 with the PIN upgrades, got %s %s" % (reply.status_code, reply.get_json()))
            # Offered to a phone without a step-up key when the method is the PIN
            # and one is set and not locked -- never otherwise.
            db.step_jwk = None
            offered = lambda: "stepup" in s._upgrade_routes(db, account, inst.installation_id,
                                                            ["integrity_elevated"])
            expect(offered(), "route 1 must be offered on the PIN alone under app_pin")
            db.app_pins[account]["locked_at"] = s._utc_now()
            expect(not offered(), "nor while the PIN is locked")
        with policy(upgrade_stepup_same_device=1):
            expect(not offered(), "under screen_lock a phone without a key is not offered route 1")
    finally:
        db.app_pins, db.refresh_row, db.step_jwk = {}, None, step.jwk


@check
def a_support_reset_lets_a_limited_session_set_a_pin_once():
    """DESIGN.md 79. A limited session never sets a PIN -- unless support has
    opened a reset for the account: then a limited session may set a new PIN,
    with the password, before the reset lapses. Once: the change consumes the
    reset in the same statement, so two requests that both saw it open set one
    PIN between them. A wrong password leaves the reset open, and a blocked
    phone is still refused. A row holding only a reset is no PIN: it verifies
    nothing, counts no attempt, and route 1 is not offered on it."""
    import bcrypt as _bcrypt
    db.observations = []
    db.password_hash = _bcrypt.hashpw(b"Passw0rd123", _bcrypt.gensalt(4))
    path, body = "/v1/account/app-pin", {"password": "Passw0rd123", "pin": PIN}
    real_open, real_gate, real_policy = (s._support_reset_open, s._enforce_integrity_gate,
                                         s._evaluate_risk_policy)

    def reset(minutes, pin_hash=None):
        db.app_pins = {account: {"hash": pin_hash, "failures": 0, "locked_at": None, "by": None,
                                 "reset_until": s._utc_now() + timedelta(minutes=minutes)}}

    def set_limited(password="Passw0rd123"):
        return pin_call(path, dict(body, password=password),
                        bearer=_limited_session("integrity_elevated"))

    def blocked(*args, **kwargs):
        raise s.ApiProblem("The device is blocked.", 403, "integrity_blocked")

    try:
        with isolated_stepup():
            trusted_gate, allowing = s._enforce_integrity_gate, s._evaluate_risk_policy
            reset(15)
            state = s._app_pin_state(account)
            expect(state["app_pin_set"] is False and state["app_pin_reset_open"] is True,
                   "a reset alone is not a PIN: %s" % state)
            with policy(stepup_method="app_pin", upgrade_stepup_same_device=1):
                reply = pin_call(SENSITIVE, {"amount": 1}, pin=PIN)
                expect(error_code(reply) == "app_pin_not_set"
                       and db.app_pins[account]["failures"] == 0,
                       "a reset alone verifies nothing and counts no attempt: %s %s"
                       % (error_code(reply), db.app_pins[account]))
                db.step_jwk = None
                offered = lambda: "stepup" in s._upgrade_routes(db, account, inst.installation_id,
                                                                ["integrity_elevated"])
                expect(not offered(), "nor is route 1 offered on a reset alone")
                reset(15, b"$2b$04$a-verifier")
                expect(offered(), "while a PIN that is set, with a reset open, is")
                reset(15)
                db.step_jwk = step.jwk
            reply = set_limited(password="Wrong-Passw0rd")
            expect(reply.status_code == 401 and db.app_pins[account]["reset_until"] is not None,
                   "a wrong password is refused and leaves the reset open: %s %s"
                   % (reply.status_code, error_code(reply)))
            for patch, code in (("_enforce_integrity_gate", "integrity_blocked"),
                                ("_evaluate_risk_policy", "risk_policy_blocked")):
                if patch == "_enforce_integrity_gate":
                    s._enforce_integrity_gate = blocked
                else:
                    s._evaluate_risk_policy = lambda *a, **k: {"effective_action": "block"}
                reply = set_limited()
                s._enforce_integrity_gate, s._evaluate_risk_policy = trusted_gate, allowing
                expect(reply.status_code == 403 and error_code(reply) == code
                       and db.app_pins[account]["hash"] is None,
                       "a blocked phone is refused even with a reset open, got %s %s"
                       % (reply.status_code, error_code(reply)))
            reply = set_limited()
            pin_row = db.app_pins[account]
            expect(reply.status_code == 200 and pin_row["hash"] is not None
                   and pin_row["reset_until"] is None and pin_row["by"] == inst.installation_id
                   and [p[1:3] for p in db.observations][-1]
                   == ("app_pin_set", "app_pin_set_after_support_reset"),
                   "with the reset open a limited session sets the PIN, recorded as such: "
                   "%s %s %s" % (reply.status_code, error_code(reply), db.observations[-1:]))
            reply = set_limited()
            expect(reply.status_code == 403 and error_code(reply) == "session_limited",
                   "the reset serves once, got %s %s" % (reply.status_code, error_code(reply)))
            reset(-1)
            reply = set_limited()
            expect(reply.status_code == 403 and error_code(reply) == "session_limited",
                   "a lapsed reset opens nothing, got %s %s"
                   % (reply.status_code, error_code(reply)))
            # Two requests both saw it open; the other one's change consumed it.
            original = s._bcrypt_hash_bytes(s._app_pin_material(account, "135799"))
            reset(15, original)
            db.app_pins[account]["reset_until"] = None
            s._support_reset_open = lambda account_id: True
            reply = set_limited()
            s._support_reset_open = real_open
            expect(reply.status_code == 403 and error_code(reply) == "app_pin_reset_lapsed"
                   and db.app_pins[account]["hash"] == original,
                   "the loser of two must change nothing, got %s %s"
                   % (reply.status_code, error_code(reply)))
            reset(15, original)
            reply = pin_call(path, body, bearer=_full_session())
            expect(reply.status_code == 200 and db.app_pins[account]["reset_until"] is None,
                   "a PIN set from a full session closes the reset too: %s %s"
                   % (reply.status_code, db.app_pins[account]))
    finally:
        s._support_reset_open, s._enforce_integrity_gate, s._evaluate_risk_policy = (
            real_open, real_gate, real_policy)
        db.app_pins, db.password_hash, db.refresh_row, db.step_jwk = {}, None, None, step.jwk


@check
def support_unlocks_or_resets_an_app_pin_only_as_the_dba_allows():
    """DESIGN.md 79. Support's tool, a business API caller, after verifying the
    customer, unlocks a locked app PIN -- or, where the DBA allows it, opens
    one reset for app_pin_support_reset_minutes. Off by default: both answer
    app_pin_support_disabled. Each names exactly one account, by account_id or
    handle, with the caller's own ticket reference, recorded as the server's
    observation (no phone); nothing else is accepted. Unlocking needs a PIN to
    unlock; a reset on an account without one opens a row holding only it."""
    unlock, reset = "/v1/business/app-pin/unlock", "/v1/business/app-pin/reset"
    with business_store() as connection:
        locked = business_account(connection, "support-locked")
        bare = business_account(connection, "support-bare")
        connection.execute("INSERT INTO app_pins (account_id, pin_hash, failures, locked_at) "
                           "VALUES (?, ?, 5, ?)", (locked, b"verifier", s._utc_now()))
        ask = {"account_id": locked, "reference": "TICKET-1"}
        status, payload = business_call("POST", unlock, ask, token="")
        expect(status == 401, "support needs the business token, got %s" % status)
        for path in (unlock, reset):
            status, payload = business_call("POST", path, ask)
            expect(status == 403 and payload["error"]["code"] == "app_pin_support_disabled",
                   "off by default, %s must refuse: %s %s" % (path, status, payload))
        with business_policy(app_pin_support="unlock"):
            status, payload = business_call("POST", reset, ask)
            expect(status == 403 and payload["error"]["code"] == "app_pin_support_disabled",
                   "unlock alone must not open a reset: %s %s" % (status, payload))
            for bad, field in (
                    ({"account_id": locked}, "reference"),
                    ({"account_id": locked, "reference": "ticket 1"}, "reference"),
                    ({"account_id": locked, "reference": "x" * 65}, "reference"),
                    ({"reference": "T-1"}, "account_id"),
                    ({"account_id": locked, "handle": "support-locked", "reference": "T-1"},
                     "account_id"),
                    ({"account_id": locked, "reference": "T-1", "note": "x"}, "note")):
                status, payload = business_call("POST", unlock, bad)
                error = payload.get("error") or {}
                expect(status == 400 and error.get("code") == "invalid_support_request"
                       and (error.get("details") or {}).get("field") == field,
                       "%s must be refused on %s: %s %s" % (sorted(bad), field, status, payload))
            status, payload = business_call("POST", unlock, {"account_id": str(uuid.uuid4()),
                                                             "reference": "T-2"})
            expect(status == 404 and payload["error"]["code"] == "unknown_account",
                   "an unknown account: %s %s" % (status, payload))
            status, payload = business_call("POST", unlock, {"handle": "support-bare",
                                                             "reference": "T-3"})
            expect(status == 404 and payload["error"]["code"] == "app_pin_not_set",
                   "no PIN, nothing to unlock: %s %s" % (status, payload))
            status, payload = business_call("POST", unlock, {"handle": "support-locked",
                                                             "reference": "T-4"})
            row = connection.execute("SELECT failures, locked_at, reset_until FROM app_pins "
                                     "WHERE account_id = ?", (locked,)).fetchone()
            expect(status == 200 and payload == {"account_id": locked, "unlocked": True,
                                                 "reset_until": None}
                   and tuple(row) == (0, None, None),
                   "unlock clears the count and the lock, and opens no reset: %s %s %s"
                   % (status, payload, row))
        with business_policy(app_pin_support="unlock_and_reset", app_pin_support_reset_minutes=20):
            before = s._utc_now()
            for reference in ("T-5", "T-6"):
                status, payload = business_call("POST", reset, {"account_id": bare,
                                                                "reference": reference})
                row = connection.execute("SELECT pin_hash, reset_until FROM app_pins "
                                         "WHERE account_id = ?", (bare,)).fetchone()
                expect(status == 200 and row[0] is None
                       and before + timedelta(minutes=20) <= row[1]
                       <= s._utc_now() + timedelta(minutes=20)
                       and payload["reset_until"] == s._iso_z(row[1]),
                       "a reset opens for the DBA's minutes, a row holding only it: %s %s %s"
                       % (status, payload, row))
        with business_policy(app_pin_support="unlock"):
            status, payload = business_call("POST", unlock, {"account_id": bare,
                                                             "reference": "T-7"})
            expect(status == 404 and payload["error"]["code"] == "app_pin_not_set",
                   "a row holding only a reset has no PIN to unlock: %s %s" % (status, payload))
        seen = [tuple(r) for r in connection.execute(
            "SELECT kind, code, account_id, device_id, installation_id "
            "FROM server_observations ORDER BY rowid")]
        expect(seen == [("app_pin_support_unlocked", "T-4", locked, None, None),
                        ("app_pin_support_reset", "T-5", bare, None, None),
                        ("app_pin_support_reset", "T-6", bare, None, None)],
               "each support action is recorded once, with its reference: %s" % seen)


@check
def the_business_reads_every_integrity_report_page_by_page():
    """DESIGN.md 79. The business feed returns each stored report with the
    phone's measurements and the server's reasons, oldest first; the cursor
    carries the last report's time and id, so reports sharing a timestamp at a
    page edge are neither skipped nor repeated. At most one filter: a phone, an
    installation, or an account -- every phone linked to it, reports from
    before the link included."""
    path = "/v1/business/integrity-reports"
    with business_store() as connection:
        account_id = business_account(connection, "report-reader")
        phone, other = str(uuid.uuid4()), str(uuid.uuid4())
        business_link(connection, phone, account_id)
        install = str(uuid.uuid4())
        start = s._utc_now() - timedelta(hours=3)
        rows = []
        for minutes, device in ((0, phone), (0, phone), (0, other), (30, other), (60, phone)):
            report = str(uuid.uuid4())
            created = start + timedelta(minutes=minutes)
            connection.execute(
                "INSERT INTO integrity_reports (report_id, installation_id, device_id, score, "
                "verdict, hard_block, created_at, evidence_quality, finding_score, platform, "
                "collector_version, reasons, probe_results, report_sha256) "
                "VALUES (?, ?, ?, 8, 'trusted', 0, ?, 'complete', 0, 'android', 3, ?, ?, ?)",
                (report, install if device == phone else str(uuid.uuid4()), device, created,
                 json.dumps([{"code": "android_developer_options", "points": 8}]),
                 json.dumps({"debug_state": {"developer_options": True}}), "ab" * 32))
            rows.append((created, report, device))
        rows.sort()
        status, payload = business_call("GET", path, token="", query={})
        expect(status == 401, "the feed needs the business token, got %s" % status)
        seen, query = [], {"limit": "2"}
        for _ in range(4):
            status, payload = business_call("GET", path, query=query)
            expect(status == 200, "a page: %s %s" % (status, payload))
            seen.extend(r["report_id"] for r in payload["reports"])
            query = {"limit": "2", "cursor": payload["next_cursor"]}
        expect(seen == [r[1] for r in rows],
               "pages of two must return each report once, in order: %s" % seen)
        first = business_call("GET", path, query={"limit": "1"})[1]["reports"][0]
        expect(first["probe_results"] == {"debug_state": {"developer_options": True}}
               and first["reasons"] == [{"code": "android_developer_options", "points": 8}]
               and first["platform"] == "android" and first["collector_version"] == 3
               and first["hard_block"] is False and first["evidence_quality"] == "complete"
               and first["report_sha256"] == "ab" * 32,
               "a report carries the phone's measurements and the server's reasons: %s" % first)
        for name, value, expected in (
                ("device_id", other, [r[1] for r in rows if r[2] == other]),
                ("installation_id", install, [r[1] for r in rows if r[2] == phone]),
                ("account_id", account_id, [r[1] for r in rows if r[2] == phone])):
            status, payload = business_call("GET", path, query={name: value})
            expect(status == 200 and [r["report_id"] for r in payload["reports"]] == expected,
                   "filtered by %s: %s %s" % (name, status, payload))
        status, payload = business_call("GET", path, query={
            "since": s._iso_z(rows[2][0]), "device_id": phone})
        expect([r["report_id"] for r in payload["reports"]] == [rows[4][1]],
               "since returns only what came after it: %s" % payload)
        for query, code in (({"device_id": phone, "account_id": account_id}, "invalid_filter"),
                            ({"cursor": "not-a-cursor"}, "invalid_cursor"),
                            ({"device_id": "not-a-uuid"}, None)):
            status, payload = business_call("GET", path, query=query)
            expect(status == 400 and (code is None or payload["error"]["code"] == code),
                   "%s must be refused: %s %s" % (sorted(query), status, payload))


@check
def the_app_reads_the_dbas_step_up_policy():
    """DESIGN.md 79 (G4). The step-up policy is readable before sign-in, so an
    app creates its screen-lock key as the DBA chose -- factor, mode, window
    -- and knows whether the PIN is the method and how long it is. Never
    cached; budgeted per source. The account's own view carries the same."""
    path = "/v1/policy/step-up"
    chosen = dict(stepup_method="screen_lock_and_app_pin", stepup_factor="biometric",
                  stepup_mode="windowed", stepup_window_seconds=60, app_pin_length=8,
                  stepup_required_paths=SENSITIVE + "," + ECHO, app_pin_required_paths=ECHO)
    expected = {"method": "screen_lock_and_app_pin", "factor": "biometric", "mode": "windowed",
                "window_seconds": 60, "app_pin_length": 8,
                "required_paths": sorted([SENSITIVE, ECHO]), "app_pin_required_paths": [ECHO]}
    with policy(**chosen):
        reply = client.get(path)
        expect(reply.status_code == 200 and reply.get_json() == expected
               and reply.headers.get("Cache-Control") == "no-store",
               "the policy as the DBA chose it, never cached: %s %s %s"
               % (reply.status_code, reply.get_json(), reply.headers.get("Cache-Control")))
        with isolated_stepup():
            reply = client.get("/v1/account/me", headers=access_headers(
                "GET", "/v1/account/me", b""))
        state = (reply.get_json() or {}).get("step_up") or {}
        expect(reply.status_code == 200
               and {k: state.get(k) for k in expected} == expected
               and state.get("app_pin_set") is False,
               "the account's view carries the same policy: %s %s"
               % (reply.status_code, reply.get_json()))
    with policy(stepup_mode="per_use", stepup_window_seconds=60):
        expect(client.get(path).get_json()["window_seconds"] == 0,
               "a per_use policy has no window")
    saved = (s.RATE_LIMIT_ENABLED, s.REDIS_URL, s._REDIS_CLIENT)
    fake = FakeRedis()
    s.RATE_LIMIT_ENABLED, s.REDIS_URL, s._REDIS_CLIENT = True, "redis://fixture", fake
    try:
        expect(client.get(path).status_code == 200
               and any(k.startswith("dt:rate:policy_read_source:") for k in fake.counts),
               "the policy read is budgeted per source: %s" % sorted(fake.counts))
        for key in [k for k in fake.counts if k.startswith("dt:rate:policy_read_source:")]:
            fake.counts[key] = s.RATE_LIMIT_SOURCE_MAX_ATTEMPTS
        reply = client.get(path)
        expect(reply.status_code == 429, "an exhausted source budget refuses, got %s"
               % reply.status_code)
    finally:
        s.RATE_LIMIT_ENABLED, s.REDIS_URL, s._REDIS_CLIENT = saved


def _source_measurements():
    """Every code, kind and field the server source can emit, by kind."""
    tree = ast.parse(Path(s.__file__).read_text(encoding="utf-8"))

    def literals(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.IfExp):
            return literals(node.body) + literals(node.orelse)
        return []

    found = {"integrity reason": set(), "relationship reason": set(),
             "observation code": set(), "context field": set()}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name, args = node.func.id, node.args
            if name == "_integrity_reason" and len(args) > 1:
                found["integrity reason"].update(literals(args[1]))
            elif name == "_policy_reason" and len(args) > 1:
                found["relationship reason"].update(literals(args[1]))
            elif name == "_record_observation" and len(args) > 1:
                found["observation code"].update(literals(args[1]))
            elif name == "_observed_refusal" and args:
                found["observation code"].update(literals(args[0]))
        elif (isinstance(node, ast.FunctionDef) and node.name == "_evaluate_risk_policy"):
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Assign) and isinstance(inner.value, ast.Dict)
                        and [ast.unparse(t) for t in inner.targets] == ["context"]):
                    found["context field"].update(literals_of_keys(inner.value))
                elif (isinstance(inner, ast.Subscript) and ast.unparse(inner.value) == "context"):
                    found["context field"].update(literals(inner.slice))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            for text in literals(node.left):
                if text.startswith("integrity_") and text.endswith(":%s"):
                    found["integrity reason"].add(text[:-2] + "<probe>")
    found["cross-check rule"] = {rule[0] for rule in s._CROSS_CHECK_RULES}
    found["observation kind"] = set(s._OBSERVATION_KINDS)
    fields = set()
    for contract in (s._PROBE_REQUIRED_FIELDS, s._PROBE_OPTIONAL_FIELDS):
        for probes in contract.values():
            for probe, names in probes.items():
                fields.add(probe)
                fields.update(names)
    found["probe or field"] = fields
    # What the native collectors put in a report (their result keys), so the
    # catalog cannot fall behind a collector either.
    collectors = {
        "android/app/src/main/kotlin/com/example/devicefingerprinting/IntegrityProbeManager.kt":
            (r'"([a-z_]+)" to ', r'result\["([a-z_]+)"\]'),
        "ios/Runner/IntegrityProbeManager.swift": (r'"([a-z_]+)":\s', r'result\["([a-z_]+)"\]'),
    }
    sent = set()
    for path, patterns in collectors.items():
        text = (DOCS / path).read_text(encoding="utf-8")
        for pattern in patterns:
            sent.update(re.findall(pattern, text))
    found["collector field"] = sent - {"test_fixture"}  # a channel argument, not a measurement
    return found


def literals_of_keys(node):
    return [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]


@check
def the_measurement_catalog_lists_every_code():
    """DESIGN.md 79 (G5). MEASUREMENTS.md names every integrity and relationship
    reason code, cross-check rule, observation kind and code, decision-context
    field, and every probe field of the server's evidence contract: a code the
    source can emit but the catalog does not name fails here."""
    catalog = (DOCS / "MEASUREMENTS.md").read_text(encoding="utf-8")
    found = _source_measurements()
    expect(len(found["integrity reason"]) >= 60 and len(found["relationship reason"]) >= 20
           and len(found["observation kind"]) >= 11 and len(found["context field"]) >= 25,
           "the source scan found too little to be trusted: %s"
           % {kind: len(names) for kind, names in found.items()})
    missing = sorted("%s %s" % (kind, name) for kind, names in found.items()
                     for name in names if "`%s`" % name not in catalog)
    expect(not missing, "MEASUREMENTS.md does not name: %s" % missing)


@check
def the_settings_reference_matches_the_migrations():
    """DESIGN.md 79 (G7). The settings reference in the guide and the audit map
    is what tools/settings_reference.py renders from the migrations; both
    engines' migrations seed the same rows; every setting the server reads is
    seeded, and every seeded one is read; and a missing row falls back to the
    seeded default, never to another value."""
    sys.path.insert(0, str(DOCS / "tools"))
    try:
        import settings_reference as reference
    finally:
        sys.path.pop(0)
    rendered = reference.render()
    for name in reference.DOCUMENTS:
        block = reference.block_in((DOCS / name).read_text(encoding="utf-8"))
        expect(block == rendered, "%s's settings reference is not what the migrations say; "
               "run python3 tools/settings_reference.py --write" % name)
    engines = {engine: {key: (number, value, description)
                        for number, _, rows in reference.seeded_settings(engine)
                        for key, value, description in rows}
               for engine in ("postgresql", "sqlserver")}
    differ = sorted(key for key in set(engines["postgresql"]) | set(engines["sqlserver"])
                    if engines["postgresql"].get(key) != engines["sqlserver"].get(key))
    expect(not differ, "the engines' migrations seed these differently: %s" % differ)
    # The columns' sizes on both engines (migration 003): a longer row fails
    # the migration on the DBA's server, as one did live (DESIGN.md 80).
    too_long = sorted(key for key, (_, value, description) in engines["postgresql"].items()
                      if len(key) > 64 or len(value) > 256 or len(description) > 256)
    expect(not too_long, "longer than risk_policy_settings' columns allow: %s" % too_long)
    seeded = {key: value for key, (_, value, _) in engines["postgresql"].items()}
    tree = ast.parse(Path(s.__file__).read_text(encoding="utf-8"))
    read, fallbacks = set(), []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id.startswith("_risk_setting_") and node.args
                and isinstance(node.args[0], ast.Constant)):
            read.add(node.args[0].value)
            if len(node.args) > 1 and not isinstance(node.args[1], ast.Call):
                fallbacks.append((node.args[0].value, eval(ast.unparse(node.args[1]), vars(s))))
    read |= {"%s_%s" % (rule[0], part) for rule in s._CROSS_CHECK_RULES
             for part in ("count", "points")}
    read |= {rule[0] for rule in s._ELIGIBILITY_RULES}
    expect(not read - set(seeded), "read by the server but seeded by no migration: %s"
           % sorted(read - set(seeded)))
    expect(not set(seeded) - read, "seeded but never read: %s" % sorted(set(seeded) - read))
    wrong = sorted("%s: code %r, seeded %r" % (key, default, seeded[key])
                   for key, default in fallbacks
                   if ({True: "1", False: "0"}.get(default, default)
                       if isinstance(default, bool) else str(default)) != seeded[key])
    expect(not wrong, "a missing row would fall back to another value: %s" % wrong)


# ---------------------------------------------------------------------------
# The device and network probes, optional measurements, request metadata
# (DESIGN.md 80)
# ---------------------------------------------------------------------------


def _stored_probes():
    """probe_results as the last report stored them."""
    rows = [params for q, params in db.writes if q.startswith("INSERT INTO integrity_reports")]
    return rows[-1][10].adapted if rows else None


def _without(probes, *names):
    return {name: value for name, value in probes.items() if name not in names}


@check
def the_network_probe_is_measured_and_advisory():
    """DESIGN.md 80. Collectors from Android 4 and iOS 3 volunteer device and
    network on every scan, never in the plan, so a report without them -- an
    older app -- loses nothing. A VPN or an HTTP proxy is recorded at 0 points;
    the fields are type-checked like any probe's, and stored."""
    measured = {
        "android": ({"status": "ok", "vpn_active": True, "http_proxy_configured": True,
                     "transports": ["wifi", "vpn"], "interfaces": ["wlan0", "tun0"]},
                    {"status": "ok", "release": "9", "sdk_int": 28, "security_patch": "2020-04-05",
                     "manufacturer": "OPPO", "brand": "OPPO", "model": "CPH2083",
                     "device": "OP4BA5L1", "build_id": "PPR1.180610.011",
                     "fingerprint": "OPPO/CPH2083/OP4BA5L1:9/PPR1.180610.011/1:user/release-keys"}),
        "ios": ({"status": "ok", "vpn_active": True, "http_proxy_configured": True,
                 "scoped_interfaces": ["en0", "utun3"]},
                {"status": "ok", "os_version": "15.8.5", "model_identifier": "iPhone9,3"}),
    }
    for platform, (network, device) in measured.items():
        expect("network" not in s._integrity_probe_plan(platform)
               and "device" not in s._integrity_probe_plan(platform),
               "%s: a volunteered probe must stay out of the plan" % platform)
        older = _without(clean(platform), "network", "device")
        status, plain = send_report(platform, older)
        expect(status == 200 and not {c for c in codes(plain) if c.startswith("integrity_")},
               "%s: an older app without them loses nothing: %s %s"
               % (platform, status, plain.get("integrity")))
        db.writes = []
        status, payload = send_report(platform, dict(older, network=network, device=device))
        points = {r["code"]: r["points"] for r in (payload.get("integrity") or {}).get("reasons", [])}
        expect(status == 200 and points.get("%s_vpn_active" % platform) == 0
               and points.get("%s_http_proxy" % platform) == 0
               and payload["integrity"]["score"] == plain["integrity"]["score"]
               and payload["integrity"]["verdict"] == plain["integrity"]["verdict"],
               "%s: a VPN and a proxy are recorded at 0 points: %s %s" % (platform, status, points))
        stored = _stored_probes() or {}
        expect(stored.get("network") == network and stored.get("device") == device,
               "%s: both are stored as sent: %s" % (platform, sorted(stored)))
        status, payload = send_report(platform, dict(older, network=dict(network, vpn_active="yes")))
        expect(status == 400 and payload["error"]["code"] == "invalid_integrity_probe",
               "%s: a wrongly typed field is refused: %s %s" % (platform, status, payload))


@check
def network_eligibility_rules_refuse_only_when_set():
    """DESIGN.md 80. A VPN or an HTTP proxy never costs points; a deployment
    that wants them off sets vpn_active_refuses or http_proxy_refuses, refused
    with integrity_device_ineligible and the rule's remedy."""
    saved = (s._latest_integrity_state, s._device_integrity_memory, s.INTEGRITY_MODE)
    s._device_integrity_memory = lambda did, iid: None
    s.INTEGRITY_MODE = "enforce"
    try:
        for rule, code in (("vpn_active_refuses", "android_vpn_active"),
                           ("vpn_active_refuses", "ios_vpn_active"),
                           ("http_proxy_refuses", "android_http_proxy"),
                           ("http_proxy_refuses", "ios_http_proxy")):
            s._latest_integrity_state = lambda iid, code=code: {
                "score": 0, "verdict": "trusted", "fresh": True,
                "reasons": [{"code": code, "points": 0}]}
            for value, refused in ((0, False), (1, True)):
                with policy(**{rule: value}):
                    try:
                        s._enforce_integrity_gate(inst.device_id, inst.installation_id)
                        problem = None
                    except s.ApiProblem as error:
                        problem = error
                expect(bool(problem) == refused and (
                    not refused or (problem.code == "integrity_device_ineligible"
                                    and [e["reason"] for e in problem.details["eligibility"]]
                                    == [code]
                                    and problem.details["eligibility"][0]["remedy"])),
                       "%s=%d with %s: refused=%s, got %s" % (rule, value, code, refused,
                                                             problem and problem.code))
    finally:
        s._latest_integrity_state, s._device_integrity_memory, s.INTEGRITY_MODE = saved


@check
def optional_measurements_need_both_keys():
    """DESIGN.md 80. The DBA lists optional measurements; the challenge asks
    for them and never requires them; the app answers each one it enabled, or
    not_enabled, which is no collection problem. One the DBA does not request
    is dropped before the report is stored; an unknown name is a DBA typo
    that invalidates the snapshot."""
    addresses = {"status": "ok",
                 "addresses": [{"interface": "wlan0", "address": "192.0.2.10"}]}
    path = "/v1/integrity/challenge"

    def challenge():
        reply = client.post(path, data=b"{}",
                            headers=access_headers("POST", path, b"{}", device_token))
        return reply.status_code, reply.get_json() or {}

    with policy():
        status, asked = challenge()
        expect(status == 200 and asked.get("optional_probes") == [],
               "nothing optional is asked for by default: %s %s" % (status, asked))
        db.writes = []
        status, payload = send_report("android", dict(clean("android"), local_addresses=addresses))
        expect(status == 200 and "local_addresses" not in (_stored_probes() or {}),
               "what the DBA did not request is dropped before storing: %s" % status)
    with policy(optional_measurements="local_addresses"):
        status, asked = challenge()
        expect(status == 200 and asked.get("optional_probes") == ["local_addresses"]
               and "local_addresses" not in asked.get("required_probes", []),
               "requested, never required: %s" % asked)
        db.writes = []
        status, payload = send_report("android", dict(clean("android"), local_addresses=addresses))
        expect(status == 200 and (_stored_probes() or {}).get("local_addresses") == addresses,
               "requested and enabled: stored as sent: %s" % status)
        for answer in ({"status": "not_enabled"}, {"status": "error", "error": "no interfaces"}):
            status, payload = send_report("android", dict(clean("android"), local_addresses=answer))
            expect(status == 200 and payload["integrity"]["verdict"] == "trusted"
                   and not {c for c in codes(payload) if c.startswith("integrity_")},
                   "%s is no collection problem: %s" % (answer["status"], codes(payload)))
    for bad in ("mac_address", "local_addresses,imei"):
        try:
            s._validate_risk_settings(dict(SETTINGS, optional_measurements=bad))
            refused = False
        except ValueError:
            refused = True
        expect(refused, "optional_measurements=%r must invalidate the snapshot" % bad)


@check
def request_metadata_is_kept_only_where_the_dba_says():
    """DESIGN.md 80. The address a request came from and its User-Agent are
    personal data: a decision's context carries them only where the DBA sets
    record_source_ip or record_user_agent, the agent cut at 256 characters."""
    store = ObservationStore()
    phone = store.phone()
    with s.app.test_request_context("/v1/policy/me", headers={"User-Agent": "A" * 300},
                                    environ_base={"REMOTE_ADDR": "203.0.113.7"}):
        off = store.decide(phone)["context"]
        address = store.decide(phone, record_source_ip=1)["context"]
        both = store.decide(phone, record_source_ip=1, record_user_agent=1)["context"]
    expect("source_ip" not in off and "user_agent" not in off,
           "kept only where the DBA says: %s" % sorted(off))
    expect(address.get("source_ip") == "203.0.113.7" and "user_agent" not in address,
           "record_source_ip alone: %s" % {k: address.get(k) for k in ("source_ip", "user_agent")})
    expect(both.get("user_agent") == "A" * 256, "the agent is cut at 256 characters")


@check
def the_relationship_rules_are_the_dbas():
    """DESIGN.md 79 (owner: "put them under DBA"). A new phone, a known
    phone's new installation, reinstall velocity, a missing or stale scan and
    another installation blocked on the phone score the DBA's points, at the
    values the code used before by default; 0 switches a rule off."""
    store = ObservationStore()

    def points(decision):
        return {r["code"]: r["points"] for r in decision["reasons"]}

    fresh_phone = store.phone(age_days=0)
    expect(points(store.decide(fresh_phone)).get("new_device") == 10, "a new phone: +10")
    expect(points(store.decide(fresh_phone, new_device_points=25)).get("new_device") == 25,
           "the DBA's points for a new phone")
    expect("new_device" not in points(store.decide(fresh_phone, new_device_points=0)),
           "0 switches the new-phone rule off")
    expect("new_device" not in points(store.decide(store.phone(age_days=2), new_device_hours=24))
           and points(store.decide(store.phone(age_days=2), new_device_hours=72)).get("new_device")
           == 10, "how long a phone counts as new is the DBA's")
    busy = store.phone()
    for _ in range(3):
        store.reinstall(busy)
    expect(points(store.decide(busy)).get("rapid_reinstall_elevated") == 35,
           "three proven reinstalls: +35 by default")
    tuned = points(store.decide(busy, reinstall_elevated_points=20, reinstall_high_count=3,
                                reinstall_high_points=70))
    expect(tuned.get("rapid_reinstall_high") == 70 and "rapid_reinstall_elevated" not in tuned,
           "the DBA's counts and points: %s" % tuned)
    expect(store.decide(busy, reinstall_block_count=3)["recommended_action"] == "block",
           "the DBA's block count")
    quiet = store.phone()
    expect(points(store.decide(quiet, scan="missing")).get("integrity_report_missing") == 40
           and points(store.decide(quiet, scan="missing", integrity_report_missing_points=20))
           .get("integrity_report_missing") == 20, "a missing scan: the DBA's points")
    expect(points(store.decide(quiet, scan="stale")).get("integrity_report_stale") == 35
           and points(store.decide(quiet, scan="stale", integrity_report_stale_points=10))
           .get("integrity_report_stale") == 10, "a stale scan: the DBA's points")
    blocked_elsewhere = {"finding_verdict": "block", "installation_id": str(uuid.uuid4())}
    expect(points(store.decide(quiet, memory=blocked_elsewhere))
           .get("device_integrity_history_block") == 50
           and points(store.decide(quiet, memory=blocked_elsewhere,
                                   device_integrity_history_block_points=80))
           .get("device_integrity_history_block") == 80,
           "another installation blocked: the DBA's points")


@check
def a_scan_is_fresh_for_as_long_as_the_dba_says():
    """DESIGN.md 79. The latest scan's freshness follows the DBA's
    integrity_freshness_seconds; the environment's value only answers a
    missing row."""
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(LITE_SCHEMA)
    installation = str(uuid.uuid4())
    connection.execute(
        "INSERT INTO integrity_reports (report_id, installation_id, device_id, score, verdict, "
        "hard_block, created_at) VALUES (?, ?, ?, 0, 'trusted', 0, ?)",
        (str(uuid.uuid4()), installation, str(uuid.uuid4()),
         s._utc_now() - timedelta(seconds=700)))
    connection.execute("ALTER TABLE integrity_reports ADD COLUMN reasons TEXT DEFAULT '[]'")

    @contextmanager
    def lite_cursor(commit=False):
        yield LiteCursor(connection)

    saved = s._cursor
    s._cursor = lite_cursor
    try:
        for seconds, fresh in ((None, False), (900, True), (600, False)):
            values = dict(db.settings)
            if seconds is not None:
                values["integrity_freshness_seconds"] = str(seconds)
            s._risk_settings_cache.update(values=values, at=time.monotonic(), failed_at=None,
                                          error=None)
            state = s._latest_integrity_state(installation)
            expect(state["fresh"] is fresh, "a 700-second-old scan with freshness %s: fresh=%s"
                   % (seconds, state["fresh"]))
    finally:
        s._cursor = saved
        s._risk_settings_cache.update(values=dict(db.settings), at=time.monotonic(),
                                      failed_at=None, error=None)
        connection.close()


@check
def a_session_lives_as_long_as_the_dba_says():
    """DESIGN.md 79 (owner: G8 DBA-configurable, 30 days the default). Each
    refresh token lives refresh_idle_days (the session ends after that many
    idle days); session_max_days, off by default, ends a session that many
    days after its first sign-in however often it refreshed -- also for
    tokens issued before the DBA set it. The bounds are ours: idle 1-90, cap
    0 or up to 365."""
    import base64

    def expiry_days(tokens):
        payload = tokens["refresh_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (claims["exp"] - time.time()) / 86400.0

    with s.app.app_context():
        with policy():
            fresh = s._issue_account_tokens(db, account, inst.device_id, inst.installation_id)
            expect(29.9 < expiry_days(fresh) <= 30.0, "the default idle lifetime is 30 days")
        with policy(refresh_idle_days=7):
            tokens = s._issue_account_tokens(db, account, inst.device_id, inst.installation_id)
            expect(6.9 < expiry_days(tokens) <= 7.0, "the DBA's idle lifetime: 7 days")
        with policy(session_max_days=10):
            db.family_started = s._utc_now() - timedelta(days=8)
            tokens = s._issue_account_tokens(db, account, inst.device_id, inst.installation_id,
                                             family_id=str(uuid.uuid4()))
            expect(1.9 < expiry_days(tokens) <= 2.0,
                   "a session capped at 10 days that began 8 days ago refreshes for 2 more")
    family, session = str(uuid.uuid4()), str(uuid.uuid4())
    claims = {"sid": session, "family": family, "did": inst.device_id, "iid": inst.installation_id}
    db.refresh_row = (family, account, inst.device_id, inst.installation_id,
                      s._utc_now() + timedelta(days=20), None, "full", None, None, None)
    real_identity = s.get_jwt_identity
    try:
        with s.app.test_request_context("/v1/auth/refresh", method="POST"):
            s.get_jwt_identity = lambda: account
            for started_days, cap, refused in ((40, 0, False), (40, 30, True), (20, 30, False)):
                db.family_started = s._utc_now() - timedelta(days=started_days)
                with policy(session_max_days=cap):
                    code = None
                    try:
                        s._refresh_session(db, claims)
                    except s.ApiProblem as problem:
                        code = problem.code
                expect((code == "session_max_age_reached") is refused,
                       "a session %d days old under a %d-day cap: refused=%s (%s)"
                       % (started_days, cap, code is not None, code))
    finally:
        db.refresh_row, db.family_started = None, None
        s.get_jwt_identity = real_identity
    for values, valid in (({"refresh_idle_days": "90"}, True), ({"refresh_idle_days": "91"}, False),
                          ({"refresh_idle_days": "0"}, False), ({"session_max_days": "365"}, True),
                          ({"session_max_days": "366"}, False)):
        try:
            s._validate_risk_settings(dict(SETTINGS, **values))
            accepted = True
        except ValueError:
            accepted = False
        expect(accepted is valid, "%s: accepted=%s" % (values, accepted))


@check
def a_counter_outage_is_degraded_evidence_never_a_rate_of_zero():
    """DESIGN.md 77; review of 2026-10-13. With the request-rate rule on and its
    counter unreadable -- Redis unreachable, or none configured -- the decision
    says so (state unavailable, request_rate_unavailable listed at 0 points),
    never reads it as a rate of zero, and never restricts anyone for an outage.
    A rate limiter that could not run is noted on the request's decision."""
    store = ObservationStore()
    phone = store.phone()
    saved = (s.REDIS_URL, s._redis, s.RATE_LIMIT_ENABLED)

    def broken():
        raise ConnectionError("simulated Redis outage")

    try:
        fake = FakeRedis()
        s.REDIS_URL, s._redis = "redis://gate.invalid:6379/0", lambda: fake
        healthy = store.decide(phone, rate_anomaly_enabled=1)
        expect(healthy["context"]["request_rate"] == {"state": "measured", "count": 1,
                                                       "window_seconds": 60},
               "a working counter is measured: %s" % healthy["context"]["request_rate"])
        for url, client_factory in (("redis://gate.invalid:6379/0", broken), ("", broken)):
            s.REDIS_URL, s._redis = url, client_factory
            decision = store.decide(phone, rate_anomaly_enabled=1)
            expect(decision["context"]["request_rate"]["state"] == "unavailable"
                   and "count" not in decision["context"]["request_rate"]
                   and {"request_rate_unavailable": 0} == {
                       r["code"]: r["points"] for r in decision["reasons"]
                       if r["code"].startswith("request_rate")}
                   and decision["score"] == healthy["score"],
                   "an unreadable counter (REDIS_URL=%r) is degraded, not 0: %s %s"
                   % (url, decision["context"]["request_rate"], decision["reasons"]))
        off = store.decide(phone)
        expect(off["context"]["request_rate"] == {"state": "off"}
               and "rate_limiter" not in off["context"],
               "the rule off reads off: %s" % off["context"])
        s.RATE_LIMIT_ENABLED = True
        for url in ("redis://gate.invalid:6379/0", ""):
            s.REDIS_URL = url
            with s.app.test_request_context("/v1/accounts/login", method="POST"):
                s._enforce_rate_limit("accounts_login", "someone")
                noted = store.decide(phone)
            expect(noted["context"].get("rate_limiter") == "unavailable",
                   "a rate limiter that could not run (REDIS_URL=%r) is noted: %s"
                   % (url, noted["context"]))
    finally:
        s.REDIS_URL, s._redis, s.RATE_LIMIT_ENABLED = saved


@check
def an_approval_covers_a_counted_reason_only_up_to_its_count():
    """DESIGN.md 77, the R1 rule for count-following reasons: an approval that
    saw three failed step-up proofs covers three or fewer, not a fourth."""
    approved = {"revoked_at": None, "expires_at": s._utc_now() + timedelta(days=1),
                "causes": ["risk_step_up"], "device_accounts": 1, "account_devices": 1,
                "reasons": [{"code": "device_stepup_failures", "points": 30,
                             "source": "relationship", "count": 3}]}

    def covered(count, record=approved):
        policy_now = {"reasons": [{"code": "device_stepup_failures", "points": 30,
                                   "count": count, "message": "m"}],
                      "context": {"device_account_count": 1, "account_device_count": 1}}
        with policy():
            return s._acceptance_covers(record, "risk_step_up", policy=policy_now)[0]

    expect(covered(3) and covered(2), "up to the approved count is covered")
    expect(not covered(4), "a fourth failure was never approved")
    countless = dict(approved, reasons=[dict(approved["reasons"][0])])
    del countless["reasons"][0]["count"]
    expect(not covered(1, countless), "an approval without the count covers none")
    entries = s._reason_entries([{"code": "device_stepup_failures", "points": 30, "count": 3,
                                  "message": "m"}], "relationship")
    expect(entries and entries[0].get("count") == 3,
           "what an approver is shown keeps the count: %s" % entries)


def main():
    passed = failed = 0
    for function in CHECKS:
        try:
            function()
        except Exception as error:  # noqa: BLE001 - report every failure
            failed += 1
            print("FAIL %s\n       %s: %s" % (function.__name__, type(error).__name__, error))
        else:
            passed += 1
            print("PASS %s" % function.__name__)
    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
