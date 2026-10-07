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
import json
import os
import random
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
        elif q.startswith("SELECT key_hardware_backed FROM app_installations"):
            self.result = (self.hardware_backed,)
        elif q.startswith("SELECT stepup_public_key_jwk"):
            self.result = (self.step_jwk, "ES256", self.step_factor, "per_use", 0, None,
                           s._parse_public_key(inst.jwk)["thumbprint"])
        elif q.startswith("SELECT installation_id, device_id, registration_method"):
            self.result = self.reenrol_row
        elif q.startswith("SELECT family_id, account_id, device_id, installation_id, expires_at, revoked_at FROM refresh_sessions"):
            self.result = self.refresh_row
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
        elif q.startswith(("DELETE FROM access_proof_nonces", "UPDATE app_installations",
                           "UPDATE recognized_devices", "UPDATE integrity_challenges")):
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


def access_headers(method, path, body=b"", bearer=None, nonce=None, version=2, query=""):
    bearer = bearer or token
    proof = {"version": version, "installation_id": inst.installation_id,
             "method": method, "path": path, "body_sha256": c.sha256_hex(body),
             "access_token_sha256": c.sha256_hex(bearer.encode()),
             "timestamp": int(time.time()), "nonce": nonce or fresh_nonce()}
    if version >= 2:
        proof["query"] = query
    raw = c.b64u(encode(proof))
    return {"Authorization": "Bearer " + bearer, "X-Access-Proof": raw,
            "X-Access-Signature": inst.sign_b64(raw), "Content-Type": "application/json"}


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


def send_report(platform, probes, collector_version=2):
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
    expect(status == 200 and "integrity_probe_incomplete:code_integrity" in codes(payload),
           "coverage that does not add up must be incomplete evidence, got %s" % payload)
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
        login = encode({"handle": "someone", "password": "Passw0rd123"})
        reply = client.post("/v1/accounts/login", data=login,
                            headers=access_headers("POST", "/v1/accounts/login", login, device_token))
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
                      s._utc_now() + s.REFRESH_TOKEN_LIFETIME, s._utc_now())
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
    report_id       TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL REFERENCES app_installations(installation_id),
    device_id       TEXT NOT NULL,
    score           INTEGER NOT NULL,
    verdict         TEXT NOT NULL,
    hard_block      BOOLEAN NOT NULL,
    created_at      TSZ NOT NULL
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
        self.cursor.execute(sql.replace("%s", "?").replace("NOW()", "CURRENT_TIMESTAMP"),
                            tuple(params or ()))
        self.rowcount = self.cursor.rowcount

    def fetchone(self):
        return self.cursor.fetchone()


@contextmanager
def lite_store():
    connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    connection.executescript(LITE_SCHEMA)

    @contextmanager
    def lite_cursor(commit=False):
        yield LiteCursor(connection)
        connection.commit()

    saved = (s._cursor, s._latest_integrity_state)
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


def lite_report(connection, installation_id, device_id, score, hard_block=False, age_hours=0.0):
    connection.execute(
        "INSERT INTO integrity_reports VALUES (?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), installation_id, device_id, score,
         s._integrity_verdict(score, hard_block), hard_block,
         s._utc_now() - timedelta(hours=age_hours)))


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
    blocked = memory is not None and (memory["hard_block"] or memory["verdict"] == "block")
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
