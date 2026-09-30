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
here: those need the conformance suite against a live engine.

    python3 tools/check_security_regressions.py [path/to/repo]

Needs the server's own dependencies plus `cryptography` (via the conformance
suite's software key), exactly like conformance_suite.py.
"""
import json
import os
import sys
import time
import uuid
from contextlib import contextmanager
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

    def execute(self, sql, params=None):
        q = " ".join(sql.split())
        self.statements.append(q)
        self.result = None
        self.rowcount = 1
        if q == "SELECT 1":
            self.result = (1,)
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


def access_headers(method, path, body=b"", bearer=None, nonce=None):
    bearer = bearer or token
    proof = {"version": 1, "installation_id": inst.installation_id,
             "method": method, "path": path, "body_sha256": c.sha256_hex(body),
             "access_token_sha256": c.sha256_hex(bearer.encode()),
             "timestamp": int(time.time()), "nonce": nonce or fresh_nonce()}
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


# ---------------------------------------------------------------------------
# F1 -- a step-up approval authorises exactly one request
# ---------------------------------------------------------------------------

_real_integrity_gate = s._enforce_integrity_gate
_real_risk_policy = s._evaluate_risk_policy


@contextmanager
def isolated_stepup():
    s._enforce_integrity_gate = lambda *a: {"score": 0, "verdict": "trusted", "fresh": True}
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
