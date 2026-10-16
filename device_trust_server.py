"""
Device-recognition and device-trust API server.

Python compatibility: 3.9+

Always required:
    Flask
    Flask-JWT-Extended 4.x
    bcrypt
    pycryptodome

Per backend, imported lazily so only what is used must be installed:
    DB_ENGINE=postgresql   psycopg2-binary
    DB_ENGINE=sqlserver    pyodbc, plus the system package
                           "ODBC Driver 18 for SQL Server" (msodbcsql18)

Optional:
    REDIS_URL set          redis

Serving (DESIGN.md 60): run it under a multi-process WSGI server, e.g.
    gunicorn --workers 4 --bind 127.0.0.1:5000 device_trust_server:app
Worker processes, not threads: the SQL Server ODBC stack is not thread-safe
(DESIGN.md 55). app.run() below is the development server only.
    DB_POOL_SIZE             idle connections kept per process (default 4, 0 = off)
    DB_POOL_RECHECK_SECONDS  ping an idle connection older than this (default 30)
    DB_QUERY_TIMEOUT         SQL Server statement timeout, seconds (default 15)

This replaces the old shared-passphrase/RSA-AES transport. Run it behind HTTPS.
The private installation key stays inside Android Keystore or the iOS Secure
Enclave/Keychain. The server stores only public JWKs, opaque IDs, password
hashes, and HMACed reinstall hints. Existing RS256 rows remain verifiable while
new native keys use P-256 ECDSA (ES256 with DER-encoded signatures).

This version also adds a server-side device/account risk-policy layer. Risk is
computed from opaque device/account relationships only; no PII or device
hardware fingerprint is added.
"""

import base64
import bisect
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import struct
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Flask, g, has_request_context, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15
from werkzeug.exceptions import HTTPException


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _read_root_secret():
    """Load one high-entropy root secret and domain-separate its uses."""
    value = os.environ.get("DEVICE_ID_MASTER_SECRET", "").strip()
    if not value:
        secret_file = os.environ.get("DEVICE_ID_MASTER_SECRET_FILE", "jwtkey.txt")
        try:
            with open(secret_file, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except FileNotFoundError:
            value = ""

    if len(value.encode("utf-8")) < 32:
        raise RuntimeError(
            "Set DEVICE_ID_MASTER_SECRET to at least 32 random bytes, or place "
            "that value in jwtkey.txt."
        )
    return value.encode("utf-8")


_ROOT_SECRET = _read_root_secret()
_JWT_SECRET = hmac.new(_ROOT_SECRET, b"jwt-signing-v1", hashlib.sha256).hexdigest()
_REINSTALL_PEPPER = hmac.new(
    _ROOT_SECRET, b"reinstall-hint-v1", hashlib.sha256
).digest()
_ACCOUNT_LOOKUP_PEPPER = hmac.new(
    _ROOT_SECRET, b"account-lookup-v1", hashlib.sha256
).digest()
_CHALLENGE_MAC_KEY = hmac.new(
    _ROOT_SECRET, b"installation-challenge-mac-v1", hashlib.sha256
).digest()
_BUSINESS_SUBJECT_PEPPER = hmac.new(
    _ROOT_SECRET, b"business-subject-v1", hashlib.sha256
).digest()
# App PINs (DESIGN.md 78) are stored only as bcrypt over an HMAC keyed by this:
# a copy of the table without the root secret cannot be searched at all.
_APP_PIN_PEPPER = hmac.new(_ROOT_SECRET, b"app-pin-v1", hashlib.sha256).digest()


def _business_token_digests():
    """SHA-256 digests (hex) of the bearer tokens the customer's backend may
    use on /v1/business/* (DESIGN.md 76), comma-separated so a token can be
    rotated with no gap. Unset: the business API answers 404."""
    raw = os.environ.get("BUSINESS_API_TOKEN_SHA256", "")
    digests = [d.strip().lower() for d in raw.replace(";", ",").split(",") if d.strip()]
    for digest in digests:
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise RuntimeError("BUSINESS_API_TOKEN_SHA256 must list 64-hex SHA-256 digests.")
    return tuple(digests)


BUSINESS_API_TOKEN_SHA256 = _business_token_digests()

ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
DEVICE_TOKEN_LIFETIME = timedelta(minutes=10)
REFRESH_TOKEN_LIFETIME = timedelta(days=30)
CHALLENGE_LIFETIME = timedelta(minutes=2)
ACCESS_PROOF_MAX_SKEW_SECONDS = 120
ACCESS_PROOF_NONCE_RETENTION = timedelta(minutes=10)
# Lowest access-proof version accepted (DESIGN.md 63). v2 adds the raw query
# string to the signed request fields, which v1 never covered (review backlog).
# The default, 2, refuses v1. Setting 1 is a transition aid for a fleet whose
# clients still send v1 -- and even then a v1 proof is refused for any request
# that carries a query string, since nothing it signed covers one.
ACCESS_PROOF_MIN_VERSION = int(os.environ.get("ACCESS_PROOF_MIN_VERSION", "2"))
if ACCESS_PROOF_MIN_VERSION not in (1, 2):
    raise RuntimeError("ACCESS_PROOF_MIN_VERSION must be 1 or 2.")

# ---------------------------------------------------------------------------
# Device/account risk policy
# ---------------------------------------------------------------------------
# Keep observe mode while tuning thresholds. In observe mode the recommended
# action is calculated and logged but soft decisions do not block authentication.
# Switching to "enforce" makes step_up/review/block decisions reject the
# account registration, login, refresh, or policy-gated operation with HTTP 403.
DEVICE_POLICY_MODE = os.environ.get("DEVICE_POLICY_MODE", "observe").strip().lower()
if DEVICE_POLICY_MODE not in ("observe", "enforce"):
    raise RuntimeError("DEVICE_POLICY_MODE must be 'observe' or 'enforce'.")

# Fallbacks only: the live bands are risk_policy_settings.policy_step_up_score,
# policy_review_score and policy_block_score (DBA-tunable, seeded by migration
# 012 with the owner's defaults 30 / 60 / 90).
POLICY_STEP_UP_SCORE = int(os.environ.get("POLICY_STEP_UP_SCORE", "30"))
POLICY_REVIEW_SCORE = int(os.environ.get("POLICY_REVIEW_SCORE", "60"))
POLICY_BLOCK_SCORE = int(os.environ.get("POLICY_BLOCK_SCORE", "90"))
POLICY_REINSTALL_WINDOW_HOURS = int(
    os.environ.get("POLICY_REINSTALL_WINDOW_HOURS", "24")
)
# Fallback only: the live value is risk_policy_settings.device_accounts_block_count
# (DBA-tunable, seeded by migration 006 with the owner's default of 4).
POLICY_DEVICE_ACCOUNT_BLOCK_COUNT = int(
    os.environ.get("POLICY_DEVICE_ACCOUNT_BLOCK_COUNT", "4")
)
# Fallback only: the live value is risk_policy_settings.account_devices_block_count
# (DBA-tunable, seeded by migration 012 with the owner's default of 5).
POLICY_ACCOUNT_DEVICE_BLOCK_COUNT = int(
    os.environ.get("POLICY_ACCOUNT_DEVICE_BLOCK_COUNT", "5")
)
POLICY_REINSTALL_BLOCK_COUNT = int(
    os.environ.get("POLICY_REINSTALL_BLOCK_COUNT", "5")
)

# ---------------------------------------------------------------------------
# Local integrity / tamper measurement policy
# ---------------------------------------------------------------------------
# No Google Play Integrity, SafetyNet, App Attest, DeviceCheck, or Apple/Google
# remote attestation service is used. The device reports local measurements,
# signs the complete report with its registered installation key, and this
# server owns all scoring and allow/review/block decisions.
INTEGRITY_MODE = os.environ.get("INTEGRITY_MODE", "observe").strip().lower()
if INTEGRITY_MODE not in ("observe", "enforce"):
    raise RuntimeError("INTEGRITY_MODE must be 'observe' or 'enforce'.")

# Per-deployment policy for a software-backed installation key (Secure Enclave /
# StrongBox generation failed and the client fell back to a software keychain).
# It is a client claim, never proof (a compromised client can lie), so the
# operator opts in. "off" (default) scores nothing and changes no verdict;
# "advisory" adds a moderate weight so a software-backed key trends to step-up;
# "required" hard-blocks it. A NULL measurement (client did not report it) is
# never treated as software; under "required" it is still unsatisfied and
# blocks as key_hardware_backing_unreported (DESIGN.md 63).
INTEGRITY_HARDWARE_BACKING_POLICY = os.environ.get(
    "INTEGRITY_HARDWARE_BACKING_POLICY", "off"
).strip().lower()
if INTEGRITY_HARDWARE_BACKING_POLICY not in ("off", "advisory", "required"):
    raise RuntimeError(
        "INTEGRITY_HARDWARE_BACKING_POLICY must be 'off', 'advisory', or 'required'."
    )

INTEGRITY_CHALLENGE_LIFETIME = timedelta(
    seconds=int(os.environ.get("INTEGRITY_CHALLENGE_LIFETIME_SECONDS", "60"))
)
INTEGRITY_REPORT_MAX_SKEW_SECONDS = int(
    os.environ.get("INTEGRITY_REPORT_MAX_SKEW_SECONDS", "90")
)
INTEGRITY_FRESHNESS_SECONDS = int(
    os.environ.get("INTEGRITY_FRESHNESS_SECONDS", "600")
)
# Integrity reports are keyed to an installation, so reinstalling the app would
# otherwise erase a block verdict. This window carries the worst recent verdict
# forward on the canonical device_id instead. 0 disables device-level memory.
INTEGRITY_DEVICE_MEMORY_HOURS = int(
    os.environ.get("INTEGRITY_DEVICE_MEMORY_HOURS", "24")
)
# Code-integrity scoring for the extended library set (ext + the app's own
# native code). ON by default since 2026-09-06: both handsets were baselined
# clean across all three buckets (OPPO core 5,058,560 / ext 5,742,592 /
# app 4,194,304 bytes compared, all zero diff; Huawei likewise), and neither
# false-positived with it enabled. Set to 0 to fall back to scoring the core
# libc/libart bucket only.
INTEGRITY_SCORE_EXTENDED_LIBS = (
    os.environ.get("INTEGRITY_SCORE_EXTENDED_LIBS", "1").strip() == "1"
)

# iOS fake-signature detection (DESIGN.md 35.5 and 35.6).
#
# Defaults to 0 -- REPORT-ONLY -- and that default is deliberate. The entire
# evidence base for these two rules is a single TrollStore installation; no
# legitimately signed iOS build has ever been observed by this server. Scoring
# a rule before its clean baseline exists is the mistake DESIGN.md 28 was
# written to prevent, so the signals ship visible but inert, exactly as
# INTEGRITY_SCORE_EXTENDED_LIBS did before its default was flipped.
#
# Set to 1 once a normally signed iOS build has been observed not to raise
# ios_signing_identifier_bundle_mismatch.
INTEGRITY_SCORE_IOS_FAKE_SIGNATURE = (
    os.environ.get("INTEGRITY_SCORE_IOS_FAKE_SIGNATURE", "0").strip() == "1"
)

# iOS structural code integrity, the app bucket (battery item 16, DESIGN.md 33.4).
# Report-only by default for the same reason as the rules above: the signal has
# never been baselined on hardware, and a code-integrity probe that has not been
# confirmed to read non-zero on a clean device is indistinguishable from one
# that measures nothing at all (DESIGN.md 28.8).
INTEGRITY_SCORE_IOS_CODE_INTEGRITY = (
    os.environ.get("INTEGRITY_SCORE_IOS_CODE_INTEGRITY", "0").strip() == "1"
)

# Team identifiers belonging to known fake-signing tooling. Compared
# case-insensitively. This is a NAME match and carries every weakness that
# implies -- see the comment on the rule that uses it.
IOS_KNOWN_FAKE_TEAM_IDS = {"TROLLTROLL"}
INTEGRITY_RANDOM_OPTIONAL_PROBES = int(
    os.environ.get("INTEGRITY_RANDOM_OPTIONAL_PROBES", "4")
)
INTEGRITY_ALLOW_DEBUG = os.environ.get("INTEGRITY_ALLOW_DEBUG", "0") == "1"
INTEGRITY_ALLOW_EMULATOR = os.environ.get("INTEGRITY_ALLOW_EMULATOR", "0") == "1"
# Lab-only. When set, the signals that merely say "this is a development OS
# image" (non-user build type, test-keys, no Verified Boot data) are not
# scored, so a userdebug emulator can reach a trusted baseline and be used for
# enforce-mode testing. It never suppresses evidence of actual compromise
# (Frida, hooks, root artifacts), so a compromised emulator still blocks.
# Must stay 0 in production.
INTEGRITY_ALLOW_USERDEBUG = os.environ.get("INTEGRITY_ALLOW_USERDEBUG", "0") == "1"

def _env_values(name):
    raw = os.environ.get(name, "").replace(";", ",")
    values = set()
    for item in raw.split(","):
        normalized = item.strip().lower().replace(":", "").replace(" ", "")
        if normalized:
            values.add(normalized)
    return values

EXPECTED_ANDROID_PACKAGE = os.environ.get("INTEGRITY_ANDROID_PACKAGE", "").strip()
EXPECTED_ANDROID_CERT_SHA256 = _env_values("INTEGRITY_ANDROID_CERT_SHA256")
EXPECTED_ANDROID_APK_SHA256 = _env_values("INTEGRITY_ANDROID_APK_SHA256")


def _parse_wx_baselines(raw):
    """INTEGRITY_ANDROID_WX_BASELINES: "<apk_sha256>:<bytes>:<granularity>,..."

    The writable-and-executable memory a given build is known to reserve
    (DESIGN.md 62), measured per build by the .NET SDK's `baseline` command and
    keyed on the APK hash the operator pins -- never on a runtime name the
    client reports, which a compromised process could claim. A malformed entry
    stops the server at start-up rather than silently scoring without it.
    """
    baselines = {}
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        parts = [part.strip() for part in item.split(":")]
        if (
            len(parts) != 3
            or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0])
            or not parts[1].isdigit()
            or not parts[2].isdigit()
            or int(parts[2]) < 1
        ):
            raise RuntimeError(
                "INTEGRITY_ANDROID_WX_BASELINES entries must be "
                "<apk_sha256>:<bytes>:<granularity>; got %r" % item
            )
        baselines[parts[0].lower()] = (int(parts[1]), int(parts[2]))
    return baselines


ANDROID_WX_BASELINES = _parse_wx_baselines(
    os.environ.get("INTEGRITY_ANDROID_WX_BASELINES", "")
)
EXPECTED_IOS_BUNDLE_ID = os.environ.get("INTEGRITY_IOS_BUNDLE_ID", "").strip()
EXPECTED_IOS_SIGNING_ID = os.environ.get("INTEGRITY_IOS_SIGNING_ID", "").strip()
EXPECTED_IOS_TEAM_ID = os.environ.get("INTEGRITY_IOS_TEAM_ID", "").strip()
EXPECTED_IOS_EXECUTABLE_SHA256 = _env_values("INTEGRITY_IOS_EXECUTABLE_SHA256")

# Collector versions accepted in integrity reports (DESIGN.md 63). The Kotlin,
# Swift and .NET collectors report 2 and the conformance suite 1; raise the
# floor to retire an old collector. A version outside the range is refused with
# 400 rather than scored: an unknown collector is not evidence.
INTEGRITY_MIN_COLLECTOR_VERSION = int(
    os.environ.get("INTEGRITY_MIN_COLLECTOR_VERSION", "1")
)
INTEGRITY_MAX_COLLECTOR_VERSION = 1000
if INTEGRITY_MIN_COLLECTOR_VERSION < 1:
    raise RuntimeError("INTEGRITY_MIN_COLLECTOR_VERSION must be at least 1.")

REQUIRE_HTTPS = os.environ.get("REQUIRE_HTTPS", "0") == "1"
# Reverse proxies in front of this process that set X-Forwarded-For/-Proto
# (DESIGN.md 63). 0, the default, trusts no forwarded header at all: the HTTPS
# guard used to believe a client-supplied X-Forwarded-Proto, so a direct HTTP
# request could claim to be HTTPS (review F8). Set it to the number of proxies
# that REPLACE these headers -- 1 for a single nginx/Caddy terminating TLS in
# front of a backend that listens only on 127.0.0.1.
TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
# Whole-request body limit, enforced before JSON parsing (413). The largest
# legitimate body, a signed integrity report, is well under 140 KiB.
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(256 * 1024)))

app = Flask(__name__)
if TRUSTED_PROXY_COUNT > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=TRUSTED_PROXY_COUNT, x_proto=TRUSTED_PROXY_COUNT
    )
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
app.config["JWT_SECRET_KEY"] = _JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_TOKEN_LIFETIME
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = REFRESH_TOKEN_LIFETIME
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_HEADER_TYPE"] = "Bearer"
jwt = JWTManager(app)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("device-recognition")


# ---------------------------------------------------------------------------
# Errors and validation
# ---------------------------------------------------------------------------


class ApiProblem(Exception):
    def __init__(self, message, status=400, code="bad_request", details=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.details = details


@app.errorhandler(ApiProblem)
def handle_api_problem(error):
    payload = {"error": {"code": error.code, "message": error.message}}
    if error.details is not None:
        payload["error"]["details"] = error.details
    return jsonify(payload), error.status


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return (
        jsonify(
            {
                "error": {
                    "code": error.name.lower().replace(" ", "_"),
                    "message": error.description,
                }
            }
        ),
        error.code,
    )


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.exception("Unhandled server error")
    return (
        jsonify(
            {
                "error": {
                    "code": "internal_error",
                    "message": "The server could not complete the request.",
                }
            }
        ),
        500,
    )


@jwt.unauthorized_loader
def jwt_missing(reason):
    return jsonify({"error": {"code": "missing_token", "message": reason}}), 401


@jwt.invalid_token_loader
def jwt_invalid(reason):
    return jsonify({"error": {"code": "invalid_token", "message": reason}}), 401


@jwt.expired_token_loader
def jwt_expired(jwt_header, jwt_payload):
    return (
        jsonify(
            {
                "error": {
                    "code": "expired_token",
                    "message": "The token has expired.",
                }
            }
        ),
        401,
    )


def _json_body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiProblem("A JSON object is required.", 400, "invalid_json")
    return body


def _required_text(body, field, minimum=1, maximum=4096):
    value = body.get(field)
    if not isinstance(value, str):
        raise ApiProblem("%s must be a string." % field, 400, "invalid_%s" % field)
    value = value.strip()
    if len(value) < minimum or len(value) > maximum:
        raise ApiProblem(
            "%s must be between %d and %d characters."
            % (field, minimum, maximum),
            400,
            "invalid_%s" % field,
        )
    return value


def _uuid_text(value, field):
    if not isinstance(value, str):
        raise ApiProblem("%s must be a UUID string." % field, 400, "invalid_%s" % field)
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise ApiProblem("%s is not a valid UUID." % field, 400, "invalid_%s" % field)


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value, field, maximum_bytes=8192):
    if not isinstance(value, str) or not value:
        raise ApiProblem("%s must be base64url text." % field, 400, "invalid_%s" % field)
    if len(value) > maximum_bytes * 2:
        raise ApiProblem("%s is too large." % field, 400, "invalid_%s" % field)
    try:
        padded = value + ("=" * ((4 - len(value) % 4) % 4))
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, TypeError, base64.binascii.Error):
        raise ApiProblem("%s is not valid base64url." % field, 400, "invalid_%s" % field)
    if len(decoded) > maximum_bytes:
        raise ApiProblem("%s is too large." % field, 400, "invalid_%s" % field)
    return decoded


def _utc_now():
    return datetime.now(timezone.utc)


def _iso_z(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@app.before_request
def transport_guard():
    if not REQUIRE_HTTPS or request.path in ("/health/live", "/health/ready"):
        return None
    # request.scheme is the connection's own scheme, or -- only when
    # TRUSTED_PROXY_COUNT is set -- the one the trusted proxy recorded. A raw
    # X-Forwarded-Proto from the client is never consulted.
    if request.scheme.lower() != "https":
        raise ApiProblem(
            "HTTPS is required for this endpoint.", 426, "https_required"
        )
    return None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


# TLS to the database. Managed engines commonly force TLS (RDS sets
# rds.force_ssl), and psycopg2's default "prefer" would silently accept an
# unverified session. "verify-full" additionally pins the server certificate to
# a trusted CA *and* checks the hostname, which is what stops an attacker who
# can reach the database subnet from impersonating it. Point DB_SSLROOTCERT at
# the provider CA bundle (for RDS:
# https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem).
DB_SSLMODE = os.environ.get("DB_SSLMODE", "prefer").strip()
DB_SSLROOTCERT = os.environ.get("DB_SSLROOTCERT", "").strip()

if DB_SSLMODE in ("verify-ca", "verify-full") and not DB_SSLROOTCERT:
    raise RuntimeError(
        "DB_SSLMODE=%s requires DB_SSLROOTCERT to point at the CA bundle." % DB_SSLMODE
    )


# ---------------------------------------------------------------------------
# SQL dialect
# ---------------------------------------------------------------------------
# Everything that genuinely differs between PostgreSQL and SQL Server lives
# here. The principle is deliberate: token-level differences (placeholders, the
# current-time function) are translated automatically at one seam, but anything
# that changes *semantics* - the replay upsert and row locking above all - gets
# an explicit per-dialect statement rather than a string rewrite. A silent
# mistranslation in those two places reopens a real attack, so they must be
# read and reviewed as SQL, not trusted to a regex.


DB_ENGINE = os.environ.get("DB_ENGINE", "postgresql").strip().lower()


class Dialect(object):
    """Base dialect. Subclasses supply the engine-specific behaviour."""

    name = None
    paramstyle = "format"

    def connect(self):
        raise NotImplementedError

    def unit_lock(self):
        """Held for a whole unit of work (connect .. close); none by default."""
        return nullcontext()

    def sql(self, text):
        """Translate a statement written in the canonical (PostgreSQL) form."""
        return text

    def json_param(self, value):
        """Adapt a Python object for a JSON column."""
        raise NotImplementedError

    def json_value(self, raw):
        """Adapt a JSON column read back from the driver into Python."""
        if raw is None or isinstance(raw, (dict, list)):
            return raw
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw

    def is_unique_violation(self, error):
        raise NotImplementedError

    def bind_parameters(self, parameters):
        """Adapt bound parameters to what the driver expects."""
        return parameters

    def row_lock_suffix(self):
        """Statement suffix that takes an exclusive row lock."""
        return ""

    def row_lock_hint(self):
        """Table hint that takes an exclusive row lock."""
        return ""

    def savepoint(self, name):
        """(set, rollback, release) statements that let one failed statement be
        undone without losing the enclosing transaction, or None where the
        engine already rolls back only the failed statement."""
        return None


class PostgresDialect(Dialect):
    name = "postgresql"

    def __init__(self):
        # Imported lazily, exactly like pyodbc below, so that each deployment
        # installs only the driver for the engine it actually runs. A SQL
        # Server shop should not be made to build psycopg2.
        import psycopg2
        import psycopg2.errors
        from psycopg2.extras import Json

        self._driver = psycopg2
        self._json = Json

    def connect(self):
        options = {
            "host": os.environ.get("DB_HOST", "localhost"),
            "port": int(os.environ.get("DB_PORT", "5432")),
            "database": os.environ.get("DB_NAME", "devicetrustdb"),
            "user": os.environ["DB_USERNAME"],
            "password": os.environ["DB_PASSWORD"],
            "connect_timeout": int(os.environ.get("DB_CONNECT_TIMEOUT", "5")),
            "sslmode": DB_SSLMODE,
        }
        if DB_SSLROOTCERT:
            options["sslrootcert"] = DB_SSLROOTCERT
        return self._driver.connect(**options)

    def json_param(self, value):
        return self._json(value)

    def is_unique_violation(self, error):
        return isinstance(error, self._driver.errors.UniqueViolation)

    def row_lock_suffix(self):
        return " FOR UPDATE"

    def savepoint(self, name):
        # Any failed statement aborts the whole PostgreSQL transaction; every
        # later statement fails with "current transaction is aborted" until a
        # rollback. A savepoint confines the rollback to the failed statement.
        return (
            "SAVEPOINT %s" % name,
            "ROLLBACK TO SAVEPOINT %s" % name,
            "RELEASE SAVEPOINT %s" % name,
        )


class SqlServerDialect(Dialect):
    """SQL Server 2017+ (written to 2016-compatible T-SQL).

    Only the token-level translation lives here; the statements whose shape
    differs (LIMIT/TOP, FOR UPDATE/UPDLOCK, RETURNING/OUTPUT, ON CONFLICT) are
    selected explicitly at their call sites.
    """

    name = "sqlserver"
    paramstyle = "qmark"

    # SQL_SS_TIMESTAMPOFFSET. pyodbc has no native mapping for datetimeoffset
    # and hands back the raw TDS bytes, so every timestamp in the system would
    # arrive as bytes and every expiry comparison would fail. The converter
    # below is what makes datetimeoffset usable.
    _SQL_SS_TIMESTAMPOFFSET = -155

    # DESIGN.md 55. On the reference host (unixODBC 2.3.12, msodbcsql18
    # 18.6.2.1, arm64) the ODBC stack is not safe to drive from concurrent
    # threads, even on separate connections: parallel clients reproduced heap
    # corruption, a SIGSEGV inside cursor.execute, and a deadlock between
    # connect and close. Every unit of work therefore runs under one
    # process-wide re-entrant lock (re-entrant because units nest); scale a
    # SQL Server deployment with worker processes, not threads.
    _unit_lock = threading.RLock()

    def unit_lock(self):
        return self._unit_lock

    @staticmethod
    def _decode_datetimeoffset(raw):
        if raw is None:
            return None
        year, month, day, hour, minute, second, fraction, tz_hour, tz_minute = (
            struct.unpack("<6hI2h", raw)
        )
        return datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction // 1000,
            timezone(timedelta(hours=tz_hour, minutes=tz_minute)),
        )

    def connect(self):
        import pyodbc  # imported lazily so PostgreSQL deployments need no ODBC

        # The server is threaded and opens a connection per unit of work. With
        # pyodbc's default driver-manager pooling on, concurrent requests
        # corrupted the heap and killed the process (DESIGN.md 55). Pooling is a
        # process-wide setting read when the first connection is made.
        pyodbc.pooling = False

        parts = [
            "DRIVER={ODBC Driver 18 for SQL Server}",
            "SERVER=%s,%s" % (
                os.environ.get("DB_HOST", "localhost"),
                os.environ.get("DB_PORT", "1433"),
            ),
            "DATABASE=%s" % os.environ.get("DB_NAME", "devicetrustdb"),
            "UID=%s" % os.environ["DB_USERNAME"],
            "PWD=%s" % os.environ["DB_PASSWORD"],
            "Encrypt=yes",
            # Never TrustServerCertificate=yes: that is encryption without
            # authentication, which is what verify-full exists to prevent.
            "TrustServerCertificate=no",
            "LoginTimeout=%s" % os.environ.get("DB_CONNECT_TIMEOUT", "5"),
        ]
        connection = pyodbc.connect(";".join(parts))
        # A statement must fail rather than wait forever: units of work are
        # serialized (above), so one statement stuck behind the server -- e.g.
        # queued for a memory grant on a small instance (DESIGN.md 55) -- would
        # otherwise stall every request in the process.
        connection.timeout = int(os.environ.get("DB_QUERY_TIMEOUT", "15"))
        connection.add_output_converter(
            self._SQL_SS_TIMESTAMPOFFSET, self._decode_datetimeoffset
        )
        return connection

    _LIMIT_TAIL = re.compile(r"\s+LIMIT\s+(\d+)\s*$", re.IGNORECASE)
    _LEADING_SELECT = re.compile(r"^(\s*)SELECT\s", re.IGNORECASE)

    def sql(self, text):
        # Interval arithmetic first, while NOW() is still recognisable.
        text = text.replace(
            "NOW() - INTERVAL '1 day'", "DATEADD(day, -1, SYSUTCDATETIME())"
        )
        # SYSUTCDATETIME, never GETDATE: GETDATE is server-local and would
        # silently shift every expiry window.
        text = text.replace("NOW()", "SYSUTCDATETIME()")
        # LIMIT n is a trailing clause; TOP n is a prefix. Rewrite rather than
        # leave it, since only trailing "LIMIT <digits>" is ever used here.
        trimmed = text.rstrip()
        match = self._LIMIT_TAIL.search(trimmed)
        if match:
            trimmed = self._LIMIT_TAIL.sub("", trimmed)
            text = self._LEADING_SELECT.sub(
                "\\1SELECT TOP %s " % match.group(1), trimmed, count=1
            )
        text = text.replace("%s", "?")
        return text

    def json_param(self, value):
        return json.dumps(value)

    def is_unique_violation(self, error):
        # 2627 = unique constraint, 2601 = unique index.
        return any(code in str(error) for code in ("2627", "2601"))

    def bind_parameters(self, parameters):
        # pyodbc binds a datetime as SQL_TIMESTAMP and drops tzinfo rather than
        # converting it, so an aware non-UTC value would be written with its
        # wall-clock fields and silently shift the expiry it represents.
        # Converting to UTC first makes the implicit datetime2 ->
        # datetimeoffset promotion land on +00:00, which is what every column
        # in this schema means.
        adapted = []
        for value in parameters:
            if isinstance(value, datetime) and value.tzinfo is not None:
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            adapted.append(value)
        return tuple(adapted)

    def row_lock_hint(self):
        # PostgreSQL is MVCC; SQL Server READ COMMITTED takes shared locks and
        # would let refresh-reuse detection be raced without this.
        return " WITH (UPDLOCK, ROWLOCK)"

    # savepoint() stays None: a duplicate-key error (2627/2601) terminates only
    # its own statement, and the transaction continues, because this server
    # never sets XACT_ABORT ON.


def _make_dialect():
    if DB_ENGINE == "postgresql":
        return PostgresDialect()
    if DB_ENGINE == "sqlserver":
        return SqlServerDialect()
    raise RuntimeError("DB_ENGINE must be 'postgresql' or 'sqlserver'.")


DIALECT = _make_dialect()


class _DialectCursor(object):
    """Cursor wrapper that translates statements on the way through.

    This is the single seam where canonical SQL becomes dialect SQL, so the
    48 call sites in this file stay written once.
    """

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, statement, parameters=None):
        translated = DIALECT.sql(statement)
        if parameters is None:
            return self._cursor.execute(translated)
        return self._cursor.execute(
            translated, DIALECT.bind_parameters(parameters)
        )

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def __iter__(self):
        return iter(self._cursor)


# ---------------------------------------------------------------------------
# Redis
#
# Redis is optional. It is configured only when REDIS_URL is set, and the
# `redis` package is imported lazily, so a deployment that does not use it
# installs nothing extra.
#
# Two very different things are stored here, and they deliberately fail in
# opposite directions:
#
#   nonces        fail CLOSED. The nonce store IS the replay defence. If it
#                 cannot be reached we must refuse the request, because
#                 "allow on error" turns a Redis outage into an open replay
#                 window - exactly the attack the nonce exists to stop.
#
#   rate limits   fail OPEN. Rate limiting protects availability. Refusing
#                 every request because the rate limiter is down converts a
#                 cache outage into a total outage, which is a worse outcome
#                 than briefly not enforcing a throttle.
#
# The nonce backend defaults to the database. Redis is faster and takes the
# write load off the database, but it is a weaker durability guarantee: a
# committed row survives anything, whereas Redis with appendfsync=everysec can
# lose up to a second of nonces on an unclean stop, and any nonce lost that way
# becomes replayable until its original expiry. Choose it deliberately, run it
# with appendonly yes, and know what the trade is.
# ---------------------------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "").strip()
NONCE_BACKEND = os.environ.get("NONCE_BACKEND", "database").strip().lower()
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "0").strip() == "1"
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get("RATE_LIMIT_MAX_ATTEMPTS", "20"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
# Per-source budgets (DESIGN.md 63, review F9) are looser than the per-identity
# ones above because one address can front many legitimate phones (carrier
# NAT). They key on request.remote_addr, which is the client's own address only
# when TRUSTED_PROXY_COUNT names the proxies in front; otherwise every client
# shares the proxy's address and one budget.
RATE_LIMIT_SOURCE_MAX_ATTEMPTS = int(
    os.environ.get("RATE_LIMIT_SOURCE_MAX_ATTEMPTS", "120")
)

if NONCE_BACKEND not in ("database", "redis"):
    raise RuntimeError(
        "NONCE_BACKEND must be 'database' or 'redis', not %r." % NONCE_BACKEND
    )
if NONCE_BACKEND == "redis" and not REDIS_URL:
    raise RuntimeError("NONCE_BACKEND=redis requires REDIS_URL to be set.")

_REDIS_CLIENT = None
_REDIS_LOCK = threading.Lock()


def _redis():
    """Return a shared Redis client, or raise if Redis is not configured."""
    global _REDIS_CLIENT
    if not REDIS_URL:
        raise RuntimeError("REDIS_URL is not configured.")
    if _REDIS_CLIENT is None:
        with _REDIS_LOCK:
            if _REDIS_CLIENT is None:
                import redis  # imported lazily; not a dependency without Redis

                _REDIS_CLIENT = redis.Redis.from_url(
                    REDIS_URL,
                    socket_timeout=2,
                    socket_connect_timeout=2,
                    health_check_interval=30,
                    decode_responses=True,
                )
    return _REDIS_CLIENT


def _redis_status():
    """Health-check view of Redis. Never raises."""
    if not REDIS_URL:
        return {"configured": False, "nonce_backend": NONCE_BACKEND}
    state = {
        "configured": True,
        "nonce_backend": NONCE_BACKEND,
        "rate_limiting": RATE_LIMIT_ENABLED,
    }
    try:
        info = _redis().info("persistence")
        state["reachable"] = True
        # Surface this: NONCE_BACKEND=redis without AOF is a silent downgrade
        # of the replay defence, and an operator should be able to see it.
        state["appendonly"] = info.get("aof_enabled") in (1, "1", True)
    except Exception as error:
        state["reachable"] = False
        state["error"] = type(error).__name__
    return state


def _claim_nonce_redis(nonce_hash, installation_id):
    """Atomically claim a nonce. SET NX is atomic on Redis's single thread, so
    a concurrent duplicate loses the race and is reported as a replay."""
    ttl_ms = int(ACCESS_PROOF_NONCE_RETENTION.total_seconds() * 1000)
    try:
        claimed = _redis().set(
            "dt:nonce:%s" % nonce_hash, installation_id, nx=True, px=ttl_ms
        )
    except Exception:
        logger.exception("The Redis nonce store is unreachable.")
        # Fail closed. See the note at the top of this section.
        raise ApiProblem(
            "The replay-protection store is unavailable.",
            503,
            "nonce_store_unavailable",
        )
    if not claimed:
        raise ApiProblem(
            "This signed access proof has already been used.",
            401,
            "access_proof_replay",
        )


def _rate_limiter_unavailable():
    """This request went unthrottled; its risk decision says so (DESIGN.md 77)."""
    if has_request_context():
        g.rate_limiter_unavailable = True


def _enforce_rate_limit(bucket, identity, limit=None):
    """Throttle repeated attempts. Fails open by design -- and an outage is
    noted on the request, never passed off as a throttle that ran."""
    if not RATE_LIMIT_ENABLED:
        return
    if not REDIS_URL:
        _rate_limiter_unavailable()
        return
    key = "dt:rate:%s:%s" % (bucket, identity)
    try:
        client = _redis()
        attempts = client.incr(key)
        if attempts == 1:
            client.expire(key, RATE_LIMIT_WINDOW_SECONDS)
    except Exception:
        logger.exception("The Redis rate limiter is unreachable; allowing.")
        _rate_limiter_unavailable()
        return
    if attempts > (limit or RATE_LIMIT_MAX_ATTEMPTS):
        raise ApiProblem(
            "Too many attempts. Try again shortly.",
            429,
            "rate_limited",
        )


def _limit_source(bucket):
    """The per-source budget for one public or credential-bearing endpoint."""
    _enforce_rate_limit(
        bucket + "_source", request.remote_addr or "unknown", RATE_LIMIT_SOURCE_MAX_ATTEMPTS
    )


# Housekeeping deletes of expired, ephemeral rows (nonces, unused challenges)
# used to run inside every request that touched those tables (review F9). Each
# worker now runs each one at most once per MAINTENANCE_INTERVAL_SECONDS. These
# are the only rows the server ever deletes: nothing that records a
# relationship or a verdict is removed (DESIGN.md 63.3a).
MAINTENANCE_INTERVAL_SECONDS = int(os.environ.get("MAINTENANCE_INTERVAL_SECONDS", "60"))
_maintenance_last = {}
_maintenance_lock = threading.Lock()


def _maintenance_due(name):
    now = time.monotonic()
    with _maintenance_lock:
        if _maintenance_last.get(name, -1e9) + MAINTENANCE_INTERVAL_SECONDS > now:
            return False
        _maintenance_last[name] = now
        return True


def _key_request_rate(installation_id, window_seconds):
    """Requests seen for one installation in the current window, or None.

    A per-installation Redis counter, incremented once per risk evaluation.
    None when it cannot be read -- no Redis configured, or Redis unreachable:
    degraded evidence, never a measured rate of zero (DESIGN.md 77). Nothing
    refuses on None, so a cache outage still cannot become a lockout.
    """
    if not REDIS_URL:
        return None
    key = "dt:reqrate:%s" % installation_id
    try:
        client = _redis()
        count = client.incr(key)
        if count == 1:
            client.expire(key, max(1, int(window_seconds)))
        return int(count)
    except Exception:
        logger.exception("Request-rate counter unreachable; deciding without it.")
        return None


def _connect_db():
    return DIALECT.connect()


# Per-process pool of idle connections (DESIGN.md 60). Opening a connection
# costs a TCP + TLS handshake and a login on every unit of work; reusing one
# removes that from the request path. The pool belongs to one process: after a
# fork (a multi-process server) the child starts empty and never touches the
# parent's sockets. A connection idle longer than DB_POOL_RECHECK_SECONDS is
# pinged before reuse; DB_POOL_SIZE=0 turns pooling off.
DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "4"))
DB_POOL_RECHECK_SECONDS = int(os.environ.get("DB_POOL_RECHECK_SECONDS", "30"))
_pool_lock = threading.Lock()
_pool_state = {"pid": None, "idle": []}


def _close_quietly(connection):
    try:
        connection.close()
    except Exception:
        pass


def _connection_alive(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        connection.rollback()
        return True
    except Exception:
        return False


def _checkout_connection():
    with _pool_lock:
        if _pool_state["pid"] != os.getpid():
            _pool_state["pid"] = os.getpid()
            _pool_state["idle"] = []
        idle = _pool_state["idle"].pop() if _pool_state["idle"] else None
    if idle is not None:
        connection, last_used = idle
        if time.monotonic() - last_used < DB_POOL_RECHECK_SECONDS or _connection_alive(
            connection
        ):
            return connection
        _close_quietly(connection)
    return _connect_db()


def _checkin_connection(connection, reusable):
    if reusable and DB_POOL_SIZE > 0:
        with _pool_lock:
            if (
                _pool_state["pid"] == os.getpid()
                and len(_pool_state["idle"]) < DB_POOL_SIZE
            ):
                _pool_state["idle"].append((connection, time.monotonic()))
                return
    _close_quietly(connection)


@contextmanager
def _cursor(commit=False):
    # A no-op for PostgreSQL; serializes units of work for SQL Server (55).
    with DIALECT.unit_lock():
        connection = _checkout_connection()
        reusable = False
        cursor = None
        try:
            cursor = _DialectCursor(connection.cursor())
            yield cursor
            if commit:
                connection.commit()
            else:
                # End the read transaction so a pooled connection holds no
                # snapshot or locks while idle.
                connection.rollback()
            reusable = True
        except Exception:
            try:
                connection.rollback()
                reusable = True
            except Exception:
                reusable = False
            raise
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    reusable = False
            _checkin_connection(connection, reusable)


# ---------------------------------------------------------------------------
# Backend identity
# ---------------------------------------------------------------------------
# This server runs on a deliberately wide range of databases - PostgreSQL 13+
# and SQL Server 2017+ (written to 2016-compatible T-SQL) - so the engine and
# its version are detected and published rather than assumed. /health/ready
# reports them, which is what lets a conformance run record which engine it
# actually exercised.

POSTGRES_MINIMUM_VERSION_NUM = 130000  # PostgreSQL 13
SQLSERVER_MINIMUM_MAJOR = 14  # SQL Server 2017 (internal major version 14)


def _read_backend_identity(cursor):
    if DB_ENGINE == "postgresql":
        cursor.execute("SHOW server_version_num")
        version_num = int(cursor.fetchone()[0])
        return {
            "engine": "postgresql",
            "version": "%d.%d" % (version_num // 10000, version_num % 100),
            "minimum_supported": "13",
            "supported": version_num >= POSTGRES_MINIMUM_VERSION_NUM,
        }
    if DB_ENGINE == "sqlserver":
        cursor.execute(
            "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(64))"
        )
        product = str(cursor.fetchone()[0])
        return {
            "engine": "sqlserver",
            "version": product,
            "minimum_supported": "2017",
            "supported": int(product.split(".")[0]) >= SQLSERVER_MINIMUM_MAJOR,
        }
    raise RuntimeError("DB_ENGINE must be 'postgresql' or 'sqlserver'.")


_backend_identity = None
_backend_identity_lock = threading.Lock()


def _get_backend_identity():
    global _backend_identity
    if _backend_identity is not None:
        return _backend_identity
    with DIALECT.unit_lock(), _backend_identity_lock:  # lock order: unit first
        if _backend_identity is None:
            with _cursor() as cursor:
                identity = _read_backend_identity(cursor)
            if not identity["supported"]:
                logger.error(
                    "Database %s %s is below the supported minimum (%s); "
                    "behaviour is unverified on this version.",
                    identity["engine"],
                    identity["version"],
                    identity["minimum_supported"],
                )
            _backend_identity = identity
    return _backend_identity


# ---------------------------------------------------------------------------
# Schema version contract
# ---------------------------------------------------------------------------
# The application does NOT create or alter schema. Migrations under
# migrations/<dialect>/ are applied by a database administrator, and this
# service only verifies what it finds. Runtime DDL would force the application
# principal to hold DDL rights permanently, which is a finding in its own right
# and is routinely rejected in enterprise review.
#
# On a mismatch the service refuses to serve traffic rather than limping along
# against a schema it does not understand. /health/* still answers so operators
# can see why.

REQUIRED_SCHEMA_VERSION = 25

_schema_state = None
_schema_lock = threading.Lock()


def _read_schema_version(cursor):
    """Highest applied migration, or None when the table is absent."""
    if DB_ENGINE == "postgresql":
        cursor.execute("SELECT to_regclass('public.schema_migrations')")
        if cursor.fetchone()[0] is None:
            return None
    elif DB_ENGINE == "sqlserver":
        cursor.execute("SELECT OBJECT_ID('dbo.schema_migrations', 'U')")
        if cursor.fetchone()[0] is None:
            return None
    else:
        raise RuntimeError("DB_ENGINE must be 'postgresql' or 'sqlserver'.")
    cursor.execute("SELECT MAX(version) FROM schema_migrations")
    row = cursor.fetchone()
    return int(row[0]) if row and row[0] is not None else None


def _get_schema_state():
    global _schema_state
    if _schema_state is not None:
        return _schema_state
    with DIALECT.unit_lock(), _schema_lock:  # lock order: unit first
        if _schema_state is None:
            with _cursor() as cursor:
                found = _read_schema_version(cursor)
            state = {
                "required": REQUIRED_SCHEMA_VERSION,
                "found": found,
                "ok": found == REQUIRED_SCHEMA_VERSION,
            }
            if state["ok"]:
                logger.info("Database schema version %s verified", found)
            elif found is None:
                logger.error(
                    "No schema_migrations table. Apply migrations/%s/001_initial.sql "
                    "before starting the service.",
                    DB_ENGINE,
                )
            else:
                logger.error(
                    "Database schema is version %s but this build requires %s. "
                    "Apply the pending migrations, or deploy the matching build.",
                    found,
                    REQUIRED_SCHEMA_VERSION,
                )
            _schema_state = state
    return _schema_state


@app.before_request
def schema_guard():
    if request.path.startswith("/health/"):
        return None
    state = _get_schema_state()
    if not state["ok"]:
        raise ApiProblem(
            "The database schema does not match this build.",
            503,
            "schema_version_mismatch",
            details={"schema": state},
        )
    return None


# ---------------------------------------------------------------------------
# DBA-tunable risk policy settings (migration 003)
# ---------------------------------------------------------------------------
# risk_policy_settings is owned by the consumer's DBA and read -- never written
# -- by the server. Values are cached with a short TTL so a DBA UPDATE takes
# effect without a restart.
#
# The read fails CLOSED (DESIGN.md 63). It used to fall back to an empty dict,
# and an empty dict means "no path needs step-up": a cold worker that could not
# read the table -- a missing SELECT grant is enough -- served sensitive
# operations without step-up. Now only a successfully loaded and validated
# snapshot is used. A worker that loaded one keeps serving it for at most
# RISK_SETTINGS_MAX_STALE_SECONDS while reads fail (visible on /health/ready as
# "stale"); a worker with none, or past that bound, refuses policy-dependent
# requests with 503 risk_policy_unavailable.

# Route-3 verification keys (DESIGN.md 70): the customer's identity backend
# signs upgrade assertions (ES256 JWS); its public keys are deployment
# configuration -- a JWKS file next to the other secrets, read once per process,
# so a key rotation is a restart. UPGRADE_ASSERTION_ISSUER, when set, must
# equal each assertion's "iss".
UPGRADE_ASSERTION_JWKS_FILE = os.environ.get("UPGRADE_ASSERTION_JWKS_FILE", "").strip()
UPGRADE_ASSERTION_ISSUER = os.environ.get("UPGRADE_ASSERTION_ISSUER", "").strip()
UPGRADE_ASSERTION_AUDIENCE = "device-trust-upgrade"
UPGRADE_ASSERTION_MAX_LIFETIME_SECONDS = 600
_upgrade_assertion_cache = {}

RISK_SETTINGS_CACHE_TTL_SECONDS = int(
    os.environ.get("RISK_SETTINGS_CACHE_TTL_SECONDS", "30")
)
RISK_SETTINGS_MAX_STALE_SECONDS = int(
    os.environ.get("RISK_SETTINGS_MAX_STALE_SECONDS", "300")
)
_RISK_SETTINGS_RETRY_SECONDS = 5
_risk_settings_cache = {"at": 0.0, "values": None, "failed_at": None, "error": None}
_risk_settings_lock = threading.Lock()

# The server's own observations as rules (DESIGN.md 77): what the server saw
# and recorded itself -- never what a phone reports -- counted over
# cross_check_window_hours. Each rule's count and points are DBA settings,
# <code>_count and <code>_points, seeded by migration 019 with the defaults
# below (0 switches a rule off); none adds points unless cross_checks_enabled.
# A phone's rules count what that phone did. The account's rule judges only a
# phone new to the account, by the wrong passwords OTHER phones sent in the
# window before it joined.
#   (code, scope, measured key, default count, default points, message)
_CROSS_CHECK_RULES = (
    ("account_sign_in_failures_elsewhere", "newcomer", "sign_in_failed_elsewhere_before",
     5, 30,
     "%d wrong-password sign-ins to this account came from other phones in the %d hours "
     "before this phone joined it."),
    ("device_sign_in_failures_many_accounts", "device", "sign_in_failed_accounts", 3, 60,
     "Wrong-password sign-ins to %d different accounts came from this phone in the last "
     "%d hours."),
    ("device_sign_in_unknown_accounts", "device", "sign_in_unknown_account", 5, 30,
     "%d sign-ins to accounts that do not exist came from this phone in the last %d hours."),
    ("device_stepup_failures", "device", "stepup_failed", 3, 30,
     "%d step-up proofs from this phone did not verify in the last %d hours."),
    # What an approval flow or a re-enrolment says concerns one account on the
    # phone, never the others sharing it: these three count this account on
    # this phone.
    ("device_approvals_denied", "device_account", "approval_denied", 1, 30,
     "%d approval requests from this phone for this account were denied in the last %d "
     "hours."),
    # Counted once per budget period -- until the oldest request in the hour
    # leaves it -- however often the phone asked meanwhile: one impatient hour
    # is one, a second period is two (owner decision of 2026-10-14).
    ("device_approval_budget_exhausted", "device_account", "approval_budget_exhausted", 2, 30,
     "This phone found this account's hourly approval budget spent in %d separate budget "
     "periods in the last %d hours."),
    ("device_stepup_reenrolments", "device_account", "stepup_reenrolled", 2, 30,
     "This account's step-up key on this phone was re-enrolled %d times in the last %d "
     "hours."),
    ("device_app_pin_failures", "device_account", "app_pin_failed", 3, 30,
     "%d wrong app PINs for this account came from this phone in the last %d hours."),
)
CROSS_CHECK_WINDOW_HOURS = 24

# Measurements a business may want and the OS allows, but which identify a
# person's phone or network: collected only where the DBA lists them in
# optional_measurements AND the app's developers enabled them; anything else
# is dropped before a report is stored (DESIGN.md 80). Migration 024 added what
# can read or drive the phone -- Accessibility and the keyboard, notification
# access, device administrators and remote-control apps -- screen capture, the
# location and whether it is mocked (DESIGN.md 82).
_OPTIONAL_MEASUREMENTS = ("local_addresses", "accessibility", "notification_access",
                          "other_access", "screen_capture", "location", "mock_location")
# The app stores an app counts as "from a store" when one of them installed it
# (migration 024's default; the DBA's app_store_installers replaces it). Each
# was checked against published installer tables, 2026-10-15; a store missing
# here -- vivo's, Honor's -- counts as sideloading until the DBA adds it.
APP_STORE_INSTALLERS_DEFAULT = (
    "com.android.vending,com.sec.android.app.samsungapps,com.huawei.appmarket,"
    "com.heytap.market,com.oppo.market,com.xiaomi.mipicks,com.amazon.venezia"
)

# What each known setting must parse as. A value that does not is a DBA typo;
# substituting the default would hide it, so the snapshot is refused instead.
# Keys not listed here pass through unchecked.
_RISK_SETTING_KINDS = {
    "stepup_required_paths": "paths",
    "stepup_factor": ("passcode", "biometric"),
    "stepup_mode": ("per_use", "windowed"),
    "stepup_window_seconds": "int",
    "rate_anomaly_enabled": "bool",
    "rate_anomaly_max_requests": "int",
    "rate_anomaly_window_seconds": "int",
    "rate_anomaly_points": "int",
    "population_baseline_enabled": "bool",
    "population_baseline_metric": ("accounts_per_device", "installations_per_device"),
    "population_baseline_threshold": "int",
    "population_points": "int",
    "device_accounts_elevated_count": "int",
    "device_accounts_elevated_points": "int",
    "device_accounts_review_count": "int",
    "device_accounts_review_points": "int",
    "device_accounts_block_count": "int",
    "elevated_risk_refuses": "bool",
    "wx_far_above_baseline_percent": "int",
    "developer_options_refuses": "bool",
    "adb_enabled_refuses": "bool",
    # Migration 022 (DESIGN.md 80).
    "vpn_active_refuses": "bool",
    "http_proxy_refuses": "bool",
    "optional_measurements": "list:" + ",".join(_OPTIONAL_MEASUREMENTS),
    "record_source_ip": "bool",
    "record_user_agent": "bool",
    # Migration 023 (DESIGN.md 81).
    "vpn_exit_learning": "bool",
    "vpn_exit_min_phones": "int",
    "vpn_exit_min_share_percent": "int",
    "vpn_exit_window_days": "int",
    "source_vpn_listed_points": "int",
    "source_tor_exit_points": "int",
    "source_hosting_points": "int",
    "source_vpn_observed_points": "int",
    "source_vpn_observed_non_hosting_points": "int",
    # Migration 024 (DESIGN.md 82).
    "app_store_installers": "packages",
    "accessibility_sideloaded_refuses": "bool",
    "accessibility_non_system_refuses": "bool",
    "keyboard_sideloaded_refuses": "bool",
    "keyboard_non_system_refuses": "bool",
    "notification_access_sideloaded_refuses": "bool",
    "notification_access_non_system_refuses": "bool",
    "device_admin_sideloaded_refuses": "bool",
    "device_admin_non_system_refuses": "bool",
    "remote_access_app_refuses": "bool",
    "screen_capture_refuses": "bool",
    "mock_location_refuses": "bool",
    "security_patch_max_age_days": "int",
    "security_patch_outdated_refuses": "bool",
    "accessibility_sideloaded_points": "int",
    "accessibility_non_system_points": "int",
    "keyboard_sideloaded_points": "int",
    "keyboard_non_system_points": "int",
    "notification_access_sideloaded_points": "int",
    "notification_access_non_system_points": "int",
    "device_admin_sideloaded_points": "int",
    "device_admin_non_system_points": "int",
    "remote_access_app_points": "int",
    "screen_capture_points": "int",
    "mock_location_points": "int",
    "security_patch_outdated_points": "int",
    # Migration 025 (DESIGN.md 83).
    "conditions_points_cap": "int",
    "limited_session_paths": "paths",
    "limited_session_integrity_verdicts": "list:elevated,review",
    "limited_session_policy_actions": "list:step_up,review",
    "upgrade_stepup_same_device": "bool",
    "upgrade_other_device_approval": "bool",
    "upgrade_mfa_assertion": "bool",
    "upgrade_request_ttl_seconds": "int",
    "upgrade_approvals_per_hour": "int",
    "policy_step_up_score": "int",
    "policy_review_score": "int",
    "policy_block_score": "int",
    "account_devices_elevated_count": "int",
    "account_devices_elevated_points": "int",
    "account_devices_review_count": "int",
    "account_devices_review_points": "int",
    "account_devices_block_count": "int",
    "upgrade_acceptance_hours": "int",
    "collection_problems_block": "bool",
    "integrity_device_memory_hours": "int",
    "complete_evidence_paths": "paths",
    "complete_evidence_max_age_seconds": "int",
    "incomplete_evidence_review_after": "int",
    "acceptance_auto_cover_reasons": "codes",
    "business_event_types": "codes",
    "business_graph_depth": "int",
    "business_graph_max_nodes": "int",
    "legacy_acceptances": ("carry", "drop"),
    "cross_checks_enabled": "bool",
    "cross_check_window_hours": "int",
    "device_approvals_denied_effect": ("limit", "points"),
    "stepup_method": ("screen_lock", "app_pin", "screen_lock_and_app_pin"),
    "app_pin_required_paths": "paths",
    "app_pin_length": "int",
    "app_pin_max_failures": "int",
    # Migration 021 (DESIGN.md 79): the relationship rules, scan freshness and
    # the hardware-backing policy, session lifetimes, support for app PINs.
    "new_device_points": "int",
    "new_device_hours": "int",
    "known_device_new_installation_points": "int",
    "reinstall_window_hours": "int",
    "reinstall_elevated_count": "int",
    "reinstall_elevated_points": "int",
    "reinstall_high_count": "int",
    "reinstall_high_points": "int",
    "reinstall_block_count": "int",
    "integrity_report_missing_points": "int",
    "integrity_report_stale_points": "int",
    "integrity_freshness_seconds": "int",
    "device_integrity_history_block_points": "int",
    "hardware_backing_policy": ("off", "advisory", "required"),
    "refresh_idle_days": "int",
    "session_max_days": "int",
    "app_pin_support": ("off", "unlock", "unlock_and_reset"),
    "app_pin_support_reset_minutes": "int",
}
_RISK_SETTING_KINDS.update(
    ("%s_%s" % (rule[0], part), "int")
    for rule in _CROSS_CHECK_RULES
    for part in ("count", "points")
)
# Lower bounds a value must also meet. Below 100 the "far above the baseline"
# rule would fire for memory inside the build's own measured envelope.
_RISK_SETTING_MINIMUMS = {
    "wx_far_above_baseline_percent": 100,
    "upgrade_request_ttl_seconds": 30,
    "policy_step_up_score": 1,
    "complete_evidence_max_age_seconds": 30,
    "business_graph_depth": 1,
    "business_graph_max_nodes": 1,
    "cross_check_window_hours": 1,
    "app_pin_length": 4,
    # Unlimited guesses at a 4-12 digit PIN is no setting: at least one.
    "app_pin_max_failures": 1,
    "reinstall_window_hours": 1,
    "integrity_freshness_seconds": 30,
    "refresh_idle_days": 1,
    "app_pin_support_reset_minutes": 1,
    "vpn_exit_min_phones": 1,
    "vpn_exit_min_share_percent": 1,
    "vpn_exit_window_days": 1,
    "conditions_points_cap": 1,
}
# Upper bounds a value must also meet. The session limits are ours (DESIGN.md
# 79): a refresh token idle for more than 90 days, or a session older than a
# year, is not a business choice.
_RISK_SETTING_MAXIMUMS = {
    "app_pin_length": 12,
    "integrity_freshness_seconds": 86400,
    "refresh_idle_days": 90,
    "session_max_days": 365,
    "app_pin_support_reset_minutes": 1440,
    "vpn_exit_min_share_percent": 100,
    "vpn_exit_window_days": 365,
    "security_patch_max_age_days": 3650,
    "conditions_points_cap": 100,
}
_RISK_SETTING_BOOL_WORDS = ("0", "1", "true", "false", "yes", "no", "on", "off")
# Rows whose absence would silently weaken a gate instead of restoring the
# owner's default. An EMPTY stepup_required_paths is a valid choice (step-up
# nowhere); a MISSING row is not that statement, so the snapshot is refused.
_RISK_SETTINGS_REQUIRED = ("stepup_required_paths", "stepup_factor", "stepup_mode")


def _validate_risk_settings(values):
    for key in _RISK_SETTINGS_REQUIRED:
        if key not in values:
            raise ValueError("risk_policy_settings has no %s row" % key)
    for key, kind in _RISK_SETTING_KINDS.items():
        if key not in values:
            continue
        value = values[key].strip()
        if kind == "int":
            valid = re.fullmatch(r"[0-9]{1,9}", value) is not None
        elif kind == "bool":
            valid = value.lower() in _RISK_SETTING_BOOL_WORDS
        elif kind == "paths":
            valid = all(
                path.strip().startswith("/")
                for path in value.replace(";", ",").split(",")
                if path.strip()
            )
        elif kind == "packages":
            # Android package names, comma-separated; empty is a valid choice
            # (then no installer is a store, DESIGN.md 82).
            valid = all(
                re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+", item.strip()) is not None
                and len(item.strip()) <= 128
                for item in value.replace(";", ",").split(",")
                if item.strip()
            )
        elif kind == "codes":
            # Reason codes, comma-separated; empty is a valid choice.
            valid = all(
                re.fullmatch(r"[a-z0-9_:]{1,96}", item.strip()) is not None
                for item in value.replace(";", ",").split(",")
                if item.strip()
            )
        elif isinstance(kind, str) and kind.startswith("list:"):
            # A comma-separated subset of fixed words; empty is a valid choice.
            # "block" is never among them: a block always refuses.
            allowed = kind[len("list:"):].split(",")
            valid = all(
                item.strip() in allowed
                for item in value.replace(";", ",").split(",")
                if item.strip()
            )
        else:
            valid = value in kind
        if valid and key in _RISK_SETTING_MINIMUMS:
            valid = int(value) >= _RISK_SETTING_MINIMUMS[key]
        if valid and key in _RISK_SETTING_MAXIMUMS:
            valid = int(value) <= _RISK_SETTING_MAXIMUMS[key]
        if not valid:
            raise ValueError("risk_policy_settings.%s has an invalid value" % key)
    # The relationship bands must rise: step-up < review < block. A missing
    # row means its fallback, so a lone retuned row is checked against those.
    bands = [
        int(values.get(key, "").strip() or default)
        for key, default in (
            ("policy_step_up_score", POLICY_STEP_UP_SCORE),
            ("policy_review_score", POLICY_REVIEW_SCORE),
            ("policy_block_score", POLICY_BLOCK_SCORE),
        )
    ]
    if not bands[0] < bands[1] < bands[2]:
        raise ValueError(
            "risk_policy_settings bands must rise: policy_step_up_score < "
            "policy_review_score < policy_block_score"
        )


def _risk_policy_settings():
    cache = _risk_settings_cache
    if cache["values"] is not None and (
        time.monotonic() - cache["at"]
    ) < RISK_SETTINGS_CACHE_TTL_SECONDS:
        return cache["values"]
    with DIALECT.unit_lock(), _risk_settings_lock:  # lock order: unit first
        now = time.monotonic()
        if cache["values"] is not None and now - cache["at"] < RISK_SETTINGS_CACHE_TTL_SECONDS:
            return cache["values"]
        failed_at = cache.get("failed_at")
        if failed_at is None or now - failed_at >= _RISK_SETTINGS_RETRY_SECONDS:
            try:
                values = {}
                with _cursor() as cursor:
                    cursor.execute(
                        "SELECT setting_key, setting_value FROM risk_policy_settings"
                    )
                    for row in cursor.fetchall():
                        values[str(row[0])] = str(row[1])
                _validate_risk_settings(values)
            except Exception as error:
                logger.exception("Could not load a valid risk_policy_settings snapshot")
                cache["failed_at"] = now
                cache["error"] = ("%s: %s" % (type(error).__name__, error))[:200]
            else:
                cache.update(values=values, at=now, failed_at=None, error=None)
                return values
        if cache["values"] is not None and now - cache["at"] < RISK_SETTINGS_MAX_STALE_SECONDS:
            return cache["values"]
        raise ApiProblem(
            "The risk policy could not be loaded, so the request was refused "
            "rather than evaluated without it.",
            503,
            "risk_policy_unavailable",
        )


def _risk_policy_status():
    """Health view of the policy snapshot: (status, values or None). Never raises."""
    try:
        values = _risk_policy_settings()
    except ApiProblem:
        return {"state": "unavailable", "error": _risk_settings_cache.get("error")}, None
    age = time.monotonic() - _risk_settings_cache["at"]
    if age < RISK_SETTINGS_CACHE_TTL_SECONDS:
        return {"state": "fresh", "age_seconds": int(age)}, values
    return {
        "state": "stale",
        "age_seconds": int(age),
        "max_stale_seconds": RISK_SETTINGS_MAX_STALE_SECONDS,
        "error": _risk_settings_cache.get("error"),
    }, values


def _risk_setting_str(key, default):
    value = _risk_policy_settings().get(key)
    return value if value is not None else default


def _risk_setting_int(key, default):
    try:
        return int(_risk_policy_settings().get(key, default))
    except (TypeError, ValueError):
        return default


def _risk_setting_bool(key, default=False):
    value = _risk_policy_settings().get(key)
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _integrity_freshness_seconds():
    """How old the latest scan may be and still count (DESIGN.md 79): the
    DBA's setting; INTEGRITY_FRESHNESS_SECONDS answers only a missing row."""
    return _risk_setting_int("integrity_freshness_seconds", INTEGRITY_FRESHNESS_SECONDS)


def _hardware_backing_policy():
    """The hardware-backing policy (DESIGN.md 50, 79): the DBA's setting;
    INTEGRITY_HARDWARE_BACKING_POLICY answers only a missing row."""
    return _risk_setting_str("hardware_backing_policy", INTEGRITY_HARDWARE_BACKING_POLICY)


def _risk_setting_words(key, default):
    """A comma-separated setting as a set of trimmed words (empty allowed)."""
    raw = _risk_setting_str(key, default)
    return {word.strip() for word in raw.replace(";", ",").split(",") if word.strip()}


# ---------------------------------------------------------------------------
# Installation key and reinstall-hint helpers
# ---------------------------------------------------------------------------


def _parse_public_key(public_key):
    if not isinstance(public_key, dict):
        raise ApiProblem("public_key must be an object.", 400, "invalid_public_key")

    kty = public_key.get("kty")
    alg = public_key.get("alg")

    if kty == "EC" and alg == "ES256":
        if public_key.get("crv") != "P-256":
            raise ApiProblem(
                "Only the P-256 curve is accepted for ES256 keys.",
                400,
                "unsupported_public_key_curve",
            )
        x_bytes = _b64url_decode(public_key.get("x"), "public_key.x", 64)
        y_bytes = _b64url_decode(public_key.get("y"), "public_key.y", 64)
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            raise ApiProblem(
                "P-256 x and y coordinates must each be exactly 32 bytes.",
                400,
                "invalid_public_key_size",
            )
        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")
        try:
            key = ECC.construct(curve="P-256", point_x=x, point_y=y)
        except (ValueError, TypeError):
            raise ApiProblem(
                "The P-256 public point is invalid.", 400, "invalid_public_key"
            )

        normalized = {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": _b64url_encode(x.to_bytes(32, "big")),
            "y": _b64url_encode(y.to_bytes(32, "big")),
        }
        canonical = json.dumps(
            {
                "crv": normalized["crv"],
                "kty": normalized["kty"],
                "x": normalized["x"],
                "y": normalized["y"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return {
            "algorithm": "ES256",
            "jwk": normalized,
            "key": key,
            "thumbprint": hashlib.sha256(canonical).hexdigest(),
        }

    # Backward compatibility for installation rows created by the first
    # exportable-RSA prototype. New mobile code never generates these keys.
    if kty == "RSA" and alg == "RS256":
        n_bytes = _b64url_decode(public_key.get("n"), "public_key.n", 1024)
        e_bytes = _b64url_decode(public_key.get("e"), "public_key.e", 16)
        n = int.from_bytes(n_bytes, "big")
        e = int.from_bytes(e_bytes, "big")

        if n.bit_length() < 2048 or n.bit_length() > 4096:
            raise ApiProblem(
                "The RSA modulus must be between 2048 and 4096 bits.",
                400,
                "invalid_public_key_size",
            )
        if e != 65537:
            raise ApiProblem(
                "The RSA public exponent must be 65537.",
                400,
                "invalid_public_exponent",
            )
        try:
            key = RSA.construct((n, e), consistency_check=True)
        except (ValueError, IndexError, TypeError):
            raise ApiProblem("The RSA public key is invalid.", 400, "invalid_public_key")

        normalized = {
            "kty": "RSA",
            "alg": "RS256",
            "n": _b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")),
            "e": _b64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")),
        }
        canonical = json.dumps(
            {"e": normalized["e"], "kty": "RSA", "n": normalized["n"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return {
            "algorithm": "RS256",
            "jwk": normalized,
            "key": key,
            "thumbprint": hashlib.sha256(canonical).hexdigest(),
        }

    raise ApiProblem(
        "Only EC/P-256/ES256 keys are accepted for new installations; "
        "RS256 remains accepted only for prototype compatibility.",
        400,
        "unsupported_public_key",
    )


def _verify_installation_signature(key_algorithm, public_key_jwk, payload, signature):
    if isinstance(public_key_jwk, str):
        try:
            public_key_jwk = json.loads(public_key_jwk)
        except json.JSONDecodeError:
            raise ApiProblem(
                "The stored public key is invalid.", 500, "stored_public_key_invalid"
            )

    parsed = _parse_public_key(public_key_jwk)
    if parsed["algorithm"] != key_algorithm:
        raise ApiProblem(
            "The stored key algorithm does not match its public key.",
            500,
            "stored_public_key_invalid",
        )

    try:
        digest = SHA256.new(payload)
        if key_algorithm == "ES256":
            # Android SHA256withECDSA and Apple's X9.62 signing API both return
            # ASN.1 DER signatures. PyCryptodome verifies that format directly.
            DSS.new(parsed["key"], "fips-186-3", encoding="der").verify(
                digest, signature
            )
        elif key_algorithm == "RS256":
            pkcs1_15.new(parsed["key"]).verify(digest, signature)
        else:
            raise ValueError("Unsupported stored key algorithm")
    except (ValueError, TypeError, IndexError):
        raise ApiProblem(
            "The installation signature is invalid.",
            401,
            "invalid_installation_signature",
        )


# Recognised key security levels, strongest first. Anything a client sends that
# is not in this list is stored verbatim but treated as unknown when comparing,
# so a novel platform cannot claim a strength the server does not understand.
KEY_SECURITY_RANK = {
    "strongbox": 3,
    "secure_enclave": 3,
    "tee": 2,
    "hardware": 2,
    "software": 1,
}


def _parse_key_security(body):
    """Read the optional key_security block a client may send at registration.

    Returns a dict whose three values are each either a parsed value or None.

    **None means "not reported", and must never be collapsed to False.** The
    Kotlin and .NET collectors do not send this block at all, and a server that
    read a missing hardware_backed as False would mark every Android
    installation software-backed on no evidence. This is the same defect class
    as an integrity bucket reporting compared_bytes: 0 and scoring as clean
    (DESIGN.md 28.8), and as the .NET session's wx_bytes finding, where an
    absent field read as a benign zero.

    Note what this value is and is not. It is a *client claim* about its own
    keystore, and a compromised client can lie about it, so it is a risk input
    and never proof. Its value is comparative: the key thumbprint is the
    authoritative identity, and a non-exportable hardware key cannot migrate
    into software, so the same thumbprint later claiming a weaker level is a
    contradiction the server can act on.
    """
    block = body.get("key_security")
    if block is None:
        return {"security_level": None, "hardware_backed": None, "provider": None}
    if not isinstance(block, dict):
        raise ApiProblem(
            "key_security must be an object when present.",
            400,
            "invalid_key_security",
        )

    level = block.get("security_level")
    if level is not None:
        if not isinstance(level, str) or not level.strip():
            raise ApiProblem(
                "key_security.security_level must be a non-empty string.",
                400,
                "invalid_key_security",
            )
        level = level.strip().lower()[:32]

    backed = block.get("hardware_backed")
    if backed is not None and not isinstance(backed, bool):
        raise ApiProblem(
            "key_security.hardware_backed must be a boolean.",
            400,
            "invalid_key_security",
        )

    provider = block.get("provider")
    if provider is not None:
        if not isinstance(provider, str):
            raise ApiProblem(
                "key_security.provider must be a string.",
                400,
                "invalid_key_security",
            )
        provider = provider.strip()[:64] or None

    return {
        "security_level": level,
        "hardware_backed": backed,
        "provider": provider,
    }


def _key_security_downgraded(stored_level, stored_backed, reported):
    """True when a known installation now claims weaker key protection.

    Only a genuine downgrade counts. Either side being None means the
    comparison was never possible, which is not evidence of anything.
    """
    if reported["hardware_backed"] is False and stored_backed is True:
        return True
    reported_rank = KEY_SECURITY_RANK.get(reported["security_level"] or "")
    stored_rank = KEY_SECURITY_RANK.get((stored_level or "").lower())
    if reported_rank is None or stored_rank is None:
        return False
    return reported_rank < stored_rank


def _reinstall_hint_hash(platform, hint):
    if hint is None:
        return None
    if not isinstance(hint, dict):
        raise ApiProblem(
            "reinstall_hint must be an object or null.",
            400,
            "invalid_reinstall_hint",
        )

    kind = hint.get("kind")
    value = hint.get("value")
    allowed = {"android": "android_id_sha256", "ios": "idfv_sha256"}
    if allowed.get(platform) != kind:
        raise ApiProblem(
            "The reinstall hint kind does not match the platform.",
            400,
            "invalid_reinstall_hint_kind",
        )
    if not isinstance(value, str):
        raise ApiProblem(
            "The reinstall hint value must be text.",
            400,
            "invalid_reinstall_hint",
        )
    value = value.strip().lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ApiProblem(
            "The reinstall hint must be a 64-character SHA-256 digest.",
            400,
            "invalid_reinstall_hint",
        )

    message = ("%s|%s|%s" % (platform, kind, value)).encode("utf-8")
    return hmac.new(_REINSTALL_PEPPER, message, hashlib.sha256).hexdigest()


def _normalize_handle(handle):
    if not isinstance(handle, str):
        raise ApiProblem("handle must be text.", 400, "invalid_handle")
    normalized = unicodedata.normalize("NFKC", handle).strip().casefold()
    if len(normalized) < 3 or len(normalized) > 80:
        raise ApiProblem(
            "The account handle must be between 3 and 80 characters.",
            400,
            "invalid_handle",
        )
    return normalized


def _handle_lookup(handle):
    normalized = _normalize_handle(handle)
    return hmac.new(
        _ACCOUNT_LOOKUP_PEPPER, normalized.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _password_bytes(password):
    if not isinstance(password, str):
        raise ApiProblem("password must be text.", 400, "invalid_password")
    raw = password.encode("utf-8")
    if len(raw) < 10 or len(raw) > 72:
        raise ApiProblem(
            "The password must be between 10 and 72 UTF-8 bytes.",
            400,
            "invalid_password",
        )
    return raw


def _bcrypt_hash_bytes(password_bytes):
    """Return a bcrypt hash as real Python bytes across bcrypt variants."""
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    if isinstance(hashed, bytes):
        return hashed
    if isinstance(hashed, str):
        # bcrypt hashes are ASCII ($2a$/$2b$/$2y$...).
        return hashed.encode("ascii")
    if isinstance(hashed, bytearray):
        return bytes(hashed)
    if isinstance(hashed, memoryview):
        return hashed.tobytes()

    raise RuntimeError(
        "Unsupported bcrypt.hashpw() return type: %s"
        % type(hashed).__name__
    )


def _bcrypt_db_bytes(value):
    """Normalize PostgreSQL BYTEA / legacy text values for bcrypt.checkpw()."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("ascii")

    raise RuntimeError(
        "Unsupported stored bcrypt hash type: %s" % type(value).__name__
    )


# ---------------------------------------------------------------------------
# Native integrity challenge, scoring, and freshness helpers
# ---------------------------------------------------------------------------


def _optional_measurements_requested():
    """The optional measurements the DBA currently requests (DESIGN.md 80)."""
    requested = _risk_setting_words("optional_measurements", "")
    return [name for name in _OPTIONAL_MEASUREMENTS if name in requested]


def _integrity_probe_plan(platform):
    if platform == "android":
        mandatory = [
            "app_identity",
            "debug_state",
            "root_files",
            "system_properties",
            "runtime_maps",
            "tracer",
            # Block-weight probes run on every scan. While they sat in the
            # random pool, a compromised client could simply rescan until the
            # probe that would catch it was not drawn; the challenge nonce
            # already prevents precomputed reports, so randomness buys nothing
            # here. Only low-weight telemetry stays optional.
            "root_shell",
            "selinux",
            "mounts",
            "frida_ports",
            # Structural hook detection. These do not depend on the injected
            # library's filename, unlike runtime_maps, so they survive the
            # rename-and-move-port evasion documented in DESIGN.md 27.11.
            "instrumentation_threads",
            "exec_mappings",
            "code_integrity",
            # Policy input since joint review R1: a deployment may make
            # developer options or ADB an eligibility rule (DESIGN.md 69), so
            # the setting is measured on every scan. With the default four
            # optional draws it was already requested every time.
            "developer_settings",
        ]
        optional = [
            "emulator",
        ]
    elif platform == "ios":
        mandatory = [
            "app_identity",
            "code_signing",
            "debugger",
            "jailbreak_files",
            "sandbox",
            "dyld_images",
        ]
        # Once its scoring is on, the app-bucket comparison must be requested
        # rather than volunteered: a client that simply omitted it would
        # otherwise never be scored on it (review F2). Report-only, it stays
        # out of the plan and the Swift collector keeps sending it unasked.
        if INTEGRITY_SCORE_IOS_CODE_INTEGRITY:
            mandatory.append("code_integrity")
        optional = ["environment", "simulator"]
    else:
        raise ApiProblem("Unsupported integrity platform.", 400, "unsupported_platform")

    pool = list(optional)
    chosen = []
    target = min(max(INTEGRITY_RANDOM_OPTIONAL_PROBES, 0), len(pool))
    while pool and len(chosen) < target:
        chosen.append(pool.pop(secrets.randbelow(len(pool))))
    return mandatory + chosen


def _integrity_reason(reasons, code, points, message, hard=False, report_only=False):
    """Record one scored reason.

    A report_only reason is visible in the stored report and in the API
    response but contributes nothing: its points are zero and it can never
    hard-block. The weight it *would* carry is preserved as proposed_points so
    that an operator can see what enabling it would cost before enabling it.

    The two extra keys appear only in the report-only case, so a rule that is
    actually scoring produces output byte-identical to every other rule.
    """
    entry = {
        "code": code,
        "points": 0 if report_only else int(points),
        "message": message,
        "hard": False if report_only else bool(hard),
    }
    if report_only:
        entry["report_only"] = True
        entry["proposed_points"] = int(points)
    reasons.append(entry)


def _probe(probes, name):
    value = probes.get(name)
    return value if isinstance(value, dict) else {}


def _as_bool(value):
    return value is True


def _as_text(value):
    return value.strip() if isinstance(value, str) else ""


def _as_list(value):
    return value if isinstance(value, list) else []


def _as_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


# The measurements each probe must carry when it answers status "ok"
# (DESIGN.md 63). The scorers read an absent field as its clean value -- an
# empty list, False, 0 -- so an "ok" probe without its fields used to score as a
# pristine device: fifteen bare {"status": "ok"} probes came out trusted
# (review F2). Such a probe delivered no evidence, and is now scored exactly
# like one that failed to run. A field present with the wrong JSON type makes
# the report malformed: 400, never a 500 and never a silent zero.
#
# Checked against every report the Kotlin, Swift and .NET collectors and the
# conformance suite sent in September 2026: none lacks one of these fields.
_PROBE_REQUIRED_FIELDS = {
    "android": {
        "app_identity": {"package_name": str, "apk_sha256": str, "cert_sha256": list,
                         "debuggable": bool, "allow_backup": bool},
        "debug_state": {"debugger_connected": bool, "waiting_for_debugger": bool},
        "tracer": {"tracer_pid": int},
        "root_files": {"found_paths": list, "test_keys": bool},
        "root_shell": {"su_found": bool},
        "system_properties": {"properties": dict},
        "selinux": {"mode": str, "getenforce": str, "enforce_value": str},
        "mounts": {"protected_rw_mounts": list},
        "runtime_maps": {"suspicious_tokens": list},
        "frida_ports": {"open_ports": list},
        "instrumentation_threads": {"frida_threads": list, "token_threads": list,
                                    "glib_threads": list},
        "exec_mappings": {"wx_mappings": int, "deleted_exec_mappings": int},
        "code_integrity": {"checked": bool, "diff_bytes": int, "core_compared_bytes": int,
                           "ext_diff_bytes": int, "ext_compared_bytes": int,
                           "app_diff_bytes": int, "app_compared_bytes": int},
        "emulator": {"suspected": bool},
        "developer_settings": {"developer_options_enabled": bool, "adb_enabled": bool},
    },
    "ios": {
        "app_identity": {"bundle_id": str, "executable_sha256": str},
        "code_signing": {"signing_identifier": str, "team_identifier": str,
                         "get_task_allow": bool},
        "debugger": {"traced": bool},
        "jailbreak_files": {"found_paths": list},
        "sandbox": {"write_outside_sandbox_succeeded": bool},
        "dyld_images": {"suspicious_tokens": list},
        "environment": {"dyld_insert_libraries": str},
        "simulator": {"is_simulator": bool},
        "code_integrity": {"checked": bool, "app_diff_bytes": int, "app_compared_bytes": int},
    },
}
class _Number(object):
    """A probe field that is a finite JSON number within bounds -- never a bool
    (DESIGN.md 82: coordinates are the first fields that may be negative)."""

    def __init__(self, name, low, high):
        self.__name__ = name
        self.low = low
        self.high = high


_LATITUDE = _Number("latitude", -90.0, 90.0)
_LONGITUDE = _Number("longitude", -180.0, 180.0)
_METRES = _Number("distance in metres", 0.0, 1.0e7)
# Fields a scorer reads when present but that not every collector sends; only
# their type is checked.
_PROBE_OPTIONAL_FIELDS = {
    "android": {
        # Volunteered on every scan by collectors from version 4, never in the
        # plan, so older clients lose nothing (DESIGN.md 80).
        "device": {"release": str, "sdk_int": int, "security_patch": str, "manufacturer": str,
                   "brand": str, "model": str, "device": str, "build_id": str,
                   "fingerprint": str},
        "network": {"vpn_active": bool, "http_proxy_configured": bool, "transports": list,
                    "interfaces": list},
        # Only where the DBA requests it and the app's developers enabled it.
        "local_addresses": {"addresses": list},
        # The same two keys (DESIGN.md 82). The apps in each list are judged
        # by _app_source, which reads only well-formed entries.
        "accessibility": {"services": list, "keyboard": dict, "settings_only": list},
        "notification_access": {"listeners": list},
        "other_access": {"device_admins": list, "remote_access_apps": list},
        "screen_capture": {"recording": bool, "external_displays": int},
        "location": {"permission": str, "latitude": _LATITUDE, "longitude": _LONGITUDE,
                     "accuracy_m": _METRES, "age_seconds": int, "provider": str},
        "mock_location": {"permission": str, "mock": bool, "age_seconds": int},
        "exec_mappings": {"wx_bytes": int, "wx_size_classes": str,
                          "wx_smallest_bytes": int, "wx_largest_bytes": int,
                          "deleted_exec_own_code": int, "deleted_exec_jit": int,
                          "anon_exec_labeled": int, "anon_exec_unlabeled": int,
                          "maps_lines": int, "samples": list},
        "runtime_maps": {"maps_lines": int, "suspicious_line_count": int},
        "instrumentation_threads": {"thread_count": int},
        # Coverage, reported by the native scanner since DESIGN.md 63.
        "code_integrity": dict(
            [("%s_%s" % (bucket, field), int)
             for bucket in ("core", "ext", "app")
             for field in ("expected_bytes", "skipped_bytes", "unreadable_bytes")]
            + [("%s_complete" % bucket, bool) for bucket in ("core", "ext", "app")]
            + [("protect_restore_failures", int), ("xom_regions_unlocked", int),
               ("xom_regions_unreadable", int), ("elapsed_ms", int)]
        ),
    },
    "ios": {
        "device": {"os_version": str, "os_build": str, "model_identifier": str},
        "network": {"vpn_active": bool, "http_proxy_configured": bool,
                    "scoped_interfaces": list},
        "local_addresses": {"addresses": list},
        "screen_capture": {"recording": bool, "external_displays": int},
        "location": {"permission": str, "latitude": _LATITUDE, "longitude": _LONGITUDE,
                     "accuracy_m": _METRES, "age_seconds": int},
        "mock_location": {"permission": str, "mock": bool, "accessory": bool,
                          "age_seconds": int},
    },
}
_CODE_BUCKETS = ("core", "ext", "app")
# Buckets a working scanner always measures something in (DESIGN.md 66.2,
# joint review R3). Android: libc/libart, the extended system libraries and the
# app's own native code are mapped in every app process. iOS: only the app's
# own images -- its system libraries live in the shared cache and are never
# readable, so a zero there is the platform, not a failure.
_MUST_MEASURE_BUCKETS = {"android": ("core", "ext", "app"), "ios": ("app",)}


def _code_coverage_consistent(code):
    """Whether reported code-integrity coverage adds up (DESIGN.md 63).

    expected = compared + skipped + unreadable in every bucket that reports
    coverage, and complete is true exactly when all expected bytes were
    compared. A collector that does not report coverage is not judged here.
    """
    for bucket in _CODE_BUCKETS:
        expected = code.get("%s_expected_bytes" % bucket)
        if expected is None:
            continue
        parts = [code.get("%s_%s" % (bucket, f)) for f in
                 ("compared_bytes", "skipped_bytes", "unreadable_bytes")]
        if any(not isinstance(v, int) or isinstance(v, bool) for v in parts):
            return False
        if sum(parts) != expected:
            return False
        complete = code.get("%s_complete" % bucket)
        if complete is not None and complete != (expected > 0 and parts[0] == expected):
            return False
    return True
_MAX_PROBE_INT = 1 << 53


def _probe_field_ok(value, kind):
    if isinstance(kind, _Number):
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(value) and kind.low <= value <= kind.high)
    if kind is int:
        return (isinstance(value, int) and not isinstance(value, bool)
                and 0 <= value <= _MAX_PROBE_INT)
    if kind is bool:
        return isinstance(value, bool)
    return isinstance(value, kind)


def _check_probe_evidence(platform, probes, required_probes):
    """Reject wrongly typed fields; return the required probes lacking evidence.

    Returns [(probe, [missing field, ...])] for every server-requested probe
    that answered "ok" without its measurements. A code_integrity probe
    reporting checked=false measured nothing and is listed too, whatever else
    it carries -- "the native component did not run" is not a clean result --
    and so is one reporting checked=true that compared zero bytes in a bucket
    that always holds code on its platform.
    """
    required_fields = _PROBE_REQUIRED_FIELDS.get(platform, {})
    optional_fields = _PROBE_OPTIONAL_FIELDS.get(platform, {})
    for name, value in probes.items():
        if not isinstance(value, dict):
            continue
        for fields in (required_fields.get(name, {}), optional_fields.get(name, {})):
            for field, kind in fields.items():
                present = value.get(field)
                if present is not None and not _probe_field_ok(present, kind):
                    raise ApiProblem(
                        "Integrity probe field %s.%s is not a valid %s."
                        % (name, field, kind.__name__),
                        400,
                        "invalid_integrity_probe",
                        details={"probe": name, "field": field},
                    )
    incomplete = []
    for name in required_probes:
        value = probes.get(name)
        if not isinstance(value, dict) or value.get("status") != "ok":
            continue  # scored as integrity_probe_failed
        missing = [f for f in required_fields.get(name, {}) if value.get(f) is None]
        if name == "code_integrity" and value.get("checked") is False and not missing:
            missing = ["checked=false"]
        # checked=true only says the scanner ran. A bucket that must contain
        # code but compared zero bytes measured nothing, and "no differences in
        # nothing" used to score as a clean scan (joint review R3).
        if name == "code_integrity" and value.get("checked") is True and not missing:
            missing = [
                "%s_compared_bytes above 0" % bucket
                for bucket in _MUST_MEASURE_BUCKETS.get(platform, ())
                if value.get("%s_compared_bytes" % bucket) == 0
            ]
        if missing:
            incomplete.append((name, missing))
    return incomplete


# The evidence contract each platform's current collector meets (DESIGN.md 76,
# review R4). A report from an older collector is scored as before but
# labelled legacy, never complete; a report at or above the contract must
# carry these fields wherever the probe answered ok.
_EVIDENCE_CONTRACT_VERSION = {"android": 3, "ios": 2}
_CONTRACT_FIELDS = {
    "android": {
        "runtime_maps": ("maps_lines",),
        "exec_mappings": ("maps_lines", "deleted_exec_own_code"),
        "instrumentation_threads": ("thread_count",),
    },
}


def _check_probe_consistency(platform, probes, required_probes, collector_version):
    """Find evidence that cannot be true, and measurements that were not made.

    Returns (invalid, incomplete): [(probe, detail)] and [(probe, [missing])].
    Run before scoring, because the scorers take fast paths on zeros -- zero
    writable-executable mappings returned clean before the sizes listed for
    them were ever read (review R4). Unknown or unreadable data must stay
    distinguishable from a measured negative: a collector that could not read
    the process map, or enumerated no thread of a running process, measured
    nothing, whatever "ok" it reported.
    """
    invalid, incomplete = [], []
    current = collector_version >= _EVIDENCE_CONTRACT_VERSION.get(platform, 0)
    contract = _CONTRACT_FIELDS.get(platform, {}) if current else {}
    for name in required_probes:
        value = probes.get(name)
        if not isinstance(value, dict) or value.get("status") != "ok":
            continue
        missing = [f for f in contract.get(name, ()) if value.get(f) is None]
        if (name == "code_integrity" and platform == "android" and current
                and value.get("checked") is True):
            missing += ["%s_expected_bytes" % bucket for bucket in _CODE_BUCKETS
                        if value.get("%s_expected_bytes" % bucket) is None]
        if name in ("runtime_maps", "exec_mappings") and value.get("maps_lines") == 0:
            missing.append("a readable process map (maps_lines 0)")
        if name == "instrumentation_threads" and value.get("thread_count") == 0:
            missing.append("an enumerated thread (thread_count 0)")
        if missing:
            incomplete.append((name, missing))
        if name == "exec_mappings":
            listed = _wx_size_classes(value)
            extremes = _as_int(value.get("wx_smallest_bytes")) or _as_int(value.get("wx_largest_bytes"))
            if (_as_int(value.get("wx_mappings")) == 0 and not _as_int(value.get("wx_bytes"))
                    and (listed or extremes)):
                invalid.append((name, "zero writable-executable mappings, but their sizes listed"))
        if (name == "code_integrity" and platform == "android"
                and not _code_coverage_consistent(value)):
            invalid.append((name, "coverage figures that do not add up"))
    return invalid, incomplete


def _integrity_verdict(score, hard_block=False):
    if hard_block or score >= 90:
        return "block"
    if score >= 60:
        return "review"
    if score >= 30:
        return "elevated"
    return "trusted"


# Collection quality, kept apart from findings (review R3, DESIGN.md 76).
_QUALITY_REASON_PREFIXES = (
    "integrity_probe_failed:",
    "integrity_probe_incomplete:",
    "integrity_evidence_",
)
# Coverage reasons that mark a scan as measuring only part of its targets.
_PARTIAL_EVIDENCE_REASONS = (
    "android_code_integrity_partial",
    "android_code_integrity_restore_failed",
)
EVIDENCE_QUALITIES = ("complete", "partial", "incomplete", "invalid", "legacy")


def _is_quality_reason(reason):
    return str(reason.get("code", "")).startswith(_QUALITY_REASON_PREFIXES)


# Conditions: what the phone allows or is doing -- apps that can read the
# screen, the keyboard or notifications, device administrators, remote-control
# apps, a recorded or extra screen, a fake location, an old security patch, a
# VPN or proxy, developer options, ADB (DESIGN.md 82, 83). Legitimate use holds
# every one of them, alone or together: a remote-support session is a support
# app with Accessibility, a remote-control app and a recorded screen. So,
# unlike a phone integrity finding (root, hooks, tampering), they add at most
# conditions_points_cap together, and they never enter the device memory: a
# clean rescan clears them (review F2, 2026-10-16).
_CONDITION_CODES = frozenset((
    "android_accessibility_sideloaded", "android_accessibility_non_system",
    "android_accessibility_hidden",
    "android_keyboard_sideloaded", "android_keyboard_non_system",
    "android_notification_access_sideloaded", "android_notification_access_non_system",
    "android_device_admin_sideloaded", "android_device_admin_non_system",
    "android_remote_access_app",
    "android_screen_captured", "ios_screen_captured",
    "android_external_display", "ios_external_display",
    "android_mock_location", "ios_mock_location",
    "android_security_patch_outdated",
    "android_vpn_active", "ios_vpn_active", "android_http_proxy", "ios_http_proxy",
    "android_developer_options", "android_adb_enabled",
))


def _is_condition_reason(reason):
    return reason.get("code") in _CONDITION_CODES


def _cap_conditions(reasons):
    """Conditions together add at most the DBA's conditions_points_cap (owner
    default 60: review, never a block on their own). The later ones give way;
    each reduced reason keeps what it would have scored in points_before_cap,
    so an approver, and an approval's reason-level coverage, see the cap."""
    room = _risk_setting_int("conditions_points_cap", 60)
    for reason in reasons:
        if not _is_condition_reason(reason):
            continue
        points = max(0, int(reason.get("points", 0)))
        if points > room:
            reason["points_before_cap"] = points
            reason["points"] = max(0, room)
        room -= min(points, max(0, room))


def _categorize(reasons):
    """Each integrity reason says what kind of evidence it is: integrity (the
    phone or the app compromised or not genuine), condition (what the phone
    allows or is doing) or collection (a check that measured nothing usable)."""
    for reason in reasons:
        reason["category"] = ("collection" if _is_quality_reason(reason) else
                              "condition" if _is_condition_reason(reason) else "integrity")


def _incomplete_streak(cursor, installation_id):
    """How many of this installation's latest reports, newest first, were
    incomplete or invalid with no complete one between them. Legacy reports
    and reports from before migration 015 end the streak: an old collector is
    not a collection problem."""
    limit = max(0, _risk_setting_int("incomplete_evidence_review_after", 3))
    if limit <= 0:
        return 0
    cursor.execute(
        """
        SELECT evidence_quality FROM integrity_reports
        WHERE installation_id = %s
        ORDER BY created_at DESC
        LIMIT """ + str(limit),
        (installation_id,),
    )
    streak = 0
    for (quality,) in cursor.fetchall() or []:
        if quality not in ("incomplete", "invalid"):
            break
        streak += 1
    return streak


def _apply_collection_problems(scored, failed_required, incomplete, invalid=(), legacy=False,
                               streak=None):
    """Score what the scan could not measure apart from what it found.

    A probe that failed, answered "ok" without its measurements, or reported
    figures that contradict each other measured nothing usable; it must never
    read as clean. Each is listed (0 points, for investigation), and together
    they add +30 once, as integrity_evidence_incomplete: one collection problem
    -- an unreadable process map, say -- can break three probes at once, which
    used to add +90, a block, remembered for every account on the phone for a
    day. finding_score is the score of the positive findings alone, which is
    what the device memory remembers; a complete scan clears the rest. Owner
    decision of 2026-10-13. collection_problems_block = 1 restores the earlier
    rule in one place: each problem +30, counted as a finding.

    evidence_quality, worst first: invalid (figures that contradict each
    other), incomplete (failed or unmeasured), legacy (a collector below its
    platform's evidence contract), partial (code compared only in part, an
    advisory the owner kept), complete.

    Sets score, verdict, evidence_quality and finding_score on scored.
    """
    per_probe = _risk_setting_bool("collection_problems_block", False)
    problems = [
        ("integrity_probe_failed:%s" % name,
         "A server-requested native integrity probe did not complete successfully.")
        for name in failed_required
    ] + [
        ("integrity_probe_incomplete:%s" % name,
         "A server-requested probe answered ok without the measurements it must "
         "carry (%s)." % ", ".join(missing[:6]))
        for name, missing in incomplete
    ] + [
        ("integrity_evidence_invalid:%s" % name,
         "A probe reported measurements that contradict each other (%s)." % detail)
        for name, detail in invalid
    ]
    for code, message in problems:
        _integrity_reason(scored["reasons"], code, 30 if per_probe else 0, message)
    if problems and not per_probe:
        _integrity_reason(
            scored["reasons"],
            "integrity_evidence_incomplete",
            30,
            "%d requested probe(s) measured nothing usable; a complete scan clears this."
            % len(problems),
        )
    # Evidence that stays incomplete scan after scan is deliberate blinding
    # far more often than a passing glitch, which the next scan clears
    # (owner decision of 2026-10-13): incomplete_evidence_review_after such
    # scans in a row add +30 more -- review with nothing else found. It is a
    # collection reason, so it never enters the device memory, and one
    # complete scan resets the count. 0 turns it off.
    after = _risk_setting_int("incomplete_evidence_review_after", 3)
    if problems and after > 0 and streak is not None and streak() + 1 >= after:
        _integrity_reason(
            scored["reasons"],
            "integrity_evidence_persistently_incomplete",
            30,
            "%d integrity scans in a row could not be completed; send a complete scan."
            % after,
        )
    points = lambda reasons: min(100, sum(max(0, int(r.get("points", 0))) for r in reasons))
    scored["score"] = points(scored["reasons"])
    # The device memory remembers phone integrity findings only: never a
    # condition (review F2), nor, unless the DBA says so, a collection problem.
    scored["finding_score"] = points(
        [r for r in scored["reasons"]
         if not _is_condition_reason(r) and (per_probe or not _is_quality_reason(r))]
    )
    _categorize(scored["reasons"])
    scored["verdict"] = _integrity_verdict(scored["score"], hard_block=scored["hard_block"])
    codes = {r.get("code") for r in scored["reasons"]}
    if invalid:
        quality = "invalid"
    elif problems:
        quality = "incomplete"
    elif legacy:
        quality = "legacy"
    elif codes & set(_PARTIAL_EVIDENCE_REASONS):
        quality = "partial"
    else:
        quality = "complete"
    scored["evidence_quality"] = quality


def _apply_hardware_backing_policy(cursor, installation_id, scored):
    """Fold the per-deployment hardware-backing policy into an integrity result.

    A software-backed installation key is only ever a client claim, never proof,
    so it is applied per the DBA's hardware_backing_policy (DESIGN.md 79;
    INTEGRITY_HARDWARE_BACKING_POLICY only for a missing row). key_hardware_backed is
    NULL when the client did not report it (old clients, the Kotlin and .NET
    collectors); an absent measurement must never be read as software, so
    "advisory" acts only on an explicit False. "required" demands a claim, and no
    claim cannot satisfy it (review F2): NULL blocks there under its own reason.
    Even then it is only a claim -- "required" means "claimed at enrolment", never
    "proven". The score is re-derived from the reasons so it stays the sum of
    advertised points, as _score_integrity does.
    """
    policy = _hardware_backing_policy()
    if policy == "off":
        return
    cursor.execute(
        "SELECT key_hardware_backed FROM app_installations WHERE installation_id = %s",
        (installation_id,),
    )
    row = cursor.fetchone()
    stored = row[0] if row else None
    if stored is not None and bool(stored):
        return
    if stored is None and policy != "required":
        return
    if stored is None:
        _integrity_reason(
            scored["reasons"],
            "key_hardware_backing_unreported",
            100,
            "This deployment requires a hardware-backed installation key, and this "
            "installation never reported how its key is stored.",
            hard=True,
        )
        scored["hard_block"] = True
    elif policy == "required":
        _integrity_reason(
            scored["reasons"],
            "key_software_backed",
            100,
            "The installation key is software-backed; this deployment requires a "
            "hardware-backed key.",
            hard=True,
        )
        scored["hard_block"] = True
    else:
        _integrity_reason(
            scored["reasons"],
            "key_software_backed",
            30,
            "The installation key is software-backed rather than hardware-backed.",
        )
    scored["score"] = min(
        100, sum(max(0, int(r.get("points", 0))) for r in scored["reasons"])
    )
    scored["verdict"] = _integrity_verdict(
        scored["score"], hard_block=scored["hard_block"]
    )


def _wx_size_classes(exec_maps):
    """[(size, count), ...] from wx_size_classes, or None if absent or malformed.

    The collector lists "<bytes>:<count>" pairs, largest first, for the
    writable-executable mappings; wx_smallest_bytes and wx_largest_bytes name
    the extremes.
    """
    raw = exec_maps.get("wx_size_classes")
    if not isinstance(raw, str):
        return None
    classes = []
    for part in raw.split(","):
        if not part.strip():
            continue
        size, _, count = (piece.strip() for piece in part.partition(":"))
        if not size.isdigit() or not count.isdigit():
            return None
        classes.append((int(size), int(count)))
    return classes or None


def _wx_shape_consistent(exec_maps, wx_count, wx_bytes, classes):
    """Whether the reported W^X figures agree with each other (DESIGN.md 63).

    The baseline allowance trusts sizes the client reports, so figures that
    contradict one another are not a measurement and earn no allowance (review
    F2). The class list must account for every mapping and every byte: a list
    cut short (the .NET collector sends at most twelve classes) leaves sizes
    unexamined, and a size the runtime never allocates can hide among the
    omitted ones (joint review R8, DESIGN.md 66.2). A truncated list therefore
    earns no allowance either.
    """
    if wx_count <= 0 or wx_bytes <= 0:
        return False
    if any(size <= 0 or count <= 0 for size, count in classes):
        return False
    listed = sum(count for _, count in classes)
    listed_bytes = sum(size * count for size, count in classes)
    if listed != wx_count or listed_bytes != wx_bytes:
        return False
    sizes = [size for size, _ in classes]
    smallest = _as_int(exec_maps.get("wx_smallest_bytes"))
    largest = _as_int(exec_maps.get("wx_largest_bytes"))
    if largest and (largest < max(sizes) or largest > wx_bytes):
        return False
    if smallest and (smallest > min(sizes) or smallest * wx_count > wx_bytes):
        return False
    return True


def _score_wx_memory(reasons, exec_maps, apk_hash):
    """Writable-and-executable memory, scored against the build's baseline.

    Today's rule -- +60 whenever such memory is mapped -- stays for every build
    without a pinned baseline and for every report that does not carry
    wx_bytes and its size classes (DESIGN.md 62). An absent measurement is
    never read as zero: the Flutter/Kotlin collector does not send wx_bytes,
    and treating that as "0 bytes over baseline" would switch W^X scoring off
    for a device with a live injected gadget (DESIGN_UPDATE_FROM_DOTNET.md).
    Figures that contradict one another fall back to the same +60 (63).
    """
    wx_count = _as_int(exec_maps.get("wx_mappings"))
    wx_bytes = exec_maps.get("wx_bytes")
    if isinstance(wx_bytes, bool) or not isinstance(wx_bytes, int) or wx_bytes < 0:
        wx_bytes = None
    if wx_count <= 0 and not wx_bytes:
        return 0
    baseline = ANDROID_WX_BASELINES.get(apk_hash)
    classes = _wx_size_classes(exec_maps)
    if (
        baseline is None
        or baseline[0] <= 0
        or wx_bytes is None
        or classes is None
        or not _wx_shape_consistent(exec_maps, wx_count, wx_bytes, classes)
    ):
        _integrity_reason(reasons, "android_wx_memory", 60,
                          "Writable-and-executable memory is mapped into the process.")
        return 60
    sizes = {size for size, _ in classes}
    for key in ("wx_smallest_bytes", "wx_largest_bytes"):
        if _as_int(exec_maps.get(key)) > 0:
            sizes.add(_as_int(exec_maps.get(key)))
    baseline_bytes, granularity = baseline
    points = 0
    if any(size % granularity for size in sizes):
        _integrity_reason(reasons, "android_wx_foreign_allocator", 45,
                          "Writable-executable memory of a size this build's runtime "
                          "never allocates is mapped into the process.")
        points += 45
    # Growth beyond the pinned envelope (joint review R1, DESIGN.md 69). The pin
    # is the build's measured full-session maximum; a runtime that keeps
    # generating code as a session warms can exceed it legitimately, so growth
    # up to the DBA's wx_far_above_baseline_percent (owner default 200: twice
    # the envelope) is advisory and scores nothing. Beyond that it scores +40
    # on its own, without waiting for a second signal: an injector that copies
    # the runtime's allocation sizes produces no other signal, and would
    # otherwise get unlimited room for its code.
    if wx_bytes > baseline_bytes:
        percent = _risk_setting_int("wx_far_above_baseline_percent", 200)
        if wx_bytes * 100 > baseline_bytes * percent:
            _integrity_reason(reasons, "android_wx_far_above_baseline", 40,
                              "Writable-executable memory (%d bytes) is more than %d%% of "
                              "this build's baseline (%d bytes)."
                              % (wx_bytes, percent, baseline_bytes))
            points += 40
        else:
            _integrity_reason(reasons, "android_wx_above_baseline", 0,
                              "Writable-executable memory (%d bytes) exceeds this build's "
                              "baseline (%d bytes) within the expected growth of up to %d%%; "
                              "advisory." % (wx_bytes, baseline_bytes, percent))
    return points


# What can read or drive the phone (DESIGN.md 82). Banking trojans capture what
# is typed through Accessibility, a replacement keyboard, notification access or
# screen capture: Chameleon, Vultur and RemControl all work through
# Accessibility. The phone reports which apps hold each of these and who
# installed them; the server judges the source, so the DBA's app_store_installers
# decides what a store is. Each finding scores the DBA's *_points, seeded with
# the owner's defaults: the sideloaded holders score, while what screen readers,
# password managers, store keyboards, smartwatch apps and company phone
# management also hold stays at 0. A deployment that wants one refused sets its
# eligibility rule.
_ACCESS_HOLDERS = (
    # (probe, field, code when sideloaded, code when not the system's, what holds
    # it -- "%s" is "no app store installed" or "that is not part of the system")
    ("accessibility", "services", "android_accessibility_sideloaded",
     "android_accessibility_non_system", "An Accessibility service is on in an app %s"),
    ("accessibility", "keyboard", "android_keyboard_sideloaded",
     "android_keyboard_non_system", "The keyboard in use is an app %s"),
    ("notification_access", "listeners", "android_notification_access_sideloaded",
     "android_notification_access_non_system", "An app %s can read notifications"),
    ("other_access", "device_admins", "android_device_admin_sideloaded",
     "android_device_admin_non_system", "A device-administrator app %s is active"),
)
_MAX_LISTED_APPS = 64


def _app_source(entry, stores):
    """system, store, sideloaded or unknown for one app the phone listed.

    system: the phone's own (FLAG_SYSTEM, updates included). store: installed by
    one of the stores. sideloaded: installed by anything else -- a browser, a
    file manager, adb, another app's installer, as droppers do -- or by nothing.
    unknown: the phone could not see the app's details; unknown is never
    evidence, as with SELinux.
    """
    if not isinstance(entry, dict):
        return "unknown"
    system = entry.get("system")
    if system is True:
        return "system"
    installer = entry.get("installer")
    if system is False and isinstance(installer, str):
        return "store" if installer in stores else "sideloaded"
    return "unknown"


def _listed_apps(entries):
    """The well-formed app entries of a list, at most _MAX_LISTED_APPS."""
    return [entry for entry in _as_list(entries)[:_MAX_LISTED_APPS]
            if isinstance(entry, dict) and isinstance(entry.get("package"), str)]


def _package_names(entries):
    """Package names for a reason's message: plain characters only, five at most."""
    names = sorted({re.sub(r"[^A-Za-z0-9._]", "", entry["package"])[:100] for entry in entries})
    names = [name for name in names if name]
    shown = ", ".join(names[:5])
    return shown + (" and %d more" % (len(names) - 5) if len(names) > 5 else "")


def _access_points():
    """Each finding's points: the DBA's settings, the owner's defaults (migration
    024, DESIGN.md 82)."""
    return {
        "android_accessibility_sideloaded": _risk_setting_int("accessibility_sideloaded_points", 45),
        "android_accessibility_non_system": _risk_setting_int("accessibility_non_system_points", 0),
        "android_keyboard_sideloaded": _risk_setting_int("keyboard_sideloaded_points", 30),
        "android_keyboard_non_system": _risk_setting_int("keyboard_non_system_points", 0),
        "android_notification_access_sideloaded":
            _risk_setting_int("notification_access_sideloaded_points", 30),
        "android_notification_access_non_system":
            _risk_setting_int("notification_access_non_system_points", 0),
        "android_device_admin_sideloaded": _risk_setting_int("device_admin_sideloaded_points", 30),
        "android_device_admin_non_system": _risk_setting_int("device_admin_non_system_points", 0),
        "android_remote_access_app": _risk_setting_int("remote_access_app_points", 20),
    }


def _score_access_holders(reasons, probes):
    """Reasons for the apps that hold Accessibility, the keyboard, notification
    access or device administration, and for remote-control apps; returns
    their points."""
    stores = _risk_setting_words("app_store_installers", APP_STORE_INSTALLERS_DEFAULT)
    points = _access_points()
    total = 0
    for probe, field, sideloaded_code, non_system_code, what in _ACCESS_HOLDERS:
        value = _probe(probes, probe).get(field)
        entries = _listed_apps([value] if isinstance(value, dict) else value)
        sideloaded = [e for e in entries if _app_source(e, stores) == "sideloaded"]
        not_system = [e for e in entries if e.get("system") is False]
        if sideloaded:
            _integrity_reason(reasons, sideloaded_code, points[sideloaded_code],
                              "%s: %s." % (what % "no app store installed",
                                           _package_names(sideloaded)))
            total += points[sideloaded_code]
        if not_system:
            _integrity_reason(reasons, non_system_code, points[non_system_code],
                              "%s: %s." % (what % "that is not part of the system",
                                           _package_names(not_system)))
            total += points[non_system_code]
    remote = _listed_apps(_probe(probes, "other_access").get("remote_access_apps"))
    if remote:
        _integrity_reason(reasons, "android_remote_access_app", points["android_remote_access_app"],
                          "A remote-control app is installed: %s." % _package_names(remote))
        total += points["android_remote_access_app"]
    return total


def _score_capture_and_location(reasons, probes, platform):
    """Reasons for a screen recorded or mirrored during the scan, and for a
    location simulated by an app (DESIGN.md 82); returns their points."""
    total = 0
    screen = _probe(probes, "screen_capture")
    displays = _as_int(screen.get("external_displays"))
    if _as_bool(screen.get("recording")) or displays > 0:
        points = _risk_setting_int("screen_capture_points", 30)
        _integrity_reason(reasons,
                          "android_screen_captured" if platform == "android" else "ios_screen_captured",
                          points,
                          ("The app's screen was being recorded or mirrored during the scan."
                           if _as_bool(screen.get("recording")) else
                           "%d display(s) besides the phone's own were on during the scan: "
                           "casting, mirroring or an external screen." % displays))
        total += points
    if _as_bool(_probe(probes, "mock_location").get("mock")):
        points = _risk_setting_int("mock_location_points", 40)
        _integrity_reason(reasons,
                          "android_mock_location" if platform == "android" else "ios_mock_location",
                          points,
                          "The phone's last location was simulated by an app.")
        total += points
    return total


def _security_patch_age_days(device):
    """Days since the Android security patch level the phone reports, or None
    where it reports none or nothing readable (collectors before 4, Android 5)."""
    text = _as_text(device.get("security_patch"))
    try:
        patched = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max(0, (_utc_now() - patched).days)


def _score_security_patch(reasons, probes):
    """The security patch level, sent by every collector from Android 4, against
    the DBA's security_patch_max_age_days (owner default 365; 0 = never);
    returns its points."""
    limit = _risk_setting_int("security_patch_max_age_days", 365)
    age = _security_patch_age_days(_probe(probes, "device"))
    if limit > 0 and age is not None and age > limit:
        points = _risk_setting_int("security_patch_outdated_points", 10)
        _integrity_reason(reasons, "android_security_patch_outdated", points,
                          "The security patch level is %d days old, more than the %d allowed."
                          % (age, limit))
        return points
    return 0


def _score_android_integrity(probes):
    reasons = []
    score = 0
    hard_block = False

    app_identity = _probe(probes, "app_identity")
    package_name = _as_text(app_identity.get("package_name"))
    certs = {str(x).strip().lower() for x in _as_list(app_identity.get("cert_sha256"))}
    apk_hash = _as_text(app_identity.get("apk_sha256")).lower()

    if EXPECTED_ANDROID_PACKAGE and package_name != EXPECTED_ANDROID_PACKAGE:
        _integrity_reason(reasons, "android_package_mismatch", 100, "Installed package name does not match the server baseline.", True)
        hard_block = True
    if EXPECTED_ANDROID_CERT_SHA256 and not (certs & EXPECTED_ANDROID_CERT_SHA256):
        _integrity_reason(reasons, "android_signing_certificate_mismatch", 100, "APK signing certificate is not in the server allow-list.", True)
        hard_block = True
    if EXPECTED_ANDROID_APK_SHA256 and apk_hash not in EXPECTED_ANDROID_APK_SHA256:
        _integrity_reason(reasons, "android_apk_hash_mismatch", 100, "Installed base APK hash does not match the configured build baseline.", True)
        hard_block = True
    if _as_bool(app_identity.get("debuggable")) and not INTEGRITY_ALLOW_DEBUG:
        _integrity_reason(reasons, "android_app_debuggable", 35, "The installed application is debuggable.")
        score += 35
    if _as_bool(app_identity.get("allow_backup")):
        _integrity_reason(reasons, "android_backup_enabled", 5, "The application permits OS backup/transfer.")
        score += 5

    debug_state = _probe(probes, "debug_state")
    if (_as_bool(debug_state.get("debugger_connected")) or _as_bool(debug_state.get("waiting_for_debugger"))) and not INTEGRITY_ALLOW_DEBUG:
        _integrity_reason(reasons, "android_debugger_attached", 50, "A debugger is attached to the application process.")
        score += 50

    tracer = _probe(probes, "tracer")
    tracer_pid = tracer.get("tracer_pid")
    if isinstance(tracer_pid, int) and tracer_pid > 0 and not INTEGRITY_ALLOW_DEBUG:
        _integrity_reason(reasons, "android_process_traced", 55, "TracerPid indicates that another process is tracing the app.")
        score += 55

    root_files = _probe(probes, "root_files")
    found_paths = [str(x).lower() for x in _as_list(root_files.get("found_paths"))]
    if any("magisk" in x or "kernelsu" in x or "/data/adb/ksu" in x or "/data/adb/ap" in x for x in found_paths):
        _integrity_reason(reasons, "android_root_framework_artifact", 75, "Root-management framework artifacts were visible.")
        score += 75
    elif found_paths:
        _integrity_reason(reasons, "android_root_artifact", 50, "Root/su artifacts were visible.")
        score += 50
    if _as_bool(root_files.get("test_keys")) and not INTEGRITY_ALLOW_USERDEBUG:
        _integrity_reason(reasons, "android_test_keys", 25, "Build tags contain test-keys.")
        score += 25

    root_shell = _probe(probes, "root_shell")
    if _as_bool(root_shell.get("su_found")):
        _integrity_reason(reasons, "android_su_on_path", 50, "The su command is discoverable from the application process.")
        score += 50

    props = _probe(probes, "system_properties").get("properties")
    props = props if isinstance(props, dict) else {}
    verified = _as_text(props.get("ro.boot.verifiedbootstate")).lower()
    flash_locked = _as_text(props.get("ro.boot.flash.locked")).lower()
    vbmeta_state = _as_text(props.get("ro.boot.vbmeta.device_state")).lower()
    ro_secure = _as_text(props.get("ro.secure")).lower()
    ro_debuggable = _as_text(props.get("ro.debuggable")).lower()
    build_type = _as_text(props.get("ro.build.type")).lower()
    # A userdebug/eng image is root-capable by construction: adb root succeeds
    # and the image ships su. This signal survives the app sandbox because it is
    # a property read, not a file stat, which SELinux denies to untrusted_app.
    if build_type and build_type not in ("user",) and not INTEGRITY_ALLOW_USERDEBUG:
        _integrity_reason(reasons, "android_build_type_not_user", 45, "The OS build type is not a production user build.")
        score += 45
    if verified and verified not in ("green",):
        _integrity_reason(reasons, "android_verified_boot_not_green", 60, "Verified Boot state is not green.")
        score += 60
    if flash_locked and flash_locked not in ("1", "true", "locked"):
        _integrity_reason(reasons, "android_bootloader_not_locked", 60, "Bootloader/flash lock property is not locked.")
        score += 60
    if vbmeta_state and vbmeta_state not in ("locked",):
        _integrity_reason(reasons, "android_vbmeta_not_locked", 60, "VBMeta device state is not locked.")
        score += 60
    # Full absence of Verified Boot / AVB data is itself a low-confidence signal:
    # a production Android 8+ device with AVB publishes these, and blanking all
    # of them is a cheap way to dodge the "not green / not locked" checks above.
    # Partial blanking is still caught by those checks; this only fires when the
    # device reports none of the three. Low weight, and treated as a
    # development-image signal so the lab switch suppresses it.
    if not any((verified, flash_locked, vbmeta_state)) and not INTEGRITY_ALLOW_USERDEBUG:
        _integrity_reason(reasons, "android_boot_state_unavailable", 15, "The device reported no Verified Boot / AVB state.")
        score += 15
    if ro_secure == "0":
        _integrity_reason(reasons, "android_ro_secure_disabled", 50, "ro.secure is disabled.")
        score += 50
    if ro_debuggable == "1" and not INTEGRITY_ALLOW_DEBUG:
        _integrity_reason(reasons, "android_system_debuggable", 35, "ro.debuggable is enabled.")
        score += 35

    selinux_probe = _probe(probes, "selinux")
    selinux_mode = _as_text(selinux_probe.get("mode")).strip().lower()
    selinux_getenforce = _as_text(selinux_probe.get("getenforce")).strip().lower()
    selinux_enforce_value = _as_text(selinux_probe.get("enforce_value")).strip()

    # Accept either independent signal as proof of an enforcing local state.
    # Do not classify arbitrary OEM/error text as "not enforcing".
    selinux_enforcing = (
        selinux_mode == "enforcing"
        or selinux_getenforce == "enforcing"
        or selinux_enforce_value == "1"
    )
    selinux_permissive = (
        selinux_mode == "permissive"
        or selinux_getenforce == "permissive"
        or selinux_enforce_value == "0"
    )
    selinux_disabled = (
        selinux_mode == "disabled"
        or selinux_getenforce == "disabled"
    )

    if selinux_disabled:
        _integrity_reason(
            reasons,
            "android_selinux_disabled",
            70,
            "SELinux reports disabled.",
        )
        score += 70
    elif selinux_permissive and not selinux_enforcing:
        _integrity_reason(
            reasons,
            "android_selinux_permissive",
            45,
            "SELinux reports permissive mode.",
        )
        score += 45
    elif not selinux_enforcing:
        # Some OEMs intentionally prevent an ordinary sandboxed app from
        # reading getenforce or /sys/fs/selinux/enforce. An unavailable local
        # measurement is telemetry, not evidence of compromise. Only explicit
        # permissive/disabled states receive risk points.
        pass

    writable_mounts = _as_list(_probe(probes, "mounts").get("protected_rw_mounts"))
    if writable_mounts:
        _integrity_reason(reasons, "android_protected_mount_writable", 55, "A protected system mount appears writable.")
        score += 55

    runtime = _probe(probes, "runtime_maps")
    tokens = {str(x).lower() for x in _as_list(runtime.get("suspicious_tokens"))}
    if "frida" in tokens or "gadget" in tokens or "objection" in tokens:
        _integrity_reason(reasons, "android_frida_runtime_artifact", 90, "Frida/Gadget/Objection artifacts were mapped into the process.")
        score += 90
    if tokens & {"xposed", "lsposed", "substrate", "zygisk", "riru", "magisk", "kernelsu", "apatch"}:
        _integrity_reason(reasons, "android_hook_framework_artifact", 80, "Hook/root framework artifacts were mapped into the process.")
        score += 80

    open_ports = _as_list(_probe(probes, "frida_ports").get("open_ports"))
    if 27042 in open_ports or 27043 in open_ports:
        _integrity_reason(reasons, "android_frida_port_open", 75, "A common local Frida server port is accepting connections.")
        score += 75

    # Structural hook detection (DESIGN.md 27.10-27.12). These signals do not
    # depend on the injected library's filename, so they survive the rename +
    # non-default-port evasion that defeats runtime_maps and frida_ports.
    threads = _probe(probes, "instrumentation_threads")
    frida_threads = _as_list(threads.get("frida_threads"))
    token_threads = _as_list(threads.get("token_threads"))
    glib_threads = _as_list(threads.get("glib_threads"))
    if frida_threads or token_threads:
        _integrity_reason(reasons, "android_instrumentation_runtime_thread", 90,
                          "A Frida/Gum instrumentation runtime thread is present in the process.")
        score += 90
    elif glib_threads:
        # GLib threads are a Frida dependency but not conclusive alone (an app
        # could in principle bundle GLib); weight to elevated, not block.
        _integrity_reason(reasons, "android_glib_runtime_thread", 40,
                          "GLib runtime threads, a common Frida dependency, are present in the process.")
        score += 40

    # Code integrity: native compares libc/libart .text in memory against disk.
    # Clean devices measure exactly zero, and code expected to be immutable has
    # no benign one-byte change, so ANY differing byte counts. The old 4-byte
    # floor (one arm64 branch) missed edits that alter a constant or part of an
    # encoding with fewer changed bytes (review F4; DESIGN.md 63). No report
    # stored in September 2026 had 1-3 differing bytes, so none changes verdict.
    code = _probe(probes, "code_integrity")
    code_checked = _as_bool(code.get("checked"))
    core_diff = _as_int(code.get("diff_bytes"))
    ext_diff = _as_int(code.get("ext_diff_bytes"))
    app_diff = _as_int(code.get("app_diff_bytes"))
    # Core libc/libart is always scored. The extended system libraries are
    # folded in only once their on-device baseline is confirmed (the flag).
    system_diff = core_diff + (ext_diff if INTEGRITY_SCORE_EXTENDED_LIBS else 0)
    if code_checked and system_diff > 0:
        # Modified system-library code in memory is unambiguous tampering, as
        # definitive as a mapped Frida artifact, so it blocks on its own.
        _integrity_reason(reasons, "android_code_integrity_violation", 90,
                          "A system library's executable code differs from its on-disk image (inline hook).")
        score += 90
    if code_checked and INTEGRITY_SCORE_EXTENDED_LIBS and app_diff > 0:
        _integrity_reason(reasons, "android_app_code_modified", 90,
                          "The application's own native code differs from its packaged image.")
        score += 90
    # Coverage (DESIGN.md 63). The scanner now measures every target mapping in
    # full and says when it could not; a bucket that compared only part of its
    # code is not clean evidence for the rest. Visible but not yet scored: what
    # partial evidence should cost is an owner decision awaiting fleet data, and
    # the collector that reports it is the honest one (a platform refusing to
    # make execute-only code readable), not the lying one.
    if code_checked:
        partial = []
        for bucket in _CODE_BUCKETS[: 3 if INTEGRITY_SCORE_EXTENDED_LIBS else 1]:
            expected = code.get("%s_expected_bytes" % bucket)
            if isinstance(expected, int) and not isinstance(expected, bool):
                compared = _as_int(code.get("%s_compared_bytes" % bucket))
                if expected == 0 or compared < expected:
                    partial.append("%s %d of %d bytes" % (bucket, compared, expected))
        if partial:
            _integrity_reason(reasons, "android_code_integrity_partial", 30,
                              "Code integrity compared only part of its targets (%s)."
                              % "; ".join(partial), report_only=True)
        if _as_int(code.get("protect_restore_failures")) > 0:
            _integrity_reason(reasons, "android_code_integrity_restore_failed", 30,
                              "The scanner could not restore a mapping's original "
                              "protection after reading it.", report_only=True)

    exec_maps = _probe(probes, "exec_mappings")
    score += _score_wx_memory(reasons, exec_maps, apk_hash)
    if _as_int(exec_maps.get("deleted_exec_mappings")) > 0:
        # The ART JIT cache is excluded client-side; what remains is an
        # executable region backed by a deleted file, a classic injection shape.
        _integrity_reason(reasons, "android_deleted_code_mapping", 55,
                          "Executable memory backed by a deleted file is mapped into the process.")
        score += 55
    # The app's own compiled code -- the oat/ files in its own install folder --
    # replaced on disk while it ran: Android recompiles an app in the background
    # after an install or update (the Huawei did, about a minute after an
    # install, 2026-10-13, and scored 55 until the app restarted). The collector
    # counts these apart; writing there takes installd, system or root, so it is
    # not an injection shape and stays advisory (DESIGN.md 75). An older
    # collector cannot tell them apart and counts them in deleted_exec_mappings,
    # which still costs 55.
    if _as_int(exec_maps.get("deleted_exec_own_code")) > 0:
        _integrity_reason(reasons, "android_app_code_recompiled", 0,
                          "The app's own compiled code was replaced on disk while it ran "
                          "(a system recompilation after an install or update; advisory).")

    emulator = _probe(probes, "emulator")
    if _as_bool(emulator.get("suspected")) and not INTEGRITY_ALLOW_EMULATOR:
        _integrity_reason(reasons, "android_emulator", 25, "The runtime resembles an Android emulator.")
        score += 25

    # Advisory since joint review R1 (DESIGN.md 69): common on legitimate
    # developer and power-user phones, and not evidence of compromise, so they
    # must not add up with other weak signals into a refusal. A deployment that
    # wants them off makes that an eligibility rule (developer_options_refuses,
    # adb_enabled_refuses), refused with its own code and remedy by the gate.
    dev = _probe(probes, "developer_settings")
    if _as_bool(dev.get("developer_options_enabled")):
        _integrity_reason(reasons, "android_developer_options", 0,
                          "Developer options are enabled (advisory).")
    if _as_bool(dev.get("adb_enabled")):
        _integrity_reason(reasons, "android_adb_enabled", 0, "ADB is enabled (advisory).")

    # Volunteered by collectors from version 4 (DESIGN.md 80). A VPN or an HTTP
    # proxy is common on legitimate phones -- privacy, a corporate network --
    # and no evidence of compromise: recorded at 0 points. A deployment that
    # wants them off makes it an eligibility rule (vpn_active_refuses,
    # http_proxy_refuses).
    network = _probe(probes, "network")
    if _as_bool(network.get("vpn_active")):
        _integrity_reason(reasons, "android_vpn_active", 0,
                          "A VPN is active on this phone (advisory).")
    if _as_bool(network.get("http_proxy_configured")):
        _integrity_reason(reasons, "android_http_proxy", 0,
                          "An HTTP proxy is configured on this phone (advisory).")

    # Optional measurements and the patch level (DESIGN.md 82): the DBA's
    # points, each with an eligibility rule the DBA turns on.
    score += _score_access_holders(reasons, probes)
    score += _score_capture_and_location(reasons, probes, "android")
    score += _score_security_patch(reasons, probes)

    return score, hard_block, reasons


def _score_ios_integrity(probes):
    reasons = []
    score = 0
    hard_block = False

    app_identity = _probe(probes, "app_identity")
    bundle_id = _as_text(app_identity.get("bundle_id"))
    executable_hash = _as_text(app_identity.get("executable_sha256")).lower()
    if EXPECTED_IOS_BUNDLE_ID and bundle_id != EXPECTED_IOS_BUNDLE_ID:
        _integrity_reason(reasons, "ios_bundle_id_mismatch", 100, "Bundle identifier does not match the server baseline.", True)
        hard_block = True
    if EXPECTED_IOS_EXECUTABLE_SHA256 and executable_hash not in EXPECTED_IOS_EXECUTABLE_SHA256:
        _integrity_reason(reasons, "ios_executable_hash_mismatch", 100, "Executable hash does not match the configured build baseline.", True)
        hard_block = True

    signing = _probe(probes, "code_signing")
    signing_id = _as_text(signing.get("signing_identifier"))
    team_id = _as_text(signing.get("team_identifier"))
    if EXPECTED_IOS_SIGNING_ID and signing_id != EXPECTED_IOS_SIGNING_ID:
        _integrity_reason(reasons, "ios_signing_identifier_mismatch", 100, "Code-signing identifier does not match the server baseline.", True)
        hard_block = True
    if EXPECTED_IOS_TEAM_ID and team_id != EXPECTED_IOS_TEAM_ID:
        _integrity_reason(reasons, "ios_team_identifier_mismatch", 100, "Team identifier does not match the server baseline.", True)
        hard_block = True
    if _as_bool(signing.get("get_task_allow")) and not INTEGRITY_ALLOW_DEBUG:
        _integrity_reason(reasons, "ios_get_task_allow", 35, "get-task-allow is enabled for this application.")
        score += 35

    # --- Fake-signature detection, baseline-free (DESIGN.md 35.5 / 35.6) ---
    #
    # Unlike the two rules above, neither of these needs EXPECTED_IOS_* to be
    # configured, which matters: an unconfigured deployment currently scores a
    # fake-signed application at zero for its signature.
    scoring_fake_signature = INTEGRITY_SCORE_IOS_FAKE_SIGNATURE

    # A legitimately signed iOS application has its CodeDirectory identifier
    # equal to its bundle identifier, because Xcode derives one from the other.
    #
    # MEASURED: on the iPhone 7, a TrollStore-installed build reported
    # signing_identifier "com.icraze.gtatracker" against our own bundle id
    # com.example.devicefingerprinting. That is the whole of the evidence.
    #
    # NOT MEASURED, and deliberately not claimed here: exactly which part of
    # the CoreTrust bypass produces that identifier. CVE-2023-41991 is a
    # multiple-signer confusion bug -- one CMS blob carries two signers, and
    # CoreTrust takes the Apple-signed verdict from the first signer's
    # certificates while validating the binary against the second signer's
    # CodeDirectory hashes. Whether the donor identifier always lands in
    # slot 0 of the SuperBlob, across TrollStore versions and donor binaries,
    # has not been established. The rule may therefore be keying on an
    # assembly artifact rather than on an invariant of the exploit, which is
    # one more reason it ships report-only.
    #
    # Both operands must be non-empty. An unsigned build legitimately reports an
    # empty signing_identifier, and an absent measurement must never be read as
    # a finding -- the recurring trap recorded in 28.8, 34.3 and 35.7. The
    # emptiness check is the guard, not a separate "signed" flag, because a
    # non-empty identifier can only have come from a parsed signature anyway.
    # Two client conventions map into this one field, and both are legitimate.
    # The Swift collector reports the CodeDirectory identifier, which on a
    # properly signed app equals the bundle id exactly. The .NET collector
    # reports the application-identifier entitlement, which is "TEAMID.bundleid"
    # -- so an exact comparison would raise +90 on every clean .NET device.
    # Accept either shape; a fake signature matches neither.
    identifier_is_consistent = signing_id == bundle_id or signing_id.endswith(
        "." + bundle_id
    )
    if signing_id and bundle_id and not identifier_is_consistent:
        _integrity_reason(
            reasons,
            "ios_signing_identifier_bundle_mismatch",
            90,
            "The code-signing identifier does not match the bundle identifier, "
            "which a legitimately signed application never does.",
            report_only=not scoring_fake_signature,
        )
        if scoring_fake_signature:
            score += 90

    # Deliberately the WEAKER of the pair, and recorded as such. This is a name
    # match, and 27.11 already proved on Android exactly how a name match ends:
    # a real Frida gadget renamed to libhelper.so and moved off port 27042
    # scored 18/trusted while fully active. One patched constant in a TrollStore
    # fork defeats this rule completely. It is kept because an attacker who does
    # not bother to change it should still be caught cheaply -- corroborating
    # evidence, never the detection, low weight, never a hard block.
    if team_id and team_id.strip().upper() in IOS_KNOWN_FAKE_TEAM_IDS:
        _integrity_reason(
            reasons,
            "ios_known_fake_team_identifier",
            25,
            "The team identifier matches a known fake-signing marker.",
            report_only=not scoring_fake_signature,
        )
        if scoring_fake_signature:
            score += 25

    debugger = _probe(probes, "debugger")
    if _as_bool(debugger.get("traced")) and not INTEGRITY_ALLOW_DEBUG:
        _integrity_reason(reasons, "ios_process_traced", 50, "The process is being traced/debugged.")
        score += 50

    jailbreak_paths = _as_list(_probe(probes, "jailbreak_files").get("found_paths"))
    if jailbreak_paths:
        _integrity_reason(reasons, "ios_jailbreak_artifact", 75, "Jailbreak filesystem artifacts were visible.")
        score += 75

    sandbox = _probe(probes, "sandbox")
    if _as_bool(sandbox.get("write_outside_sandbox_succeeded")):
        _integrity_reason(reasons, "ios_sandbox_escape_signal", 100, "The app successfully wrote outside its sandbox.", True)
        hard_block = True

    dyld = _probe(probes, "dyld_images")
    dyld_tokens = {str(x).lower() for x in _as_list(dyld.get("suspicious_tokens"))}
    if dyld_tokens & {"frida", "gadget", "objection"}:
        _integrity_reason(reasons, "ios_frida_runtime_artifact", 90, "Frida/Gadget/Objection images were loaded into the process.")
        score += 90
    if dyld_tokens & {"substrate", "mobilesubstrate", "substitute", "libhooker", "ellekit", "cydia"}:
        _integrity_reason(reasons, "ios_hook_framework_artifact", 85, "Jailbreak/hooking framework images were loaded into the process.")
        score += 85

    inserted = _as_text(_probe(probes, "environment").get("dyld_insert_libraries"))
    if inserted:
        _integrity_reason(reasons, "ios_dyld_injection_environment", 90, "DYLD_INSERT_LIBRARIES is set.")
        score += 90

    simulator = _probe(probes, "simulator")
    if _as_bool(simulator.get("is_simulator")) and not INTEGRITY_ALLOW_EMULATOR:
        _integrity_reason(reasons, "ios_simulator", 25, "The app is running in the iOS simulator.")
        score += 25

    # Structural code integrity, app bucket only (battery item 16).
    #
    # There is no iOS equivalent of item 14. Android compares libc and libart
    # against real files; iOS system libraries have no individual files at all,
    # because dyld merges them into the shared cache. The collector reports
    # those images as system_images_unreadable rather than as zero-diff, so a
    # structurally unmeasurable bucket is never mistaken for a clean one.
    #
    # checked gates the rule, exactly as on Android: an app bucket reporting
    # app_compared_bytes 0 is inert, not clean, and must not be scored as
    # either. Any differing byte counts, as on Android (DESIGN.md 63).
    code = _probe(probes, "code_integrity")
    if _as_bool(code.get("checked")) and _as_int(code.get("app_diff_bytes")) > 0:
        _integrity_reason(
            reasons,
            "ios_app_code_modified",
            90,
            "The application's own code differs in memory from its packaged image.",
            report_only=not INTEGRITY_SCORE_IOS_CODE_INTEGRITY,
        )
        if INTEGRITY_SCORE_IOS_CODE_INTEGRITY:
            score += 90

    # As on Android (DESIGN.md 80); iOS offers no VPN API to other apps, so the
    # collector infers one from the interfaces the system proxy settings are
    # scoped to -- a heuristic, its interface names sent with it.
    network = _probe(probes, "network")
    if _as_bool(network.get("vpn_active")):
        _integrity_reason(reasons, "ios_vpn_active", 0,
                          "A VPN appears to be active on this phone (advisory, inferred).")
    if _as_bool(network.get("http_proxy_configured")):
        _integrity_reason(reasons, "ios_http_proxy", 0,
                          "An HTTP proxy is configured on this phone (advisory).")

    # iOS shows an app no other app, so only these two (DESIGN.md 82).
    score += _score_capture_and_location(reasons, probes, "ios")

    return score, hard_block, reasons


def _score_integrity(platform, probes):
    if platform == "android":
        score, hard_block, reasons = _score_android_integrity(probes)
    elif platform == "ios":
        score, hard_block, reasons = _score_ios_integrity(probes)
    else:
        raise ApiProblem("Unsupported integrity platform.", 400, "unsupported_platform")
    _cap_conditions(reasons)
    # Derive the displayed integrity score from the same reasons returned to
    # callers. This keeps hard-block findings such as a signing-certificate
    # mismatch numerically consistent with their advertised +100 points.
    # The score remains capped at 100, while hard_block stays an independent
    # fail-closed control.
    score = min(
        sum(max(0, int(reason.get("points", 0))) for reason in reasons),
        100,
    )
    return {
        "score": score,
        "hard_block": bool(hard_block),
        "verdict": _integrity_verdict(score, hard_block=hard_block),
        "reasons": reasons,
    }


def _latest_integrity_state(installation_id):
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT report_id, score, verdict, hard_block, reasons, created_at,
                   evidence_quality, finding_score
            FROM integrity_reports
            WHERE installation_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (installation_id,),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    age_seconds = max(0, int((_utc_now() - row[5]).total_seconds()))
    return {
        "report_id": str(row[0]),
        "score": int(row[1]),
        "verdict": row[2],
        "hard_block": bool(row[3]),
        "reasons": _as_list(DIALECT.json_value(row[4])),
        "created_at": _iso_z(row[5]),
        "age_seconds": age_seconds,
        "fresh": age_seconds <= _integrity_freshness_seconds(),
        # Reports stored before migration 015 carry neither.
        "evidence_quality": row[6],
        "finding_score": int(row[7]) if row[7] is not None else None,
    }


def _device_integrity_memory(device_id, installation_id):
    """Worst native-integrity outcome this installation inherits from its device.

    Reports are stored per installation, so a reinstall hands the attacker a
    clean slate: the new installation_id has no history of its own. Recognition
    of the physical device survives a reinstall, so the integrity verdict should
    too. This returns the worst report recorded against the canonical device_id
    inside the memory window, which is what stops a compromised device from
    laundering a block by reinstalling the app.

    One-directional (DESIGN.md 68, joint review R4): the reports considered are
    this installation's own and those of the device's ESTABLISHED installations
    -- its original one, and hint-linked ones confirmed by a returning account
    (migration 009). A hint is client input, so a hint-linked installation
    nobody has confirmed can no longer push its block onto the rest of the
    device. The set is always a subset of what was considered before, so this
    can only lift refusals, never add one.
    """
    hours = _risk_setting_int("integrity_device_memory_hours", INTEGRITY_DEVICE_MEMORY_HOURS)
    if hours <= 0:
        return None
    cutoff = _utc_now() - timedelta(hours=hours)
    # What is remembered is the FINDINGS score (DESIGN.md 76): a scan whose
    # probes failed is not evidence of compromise, so it never follows the
    # device. Reports from before migration 015 have no finding_score and are
    # judged by their score until they age out of the window.
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT r.report_id, r.installation_id, r.score, r.verdict,
                   r.hard_block, r.created_at, r.finding_score
            FROM integrity_reports r
            JOIN app_installations i ON i.installation_id = r.installation_id
            WHERE r.device_id = %s AND r.created_at >= %s
              AND (r.installation_id = %s
                   OR i.registration_method <> 'reinstall_hint'
                   OR i.device_confirmed_at IS NOT NULL)
            ORDER BY r.hard_block DESC, COALESCE(r.finding_score, r.score) DESC,
                     r.created_at DESC,
                     CASE WHEN r.installation_id = %s THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (device_id, cutoff, installation_id, installation_id),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    finding = int(row[6]) if row[6] is not None else int(row[2])
    return {
        "report_id": str(row[0]),
        "installation_id": str(row[1]),
        "score": int(row[2]),
        "verdict": row[3],
        "hard_block": bool(row[4]),
        "created_at": _iso_z(row[5]),
        "finding_score": finding,
        "finding_verdict": _integrity_verdict(finding, hard_block=bool(row[4])),
        "window_hours": hours,
    }


# DBA eligibility rules (joint review R1, DESIGN.md 69): a deployment may
# require a phone setting to be off. Not a compromise finding and never scored:
# an explicit refusal with its own code and remedy. Read from the latest stored
# report's reasons, so a DBA change applies at once and a new scan clears it.
_ELIGIBILITY_RULES = (
    ("developer_options_refuses", "android_developer_options",
     "Turn off Developer options, then send a new integrity scan."),
    ("adb_enabled_refuses", "android_adb_enabled",
     "Turn off USB debugging (ADB), then send a new integrity scan."),
    # DESIGN.md 80. A client older than the network probe reports neither.
    ("vpn_active_refuses", "android_vpn_active",
     "Turn off the VPN, then send a new integrity scan."),
    ("vpn_active_refuses", "ios_vpn_active",
     "Turn off the VPN, then send a new integrity scan."),
    ("http_proxy_refuses", "android_http_proxy",
     "Remove the HTTP proxy from the network settings, then send a new integrity scan."),
    ("http_proxy_refuses", "ios_http_proxy",
     "Remove the HTTP proxy from the network settings, then send a new integrity scan."),
    # DESIGN.md 82. Each needs its measurement requested by the DBA and enabled
    # by the app; a phone that does not send it is never refused by its rule.
    ("accessibility_sideloaded_refuses", "android_accessibility_sideloaded",
     "Turn off Accessibility for apps that did not come from an app store, then send a new "
     "integrity scan."),
    ("accessibility_non_system_refuses", "android_accessibility_non_system",
     "Turn off Accessibility for apps that are not part of the phone's system, then send a new "
     "integrity scan."),
    ("keyboard_sideloaded_refuses", "android_keyboard_sideloaded",
     "Switch to a keyboard from an app store or the phone's own, then send a new integrity scan."),
    ("keyboard_non_system_refuses", "android_keyboard_non_system",
     "Switch to the phone's own keyboard, then send a new integrity scan."),
    ("notification_access_sideloaded_refuses", "android_notification_access_sideloaded",
     "Turn off notification access for apps that did not come from an app store, then send a new "
     "integrity scan."),
    ("notification_access_non_system_refuses", "android_notification_access_non_system",
     "Turn off notification access for apps that are not part of the phone's system, then send a "
     "new integrity scan."),
    ("device_admin_sideloaded_refuses", "android_device_admin_sideloaded",
     "Deactivate device-administrator apps that did not come from an app store, then send a new "
     "integrity scan."),
    ("device_admin_non_system_refuses", "android_device_admin_non_system",
     "Deactivate device-administrator apps that are not part of the phone's system, then send a "
     "new integrity scan."),
    ("remote_access_app_refuses", "android_remote_access_app",
     "Uninstall remote-control apps, then send a new integrity scan."),
    ("screen_capture_refuses", "android_screen_captured",
     "Stop recording, casting or mirroring the screen, then send a new integrity scan."),
    ("screen_capture_refuses", "ios_screen_captured",
     "Stop recording, casting or mirroring the screen, then send a new integrity scan."),
    ("mock_location_refuses", "android_mock_location",
     "Turn off the mock-location app, then send a new integrity scan."),
    ("mock_location_refuses", "ios_mock_location",
     "Stop simulating the location, then send a new integrity scan."),
    ("security_patch_outdated_refuses", "android_security_patch_outdated",
     "Install the latest security update, then send a new integrity scan."),
)


def _eligibility_failures(state):
    found = {
        reason.get("code")
        for reason in _as_list((state or {}).get("reasons"))
        if isinstance(reason, dict)
    }
    return [
        {"rule": setting, "reason": code, "remedy": remedy}
        for setting, code, remedy in _ELIGIBILITY_RULES
        if code in found and _risk_setting_bool(setting)
    ]


def _enforce_integrity_gate(
    device_id,
    installation_id,
    step_up=None,
    step_up_accepted=False,
    limited_ok=False,
    accepted=None,
):
    """Refuse the request unless the latest integrity verdict allows it.

    An elevated verdict is satisfied by a step-up proof verified for this very
    request (step_up), on the endpoints that accept one (step_up_accepted) --
    the authenticated account requests (DESIGN.md 63, review F11). It used to
    answer integrity_step_up_required even where no step-up proof could ever
    satisfy it; where none is accepted (login, registration, refresh) it now
    says so: integrity_elevated, and the remedy is a clean scan.

    limited_ok (login, registration, refresh and the session upgrade, DESIGN.md
    70): a verdict the DBA lists in limited_session_integrity_verdicts (owner
    default: elevated) does not refuse; the returned state carries
    limited_cause and the caller issues a limited session. Everything else --
    block, an unlisted review, an eligibility rule, a device-memory block --
    still refuses here, before any password is compared.

    accepted (a full session's upgrade acceptance, DESIGN.md 72): a verdict
    whose cause the upgrade accepted passes, marked accepted_by_upgrade. Only
    that cause: a worse verdict, an eligibility rule or a device-memory block
    refuses as ever.
    """
    state = _latest_integrity_state(installation_id)
    ineligible = _eligibility_failures(state)
    if ineligible:
        state = dict(state, eligibility=ineligible)
    if INTEGRITY_MODE != "enforce":
        return state
    if state is None or not state.get("fresh"):
        raise ApiProblem(
            "A fresh native integrity scan is required before this operation.",
            403,
            "integrity_scan_required",
            details={"integrity": state},
        )
    verdict = state.get("verdict")
    if verdict == "block":
        raise ApiProblem(
            "The latest device-integrity verdict is blocked.",
            403,
            "integrity_blocked",
            details={"integrity": state},
        )
    soft = (
        _risk_setting_words("limited_session_integrity_verdicts", "elevated")
        if limited_ok
        else set()
    )
    if verdict == "review" and _accepted(accepted, "integrity_review", integrity=state):
        state = dict(state, accepted_by_upgrade=True, acceptance_id=accepted.acceptance_id)
    elif verdict == "review" and "review" in soft:
        state = dict(state, limited_cause="integrity_review")
    elif verdict == "review":
        raise ApiProblem(
            "The latest device-integrity verdict requires review.",
            403,
            "integrity_review_required",
            details={"integrity": state},
        )
    if ineligible:
        raise ApiProblem(
            "This device does not meet the deployment's eligibility rules: %s"
            % " ".join(item["remedy"] for item in ineligible),
            403,
            "integrity_device_ineligible",
            details={"integrity": state, "eligibility": ineligible},
        )
    if verdict == "elevated" and step_up:
        state = dict(state, satisfied_by_step_up=True)
    elif verdict == "elevated" and _accepted(accepted, "integrity_elevated", integrity=state):
        state = dict(state, accepted_by_upgrade=True, acceptance_id=accepted.acceptance_id)
    elif verdict == "elevated" and step_up_accepted:
        raise ApiProblem(
            "The latest device-integrity verdict requires step-up verification: "
            "repeat the request with a step-up proof.",
            403,
            "integrity_step_up_required",
            details={"integrity": state},
        )
    elif verdict == "elevated" and "elevated" in soft:
        state = dict(state, limited_cause="integrity_elevated")
    elif verdict == "elevated":
        raise ApiProblem(
            "The latest device-integrity verdict is elevated and this operation "
            "accepts no step-up proof; a clean integrity scan is required.",
            403,
            "integrity_elevated",
            details={"integrity": state},
        )
    # This installation's own scan is clean. Before allowing the request, check
    # whether the physical device was blocked recently under any installation:
    # reinstalling must not clear a compromised device's record.
    memory = _device_integrity_memory(device_id, installation_id)
    if memory is not None and memory.get("finding_verdict") == "block":
        raise ApiProblem(
            "This device recorded a blocked integrity verdict recently; "
            "reinstalling the app does not clear it.",
            403,
            "integrity_device_blocked_recently",
            details={"integrity": state, "device_integrity_memory": memory},
        )
    _require_complete_evidence(state)
    return state


def _require_complete_evidence(state):
    """On the DBA's complete_evidence_paths -- payments, advances -- only a
    fresh scan that measured everything requested will do (owner decision of
    2026-10-13): incomplete, invalid, partial or legacy evidence is refused,
    whatever the verdict, and no upgrade acceptance or step-up proof changes
    that. Blinding the probes therefore gains nothing where money moves. The
    app's remedy is a new scan, or an app update for a legacy collector."""
    if not has_request_context():
        return
    if request.path not in _risk_setting_words("complete_evidence_paths", ""):
        return
    max_age = _risk_setting_int("complete_evidence_max_age_seconds", _integrity_freshness_seconds())
    quality = (state or {}).get("evidence_quality")
    age = (state or {}).get("age_seconds")
    if quality == "complete" and isinstance(age, int) and age <= max_age:
        return
    raise ApiProblem(
        "This operation needs a fresh, complete integrity scan (at most %d seconds old); "
        "send a new scan, and update the app if it reports legacy evidence." % max_age,
        403,
        "integrity_complete_evidence_required",
        details={"evidence_quality": quality, "age_seconds": age,
                 "max_age_seconds": max_age},
    )


# ---------------------------------------------------------------------------
# Risk/device policy helpers
# ---------------------------------------------------------------------------


def _account_device_points(reasons, projected_count):
    """Score devices per account against the DBA's counts; (points, hard)."""
    devices_block = _risk_setting_int(
        "account_devices_block_count", POLICY_ACCOUNT_DEVICE_BLOCK_COUNT
    )
    devices_review = _risk_setting_int("account_devices_review_count", 3)
    devices_elevated = _risk_setting_int("account_devices_elevated_count", 2)
    if devices_block > 0 and projected_count >= devices_block:
        _policy_reason(
            reasons,
            "account_device_count_block_threshold",
            100,
            "This account is linked to %d recognized devices; the configured policy "
            "blocks at %d." % (projected_count, devices_block),
        )
        return 0, True
    if devices_review > 0 and projected_count >= devices_review:
        points = _risk_setting_int("account_devices_review_points", 60)
        _policy_reason(
            reasons,
            "account_has_many_devices",
            points,
            "This account is linked to %d recognized devices; the configured policy "
            "reviews at %d." % (projected_count, devices_review),
        )
        return points, False
    if devices_elevated > 0 and projected_count >= devices_elevated:
        points = _risk_setting_int("account_devices_elevated_points", 35)
        _policy_reason(
            reasons,
            "account_has_multiple_devices",
            points,
            "This account is linked to %d recognized devices." % projected_count,
        )
        return points, False
    return 0, False


def _policy_reason(reasons, code, points, message, count=None):
    reason = {
        "code": code,
        "points": int(points),
        "message": message,
    }
    if count is not None:
        # A reason that follows a count carries it, and an approval covers it
        # only up to the count the approver saw (DESIGN.md 77).
        reason["count"] = int(count)
    reasons.append(reason)


def _policy_bands():
    """The relationship-risk bands (DBA-tunable; owner defaults 30 / 60 / 90).

    Below step-up: allow. Step-up to review: step_up, recorded and allowed
    unless elevated_risk_refuses is set. Review to block: review, refused in
    enforce mode. Block and above, or any hard reason: block.
    """
    return {
        "step_up": _risk_setting_int("policy_step_up_score", POLICY_STEP_UP_SCORE),
        "review": _risk_setting_int("policy_review_score", POLICY_REVIEW_SCORE),
        "block": _risk_setting_int("policy_block_score", POLICY_BLOCK_SCORE),
    }


def _policy_action(score, hard_block=False):
    bands = _policy_bands()
    if hard_block or score >= bands["block"]:
        return "block"
    if score >= bands["review"]:
        return "review"
    if score >= bands["step_up"]:
        return "step_up"
    return "allow"


# The server's own observations (DESIGN.md 77): only what this server decided
# or changed itself, never a phone's account of anything. sign_in_failed: a
# wrong password for an account; sign_in_unknown_account: a sign-in to a
# handle no account has; stepup_failed: a step-up proof offered that did not
# verify; approval_budget_exhausted: an approval request refused by the
# account's hourly budget; stepup_reenrolled: a step-up key replaced;
# token_without_key: one of this phone's tokens presented without its key
# (copied elsewhere), once per token; request_replayed: one of its signed
# requests sent again, once per request. Denied approvals are already rows of
# session_upgrade_requests and are counted there.
_OBSERVATION_KINDS = (
    "sign_in_failed",
    "sign_in_unknown_account",
    "stepup_failed",
    "approval_budget_exhausted",
    "stepup_reenrolled",
    "token_without_key",
    "request_replayed",
    "app_pin_failed",
    "app_pin_set",
    "app_pin_support_unlocked",
    "app_pin_support_reset",
)
# Observations recorded at most once per token or per request take an ID
# derived from it, so a duplicate is the database's own refusal.
_OBSERVATION_ONCE_NAMESPACE = uuid.UUID("0b7d6c2e-58f4-5a3e-9c1d-7e2a4b6f8d90")


def _record_observation(kind, code, device_id, installation_id, account_id=None, cursor=None,
                        once_key=None):
    """Record one server observation.

    With a cursor the row joins the caller's transaction, so a change and its
    record commit together. Without one it is its own unit, for a refusal
    whose transaction was rolled back: the caller has left that block, so no
    lock it took is still held. A standalone record is evidence, not a gate:
    if it cannot be written that is logged, and the request still ends with
    its own answer -- a wrong password stays a 401, never a 500. With
    `once_key` (a token's jti, a request's nonce) it is written at most once:
    someone repeating a stolen token adds one row, not one per attempt.
    """
    if kind not in _OBSERVATION_KINDS:
        raise ValueError("unknown observation kind %r" % kind)
    if once_key is not None and cursor is not None:
        raise ValueError("a once-only observation is recorded in its own unit")
    statement = (
        "INSERT INTO server_observations "
        "(observation_id, kind, code, account_id, device_id, installation_id) "
        "VALUES (%s, %s, %s, %s, %s, %s)"
    )
    values = (
        str(uuid.uuid5(_OBSERVATION_ONCE_NAMESPACE, "%s:%s" % (kind, once_key)))
        if once_key is not None else str(uuid.uuid4()),
        kind,
        code,
        str(account_id) if account_id is not None else None,
        str(device_id) if device_id is not None else None,
        str(installation_id) if installation_id is not None else None,
    )
    if cursor is not None:
        cursor.execute(statement, values)
        return
    try:
        with _cursor(commit=True) as own:
            own.execute(statement, values)
    except Exception as error:
        if once_key is not None and DIALECT.is_unique_violation(error):
            return  # already recorded for this token or request
        logger.exception(
            "A server observation could not be recorded: kind=%s code=%s account=%s "
            "device=%s installation=%s",
            kind,
            code,
            account_id,
            device_id,
            installation_id,
        )


@contextmanager
def _observed_refusal(code, kind, device_id, installation_id, account_id=None, once_key=None):
    """Record observation `kind` when the block refuses with `code`. Entered
    before the block's cursor, it records after that cursor has rolled back
    and released its locks:  with _observed_refusal(...), _cursor(...) as c:"""
    try:
        yield
    except ApiProblem as problem:
        if problem.code == code:
            _record_observation(kind, code, device_id, installation_id, account_id,
                                once_key=once_key() if callable(once_key) else once_key)
        raise


def _server_observation_counts(cursor, device_id, installation_id, account_id, now, window,
                               joined_at=None):
    """What this server observed in the `window` before `now`: on this phone,
    for every account; on this account, from every phone; and for this account
    on this phone (DESIGN.md 77). With `joined_at` -- this phone is new to the
    account -- also the wrong passwords other phones sent in the window before
    it joined."""
    since = now - window
    device = dict.fromkeys(_OBSERVATION_KINDS, 0)
    device["sign_in_failed_accounts"] = 0
    cursor.execute(
        """
        SELECT kind, COUNT(*), COUNT(DISTINCT account_id)
        FROM server_observations
        WHERE device_id = %s AND occurred_at >= %s
        GROUP BY kind
        """,
        (device_id, since),
    )
    for kind, count, accounts in cursor.fetchall() or []:
        if kind in _OBSERVATION_KINDS:
            device[str(kind)] = int(count)
        if kind == "sign_in_failed":
            device["sign_in_failed_accounts"] = int(accounts)
    cursor.execute(
        """
        SELECT COUNT(*) FROM session_upgrade_requests
        WHERE device_id = %s AND denied_at >= %s
        """,
        (device_id, since),
    )
    device["approval_denied"] = int(cursor.fetchone()[0])
    if account_id is None:
        return {"device": device, "account": None, "device_account": None, "newcomer": None}
    # This account on this phone: a denial, an exhausted budget or a
    # re-enrolment says nothing about another account sharing the phone.
    device_account = dict.fromkeys(
        ("approval_denied", "approval_budget_exhausted", "stepup_reenrolled", "app_pin_failed"),
        0,
    )
    cursor.execute(
        """
        SELECT kind, COUNT(*) FROM server_observations
        WHERE device_id = %s AND account_id = %s AND occurred_at >= %s
          AND kind IN ('approval_budget_exhausted', 'stepup_reenrolled', 'app_pin_failed')
        GROUP BY kind
        UNION ALL
        SELECT 'approval_denied', COUNT(*) FROM session_upgrade_requests
        WHERE device_id = %s AND account_id = %s AND denied_at >= %s
        """,
        (device_id, account_id, since, device_id, account_id, since),
    )
    for kind, count in cursor.fetchall() or []:
        device_account[str(kind)] = int(count)
    account = dict.fromkeys(
        (kind for kind in _OBSERVATION_KINDS if kind != "sign_in_unknown_account"), 0
    )
    account["sign_in_failed_installations"] = 0
    cursor.execute(
        """
        SELECT kind, COUNT(*), COUNT(DISTINCT installation_id)
        FROM server_observations
        WHERE account_id = %s AND occurred_at >= %s
        GROUP BY kind
        """,
        (account_id, since),
    )
    for kind, count, installations in cursor.fetchall() or []:
        if kind in account:
            account[str(kind)] = int(count)
        if kind == "sign_in_failed":
            account["sign_in_failed_installations"] = int(installations)
    # A user mistyping on their own phone is not evidence against anyone --
    # nor after reinstalling the app there: the account's rule counts only the
    # failures of other phones.
    cursor.execute(
        """
        SELECT COUNT(*) FROM server_observations
        WHERE account_id = %s AND occurred_at >= %s
          AND kind = 'sign_in_failed' AND device_id <> %s
        """,
        (account_id, since, device_id),
    )
    account["sign_in_failed_elsewhere"] = int(cursor.fetchone()[0])
    newcomer = None
    if joined_at is not None:
        # The window before this phone joined: failures after it cannot have
        # been what let it in. Joining now, that is the window just counted.
        before = account["sign_in_failed_elsewhere"]
        if joined_at < now:
            cursor.execute(
                """
                SELECT COUNT(*) FROM server_observations
                WHERE account_id = %s AND occurred_at >= %s AND occurred_at <= %s
                  AND kind = 'sign_in_failed' AND device_id <> %s
                """,
                (account_id, joined_at - window, joined_at, device_id),
            )
            before = int(cursor.fetchone()[0])
        newcomer = {"joined_at": _iso_z(joined_at), "sign_in_failed_elsewhere_before": before}
    return {"device": device, "account": account, "device_account": device_account,
            "newcomer": newcomer}


# Public network lists (DESIGN.md 81): VPN providers' networks and hosting
# networks (X4BNet, MIT) and the Tor Project's exit list, shipped with the
# server and refreshed by DevOps with tools/fetch_network_lists.py. Read at
# call time, so a deployment -- or the gate -- may point elsewhere. The lists
# are IPv4 only: an IPv6 address is unknown to them (None), never "not listed".
NETWORK_LISTS_DIR = os.environ.get(
    "NETWORK_LISTS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "network_lists"),
)
_NETWORK_LIST_FILES = {
    "vpn": "x4bnet_vpn_ipv4.txt",
    "hosting": "x4bnet_datacenter_ipv4.txt",
    "tor": "tor_exits.txt",
}
_NETWORK_LISTS_RECHECK_SECONDS = 60
_network_lists = {"checked_at": None, "dir": None, "mtimes": None, "ranges": {}}
_network_lists_lock = threading.Lock()


def _parse_ipv4_ranges(text):
    """(starts, ends): the IPv4 networks in `text`, merged and sorted. A line
    that is not one -- a comment, a blank, an IPv6 network -- is skipped."""
    ranges = []
    for line in text.splitlines():
        item = line.split("#", 1)[0].strip()
        if not item:
            continue
        try:
            network = ipaddress.IPv4Network(item, strict=False)
        except ValueError:
            continue
        ranges.append((int(network.network_address), int(network.broadcast_address)))
    ranges.sort()
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return [start for start, _ in merged], [end for _, end in merged]


def _network_list_ranges():
    """{kind: (starts, ends) or None}, re-read when a file changes; a missing
    or unreadable file is None -- unknown, never an empty list."""
    state, directory = _network_lists, NETWORK_LISTS_DIR
    now = time.monotonic()
    if (state["checked_at"] is not None and state["dir"] == directory
            and now - state["checked_at"] < _NETWORK_LISTS_RECHECK_SECONDS):
        return state["ranges"]
    with _network_lists_lock:
        mtimes = {}
        for kind, name in _NETWORK_LIST_FILES.items():
            try:
                mtimes[kind] = os.stat(os.path.join(directory, name)).st_mtime
            except OSError:
                mtimes[kind] = None
        if mtimes != state["mtimes"] or state["dir"] != directory:
            ranges = {}
            for kind, name in _NETWORK_LIST_FILES.items():
                if mtimes[kind] is None:
                    ranges[kind] = None
                    continue
                try:
                    with open(os.path.join(directory, name), encoding="utf-8") as handle:
                        ranges[kind] = _parse_ipv4_ranges(handle.read())
                except (OSError, UnicodeDecodeError):
                    logger.exception("Network list %s could not be read; treating it as unknown.", name)
                    ranges[kind] = None
            state.update(ranges=ranges, mtimes=mtimes, dir=directory)
        state["checked_at"] = now
        return state["ranges"]


def _in_ranges(ranges, value):
    starts, ends = ranges
    index = bisect.bisect_right(starts, value) - 1
    return index >= 0 and value <= ends[index]


def _learned_vpn_exit(address):
    """Whether this server's own Android phones show `address` to be a VPN
    exit (DESIGN.md 81): at least vpn_exit_min_phones of them came through a
    VPN from it within vpn_exit_window_days, and they are at least
    vpn_exit_min_share_percent of the phones seen from it then. A phone's own
    address -- a home line, a carrier's shared pool -- carries mostly direct
    traffic, even where an ad blocker uses Android's VPN interface."""
    since = _utc_now() - timedelta(days=_risk_setting_int("vpn_exit_window_days", 30))
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT COUNT(CASE WHEN last_via_vpn_at >= %s THEN 1 END),
                   COUNT(CASE WHEN last_via_vpn_at >= %s OR last_direct_at >= %s THEN 1 END)
            FROM vpn_exit_sightings
            WHERE address = %s
            """,
            (since, since, since, address),
        )
        row = cursor.fetchone()
    via_vpn, seen = (int(row[0] or 0), int(row[1] or 0)) if row else (0, 0)
    return (via_vpn >= max(1, _risk_setting_int("vpn_exit_min_phones", 3))
            and via_vpn * 100 >= seen * _risk_setting_int("vpn_exit_min_share_percent", 90))


def _source_network():
    """What the address this request came from is, as far as this server knows
    (DESIGN.md 81). None wherever it cannot know: outside a request, no list
    loaded, an IPv6 address against the IPv4 lists, learning switched off. The
    address itself is not kept here."""
    known = {"vpn_listed": None, "tor_exit": None, "hosting": None, "vpn_observed": None,
             "vpn_observed_non_hosting": None}
    if not has_request_context():
        return known
    try:
        address = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        return known
    if address.version == 4:
        lists = _network_list_ranges()
        for key, kind in (("vpn_listed", "vpn"), ("tor_exit", "tor"), ("hosting", "hosting")):
            if lists.get(kind) is not None:
                known[key] = _in_ranges(lists[kind], int(address))
    if _risk_setting_bool("vpn_exit_learning", False):
        known["vpn_observed"] = _learned_vpn_exit(str(address))
        if known["vpn_observed"] is False:
            known["vpn_observed_non_hosting"] = False
        elif known["hosting"] is not None:
            # Outside hosting networks only where that is known.
            known["vpn_observed_non_hosting"] = not known["hosting"]
    return known


def _record_vpn_sighting(cursor, device_id, network):
    """Learn from one Android scan (DESIGN.md 81): the address it came from,
    and whether the app's own traffic went through a VPN -- Android names the
    transports of the app's default network, so a VPN another app's traffic
    alone uses, or a split tunnel, counts as direct. iOS cannot say, so it is
    never a witness. Joins the report's unit of work."""
    if not has_request_context() or not isinstance(network, dict) or network.get("status") != "ok":
        return
    transports = network.get("transports")
    if not isinstance(transports, list) or not transports:
        return
    try:
        address = str(ipaddress.ip_address(request.remote_addr or ""))
    except ValueError:
        return
    when, counter = (("last_via_vpn_at", "scans_via_vpn") if "vpn" in transports
                     else ("last_direct_at", "scans_direct"))
    update = ("UPDATE vpn_exit_sightings SET " + when + " = %s, " + counter + " = "
              + counter + " + 1 WHERE address = %s AND device_id = %s")
    now = _utc_now()
    cursor.execute(update, (now, address, str(device_id)))
    if cursor.rowcount:
        return
    savepoint = DIALECT.savepoint("vpn_sighting")
    if savepoint:
        cursor.execute(savepoint[0])
    try:
        cursor.execute(
            "INSERT INTO vpn_exit_sightings (address, device_id, " + when + ", " + counter
            + ") VALUES (%s, %s, %s, 1)",
            (address, str(device_id), now),
        )
    except Exception as error:
        if not DIALECT.is_unique_violation(error):
            raise
        if savepoint:
            cursor.execute(savepoint[1])
        cursor.execute(update, (now, address, str(device_id)))
    else:
        if savepoint:
            cursor.execute(savepoint[2])


_SOURCE_NETWORK_RULES = (
    # (code, the source_network key, its points setting, message)
    ("source_vpn_listed", "vpn_listed", "source_vpn_listed_points",
     "The request came from an address on the public VPN list."),
    ("source_tor_exit", "tor_exit", "source_tor_exit_points",
     "The request came from a Tor exit."),
    ("source_hosting", "hosting", "source_hosting_points",
     "The request came from a hosting or data-centre network."),
    ("source_vpn_observed", "vpn_observed", "source_vpn_observed_points",
     "The request came from an address this server's Android phones show to be a VPN exit."),
    ("source_vpn_observed_non_hosting", "vpn_observed_non_hosting",
     "source_vpn_observed_non_hosting_points",
     "The request came from an address this server's Android phones show to be a VPN exit, "
     "outside hosting networks: a home or office VPN."),
)


def _source_network_reasons(reasons, source):
    """The source-network reasons, 0 points unless the DBA gives them points;
    each address is named once, by its most specific kind. Returns the points."""
    found = {key for key, value in source.items() if value}
    if "vpn_observed_non_hosting" in found:
        found.discard("vpn_observed")
    if found & {"vpn_listed", "vpn_observed", "vpn_observed_non_hosting"}:
        found.discard("hosting")
    total = 0
    for code, key, setting, message in _SOURCE_NETWORK_RULES:
        if key in found:
            points = _risk_setting_int(setting, 0)
            _policy_reason(reasons, code, points, message)
            total += points
    return total


def _evaluate_risk_policy(
    event_type,
    device_id,
    installation_id,
    account_id=None,
    account_link_pending=False,
    persist=True,
):
    """Calculate an opaque relationship-based risk decision.

    No device hardware attributes or PII are used. The decision is based on
    server-side relationships already established by the cryptographic device
    identity: recognition method, installation velocity, accounts per device,
    and devices per account.
    """
    device_id = str(device_id)
    installation_id = str(installation_id)
    account_id = str(account_id) if account_id is not None else None

    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT i.status,
                   i.registration_method,
                   i.registration_confidence,
                   i.created_at,
                   d.status,
                   d.platform,
                   d.created_at,
                   i.device_confirmed_at
            FROM app_installations i
            JOIN recognized_devices d ON d.device_id = i.device_id
            WHERE i.installation_id = %s AND i.device_id = %s
            """,
            (installation_id, device_id),
        )
        installation_row = cursor.fetchone()
        if installation_row is None:
            raise ApiProblem(
                "The policy engine could not find the installation.",
                401,
                "policy_installation_not_found",
            )

        (
            installation_status,
            registration_method,
            registration_confidence,
            installation_created_at,
            device_status,
            platform,
            device_created_at,
            device_confirmed_at,
        ) = installation_row

        cursor.execute(
            "SELECT COUNT(*) FROM device_account_links WHERE device_id = %s",
            (device_id,),
        )
        device_account_count = int(cursor.fetchone()[0])

        # Only installations that have proven their key count toward a device
        # (review F6): registration is public, so anyone holding a device's
        # reinstall hint could otherwise add rows to it and push it to the
        # reinstall block without ever holding a key. The calling installation
        # counts regardless. Links and integrity reports need a device token,
        # so they come from proven installations already.
        cursor.execute(
            """
            SELECT COUNT(*) FROM app_installations
            WHERE device_id = %s AND (verified_at IS NOT NULL OR installation_id = %s)
            """,
            (device_id, installation_id),
        )
        device_installation_count = int(cursor.fetchone()[0])

        reinstall_window_hours = _risk_setting_int(
            "reinstall_window_hours", POLICY_REINSTALL_WINDOW_HOURS
        )
        reinstall_cutoff = _utc_now() - timedelta(hours=reinstall_window_hours)
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM app_installations
            WHERE device_id = %s
              AND registration_method = 'reinstall_hint'
              AND created_at >= %s
              AND (verified_at IS NOT NULL OR installation_id = %s)
            """,
            (device_id, reinstall_cutoff, installation_id),
        )
        recent_reinstall_count = int(cursor.fetchone()[0])

        link_exists = False
        link_first_seen = None
        account_device_count = 0
        if account_id is not None:
            cursor.execute(
                """
                SELECT first_seen_at
                FROM device_account_links
                WHERE device_id = %s AND account_id = %s
                """,
                (device_id, account_id),
            )
            link_row = cursor.fetchone()
            link_exists = link_row is not None
            link_first_seen = link_row[0] if link_exists else None

            cursor.execute(
                """
                SELECT COUNT(DISTINCT device_id)
                FROM device_account_links
                WHERE account_id = %s
                """,
                (account_id,),
            )
            account_device_count = int(cursor.fetchone()[0])

        window_hours = _risk_setting_int("cross_check_window_hours", CROSS_CHECK_WINDOW_HOURS)
        window = timedelta(hours=window_hours)
        observed_at = _utc_now()
        # A phone new to the account (DESIGN.md 77): joining it now, or joined
        # within the window. One the account used before is never new to it.
        joined_at = None
        if account_id is not None and account_link_pending and not link_exists:
            joined_at = observed_at
        elif link_first_seen is not None and link_first_seen >= observed_at - window:
            joined_at = link_first_seen
        observations = _server_observation_counts(
            cursor, device_id, installation_id, account_id, observed_at, window, joined_at
        )

    add_link = bool(account_id is not None and account_link_pending and not link_exists)
    projected_device_account_count = device_account_count + (1 if add_link else 0)
    projected_account_device_count = account_device_count + (1 if add_link else 0)
    integrity_state = _latest_integrity_state(installation_id)
    device_integrity_memory = _device_integrity_memory(device_id, installation_id)

    reasons = []
    score = 0
    hard_block = False

    if installation_status != "active":
        _policy_reason(
            reasons,
            "installation_not_active",
            100,
            "The cryptographic installation is not active.",
        )
        hard_block = True

    if device_status != "active":
        _policy_reason(
            reasons,
            "device_not_active",
            100,
            "The recognized device has been administratively blocked.",
        )
        hard_block = True

    # A new phone, and a known phone's new installation: DBA settings since
    # migration 021 (DESIGN.md 79), at the values the code used before.
    device_age = _utc_now() - device_created_at
    new_device_hours = _risk_setting_int("new_device_hours", 24)
    new_device_points = _risk_setting_int("new_device_points", 10)
    reinstall_points = _risk_setting_int("known_device_new_installation_points", 15)
    if (
        registration_method == "new_device"
        and new_device_points > 0
        and device_age <= timedelta(hours=new_device_hours)
    ):
        _policy_reason(
            reasons,
            "new_device",
            new_device_points,
            "This recognized device was first seen less than %d hours ago." % new_device_hours,
        )
        score += new_device_points
    elif registration_method == "reinstall_hint" and reinstall_points > 0:
        _policy_reason(
            reasons,
            "known_device_new_installation",
            reinstall_points,
            "A new installation was correlated to a previously recognized device.",
        )
        score += reinstall_points

    # Accounts sharing one recognized physical device. DBA-tunable in
    # risk_policy_settings; the owner's defaults (DESIGN.md 54) treat a phone
    # shared by two people as legitimate -- elevated, never refused by itself --
    # hold a third account for review, and block a fourth.
    accounts_block = _risk_setting_int(
        "device_accounts_block_count", POLICY_DEVICE_ACCOUNT_BLOCK_COUNT
    )
    accounts_review = _risk_setting_int("device_accounts_review_count", 3)
    accounts_elevated = _risk_setting_int("device_accounts_elevated_count", 2)
    if accounts_block > 0 and projected_device_account_count >= accounts_block:
        _policy_reason(
            reasons,
            "device_account_count_block_threshold",
            100,
            "This device is linked to %d unique accounts; the configured policy "
            "blocks at %d." % (projected_device_account_count, accounts_block),
        )
        hard_block = True
    elif accounts_review > 0 and projected_device_account_count >= accounts_review:
        review_points = _risk_setting_int("device_accounts_review_points", 60)
        _policy_reason(
            reasons,
            "device_has_many_accounts",
            review_points,
            "This device is linked to %d unique accounts; the configured policy "
            "reviews at %d." % (projected_device_account_count, accounts_review),
        )
        score += review_points
    elif accounts_elevated > 0 and projected_device_account_count >= accounts_elevated:
        elevated_points = _risk_setting_int("device_accounts_elevated_points", 35)
        _policy_reason(
            reasons,
            "device_has_multiple_accounts",
            elevated_points,
            "This device is linked to %d unique accounts."
            % projected_device_account_count,
        )
        score += elevated_points

    # One account appearing on several recognized physical devices. DBA-tunable
    # (migration 012); the owner's defaults: a second device is elevated and
    # allowed, a third or more is held for review -- refused in enforce mode --
    # and a fifth is blocked. A business whose users legitimately carry more
    # devices raises the counts.
    if account_id is not None:
        points, blocked = _account_device_points(reasons, projected_account_device_count)
        score += points
        hard_block = hard_block or blocked

    # Reinstall velocity on one server-recognized device; DBA settings since
    # migration 021, 0 switching a step off.
    reinstall_block = _risk_setting_int("reinstall_block_count", POLICY_REINSTALL_BLOCK_COUNT)
    reinstall_high = _risk_setting_int("reinstall_high_count", 4)
    reinstall_elevated = _risk_setting_int("reinstall_elevated_count", 3)
    if reinstall_block > 0 and recent_reinstall_count >= reinstall_block:
        _policy_reason(
            reasons,
            "rapid_reinstall_block_threshold",
            100,
            "The device exceeded the configured reinstall count in the policy window.",
        )
        hard_block = True
    elif reinstall_high > 0 and recent_reinstall_count >= reinstall_high:
        points = _risk_setting_int("reinstall_high_points", 60)
        _policy_reason(
            reasons,
            "rapid_reinstall_high",
            points,
            "%d or more correlated reinstalls occurred inside the policy window."
            % reinstall_high,
        )
        score += points
    elif reinstall_elevated > 0 and recent_reinstall_count >= reinstall_elevated:
        points = _risk_setting_int("reinstall_elevated_points", 35)
        _policy_reason(
            reasons,
            "rapid_reinstall_elevated",
            points,
            "%d correlated reinstalls occurred inside the policy window." % reinstall_elevated,
        )
        score += points

    # Latest server-scored native integrity result. Missing/stale measurements
    # are themselves risk, while a fresh report contributes its server-owned score.
    if integrity_state is None:
        points = _risk_setting_int("integrity_report_missing_points", 40)
        _policy_reason(
            reasons,
            "integrity_report_missing",
            points,
            "No signed native integrity report exists for this installation.",
        )
        score += points
    elif not integrity_state.get("fresh"):
        points = _risk_setting_int("integrity_report_stale_points", 35)
        _policy_reason(
            reasons,
            "integrity_report_stale",
            points,
            "The latest native integrity report is older than the freshness window.",
        )
        score += points
    else:
        integrity_score = min(int(integrity_state.get("score", 0)), 100)
        if integrity_score > 0:
            _policy_reason(
                reasons,
                "native_integrity_risk",
                integrity_score,
                "The latest native integrity report contributed server-scored risk.",
            )
            score += integrity_score
        if integrity_state.get("verdict") == "block" or integrity_state.get("hard_block"):
            hard_block = True

    # Device-level integrity memory. A block recorded against another
    # installation on this same physical device stays relevant after a
    # reinstall, which is exactly the case the installation-scoped lookup above
    # cannot see.
    if device_integrity_memory is not None and (
        device_integrity_memory.get("finding_verdict") == "block"
    ):
        if device_integrity_memory.get("installation_id") != str(installation_id):
            points = _risk_setting_int("device_integrity_history_block_points", 50)
            _policy_reason(
                reasons,
                "device_integrity_history_block",
                points,
                "Another installation on this device was blocked by native "
                "integrity inside the device memory window.",
            )
            score += points

    # Server-side request-rate anomaly (DESIGN.md 51.6): opt-in, advisory, and
    # device-unfalsifiable. Only counts when the DBA has enabled it, so it costs
    # nothing on a default deployment.
    request_rate = {"state": "off"}
    if _risk_setting_bool("rate_anomaly_enabled", False):
        rate_limit = _risk_setting_int("rate_anomaly_max_requests", 120)
        rate_window = _risk_setting_int("rate_anomaly_window_seconds", 60)
        rate_count = _key_request_rate(installation_id, rate_window)
        if rate_count is None:
            # Degraded evidence, not a rate of zero (DESIGN.md 77). Listed at 0
            # points -- an outage must not restrict everyone -- and kept in the
            # context, so a decision made without the counter says so.
            request_rate = {"state": "unavailable", "window_seconds": rate_window}
            _policy_reason(
                reasons,
                "request_rate_unavailable",
                0,
                "The request-rate counter could not be read, so this decision was "
                "made without it.",
            )
        else:
            request_rate = {
                "state": "measured", "count": rate_count, "window_seconds": rate_window,
            }
        if rate_count is not None and rate_limit > 0 and rate_count > rate_limit:
            rate_points = _risk_setting_int("rate_anomaly_points", 30)
            _policy_reason(
                reasons,
                "request_rate_anomaly",
                rate_points,
                "This installation's request rate exceeds the configured anomaly "
                "threshold.",
            )
            score += rate_points

    # Population-baseline deviation (DESIGN.md 51.6, Option A: DBA-set absolute
    # threshold on a relationship metric). Advisory, opt-in; reuses counts already
    # computed above, so it adds no query and is portable across engines.
    if _risk_setting_bool("population_baseline_enabled", False):
        pop_metric = _risk_setting_str("population_baseline_metric", "accounts_per_device")
        pop_threshold = _risk_setting_int("population_baseline_threshold", 10)
        if pop_metric == "installations_per_device":
            pop_value = device_installation_count
        else:
            pop_metric = "accounts_per_device"
            pop_value = projected_device_account_count
        if pop_threshold > 0 and pop_value > pop_threshold:
            pop_points = _risk_setting_int("population_points", 30)
            _policy_reason(
                reasons,
                "population_outlier",
                pop_points,
                "This device's %s (%d) exceeds the configured population threshold "
                "(%d)." % (pop_metric, pop_value, pop_threshold),
            )
            score += pop_points

    # Where the request came from (DESIGN.md 81): measured into every
    # decision, 0 points unless the DBA gives a kind points.
    source_network = _source_network()
    score += _source_network_reasons(reasons, source_network)

    # The server's own observations (DESIGN.md 77), scored only where the DBA
    # has switched them on. A phone's rules count what that phone did. The
    # account's rule judges only a phone new to the account, by the failures
    # other phones sent before it joined -- so failures someone causes
    # on an account never restrict a phone that was there before them.
    cross_checks_scored = _risk_setting_bool("cross_checks_enabled", False)
    denial_hold = None
    if cross_checks_scored:
        for code, scope, key, default_count, default_points, message in _CROSS_CHECK_RULES:
            measured = observations.get(scope)
            if measured is None:
                continue
            threshold = _risk_setting_int(code + "_count", default_count)
            count = int(measured.get(key, 0))
            if threshold <= 0 or count < threshold:
                continue
            points = _risk_setting_int(code + "_points", default_points)
            message = message % (count, window_hours)
            if code == "device_approvals_denied" and _risk_setting_str(
                "device_approvals_denied_effect", "limit"
            ) == "limit":
                denial_hold = points
                message += " A denial alone holds the phone at review (limited) for that time."
            _policy_reason(reasons, code, points, message, count=count)
            score += points

    recommended_action = _policy_action(score, hard_block=hard_block)
    held_by_denial = False
    if denial_hold is not None:
        # Owner decision of 2026-10-14 (DESIGN.md 77): a phone the account's
        # other phone denied is held at review -- a limited session -- for
        # the window, even if its first cause clears, and a denial alone never
        # blocks it: its points could not promise either, being added to
        # whatever else the phone scores. Whatever blocks without the denial
        # still blocks. device_approvals_denied_effect = points turns this off.
        if _policy_action(score - denial_hold, hard_block=hard_block) != "block":
            recommended_action = "review"
            held_by_denial = True
    effective_action = (
        recommended_action if DEVICE_POLICY_MODE == "enforce" else "allow"
    )
    decision_id = str(uuid.uuid4())
    context = {
        "platform": platform,
        "registration_method": registration_method,
        "registration_confidence": registration_confidence,
        # Whether a block on this installation spreads to the rest of the
        # device (DESIGN.md 68): the original installation, or a hint-linked
        # one confirmed when a returning account signed in on it.
        "installation_established": (
            registration_method != "reinstall_hint" or device_confirmed_at is not None
        ),
        "installation_device_confirmed_at": (
            _iso_z(device_confirmed_at) if device_confirmed_at is not None else None
        ),
        "installation_created_at": _iso_z(installation_created_at),
        "installation_status": installation_status,
        "device_status": device_status,
        "device_created_at": _iso_z(device_created_at),
        "device_age_hours": round(device_age.total_seconds() / 3600.0, 2),
        "device_installation_count": device_installation_count,
        "device_account_count": device_account_count,
        "projected_device_account_count": projected_device_account_count,
        "account_device_count": account_device_count if account_id is not None else None,
        "projected_account_device_count": (
            projected_account_device_count if account_id is not None else None
        ),
        "account_already_linked_to_device": link_exists if account_id is not None else None,
        "recent_reinstall_count": recent_reinstall_count,
        "reinstall_window_hours": reinstall_window_hours,
        "integrity": integrity_state,
        "integrity_mode": INTEGRITY_MODE,
        "integrity_freshness_seconds": _integrity_freshness_seconds(),
        "device_integrity_memory": device_integrity_memory,
        "device_integrity_memory_hours": _risk_setting_int(
            "integrity_device_memory_hours", INTEGRITY_DEVICE_MEMORY_HOURS
        ),
        # Measured into every decision, scored or not (DESIGN.md 77).
        "server_observations": dict(
            observations, window_hours=window_hours, scored=cross_checks_scored
        ),
        "request_rate": request_rate,
        "held_by_denial": held_by_denial,
    }
    if has_request_context() and g.get("rate_limiter_unavailable"):
        context["rate_limiter"] = "unavailable"
    context["source_network"] = source_network
    if has_request_context():
        # Opt-in request metadata (DESIGN.md 80): personal data, so off unless
        # the DBA records it, and then kept as long as the decision is.
        if _risk_setting_bool("record_source_ip", False):
            context["source_ip"] = request.remote_addr
        if _risk_setting_bool("record_user_agent", False):
            context["user_agent"] = (request.headers.get("User-Agent") or "")[:256]
    if BUSINESS_API_TOKEN_SHA256:
        # Measurements only (DESIGN.md 76): the business decides what they mean.
        context["business_events_30d"] = _business_event_counts(device_id, account_id)
    decision = {
        "decision_id": decision_id,
        "event_type": event_type,
        "mode": DEVICE_POLICY_MODE,
        "score": int(score),
        "recommended_action": recommended_action,
        "effective_action": effective_action,
        "enforced": DEVICE_POLICY_MODE == "enforce" and recommended_action != "allow",
        "reasons": reasons,
        "context": context,
        "thresholds": _policy_bands(),
        "created_at": _iso_z(_utc_now()),
    }

    if persist:
        with _cursor(commit=True) as cursor:
            cursor.execute(
                """
                INSERT INTO risk_policy_decisions
                    (decision_id, event_type, account_id, device_id,
                     installation_id, policy_mode, recommended_action,
                     effective_action, score, reasons, context)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    decision_id,
                    event_type,
                    account_id,
                    device_id,
                    installation_id,
                    DEVICE_POLICY_MODE,
                    recommended_action,
                    effective_action,
                    int(score),
                    DIALECT.json_param(reasons),
                    DIALECT.json_param(context),
                ),
            )

    return decision


def _mark_decision_accepted(decision):
    """The stored decision row names the acceptance that let it pass, so the
    row alone explains why a request proceeded (review R1)."""
    decision_id = decision.get("decision_id")
    if not decision.get("acceptance_id") or not decision_id or decision_id == "not-persisted":
        return
    with _cursor(commit=True) as cursor:
        cursor.execute(
            "UPDATE risk_policy_decisions SET acceptance_id = %s WHERE decision_id = %s",
            (decision["acceptance_id"], decision_id),
        )


def _enforce_risk_policy(decision, limited_ok=False, accepted=None):
    """Refuse review and block; refuse elevated (step_up) only if a DBA opts in.

    By default an elevated decision is recorded and returned but does not
    refuse (owner decision, DESIGN.md 54): a phone legitimately shared by two
    people must keep working for both. Its points still count, so combined with
    other risk it escalates to review or block. Step-up itself is enforced where
    it has meaning -- the DBA-designated sensitive paths (_enforce_step_up).
    risk_policy_settings.elevated_risk_refuses = 1 restores a flat refusal.

    limited_ok (DESIGN.md 70): an outcome that would refuse and that the DBA
    lists in limited_session_policy_actions (owner default: step_up,review)
    returns its cause instead -- risk_step_up or risk_review -- and the caller
    issues a limited session. A block always refuses. Returns None otherwise.

    accepted (DESIGN.md 72): an outcome whose cause a full session's upgrade
    accepted passes, marked accepted_by_upgrade in the returned decision (the
    stored decision row is written before this and does not carry the mark).
    """
    action = decision.get("effective_action")
    if action == "allow":
        return None
    if action == "step_up" and not _risk_setting_bool("elevated_risk_refuses", False):
        return None
    if action in ("step_up", "review") and _accepted(accepted, "risk_%s" % action, policy=decision):
        decision["accepted_by_upgrade"] = True
        decision["acceptance_id"] = accepted.acceptance_id
        _mark_decision_accepted(decision)
        return None
    if (
        limited_ok
        and action in ("step_up", "review")
        and action in _risk_setting_words("limited_session_policy_actions", "step_up,review")
    ):
        return "risk_%s" % action

    if action == "step_up":
        code = "risk_step_up_required"
        message = "The current device/account risk requires additional verification."
    elif action == "review":
        code = "risk_review_required"
        message = "The current device/account risk requires review."
    else:
        code = "risk_policy_blocked"
        message = "The current device/account risk is blocked by policy."

    raise ApiProblem(
        message,
        403,
        code,
        details={"policy": decision},
    )


STEPUP_FACTORS = ("passcode", "biometric")
STEPUP_MODES = ("per_use", "windowed")
STEPUP_MAX_WINDOW_SECONDS = 3600
STEPUP_AUTH_NOT_REPORTED = {"factor": None, "mode": None, "window_seconds": None}


def _parse_stepup_key_auth(body):
    """Read the stepup_key_auth block that must accompany a step-up key.

    It states how the key was created: the device factor that unlocks it, and
    whether every signature needs a fresh authentication (per_use) or one
    authentication covers a hardware-enforced window (windowed). Like
    key_security it is a client claim the server cannot re-verify without key
    attestation (51.2), so it is recorded and compared with policy, never
    treated as proof. It is required with the key (DESIGN.md 63): a key whose
    factor was never stated can never be shown to satisfy the policy's factor,
    and step-up now checks the stored factor as well as the proof's.
    """
    block = body.get("stepup_key_auth")
    if not isinstance(block, dict):
        raise ApiProblem(
            "stepup_key_auth is required with a step-up key and must be an object.",
            400,
            "invalid_stepup_key_auth",
        )
    factor = block.get("factor")
    mode = block.get("mode")
    window = block.get("window_seconds")
    if factor not in STEPUP_FACTORS:
        raise ApiProblem(
            "stepup_key_auth.factor must be passcode or biometric.",
            400,
            "invalid_stepup_key_auth",
        )
    if mode not in STEPUP_MODES:
        raise ApiProblem(
            "stepup_key_auth.mode must be per_use or windowed.",
            400,
            "invalid_stepup_key_auth",
        )
    if isinstance(window, bool) or not isinstance(window, int):
        raise ApiProblem(
            "stepup_key_auth.window_seconds must be an integer.",
            400,
            "invalid_stepup_key_auth",
        )
    if mode == "per_use" and window != 0:
        raise ApiProblem(
            "A per_use step-up key has window_seconds 0.",
            400,
            "invalid_stepup_key_auth",
        )
    if mode == "windowed" and not 1 <= window <= STEPUP_MAX_WINDOW_SECONDS:
        raise ApiProblem(
            "A windowed step-up key needs window_seconds between 1 and %d."
            % STEPUP_MAX_WINDOW_SECONDS,
            400,
            "invalid_stepup_key_auth",
        )
    return {"factor": factor, "mode": mode, "window_seconds": window}


def _stepup_policy_downgrade(key_auth):
    """Whether a step-up key is weaker than the deployment's declared mode.

    Under a per_use policy any windowed key is a downgrade; under windowed(N) a
    window longer than N is. None when the client did not report, which is not
    evidence either way. A downgrade is accepted, recorded and surfaced rather
    than refused: Android 9/10 cannot bind a passcode to each signature, and
    refusing those keys would lock legitimate users out of sensitive
    operations (DESIGN.md 53).
    """
    if not key_auth or key_auth.get("mode") is None:
        return None
    if key_auth["mode"] == "per_use":
        return False
    if _risk_setting_str("stepup_mode", "per_use") == "per_use":
        return True
    return (key_auth.get("window_seconds") or 0) > _risk_setting_int(
        "stepup_window_seconds", 0
    )


def _stepup_required_paths():
    raw = _risk_setting_str("stepup_required_paths", "")
    return {p.strip() for p in raw.replace(";", ",").split(",") if p.strip()}


def _app_pin_required_paths():
    raw = _risk_setting_str("app_pin_required_paths", "")
    return {p.strip() for p in raw.replace(";", ",").split(",") if p.strip()}


# The owner's default step-up method (DESIGN.md 78, owner decision of
# 2026-10-14): the app PIN the server checks. A DBA chooses another per
# deployment; this only answers a missing row.
STEPUP_METHOD_DEFAULT = "app_pin"

# Where a PIN is set or replaced (DESIGN.md 78). The PIN is never required
# there: a locked or forgotten PIN could otherwise never be replaced. Nor is
# the screen-lock key required where it is re-enrolled: a dead key could
# otherwise never be replaced (DESIGN.md 58).
_APP_PIN_PATH = "/v1/account/app-pin"
_STEPUP_KEY_PATH = "/v1/installations/stepup-key"


def _stepup_factors():
    """(the screen-lock key, the app PIN): which factors a step-up needs under
    the DBA's stepup_method, wherever one is required (DESIGN.md 78)."""
    method = _risk_setting_str("stepup_method", STEPUP_METHOD_DEFAULT)
    return method != "app_pin", method != "screen_lock"


def _prove_step_up(installation_id, account_id, need_key, need_pin, required=None):
    """Verify the step-up factors this request carries or must carry: the
    screen-lock key's proof v2, the app PIN, or both (DESIGN.md 78). A missing
    PIN is named before anything is checked, so asking for it costs no attempt,
    and the key is checked before the PIN, so a bad proof never spends one; a
    refusal for a missing factor names the factors required (`required`, by
    default both flags). Returns the key's auth when the key was proven."""
    needs = required if required is not None else [
        name for name, needed in (("screen_lock", need_key), ("app_pin", need_pin)) if needed
    ]
    details = {"step_up": {"method": _risk_setting_str("stepup_method", STEPUP_METHOD_DEFAULT),
                           "needs": needs}}
    if need_pin and not request.headers.get("X-App-PIN"):
        raise ApiProblem("This operation needs the app PIN.", 403, "app_pin_required",
                         details=details)
    key_auth = None
    if need_key:
        try:
            key_auth = _verify_step_up(installation_id, account_id)
        except ApiProblem as problem:
            if problem.code == "stepup_required" and problem.details is None:
                problem.details = details
            raise
    if need_pin:
        _verify_app_pin(account_id, get_jwt().get("did"), installation_id)
    return key_auth


def _enforce_step_up(installation_id, account_id):
    """Verify the step-up a request must carry, or offers; return it.

    Required on the DBA-designated paths, none by default: stepup_required_paths,
    proven as stepup_method says -- the screen-lock key, the app PIN the server
    checks, or both -- and app_pin_required_paths, which need the app PIN on top
    (DESIGN.md 78). On any other authenticated account request a client may
    attach a factor anyway, to satisfy an elevated integrity verdict (DESIGN.md
    63): it is verified exactly as on a required path, and an invalid one
    refuses the request rather than being ignored. Returns g.step_up only when
    every factor the method names was proven, else None. Every decision is
    logged with its outcome code -- never the PIN.
    """
    key_method, pin_method = _stepup_factors()
    required = request.path in _stepup_required_paths()
    key_required = required and key_method and request.path != _STEPUP_KEY_PATH
    pin_required = request.path != _APP_PIN_PATH and (
        (required and pin_method) or request.path in _app_pin_required_paths()
    )
    need_key = key_required or bool(
        request.headers.get("X-Step-Up-Proof") or request.headers.get("X-Step-Up-Signature")
    )
    need_pin = pin_required or (
        request.path != _APP_PIN_PATH and bool(request.headers.get("X-App-PIN"))
    )
    if not need_key and not need_pin:
        return None
    try:
        key_auth = _prove_step_up(
            installation_id, account_id, need_key, need_pin,
            required=[name for name, needed in (("screen_lock", key_required),
                                                ("app_pin", pin_required)) if needed],
        )
    except ApiProblem as problem:
        logger.info(
            "Step-up refused: installation=%s path=%s code=%s",
            installation_id,
            request.path,
            problem.code,
        )
        raise
    if (key_method and not need_key) or (pin_method and not need_pin):
        # What was offered verified, but the method asks for more: no step-up.
        return None
    downgrade = _stepup_policy_downgrade(key_auth) if key_auth is not None else None
    g.step_up = {
        "key_auth": key_auth,
        "policy_downgrade": downgrade,
        "app_pin": need_pin,
        "method": _risk_setting_str("stepup_method", STEPUP_METHOD_DEFAULT),
    }
    logger.info(
        "Step-up verified: installation=%s path=%s method=%s factor=%s key_mode=%s "
        "window_seconds=%s policy_downgrade=%s app_pin=%s",
        installation_id,
        request.path,
        g.step_up["method"],
        (key_auth or {}).get("factor"),
        (key_auth or {}).get("mode"),
        (key_auth or {}).get("window_seconds"),
        downgrade,
        need_pin,
    )
    return g.step_up


def _app_pin_well_formed(pin):
    length = _risk_setting_int("app_pin_length", 6)
    return isinstance(pin, str) and len(pin) == length and pin.isascii() and pin.isdigit()


def _app_pin_material(account_id, pin):
    """What bcrypt hashes for an app PIN: an HMAC of the account and the PIN,
    keyed by a secret the database never holds (DESIGN.md 78)."""
    return hmac.new(
        _APP_PIN_PEPPER, ("%s:%s" % (account_id, pin)).encode("utf-8"), hashlib.sha256
    ).hexdigest().encode("ascii")


def _verify_app_pin(account_id, device_id, installation_id):
    """Check the app PIN this request carries (X-App-PIN), counting the attempt
    first (DESIGN.md 78).

    One atomic UPDATE claims the attempt before anything is compared, so
    concurrent guesses never exceed app_pin_max_failures, and bcrypt runs
    outside any unit of work (on SQL Server a unit holds the worker's lock). A
    right PIN clears the count; the last wrong one locks the PIN until the user
    sets a new one with the account password. Each wrong PIN is the server's
    own observation (app_pin_failed), for this account on this phone.
    """
    account_id = str(account_id)
    pin = request.headers.get("X-App-PIN", "")
    max_failures = max(1, _risk_setting_int("app_pin_max_failures", 5))
    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            UPDATE app_pins SET failures = failures + 1
            WHERE account_id = %s AND locked_at IS NULL AND failures < %s
              AND pin_hash IS NOT NULL
            """,
            (account_id, max_failures),
        )
        claimed = cursor.rowcount == 1
        cursor.execute(
            "SELECT pin_hash, failures, locked_at FROM app_pins WHERE account_id = %s",
            (account_id,),
        )
        row = cursor.fetchone()
    if row is None or row[0] is None:
        raise ApiProblem(
            "No app PIN is set for this account; set one first.", 403, "app_pin_not_set"
        )
    locked_message = (
        "The app PIN is locked after too many wrong attempts; set a new one with the "
        "account password."
    )
    if not claimed:
        if row[2] is None:  # the count reached a maximum the DBA has since lowered
            with _cursor(commit=True) as cursor:
                cursor.execute(
                    "UPDATE app_pins SET locked_at = NOW() "
                    "WHERE account_id = %s AND locked_at IS NULL",
                    (account_id,),
                )
        raise ApiProblem(locked_message, 403, "app_pin_locked")
    if _app_pin_well_formed(pin) and bcrypt.checkpw(
        _app_pin_material(account_id, pin), _bcrypt_db_bytes(row[0])
    ):
        with _cursor(commit=True) as cursor:
            cursor.execute(
                "UPDATE app_pins SET failures = 0 WHERE account_id = %s", (account_id,)
            )
        g.app_pin_verified = True
        return
    failures = int(row[1])
    locked = failures >= max_failures
    if locked:
        with _cursor(commit=True) as cursor:
            cursor.execute(
                "UPDATE app_pins SET locked_at = NOW() "
                "WHERE account_id = %s AND locked_at IS NULL",
                (account_id,),
            )
    _record_observation(
        "app_pin_failed",
        "app_pin_locked" if locked else "app_pin_invalid",
        device_id,
        installation_id,
        account_id=account_id,
    )
    if locked:
        raise ApiProblem(locked_message, 403, "app_pin_locked")
    raise ApiProblem(
        "The app PIN is wrong.",
        403,
        "app_pin_invalid",
        details={"attempts_left": max_failures - failures},
    )


def _stepup_policy_public():
    """The step-up policy as the DBA chose it, for the app to follow (DESIGN.md
    79): the method; the factor, mode and window a screen-lock key must be
    created with; the app PIN's length; and the paths that need each."""
    mode = _risk_setting_str("stepup_mode", "per_use")
    return {
        "method": _risk_setting_str("stepup_method", STEPUP_METHOD_DEFAULT),
        "factor": _risk_setting_str("stepup_factor", "passcode"),
        "mode": mode,
        "window_seconds": (_risk_setting_int("stepup_window_seconds", 0)
                           if mode == "windowed" else 0),
        "app_pin_length": _risk_setting_int("app_pin_length", 6),
        "required_paths": sorted(_stepup_required_paths()),
        "app_pin_required_paths": sorted(_app_pin_required_paths()),
    }


def _app_pin_state(account_id):
    """The step-up policy, and this account's app PIN: whether it is set,
    whether it is locked, whether support has opened a reset (DESIGN.md 78,
    79)."""
    with _cursor() as cursor:
        cursor.execute(
            "SELECT pin_hash, locked_at, reset_until FROM app_pins WHERE account_id = %s",
            (str(account_id),),
        )
        row = cursor.fetchone()
    state = _stepup_policy_public()
    state.update({
        "app_pin_set": bool(row is not None and row[0] is not None),
        "app_pin_locked": bool(row is not None and row[1] is not None),
        "app_pin_reset_open": bool(row is not None and row[2] is not None
                                   and row[2] > _utc_now()),
    })
    return state


def _support_reset_open(account_id):
    """Support opened a reset for this account, and it has not lapsed."""
    with _cursor() as cursor:
        cursor.execute(
            "SELECT reset_until FROM app_pins WHERE account_id = %s", (str(account_id),)
        )
        row = cursor.fetchone()
    return row is not None and row[0] is not None and row[0] > _utc_now()


# Step-up refusals that are not a failed proof (DESIGN.md 77): a request sent
# without one is the ordinary first leg (the app then asks for the screen
# lock), and a key that is missing, another account's or the installation key
# is this installation's state, not an attempt.
_STEPUP_NOT_ATTEMPTS = frozenset((
    "stepup_required",
    "stepup_key_not_registered",
    "stepup_key_other_account",
    "stepup_key_not_independent",
))


def _verify_step_up(installation_id, account_id):
    """_check_step_up, with every proof that did not verify recorded as the
    server's own observation against this phone -- whichever caller asked:
    a sensitive path, the same-device upgrade route, or an approver."""
    try:
        return _check_step_up(installation_id, account_id)
    except ApiProblem as problem:
        if problem.code not in _STEPUP_NOT_ATTEMPTS:
            _record_observation(
                "stepup_failed",
                problem.code,
                get_jwt().get("did"),
                installation_id,
                account_id=account_id,
            )
        raise


def _check_step_up(installation_id, account_id):
    """Verify the step-up proof on a sensitive path; return the key's auth.

    Proof v2 (DESIGN.md 63) is a step-up-key signature over the complete
    request it approves:

        {"version": 2, "purpose": "stepup", "installation_id", "factor",
         "access_token_sha256", "method", "path", "query", "body_sha256",
         "nonce", "timestamp"}

    and every request field is compared with THIS request. Proof v1 signed only
    the installation, factor, nonce and timestamp, so whoever held the
    installation signer could attach a fresh approval to a different body under
    a re-signed access proof carrying the same nonce (review F1). The nonce is
    the access proof's, which is claimed once, so one approval authorises one
    request; the token hash ties it to this session and therefore this account.

    The factor must equal the deployment policy AND the factor the key was
    registered with. Per-use vs windowed is the client's hardware auth cadence,
    reported at enrolment and not proven here (51.2); a windowed key under a
    per_use policy is accepted and reported as a downgrade (owner decision, 53).
    """
    with _cursor() as cursor:
        cursor.execute(
            "SELECT stepup_public_key_jwk, stepup_key_algorithm, "
            "stepup_key_factor, stepup_key_mode, stepup_key_window_seconds, "
            "stepup_key_account_id, key_thumbprint "
            "FROM app_installations WHERE installation_id = %s",
            (installation_id,),
        )
        row = cursor.fetchone()
    stepup_jwk = DIALECT.json_value(row[0]) if row and row[0] is not None else None
    stepup_alg = row[1] if row else None
    if not stepup_jwk:
        raise ApiProblem(
            "This operation requires step-up verification, but no step-up key is "
            "registered for this installation.",
            403,
            "stepup_key_not_registered",
        )
    # A key re-enrolled later belongs to the account that re-enrolled it
    # (DESIGN.md 58); only a key bound at registration (NULL) serves them all.
    if row[5] is not None and str(row[5]) != str(account_id):
        raise ApiProblem(
            "This installation's step-up key was re-enrolled by another account; "
            "re-enrol it with your own password.",
            403,
            "stepup_key_other_account",
        )
    # A step-up key that is the installation key adds nothing: whatever can
    # sign access proofs could sign approvals. Registration and re-enrolment
    # refuse it; this covers rows written before they did.
    if _parse_public_key(stepup_jwk)["thumbprint"] == row[6]:
        raise ApiProblem(
            "The step-up key is the installation key; re-enrol a separate key.",
            403,
            "stepup_key_not_independent",
        )
    proof_b64 = request.headers.get("X-Step-Up-Proof")
    signature_b64 = request.headers.get("X-Step-Up-Signature")
    if not proof_b64 or not signature_b64:
        raise ApiProblem(
            "This operation requires step-up verification.", 403, "stepup_required"
        )
    proof_bytes = _b64url_decode(proof_b64, "stepup_proof", 8192)
    signature_bytes = _b64url_decode(signature_b64, "stepup_signature", 1024)
    try:
        _verify_installation_signature(stepup_alg, stepup_jwk, proof_bytes, signature_bytes)
    except ApiProblem:
        raise ApiProblem(
            "The step-up signature did not verify.", 403, "stepup_signature_invalid"
        )
    try:
        proof = json.loads(proof_bytes.decode("utf-8"))
    except Exception:
        raise ApiProblem("The step-up proof is not valid JSON.", 400, "stepup_proof_invalid")
    if (
        not isinstance(proof, dict)
        or proof.get("version") != 2
        or proof.get("purpose") != "stepup"
    ):
        raise ApiProblem(
            "Only step-up proof version 2 with purpose \"stepup\" is accepted.",
            403,
            "stepup_proof_version_unsupported",
        )
    if proof.get("installation_id") != installation_id:
        raise ApiProblem(
            "The step-up proof installation does not match.",
            403,
            "stepup_installation_mismatch",
        )
    try:
        access_nonce = json.loads(
            _b64url_decode(request.headers.get("X-Access-Proof"), "access_proof", 8192).decode("utf-8")
        ).get("nonce")
    except Exception:
        access_nonce = None
    this_request = (
        ("nonce", access_nonce),
        ("access_token_sha256", hashlib.sha256(
            _bearer_token_from_request().encode("utf-8")).hexdigest()),
        ("method", request.method.upper()),
        ("path", request.path),
        ("query", request.query_string.decode("latin-1")),
        ("body_sha256", hashlib.sha256(request.get_data(cache=True) or b"").hexdigest()),
    )
    for field, expected in this_request:
        claimed = proof.get(field)
        if (
            not isinstance(expected, str)
            or not isinstance(claimed, str)
            or not hmac.compare_digest(claimed.encode("utf-8"), expected.encode("utf-8"))
        ):
            raise ApiProblem(
                "The step-up proof does not approve this request (%s differs)." % field,
                403,
                "stepup_binding_mismatch",
                details={"field": field},
            )
    required_factor = _risk_setting_str("stepup_factor", "passcode")
    if proof.get("factor") != required_factor or row[2] != required_factor:
        raise ApiProblem(
            "The step-up factor (claimed in the proof, or registered with the key) "
            "does not match the deployment policy.",
            403,
            "stepup_factor_mismatch",
        )
    timestamp = proof.get("timestamp")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ApiProblem(
            "The step-up proof timestamp is invalid.", 403, "stepup_timestamp_invalid"
        )
    if abs(int(_utc_now().timestamp()) - timestamp) > ACCESS_PROOF_MAX_SKEW_SECONDS:
        raise ApiProblem(
            "The step-up proof timestamp is outside the allowed window.",
            403,
            "stepup_timestamp_outside_window",
        )
    return {"factor": row[2], "mode": row[3], "window_seconds": row[4]}


def _require_trusted_account_request(event_type="protected_request"):
    """One server-owned gate for a customer's normal authenticated APIs.

    Order matters: first prove possession of the installation key for this exact
    HTTP request, then require a fresh integrity report, then calculate the
    server-side device/account policy and enforce its effective action.
    """
    claims = _require_access_proof("account")
    accepted = _session_acceptance(claims, event_type)
    step_up = _enforce_step_up(claims.get("iid"), get_jwt_identity())
    integrity = _enforce_integrity_gate(
        claims.get("did"),
        claims.get("iid"),
        step_up=step_up,
        step_up_accepted=True,
        accepted=accepted,
    )
    policy = _evaluate_risk_policy(
        event_type,
        claims.get("did"),
        claims.get("iid"),
        account_id=str(get_jwt_identity()),
        account_link_pending=False,
        persist=True,
    )
    _enforce_risk_policy(policy, accepted=accepted)
    return claims, policy, integrity


# An upgrade accepts what was approved, reason by reason (review R1, DESIGN.md
# 76). Relationship reasons whose points follow a count are covered up to the
# counts seen at approval; every other reason by its code, up to its points.
_DEVICE_COUNT_REASONS = ("device_has_multiple_accounts", "device_has_many_accounts")
_ACCOUNT_COUNT_REASONS = ("account_has_multiple_devices", "account_has_many_devices")


def _reason_entries(reasons, source):
    """The reasons of one source that carry points, in the stored form."""
    entries = []
    for reason in _as_list(reasons):
        if not isinstance(reason, dict) or not reason.get("code"):
            continue
        points = reason.get("points", 0)
        points = points if isinstance(points, int) and not isinstance(points, bool) else 0
        if points > 0:
            entry = {"code": str(reason["code"]), "points": points, "source": source,
                     "message": str(reason.get("message", ""))[:240]}
            count = reason.get("count")
            if isinstance(count, int) and not isinstance(count, bool):
                entry["count"] = count
            entries.append(entry)
    return entries


def _cause_reasons(cause, integrity=None, policy=None):
    """The reasons behind one limited cause, now."""
    if cause.startswith("integrity_"):
        return _reason_entries((integrity or {}).get("reasons"), "integrity")
    if cause.startswith("risk_"):
        return _reason_entries((policy or {}).get("reasons"), "relationship")
    return []


def _acceptance_snapshot(causes, integrity, policy):
    """What an upgrade over these causes may accept: their reasons now --
    collection problems excepted, which only a complete scan clears -- and the
    relationship counts seen now. An integrity cause made of collection
    problems alone cannot be approved at all: 403 complete_scan_required."""
    reasons = []
    for cause in causes:
        found = _cause_reasons(cause, integrity, policy)
        kept = [r for r in found if not _is_quality_reason(r)]
        if cause.startswith("integrity_") and found and not kept:
            raise ApiProblem(
                "The integrity scan could not measure everything requested; that cannot "
                "be approved. Send a complete scan; the session then upgrades by itself.",
                403,
                "complete_scan_required",
                details={"limited_causes": list(causes)},
            )
        reasons.extend(kept)
    context = (policy or {}).get("context") or {}
    return reasons, context.get("device_account_count"), context.get("account_device_count")


def _acceptance_covers(record, cause, integrity=None, policy=None, ignore_quality=False):
    """(covered, uncovered reasons) for one limited cause under an acceptance.

    Covered means: the acceptance is current and unrevoked, it accepted this
    cause, and every reason behind the cause now was approved -- the same code
    with no more points, or for the two count-following relationship reasons
    no more accounts on the phone or devices on the account than at approval.
    The DBA's acceptance_auto_cover_reasons are covered as well (a business
    decision). Collection problems never are.
    """
    current = _cause_reasons(cause, integrity, policy)
    if (
        record is None
        or record["revoked_at"] is not None
        or record["expires_at"] <= _utc_now()
        or cause not in record["causes"]
    ):
        return False, current
    approved = {(r.get("source"), r.get("code")): r.get("points", 0) for r in record["reasons"]}
    approved_counts = {(r.get("source"), r.get("code")): _as_int(r.get("count"))
                       for r in record["reasons"] if r.get("count") is not None}
    auto = _risk_setting_words("acceptance_auto_cover_reasons", "")
    context = (policy or {}).get("context") or {}
    uncovered = []
    for reason in current:
        code, points = reason["code"], reason["points"]
        if _is_quality_reason(reason):
            if not ignore_quality:
                uncovered.append(reason)
        elif code in auto:
            continue
        elif reason["source"] == "relationship" and code in _DEVICE_COUNT_REASONS:
            if record["device_accounts"] is None or _as_int(
                    context.get("device_account_count")) > record["device_accounts"]:
                uncovered.append(reason)
        elif reason["source"] == "relationship" and code in _ACCOUNT_COUNT_REASONS:
            if record["account_devices"] is None or _as_int(
                    context.get("account_device_count")) > record["account_devices"]:
                uncovered.append(reason)
        elif approved.get((reason["source"], code), -1) < points:
            uncovered.append(reason)
        elif "count" in reason and (
                approved_counts.get((reason["source"], code)) is None
                or reason["count"] > approved_counts[(reason["source"], code)]):
            # A count-following reason (DESIGN.md 77): covered up to the count
            # the approver saw, never beyond it.
            uncovered.append(reason)
    return not uncovered, uncovered


def _load_acceptance(acceptance_id, family_id, account_id, installation_id):
    """The acceptance record, if it belongs to this family, account and phone."""
    if not isinstance(acceptance_id, str) or not acceptance_id:
        return None
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT acceptance_id, family_id, account_id, installation_id, causes,
                   reasons, device_accounts, account_devices, expires_at, revoked_at
            FROM session_acceptances
            WHERE acceptance_id = %s
            """,
            (acceptance_id,),
        )
        row = cursor.fetchone()
    if row is None or (str(row[1]), str(row[2]), str(row[3])) != (
        str(family_id), str(account_id), str(installation_id)
    ):
        return None
    return {
        "acceptance_id": str(row[0]),
        "family_id": str(row[1]),
        "account_id": str(row[2]),
        "installation_id": str(row[3]),
        "causes": [c for c in (row[4] or "").split(",") if c],
        "reasons": [r for r in _as_list(DIALECT.json_value(row[5])) if isinstance(r, dict)],
        "device_accounts": row[6],
        "account_devices": row[7],
        "expires_at": row[8],
        "revoked_at": row[9],
    }


# An approval granted before migration 016 recorded only its categories. Its
# carried-over record has an ID derived from its refresh family, so the first
# uses of it -- concurrent or not -- all land on one record.
_LEGACY_ACCEPTANCE_NAMESPACE = uuid.UUID("6f1f0d3e-2b7a-5c41-9a8e-3d4c5b6a7f80")


def _carry_legacy_acceptance(family_id, account_id, device_id, installation_id, causes, until,
                             integrity=None, policy=None):
    """The record for an approval granted before migration 016 (DESIGN.md 76).

    With legacy_acceptances = carry (owner default) the first use records what
    the approval covers at that moment -- the reasons behind its causes now,
    collection problems excepted, which are never approved -- and the counts
    seen now, until the approval's own expiry. Its users do nothing; from then
    on a new reason needs a new decision. With drop, an approval not yet
    carried over covers nothing. A record carried over earlier stays.
    """
    if not isinstance(family_id, str) or not family_id or not causes or until is None:
        return None
    acceptance_id = str(uuid.uuid5(_LEGACY_ACCEPTANCE_NAMESPACE, family_id))
    record = _load_acceptance(acceptance_id, family_id, account_id, installation_id)
    if record is not None or _risk_setting_str("legacy_acceptances", "carry") != "carry":
        return record
    if until <= _utc_now():
        return None
    if integrity is None:
        integrity = _latest_integrity_state(installation_id)
    if policy is None:
        policy = _evaluate_risk_policy(
            "acceptance_carry",
            device_id,
            installation_id,
            account_id=account_id,
            account_link_pending=False,
            persist=False,
        )
    reasons = []
    for cause in causes:
        reasons += [r for r in _cause_reasons(cause, integrity, policy) if not _is_quality_reason(r)]
    context = (policy or {}).get("context") or {}
    with _cursor(commit=True) as cursor:
        savepoint = DIALECT.savepoint("legacy_acceptance")
        if savepoint:
            cursor.execute(savepoint[0])
        try:
            cursor.execute(
                """
                INSERT INTO session_acceptances
                    (acceptance_id, family_id, account_id, device_id, installation_id, route,
                     causes, reasons, device_accounts, account_devices, evidence_quality,
                     integrity_report_id, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (acceptance_id, family_id, account_id, device_id, installation_id, "legacy",
                 ",".join(sorted(set(causes))), DIALECT.json_param(reasons),
                 context.get("device_account_count"), context.get("account_device_count"),
                 (integrity or {}).get("evidence_quality"), (integrity or {}).get("report_id"),
                 until),
            )
        except Exception as error:
            if not DIALECT.is_unique_violation(error):
                raise
            if savepoint:
                cursor.execute(savepoint[1])
        else:
            if savepoint:
                cursor.execute(savepoint[2])
    logger.info("Carried over a pre-016 approval: family=%s causes=%s", family_id, ",".join(causes))
    return _load_acceptance(acceptance_id, family_id, account_id, installation_id)


def _record_lapses(record, uncovered, event_type):
    """Write down, once per reason, that an approved session met a reason its
    approval did not cover (DESIGN.md 76). This is the measurement the
    business reads -- when an approved session was limited again, and by what
    -- to decide which reasons, if any, to cover automatically."""
    if record is None or not uncovered:
        return
    with _cursor(commit=True) as cursor:
        for reason in uncovered:
            cursor.execute(
                """
                SELECT 1 FROM acceptance_lapses
                WHERE acceptance_id = %s AND reason_code = %s
                """,
                (record["acceptance_id"], reason["code"][:96]),
            )
            if cursor.fetchone() is not None:
                continue
            savepoint = DIALECT.savepoint("lapse_insert")
            if savepoint:
                cursor.execute(savepoint[0])
            try:
                cursor.execute(
                    """
                    INSERT INTO acceptance_lapses
                        (acceptance_id, reason_code, source, points, account_id,
                         installation_id, event_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (record["acceptance_id"], reason["code"][:96], reason["source"],
                     int(reason["points"]), record["account_id"],
                     record["installation_id"], event_type[:32]),
                )
            except Exception as error:
                if not DIALECT.is_unique_violation(error):
                    raise
                if savepoint:
                    cursor.execute(savepoint[1])
            else:
                if savepoint:
                    cursor.execute(savepoint[2])


class _Acceptance(object):
    """A full session's acceptance, judged reason by reason on each use."""

    def __init__(self, record, event_type):
        self.record = record
        self.event_type = event_type

    def covers(self, cause, integrity=None, policy=None):
        covered, uncovered = _acceptance_covers(self.record, cause, integrity, policy)
        if not covered:
            _record_lapses(self.record, uncovered, self.event_type)
        return covered

    @property
    def acceptance_id(self):
        return self.record["acceptance_id"] if self.record else None


def _accepted(accepted, cause, integrity=None, policy=None):
    if isinstance(accepted, _Acceptance):
        return accepted.covers(cause, integrity, policy)
    return False


def _session_acceptance(claims, event_type="protected_request"):
    """This full session's acceptance, while its time runs. A session whose
    upgrade predates migration 016 carries causes but no record: it is carried
    over at this first use, or covers nothing, as the DBA's legacy_acceptances
    says."""
    until = claims.get("accepted_until")
    if (
        claims.get("scope") != "full"
        or isinstance(until, bool)
        or not isinstance(until, int)
        or until <= int(_utc_now().timestamp())
    ):
        return _Acceptance(None, event_type)
    account_id = str(get_jwt_identity())
    if isinstance(claims.get("acc"), str):
        record = _load_acceptance(claims["acc"], claims.get("family"), account_id, claims.get("iid"))
    else:
        record = _carry_legacy_acceptance(
            claims.get("family"), account_id, claims.get("did"), claims.get("iid"),
            [c for c in claims.get("accepted") or [] if isinstance(c, str)],
            datetime.fromtimestamp(until, timezone.utc),
        )
    return _Acceptance(record, event_type)


# ---------------------------------------------------------------------------
# Challenge and token helpers
# ---------------------------------------------------------------------------


# Installation challenges are stateless until they are used (DESIGN.md 66.2,
# joint review R5). The server MACs the payload it issues with a key derived
# from the root secret, and stores nothing at issue time; a challenge is written
# down only when it is consumed -- MAC intact, unexpired, signed by the
# installation key -- and the primary key on that record is the replay defence.
# Issuing used to store each challenge under a five-per-installation cap, and
# the public endpoint needs only an installation ID: a flood first refused the
# real client a challenge, then, once the oldest was dropped instead, cancelled
# the one the real client was about to sign. With nothing stored, a flood has
# nothing to fill or displace. Clients pass the payload through untouched.


def _challenge_mac(fields):
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(hmac.new(_CHALLENGE_MAC_KEY, canonical, hashlib.sha256).digest())


def _create_challenge(installation_id, purpose):
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT i.status, d.status
            FROM app_installations i
            JOIN recognized_devices d ON d.device_id = i.device_id
            WHERE i.installation_id = %s
            """,
            (installation_id,),
        )
        row = cursor.fetchone()
    if row is None:
        raise ApiProblem(
            "The installation is not registered.", 404, "installation_not_found"
        )
    if row[0] != "active":
        raise ApiProblem(
            "The installation is not active.", 403, "installation_inactive"
        )
    if row[1] != "active":
        raise ApiProblem(
            "The recognized device is not active.", 403, "device_inactive"
        )

    expires_at = _utc_now() + CHALLENGE_LIFETIME
    fields = {
        "challenge_id": str(uuid.uuid4()),
        "expires_at": _iso_z(expires_at),
        "installation_id": installation_id,
        "nonce": _b64url_encode(secrets.token_bytes(32)),
        "purpose": purpose,
        "version": 2,
    }
    payload = dict(fields, mac=_challenge_mac(fields))
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "challenge_id": fields["challenge_id"],
        "payload": _b64url_encode(payload_bytes),
        "expires_at": fields["expires_at"],
    }


def _verify_challenge(
    installation_id, challenge_id, payload_b64, signature_b64, expected_purpose
):
    payload_bytes = _b64url_decode(payload_b64, "payload", 4096)
    signature = _b64url_decode(signature_b64, "signature", 1024)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    try:
        decoded_payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiProblem(
            "The challenge payload is not valid JSON.",
            400,
            "invalid_challenge_payload",
        )
    if not isinstance(decoded_payload, dict):
        raise ApiProblem(
            "The challenge payload is invalid.", 400, "invalid_challenge_payload"
        )
    mac = decoded_payload.get("mac")
    fields = {key: value for key, value in decoded_payload.items() if key != "mac"}
    if (
        not isinstance(mac, str)
        or fields.get("version") != 2
        or not hmac.compare_digest(
            mac.encode("utf-8"), _challenge_mac(fields).encode("utf-8")
        )
    ):
        raise ApiProblem(
            "The challenge was not issued by this server, or was modified.",
            401,
            "challenge_payload_mismatch",
        )
    if fields.get("challenge_id") != challenge_id:
        raise ApiProblem(
            "The challenge payload does not match the challenge ID.",
            401,
            "challenge_payload_mismatch",
        )
    if fields.get("installation_id") != installation_id:
        raise ApiProblem(
            "The challenge belongs to another installation.",
            401,
            "challenge_installation_mismatch",
        )
    if fields.get("purpose") != expected_purpose:
        raise ApiProblem(
            "The challenge purpose does not match this operation.",
            401,
            "challenge_purpose_mismatch",
        )
    try:
        expires_at = datetime.fromisoformat(str(fields.get("expires_at")).replace("Z", "+00:00"))
    except ValueError:
        raise ApiProblem(
            "The challenge payload is invalid.", 400, "invalid_challenge_payload"
        )
    if expires_at <= _utc_now():
        raise ApiProblem("The challenge has expired.", 401, "challenge_expired")

    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT i.key_algorithm,
                   i.public_key_jwk,
                   i.device_id,
                   i.key_thumbprint,
                   i.status,
                   d.status
            FROM app_installations i
            JOIN recognized_devices d
              ON d.device_id = i.device_id
            WHERE i.installation_id = %s
            """,
            (installation_id,),
        )
        row = cursor.fetchone()
    if row is None:
        raise ApiProblem(
            "The installation is not registered.", 404, "installation_not_found"
        )
    (
        key_algorithm,
        public_key_jwk,
        device_id,
        key_thumbprint,
        installation_status,
        device_status,
    ) = row
    device_id = str(device_id)
    if installation_status != "active":
        raise ApiProblem(
            "The installation is not active.", 403, "installation_inactive"
        )
    if device_status != "active":
        raise ApiProblem(
            "The recognized device is not active.", 403, "device_inactive"
        )

    _verify_installation_signature(
        key_algorithm, public_key_jwk, payload_bytes, signature
    )

    # Consume the challenge after cryptographic verification. The INSERT is
    # the single-use check: a second use of the same challenge hits the
    # primary key, on both engines, however the two requests interleave.
    with _cursor(commit=True) as cursor:
        if _maintenance_due("installation_challenges"):
            cursor.execute(
                """
                DELETE FROM installation_challenges
                WHERE expires_at < NOW() - INTERVAL '1 day'
                """
            )
        try:
            cursor.execute(
                """
                INSERT INTO installation_challenges
                    (challenge_id, installation_id, purpose, payload_sha256,
                     expires_at, used_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                """,
                (challenge_id, installation_id, expected_purpose, payload_hash, expires_at),
            )
        except Exception as error:
            if not DIALECT.is_unique_violation(error):
                raise
            raise ApiProblem(
                "The challenge has already been used.", 401, "challenge_used"
            )
        # The first consumed challenge is the installation's first proof that
        # it holds its key; only proven installations count toward a device
        # (migration 008, review F6).
        cursor.execute(
            """
            UPDATE app_installations
            SET last_seen_at = NOW(),
                verified_at = COALESCE(verified_at, NOW())
            WHERE installation_id = %s
            """,
            (installation_id,),
        )
        cursor.execute(
            """
            UPDATE recognized_devices
            SET last_seen_at = NOW()
            WHERE device_id = %s
            """,
            (device_id,),
        )

    return {
        "installation_id": installation_id,
        "device_id": device_id,
        "key_thumbprint": key_thumbprint,
        "key_algorithm": key_algorithm,
    }


def _require_role(required_role):
    claims = get_jwt()
    if claims.get("role") != required_role:
        raise ApiProblem(
            "This operation requires a %s token." % required_role,
            403,
            "wrong_token_role",
        )
    return claims


def _bearer_token_from_request():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiProblem(
            "A Bearer access token is required.",
            401,
            "missing_access_token",
        )
    token = header[7:].strip()
    if not token:
        raise ApiProblem(
            "A Bearer access token is required.",
            401,
            "missing_access_token",
        )
    return token


def _family_active(cursor, family_id):
    """Whether this refresh family still holds a current session."""
    if not isinstance(family_id, str) or not family_id:
        return False
    cursor.execute(
        """
        SELECT COUNT(*) FROM refresh_sessions
        WHERE family_id = %s AND revoked_at IS NULL AND expires_at > %s
        """,
        (family_id, _utc_now()),
    )
    return int(cursor.fetchone()[0]) > 0


def _require_access_proof(required_role="account"):
    """Verify a one-request proof of possession for the current access token.

    The client signs the exact base64url-decoded proof JSON bytes. The server
    then verifies that those signed fields describe this exact HTTP request:
    token hash, installation id, method, path, query (v2), body hash, timestamp
    and nonce.
    The nonce is committed only after the signature verifies, making a captured
    proof unusable a second time.
    """
    claims = _require_role(required_role)

    installation_id = claims.get("iid")
    device_id = claims.get("did")
    token_jti = claims.get("jti")
    if not installation_id or not device_id or not token_jti:
        raise ApiProblem(
            "The access token is missing proof-of-possession binding claims.",
            401,
            "invalid_access_binding",
        )

    proof_b64 = request.headers.get("X-Access-Proof")
    signature_b64 = request.headers.get("X-Access-Signature")
    if not proof_b64 or not signature_b64:
        raise ApiProblem(
            "This endpoint requires an installation-key access proof.",
            401,
            "missing_access_proof",
        )

    proof_bytes = _b64url_decode(proof_b64, "access_proof", 4096)
    signature = _b64url_decode(signature_b64, "access_signature", 1024)

    try:
        proof = json.loads(proof_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiProblem(
            "The access proof is not valid JSON.",
            400,
            "invalid_access_proof",
        )
    if not isinstance(proof, dict):
        raise ApiProblem(
            "The access proof must be a JSON object.",
            400,
            "invalid_access_proof",
        )

    version = proof.get("version")
    if (
        isinstance(version, bool)
        or version not in (1, 2)
        or version < ACCESS_PROOF_MIN_VERSION
    ):
        raise ApiProblem(
            "The access proof version is unsupported.",
            400,
            "unsupported_access_proof_version",
            details={"minimum": ACCESS_PROOF_MIN_VERSION, "current": 2},
        )

    if proof.get("installation_id") != installation_id:
        raise ApiProblem(
            "The access proof installation does not match the access token.",
            401,
            "access_proof_installation_mismatch",
        )

    expected_method = request.method.upper()
    if proof.get("method") != expected_method:
        raise ApiProblem(
            "The access proof HTTP method does not match the request.",
            401,
            "access_proof_method_mismatch",
        )

    if proof.get("path") != request.path:
        raise ApiProblem(
            "The access proof path does not match the request.",
            401,
            "access_proof_path_mismatch",
        )

    # The query string, exactly as sent (v2). request.path excludes it, so v1
    # left every query parameter outside the signature (review backlog).
    raw_query = request.query_string.decode("latin-1")
    if version >= 2:
        signed_query = proof.get("query")
        if not isinstance(signed_query, str) or signed_query != raw_query:
            raise ApiProblem(
                "The access proof query string does not match the request.",
                401,
                "access_proof_query_mismatch",
            )
    elif raw_query:
        raise ApiProblem(
            "A version 1 access proof cannot cover a query string.",
            401,
            "access_proof_query_mismatch",
        )

    raw_body = request.get_data(cache=True) or b""
    expected_body_hash = hashlib.sha256(raw_body).hexdigest()
    body_hash = proof.get("body_sha256")
    if not isinstance(body_hash, str) or not hmac.compare_digest(
        body_hash, expected_body_hash
    ):
        raise ApiProblem(
            "The access proof body hash does not match the request body.",
            401,
            "access_proof_body_mismatch",
        )

    raw_access_token = _bearer_token_from_request()
    expected_token_hash = hashlib.sha256(
        raw_access_token.encode("utf-8")
    ).hexdigest()
    token_hash = proof.get("access_token_sha256")
    if not isinstance(token_hash, str) or not hmac.compare_digest(
        token_hash, expected_token_hash
    ):
        raise ApiProblem(
            "The access proof is bound to a different access token.",
            401,
            "access_proof_token_mismatch",
        )

    timestamp = proof.get("timestamp")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ApiProblem(
            "The access proof timestamp is invalid.",
            400,
            "invalid_access_proof_timestamp",
        )
    now_seconds = int(_utc_now().timestamp())
    if abs(now_seconds - timestamp) > ACCESS_PROOF_MAX_SKEW_SECONDS:
        raise ApiProblem(
            "The access proof timestamp is outside the allowed clock window.",
            401,
            "access_proof_timestamp_outside_window",
        )

    nonce_text = proof.get("nonce")
    nonce_bytes = _b64url_decode(nonce_text, "access_proof_nonce", 64)
    if len(nonce_bytes) != 32:
        raise ApiProblem(
            "The access proof nonce must contain exactly 32 random bytes.",
            400,
            "invalid_access_proof_nonce",
        )
    nonce_hash = hashlib.sha256(nonce_bytes).hexdigest()

    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT i.key_algorithm, i.public_key_jwk, i.device_id,
                   i.status, d.status
            FROM app_installations i
            JOIN recognized_devices d ON d.device_id = i.device_id
            WHERE i.installation_id = %s
            """,
            (installation_id,),
        )
        row = cursor.fetchone()

    if row is None:
        raise ApiProblem(
            "The access token installation no longer exists.",
            401,
            "installation_not_found",
        )

    (
        key_algorithm,
        public_key_jwk,
        stored_device_id,
        installation_status,
        device_status,
    ) = row
    if str(stored_device_id) != device_id:
        raise ApiProblem(
            "The access token device binding does not match the installation.",
            401,
            "access_device_binding_mismatch",
        )
    if installation_status != "active":
        raise ApiProblem(
            "The installation is not active.",
            403,
            "installation_inactive",
        )
    if device_status != "active":
        raise ApiProblem(
            "The recognized device is not active.",
            403,
            "device_inactive",
        )

    # This is the cryptographic possession check. A copied access token from
    # Phone A, signed by Phone B's non-exportable key, fails here -- and is
    # recorded against the account and phone the token belongs to, once per
    # token (DESIGN.md 77); so is a signed request sent a second time, once
    # per request. The token's claims are the server's own, so a stranger
    # cannot write against someone else's phone.
    owner = str(get_jwt_identity()) if claims.get("role") == "account" else None
    with _observed_refusal("invalid_installation_signature", "token_without_key",
                           device_id, installation_id, owner, once_key=token_jti):
        _verify_installation_signature(
            key_algorithm,
            public_key_jwk,
            proof_bytes,
            signature,
        )

    # Consume the client nonce after signature verification, so an unverified
    # request can never burn a nonce.
    if NONCE_BACKEND == "redis":
        # Redis expires nonces itself, so there is no sweep and no INSERT; the
        # database work below still runs, because last_seen_at feeds the
        # relationship-risk signals and must not depend on the nonce backend.
        with _observed_refusal("access_proof_replay", "request_replayed",
                               device_id, installation_id, owner, once_key=nonce_hash):
            _claim_nonce_redis(nonce_hash, installation_id)

    replayed = _observed_refusal("access_proof_replay", "request_replayed",
                                 device_id, installation_id, owner, once_key=nonce_hash)
    with replayed, _cursor(commit=True) as cursor:
        # An access token outlives its refresh family by up to its lifetime.
        # A signed-out or reuse-revoked family stops here at once (review R6,
        # DESIGN.md 76); a routine rotation leaves the newest session current,
        # so requests in flight with the previous access token still pass.
        if required_role == "account" and not _family_active(cursor, claims.get("family")):
            raise ApiProblem(
                "This session was signed out or revoked; sign in again.",
                401,
                "session_revoked",
            )
        if NONCE_BACKEND == "database":
            if _maintenance_due("access_proof_nonces"):
                cursor.execute(
                    """
                    DELETE FROM access_proof_nonces
                    WHERE expires_at < NOW() - INTERVAL '1 day'
                    """
                )
            # A plain INSERT is the whole replay defence, and it is portable:
            # a duplicate primary key IS the replay. This deliberately avoids
            # ON CONFLICT (PostgreSQL-only) and its SQL Server translations,
            # both of which are traps - MERGE is racy without HOLDLOCK, and
            # IF NOT EXISTS(...) INSERT is racy under READ COMMITTED, so
            # either would let two concurrent identical proofs through.
            try:
                cursor.execute(
                    """
                    INSERT INTO access_proof_nonces
                        (nonce_hash, installation_id, access_token_jti,
                         expires_at)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        nonce_hash,
                        installation_id,
                        token_jti,
                        _utc_now() + ACCESS_PROOF_NONCE_RETENTION,
                    ),
                )
            except Exception as error:
                if not DIALECT.is_unique_violation(error):
                    raise
                raise ApiProblem(
                    "This signed access proof has already been used.",
                    401,
                    "access_proof_replay",
                )

        cursor.execute(
            """
            UPDATE app_installations
            SET last_seen_at = NOW()
            WHERE installation_id = %s
            """,
            (installation_id,),
        )
        cursor.execute(
            """
            UPDATE recognized_devices
            SET last_seen_at = NOW()
            WHERE device_id = %s
            """,
            (device_id,),
        )

    if required_role == "account" and claims.get("scope") == "limited":
        _require_limited_session_path(claims)
    return claims


# A limited session (DESIGN.md 70) always reaches the upgrade endpoints and the
# integrity scan -- a new clean scan is how an elevated verdict clears -- and
# otherwise only the paths a DBA lists in limited_session_paths.
_LIMITED_SESSION_ALWAYS_PATHS = frozenset(
    (
        "/v1/auth/logout",
        "/v1/auth/upgrade",
        "/v1/auth/upgrade/request",
        "/v1/integrity/challenge",
        "/v1/integrity/report",
        "/v1/integrity/me",
    )
)


def _require_limited_session_path(claims):
    if request.path in _LIMITED_SESSION_ALWAYS_PATHS:
        return
    if request.path in _risk_setting_words("limited_session_paths", ""):
        return
    # The one exception (DESIGN.md 79): support opened a reset after verifying
    # the customer, so this phone may set a new PIN, once, before it lapses.
    if request.path == _APP_PIN_PATH and _support_reset_open(get_jwt_identity()):
        return
    causes = claims.get("limited") or []
    with _cursor() as cursor:
        routes = _upgrade_routes(
            cursor, str(get_jwt_identity()), claims.get("iid"), causes
        )
    raise ApiProblem(
        "This session is limited and cannot reach this path; upgrade it first.",
        403,
        "session_limited",
        details={"limited_causes": causes, "upgrade_routes": routes},
    )


def _enabled_upgrade_routes(causes):
    """The proof routes the DBA enabled that can clear these causes.

    stepup (route 1): a step-up proof from this same phone -- off by default,
    and only when every cause is integrity-related: it proves the screen lock
    of the phone the risk came from, nothing about relationship risk.
    approval (route 2): another installation of the account approves -- on.
    assertion (route 3): the customer's identity backend signs -- off, and
    unusable until its verification keys are configured.
    """
    routes = []
    if (
        _risk_setting_bool("upgrade_stepup_same_device", False)
        and causes
        and all(cause.startswith("integrity_") for cause in causes)
    ):
        routes.append("stepup")
    if _risk_setting_bool("upgrade_other_device_approval", True):
        routes.append("approval")
    if _risk_setting_bool("upgrade_mfa_assertion", False) and _upgrade_assertion_keys()[0]:
        routes.append("assertion")
    return routes


def _upgrade_routes(cursor, account_id, installation_id, causes):
    """The routes enabled for these causes AND open to this user right now."""
    routes = []
    enabled = _enabled_upgrade_routes(causes)
    if "stepup" in enabled:
        # Open when this phone can give what the DBA's stepup_method asks
        # (DESIGN.md 78): a step-up key bound here, and/or an app PIN that is
        # set and not locked.
        need_key, need_pin = _stepup_factors()
        open_now = True
        if need_key:
            cursor.execute(
                "SELECT stepup_key_account_id, stepup_public_key_jwk "
                "FROM app_installations WHERE installation_id = %s",
                (installation_id,),
            )
            row = cursor.fetchone()
            open_now = row is not None and row[1] is not None and (
                row[0] is None or str(row[0]) == str(account_id)
            )
        if open_now and need_pin:
            cursor.execute(
                "SELECT pin_hash, locked_at FROM app_pins WHERE account_id = %s",
                (str(account_id),),
            )
            row = cursor.fetchone()
            open_now = row is not None and row[0] is not None and row[1] is None
        if open_now:
            routes.append("stepup")
    if "approval" in enabled and _has_other_full_session(
        cursor, account_id, installation_id
    ):
        routes.append("approval")
    if "assertion" in enabled:
        routes.append("assertion")
    return routes


def _has_other_full_session(cursor, account_id, installation_id):
    """Another active installation of this account holds a current full session."""
    cursor.execute(
        """
        SELECT r.session_id
        FROM refresh_sessions r
        JOIN app_installations i ON i.installation_id = r.installation_id
        WHERE r.account_id = %s AND r.installation_id <> %s
          AND r.scope = 'full' AND r.revoked_at IS NULL AND r.expires_at > %s
          AND i.status = 'active'
        LIMIT 1
        """,
        (account_id, installation_id, _utc_now()),
    )
    return cursor.fetchone() is not None


def _issue_device_token(installation_id, device_id, key_thumbprint):
    claims = {
        "role": "device",
        "did": device_id,
        "iid": installation_id,
        "key_thumbprint": key_thumbprint,
    }
    return create_access_token(
        identity=installation_id,
        additional_claims=claims,
        expires_delta=DEVICE_TOKEN_LIFETIME,
    )


def _confirm_hint_installation(cursor, device_id, account_id, installation_id):
    """Mark a hint-linked installation as belonging to its device (DESIGN.md 68).

    Called when an account signs in on the installation. It is confirmed when
    that account already belonged to the device -- linked first through an
    ESTABLISHED installation, the device's original one or a hint-linked one
    already confirmed. Requiring an established first link is what stops
    someone confirming their own hint-linked installations with accounts they
    opened on them. Only established installations spread an integrity block to
    the rest of the device (_device_integrity_memory). Login is the only caller:
    opening a new account proves nothing about the device, and refresh only
    continues a session on the installation. Must run before the link upsert,
    so a first login on this installation is not mistaken for a returning one.
    """
    cursor.execute(
        """
        UPDATE app_installations
        SET device_confirmed_at = NOW()
        WHERE installation_id = %s
          AND device_confirmed_at IS NULL
          AND registration_method = 'reinstall_hint'
          AND EXISTS (
              SELECT 1
              FROM device_account_links l
              JOIN app_installations first_i
                ON first_i.installation_id = l.first_installation_id
              WHERE l.device_id = %s
                AND l.account_id = %s
                AND l.first_installation_id <> %s
                AND (first_i.registration_method <> 'reinstall_hint'
                     OR first_i.device_confirmed_at IS NOT NULL)
          )
        """,
        (installation_id, device_id, account_id, installation_id),
    )


def _admit_link(cursor, device_id, account_id, policy):
    """Recheck, inside the transaction that creates the link, the relationship
    counts the risk decision was made on (review R2, DESIGN.md 76).

    The decision reads the counts in its own transaction; the link and the
    session are written in a later one. Four sign-ins of one account from four
    new phones could all read "one device" and all be admitted, ending with
    five links, which no single decision allowed. Here the account row and then
    the device row are locked -- always in that order, so concurrent sign-ins
    cannot deadlock -- and the counts are read again. If another sign-in has
    linked the account or the device since this decision was made, the link is
    refused with 409 relationship_changed and nothing is written; signing in
    again gets a decision on the new counts. A pair already linked adds
    nothing, so it is always admitted.
    """
    context = (policy or {}).get("context") or {}
    decided = (context.get("device_account_count"), context.get("account_device_count"))
    if any(isinstance(n, bool) or not isinstance(n, int) for n in decided):
        raise ApiProblem(
            "The sign-in decision did not record the relationship counts.",
            500,
            "admission_unverifiable",
        )
    hint, suffix = DIALECT.row_lock_hint(), DIALECT.row_lock_suffix()
    cursor.execute(
        "SELECT account_id FROM demo_accounts" + hint + " WHERE account_id = %s" + suffix,
        (account_id,),
    )
    cursor.execute(
        "SELECT device_id FROM recognized_devices" + hint + " WHERE device_id = %s" + suffix,
        (device_id,),
    )
    cursor.execute(
        "SELECT 1 FROM device_account_links WHERE device_id = %s AND account_id = %s",
        (device_id, account_id),
    )
    if cursor.fetchone() is not None:
        return
    cursor.execute(
        "SELECT COUNT(*) FROM device_account_links WHERE device_id = %s",
        (device_id,),
    )
    device_accounts = int(cursor.fetchone()[0])
    cursor.execute(
        "SELECT COUNT(DISTINCT device_id) FROM device_account_links WHERE account_id = %s",
        (account_id,),
    )
    account_devices = int(cursor.fetchone()[0])
    if device_accounts > decided[0] or account_devices > decided[1]:
        raise ApiProblem(
            "Another sign-in changed this phone's or this account's links while this "
            "one was being decided; sign in again.",
            409,
            "relationship_changed",
            details={
                "decided": {"device_accounts": decided[0], "account_devices": decided[1]},
                "now": {"device_accounts": device_accounts, "account_devices": account_devices},
            },
        )


def _link_device_account(cursor, device_id, account_id, installation_id):
    # Portable upsert: update first, insert only if nothing was updated. Two
    # first logins racing both see no row, and the loser's INSERT hits the
    # primary key -- the link exists, the desired end state either way. On
    # PostgreSQL that failed INSERT used to abort the caller's whole
    # transaction, so the refresh-session INSERT after it failed too (review
    # F10); the savepoint confines the rollback to the INSERT.
    cursor.execute(
        """
        UPDATE device_account_links
        SET last_seen_at = NOW()
        WHERE device_id = %s AND account_id = %s
        """,
        (device_id, account_id),
    )
    if cursor.rowcount == 0:
        savepoint = DIALECT.savepoint("link_insert")
        if savepoint:
            cursor.execute(savepoint[0])
        try:
            cursor.execute(
                """
                INSERT INTO device_account_links
                    (device_id, account_id, first_installation_id)
                VALUES (%s, %s, %s)
                """,
                (device_id, account_id, installation_id),
            )
        except Exception as error:
            if not DIALECT.is_unique_violation(error):
                raise
            if savepoint:
                cursor.execute(savepoint[1])
        else:
            if savepoint:
                cursor.execute(savepoint[2])


def _issue_account_tokens(
    cursor,
    account_id,
    device_id,
    installation_id,
    family_id=None,
    policy=None,
    limited_causes=(),
    accepted_causes=(),
    accepted_until=None,
    acceptance_id=None,
):
    """Issue an access and refresh token pair and record the refresh session.

    With limited_causes the session is LIMITED (DESIGN.md 70): the scope rides
    in both server-signed tokens and in refresh_sessions, so neither the client
    nor a refresh can widen it; only /v1/auth/upgrade issues a full session.

    With accepted_causes (a full session only) the soft causes an upgrade's
    proof accepted ride along until accepted_until (DESIGN.md 72): protected
    requests and refreshes honour exactly those causes, and nothing else.
    """
    new_family = family_id is None
    family_id = family_id or str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    refresh_lifetime = _refresh_lifetime(cursor, family_id, new_family)
    limited = sorted(set(limited_causes))
    scope = "limited" if limited else "full"
    claims = {
        "role": "account",
        "did": device_id,
        "iid": installation_id,
        "sid": session_id,
        "family": family_id,
        "scope": scope,
    }
    if limited:
        claims["limited"] = limited
    accepted = [] if limited else sorted(set(accepted_causes))
    if accepted and accepted_until is not None and accepted_until > _utc_now():
        claims["accepted"] = accepted
        claims["accepted_until"] = int(accepted_until.timestamp())
        if acceptance_id:
            claims["acc"] = acceptance_id
    else:
        accepted, accepted_until, acceptance_id = [], None, None
    access_token = create_access_token(
        identity=account_id,
        additional_claims=claims,
        expires_delta=ACCESS_TOKEN_LIFETIME,
    )
    refresh_token = create_refresh_token(
        identity=account_id,
        additional_claims=claims,
        expires_delta=refresh_lifetime,
    )
    cursor.execute(
        """
        INSERT INTO refresh_sessions
            (session_id, family_id, account_id, device_id, installation_id,
             expires_at, scope, limited_causes, accepted_causes, accepted_until,
             acceptance_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            session_id,
            family_id,
            account_id,
            device_id,
            installation_id,
            _utc_now() + refresh_lifetime,
            scope,
            ",".join(limited) or None,
            ",".join(accepted) or None,
            accepted_until,
            acceptance_id,
        ),
    )
    tokens = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "refresh_session_id": session_id,
        "account_id": account_id,
        "device_id": device_id,
        "installation_id": installation_id,
        "policy": policy,
        "scope": scope,
    }
    if limited:
        tokens["limited_causes"] = limited
        tokens["upgrade_routes"] = _upgrade_routes(
            cursor, account_id, installation_id, limited
        )
    if accepted:
        tokens["accepted_causes"] = accepted
        tokens["accepted_until"] = _iso_z(accepted_until)
        if acceptance_id:
            tokens["acceptance_id"] = acceptance_id
    return tokens


def _family_started_at(cursor, family_id):
    """When this session family began: its first refresh-session row."""
    cursor.execute(
        "SELECT MIN(created_at) FROM refresh_sessions WHERE family_id = %s", (family_id,)
    )
    row = cursor.fetchone()
    return row[0] if row and row[0] is not None else None


def _refresh_lifetime(cursor, family_id, new_family):
    """How long the refresh token issued now may live (DESIGN.md 79): the DBA's
    refresh_idle_days, each refresh starting it again, and never past the
    session_max_days the DBA may set from the session's first sign-in."""
    lifetime = timedelta(days=_risk_setting_int("refresh_idle_days", 30))
    max_days = _risk_setting_int("session_max_days", 0)
    if max_days <= 0:
        return lifetime
    started = None if new_family else _family_started_at(cursor, family_id)
    remaining = (started or _utc_now()) + timedelta(days=max_days) - _utc_now()
    return max(timedelta(seconds=0), min(lifetime, remaining))


def _refresh_session(cursor, claims, lock=False):
    session_id = claims.get("sid")
    family_id = claims.get("family")
    account_id = str(get_jwt_identity())
    device_id = claims.get("did")
    installation_id = claims.get("iid")
    if not all([session_id, family_id, device_id, installation_id]):
        raise ApiProblem(
            "The refresh token is missing binding claims.",
            401,
            "invalid_refresh_binding",
        )

    hint = DIALECT.row_lock_hint() if lock else ""
    suffix = DIALECT.row_lock_suffix() if lock else ""
    cursor.execute(
        """
        SELECT family_id, account_id, device_id, installation_id,
               expires_at, revoked_at, scope, limited_causes,
               accepted_causes, accepted_until, acceptance_id
        FROM refresh_sessions""" + hint + """
        WHERE session_id = %s
        """
        + suffix,
        (session_id,),
    )
    row = cursor.fetchone()
    if row is None:
        raise ApiProblem(
            "The refresh session is unknown.", 401, "unknown_refresh_session"
        )

    (
        stored_family,
        stored_account,
        stored_device,
        stored_installation,
        expires_at,
        revoked_at,
        stored_scope,
        stored_causes,
        stored_accepted,
        stored_accepted_until,
        stored_acceptance_id,
    ) = row
    if (
        str(stored_family) != family_id
        or str(stored_account) != account_id
        or str(stored_device) != device_id
        or str(stored_installation) != installation_id
    ):
        raise ApiProblem(
            "The refresh token binding does not match the session.",
            401,
            "refresh_binding_mismatch",
        )
    if expires_at <= _utc_now():
        raise ApiProblem(
            "The refresh session has expired.", 401, "refresh_session_expired"
        )
    # A session older than the DBA's session_max_days ends, however often it
    # refreshed -- also for tokens issued before the DBA lowered it (DESIGN.md 79).
    max_days = _risk_setting_int("session_max_days", 0)
    if max_days > 0:
        started = _family_started_at(cursor, family_id)
        if started is not None and started + timedelta(days=max_days) <= _utc_now():
            raise ApiProblem(
                "This session reached its maximum age; sign in again.",
                401,
                "session_max_age_reached",
            )
    return {
        "revoked": revoked_at is not None,
        "session_id": session_id,
        "family_id": family_id,
        "account_id": account_id,
        "device_id": device_id,
        "installation_id": installation_id,
        "scope": stored_scope or "full",
        "limited_causes": [c for c in (stored_causes or "").split(",") if c],
        "accepted_causes": [c for c in (stored_accepted or "").split(",") if c],
        "accepted_until": stored_accepted_until,
        "acceptance_id": str(stored_acceptance_id) if stored_acceptance_id else None,
    }


# ---------------------------------------------------------------------------
# Routes: health and installation identity
# ---------------------------------------------------------------------------


@app.get("/health/live")
def health_live():
    return jsonify({"status": "live", "python": "3.9-compatible"})


@app.get("/health/ready")
def health_ready():
    """Readiness: 200 only when this worker can serve protected requests.

    503 "not_ready", naming each problem, when the database cannot be reached,
    the schema does not match this build, no valid policy snapshot is loaded,
    or NONCE_BACKEND=redis and Redis is unreachable (the replay store fails
    closed, so nothing protected could be served). It used to answer 200
    "ready" beside schema.ok=false (DESIGN.md 63). /health/live stays a bare
    liveness probe.
    """
    problems = []
    database = schema = None
    try:
        with _cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        database = _get_backend_identity()
        schema = _get_schema_state()
    except Exception as error:
        logger.exception("Readiness: the database is unreachable")
        database = {"reachable": False, "error": type(error).__name__}
        problems.append("database_unreachable")
    if schema is not None and not schema.get("ok"):
        problems.append("schema_version_mismatch")
    policy_state, policy_values = _risk_policy_status()
    if policy_state["state"] == "unavailable":
        problems.append("risk_policy_unavailable")
    redis_state = _redis_status()
    if NONCE_BACKEND == "redis" and not redis_state.get("reachable"):
        problems.append("nonce_store_unavailable")
    assertion_keys, assertion_error = _upgrade_assertion_keys()
    if UPGRADE_ASSERTION_JWKS_FILE and assertion_error:
        problems.append("upgrade_assertion_keys_invalid")
    return jsonify(
        {
            "status": "not_ready" if problems else "ready",
            "problems": problems,
            "database": database,
            "schema": schema,
            "risk_policy": policy_state,
            "installation_key_algorithms": ["ES256", "RS256"],
            "access_proof_versions": list(range(ACCESS_PROOF_MIN_VERSION, 3)),
            "device_policy_mode": DEVICE_POLICY_MODE,
            "integrity_mode": INTEGRITY_MODE,
            # The effective values: the DBA's rows, or the environment's for a
            # missing row (DESIGN.md 79). Never raises: no policy, no rows.
            "integrity_freshness_seconds": int(
                (policy_values or {}).get("integrity_freshness_seconds")
                or INTEGRITY_FRESHNESS_SECONDS
            ),
            # Which signals are live versus shipped report-only. An operator
            # reading a low score needs to know whether a rule was absent or
            # merely inert, and the conformance suite asserts against this.
            "scoring_flags": {
                "extended_libs": INTEGRITY_SCORE_EXTENDED_LIBS,
                "ios_fake_signature": INTEGRITY_SCORE_IOS_FAKE_SIGNATURE,
                "ios_code_integrity": INTEGRITY_SCORE_IOS_CODE_INTEGRITY,
                "hardware_backing_policy": (policy_values or {}).get(
                    "hardware_backing_policy") or INTEGRITY_HARDWARE_BACKING_POLICY,
                "android_wx_baselines": len(ANDROID_WX_BASELINES),
                "risk_policy_settings": policy_values or {},
                "limited_sessions": {
                    "assertion_key_ids": sorted(assertion_keys),
                    "assertion_issuer_pinned": bool(UPGRADE_ASSERTION_ISSUER),
                },
            },
            "remote_attestation": "not_used",
            "redis": redis_state,
        }
    ), (503 if problems else 200)


@app.post("/v1/installations/register")
def register_installation():
    _limit_source("installations_register")
    body = _json_body()
    submitted_installation_id = _uuid_text(
        body.get("installation_id"), "installation_id"
    )
    platform = _required_text(body, "platform", 3, 16).lower()
    if platform not in ("android", "ios"):
        raise ApiProblem(
            "Only android and ios are supported.", 400, "unsupported_platform"
        )

    parsed_key = _parse_public_key(body.get("public_key"))
    key_algorithm = parsed_key["algorithm"]
    public_key_jwk = parsed_key["jwk"]
    key_thumbprint = parsed_key["thumbprint"]
    hint_hash = _reinstall_hint_hash(platform, body.get("reinstall_hint"))
    key_security = _parse_key_security(body)
    stepup_key = None
    if body.get("stepup_public_key") is not None:
        parsed_stepup = _parse_public_key(body.get("stepup_public_key"))
        if parsed_stepup["algorithm"] != "ES256":
            raise ApiProblem(
                "The step-up key must be an ES256 P-256 key.",
                400,
                "invalid_stepup_key",
            )
        if parsed_stepup["thumbprint"] == key_thumbprint:
            raise ApiProblem(
                "The step-up key must be a separate key from the installation key.",
                400,
                "invalid_stepup_key",
            )
        stepup_key = parsed_stepup
    stepup_auth = (
        _parse_stepup_key_auth(body) if stepup_key else dict(STEPUP_AUTH_NOT_REPORTED)
    )

    with _cursor(commit=True) as cursor:
        # The public key is the authoritative installation identity. This also
        # recovers gracefully if the UUID was lost but the Keychain key survived.
        cursor.execute(
            """
            SELECT installation_id, device_id, registration_method,
                   registration_confidence, key_algorithm,
                   key_security_level, key_hardware_backed, key_provider,
                   stepup_public_key_jwk, stepup_key_factor, stepup_key_mode,
                   stepup_key_window_seconds
            FROM app_installations
            WHERE key_thumbprint = %s
            """,
            (key_thumbprint,),
        )
        row = cursor.fetchone()
        if row is not None:
            canonical_installation_id = str(row[0])
            device_id = str(row[1])
            stored_level, stored_backed, stored_provider = row[5], row[6], row[7]

            # A step-up key binds only when the installation is first
            # registered, never here. Registration is unauthenticated, so
            # attaching or replacing a step-up key on this path would let
            # anyone holding the public installation key -- or a silent signing
            # oracle on a compromised device -- swap in a key it controls and
            # pass step-up. Changing the lock must require passing the lock
            # (51.4). Report whether the offered key is the bound one instead.
            stored_stepup_jwk = (
                DIALECT.json_value(row[8]) if row[8] is not None else None
            )
            stored_stepup_auth = {
                "factor": row[9],
                "mode": row[10],
                "window_seconds": row[11],
            }
            stepup_matches = None
            if stepup_key is not None:
                stepup_matches = bool(stored_stepup_jwk) and (
                    _parse_public_key(stored_stepup_jwk)["thumbprint"]
                    == stepup_key["thumbprint"]
                )
            if stepup_key is not None or stored_stepup_jwk:
                # What happened to a device's step-up key is otherwise invisible
                # server-side (e.g. after the screen lock is removed, DESIGN.md 56).
                logger.info(
                    "Re-registration: installation=%s stepup_offered=%s "
                    "stepup_bound=%s stepup_matches=%s",
                    canonical_installation_id,
                    stepup_key is not None,
                    bool(stored_stepup_jwk),
                    stepup_matches,
                )

            # Key-security metadata is recorded once, when the installation key
            # is first registered, and never changed here. This path is public:
            # it proves nothing about the caller, since the public key is not a
            # credential, so letting it rewrite the stored claim let anyone
            # holding the JWK "upgrade" a software key to StrongBox, or fill in
            # an unreported one (review F7) -- which the "required" hardware
            # policy would then honour. A different claim is logged, and a
            # weaker one is still reported, because the same non-exportable key
            # cannot have become weaker (the contradiction is the signal).
            downgraded = _key_security_downgraded(
                stored_level, stored_backed, key_security
            )
            claimed = (
                key_security["security_level"],
                key_security["hardware_backed"],
                key_security["provider"],
            )
            if any(value is not None for value in claimed) and claimed != (
                stored_level, stored_backed, stored_provider
            ):
                logger.warning(
                    "Installation %s re-registered with a key-security claim that "
                    "differs from the stored one (stored level=%s hardware_backed=%s; "
                    "claimed level=%s hardware_backed=%s; downgrade=%s). Stored "
                    "value kept: re-registration is unauthenticated.",
                    canonical_installation_id,
                    stored_level,
                    stored_backed,
                    key_security["security_level"],
                    key_security["hardware_backed"],
                    downgraded,
                )
            cursor.execute(
                """
                UPDATE app_installations
                SET last_seen_at = NOW()
                WHERE installation_id = %s
                """,
                (canonical_installation_id,),
            )
            cursor.execute(
                "UPDATE recognized_devices SET last_seen_at = NOW() WHERE device_id = %s",
                (device_id,),
            )
            return jsonify(
                {
                    "installation_id": canonical_installation_id,
                    "device_id": device_id,
                    "key_thumbprint": key_thumbprint,
                    "key_algorithm": row[4],
                    "recognition": {
                        "method": "exact_key",
                        "confidence": "high",
                        "is_reinstall_correlation": False,
                    },
                    "key_security": {
                        "security_level": stored_level,
                        "hardware_backed": stored_backed,
                        "provider": stored_provider,
                        "downgrade_reported": downgraded,
                    },
                    "stepup_key_registered": bool(stored_stepup_jwk),
                    "stepup_key_matches": stepup_matches,
                    "stepup_key_auth": (
                        stored_stepup_auth if stored_stepup_jwk else None
                    ),
                    "stepup_policy_downgrade": (
                        _stepup_policy_downgrade(stored_stepup_auth)
                        if stored_stepup_jwk
                        else None
                    ),
                }
            )

        cursor.execute(
            """
            SELECT key_thumbprint
            FROM app_installations
            WHERE installation_id = %s
            """,
            (submitted_installation_id,),
        )
        collision = cursor.fetchone()
        if collision is not None:
            raise ApiProblem(
                "The installation UUID is already bound to another public key.",
                409,
                "installation_id_collision",
            )

        device_id = None
        recognition_method = "new_device"
        recognition_confidence = "new"
        if hint_hash is not None:
            cursor.execute(
                """
                SELECT device_id
                FROM recognized_devices
                WHERE platform = %s AND reinstall_hint_hash = %s
                """,
                (platform, hint_hash),
            )
            matched = cursor.fetchone()
            if matched is not None:
                device_id = str(matched[0])
                recognition_method = "reinstall_hint"
                recognition_confidence = "medium"

        if device_id is None:
            device_id = str(uuid.uuid4())
            try:
                cursor.execute(
                    """
                    INSERT INTO recognized_devices
                        (device_id, platform, reinstall_hint_hash)
                    VALUES (%s, %s, %s)
                    """,
                    (device_id, platform, hint_hash),
                )
            except Exception as error:
                if not DIALECT.is_unique_violation(error):
                    raise
                # A concurrent registration used the same reinstall hint.
                # Roll back this transaction and ask the client to retry once.
                raise ApiProblem(
                    "A concurrent registration used this reinstall hint; retry.",
                    409,
                    "registration_race_retry",
                )
        else:
            cursor.execute(
                "UPDATE recognized_devices SET last_seen_at = NOW() WHERE device_id = %s",
                (device_id,),
            )

        cursor.execute(
            """
            INSERT INTO app_installations
                (installation_id, device_id, key_algorithm, public_key_jwk,
                 public_key_n, public_key_e, key_thumbprint,
                 registration_method, registration_confidence,
                 key_security_level, key_hardware_backed, key_provider,
                 stepup_public_key_jwk, stepup_key_algorithm,
                 stepup_key_factor, stepup_key_mode, stepup_key_window_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s)
            """,
            (
                submitted_installation_id,
                device_id,
                key_algorithm,
                DIALECT.json_param(public_key_jwk),
                public_key_jwk.get("n"),
                public_key_jwk.get("e"),
                key_thumbprint,
                recognition_method,
                recognition_confidence,
                key_security["security_level"],
                key_security["hardware_backed"],
                key_security["provider"],
                DIALECT.json_param(stepup_key["jwk"]) if stepup_key else None,
                stepup_key["algorithm"] if stepup_key else None,
                stepup_auth["factor"],
                stepup_auth["mode"],
                stepup_auth["window_seconds"],
            ),
        )

    stepup_downgrade = _stepup_policy_downgrade(stepup_auth) if stepup_key else None
    if stepup_downgrade:
        logger.info(
            "Installation %s registered a step-up key weaker than policy "
            "(factor=%s mode=%s window_seconds=%s; policy stepup_mode=%s)",
            submitted_installation_id,
            stepup_auth["factor"],
            stepup_auth["mode"],
            stepup_auth["window_seconds"],
            _risk_setting_str("stepup_mode", "per_use"),
        )

    return (
        jsonify(
            {
                "installation_id": submitted_installation_id,
                "device_id": device_id,
                "key_thumbprint": key_thumbprint,
                "key_algorithm": key_algorithm,
                "recognition": {
                    "method": recognition_method,
                    "confidence": recognition_confidence,
                    "is_reinstall_correlation": recognition_method == "reinstall_hint",
                },
                "key_security": {
                    "security_level": key_security["security_level"],
                    "hardware_backed": key_security["hardware_backed"],
                    "provider": key_security["provider"],
                    "downgrade_reported": False,
                },
                "stepup_key_registered": bool(stepup_key),
                "stepup_key_auth": stepup_auth if stepup_key else None,
                "stepup_policy_downgrade": stepup_downgrade,
            }
        ),
        201,
    )


@app.post("/v1/installations/challenge")
def installation_challenge():
    _limit_source("installations_challenge")
    body = _json_body()
    installation_id = _uuid_text(body.get("installation_id"), "installation_id")
    # No per-installation budget: issuing stores nothing now, so a bucket keyed
    # on a public installation ID would only let a third party lock its owner
    # out (joint review R5).
    return jsonify(_create_challenge(installation_id, "device_auth"))


@app.post("/v1/installations/verify")
def installation_verify():
    _limit_source("installations_verify")
    body = _json_body()
    installation_id = _uuid_text(body.get("installation_id"), "installation_id")
    challenge_id = _uuid_text(body.get("challenge_id"), "challenge_id")
    payload = _required_text(body, "payload", 16, 8192)
    signature = _required_text(body, "signature", 16, 4096)

    verified = _verify_challenge(
        installation_id,
        challenge_id,
        payload,
        signature,
        "device_auth",
    )
    device_token = _issue_device_token(
        verified["installation_id"],
        verified["device_id"],
        verified["key_thumbprint"],
    )
    return jsonify(
        {
            "device_token": device_token,
            "device_id": verified["device_id"],
            "installation_id": verified["installation_id"],
            "key_thumbprint": verified["key_thumbprint"],
            "key_algorithm": verified["key_algorithm"],
        }
    )


@app.get("/v1/device/me")
@jwt_required()
def device_me():
    claims = get_jwt()
    role = claims.get("role")
    if role not in ("device", "account"):
        raise ApiProblem("Unsupported token role.", 403, "wrong_token_role")
    claims = _require_access_proof(role)
    installation_id = claims.get("iid")
    device_id = claims.get("did")
    if not installation_id or not device_id:
        raise ApiProblem("The token is not device-bound.", 401, "unbound_token")

    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT i.installation_id,
                   i.device_id,
                   d.platform,
                   d.status,
                   i.key_thumbprint,
                   i.key_algorithm,
                   i.registration_method,
                   i.registration_confidence,
                   i.created_at,
                   i.last_seen_at,
                   (SELECT COUNT(*) FROM app_installations i2
                    WHERE i2.device_id = i.device_id
                      AND (i2.verified_at IS NOT NULL
                           OR i2.installation_id = i.installation_id)) AS installation_count,
                   (SELECT COUNT(*) FROM device_account_links l
                    WHERE l.device_id = i.device_id) AS linked_account_count
            FROM app_installations i
            JOIN recognized_devices d ON d.device_id = i.device_id
            WHERE i.installation_id = %s AND i.device_id = %s
            """,
            (installation_id, device_id),
        )
        row = cursor.fetchone()
    if row is None:
        raise ApiProblem(
            "The token no longer maps to an active installation.",
            401,
            "installation_not_found",
        )

    device_policy = _evaluate_risk_policy(
        "device_check",
        device_id,
        installation_id,
        account_id=(str(get_jwt_identity()) if role == "account" else None),
        account_link_pending=False,
        persist=False,
    )

    return jsonify(
        {
            "installation_id": str(row[0]),
            "device_id": str(row[1]),
            "platform": row[2],
            "device_status": row[3],
            "key_thumbprint": row[4],
            "key_algorithm": row[5],
            "recognition": {
                "method": row[6],
                "confidence": row[7],
            },
            "created_at": _iso_z(row[8]),
            "last_seen_at": _iso_z(row[9]),
            "installation_count": row[10],
            "linked_account_count": row[11],
            "policy": device_policy,
        }
    )


# ---------------------------------------------------------------------------
# Routes: challenge-driven native integrity measurement
# ---------------------------------------------------------------------------


@app.post("/v1/integrity/challenge")
@jwt_required()
def integrity_challenge():
    claims = get_jwt()
    role = claims.get("role")
    if role not in ("device", "account"):
        raise ApiProblem("Unsupported token role.", 403, "wrong_token_role")
    claims = _require_access_proof(role)
    installation_id = claims.get("iid")
    device_id = claims.get("did")

    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT d.platform, i.status, d.status
            FROM app_installations i
            JOIN recognized_devices d ON d.device_id = i.device_id
            WHERE i.installation_id = %s AND i.device_id = %s
            """,
            (installation_id, device_id),
        )
        row = cursor.fetchone()
    if row is None:
        raise ApiProblem("Installation not found.", 404, "installation_not_found")
    platform, installation_status, device_status = row
    if installation_status != "active":
        raise ApiProblem("Installation is not active.", 403, "installation_inactive")
    if device_status != "active":
        raise ApiProblem("Recognized device is not active.", 403, "device_inactive")

    challenge_id = str(uuid.uuid4())
    nonce = secrets.token_bytes(32)
    expires_at = _utc_now() + INTEGRITY_CHALLENGE_LIFETIME
    probes = _integrity_probe_plan(platform)

    with _cursor(commit=True) as cursor:
        if _maintenance_due("integrity_challenges"):
            cursor.execute(
                """
                DELETE FROM integrity_challenges
                WHERE expires_at < NOW() - INTERVAL '1 day'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM integrity_reports AS r
                      WHERE r.challenge_id = integrity_challenges.challenge_id
                  )
                """
            )
        cursor.execute(
            """
            INSERT INTO integrity_challenges
                (challenge_id, installation_id, device_id, platform,
                 nonce_sha256, required_probes, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                challenge_id,
                installation_id,
                device_id,
                platform,
                hashlib.sha256(nonce).hexdigest(),
                DIALECT.json_param(probes),
                expires_at,
            ),
        )

    return jsonify(
        {
            "challenge_id": challenge_id,
            "nonce": _b64url_encode(nonce),
            "platform": platform,
            "required_probes": probes,
            # Asked for, never required: a client collects those its app's
            # developers enabled and answers not_enabled for the rest; an older
            # client ignores the field (DESIGN.md 80).
            "optional_probes": _optional_measurements_requested(),
            "expires_at": _iso_z(expires_at),
            "server_time": _iso_z(_utc_now()),
            "collector_policy_version": 1,
        }
    )


@app.post("/v1/integrity/report")
@jwt_required()
def integrity_report():
    claims = get_jwt()
    role = claims.get("role")
    if role not in ("device", "account"):
        raise ApiProblem("Unsupported token role.", 403, "wrong_token_role")
    claims = _require_access_proof(role)
    outer_body = _json_body()
    report_payload = _required_text(outer_body, "report_payload", 16, 131072)
    report_signature_text = _required_text(outer_body, "report_signature", 16, 4096)
    report_bytes = _b64url_decode(report_payload, "report_payload", 65536)
    report_signature = _b64url_decode(report_signature_text, "report_signature", 2048)

    try:
        report = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiProblem("Integrity report is not valid JSON.", 400, "invalid_integrity_report")
    if not isinstance(report, dict) or report.get("version") != 1:
        raise ApiProblem("Unsupported integrity report.", 400, "invalid_integrity_report")

    installation_id = claims.get("iid")
    device_id = claims.get("did")
    if report.get("installation_id") != installation_id:
        raise ApiProblem("Integrity report installation mismatch.", 401, "integrity_installation_mismatch")
    challenge_id = _uuid_text(report.get("challenge_id"), "challenge_id")
    platform = report.get("platform")
    challenge_nonce_text = report.get("challenge_nonce")
    nonce = _b64url_decode(challenge_nonce_text, "challenge_nonce", 64)
    if len(nonce) != 32:
        raise ApiProblem("Integrity challenge nonce must be 32 bytes.", 400, "invalid_integrity_nonce")
    collected_at = report.get("collected_at")
    if isinstance(collected_at, bool) or not isinstance(collected_at, int):
        raise ApiProblem("Integrity collection timestamp is invalid.", 400, "invalid_integrity_timestamp")
    now_seconds = int(_utc_now().timestamp())
    if abs(now_seconds - collected_at) > INTEGRITY_REPORT_MAX_SKEW_SECONDS:
        raise ApiProblem("Integrity report timestamp is outside the allowed window.", 401, "integrity_report_stale")
    collector_version = report.get("collector_version")
    if (
        isinstance(collector_version, bool)
        or not isinstance(collector_version, int)
        or not INTEGRITY_MIN_COLLECTOR_VERSION <= collector_version <= INTEGRITY_MAX_COLLECTOR_VERSION
    ):
        raise ApiProblem(
            "Integrity collector version is invalid or no longer supported.",
            400,
            "invalid_integrity_collector",
            details={"minimum": INTEGRITY_MIN_COLLECTOR_VERSION},
        )
    probes = report.get("probe_results")
    if not isinstance(probes, dict):
        raise ApiProblem("probe_results must be an object.", 400, "invalid_integrity_report")
    # An optional measurement the DBA does not request now is dropped before
    # anything reads or stores the report (DESIGN.md 80). The signature and
    # report_sha256 still cover the bytes as sent.
    requested = _optional_measurements_requested()
    for name in _OPTIONAL_MEASUREMENTS:
        if name not in requested:
            probes.pop(name, None)

    report_id = str(uuid.uuid4())
    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            SELECT c.installation_id, c.device_id, c.platform, c.nonce_sha256,
                   c.required_probes, c.expires_at, c.used_at,
                   i.key_algorithm, i.public_key_jwk, i.status, d.status
            FROM integrity_challenges c""" + DIALECT.row_lock_hint() + """
            JOIN app_installations i ON i.installation_id = c.installation_id
            JOIN recognized_devices d ON d.device_id = c.device_id
            WHERE c.challenge_id = %s
            """ + DIALECT.row_lock_suffix() + """
            """,
            (challenge_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise ApiProblem("Integrity challenge not found.", 404, "integrity_challenge_not_found")
        (
            stored_installation_id,
            stored_device_id,
            stored_platform,
            nonce_sha256,
            required_probes,
            expires_at,
            used_at,
            key_algorithm,
            public_key_jwk,
            installation_status,
            device_status,
        ) = row
        if str(stored_installation_id) != installation_id or str(stored_device_id) != device_id:
            raise ApiProblem("Integrity challenge binding mismatch.", 401, "integrity_challenge_binding_mismatch")
        if stored_platform != platform:
            raise ApiProblem("Integrity platform mismatch.", 401, "integrity_platform_mismatch")
        if used_at is not None:
            raise ApiProblem("Integrity challenge has already been used.", 401, "integrity_challenge_replay")
        if expires_at < _utc_now():
            raise ApiProblem("Integrity challenge expired.", 401, "integrity_challenge_expired")
        if installation_status != "active":
            raise ApiProblem("Installation is not active.", 403, "installation_inactive")
        if device_status != "active":
            raise ApiProblem("Recognized device is not active.", 403, "device_inactive")
        if not hmac.compare_digest(nonce_sha256, hashlib.sha256(nonce).hexdigest()):
            raise ApiProblem("Integrity challenge nonce mismatch.", 401, "integrity_nonce_mismatch")

        # psycopg2 hands back a parsed list; pyodbc hands back the raw JSON
        # text of the nvarchar(max) column. Normalising here is what keeps the
        # probe requirement meaningful on both engines.
        required_probes = DIALECT.json_value(required_probes)
        if not isinstance(required_probes, list):
            # Fail closed. Treating an unreadable requirement list as "no
            # probes required" would let a client omit every mandatory probe
            # and still be scored as pristine.
            raise ApiProblem(
                "The stored integrity challenge could not be read.",
                500,
                "integrity_challenge_unreadable",
            )
        missing = [name for name in required_probes if name not in probes]
        if missing:
            raise ApiProblem(
                "The client omitted server-requested integrity probes.",
                400,
                "integrity_probe_missing",
                details={"missing_probes": missing},
            )
        if report.get("challenge_nonce") != challenge_nonce_text:
            raise ApiProblem("Integrity nonce encoding mismatch.", 400, "integrity_nonce_mismatch")
        incomplete = _check_probe_evidence(platform, probes, required_probes)
        invalid, unmeasured = _check_probe_consistency(
            platform, probes, required_probes, collector_version
        )
        incomplete = incomplete + [
            item for item in unmeasured if item[0] not in {n for n, _ in incomplete}
        ]

        _verify_installation_signature(
            key_algorithm,
            public_key_jwk,
            report_bytes,
            report_signature,
        )

        scored = _score_integrity(platform, probes)
        failed_required = []
        for probe_name in required_probes:
            probe_value = probes.get(probe_name)
            if not isinstance(probe_value, dict) or probe_value.get("status") != "ok":
                failed_required.append(probe_name)

        _apply_hardware_backing_policy(cursor, installation_id, scored)
        _apply_collection_problems(
            scored,
            failed_required,
            incomplete,
            invalid,
            legacy=collector_version < _EVIDENCE_CONTRACT_VERSION.get(platform, 0),
            streak=lambda: _incomplete_streak(cursor, installation_id),
        )
        cursor.execute(
            "UPDATE integrity_challenges SET used_at = NOW() WHERE challenge_id = %s",
            (challenge_id,),
        )
        if platform == "android" and _risk_setting_bool("vpn_exit_learning", False):
            _record_vpn_sighting(cursor, device_id, probes.get("network"))
        cursor.execute(
            """
            INSERT INTO integrity_reports
                (report_id, challenge_id, installation_id, device_id, platform,
                 collector_version, score, verdict, hard_block, reasons,
                 probe_results, report_sha256, evidence_quality, finding_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                report_id,
                challenge_id,
                installation_id,
                device_id,
                platform,
                collector_version,
                scored["score"],
                scored["verdict"],
                scored["hard_block"],
                DIALECT.json_param(scored["reasons"]),
                DIALECT.json_param(probes),
                hashlib.sha256(report_bytes).hexdigest(),
                scored["evidence_quality"],
                scored["finding_score"],
            ),
        )

    response = {
        "report_id": report_id,
        "score": scored["score"],
        "verdict": scored["verdict"],
        "hard_block": scored["hard_block"],
        "evidence_quality": scored["evidence_quality"],
        "finding_score": scored["finding_score"],
        "reasons": scored["reasons"],
        "mode": INTEGRITY_MODE,
        "fresh_for_seconds": _integrity_freshness_seconds(),
        "remote_attestation": "not_used",
        "created_at": _iso_z(_utc_now()),
    }
    return jsonify({"integrity": response})


@app.get("/v1/integrity/me")
@jwt_required()
def integrity_me():
    claims = get_jwt()
    role = claims.get("role")
    if role not in ("device", "account"):
        raise ApiProblem("Unsupported token role.", 403, "wrong_token_role")
    claims = _require_access_proof(role)
    return jsonify({"integrity": _latest_integrity_state(claims.get("iid"))})


# ---------------------------------------------------------------------------
# Routes: non-PII demo accounts bound to the recognized device
# ---------------------------------------------------------------------------


@app.post("/v1/accounts/register")
@jwt_required()
def account_register():
    _enforce_rate_limit("accounts_register", get_jwt().get("iid") or request.remote_addr)
    _limit_source("accounts_register")
    claims = _require_access_proof("device")
    body = _json_body()
    lookup = _handle_lookup(body.get("handle"))
    password = _password_bytes(body.get("password"))
    account_id = str(uuid.uuid4())
    device_id = claims.get("did")
    installation_id = claims.get("iid")
    integrity = _enforce_integrity_gate(device_id, installation_id, limited_ok=True)

    password_hash = _bcrypt_hash_bytes(password)

    policy = _evaluate_risk_policy(
        "account_register",
        device_id,
        installation_id,
        account_id=account_id,
        account_link_pending=True,
        persist=True,
    )
    # On a soft INTEGRITY verdict the account is still created -- and linked,
    # permanently -- but its session starts limited (DESIGN.md 70). Relationship
    # risk is never admitted here: the new account's link would raise the
    # device's counts for every account on it, for good.
    limited = _limited_causes(integrity, _enforce_risk_policy(policy))

    try:
        with _cursor(commit=True) as cursor:
            cursor.execute(
                """
                INSERT INTO demo_accounts (account_id, handle_lookup, password_hash)
                VALUES (%s, %s, %s)
                """,
                (account_id, lookup, password_hash),
            )
            _admit_link(cursor, device_id, account_id, policy)
            _link_device_account(cursor, device_id, account_id, installation_id)
            tokens = _issue_account_tokens(
                cursor,
                account_id,
                device_id,
                installation_id,
                policy=policy,
                limited_causes=limited,
            )
    except Exception as error:
        if not DIALECT.is_unique_violation(error):
            raise
        raise ApiProblem(
            "That account handle is already registered.",
            409,
            "account_handle_exists",
        )

    return jsonify(tokens), 201


@app.post("/v1/accounts/login")
@jwt_required()
def account_login():
    _enforce_rate_limit("accounts_login", get_jwt().get("iid") or request.remote_addr)
    _limit_source("accounts_login")
    claims = _require_access_proof("device")
    body = _json_body()
    lookup = _handle_lookup(body.get("handle"))
    # Per account handle as well: the installation bucket alone is spread by a
    # client that keeps registering new installations (review F9).
    _enforce_rate_limit("accounts_login_handle", lookup)
    password = _password_bytes(body.get("password"))
    device_id = claims.get("did")
    installation_id = claims.get("iid")

    # The gate runs BEFORE any credential comparison, and must stay here.
    # Checking the password first turns a blocked device into a credential
    # oracle: a wrong password answered 401 invalid_credentials while a correct
    # one answered 403 integrity_blocked, so an attacker on a compromised
    # device - exactly the device class this gate exists to distrust - could
    # confirm which passwords are valid and reuse them on a clean device or
    # another channel. Refusing before the lookup makes both cases identical.
    # /v1/accounts/register already had this ordering. Only a SOFT verdict the
    # DBA lists is deferred past the password, to a limited session (DESIGN.md
    # 70); a soft-risk device therefore learns whether a password is right, as
    # any client does from a successful login.
    integrity = _enforce_integrity_gate(device_id, installation_id, limited_ok=True)

    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            SELECT account_id, password_hash
            FROM demo_accounts
            WHERE handle_lookup = %s
            """,
            (lookup,),
        )
        row = cursor.fetchone()
    if row is None or not bcrypt.checkpw(password, _bcrypt_db_bytes(row[1])):
        # The server's own observation (DESIGN.md 77), against the account
        # when there is one and the phone whose key asked. The answer is the
        # same either way, so the record reveals nothing to the caller.
        _record_observation(
            "sign_in_failed" if row is not None else "sign_in_unknown_account",
            "invalid_credentials",
            device_id,
            installation_id,
            account_id=row[0] if row is not None else None,
        )
        raise ApiProblem(
            "The account credentials are invalid.",
            401,
            "invalid_credentials",
        )
    account_id = str(row[0])
    policy = _evaluate_risk_policy(
        "account_login",
        device_id,
        installation_id,
        account_id=account_id,
        account_link_pending=True,
        persist=True,
    )
    limited = _limited_causes(
        integrity,
        _enforce_risk_policy(policy, limited_ok=_first_link_within_counts(policy)),
    )

    with _cursor(commit=True) as cursor:
        _admit_link(cursor, device_id, account_id, policy)
        _confirm_hint_installation(cursor, device_id, account_id, installation_id)
        _link_device_account(cursor, device_id, account_id, installation_id)
        tokens = _issue_account_tokens(
            cursor,
            account_id,
            device_id,
            installation_id,
            policy=policy,
            limited_causes=limited,
        )

    return jsonify(tokens)


@app.get("/v1/policy/step-up")
def policy_step_up():
    """The DBA's step-up policy, before sign-in (DESIGN.md 79). An app creates
    its screen-lock key when it first registers, before any account exists,
    so it reads here which factor, mode and window to create it with -- and
    whether a PIN is the method -- instead of fixing them at build time. The
    policy is no secret: the server enforces it either way. Never cached, so
    a DBA's change reaches the next app that asks."""
    _limit_source("policy_read")
    response = jsonify(_stepup_policy_public())
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/v1/account/me")
@jwt_required()
def account_me():
    claims, policy, integrity = _require_trusted_account_request("account_me")
    return jsonify(
        {
            "account_id": str(get_jwt_identity()),
            "device_id": claims.get("did"),
            "installation_id": claims.get("iid"),
            "session_id": claims.get("sid"),
            "access_proof": "accepted",
            "trust_policy": policy,
            "integrity": integrity,
            # What a step-up needs here, so an app can ask for it up front.
            "step_up": _app_pin_state(get_jwt_identity()),
        }
    )


@app.post(_APP_PIN_PATH)
@jwt_required()
def set_app_pin():
    """Set or replace this account's app PIN (DESIGN.md 78).

    Needs a current full session -- a limited one never sets a PIN -- and the
    account password re-entered now; as at login, every gate runs before the
    password is compared. A new PIN clears the failure count and any lock: it
    is how a user who forgot or locked their PIN gets back in, with the
    password. Recorded as app_pin_set against the phone that set it, so a
    reset made somewhere else is visible. Only a verifier is stored.

    The one exception (DESIGN.md 79): when support has opened a reset for the
    account -- after verifying the customer, where the DBA allows it -- a
    limited session on one of the account's phones may set a new PIN, still
    with the password, once, before the reset lapses. A hard outcome still
    refuses. Whoever talks support into a reset is the business's
    verification procedure to stop.
    """
    account_id = str(get_jwt_identity())
    _enforce_rate_limit("app_pin_set", account_id)
    via_reset = get_jwt().get("scope") == "limited" and _support_reset_open(account_id)
    if via_reset:
        claims = _require_access_proof("account")
        _enforce_integrity_gate(claims.get("did"), claims.get("iid"), limited_ok=True)
        policy = _evaluate_risk_policy(
            "app_pin_set",
            claims.get("did"),
            claims.get("iid"),
            account_id=account_id,
            account_link_pending=False,
            persist=True,
        )
        _enforce_risk_policy(policy, limited_ok=True)
        with _cursor() as cursor:
            if _refresh_session(cursor, claims, lock=False)["revoked"]:
                raise ApiProblem(
                    "This session was signed out or revoked; sign in again.",
                    401,
                    "session_revoked",
                )
    else:
        claims, policy, integrity = _require_trusted_account_request("app_pin_set")
        _require_full_session(claims)
    body = _json_body()
    password = _password_bytes(body.get("password"))
    pin = body.get("pin")
    if not _app_pin_well_formed(pin):
        raise ApiProblem(
            "The app PIN must be %d digits." % _risk_setting_int("app_pin_length", 6),
            400,
            "invalid_app_pin",
        )
    with _cursor() as cursor:
        cursor.execute(
            "SELECT password_hash FROM demo_accounts WHERE account_id = %s", (account_id,)
        )
        row = cursor.fetchone()
    if row is None or not bcrypt.checkpw(password, _bcrypt_db_bytes(row[0])):
        _record_observation(
            "sign_in_failed",
            "app_pin_set_invalid_credentials",
            claims.get("did"),
            claims.get("iid"),
            account_id=account_id,
        )
        raise ApiProblem("The account credentials are invalid.", 401, "invalid_credentials")
    pin_hash = _bcrypt_hash_bytes(_app_pin_material(account_id, pin))
    with _cursor(commit=True) as cursor:
        update = (
            "UPDATE app_pins SET pin_hash = %s, failures = 0, locked_at = NULL, "
            "reset_until = NULL, set_at = NOW(), set_by_installation = %s "
            "WHERE account_id = %s"
        )
        if via_reset:
            # Consumes the reset in the same statement, so it serves once.
            cursor.execute(update + " AND reset_until > %s",
                           (pin_hash, claims.get("iid"), account_id, _utc_now()))
            if cursor.rowcount != 1:
                raise ApiProblem(
                    "The support reset has lapsed or was used; ask support again.",
                    403,
                    "app_pin_reset_lapsed",
                )
        else:
            cursor.execute(update, (pin_hash, claims.get("iid"), account_id))
        if cursor.rowcount == 0:
            # A first PIN; two at once both miss the UPDATE, and the loser's
            # INSERT hits the primary key -- then it simply updates.
            savepoint = DIALECT.savepoint("app_pin_insert")
            if savepoint:
                cursor.execute(savepoint[0])
            try:
                cursor.execute(
                    "INSERT INTO app_pins (account_id, pin_hash, set_by_installation) "
                    "VALUES (%s, %s, %s)",
                    (account_id, pin_hash, claims.get("iid")),
                )
            except Exception as error:
                if not DIALECT.is_unique_violation(error):
                    raise
                if savepoint:
                    cursor.execute(savepoint[1])
                cursor.execute(update, (pin_hash, claims.get("iid"), account_id))
            else:
                if savepoint:
                    cursor.execute(savepoint[2])
        _record_observation(
            "app_pin_set",
            "app_pin_set_after_support_reset" if via_reset else "app_pin_set",
            claims.get("did"),
            claims.get("iid"),
            account_id=account_id,
            cursor=cursor,
        )
    logger.info("App PIN set: account=%s installation=%s", account_id, claims.get("iid"))
    return jsonify({"app_pin_set": True, "step_up": _app_pin_state(account_id)})


@app.get("/v1/policy/me")
@jwt_required()
def policy_me():
    claims = _require_access_proof("account")
    _enforce_integrity_gate(
        claims.get("did"), claims.get("iid"),
        accepted=_session_acceptance(claims, "policy_check"),
    )
    decision = _evaluate_risk_policy(
        "policy_check",
        claims.get("did"),
        claims.get("iid"),
        account_id=str(get_jwt_identity()),
        account_link_pending=False,
        persist=True,
    )
    return jsonify({"policy": decision})


@app.post("/v1/account/sensitive-echo")
@jwt_required()
def account_sensitive_echo():
    # Demo crown-jewel endpoint. Step-up is enforced inside
    # _require_trusted_account_request only when a deployment lists this path in
    # risk_policy_settings.stepup_required_paths; otherwise it behaves like
    # protected-echo.
    claims, policy, integrity = _require_trusted_account_request("sensitive_echo")
    body = _json_body()
    step_up = g.get("step_up")
    return jsonify(
        {
            "sensitive_echo": body,
            "step_up": "verified" if step_up else "not_required",
            "step_up_key": step_up,
            "app_pin": "verified" if g.get("app_pin_verified") else "not_required",
        }
    )


@app.post("/v1/installations/stepup-key")
@jwt_required()
def reenrol_stepup_key():
    """Re-enrol the step-up key of an existing installation (DESIGN.md 58).

    A step-up key binds only at first registration, so an installation whose
    key died (screen lock removed, 57) had no way back short of a new
    installation. The re-enrolled key is scoped to the re-enrolling account:
    opening a second account on a device needs only the installation key, so an
    installation-wide key would let that account's password unlock step-up for
    the first account. This path accepts a new key only with all three of:
    possession of the installation key (the access proof), the account password
    re-entered now, and a signature by the new step-up key itself -- which the
    device grants only after the user passes the new screen lock. A signing
    oracle on a compromised device holds the first but not the password, so it
    cannot swap in a key of its own; an attacker who also holds the password
    could already enrol a fresh installation, so this grants nothing new. As in
    login, every gate runs before the password check, so the endpoint cannot
    serve as a credential oracle.
    """
    _enforce_rate_limit("stepup_reenrol", get_jwt().get("iid") or request.remote_addr)
    _enforce_rate_limit("stepup_reenrol_account", str(get_jwt_identity()))
    claims, policy, integrity = _require_trusted_account_request("stepup_reenrol")
    installation_id = claims.get("iid")
    account_id = str(get_jwt_identity())
    body = _json_body()
    password = _password_bytes(body.get("password"))
    parsed = _parse_public_key(body.get("stepup_public_key"))
    if parsed["algorithm"] != "ES256":
        raise ApiProblem(
            "The step-up key must be an ES256 P-256 key.", 400, "invalid_stepup_key"
        )
    stepup_auth = _parse_stepup_key_auth(body)
    with _cursor() as cursor:
        cursor.execute(
            "SELECT key_thumbprint FROM app_installations WHERE installation_id = %s",
            (installation_id,),
        )
        row = cursor.fetchone()
    if row is None or parsed["thumbprint"] == row[0]:
        raise ApiProblem(
            "The step-up key must be a separate key from the installation key.",
            400,
            "invalid_stepup_key",
        )

    def refuse(message, code, status=403):
        logger.info(
            "Step-up re-enrolment refused: installation=%s code=%s",
            installation_id,
            code,
        )
        # A wrong password here is a failed sign-in like any other; a new key
        # whose proof does not verify is a failed step-up (DESIGN.md 77).
        if code == "invalid_credentials":
            kind, recorded = "sign_in_failed", "stepup_reenrol_invalid_credentials"
        else:
            kind, recorded = "stepup_failed", code
        _record_observation(
            kind, recorded, claims.get("did"), installation_id, account_id=account_id
        )
        return ApiProblem(message, status, code)

    proof_bytes = _b64url_decode(body.get("stepup_key_proof"), "stepup_key_proof", 4096)
    signature = _b64url_decode(
        body.get("stepup_key_signature"), "stepup_key_signature", 1024
    )
    try:
        _verify_installation_signature("ES256", parsed["jwk"], proof_bytes, signature)
        proof = json.loads(proof_bytes.decode("utf-8"))
        access_nonce = json.loads(
            _b64url_decode(
                request.headers.get("X-Access-Proof"), "access_proof", 8192
            ).decode("utf-8")
        ).get("nonce")
    except Exception:
        raise refuse(
            "The new step-up key's proof did not verify.", "stepup_reenrol_proof_invalid"
        )
    timestamp = proof.get("timestamp") if isinstance(proof, dict) else None
    if (
        not isinstance(proof, dict)
        or proof.get("purpose") != "stepup_reenrol"
        or proof.get("installation_id") != installation_id
        or proof.get("stepup_key_thumbprint") != parsed["thumbprint"]
        or not proof.get("nonce")
        or proof.get("nonce") != access_nonce
        or isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or abs(int(_utc_now().timestamp()) - timestamp) > ACCESS_PROOF_MAX_SKEW_SECONDS
    ):
        raise refuse(
            "The new step-up key's proof is not bound to this request.",
            "stepup_reenrol_proof_invalid",
        )

    with _cursor() as cursor:
        cursor.execute(
            "SELECT password_hash FROM demo_accounts WHERE account_id = %s",
            (account_id,),
        )
        row = cursor.fetchone()
    if row is None or not bcrypt.checkpw(password, _bcrypt_db_bytes(row[0])):
        raise refuse("The account credentials are invalid.", "invalid_credentials", 401)

    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            UPDATE app_installations
            SET stepup_public_key_jwk = %s,
                stepup_key_algorithm = %s,
                stepup_key_factor = %s,
                stepup_key_mode = %s,
                stepup_key_window_seconds = %s,
                stepup_key_account_id = %s
            WHERE installation_id = %s
            """,
            (
                DIALECT.json_param(parsed["jwk"]),
                parsed["algorithm"],
                stepup_auth["factor"],
                stepup_auth["mode"],
                stepup_auth["window_seconds"],
                account_id,
                installation_id,
            ),
        )
        # In the same transaction: a replaced key always leaves its record.
        _record_observation(
            "stepup_reenrolled",
            "stepup_reenrolled",
            claims.get("did"),
            installation_id,
            account_id=account_id,
            cursor=cursor,
        )
    downgrade = _stepup_policy_downgrade(stepup_auth)
    logger.info(
        "Step-up key re-enrolled: installation=%s account=%s factor=%s mode=%s "
        "window_seconds=%s policy_downgrade=%s",
        installation_id,
        account_id,
        stepup_auth["factor"],
        stepup_auth["mode"],
        stepup_auth["window_seconds"],
        downgrade,
    )
    return jsonify(
        {
            "stepup_key_registered": True,
            "stepup_key_auth": stepup_auth,
            "stepup_policy_downgrade": downgrade,
        }
    )


@app.post("/v1/account/protected-echo")
@jwt_required()
def account_protected_echo():
    claims, policy, integrity = _require_trusted_account_request("protected_echo")
    body = _json_body()
    return jsonify(
        {
            "account_id": str(get_jwt_identity()),
            "device_id": claims.get("did"),
            "installation_id": claims.get("iid"),
            "access_proof": "accepted",
            "body_sha256": hashlib.sha256(request.get_data(cache=True) or b"").hexdigest(),
            "trust_policy": policy,
            "integrity": integrity,
            "echo": body,
        }
    )


# ---------------------------------------------------------------------------
# Routes: sender-constrained, rotating refresh tokens
# ---------------------------------------------------------------------------


@app.post("/v1/auth/refresh/challenge")
@jwt_required(refresh=True)
def refresh_challenge():
    """Issue the installation-key challenge for a refresh; change nothing.

    Reuse of a rotated refresh token is detected -- and its whole family
    revoked -- only in /v1/auth/refresh, after the installation key has signed
    the challenge. Revoking here, on the bearer token alone, let anyone holding
    an old rotated token but not the key log the user out (joint review R7,
    DESIGN.md 66.2).
    """
    claims = _require_role("account")
    with _cursor() as cursor:
        session = _refresh_session(cursor, claims, lock=False)
    purpose = "refresh:%s" % session["session_id"]
    return jsonify(_create_challenge(session["installation_id"], purpose))


@app.post("/v1/auth/refresh")
@jwt_required(refresh=True)
def refresh_account_tokens():
    claims = _require_role("account")
    body = _json_body()
    installation_id = claims.get("iid")
    challenge_id = _uuid_text(body.get("challenge_id"), "challenge_id")
    payload = _required_text(body, "payload", 16, 8192)
    signature = _required_text(body, "signature", 16, 4096)
    session_id = claims.get("sid")
    if not installation_id or not session_id:
        raise ApiProblem(
            "The refresh token is missing device binding.",
            401,
            "invalid_refresh_binding",
        )

    # A refresh token used on another phone fails the key check: recorded,
    # once per token, like an access token (DESIGN.md 77).
    with _observed_refusal("invalid_installation_signature", "token_without_key",
                           claims.get("did"), installation_id, str(get_jwt_identity()),
                           once_key=claims.get("jti")):
        _verify_challenge(
            installation_id,
            challenge_id,
            payload,
            signature,
            "refresh:%s" % session_id,
        )

    with _cursor() as cursor:
        policy_session = _refresh_session(cursor, claims, lock=False)

    integrity = _enforce_integrity_gate(
        policy_session["device_id"],
        policy_session["installation_id"],
        limited_ok=True,
    )
    policy = _evaluate_risk_policy(
        "refresh",
        policy_session["device_id"],
        policy_session["installation_id"],
        account_id=policy_session["account_id"],
        account_link_pending=False,
        persist=True,
    )
    limited = _limited_causes(integrity, _enforce_risk_policy(policy, limited_ok=True))

    reused = False
    tokens = None
    with _cursor(commit=True) as cursor:
        session = _refresh_session(cursor, claims, lock=True)
        if session["revoked"]:
            cursor.execute(
                """
                UPDATE refresh_sessions
                SET revoked_at = COALESCE(revoked_at, NOW())
                WHERE family_id = %s
                """,
                (session["family_id"],),
            )
            reused = True
        else:
            cursor.execute(
                """
                UPDATE refresh_sessions
                SET revoked_at = NOW()
                WHERE session_id = %s AND revoked_at IS NULL
                """,
                (session["session_id"],),
            )
            # A refresh never widens a session: a limited one stays limited
            # (with its causes) unless soft risk is found now, and a full one
            # becomes limited when it is (DESIGN.md 70). Only the upgrade
            # endpoint issues a full session from a limited one. A full session
            # whose upgrade accepted every cause found now stays full, with its
            # acceptance, until accepted_until; anything beyond what was
            # accepted narrows it and drops the acceptance (DESIGN.md 72).
            accepted, accepted_until, acceptance_id = (), None, None
            if (
                session["scope"] == "full"
                and session["accepted_causes"]
                and session["accepted_until"] is not None
                and session["accepted_until"] > _utc_now()
            ):
                # Judged reason by reason (DESIGN.md 76): every cause found now
                # must be covered by what was approved; each one that is not is
                # recorded as a lapse, and the session narrows.
                if session["acceptance_id"]:
                    record = _load_acceptance(session["acceptance_id"], session["family_id"],
                                              session["account_id"], session["installation_id"])
                else:  # granted before migration 016
                    record = _carry_legacy_acceptance(
                        session["family_id"], session["account_id"], session["device_id"],
                        session["installation_id"], session["accepted_causes"],
                        session["accepted_until"], integrity=integrity, policy=policy,
                    )
                acceptance = _Acceptance(record, "refresh")
                verdicts = [acceptance.covers(cause, integrity=integrity, policy=policy)
                            for cause in limited]
                if acceptance.record is not None and all(verdicts):
                    accepted, accepted_until = session["accepted_causes"], session["accepted_until"]
                    acceptance_id = acceptance.acceptance_id
                    limited = []
            if not limited and session["scope"] == "limited":
                limited = session["limited_causes"] or ["session_limited"]
            tokens = _issue_account_tokens(
                cursor,
                session["account_id"],
                session["device_id"],
                session["installation_id"],
                family_id=session["family_id"],
                policy=policy,
                limited_causes=limited,
                accepted_causes=accepted,
                accepted_until=accepted_until,
                acceptance_id=acceptance_id,
            )
            cursor.execute(
                """
                UPDATE refresh_sessions
                SET replaced_by = %s
                WHERE session_id = %s
                """,
                (tokens["refresh_session_id"], session["session_id"]),
            )

    if reused:
        raise ApiProblem(
            "A rotated refresh token was reused; the token family was revoked.",
            401,
            "refresh_token_reuse",
        )
    return jsonify(tokens)


# ---------------------------------------------------------------------------
# Routes: limited sessions and their upgrade (DESIGN.md 67, 70)
# ---------------------------------------------------------------------------


def _first_link_within_counts(policy):
    """Relationship risk may limit a first sign-in only within the DBA's counts.

    A first sign-in of an account on a device writes a device-account link, and
    links are permanent. If that link made the phone's third account or the
    account's third device (the owner's defaults: the review counts), every
    account on that phone, or every device of that account, would be refused
    from then on -- and anyone holding only a password could do it from a
    fresh phone, since a phone cannot prove it is new. Such a sign-in is
    refused as before (owner decision, DESIGN.md 72). Within the counts -- two
    people sharing a phone, a user's own second phone -- it gets a limited
    session. Where elevated_risk_refuses is set, the elevated counts are the
    ones that refuse, so they are the limits. An account already linked to the
    device adds no link and may always be limited.
    """
    context = (policy or {}).get("context") or {}
    if context.get("account_already_linked_to_device") is True:
        return True
    accounts = context.get("projected_device_account_count")
    devices = context.get("projected_account_device_count")
    if not isinstance(accounts, int) or not isinstance(devices, int):
        return False
    level = "elevated" if _risk_setting_bool("elevated_risk_refuses", False) else "review"
    defaults = {"elevated": 2, "review": 3}
    for key, count in (("device_accounts_%s_count", accounts), ("account_devices_%s_count", devices)):
        limit = _risk_setting_int(key % level, defaults[level])
        if limit > 0 and count >= limit:
            return False
    return True


def _limited_causes(integrity, risk_cause):
    causes = []
    if isinstance(integrity, dict) and integrity.get("limited_cause"):
        causes.append(integrity["limited_cause"])
    if risk_cause:
        causes.append(risk_cause)
    return causes


_UPGRADE_ROUTES = ("recheck", "stepup", "approval", "assertion")


@app.post("/v1/auth/logout")
@jwt_required()
def logout():
    """Sign this session out on the server (review R6, DESIGN.md 76).

    Revokes every current session of the caller's refresh family: its refresh
    token stops working, and so do its access tokens, at once -- account
    requests check the family. Clearing tokens on the phone alone leaves a
    copied token, with the phone's key, usable until it expires. A limited
    session may sign out too.
    """
    _enforce_rate_limit("auth_logout", get_jwt().get("iid") or request.remote_addr)
    claims = _require_access_proof("account")
    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            UPDATE refresh_sessions SET revoked_at = NOW()
            WHERE family_id = %s AND revoked_at IS NULL
            """,
            (claims.get("family"),),
        )
        revoked = cursor.rowcount
        cursor.execute(
            """
            UPDATE session_acceptances SET revoked_at = NOW()
            WHERE family_id = %s AND revoked_at IS NULL
            """,
            (claims.get("family"),),
        )
    logger.info(
        "Signed out: installation=%s family=%s sessions=%s",
        claims.get("iid"), claims.get("family"), revoked,
    )
    return jsonify({"signed_out": True, "sessions_revoked": revoked})


@app.post("/v1/auth/upgrade")
@jwt_required()
def upgrade_session():
    """Turn a limited session into a full one, in the same refresh family.

    The integrity and relationship gates run again first, so an upgrade never
    overrides a hard outcome. If no soft cause remains -- a new clean scan has
    cleared an elevated verdict -- no proof is needed ("recheck"). Otherwise
    the request must carry one proof from a route the DBA enabled and that is
    open to this user.
    """
    _enforce_rate_limit("auth_upgrade", get_jwt().get("iid") or request.remote_addr)
    claims = _require_access_proof("account")
    if claims.get("scope") != "limited":
        raise ApiProblem("This session is not limited.", 409, "session_not_limited")
    account_id = str(get_jwt_identity())
    device_id = claims.get("did")
    installation_id = claims.get("iid")
    body = _json_body()
    route = body.get("route", "recheck")
    if route not in _UPGRADE_ROUTES:
        raise ApiProblem(
            "route must be one of %s." % ", ".join(_UPGRADE_ROUTES),
            400,
            "invalid_route",
        )

    if route == "approval":
        # Before the gates, so a client polling for the approval costs one
        # cheap read per attempt and stores no risk decision until it is real.
        with _cursor() as cursor:
            _approval_state(cursor, body, claims, account_id, installation_id, required=True)

    integrity = _enforce_integrity_gate(device_id, installation_id, limited_ok=True)
    policy = _evaluate_risk_policy(
        "session_upgrade",
        device_id,
        installation_id,
        account_id=account_id,
        account_link_pending=False,
        persist=True,
    )
    causes = _limited_causes(integrity, _enforce_risk_policy(policy, limited_ok=True))
    snapshot = scope = None
    if causes:
        snapshot = _acceptance_snapshot(causes, integrity, policy)
        if route in ("approval", "assertion"):
            # Accept what the approver or the identity backend was shown --
            # the request's reasons -- provided nothing has been added since.
            scope = _request_scope(body.get("request_id"), account_id, installation_id)
            if scope is not None:
                _require_within_scope(scope, causes, integrity, policy)
                snapshot = (scope["reasons"], scope["device_accounts"], scope["account_devices"])
        _verify_upgrade_proof(route, body, claims, account_id, installation_id, causes)

    with _cursor(commit=True) as cursor:
        session = _refresh_session(cursor, claims, lock=True)
        if session["revoked"]:
            raise ApiProblem(
                "This session was already rotated; upgrade with the newest token.",
                401,
                "session_rotated",
            )
        if causes:
            _consume_upgrade_proof(route, body, cursor, session)
        cursor.execute(
            """
            UPDATE refresh_sessions
            SET revoked_at = NOW()
            WHERE session_id = %s AND revoked_at IS NULL
            """,
            (session["session_id"],),
        )
        # The proof accepts the soft causes found now, for this sign-in, until
        # the DBA's upgrade_acceptance_hours (owner default 720: the refresh
        # lifetime) -- not any other cause, and never past the refresh lifetime
        # (DESIGN.md 72). A recheck needed no proof and accepts nothing.
        hours = _risk_setting_int("upgrade_acceptance_hours", 720)
        accepted_until = _utc_now() + min(
            timedelta(hours=hours), timedelta(days=_risk_setting_int("refresh_idle_days", 30))
        )
        acceptance_id = None
        if causes and hours > 0:
            acceptance_id = _insert_acceptance(
                cursor, session, route, scope, causes, snapshot, integrity, accepted_until
            )
        tokens = _issue_account_tokens(
            cursor,
            account_id,
            device_id,
            installation_id,
            family_id=session["family_id"],
            policy=policy,
            accepted_causes=causes if hours > 0 else (),
            accepted_until=accepted_until,
            acceptance_id=acceptance_id,
        )
        cursor.execute(
            """
            UPDATE refresh_sessions
            SET replaced_by = %s
            WHERE session_id = %s
            """,
            (tokens["refresh_session_id"], session["session_id"]),
        )
    tokens["upgraded_by"] = route if causes else "recheck"
    logger.info(
        "Session upgraded: installation=%s route=%s causes=%s",
        installation_id,
        tokens["upgraded_by"],
        ",".join(causes) or "-",
    )
    return jsonify(tokens)


def _request_scope(request_id, account_id, installation_id):
    """What an approval or assertion request showed: its causes, reasons and
    counts. None for a request from before migration 016."""
    request_id = _uuid_text(request_id, "request_id")
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT causes, reasons, device_accounts, account_devices, approved_by_installation
            FROM session_upgrade_requests
            WHERE request_id = %s AND account_id = %s AND installation_id = %s
            """,
            (request_id, account_id, installation_id),
        )
        row = cursor.fetchone()
    if row is None or row[1] is None:
        return None
    return {
        "request_id": request_id,
        "causes": [c for c in (row[0] or "").split(",") if c],
        "reasons": [r for r in _as_list(DIALECT.json_value(row[1])) if isinstance(r, dict)],
        "device_accounts": row[2],
        "account_devices": row[3],
        "approved_by_installation": str(row[4]) if row[4] else None,
    }


def _require_within_scope(scope, causes, integrity, policy):
    """Refuse an upgrade whose causes grew after the request was shown: the
    approver approved those reasons, not these (DESIGN.md 76)."""
    record = dict(scope, revoked_at=None, expires_at=_utc_now() + timedelta(days=1))
    grown = []
    for cause in causes:
        covered, uncovered = _acceptance_covers(record, cause, integrity, policy,
                                                ignore_quality=True)
        if not covered:
            grown.extend(uncovered or [{"code": cause}])
    if grown:
        raise ApiProblem(
            "Something was found after the approval was requested; ask again, so the "
            "approver sees it.",
            409,
            "upgrade_scope_changed",
            details={"new_reasons": [r.get("code") for r in grown]},
        )


def _insert_acceptance(cursor, session, route, scope, causes, snapshot, integrity, until):
    """Record what this upgrade accepted; returns its acceptance_id."""
    reasons, device_accounts, account_devices = snapshot
    report_id = (integrity or {}).get("report_id")
    build = None
    if report_id:
        cursor.execute("SELECT probe_results FROM integrity_reports WHERE report_id = %s",
                       (report_id,))
        row = cursor.fetchone()
        identity = (DIALECT.json_value(row[0]) or {}).get("app_identity") if row else None
        if isinstance(identity, dict):
            build = identity.get("apk_sha256") or identity.get("executable_sha256")
    acceptance_id = str(uuid.uuid4())
    cursor.execute(
        """
        INSERT INTO session_acceptances
            (acceptance_id, family_id, account_id, device_id, installation_id, route,
             request_id, approved_by_installation, causes, reasons, device_accounts,
             account_devices, evidence_quality, integrity_report_id, apk_sha256, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            acceptance_id,
            session["family_id"],
            session["account_id"],
            session["device_id"],
            session["installation_id"],
            route,
            scope["request_id"] if scope else None,
            scope["approved_by_installation"] if scope else None,
            ",".join(sorted(set(causes))),
            DIALECT.json_param(list(reasons)),
            device_accounts,
            account_devices,
            (integrity or {}).get("evidence_quality"),
            report_id,
            build if isinstance(build, str) and len(build) <= 64 else None,
            until,
        ),
    )
    return acceptance_id


def _verify_upgrade_proof(route, body, claims, account_id, installation_id, causes):
    """Check the proof a still-limited session offers (before any write)."""
    with _cursor() as cursor:
        routes = _upgrade_routes(cursor, account_id, installation_id, causes)
    if route == "recheck" or route not in _enabled_upgrade_routes(causes):
        raise ApiProblem(
            "The session is still limited (%s); upgrade through one of the routes "
            "open to it." % ", ".join(causes),
            403,
            "upgrade_proof_required" if route == "recheck" else "upgrade_route_unavailable",
            details={"limited_causes": causes, "upgrade_routes": routes},
        )
    if route == "stepup":
        # Bound to this very upgrade request, like any step-up proof v2; the
        # access proof's nonce, claimed once, makes it single-use. Proven as the
        # DBA's stepup_method says (DESIGN.md 78).
        _prove_step_up(installation_id, account_id, *_stepup_factors())
    elif route == "assertion":
        g.upgrade_assertion = _verify_upgrade_assertion(
            body.get("assertion"),
            account_id,
            installation_id,
            _uuid_text(body.get("request_id"), "request_id"),
        )


def _consume_upgrade_proof(route, body, cursor, session):
    """Consume a single-use proof inside the upgrade's transaction."""
    if route == "approval":
        if _consume_approval(cursor, body.get("request_id"), session) != 1:
            raise ApiProblem(
                "The approval is no longer usable.",
                403,
                "approval_not_granted",
                details={"state": "used"},
            )
    elif route == "assertion":
        if _consume_assertion(cursor, body.get("request_id"), session, g.upgrade_assertion) != 1:
            raise ApiProblem(
                "The upgrade assertion does not match an open request of this session.",
                403,
                "upgrade_assertion_invalid",
                details={"field": "request"},
            )


def _upgrade_assertion_keys():
    """kid -> P-256 key from UPGRADE_ASSERTION_JWKS_FILE; (keys, error)."""
    if "keys" not in _upgrade_assertion_cache:
        keys, error = {}, None
        if UPGRADE_ASSERTION_JWKS_FILE:
            try:
                with open(UPGRADE_ASSERTION_JWKS_FILE, "r", encoding="utf-8") as handle:
                    document = json.load(handle)
                for jwk in document.get("keys") or []:
                    parsed = _parse_public_key(dict(jwk, alg=jwk.get("alg", "ES256")))
                    keys[str(jwk.get("kid") or parsed["thumbprint"])] = parsed["key"]
                if not keys:
                    error = "no_keys"
            except (OSError, ValueError, TypeError, AttributeError, ApiProblem) as exc:
                keys, error = {}, type(exc).__name__
            if error:
                logger.error("UPGRADE_ASSERTION_JWKS_FILE could not be used: %s", error)
        _upgrade_assertion_cache.update(keys=keys, error=error)
    return _upgrade_assertion_cache["keys"], _upgrade_assertion_cache["error"]


def _verify_upgrade_assertion(token, account_id, installation_id, request_id):
    """Verify a route-3 assertion: an ES256 compact JWS by the customer's backend.

    Only ES256 with a raw r||s signature, by a configured key (by kid when the
    header names one); no "crit" extensions. The payload must name this
    deployment's audience, the account, the installation and the upgrade
    request, carry the request's nonce, and live at most ten minutes. The
    nonce is checked against the request -- and consumed -- in the upgrade's
    transaction.
    """
    def invalid(field):
        return ApiProblem(
            "The upgrade assertion is not valid (%s)." % field,
            403,
            "upgrade_assertion_invalid",
            details={"field": field},
        )

    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 8192:
        raise invalid("format")
    head_b64, body_b64, signature_b64 = token.split(".")
    try:
        header = json.loads(_b64url_decode(head_b64, "assertion_header", 2048).decode("utf-8"))
        payload = json.loads(_b64url_decode(body_b64, "assertion_payload", 4096).decode("utf-8"))
        signature = _b64url_decode(signature_b64, "assertion_signature", 128)
    except (ApiProblem, ValueError, UnicodeDecodeError):
        raise invalid("format")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise invalid("format")
    if header.get("alg") != "ES256" or "crit" in header:
        raise invalid("alg")
    keys, _ = _upgrade_assertion_keys()
    kid = header.get("kid")
    if kid is None:
        candidates = list(keys.values())
    else:
        candidates = [keys[kid]] if isinstance(kid, str) and kid in keys else []
    signed = (head_b64 + "." + body_b64).encode("ascii")
    verified = False
    if len(signature) == 64:
        for key in candidates:
            try:
                DSS.new(key, "fips-186-3", encoding="binary").verify(
                    SHA256.new(signed), signature
                )
            except ValueError:
                continue
            verified = True
            break
    if not verified:
        raise invalid("signature")
    audience = payload.get("aud")
    if audience != UPGRADE_ASSERTION_AUDIENCE and not (
        isinstance(audience, list) and UPGRADE_ASSERTION_AUDIENCE in audience
    ):
        raise invalid("aud")
    if UPGRADE_ASSERTION_ISSUER and payload.get("iss") != UPGRADE_ASSERTION_ISSUER:
        raise invalid("iss")
    for field, expected in (("sub", account_id), ("iid", installation_id), ("rid", request_id)):
        if payload.get(field) != expected:
            raise invalid(field)
    issued, expires = payload.get("iat"), payload.get("exp")
    now = int(_utc_now().timestamp())
    if (
        not all(isinstance(v, int) and not isinstance(v, bool) for v in (issued, expires))
        or expires <= now
        or issued > now + ACCESS_PROOF_MAX_SKEW_SECONDS
        or expires - issued > UPGRADE_ASSERTION_MAX_LIFETIME_SECONDS
    ):
        raise invalid("exp")
    if not isinstance(payload.get("nonce"), str) or not payload["nonce"]:
        raise invalid("nonce")
    return payload


def _consume_assertion(cursor, request_id, session, payload):
    """Use an open assertion request of this session, exactly once."""
    method = payload.get("amr")
    if isinstance(method, list):
        method = ",".join(str(m) for m in method)
    cursor.execute(
        """
        UPDATE session_upgrade_requests
        SET consumed_at = NOW(), assertion_method = %s
        WHERE request_id = %s AND route = 'assertion' AND account_id = %s
          AND installation_id = %s AND family_id = %s AND nonce_sha256 = %s
          AND consumed_at IS NULL AND expires_at > %s
        """,
        (
            (str(method)[:64] or None) if method else None,
            _uuid_text(request_id, "request_id"),
            session["account_id"],
            session["installation_id"],
            session["family_id"],
            hashlib.sha256(payload["nonce"].encode("utf-8")).hexdigest(),
            _utc_now(),
        ),
    )
    return cursor.rowcount


def _approval_state(cursor, body, claims, account_id, installation_id, required=False):
    """Where this limited session's approval request stands.

    The request must belong to this account, this installation and this
    session's refresh family -- so a refresh in between does not break it, and
    no other login can use it.
    """
    request_id = _uuid_text(body.get("request_id"), "request_id")
    cursor.execute(
        """
        SELECT approved_at, denied_at, consumed_at, expires_at, superseded_at
        FROM session_upgrade_requests
        WHERE request_id = %s AND route = 'approval' AND account_id = %s
          AND installation_id = %s AND family_id = %s
        """,
        (request_id, account_id, installation_id, claims.get("family")),
    )
    row = cursor.fetchone()
    if row is None:
        state = "unknown"
    elif row[2] is not None:
        state = "used"
    elif row[1] is not None:
        state = "denied"
    elif row[4] is not None:
        # This phone asked again for the same account; the newer request
        # replaced this one (DESIGN.md 75).
        state = "superseded"
    elif row[3] <= _utc_now():
        state = "expired"
    elif row[0] is None:
        state = "pending"
    else:
        state = "approved"
    if required and state != "approved":
        raise ApiProblem(
            "The approval request is %s." % state,
            403,
            "approval_not_granted",
            details={"state": state},
        )
    return state


def _consume_approval(cursor, request_id, session):
    """Mark an approved request used, exactly once; returns the rows changed."""
    cursor.execute(
        """
        UPDATE session_upgrade_requests
        SET consumed_at = NOW()
        WHERE request_id = %s AND route = 'approval' AND account_id = %s
          AND installation_id = %s AND family_id = %s
          AND approved_at IS NOT NULL AND denied_at IS NULL
          AND consumed_at IS NULL AND superseded_at IS NULL AND expires_at > %s
        """,
        (
            _uuid_text(request_id, "request_id"),
            session["account_id"],
            session["installation_id"],
            session["family_id"],
            _utc_now(),
        ),
    )
    return cursor.rowcount


def _grant_approval(cursor, request_id, account_id, approver_installation_id):
    """Approve a pending request of the same account from ANOTHER installation."""
    cursor.execute(
        """
        UPDATE session_upgrade_requests
        SET approved_at = NOW(), approved_by_installation = %s
        WHERE request_id = %s AND route = 'approval' AND account_id = %s
          AND installation_id <> %s
          AND approved_at IS NULL AND denied_at IS NULL
          AND consumed_at IS NULL AND superseded_at IS NULL AND expires_at > %s
        """,
        (approver_installation_id, request_id, account_id, approver_installation_id,
         _utc_now()),
    )
    return cursor.rowcount


def _deny_approval(cursor, request_id, account_id, installation_id):
    cursor.execute(
        """
        UPDATE session_upgrade_requests
        SET denied_at = NOW()
        WHERE request_id = %s AND route = 'approval' AND account_id = %s
          AND installation_id <> %s
          AND approved_at IS NULL AND denied_at IS NULL
          AND consumed_at IS NULL AND superseded_at IS NULL AND expires_at > %s
        """,
        (request_id, account_id, installation_id, _utc_now()),
    )
    return cursor.rowcount


def _supersede_pending_requests(cursor, account_id, installation_id):
    """Mark this installation's pending approval requests for the account as
    superseded, before it raises a new one (DESIGN.md 75).

    An approver then sees one request per phone, not duplicates from repeated
    sign-ins. Only the caller's own installation is touched -- one phone must
    never cancel another's prompt -- and only requests still open: approved,
    denied, used or already superseded rows keep their state. The rows stay as
    evidence and still count toward upgrade_approvals_per_hour.
    """
    cursor.execute(
        """
        UPDATE session_upgrade_requests
        SET superseded_at = NOW()
        WHERE account_id = %s AND installation_id = %s AND route = 'approval'
          AND approved_at IS NULL AND denied_at IS NULL
          AND consumed_at IS NULL AND superseded_at IS NULL
        """,
        (account_id, installation_id),
    )
    return cursor.rowcount


def _approval_superseded(cursor, request_id, account_id, installation_id):
    """Whether a request an approver could have acted on was superseded.

    Scoped like approving itself -- the same account, another installation --
    so the answer reveals nothing about requests the caller could not see.
    """
    cursor.execute(
        """
        SELECT superseded_at FROM session_upgrade_requests
        WHERE request_id = %s AND route = 'approval' AND account_id = %s
          AND installation_id <> %s
        """,
        (request_id, account_id, installation_id),
    )
    row = cursor.fetchone()
    return row is not None and row[0] is not None


def _refuse_unchangeable_request(cursor, request_id, account_id, installation_id, verb):
    if _approval_superseded(cursor, request_id, account_id, installation_id):
        raise ApiProblem(
            "That request was replaced by a newer one from the same phone; "
            "refresh the list.",
            409,
            "approval_superseded",
        )
    raise ApiProblem(
        "There is no pending request with that ID that this installation can %s." % verb,
        404,
        "approval_not_pending",
    )


def _require_full_session(claims):
    """The caller holds a CURRENT full session, by its refresh-session row.

    The scope claim alone is not enough: an access token outlives a revoked or
    rotated refresh family by up to its lifetime.
    """
    with _cursor() as cursor:
        session = _refresh_session(cursor, claims, lock=False)
    if session["revoked"] or session["scope"] != "full":
        raise ApiProblem(
            "This needs a full, current session: use the newest access token.",
            403,
            "full_session_required",
        )
    return session


@app.post("/v1/auth/upgrade/request")
@jwt_required()
def upgrade_request():
    """Start an upgrade that needs a second party: an approval (route 2).

    The request is bound to this account, installation and refresh family and
    expires after upgrade_request_ttl_seconds. Approval requests are budgeted
    per account (upgrade_approvals_per_hour) against prompt fatigue, and are
    refused when no other installation of the account could approve.
    """
    _enforce_rate_limit("auth_upgrade", get_jwt().get("iid") or request.remote_addr)
    claims = _require_access_proof("account")
    if claims.get("scope") != "limited":
        raise ApiProblem("This session is not limited.", 409, "session_not_limited")
    account_id = str(get_jwt_identity())
    device_id = claims.get("did")
    installation_id = claims.get("iid")
    route = _json_body().get("route")
    if route not in ("approval", "assertion"):
        raise ApiProblem("route must be approval or assertion.", 400, "invalid_route")
    # A hard outcome refuses here too: a blocked device gets no prompt sent.
    integrity = _enforce_integrity_gate(device_id, installation_id, limited_ok=True)
    policy = _evaluate_risk_policy(
        "upgrade_request",
        device_id,
        installation_id,
        account_id=account_id,
        account_link_pending=False,
        persist=False,
    )
    causes = (
        _limited_causes(integrity, _enforce_risk_policy(policy, limited_ok=True))
        or list(claims.get("limited") or [])
    )
    if route not in _enabled_upgrade_routes(causes):
        raise ApiProblem(
            "That upgrade route is not enabled here.", 403, "upgrade_route_unavailable"
        )
    # What the approver -- or the identity backend -- is shown, and all an
    # approval will accept (DESIGN.md 76). Collection problems alone cannot be
    # approved: complete_scan_required, before anyone is prompted.
    reasons, device_accounts, account_devices = _acceptance_snapshot(causes, integrity, policy)
    now = _utc_now()
    ttl = timedelta(seconds=_risk_setting_int("upgrade_request_ttl_seconds", 300))
    request_id = str(uuid.uuid4())
    response = {"request_id": request_id, "route": route, "expires_at": _iso_z(now + ttl),
                "limited_causes": causes,
                "reasons": [{k: r[k] for k in ("code", "points", "message", "source")}
                            for r in reasons]}
    # Recorded once per budget period and phone (DESIGN.md 77): the period is
    # named by its oldest request's time, set below when the budget is spent.
    exhausted = _observed_refusal(
        "upgrade_budget_exhausted", "approval_budget_exhausted",
        device_id, installation_id, account_id,
        once_key=lambda: "%s:%s:%s" % (account_id, device_id, g.get("budget_period")),
    )
    with exhausted, _cursor(commit=True) as cursor:
        # Count and insert under the account row's lock, so parallel requests
        # cannot all pass the budget count before any is inserted (review R2).
        cursor.execute(
            "SELECT account_id FROM demo_accounts" + DIALECT.row_lock_hint()
            + " WHERE account_id = %s" + DIALECT.row_lock_suffix(),
            (account_id,),
        )
        if route == "approval":
            if not _has_other_full_session(cursor, account_id, installation_id):
                raise ApiProblem(
                    "No other installation of this account holds a full session to "
                    "approve from.",
                    409,
                    "no_approving_device",
                )
            cursor.execute(
                """
                SELECT COUNT(*), MIN(created_at) FROM session_upgrade_requests
                WHERE account_id = %s AND route = 'approval' AND created_at > %s
                """,
                (account_id, now - timedelta(hours=1)),
            )
            spent, oldest = cursor.fetchone()
            if int(spent) >= _risk_setting_int("upgrade_approvals_per_hour", 3):
                # The budget period lasts until its oldest request leaves the
                # hour; every refusal until then is the same period.
                g.budget_period = _iso_z(oldest) if oldest is not None else None
                raise ApiProblem(
                    "Too many approval requests for this account in the last hour.",
                    429,
                    "upgrade_budget_exhausted",
                )
            replaced = _supersede_pending_requests(cursor, account_id, installation_id)
            if replaced:
                response["superseded"] = replaced
        nonce_sha256 = None
        if route == "assertion":
            # What the customer's identity backend must sign once its MFA has
            # passed for this account: only the nonce's hash is stored.
            nonce = _b64url_encode(secrets.token_bytes(32))
            nonce_sha256 = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            response["assertion_claims"] = {
                "aud": UPGRADE_ASSERTION_AUDIENCE,
                "sub": account_id,
                "iid": installation_id,
                "rid": request_id,
                "nonce": nonce,
            }
            response["assertion_max_lifetime_seconds"] = UPGRADE_ASSERTION_MAX_LIFETIME_SECONDS
        cursor.execute(
            """
            INSERT INTO session_upgrade_requests
                (request_id, route, account_id, device_id, installation_id,
                 session_id, family_id, nonce_sha256, created_at, expires_at,
                 causes, reasons, device_accounts, account_devices)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (request_id, route, account_id, device_id, installation_id,
             claims.get("sid"), claims.get("family"), nonce_sha256, now, now + ttl,
             ",".join(sorted(set(causes))), DIALECT.json_param(list(reasons)),
             device_accounts, account_devices),
        )
    logger.info(
        "Upgrade requested: installation=%s route=%s request=%s",
        installation_id, route, request_id,
    )
    return jsonify(response), 201


@app.get("/v1/auth/approvals")
@jwt_required()
def list_approvals():
    """Pending approval requests of this account, from its OTHER installations.

    Shows only what the approving phone needs to judge the request -- the
    platform, when the requesting installation was first seen and how it
    joined its device; no hardware attributes or personal data.
    """
    _enforce_rate_limit("auth_approvals", str(get_jwt_identity()))
    claims = _require_access_proof("account")
    _require_full_session(claims)
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT r.request_id, r.created_at, r.expires_at,
                   d.platform, i.created_at, i.registration_method,
                   r.causes, r.reasons
            FROM session_upgrade_requests r
            JOIN app_installations i ON i.installation_id = r.installation_id
            JOIN recognized_devices d ON d.device_id = i.device_id
            WHERE r.account_id = %s AND r.route = 'approval'
              AND r.installation_id <> %s
              AND r.approved_at IS NULL AND r.denied_at IS NULL
              AND r.consumed_at IS NULL AND r.superseded_at IS NULL
              AND r.expires_at > %s
            ORDER BY r.created_at DESC
            """,
            (str(get_jwt_identity()), claims.get("iid"), _utc_now()),
        )
        rows = cursor.fetchall() or []
    return jsonify(
        {
            "approvals": [
                {
                    "request_id": str(row[0]),
                    "created_at": _iso_z(row[1]),
                    "expires_at": _iso_z(row[2]),
                    "requesting_installation": {
                        "platform": row[3],
                        "first_seen_at": _iso_z(row[4]),
                        "registration_method": row[5],
                    },
                    # What approving accepts (DESIGN.md 76): the causes and the
                    # reasons behind them, as the server worded them.
                    "limited_causes": [c for c in (row[6] or "").split(",") if c],
                    "reasons": [
                        {k: r.get(k) for k in ("code", "points", "message", "source")}
                        for r in _as_list(DIALECT.json_value(row[7]) if row[7] else [])
                        if isinstance(r, dict)
                    ],
                }
                for row in rows
            ]
        }
    )


@app.post("/v1/auth/approvals/<request_id>/approve")
@jwt_required()
def approve_upgrade(request_id):
    """Approve another installation's upgrade request (route 2).

    The approver must hold a current full session on a DIFFERENT installation
    of the same account, pass the integrity gate without any step-up allowance
    and the relationship gate, and sign this very request with its step-up key.
    """
    _enforce_rate_limit("auth_approvals", str(get_jwt_identity()))
    claims = _require_access_proof("account")
    request_id = _uuid_text(request_id, "request_id")
    account_id = str(get_jwt_identity())
    installation_id = claims.get("iid")
    _require_full_session(claims)
    # Strict on purpose: no step-up allowance and no upgrade acceptance. A
    # device whose own risk was only accepted must not vouch for another.
    _enforce_integrity_gate(claims.get("did"), installation_id)
    policy = _evaluate_risk_policy(
        "approval_grant",
        claims.get("did"),
        installation_id,
        account_id=account_id,
        account_link_pending=False,
        persist=True,
    )
    _enforce_risk_policy(policy)
    _prove_step_up(installation_id, account_id, *_stepup_factors())
    with _cursor(commit=True) as cursor:
        changed = _grant_approval(cursor, request_id, account_id, installation_id)
        if changed != 1:
            _refuse_unchangeable_request(
                cursor, request_id, account_id, installation_id, "approve"
            )
    logger.info("Upgrade approved: request=%s approver=%s", request_id, installation_id)
    return jsonify({"request_id": request_id, "approved": True})


@app.post("/v1/auth/approvals/<request_id>/deny")
@jwt_required()
def deny_upgrade(request_id):
    """Refuse another installation's upgrade request; recorded, not deleted."""
    _enforce_rate_limit("auth_approvals", str(get_jwt_identity()))
    claims = _require_access_proof("account")
    request_id = _uuid_text(request_id, "request_id")
    _require_full_session(claims)
    with _cursor(commit=True) as cursor:
        changed = _deny_approval(cursor, request_id, str(get_jwt_identity()), claims.get("iid"))
        if changed != 1:
            _refuse_unchangeable_request(
                cursor, request_id, str(get_jwt_identity()), claims.get("iid"), "deny"
            )
    logger.warning("Upgrade denied: request=%s by=%s", request_id, claims.get("iid"))
    return jsonify({"request_id": request_id, "denied": True})


# ---------------------------------------------------------------------------
# Routes: the business API -- server to server, never the app (DESIGN.md 76)
# ---------------------------------------------------------------------------
#
# The customer's backend reports business events and reads the phone-account
# graph combined with them, and the acceptance lapses. The server guarantees
# the measurements; what they should refuse is the business's decision, so
# nothing here is scored. No personal data: accounts are the server's opaque
# IDs (or a handle, resolved through the same keyed lookup as sign-in and
# never stored); a subject reference is kept only as a keyed hash; types and
# outcomes are short codes; any other field is refused.

_BUSINESS_EVENT_FIELDS = frozenset((
    "event_id", "account_id", "handle", "type", "occurred_at", "amount_minor",
    "currency", "outcome", "subject_ref",
))
_BUSINESS_WINDOWS = (("1d", 1), ("7d", 7), ("30d", 30))


def _require_business_caller():
    if not BUSINESS_API_TOKEN_SHA256:
        raise ApiProblem("Not found.", 404, "not_found")
    _enforce_rate_limit("business_api", request.remote_addr or "unknown")
    header = request.headers.get("Authorization", "")
    token = header[len("Bearer "):].strip() if header.startswith("Bearer ") else ""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest() if token else "-"
    if not any(hmac.compare_digest(digest, allowed) for allowed in BUSINESS_API_TOKEN_SHA256):
        raise ApiProblem(
            "A valid business API token is required.", 401, "business_token_invalid"
        )


def _business_problem(index, field, message):
    return ApiProblem(
        "Event %d: %s" % (index, message), 400, "invalid_business_event",
        details={"index": index, "field": field},
    )


def _parse_business_time(value, index, field):
    if not isinstance(value, str) or len(value) > 40:
        raise _business_problem(index, field, "must be an ISO 8601 time with its offset.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _business_problem(index, field, "must be an ISO 8601 time with its offset.")
    if parsed.tzinfo is None:
        raise _business_problem(index, field, "must carry a UTC offset.")
    return parsed.astimezone(timezone.utc)


def _parse_business_event(event, index):
    if not isinstance(event, dict):
        raise _business_problem(index, "event", "must be an object.")
    unknown = sorted(set(event) - _BUSINESS_EVENT_FIELDS)
    if unknown:
        raise _business_problem(index, unknown[0], "is not a known field; nothing else is stored.")
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", event_id) is None:
        raise _business_problem(index, "event_id", "must be 1-64 of A-Z a-z 0-9 . _ : -")
    if ("account_id" in event) == ("handle" in event):
        raise _business_problem(index, "account_id", "give exactly one of account_id or handle.")
    account_id = (
        _uuid_text(event["account_id"], "account_id") if "account_id" in event else None
    )
    lookup = _handle_lookup(event["handle"]) if "handle" in event else None
    event_type = event.get("type")
    if not isinstance(event_type, str) or re.fullmatch(r"[a-z][a-z0-9_]{1,47}", event_type) is None:
        raise _business_problem(index, "type", "must be a short code: a-z, 0-9, _.")
    allowed = _risk_setting_words("business_event_types", "")
    if allowed and event_type not in allowed:
        raise _business_problem(index, "type", "is not among the DBA's business_event_types.")
    occurred_at = _parse_business_time(event.get("occurred_at"), index, "occurred_at")
    if occurred_at > _utc_now() + timedelta(minutes=5):
        raise _business_problem(index, "occurred_at", "is in the future.")
    amount = event.get("amount_minor")
    currency = event.get("currency")
    if amount is not None:
        if isinstance(amount, bool) or not isinstance(amount, int) or not 0 <= amount <= (1 << 53):
            raise _business_problem(index, "amount_minor", "must be a whole number of minor units.")
        if not isinstance(currency, str) or re.fullmatch(r"[A-Z]{3}", currency) is None:
            raise _business_problem(index, "currency", "an amount needs its ISO 4217 currency.")
    elif currency is not None:
        raise _business_problem(index, "currency", "is only given with an amount.")
    outcome = event.get("outcome")
    if outcome is not None and (
        not isinstance(outcome, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,31}", outcome) is None
    ):
        raise _business_problem(index, "outcome", "must be a short code: a-z, 0-9, _.")
    subject = event.get("subject_ref")
    if subject is not None and (not isinstance(subject, str) or not 1 <= len(subject) <= 256):
        raise _business_problem(index, "subject_ref", "must be 1-256 characters.")
    return {
        "event_id": event_id,
        "account_id": account_id,
        "lookup": lookup,
        "type": event_type,
        "occurred_at": occurred_at,
        "amount_minor": amount,
        "currency": currency,
        "outcome": outcome,
        # Only a keyed hash is kept: accounts that share a payee can be
        # linked, and the payee itself is never stored.
        "subject_hash": hmac.new(
            _BUSINESS_SUBJECT_PEPPER, subject.encode("utf-8"), hashlib.sha256
        ).hexdigest() if subject is not None else None,
    }


@app.post("/v1/business/events")
def business_events():
    """Record business events for accounts; each event once (its event_id)."""
    _require_business_caller()
    body = _json_body()
    events = body.get("events")
    if set(body) - {"events"} or not isinstance(events, list) or not 1 <= len(events) <= 100:
        raise ApiProblem(
            'Send {"events": [...]} with 1-100 events.', 400, "invalid_business_events"
        )
    parsed = [_parse_business_event(event, index) for index, event in enumerate(events)]
    results = []
    with _cursor(commit=True) as cursor:
        for event in parsed:
            if event["account_id"] is not None:
                cursor.execute(
                    "SELECT account_id FROM demo_accounts WHERE account_id = %s",
                    (event["account_id"],),
                )
            else:
                cursor.execute(
                    "SELECT account_id FROM demo_accounts WHERE handle_lookup = %s",
                    (event["lookup"],),
                )
            row = cursor.fetchone()
            if row is None:
                results.append({"event_id": event["event_id"], "status": "rejected",
                                "code": "unknown_account"})
                continue
            savepoint = DIALECT.savepoint("business_event")
            if savepoint:
                cursor.execute(savepoint[0])
            try:
                cursor.execute(
                    """
                    INSERT INTO business_events
                        (event_id, account_id, event_type, occurred_at, amount_minor,
                         currency, outcome, subject_hash)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (event["event_id"], str(row[0]), event["type"], event["occurred_at"],
                     event["amount_minor"], event["currency"], event["outcome"],
                     event["subject_hash"]),
                )
            except Exception as error:
                if not DIALECT.is_unique_violation(error):
                    raise
                if savepoint:
                    cursor.execute(savepoint[1])
                results.append({"event_id": event["event_id"], "status": "duplicate"})
            else:
                if savepoint:
                    cursor.execute(savepoint[2])
                results.append({"event_id": event["event_id"], "status": "accepted"})
    counts = {state: sum(1 for r in results if r["status"] == state)
              for state in ("accepted", "duplicate", "rejected")}
    return jsonify(dict(counts, results=results))


def _business_event_counts(device_id, account_id):
    """Event counts by type in the last 30 days: this account's, and those of
    every account linked to this phone."""
    cutoff = _utc_now() - timedelta(days=30)
    counts = {"account": {}, "device": {}}
    with _cursor() as cursor:
        if account_id is not None:
            cursor.execute(
                """
                SELECT event_type, COUNT(*) FROM business_events
                WHERE account_id = %s AND occurred_at >= %s
                GROUP BY event_type
                """,
                (account_id, cutoff),
            )
            counts["account"] = {str(r[0]): int(r[1]) for r in cursor.fetchall() or []}
        cursor.execute(
            """
            SELECT e.event_type, COUNT(*) FROM business_events e
            JOIN device_account_links l ON l.account_id = e.account_id
            WHERE l.device_id = %s AND e.occurred_at >= %s
            GROUP BY e.event_type
            """,
            (device_id, cutoff),
        )
        counts["device"] = {str(r[0]): int(r[1]) for r in cursor.fetchall() or []}
    return counts


def _observation_windows(cursor, column, value):
    """The server's own observations (DESIGN.md 77) on one account or phone,
    by kind, in the last 1, 7 and 30 days. `column` is account_id or
    device_id, never caller input."""
    now = _utc_now()
    cutoffs = {label: now - timedelta(days=days) for label, days in _BUSINESS_WINDOWS}
    cursor.execute(
        """
        SELECT kind,
               SUM(CASE WHEN occurred_at >= %s THEN 1 ELSE 0 END),
               SUM(CASE WHEN occurred_at >= %s THEN 1 ELSE 0 END),
               COUNT(*)
        FROM server_observations
        WHERE """ + column + """ = %s AND occurred_at >= %s
        GROUP BY kind
        """,
        (cutoffs["1d"], cutoffs["7d"], value, cutoffs["30d"]),
    )
    found = {
        str(kind): {"1d": int(day or 0), "7d": int(week or 0), "30d": int(month or 0)}
        for kind, day, week, month in cursor.fetchall() or []
    }
    if column == "device_id":
        # Denied approval requests are rows of session_upgrade_requests.
        cursor.execute(
            """
            SELECT SUM(CASE WHEN denied_at >= %s THEN 1 ELSE 0 END),
                   SUM(CASE WHEN denied_at >= %s THEN 1 ELSE 0 END),
                   COUNT(*)
            FROM session_upgrade_requests
            WHERE device_id = %s AND denied_at >= %s
            """,
            (cutoffs["1d"], cutoffs["7d"], value, cutoffs["30d"]),
        )
        day, week, month = cursor.fetchone()
        if month:
            found["approval_denied"] = {
                "1d": int(day or 0), "7d": int(week or 0), "30d": int(month),
            }
    return found


def _business_account_node(cursor, account_id):
    now = _utc_now()
    cutoffs = {label: now - timedelta(days=days) for label, days in _BUSINESS_WINDOWS}
    cursor.execute("SELECT created_at FROM demo_accounts WHERE account_id = %s", (account_id,))
    row = cursor.fetchone()
    cursor.execute(
        """
        SELECT event_type, currency,
               SUM(CASE WHEN occurred_at >= %s THEN 1 ELSE 0 END),
               SUM(CASE WHEN occurred_at >= %s THEN 1 ELSE 0 END),
               COUNT(*),
               SUM(COALESCE(amount_minor, 0))
        FROM business_events
        WHERE account_id = %s AND occurred_at >= %s
        GROUP BY event_type, currency
        """,
        (cutoffs["1d"], cutoffs["7d"], account_id, cutoffs["30d"]),
    )
    events = {}
    for event_type, currency, day, week, month, amount in cursor.fetchall() or []:
        entry = events.setdefault(str(event_type), {"1d": 0, "7d": 0, "30d": 0, "amount_30d": {}})
        entry["1d"] += int(day or 0)
        entry["7d"] += int(week or 0)
        entry["30d"] += int(month or 0)
        if currency:
            entry["amount_30d"][str(currency)] = int(amount or 0)
    cursor.execute(
        """
        SELECT COUNT(DISTINCT e2.account_id)
        FROM business_events e1
        JOIN business_events e2
          ON e2.subject_hash = e1.subject_hash AND e2.account_id <> e1.account_id
        WHERE e1.account_id = %s AND e1.subject_hash IS NOT NULL
          AND e1.occurred_at >= %s AND e2.occurred_at >= %s
        """,
        (account_id, cutoffs["30d"], cutoffs["30d"]),
    )
    shared = cursor.fetchone()
    return {
        "account_id": account_id,
        "created_at": _iso_z(row[0]) if row else None,
        "business_events": events,
        "accounts_sharing_a_subject_30d": int(shared[0]) if shared else 0,
        "server_observations": _observation_windows(cursor, "account_id", account_id),
    }


def _business_device_node(cursor, device_id):
    cursor.execute(
        """
        SELECT platform, status, created_at, last_seen_at FROM recognized_devices
        WHERE device_id = %s
        """,
        (device_id,),
    )
    row = cursor.fetchone()
    cursor.execute(
        "SELECT COUNT(*) FROM app_installations WHERE device_id = %s", (device_id,)
    )
    installations = int(cursor.fetchone()[0])
    cursor.execute(
        """
        SELECT verdict, evidence_quality, created_at FROM integrity_reports
        WHERE device_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (device_id,),
    )
    report = cursor.fetchone()
    return {
        "device_id": device_id,
        "platform": row[0] if row else None,
        "status": row[1] if row else None,
        "first_seen_at": _iso_z(row[2]) if row else None,
        "last_seen_at": _iso_z(row[3]) if row else None,
        "installations": installations,
        "latest_integrity": {
            "verdict": report[0], "evidence_quality": report[1],
            "created_at": _iso_z(report[2]),
        } if report else None,
        "server_observations": _observation_windows(cursor, "device_id", device_id),
    }


@app.get("/v1/business/graph")
def business_graph():
    """The phone-account graph around one account or phone, with business
    events per account and per component (DESIGN.md 76). Walked one
    parameterised query per node -- no recursive SQL -- to the DBA's
    business_graph_depth, cut at business_graph_max_nodes."""
    _require_business_caller()
    args = request.args
    given = [key for key in ("account_id", "device_id", "handle") if args.get(key)]
    if len(given) != 1:
        raise ApiProblem(
            "Give exactly one of account_id, device_id or handle.", 400, "invalid_graph_query"
        )
    depth = min(4, max(1, _risk_setting_int("business_graph_depth", 2)))
    limit = max(1, _risk_setting_int("business_graph_max_nodes", 200))
    with _cursor() as cursor:
        if given[0] == "handle":
            cursor.execute(
                "SELECT account_id FROM demo_accounts WHERE handle_lookup = %s",
                (_handle_lookup(args["handle"]),),
            )
            row = cursor.fetchone()
            if row is None:
                raise ApiProblem("No such account.", 404, "unknown_account")
            start = ("account", str(row[0]))
        else:
            kind = given[0][: -len("_id")]
            start = (kind, _uuid_text(args[given[0]], given[0]))
        seen = {start: 0}
        frontier = [start]
        edges = {}
        truncated = False
        while frontier:
            kind, node_id = frontier.pop(0)
            hop = seen[(kind, node_id)]
            if hop >= depth:
                continue
            if kind == "account":
                cursor.execute(
                    """
                    SELECT device_id, first_seen_at, last_seen_at FROM device_account_links
                    WHERE account_id = %s
                    """,
                    (node_id,),
                )
                found = [("device", str(r[0]), str(r[0]), node_id, r[1], r[2])
                         for r in cursor.fetchall() or []]
            else:
                cursor.execute(
                    """
                    SELECT account_id, first_seen_at, last_seen_at FROM device_account_links
                    WHERE device_id = %s
                    """,
                    (node_id,),
                )
                found = [("account", str(r[0]), node_id, str(r[0]), r[1], r[2])
                         for r in cursor.fetchall() or []]
            for other_kind, other_id, device_id, account_id, first, last in found:
                if (other_kind, other_id) not in seen:
                    if len(seen) >= limit:
                        truncated = True
                        continue
                    seen[(other_kind, other_id)] = hop + 1
                    frontier.append((other_kind, other_id))
                edges[(device_id, account_id)] = {
                    "device_id": device_id, "account_id": account_id,
                    "first_seen_at": _iso_z(first), "last_seen_at": _iso_z(last),
                }
        accounts = [_business_account_node(cursor, node_id)
                    for kind, node_id in seen if kind == "account"]
        devices = [_business_device_node(cursor, node_id)
                   for kind, node_id in seen if kind == "device"]
    for device in devices:
        # No calling installation: only the device's established ones count.
        memory = _device_integrity_memory(device["device_id"], None)
        device["integrity_memory_block"] = bool(memory and memory.get("finding_verdict") == "block")
    component = {}
    for account in accounts:
        for event_type, entry in account["business_events"].items():
            total = component.setdefault(event_type, {"events_30d": 0, "accounts_30d": 0})
            total["events_30d"] += entry["30d"]
            total["accounts_30d"] += 1 if entry["30d"] else 0
    return jsonify({
        "start": {"kind": start[0], "id": start[1]},
        "depth": depth,
        "truncated": truncated,
        "accounts": accounts,
        "devices": devices,
        "links": [edges[key] for key in sorted(edges)],
        "component_business_events_30d": component,
    })


_SUPPORT_REFERENCE = re.compile(r"[A-Za-z0-9._:-]{1,64}")


def _app_pin_support(action):
    """Support staff unlock a customer's locked app PIN -- or, where the DBA
    allows it, also open one reset (DESIGN.md 79). Server to server: the
    company's support tool calls it after verifying the customer, naming the
    account (or handle) and its own ticket reference, which is recorded with
    the action. Off unless the DBA sets app_pin_support."""
    _require_business_caller()
    allowed = {"unlock": ("unlock", "unlock_and_reset"), "reset": ("unlock_and_reset",)}[action]
    if _risk_setting_str("app_pin_support", "off") not in allowed:
        raise ApiProblem(
            "Support %s of app PINs is not enabled here (app_pin_support)." % action,
            403,
            "app_pin_support_disabled",
        )
    body = _json_body()
    unknown = sorted(set(body) - {"account_id", "handle", "reference"})
    if unknown:
        raise ApiProblem("%s is not a known field." % unknown[0], 400, "invalid_support_request",
                         details={"field": unknown[0]})
    reference = body.get("reference")
    if not isinstance(reference, str) or _SUPPORT_REFERENCE.fullmatch(reference) is None:
        raise ApiProblem("reference, your ticket, must be 1-64 of A-Z a-z 0-9 . _ : -",
                         400, "invalid_support_request", details={"field": "reference"})
    if ("account_id" in body) == ("handle" in body):
        raise ApiProblem("Give exactly one of account_id or handle.", 400,
                         "invalid_support_request", details={"field": "account_id"})
    with _cursor() as cursor:
        if "account_id" in body:
            cursor.execute("SELECT account_id FROM demo_accounts WHERE account_id = %s",
                           (_uuid_text(body["account_id"], "account_id"),))
        else:
            cursor.execute("SELECT account_id FROM demo_accounts WHERE handle_lookup = %s",
                           (_handle_lookup(body["handle"]),))
        row = cursor.fetchone()
    if row is None:
        raise ApiProblem("No such account.", 404, "unknown_account")
    account_id = str(row[0])
    reset_until = None
    with _cursor(commit=True) as cursor:
        if action == "unlock":
            cursor.execute(
                "UPDATE app_pins SET failures = 0, locked_at = NULL "
                "WHERE account_id = %s AND pin_hash IS NOT NULL",
                (account_id,),
            )
            if cursor.rowcount != 1:
                raise ApiProblem("This account has no app PIN to unlock.", 404, "app_pin_not_set")
        else:
            reset_until = _utc_now() + timedelta(
                minutes=_risk_setting_int("app_pin_support_reset_minutes", 15))
            update = ("UPDATE app_pins SET failures = 0, locked_at = NULL, reset_until = %s "
                      "WHERE account_id = %s")
            cursor.execute(update, (reset_until, account_id))
            if cursor.rowcount == 0:
                # No PIN yet: the row holds only the reset. Two at once: the
                # loser's INSERT hits the key, and it simply updates.
                savepoint = DIALECT.savepoint("app_pin_support")
                if savepoint:
                    cursor.execute(savepoint[0])
                try:
                    cursor.execute(
                        "INSERT INTO app_pins (account_id, pin_hash, reset_until) "
                        "VALUES (%s, NULL, %s)",
                        (account_id, reset_until),
                    )
                except Exception as error:
                    if not DIALECT.is_unique_violation(error):
                        raise
                    if savepoint:
                        cursor.execute(savepoint[1])
                    cursor.execute(update, (reset_until, account_id))
                else:
                    if savepoint:
                        cursor.execute(savepoint[2])
        _record_observation(
            "app_pin_support_unlocked" if action == "unlock" else "app_pin_support_reset",
            reference, None, None, account_id=account_id, cursor=cursor,
        )
    logger.warning("App PIN support %s: account=%s reference=%s", action, account_id, reference)
    return jsonify({"account_id": account_id, "unlocked": True,
                    "reset_until": _iso_z(reset_until) if reset_until else None})


@app.post("/v1/business/app-pin/unlock")
def business_app_pin_unlock():
    return _app_pin_support("unlock")


@app.post("/v1/business/app-pin/reset")
def business_app_pin_reset():
    return _app_pin_support("reset")


@app.get("/v1/business/acceptance-lapses")
def business_acceptance_lapses():
    """When an approved session met a reason its approval did not cover, and
    which (DESIGN.md 76) -- oldest first, after ?since=<ISO time>, then page
    with ?cursor=<next_cursor>. A row appears once per acceptance and reason;
    (acceptance_id, reason_code) is its key. The cursor carries the last row's
    time and key, so rows sharing a timestamp at a page edge are not skipped."""
    _require_business_caller()
    # Without a cursor nothing at the "since" instant itself is returned: the
    # highest possible key makes the tie branch empty, on both engines.
    after_acceptance, after_reason = "ffffffff-ffff-ffff-ffff-ffffffffffff", ""
    cursor_text = request.args.get("cursor")
    if cursor_text:
        parts = cursor_text.split("|")
        if len(parts) != 3:
            raise ApiProblem("cursor is not one this server issued.", 400, "invalid_cursor")
        since = _parse_business_time(parts[0], 0, "cursor")
        after_acceptance = _uuid_text(parts[1], "cursor")
        after_reason = parts[2][:96]
    elif request.args.get("since"):
        since = _parse_business_time(request.args.get("since"), 0, "since")
    else:
        since = datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        limit = min(1000, max(1, int(request.args.get("limit", "100"))))
    except ValueError:
        raise ApiProblem("limit must be a whole number.", 400, "invalid_limit")
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT acceptance_id, reason_code, source, points, account_id,
                   installation_id, event_type, occurred_at
            FROM acceptance_lapses
            WHERE occurred_at > %s
               OR (occurred_at = %s
                   AND (acceptance_id > %s
                        OR (acceptance_id = %s AND reason_code > %s)))
            ORDER BY occurred_at, acceptance_id, reason_code
            LIMIT """ + str(limit),
            (since, since, after_acceptance, after_acceptance, after_reason),
        )
        rows = cursor.fetchall() or []
    lapses = [
        {"acceptance_id": str(r[0]), "reason_code": r[1], "source": r[2], "points": int(r[3]),
         "account_id": str(r[4]), "installation_id": str(r[5]), "event_type": r[6],
         "occurred_at": _iso_z(r[7])}
        for r in rows
    ]
    last = lapses[-1] if lapses else None
    return jsonify({
        "lapses": lapses,
        "next_cursor": ("%s|%s|%s" % (last["occurred_at"], last["acceptance_id"],
                                      last["reason_code"])) if last else cursor_text,
    })


_REPORT_FILTERS = ("device_id", "installation_id", "account_id")


@app.get("/v1/business/integrity-reports")
def business_integrity_reports():
    """Every integrity report as stored, measurements included (DESIGN.md 79):
    what the phone measured (probe_results), the reasons and score this server
    derived from it, and when. Oldest first, after ?since=<ISO time>, then page
    with ?cursor=<next_cursor>, like the lapse feed. At most one filter:
    ?device_id=, ?installation_id=, or ?account_id= -- the reports of every
    phone linked to the account, from before the link too, since a report
    describes the phone, not the account. probe_results identify a phone
    (model, build, installed tools): the business holds them as such."""
    _require_business_caller()
    given = [name for name in _REPORT_FILTERS if request.args.get(name)]
    if len(given) > 1:
        raise ApiProblem("Give at most one of device_id, installation_id or account_id.", 400,
                         "invalid_filter", details={"field": given[1]})
    after_report = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    cursor_text = request.args.get("cursor")
    if cursor_text:
        parts = cursor_text.split("|")
        if len(parts) != 2:
            raise ApiProblem("cursor is not one this server issued.", 400, "invalid_cursor")
        since = _parse_business_time(parts[0], 0, "cursor")
        after_report = _uuid_text(parts[1], "cursor")
    elif request.args.get("since"):
        since = _parse_business_time(request.args.get("since"), 0, "since")
    else:
        since = datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        limit = min(200, max(1, int(request.args.get("limit", "50"))))
    except ValueError:
        raise ApiProblem("limit must be a whole number.", 400, "invalid_limit")
    where, values = "", []
    if given:
        value = _uuid_text(request.args.get(given[0]), given[0])
        where = ("device_id IN (SELECT device_id FROM device_account_links "
                 "WHERE account_id = %s) AND " if given[0] == "account_id"
                 else given[0] + " = %s AND ")
        values.append(value)
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT report_id, installation_id, device_id, platform, collector_version,
                   score, verdict, hard_block, evidence_quality, finding_score,
                   reasons, probe_results, report_sha256, created_at
            FROM integrity_reports
            WHERE """ + where + """(created_at > %s OR (created_at = %s AND report_id > %s))
            ORDER BY created_at, report_id
            LIMIT """ + str(limit),
            tuple(values) + (since, since, after_report),
        )
        rows = cursor.fetchall() or []
    reports = [
        {"report_id": str(r[0]), "installation_id": str(r[1]), "device_id": str(r[2]),
         "platform": r[3], "collector_version": int(r[4]), "score": int(r[5]),
         "verdict": r[6], "hard_block": bool(r[7]), "evidence_quality": r[8],
         "finding_score": None if r[9] is None else int(r[9]),
         "reasons": _as_list(DIALECT.json_value(r[10])),
         "probe_results": DIALECT.json_value(r[11]), "report_sha256": r[12],
         "created_at": _iso_z(r[13])}
        for r in rows
    ]
    last = reports[-1] if reports else None
    return jsonify({
        "reports": reports,
        "next_cursor": ("%s|%s" % (last["created_at"], last["report_id"])) if last
        else cursor_text,
    })


if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "0.0.0.0"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
    )
