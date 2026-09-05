"""
Device-recognition API for the Flutter proof of concept.

Python compatibility: 3.9+
Runtime dependencies:
    Flask
    Flask-JWT-Extended 4.x
    psycopg2-binary
    bcrypt
    pycryptodome

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
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Flask, jsonify, request
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

ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
DEVICE_TOKEN_LIFETIME = timedelta(minutes=10)
REFRESH_TOKEN_LIFETIME = timedelta(days=30)
CHALLENGE_LIFETIME = timedelta(minutes=2)
ACCESS_PROOF_MAX_SKEW_SECONDS = 120
ACCESS_PROOF_NONCE_RETENTION = timedelta(minutes=10)

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

POLICY_STEP_UP_SCORE = int(os.environ.get("POLICY_STEP_UP_SCORE", "30"))
POLICY_REVIEW_SCORE = int(os.environ.get("POLICY_REVIEW_SCORE", "60"))
POLICY_BLOCK_SCORE = int(os.environ.get("POLICY_BLOCK_SCORE", "90"))
POLICY_REINSTALL_WINDOW_HOURS = int(
    os.environ.get("POLICY_REINSTALL_WINDOW_HOURS", "24")
)
POLICY_DEVICE_ACCOUNT_BLOCK_COUNT = int(
    os.environ.get("POLICY_DEVICE_ACCOUNT_BLOCK_COUNT", "5")
)
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
EXPECTED_IOS_BUNDLE_ID = os.environ.get("INTEGRITY_IOS_BUNDLE_ID", "").strip()
EXPECTED_IOS_SIGNING_ID = os.environ.get("INTEGRITY_IOS_SIGNING_ID", "").strip()
EXPECTED_IOS_TEAM_ID = os.environ.get("INTEGRITY_IOS_TEAM_ID", "").strip()
EXPECTED_IOS_EXECUTABLE_SHA256 = _env_values("INTEGRITY_IOS_EXECUTABLE_SHA256")

REQUIRE_HTTPS = os.environ.get("REQUIRE_HTTPS", "0") == "1"
MAX_OPEN_CHALLENGES_PER_INSTALLATION = 5

app = Flask(__name__)
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
    forwarded_proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    if forwarded_proto.lower() != "https":
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

    def row_lock_suffix(self):
        """Statement suffix that takes an exclusive row lock."""
        return ""

    def row_lock_hint(self):
        """Table hint that takes an exclusive row lock."""
        return ""


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


class SqlServerDialect(Dialect):
    """SQL Server 2017+ (written to 2016-compatible T-SQL).

    Only the token-level translation lives here; the statements whose shape
    differs (LIMIT/TOP, FOR UPDATE/UPDLOCK, RETURNING/OUTPUT, ON CONFLICT) are
    selected explicitly at their call sites.
    """

    name = "sqlserver"
    paramstyle = "qmark"

    def connect(self):
        import pyodbc  # imported lazily so PostgreSQL deployments need no ODBC

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
        return pyodbc.connect(";".join(parts))

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

    def row_lock_hint(self):
        # PostgreSQL is MVCC; SQL Server READ COMMITTED takes shared locks and
        # would let refresh-reuse detection be raced without this.
        return " WITH (UPDLOCK, ROWLOCK)"


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
        return self._cursor.execute(translated, parameters)

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


def _enforce_rate_limit(bucket, identity):
    """Throttle repeated attempts. Fails open by design."""
    if not RATE_LIMIT_ENABLED or not REDIS_URL:
        return
    key = "dt:rate:%s:%s" % (bucket, identity)
    try:
        client = _redis()
        attempts = client.incr(key)
        if attempts == 1:
            client.expire(key, RATE_LIMIT_WINDOW_SECONDS)
    except Exception:
        logger.exception("The Redis rate limiter is unreachable; allowing.")
        return
    if attempts > RATE_LIMIT_MAX_ATTEMPTS:
        raise ApiProblem(
            "Too many attempts. Try again shortly.",
            429,
            "rate_limited",
        )


def _connect_db():
    return DIALECT.connect()


@contextmanager
def _cursor(commit=False):
    connection = _connect_db()
    cursor = _DialectCursor(connection.cursor())
    try:
        yield cursor
        if commit:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


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
    with _backend_identity_lock:
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

REQUIRED_SCHEMA_VERSION = 1

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
    with _schema_lock:
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
        ]
        optional = [
            "emulator",
            "developer_settings",
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
        optional = ["environment", "simulator"]
    else:
        raise ApiProblem("Unsupported integrity platform.", 400, "unsupported_platform")

    pool = list(optional)
    chosen = []
    target = min(max(INTEGRITY_RANDOM_OPTIONAL_PROBES, 0), len(pool))
    while pool and len(chosen) < target:
        chosen.append(pool.pop(secrets.randbelow(len(pool))))
    return mandatory + chosen


def _integrity_reason(reasons, code, points, message, hard=False):
    reasons.append(
        {
            "code": code,
            "points": int(points),
            "message": message,
            "hard": bool(hard),
        }
    )


def _probe(probes, name):
    value = probes.get(name)
    return value if isinstance(value, dict) else {}


def _as_bool(value):
    return value is True


def _as_text(value):
    return value.strip() if isinstance(value, str) else ""


def _as_list(value):
    return value if isinstance(value, list) else []


def _integrity_verdict(score, hard_block=False):
    if hard_block or score >= 90:
        return "block"
    if score >= 60:
        return "review"
    if score >= 30:
        return "elevated"
    return "trusted"


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

    emulator = _probe(probes, "emulator")
    if _as_bool(emulator.get("suspected")) and not INTEGRITY_ALLOW_EMULATOR:
        _integrity_reason(reasons, "android_emulator", 25, "The runtime resembles an Android emulator.")
        score += 25

    dev = _probe(probes, "developer_settings")
    if _as_bool(dev.get("developer_options_enabled")):
        _integrity_reason(reasons, "android_developer_options", 8, "Developer options are enabled.")
        score += 8
    if _as_bool(dev.get("adb_enabled")):
        _integrity_reason(reasons, "android_adb_enabled", 10, "ADB is enabled.")
        score += 10

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

    return score, hard_block, reasons


def _score_integrity(platform, probes):
    if platform == "android":
        score, hard_block, reasons = _score_android_integrity(probes)
    elif platform == "ios":
        score, hard_block, reasons = _score_ios_integrity(probes)
    else:
        raise ApiProblem("Unsupported integrity platform.", 400, "unsupported_platform")
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
            SELECT report_id, score, verdict, hard_block, reasons, created_at
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
        "fresh": age_seconds <= INTEGRITY_FRESHNESS_SECONDS,
    }


def _device_integrity_memory(device_id):
    """Worst native-integrity outcome for this device across all installations.

    Reports are stored per installation, so a reinstall hands the attacker a
    clean slate: the new installation_id has no history of its own. Recognition
    of the physical device survives a reinstall, so the integrity verdict should
    too. This returns the worst report recorded against the canonical device_id
    inside the memory window, which is what stops a compromised device from
    laundering a block by reinstalling the app.
    """
    if INTEGRITY_DEVICE_MEMORY_HOURS <= 0:
        return None
    cutoff = _utc_now() - timedelta(hours=INTEGRITY_DEVICE_MEMORY_HOURS)
    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT report_id, installation_id, score, verdict, hard_block, created_at
            FROM integrity_reports
            WHERE device_id = %s AND created_at >= %s
            ORDER BY hard_block DESC, score DESC, created_at DESC
            LIMIT 1
            """,
            (device_id, cutoff),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    return {
        "report_id": str(row[0]),
        "installation_id": str(row[1]),
        "score": int(row[2]),
        "verdict": row[3],
        "hard_block": bool(row[4]),
        "created_at": _iso_z(row[5]),
        "window_hours": INTEGRITY_DEVICE_MEMORY_HOURS,
    }


def _enforce_integrity_gate(device_id, installation_id):
    state = _latest_integrity_state(installation_id)
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
    if verdict == "review":
        raise ApiProblem(
            "The latest device-integrity verdict requires review.",
            403,
            "integrity_review_required",
            details={"integrity": state},
        )
    if verdict == "elevated":
        raise ApiProblem(
            "The latest device-integrity verdict requires step-up verification.",
            403,
            "integrity_step_up_required",
            details={"integrity": state},
        )
    # This installation's own scan is clean. Before allowing the request, check
    # whether the physical device was blocked recently under any installation:
    # reinstalling must not clear a compromised device's record.
    memory = _device_integrity_memory(device_id)
    if memory is not None and (
        memory.get("hard_block") or memory.get("verdict") == "block"
    ):
        raise ApiProblem(
            "This device recorded a blocked integrity verdict recently; "
            "reinstalling the app does not clear it.",
            403,
            "integrity_device_blocked_recently",
            details={"integrity": state, "device_integrity_memory": memory},
        )
    return state


# ---------------------------------------------------------------------------
# Risk/device policy helpers
# ---------------------------------------------------------------------------


def _policy_reason(reasons, code, points, message):
    reasons.append(
        {
            "code": code,
            "points": int(points),
            "message": message,
        }
    )


def _policy_action(score, hard_block=False):
    if hard_block or score >= POLICY_BLOCK_SCORE:
        return "block"
    if score >= POLICY_REVIEW_SCORE:
        return "review"
    if score >= POLICY_STEP_UP_SCORE:
        return "step_up"
    return "allow"


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
                   d.created_at
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
        ) = installation_row

        cursor.execute(
            "SELECT COUNT(*) FROM device_account_links WHERE device_id = %s",
            (device_id,),
        )
        device_account_count = int(cursor.fetchone()[0])

        cursor.execute(
            "SELECT COUNT(*) FROM app_installations WHERE device_id = %s",
            (device_id,),
        )
        device_installation_count = int(cursor.fetchone()[0])

        reinstall_cutoff = _utc_now() - timedelta(
            hours=POLICY_REINSTALL_WINDOW_HOURS
        )
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM app_installations
            WHERE device_id = %s
              AND registration_method = 'reinstall_hint'
              AND created_at >= %s
            """,
            (device_id, reinstall_cutoff),
        )
        recent_reinstall_count = int(cursor.fetchone()[0])

        link_exists = False
        account_device_count = 0
        if account_id is not None:
            cursor.execute(
                """
                SELECT 1
                FROM device_account_links
                WHERE device_id = %s AND account_id = %s
                """,
                (device_id, account_id),
            )
            link_exists = cursor.fetchone() is not None

            cursor.execute(
                """
                SELECT COUNT(DISTINCT device_id)
                FROM device_account_links
                WHERE account_id = %s
                """,
                (account_id,),
            )
            account_device_count = int(cursor.fetchone()[0])

    add_link = bool(account_id is not None and account_link_pending and not link_exists)
    projected_device_account_count = device_account_count + (1 if add_link else 0)
    projected_account_device_count = account_device_count + (1 if add_link else 0)
    integrity_state = _latest_integrity_state(installation_id)
    device_integrity_memory = _device_integrity_memory(device_id)

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

    device_age = _utc_now() - device_created_at
    if registration_method == "new_device" and device_age <= timedelta(hours=24):
        _policy_reason(
            reasons,
            "new_device",
            10,
            "This recognized device was first seen less than 24 hours ago.",
        )
        score += 10
    elif registration_method == "reinstall_hint":
        _policy_reason(
            reasons,
            "known_device_new_installation",
            15,
            "A new installation was correlated to a previously recognized device.",
        )
        score += 15

    # Accounts sharing one recognized physical device.
    if projected_device_account_count >= POLICY_DEVICE_ACCOUNT_BLOCK_COUNT:
        _policy_reason(
            reasons,
            "device_account_count_block_threshold",
            100,
            "This device is linked to too many unique accounts for the configured policy.",
        )
        hard_block = True
    elif projected_device_account_count >= 3:
        _policy_reason(
            reasons,
            "device_has_many_accounts",
            60,
            "This device is linked to three or more unique accounts.",
        )
        score += 60
    elif projected_device_account_count == 2:
        _policy_reason(
            reasons,
            "device_has_multiple_accounts",
            35,
            "This device is linked to a second unique account.",
        )
        score += 35

    # One account appearing on several recognized physical devices.
    if account_id is not None:
        if projected_account_device_count >= POLICY_ACCOUNT_DEVICE_BLOCK_COUNT:
            _policy_reason(
                reasons,
                "account_device_count_block_threshold",
                100,
                "This account is linked to too many recognized devices for the configured policy.",
            )
            hard_block = True
        elif projected_account_device_count >= 3:
            _policy_reason(
                reasons,
                "account_has_many_devices",
                60,
                "This account is linked to three or more recognized devices.",
            )
            score += 60
        elif projected_account_device_count == 2:
            _policy_reason(
                reasons,
                "account_has_multiple_devices",
                35,
                "This account is being used on a second recognized device.",
            )
            score += 35

    # Reinstall velocity on one server-recognized device.
    if recent_reinstall_count >= POLICY_REINSTALL_BLOCK_COUNT:
        _policy_reason(
            reasons,
            "rapid_reinstall_block_threshold",
            100,
            "The device exceeded the configured reinstall count in the policy window.",
        )
        hard_block = True
    elif recent_reinstall_count >= 4:
        _policy_reason(
            reasons,
            "rapid_reinstall_high",
            60,
            "Four or more correlated reinstalls occurred inside the policy window.",
        )
        score += 60
    elif recent_reinstall_count >= 3:
        _policy_reason(
            reasons,
            "rapid_reinstall_elevated",
            35,
            "Three correlated reinstalls occurred inside the policy window.",
        )
        score += 35

    # Latest server-scored native integrity result. Missing/stale measurements
    # are themselves risk, while a fresh report contributes its server-owned score.
    if integrity_state is None:
        _policy_reason(
            reasons,
            "integrity_report_missing",
            40,
            "No signed native integrity report exists for this installation.",
        )
        score += 40
    elif not integrity_state.get("fresh"):
        _policy_reason(
            reasons,
            "integrity_report_stale",
            35,
            "The latest native integrity report is older than the freshness window.",
        )
        score += 35
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
        device_integrity_memory.get("hard_block")
        or device_integrity_memory.get("verdict") == "block"
    ):
        if device_integrity_memory.get("installation_id") != str(installation_id):
            _policy_reason(
                reasons,
                "device_integrity_history_block",
                50,
                "Another installation on this device was blocked by native "
                "integrity inside the device memory window.",
            )
            score += 50

    recommended_action = _policy_action(score, hard_block=hard_block)
    effective_action = (
        recommended_action if DEVICE_POLICY_MODE == "enforce" else "allow"
    )
    decision_id = str(uuid.uuid4())
    context = {
        "platform": platform,
        "registration_method": registration_method,
        "registration_confidence": registration_confidence,
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
        "reinstall_window_hours": POLICY_REINSTALL_WINDOW_HOURS,
        "integrity": integrity_state,
        "integrity_mode": INTEGRITY_MODE,
        "integrity_freshness_seconds": INTEGRITY_FRESHNESS_SECONDS,
        "device_integrity_memory": device_integrity_memory,
        "device_integrity_memory_hours": INTEGRITY_DEVICE_MEMORY_HOURS,
    }
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
        "thresholds": {
            "step_up": POLICY_STEP_UP_SCORE,
            "review": POLICY_REVIEW_SCORE,
            "block": POLICY_BLOCK_SCORE,
        },
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


def _enforce_risk_policy(decision):
    action = decision.get("effective_action")
    if action == "allow":
        return

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


def _require_trusted_account_request(event_type="protected_request"):
    """One server-owned gate for normal authenticated Payactiv-style APIs.

    Order matters: first prove possession of the installation key for this exact
    HTTP request, then require a fresh integrity report, then calculate the
    server-side device/account policy and enforce its effective action.
    """
    claims = _require_access_proof("account")
    integrity = _enforce_integrity_gate(claims.get("did"), claims.get("iid"))
    policy = _evaluate_risk_policy(
        event_type,
        claims.get("did"),
        claims.get("iid"),
        account_id=str(get_jwt_identity()),
        account_link_pending=False,
        persist=True,
    )
    _enforce_risk_policy(policy)
    return claims, policy, integrity


# ---------------------------------------------------------------------------
# Challenge and token helpers
# ---------------------------------------------------------------------------


def _create_challenge(installation_id, purpose):
    now = _utc_now()
    expires_at = now + CHALLENGE_LIFETIME
    challenge_id = str(uuid.uuid4())
    payload = {
        "challenge_id": challenge_id,
        "expires_at": _iso_z(expires_at),
        "installation_id": installation_id,
        "nonce": _b64url_encode(secrets.token_bytes(32)),
        "purpose": purpose,
        "version": 1,
    }
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    with _cursor(commit=True) as cursor:
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

        cursor.execute(
            """
            DELETE FROM installation_challenges
            WHERE expires_at < NOW() - INTERVAL '1 day'
            """
        )
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM installation_challenges
            WHERE installation_id = %s
              AND used_at IS NULL
              AND expires_at > NOW()
            """,
            (installation_id,),
        )
        if cursor.fetchone()[0] >= MAX_OPEN_CHALLENGES_PER_INSTALLATION:
            raise ApiProblem(
                "Too many open challenges. Complete or wait for an existing challenge.",
                429,
                "too_many_challenges",
            )

        cursor.execute(
            """
            INSERT INTO installation_challenges
                (challenge_id, installation_id, purpose, payload_sha256, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (challenge_id, installation_id, purpose, payload_hash, expires_at),
        )

    return {
        "challenge_id": challenge_id,
        "payload": _b64url_encode(payload_bytes),
        "expires_at": _iso_z(expires_at),
    }


def _verify_challenge(
    installation_id, challenge_id, payload_b64, signature_b64, expected_purpose
):
    payload_bytes = _b64url_decode(payload_b64, "payload", 4096)
    signature = _b64url_decode(signature_b64, "signature", 1024)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    with _cursor() as cursor:
        cursor.execute(
            """
            SELECT c.installation_id,
                   c.purpose,
                   c.payload_sha256,
                   c.expires_at,
                   c.used_at,
                   i.key_algorithm,
                   i.public_key_jwk,
                   i.device_id,
                   i.key_thumbprint,
                   i.status,
                   d.status
            FROM installation_challenges c
            JOIN app_installations i
              ON i.installation_id = c.installation_id
            JOIN recognized_devices d
              ON d.device_id = i.device_id
            WHERE c.challenge_id = %s
            """,
            (challenge_id,),
        )
        row = cursor.fetchone()

    if row is None:
        raise ApiProblem("The challenge was not found.", 404, "challenge_not_found")

    (
        stored_installation_id,
        purpose,
        stored_payload_hash,
        expires_at,
        used_at,
        key_algorithm,
        public_key_jwk,
        device_id,
        key_thumbprint,
        installation_status,
        device_status,
    ) = row
    stored_installation_id = str(stored_installation_id)
    device_id = str(device_id)

    if stored_installation_id != installation_id:
        raise ApiProblem(
            "The challenge belongs to another installation.",
            401,
            "challenge_installation_mismatch",
        )
    if purpose != expected_purpose:
        raise ApiProblem(
            "The challenge purpose does not match this operation.",
            401,
            "challenge_purpose_mismatch",
        )
    if installation_status != "active":
        raise ApiProblem(
            "The installation is not active.", 403, "installation_inactive"
        )
    if device_status != "active":
        raise ApiProblem(
            "The recognized device is not active.", 403, "device_inactive"
        )
    if used_at is not None:
        raise ApiProblem("The challenge has already been used.", 401, "challenge_used")
    if expires_at <= _utc_now():
        raise ApiProblem("The challenge has expired.", 401, "challenge_expired")
    if not hmac.compare_digest(stored_payload_hash, payload_hash):
        raise ApiProblem(
            "The challenge payload was modified.", 401, "challenge_payload_mismatch"
        )

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
    if (
        decoded_payload.get("challenge_id") != challenge_id
        or decoded_payload.get("installation_id") != installation_id
        or decoded_payload.get("purpose") != expected_purpose
    ):
        raise ApiProblem(
            "The challenge payload fields do not match the server record.",
            401,
            "challenge_payload_mismatch",
        )

    _verify_installation_signature(
        key_algorithm, public_key_jwk, payload_bytes, signature
    )

    # Consume the challenge atomically after cryptographic verification.
    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            UPDATE installation_challenges
            SET used_at = NOW()
            WHERE challenge_id = %s
              AND used_at IS NULL
              AND expires_at > NOW()
            """,
            (challenge_id,),
        )
        # rowcount, not RETURNING/OUTPUT: the conditional UPDATE is itself the
        # atomic single-use check on both engines, and rowcount reports it
        # portably. SET NOCOUNT must stay OFF for this to hold on SQL Server.
        if cursor.rowcount == 0:
            raise ApiProblem(
                "The challenge was already consumed or expired.",
                401,
                "challenge_not_consumable",
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


def _require_access_proof(required_role="account"):
    """Verify a one-request proof of possession for the current access token.

    The client signs the exact base64url-decoded proof JSON bytes. The server
    then verifies that those signed fields describe this exact HTTP request:
    token hash, installation id, method, path, body hash, timestamp and nonce.
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

    if proof.get("version") != 1:
        raise ApiProblem(
            "The access proof version is unsupported.",
            400,
            "unsupported_access_proof_version",
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
    # Phone A, signed by Phone B's non-exportable key, fails here.
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
        _claim_nonce_redis(nonce_hash, installation_id)

    with _cursor(commit=True) as cursor:
        if NONCE_BACKEND == "database":
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

    return claims


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


def _link_device_account(cursor, device_id, account_id, installation_id):
    # Portable upsert: update first, insert only if nothing was updated. A
    # concurrent insert losing the race raises a duplicate key, which means the
    # link already exists - the desired end state either way.
    cursor.execute(
        """
        UPDATE device_account_links
        SET last_seen_at = NOW()
        WHERE device_id = %s AND account_id = %s
        """,
        (device_id, account_id),
    )
    if cursor.rowcount == 0:
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


def _issue_account_tokens(
    cursor, account_id, device_id, installation_id, family_id=None, policy=None
):
    family_id = family_id or str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    claims = {
        "role": "account",
        "did": device_id,
        "iid": installation_id,
        "sid": session_id,
        "family": family_id,
    }
    access_token = create_access_token(
        identity=account_id,
        additional_claims=claims,
        expires_delta=ACCESS_TOKEN_LIFETIME,
    )
    refresh_token = create_refresh_token(
        identity=account_id,
        additional_claims=claims,
        expires_delta=REFRESH_TOKEN_LIFETIME,
    )
    cursor.execute(
        """
        INSERT INTO refresh_sessions
            (session_id, family_id, account_id, device_id, installation_id, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            session_id,
            family_id,
            account_id,
            device_id,
            installation_id,
            _utc_now() + REFRESH_TOKEN_LIFETIME,
        ),
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "refresh_session_id": session_id,
        "account_id": account_id,
        "device_id": device_id,
        "installation_id": installation_id,
        "policy": policy,
    }


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
               expires_at, revoked_at
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

    stored_family, stored_account, stored_device, stored_installation, expires_at, revoked_at = row
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
    return {
        "revoked": revoked_at is not None,
        "session_id": session_id,
        "family_id": family_id,
        "account_id": account_id,
        "device_id": device_id,
        "installation_id": installation_id,
    }


# ---------------------------------------------------------------------------
# Routes: health and installation identity
# ---------------------------------------------------------------------------


@app.get("/health/live")
def health_live():
    return jsonify({"status": "live", "python": "3.9-compatible"})


@app.get("/health/ready")
def health_ready():
    with _cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()
    return jsonify(
        {
            "status": "ready",
            "database": _get_backend_identity(),
            "schema": _get_schema_state(),
            "installation_key_algorithms": ["ES256", "RS256"],
            "device_policy_mode": DEVICE_POLICY_MODE,
            "integrity_mode": INTEGRITY_MODE,
            "integrity_freshness_seconds": INTEGRITY_FRESHNESS_SECONDS,
            "remote_attestation": "not_used",
            "redis": _redis_status(),
        }
    )


@app.post("/v1/installations/register")
def register_installation():
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

    with _cursor(commit=True) as cursor:
        # The public key is the authoritative installation identity. This also
        # recovers gracefully if the UUID was lost but the Keychain key survived.
        cursor.execute(
            """
            SELECT installation_id, device_id, registration_method,
                   registration_confidence, key_algorithm
            FROM app_installations
            WHERE key_thumbprint = %s
            """,
            (key_thumbprint,),
        )
        row = cursor.fetchone()
        if row is not None:
            canonical_installation_id = str(row[0])
            device_id = str(row[1])
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
                 registration_method, registration_confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            ),
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
            }
        ),
        201,
    )


@app.post("/v1/installations/challenge")
def installation_challenge():
    body = _json_body()
    installation_id = _uuid_text(body.get("installation_id"), "installation_id")
    return jsonify(_create_challenge(installation_id, "device_auth"))


@app.post("/v1/installations/verify")
def installation_verify():
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
                    WHERE i2.device_id = i.device_id) AS installation_count,
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
        cursor.execute(
            """
            DELETE FROM integrity_challenges AS c
            WHERE c.expires_at < NOW() - INTERVAL '1 day'
              AND NOT EXISTS (
                  SELECT 1
                  FROM integrity_reports AS r
                  WHERE r.challenge_id = c.challenge_id
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
    if isinstance(collector_version, bool) or not isinstance(collector_version, int):
        raise ApiProblem("Integrity collector version is invalid.", 400, "invalid_integrity_collector")
    probes = report.get("probe_results")
    if not isinstance(probes, dict):
        raise ApiProblem("probe_results must be an object.", 400, "invalid_integrity_report")

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
        if failed_required:
            for probe_name in failed_required:
                _integrity_reason(
                    scored["reasons"],
                    "integrity_probe_failed:%s" % probe_name,
                    30,
                    "A server-requested native integrity probe did not complete successfully.",
                )
                scored["score"] = min(100, int(scored["score"]) + 30)
            scored["verdict"] = _integrity_verdict(
                scored["score"],
                hard_block=scored["hard_block"],
            )

        cursor.execute(
            "UPDATE integrity_challenges SET used_at = NOW() WHERE challenge_id = %s",
            (challenge_id,),
        )
        cursor.execute(
            """
            INSERT INTO integrity_reports
                (report_id, challenge_id, installation_id, device_id, platform,
                 collector_version, score, verdict, hard_block, reasons,
                 probe_results, report_sha256)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            ),
        )

    response = {
        "report_id": report_id,
        "score": scored["score"],
        "verdict": scored["verdict"],
        "hard_block": scored["hard_block"],
        "reasons": scored["reasons"],
        "mode": INTEGRITY_MODE,
        "fresh_for_seconds": INTEGRITY_FRESHNESS_SECONDS,
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
    claims = _require_access_proof("device")
    body = _json_body()
    lookup = _handle_lookup(body.get("handle"))
    password = _password_bytes(body.get("password"))
    account_id = str(uuid.uuid4())
    device_id = claims.get("did")
    installation_id = claims.get("iid")
    _enforce_integrity_gate(device_id, installation_id)

    password_hash = _bcrypt_hash_bytes(password)

    policy = _evaluate_risk_policy(
        "account_register",
        device_id,
        installation_id,
        account_id=account_id,
        account_link_pending=True,
        persist=True,
    )
    _enforce_risk_policy(policy)

    try:
        with _cursor(commit=True) as cursor:
            cursor.execute(
                """
                INSERT INTO demo_accounts (account_id, handle_lookup, password_hash)
                VALUES (%s, %s, %s)
                """,
                (account_id, lookup, password_hash),
            )
            _link_device_account(cursor, device_id, account_id, installation_id)
            tokens = _issue_account_tokens(
                cursor,
                account_id,
                device_id,
                installation_id,
                policy=policy,
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
    claims = _require_access_proof("device")
    body = _json_body()
    lookup = _handle_lookup(body.get("handle"))
    password = _password_bytes(body.get("password"))
    device_id = claims.get("did")
    installation_id = claims.get("iid")

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
            raise ApiProblem(
                "The account credentials are invalid.",
                401,
                "invalid_credentials",
            )
        account_id = str(row[0])

    _enforce_integrity_gate(device_id, installation_id)
    policy = _evaluate_risk_policy(
        "account_login",
        device_id,
        installation_id,
        account_id=account_id,
        account_link_pending=True,
        persist=True,
    )
    _enforce_risk_policy(policy)

    with _cursor(commit=True) as cursor:
        _link_device_account(cursor, device_id, account_id, installation_id)
        tokens = _issue_account_tokens(
            cursor,
            account_id,
            device_id,
            installation_id,
            policy=policy,
        )

    return jsonify(tokens)


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
        }
    )


@app.get("/v1/policy/me")
@jwt_required()
def policy_me():
    claims = _require_access_proof("account")
    _enforce_integrity_gate(claims.get("did"), claims.get("iid"))
    decision = _evaluate_risk_policy(
        "policy_check",
        claims.get("did"),
        claims.get("iid"),
        account_id=str(get_jwt_identity()),
        account_link_pending=False,
        persist=True,
    )
    return jsonify({"policy": decision})


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
    claims = _require_role("account")
    reused = False
    with _cursor(commit=True) as cursor:
        session = _refresh_session(cursor, claims, lock=False)
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
    if reused:
        raise ApiProblem(
            "A rotated refresh token was reused; the token family was revoked.",
            401,
            "refresh_token_reuse",
        )
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

    _verify_challenge(
        installation_id,
        challenge_id,
        payload,
        signature,
        "refresh:%s" % session_id,
    )

    with _cursor() as cursor:
        policy_session = _refresh_session(cursor, claims, lock=False)

    _enforce_integrity_gate(
        policy_session["device_id"],
        policy_session["installation_id"],
    )
    policy = _evaluate_risk_policy(
        "refresh",
        policy_session["device_id"],
        policy_session["installation_id"],
        account_id=policy_session["account_id"],
        account_link_pending=False,
        persist=True,
    )
    _enforce_risk_policy(policy)

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
            tokens = _issue_account_tokens(
                cursor,
                session["account_id"],
                session["device_id"],
                session["installation_id"],
                family_id=session["family_id"],
                policy=policy,
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


if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "0.0.0.0"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
    )
