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
import secrets
import threading
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import bcrypt
import psycopg2
from psycopg2.extras import Json
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
INTEGRITY_RANDOM_OPTIONAL_PROBES = int(
    os.environ.get("INTEGRITY_RANDOM_OPTIONAL_PROBES", "4")
)
INTEGRITY_ALLOW_DEBUG = os.environ.get("INTEGRITY_ALLOW_DEBUG", "0") == "1"
INTEGRITY_ALLOW_EMULATOR = os.environ.get("INTEGRITY_ALLOW_EMULATOR", "0") == "1"

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


def _connect_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=os.environ.get("DB_NAME", "familyappdb"),
        user=os.environ["DB_USERNAME"],
        password=os.environ["DB_PASSWORD"],
        connect_timeout=int(os.environ.get("DB_CONNECT_TIMEOUT", "5")),
    )


@contextmanager
def _cursor(commit=False):
    connection = _connect_db()
    cursor = connection.cursor()
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


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS recognized_devices (
    device_id UUID PRIMARY KEY,
    platform VARCHAR(16) NOT NULL,
    reinstall_hint_hash CHAR(64),
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recognized_devices_platform_hint_unique
        UNIQUE (platform, reinstall_hint_hash)
);

ALTER TABLE recognized_devices
    ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'active';

CREATE TABLE IF NOT EXISTS app_installations (
    installation_id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES recognized_devices(device_id),
    key_algorithm VARCHAR(16) NOT NULL,
    public_key_jwk JSONB NOT NULL,
    public_key_n TEXT,
    public_key_e TEXT,
    key_thumbprint CHAR(64) NOT NULL UNIQUE,
    registration_method VARCHAR(32) NOT NULL,
    registration_confidence VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- In-place migration from the first RS256 prototype. Keeping n/e permits a
-- rolling upgrade and makes old installation rows verifiable during testing.
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS key_algorithm VARCHAR(16);
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS public_key_jwk JSONB;
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS public_key_n TEXT;
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS public_key_e TEXT;
ALTER TABLE app_installations
    ALTER COLUMN public_key_n DROP NOT NULL;
ALTER TABLE app_installations
    ALTER COLUMN public_key_e DROP NOT NULL;

UPDATE app_installations
SET key_algorithm = COALESCE(key_algorithm, 'RS256'),
    public_key_jwk = COALESCE(
        public_key_jwk,
        jsonb_build_object(
            'kty', 'RSA',
            'alg', 'RS256',
            'n', public_key_n,
            'e', public_key_e
        )
    )
WHERE key_algorithm IS NULL OR public_key_jwk IS NULL;

ALTER TABLE app_installations
    ALTER COLUMN key_algorithm SET NOT NULL;
ALTER TABLE app_installations
    ALTER COLUMN public_key_jwk SET NOT NULL;

CREATE INDEX IF NOT EXISTS app_installations_device_idx
    ON app_installations(device_id);

CREATE TABLE IF NOT EXISTS installation_challenges (
    challenge_id UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    purpose VARCHAR(128) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS installation_challenges_open_idx
    ON installation_challenges(installation_id, expires_at)
    WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS demo_accounts (
    account_id UUID PRIMARY KEY,
    handle_lookup CHAR(64) NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_account_links (
    device_id UUID NOT NULL REFERENCES recognized_devices(device_id),
    account_id UUID NOT NULL REFERENCES demo_accounts(account_id),
    first_installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, account_id)
);

CREATE TABLE IF NOT EXISTS refresh_sessions (
    session_id UUID PRIMARY KEY,
    family_id UUID NOT NULL,
    account_id UUID NOT NULL REFERENCES demo_accounts(account_id),
    device_id UUID NOT NULL REFERENCES recognized_devices(device_id),
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS refresh_sessions_family_idx
    ON refresh_sessions(family_id);

CREATE TABLE IF NOT EXISTS access_proof_nonces (
    nonce_hash CHAR(64) PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    access_token_jti VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS access_proof_nonces_installation_idx
    ON access_proof_nonces(installation_id, expires_at);

CREATE TABLE IF NOT EXISTS risk_policy_decisions (
    decision_id UUID PRIMARY KEY,
    event_type VARCHAR(32) NOT NULL,
    account_id UUID,
    device_id UUID NOT NULL REFERENCES recognized_devices(device_id),
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    policy_mode VARCHAR(16) NOT NULL,
    recommended_action VARCHAR(16) NOT NULL,
    effective_action VARCHAR(16) NOT NULL,
    score INTEGER NOT NULL,
    reasons JSONB NOT NULL,
    context JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS risk_policy_decisions_device_idx
    ON risk_policy_decisions(device_id, created_at DESC);

CREATE INDEX IF NOT EXISTS risk_policy_decisions_account_idx
    ON risk_policy_decisions(account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS integrity_challenges (
    challenge_id UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    device_id UUID NOT NULL REFERENCES recognized_devices(device_id),
    platform VARCHAR(16) NOT NULL,
    nonce_sha256 CHAR(64) NOT NULL,
    required_probes JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS integrity_challenges_installation_idx
    ON integrity_challenges(installation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS integrity_reports (
    report_id UUID PRIMARY KEY,
    challenge_id UUID NOT NULL UNIQUE REFERENCES integrity_challenges(challenge_id),
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    device_id UUID NOT NULL REFERENCES recognized_devices(device_id),
    platform VARCHAR(16) NOT NULL,
    collector_version INTEGER NOT NULL,
    score INTEGER NOT NULL,
    verdict VARCHAR(16) NOT NULL,
    hard_block BOOLEAN NOT NULL DEFAULT FALSE,
    reasons JSONB NOT NULL,
    probe_results JSONB NOT NULL,
    report_sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS integrity_reports_installation_idx
    ON integrity_reports(installation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS integrity_reports_device_idx
    ON integrity_reports(device_id, created_at DESC);
"""

_schema_lock = threading.Lock()
_schema_ready = False


def _ensure_schema():
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        with _cursor(commit=True) as cursor:
            cursor.execute(_SCHEMA_SQL)
        _schema_ready = True
        logger.info("Device-recognition schema is ready")


@app.before_request
def schema_guard():
    if request.path == "/health/live":
        return None
    _ensure_schema()
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
        ]
        optional = [
            "root_shell",
            "selinux",
            "mounts",
            "frida_ports",
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
    if _as_bool(root_files.get("test_keys")):
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
    if verified and verified not in ("green",):
        _integrity_reason(reasons, "android_verified_boot_not_green", 60, "Verified Boot state is not green.")
        score += 60
    if flash_locked and flash_locked not in ("1", "true", "locked"):
        _integrity_reason(reasons, "android_bootloader_not_locked", 60, "Bootloader/flash lock property is not locked.")
        score += 60
    if vbmeta_state and vbmeta_state not in ("locked",):
        _integrity_reason(reasons, "android_vbmeta_not_locked", 60, "VBMeta device state is not locked.")
        score += 60
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
        "reasons": row[4] if isinstance(row[4], list) else [],
        "created_at": _iso_z(row[5]),
        "age_seconds": age_seconds,
        "fresh": age_seconds <= INTEGRITY_FRESHNESS_SECONDS,
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
                    Json(reasons),
                    Json(context),
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
            RETURNING challenge_id
            """,
            (challenge_id,),
        )
        if cursor.fetchone() is None:
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

    # Consume the client nonce after signature verification. ON CONFLICT gives
    # us an atomic replay check even if the same captured request arrives twice.
    with _cursor(commit=True) as cursor:
        cursor.execute(
            """
            DELETE FROM access_proof_nonces
            WHERE expires_at < NOW() - INTERVAL '1 day'
            """
        )
        cursor.execute(
            """
            INSERT INTO access_proof_nonces
                (nonce_hash, installation_id, access_token_jti, expires_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (nonce_hash) DO NOTHING
            RETURNING nonce_hash
            """,
            (
                nonce_hash,
                installation_id,
                token_jti,
                _utc_now() + ACCESS_PROOF_NONCE_RETENTION,
            ),
        )
        if cursor.fetchone() is None:
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
    cursor.execute(
        """
        INSERT INTO device_account_links
            (device_id, account_id, first_installation_id)
        VALUES (%s, %s, %s)
        ON CONFLICT (device_id, account_id)
        DO UPDATE SET last_seen_at = NOW()
        """,
        (device_id, account_id, installation_id),
    )


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

    suffix = " FOR UPDATE" if lock else ""
    cursor.execute(
        """
        SELECT family_id, account_id, device_id, installation_id,
               expires_at, revoked_at
        FROM refresh_sessions
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
            "installation_key_algorithms": ["ES256", "RS256"],
            "device_policy_mode": DEVICE_POLICY_MODE,
            "integrity_mode": INTEGRITY_MODE,
            "integrity_freshness_seconds": INTEGRITY_FRESHNESS_SECONDS,
            "remote_attestation": "not_used",
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
            except psycopg2.errors.UniqueViolation:
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
                Json(public_key_jwk),
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
            "DELETE FROM integrity_challenges WHERE expires_at < NOW() - INTERVAL '1 day'"
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
                Json(probes),
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
            FROM integrity_challenges c
            JOIN app_installations i ON i.installation_id = c.installation_id
            JOIN recognized_devices d ON d.device_id = c.device_id
            WHERE c.challenge_id = %s
            FOR UPDATE
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

        if not isinstance(required_probes, list):
            required_probes = []
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
                Json(scored["reasons"]),
                Json(probes),
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
    except psycopg2.errors.UniqueViolation:
        raise ApiProblem(
            "That account handle is already registered.",
            409,
            "account_handle_exists",
        )

    return jsonify(tokens), 201


@app.post("/v1/accounts/login")
@jwt_required()
def account_login():
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
    _ensure_schema()
    app.run(
        host=os.environ.get("FLASK_HOST", "0.0.0.0"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
    )
