#!/usr/bin/env python3
"""
Backend conformance suite for the device-recognition server.

Why this exists
---------------
Every security property of this server has so far been validated by hand, by
pressing buttons on a physical phone. That cannot prove that the server behaves
*identically* on PostgreSQL and on SQL Server, which is the claim the product
has to make once customers bring their own database.

This suite drives the real HTTP protocol with a software P-256 installation key,
so the same assertions run unattended against any backend and the results can be
diffed. It deliberately concentrates on the paths whose behaviour is
database-specific:

  access-proof replay        -> unique-constraint / upsert semantics
                                (Postgres ON CONFLICT vs SQL Server MERGE/duplicate-key)
  refresh-token reuse        -> row locking (SELECT ... FOR UPDATE vs UPDLOCK)
  identity by key thumbprint -> JSON column round-trip
  timestamp windows          -> timezone-aware column round-trip

Signing contract reproduced here (must match the native clients exactly):
the payload travels as base64url text, the client base64url-DECODES it and signs
the raw bytes with ECDSA-SHA256, and the signature is ASN.1 DER. The server
verifies the signature over exactly the bytes it received and only then parses
them, which is why Dart, .NET and Python clients do NOT need byte-identical JSON
serialisation. Preserve that property.

Dependencies: `cryptography` (harness only, NOT a server dependency) plus the
standard library. Runs on Python 3.9+.

Usage:
    python3 conformance_suite.py --base-url http://192.168.100.13:5000
    python3 conformance_suite.py --base-url https://host --verbose

The server must be in INTEGRITY_MODE=observe for this suite; enforce mode
requires a fresh signed integrity report before account operations, which the
integrity-scoring suite (phase 0b) will cover separately.
"""

import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

VERBOSE = False


# ---------------------------------------------------------------------------
# encoding helpers
# ---------------------------------------------------------------------------


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def jwt_claims(token):
    """Decode a JWT payload for assertions only. Never a trust decision."""
    return json.loads(b64u_decode(token.split(".")[1]).decode("utf-8"))


# ---------------------------------------------------------------------------
# software installation key (stands in for AndroidKeyStore / Secure Enclave)
# ---------------------------------------------------------------------------


class Installation:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.submitted_id = str(uuid.uuid4())
        self.installation_id = self.submitted_id  # replaced by the canonical id
        self.device_id = None

    @property
    def jwk(self):
        numbers = self.key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def sign_b64(self, payload_b64):
        """Sign the DECODED bytes; return base64url DER, as the natives do."""
        signature = self.key.sign(
            b64u_decode(payload_b64), ec.ECDSA(hashes.SHA256())
        )
        return b64u(signature)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class Api:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def call(self, method, path, *, body_text=None, bearer=None, headers=None):
        url = self.base_url + path
        data = body_text.encode("utf-8") if body_text is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if bearer:
            request.add_header("Authorization", "Bearer " + bearer)
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read()
            status = error.code
        except urllib.error.URLError as error:
            raise SystemExit("cannot reach %s: %s" % (url, error))
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            payload = {"_raw": raw[:400].decode("utf-8", "replace")}
        if VERBOSE:
            print("    %s %s -> %s %s" % (method, path, status, payload))
        return status, payload


# ---------------------------------------------------------------------------
# access proof
# ---------------------------------------------------------------------------


def build_proof(
    installation,
    method,
    path,
    bearer,
    body_obj=None,
    *,
    signed_method=None,
    signed_path=None,
    signed_body_text=None,
    timestamp=None,
    nonce_bytes=None,
    signer=None,
):
    """Return (headers, body_text_to_send).

    The *signed* method/path/body are separated from what is actually sent so a
    caller can tamper with one side, which is how the boundary checks work.
    """
    method = method.upper()
    body_text = "" if method == "GET" else json.dumps(body_obj or {})
    signed_body = signed_body_text if signed_body_text is not None else body_text
    nonce = b64u(nonce_bytes or secrets.token_bytes(32))
    proof = {
        "access_token_sha256": sha256_hex(bearer.encode("utf-8")),
        "body_sha256": sha256_hex(signed_body.encode("utf-8")),
        "installation_id": installation.installation_id,
        "method": (signed_method or method).upper(),
        "nonce": nonce,
        "path": signed_path or path,
        "timestamp": int(timestamp if timestamp is not None else time.time()),
        "version": 1,
    }
    payload_b64 = b64u(json.dumps(proof, separators=(",", ":")).encode("utf-8"))
    signature = (signer or installation).sign_b64(payload_b64)
    headers = {"X-Access-Proof": payload_b64, "X-Access-Signature": signature}
    return headers, (None if method == "GET" else body_text)


def protected(api, installation, method, path, bearer, body_obj=None, **kwargs):
    headers, body_text = build_proof(
        installation, method, path, bearer, body_obj, **kwargs
    )
    return api.call(
        method, path, body_text=body_text, bearer=bearer, headers=headers
    )


# ---------------------------------------------------------------------------
# protocol flows
# ---------------------------------------------------------------------------


def enrol(api, installation, reinstall_hint=None):
    body = {
        "installation_id": installation.submitted_id,
        "platform": "android",
        "public_key": installation.jwk,
        "reinstall_hint": reinstall_hint,
    }
    status, payload = api.call(
        "POST", "/v1/installations/register", body_text=json.dumps(body)
    )
    if status in (200, 201):
        installation.installation_id = payload["installation_id"]
        installation.device_id = payload["device_id"]
    return status, payload


def device_token(api, installation):
    status, challenge = api.call(
        "POST",
        "/v1/installations/challenge",
        body_text=json.dumps({"installation_id": installation.installation_id}),
    )
    if status != 200:
        raise AssertionError("challenge failed: %s %s" % (status, challenge))
    payload_b64 = challenge["payload"]
    body = {
        "installation_id": installation.installation_id,
        "challenge_id": challenge["challenge_id"],
        "payload": payload_b64,
        "signature": installation.sign_b64(payload_b64),
    }
    status, verified = api.call(
        "POST", "/v1/installations/verify", body_text=json.dumps(body)
    )
    if status != 200:
        raise AssertionError("verify failed: %s %s" % (status, verified))
    return verified["device_token"]


def open_account(api, installation, token, handle, password="Passw0rd123"):
    return protected(
        api,
        installation,
        "POST",
        "/v1/accounts/register",
        token,
        {"handle": handle, "password": password},
    )


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

CHECKS = []


def check(name, db_sensitive=False):
    def wrap(function):
        CHECKS.append((name, function, db_sensitive))
        return function

    return wrap


def expect(condition, detail):
    if not condition:
        raise AssertionError(detail)


def error_code(payload):
    """Extract the code from the API error envelope.

    The server answers failures as {"error": {"code": ..., "message": ...}}.
    That envelope is part of the client contract: the Dart, .NET and Python
    SDKs must all read error.code from this shape.
    """
    error = payload.get("error")
    if isinstance(error, dict):
        return error.get("code")
    return payload.get("code")


@check("identity: a new key enrols as a new installation")
def check_enrol(api, ctx):
    installation = Installation()
    status, payload = enrol(api, installation)
    expect(status in (200, 201), "expected 200/201, got %s %s" % (status, payload))
    expect("device_id" in payload, "no device_id returned")
    ctx["installation"] = installation


@check("identity: the key thumbprint, not the UUID, is authoritative", db_sensitive=True)
def check_thumbprint_authority(api, ctx):
    """Re-enrol the same key under a different UUID; the server must recognise
    the key and return the original installation id. Exercises the JSON public
    key column round-trip and the unique thumbprint index."""
    original = ctx["installation"]
    impostor = Installation()
    impostor.key = original.key
    impostor.submitted_id = str(uuid.uuid4())
    status, payload = enrol(api, impostor)
    expect(status == 200, "expected 200 for a known key, got %s" % status)
    expect(
        payload["installation_id"] == original.installation_id,
        "server issued a different installation for the same key",
    )
    expect(
        payload["recognition"]["method"] == "exact_key",
        "expected exact_key recognition, got %s" % payload["recognition"],
    )


@check("possession: a signed challenge yields a device token")
def check_device_token(api, ctx):
    token = device_token(api, ctx["installation"])
    claims = jwt_claims(token)
    expect(claims.get("role") == "device", "expected role=device, got %s" % claims)
    ctx["device_token"] = token


@check("account: a device token opens an account")
def check_account(api, ctx):
    handle = "conf-%s" % secrets.token_hex(4)
    status, payload = open_account(
        api, ctx["installation"], ctx["device_token"], handle
    )
    expect(status in (200, 201), "account register failed: %s %s" % (status, payload))
    ctx["handle"] = handle
    ctx["access_token"] = payload["access_token"]
    ctx["refresh_token"] = payload["refresh_token"]


@check("access proof: a correctly signed request is accepted")
def check_proof_ok(api, ctx):
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"hello": "conformance"},
    )
    expect(status == 200, "expected 200, got %s %s" % (status, payload))


@check("access proof: an exact replay is rejected", db_sensitive=True)
def check_replay(api, ctx):
    """THE database-sensitive check. Postgres uses INSERT .. ON CONFLICT; SQL
    Server has no equivalent and a naive translation re-opens replay."""
    installation = ctx["installation"]
    headers, body_text = build_proof(
        installation,
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"replay": True},
    )
    first = api.call(
        "POST",
        "/v1/account/protected-echo",
        body_text=body_text,
        bearer=ctx["access_token"],
        headers=headers,
    )
    expect(first[0] == 200, "first send should succeed, got %s" % (first,))
    status, payload = api.call(
        "POST",
        "/v1/account/protected-echo",
        body_text=body_text,
        bearer=ctx["access_token"],
        headers=headers,
    )
    expect(status == 401, "replay should be 401, got %s" % status)
    expect(
        error_code(payload) == "access_proof_replay",
        "expected access_proof_replay, got %s" % error_code(payload),
    )


@check("access proof: a tampered body is rejected")
def check_body_tamper(api, ctx):
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"amount": 1},
        signed_body_text=json.dumps({"amount": 1000000}),
    )
    expect(status == 401, "expected 401, got %s" % status)
    expect(
        error_code(payload) == "access_proof_body_mismatch",
        "expected access_proof_body_mismatch, got %s" % error_code(payload),
    )


@check("access proof: a tampered path is rejected")
def check_path_tamper(api, ctx):
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"x": 1},
        signed_path="/v1/account/some-other-path",
    )
    expect(status == 401, "expected 401, got %s" % status)
    expect(
        error_code(payload) == "access_proof_path_mismatch",
        "expected access_proof_path_mismatch, got %s" % error_code(payload),
    )


@check("access proof: a tampered method is rejected")
def check_method_tamper(api, ctx):
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"x": 1},
        signed_method="GET",
    )
    expect(status == 401, "expected 401, got %s" % status)
    expect(
        error_code(payload) == "access_proof_method_mismatch",
        "expected access_proof_method_mismatch, got %s" % error_code(payload),
    )


@check("access proof: a stale timestamp is rejected", db_sensitive=True)
def check_stale_timestamp(api, ctx):
    """Also a timezone round-trip check: Postgres TIMESTAMPTZ normalises to UTC,
    SQL Server datetimeoffset does not, and GETDATE() would shift the window."""
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"x": 1},
        timestamp=int(time.time()) - 3600,
    )
    expect(status == 401, "expected 401, got %s" % status)
    expect(
        error_code(payload) == "access_proof_timestamp_outside_window",
        "expected access_proof_timestamp_outside_window, got %s" % error_code(payload),
    )


@check("access proof: a proof signed by another key is rejected")
def check_wrong_key(api, ctx):
    """A stolen token replayed from another device: structurally perfect proof,
    signed by the wrong installation key."""
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo",
        ctx["access_token"],
        {"x": 1},
        signer=Installation(),
    )
    expect(status == 401, "expected 401, got %s" % status)
    expect(
        error_code(payload) == "invalid_installation_signature",
        "expected invalid_installation_signature, got %s" % error_code(payload),
    )


@check("refresh: rotation issues a new family member", db_sensitive=True)
def check_refresh_rotate(api, ctx):
    installation = ctx["installation"]
    status, challenge = api.call(
        "POST", "/v1/auth/refresh/challenge", bearer=ctx["refresh_token"]
    )
    expect(status == 200, "refresh challenge failed: %s %s" % (status, challenge))
    payload_b64 = challenge["payload"]
    body = {
        "challenge_id": challenge["challenge_id"],
        "payload": payload_b64,
        "signature": installation.sign_b64(payload_b64),
    }
    status, rotated = api.call(
        "POST",
        "/v1/auth/refresh",
        body_text=json.dumps(body),
        bearer=ctx["refresh_token"],
    )
    expect(status == 200, "refresh failed: %s %s" % (status, rotated))
    ctx["old_refresh_token"] = ctx["refresh_token"]
    ctx["refresh_token"] = rotated["refresh_token"]
    ctx["access_token"] = rotated["access_token"]


@check("refresh: reusing a rotated token revokes the family", db_sensitive=True)
def check_refresh_reuse(api, ctx):
    """The row-locking check. Postgres SELECT .. FOR UPDATE; SQL Server needs
    WITH (UPDLOCK, ROWLOCK) or this detection can be raced."""
    old = ctx["old_refresh_token"]
    status, challenge = api.call("POST", "/v1/auth/refresh/challenge", bearer=old)
    if status == 200:
        body = {
            "challenge_id": challenge["challenge_id"],
            "payload": challenge["payload"],
            "signature": ctx["installation"].sign_b64(challenge["payload"]),
        }
        status, payload = api.call(
            "POST", "/v1/auth/refresh", body_text=json.dumps(body), bearer=old
        )
    else:
        payload = challenge
    expect(status == 401, "reuse should be rejected, got %s %s" % (status, payload))
    expect(
        error_code(payload) in ("refresh_token_reuse", "refresh_session_revoked"),
        "expected a reuse/revocation code, got %s" % error_code(payload),
    )


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://192.168.100.13:5000")
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args()
    VERBOSE = arguments.verbose

    api = Api(arguments.base_url)
    status, health = api.call("GET", "/health/ready")
    if status != 200:
        raise SystemExit("server not ready: %s %s" % (status, health))
    mode = health.get("integrity_mode")
    backend = health.get("database", "unknown")
    print("target   : %s" % arguments.base_url)
    print("integrity: %s     database: %s" % (mode, backend))
    if mode != "observe":
        print(
            "WARNING  : this suite expects INTEGRITY_MODE=observe; "
            "enforce mode requires a fresh integrity report."
        )
    print()

    context = {}
    passed = failed = 0
    for name, function, db_sensitive in CHECKS:
        marker = " [db]" if db_sensitive else ""
        try:
            function(api, context)
        except Exception as error:  # noqa: BLE001 - report every failure
            failed += 1
            print("FAIL %s%s\n       %s" % (name, marker, error))
        else:
            passed += 1
            print("PASS %s%s" % (name, marker))

    print("\n%d passed, %d failed  (checks marked [db] are the ones whose "
          "behaviour differs between PostgreSQL and SQL Server)" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
