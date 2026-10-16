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
import copy
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
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
    version=2,
):
    """Return (headers, body_text_to_send).

    The *signed* method/path/body are separated from what is actually sent so a
    caller can tamper with one side, which is how the boundary checks work.
    """
    method = method.upper()
    body_text = "" if method == "GET" else json.dumps(body_obj or {})
    signed_body = signed_body_text if signed_body_text is not None else body_text
    nonce = b64u(nonce_bytes or secrets.token_bytes(32))
    # Access proof v2 (DESIGN.md 63): the signed target splits into the path and
    # the raw query string, both compared with the request.
    route, _, query = (signed_path or path).partition("?")
    proof = {
        "access_token_sha256": sha256_hex(bearer.encode("utf-8")),
        "body_sha256": sha256_hex(signed_body.encode("utf-8")),
        "installation_id": installation.installation_id,
        "method": (signed_method or method).upper(),
        "nonce": nonce,
        "path": route,
        "timestamp": int(timestamp if timestamp is not None else time.time()),
        "version": version,
    }
    if version >= 2:
        proof["query"] = query
    payload_b64 = b64u(json.dumps(proof, separators=(",", ":")).encode("utf-8"))
    signature = (signer or installation).sign_b64(payload_b64)
    headers = {"X-Access-Proof": payload_b64, "X-Access-Signature": signature}
    return headers, (None if method == "GET" else body_text)


def stepup_proof(installation, method, path, bearer, body_text, nonce, factor, overrides=None):
    """Step-up proof v2 (DESIGN.md 63): the step-up key approves one complete
    request -- token, method, path, query, body and the access proof's nonce --
    so the approval cannot be attached to any other request."""
    proof = {
        "version": 2,
        "purpose": "stepup",
        "installation_id": installation.installation_id,
        "access_token_sha256": sha256_hex(bearer.encode("utf-8")),
        "method": method.upper(),
        "path": path,
        "query": "",
        "body_sha256": sha256_hex((body_text or "").encode("utf-8")),
        "factor": factor,
        "nonce": nonce,
        "timestamp": int(time.time()),
    }
    proof.update(overrides or {})
    return b64u(json.dumps(proof).encode("utf-8"))


def stepup_call(api, installation, stepup_priv, method, path, bearer, body_obj, factor,
                approve_body=None, overrides=None, app_pin=None):
    """A protected call that also carries a step-up proof over this exact
    request, signed by the separate step-up key. approve_body signs an approval
    for a DIFFERENT body than the one sent, which is the retargeting attack."""
    headers, body_text = build_proof(installation, method, path, bearer, body_obj)
    access_proof = json.loads(b64u_decode(headers["X-Access-Proof"]).decode("utf-8"))
    approved = body_text if approve_body is None else json.dumps(approve_body)
    proof_b64 = stepup_proof(installation, method, path, bearer, approved,
                             access_proof["nonce"], factor, overrides)
    sig = stepup_priv.sign(b64u_decode(proof_b64), ec.ECDSA(hashes.SHA256()))
    headers["X-Step-Up-Proof"] = proof_b64
    headers["X-Step-Up-Signature"] = b64u(sig)
    if app_pin is not None:
        headers["X-App-PIN"] = app_pin
    return api.call(method, path, body_text=body_text, bearer=bearer, headers=headers)


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


def enrol(api, installation, reinstall_hint=None, platform="android",
          key_security=None, stepup_public_key=None, stepup_key_auth=None):
    body = {
        "installation_id": installation.submitted_id,
        "platform": platform,
        "public_key": installation.jwk,
        "reinstall_hint": reinstall_hint,
    }
    if stepup_public_key is not None:
        body["stepup_public_key"] = stepup_public_key
    if stepup_key_auth is not None:
        body["stepup_key_auth"] = stepup_key_auth
    # Omitted entirely when not supplied, which is what the Kotlin and .NET
    # collectors do. The server must record that as "not reported", never as
    # "software" -- see check_key_security_absent_is_null.
    if key_security is not None:
        body["key_security"] = key_security
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


def sign_in(api, installation, token, handle, password="Passw0rd123"):
    return protected(
        api,
        installation,
        "POST",
        "/v1/accounts/login",
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
    # A real client scans before account operations, and in enforce mode the
    # gate requires a fresh trusted report, so do it unconditionally. This keeps
    # the whole suite runnable in either integrity mode.
    submit_report(api, ctx["installation"], ctx["device_token"])
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


@check("access proof: a query string added after signing is rejected")
def check_query_tamper(api, ctx):
    """Access proof v2 signs the raw query string; v1 never covered it, so a
    parameter appended after signing went through (review backlog)."""
    status, payload = protected(
        api,
        ctx["installation"],
        "POST",
        "/v1/account/protected-echo?to=someone-else",
        ctx["access_token"],
        {"x": 1},
        signed_path="/v1/account/protected-echo",
    )
    expect(status == 401 and error_code(payload) == "access_proof_query_mismatch",
           "expected 401 access_proof_query_mismatch, got %s %s" % (status, error_code(payload)))
    status, payload = protected(
        api, ctx["installation"], "POST", "/v1/account/protected-echo?to=me",
        ctx["access_token"], {"x": 1},
    )
    expect(status == 200, "a signed query string must pass, got %s %s" % (status, payload))


@check("access proof: v1 only where the server allows it, and never with a query")
def check_access_proof_v1(api, ctx):
    """ACCESS_PROOF_MIN_VERSION (default 2) refuses v1; a fleet in transition may
    set 1, and then a v1 proof still cannot cover a query string."""
    _, health = api.call("GET", "/health/ready")
    versions = (health if isinstance(health, dict) else {}).get("access_proof_versions") or [1]
    status, payload = protected(
        api, ctx["installation"], "POST", "/v1/account/protected-echo",
        ctx["access_token"], {"x": 1}, version=1,
    )
    if 1 not in versions:
        expect(status == 400 and error_code(payload) == "unsupported_access_proof_version",
               "v1 refused by this server, expected 400 unsupported_access_proof_version, got %s %s"
               % (status, error_code(payload)))
        return
    expect(status == 200, "v1 is allowed here, expected 200, got %s %s" % (status, payload))
    status, payload = protected(
        api, ctx["installation"], "POST", "/v1/account/protected-echo?to=x",
        ctx["access_token"], {"x": 1}, version=1,
    )
    expect(status == 401 and error_code(payload) == "access_proof_query_mismatch",
           "a v1 proof with a query string expected 401 access_proof_query_mismatch, got %s %s"
           % (status, error_code(payload)))


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


@check("refresh: a rotated token without the key cannot revoke the family")
def check_refresh_reuse_needs_key(api, ctx):
    """Joint review R7. Presenting an old, rotated refresh token to the
    challenge endpoint used to revoke the whole family on the bearer token
    alone, so anyone holding it -- but not the installation key -- could log
    the user out. Revocation now needs the key's signature (next check)."""
    status, payload = api.call("POST", "/v1/auth/refresh/challenge", bearer=ctx["old_refresh_token"])
    expect(status == 200, "the challenge step must not judge the token, got %s %s" % (status, payload))
    status, challenge = api.call("POST", "/v1/auth/refresh/challenge", bearer=ctx["refresh_token"])
    expect(status == 200, "refresh challenge failed: %s %s" % (status, challenge))
    body = {"challenge_id": challenge["challenge_id"], "payload": challenge["payload"],
            "signature": ctx["installation"].sign_b64(challenge["payload"])}
    status, rotated = api.call("POST", "/v1/auth/refresh", body_text=json.dumps(body),
                               bearer=ctx["refresh_token"])
    expect(status == 200, "the family must survive a key-less reuse attempt, got %s %s"
           % (status, rotated))
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
    # A reuse proven with the key revokes the whole family: the newest token
    # stops working too.
    status, challenge = api.call("POST", "/v1/auth/refresh/challenge", bearer=ctx["refresh_token"])
    if status == 200:
        body = {"challenge_id": challenge["challenge_id"], "payload": challenge["payload"],
                "signature": ctx["installation"].sign_b64(challenge["payload"])}
        status, payload = api.call("POST", "/v1/auth/refresh", body_text=json.dumps(body),
                                   bearer=ctx["refresh_token"])
    expect(status == 401, "after a proven reuse the family's newest token must fail, got %s" % status)



# ---------------------------------------------------------------------------
# integrity: synthetic probe reports (phase 0b)
# ---------------------------------------------------------------------------
# The server scores raw measurements, so a software client can exercise every
# scoring rule by submitting crafted probe results. That makes the scoring table
# testable without a phone, and - because the values round-trip through a JSON
# column - it also exercises the JSONB / nvarchar(max) mapping.

CONFORMANCE_CERT = hashlib.sha256(
    b"device-recognition conformance signing certificate"
).hexdigest()


class Skip(Exception):
    """Raised by a check that cannot run under the server's current mode."""


# A pristine iPhone. Field names are a hard contract with _score_ios_integrity;
# renaming one silently disables the rule that reads it.
IOS_CLEAN = {
    "app_identity": {
        "status": "ok",
        "bundle_id": "com.example.devicefingerprinting",
        "executable_sha256": hashlib.sha256(b"conformance-ios-executable").hexdigest(),
        "version_name": "1.0.0",
        "version_code": "1",
    },
    "code_signing": {
        "status": "ok",
        # Empty is honest for the unsigned builds the jailbroken-device
        # workflow produces; the server only compares when a baseline is set.
        "signing_identifier": "",
        "team_identifier": "",
        "get_task_allow": False,
    },
    "debugger": {"status": "ok", "traced": False},
    "jailbreak_files": {"status": "ok", "found_paths": [], "checked_count": 20},
    "sandbox": {"status": "ok", "write_outside_sandbox_succeeded": False},
    "dyld_images": {
        "status": "ok",
        "suspicious_tokens": [],
        "suspicious_image_count": 0,
        "image_count": 320,
    },
    "environment": {"status": "ok", "dyld_insert_libraries": ""},
    "simulator": {"status": "ok", "is_simulator": False, "model": "iPhone10,4"},
    # Requested only once INTEGRITY_SCORE_IOS_CODE_INTEGRITY is on; the shape
    # the Swift collector reports on a clean iPhone (app bucket measured,
    # system images unreadable by construction).
    "code_integrity": {
        "status": "ok",
        "checked": True,
        "app_compared_bytes": 1310720,
        "app_diff_bytes": 0,
        "app_libs_diff": 0,
        "app_images_compared": 2,
        "core_compared_bytes": 0,
        "core_diff_bytes": 0,
        "diff_bytes": 0,
        "ext_compared_bytes": 0,
        "ext_diff_bytes": 0,
        "ext_libs_diff": 0,
        "diffed_libs": "",
        "system_images_unreadable": 380,
        "system_bucket_reason": "dyld_shared_cache_has_no_backing_files",
    },
}


# What a current collector volunteers on every scan, outside the server's plan
# (DESIGN.md 80): the OS and its patch level, and neither a VPN nor a proxy.
VOLUNTEERED_CLEAN = {
    "android": {
        "device": {"status": "ok", "release": "14", "sdk_int": 34,
                   # A month old, always: an older one would score
                   # android_security_patch_outdated (DESIGN.md 82).
                   "security_patch": time.strftime("%Y-%m-%d", time.gmtime(time.time() - 30 * 86400)),
                   "manufacturer": "Conformance",
                   "brand": "conformance", "model": "Suite", "device": "suite",
                   "build_id": "SUITE.1",
                   "fingerprint": "conformance/suite/suite:14/SUITE.1/1:user/release-keys"},
        "network": {"status": "ok", "vpn_active": False, "http_proxy_configured": False,
                    "transports": ["wifi"], "interfaces": ["wlan0"]},
    },
    "ios": {
        "device": {"status": "ok", "os_version": "17.6.1", "model_identifier": "iPhone15,2"},
        "network": {"status": "ok", "vpn_active": False, "http_proxy_configured": False,
                    "scoped_interfaces": ["en0", "pdp_ip0"]},
    },
}
# An optional measurement as an app that enabled it answers (DESIGN.md 80, 82),
# in the server's order. The phone's own keyboard and nothing else holding
# access: a clean phone.
OPTIONAL_NAMES = ("local_addresses", "accessibility", "notification_access", "other_access",
                  "screen_capture", "location", "mock_location")
OPTIONAL_CLEAN = {
    "local_addresses": {"status": "ok",
                        "addresses": [{"interface": "wlan0", "address": "192.0.2.10"}]},
    "accessibility": {"status": "ok", "services": [], "settings_only": [],
                      "keyboard": {"package": "com.google.android.inputmethod.latin",
                                   "service": "com.android.inputmethod.latin.LatinIME",
                                   "system": True, "installer": "com.android.vending"}},
    "notification_access": {"status": "ok", "listeners": []},
    "other_access": {"status": "ok", "device_admins": [], "remote_access_apps": []},
    "screen_capture": {"status": "ok", "recording": False, "external_displays": 0},
    "location": {"status": "ok", "permission": "approximate", "latitude": 51.5072,
                 "longitude": -0.1276, "accuracy_m": 2000.0, "age_seconds": 120,
                 "provider": "network"},
    "mock_location": {"status": "ok", "permission": "approximate", "mock": False,
                      "age_seconds": 120},
}
# A sideloaded app with an Accessibility service on: what banking trojans use.
SIDELOADED_SERVICE = {"package": "com.conformance.reader", "service": "com.conformance.reader.Svc",
                      "system": False, "installer": ""}


def clean_probes(required, cert=None, platform="android"):
    """A pristine production device: every rule should score zero.

    Dispatches on platform because the two collectors report entirely different
    probes - iOS has no /proc and Android has no dyld.
    """
    if platform == "ios":
        # deepcopy, not a dict comprehension over the shared fixture. The
        # Android branch below builds a fresh literal on every call; this one
        # used to hand out references into IOS_CLEAN itself, so every check
        # that did probes["x"].update(...) permanently corrupted the fixture
        # and each later iOS check ran against a progressively dirtier
        # "pristine" device. It went unnoticed because no iOS check asserted an
        # exact score after a mutating one had run.
        return {
            name: copy.deepcopy(IOS_CLEAN[name])
            for name in required
            if name in IOS_CLEAN
        }
    everything = {
        "app_identity": {
            "status": "ok",
            "package_name": "com.example.devicefingerprinting",
            "version_name": "1.0.0",
            "version_code": 1,
            "debuggable": False,
            "allow_backup": False,
            "cert_sha256": [cert or CONFORMANCE_CERT],
            "apk_sha256": hashlib.sha256(b"conformance-apk").hexdigest(),
            "installer_package": "com.android.vending",
            "source_dir": "/data/app/com.example.devicefingerprinting/base.apk",
        },
        "debug_state": {
            "status": "ok",
            "debugger_connected": False,
            "waiting_for_debugger": False,
        },
        "root_files": {
            "status": "ok",
            "found_paths": [],
            "build_tags": "release-keys",
            "test_keys": False,
        },
        "system_properties": {
            "status": "ok",
            "properties": {
                "ro.secure": "1",
                "ro.debuggable": "0",
                "ro.build.type": "user",
                "ro.build.tags": "release-keys",
                "ro.boot.verifiedbootstate": "green",
                "ro.boot.flash.locked": "1",
                "ro.boot.vbmeta.device_state": "locked",
                "ro.boot.veritymode": "enforcing",
            },
        },
        "runtime_maps": {"status": "ok", "suspicious_tokens": [], "suspicious_line_count": 0,
                         "maps_lines": 412},
        "tracer": {"status": "ok", "tracer_pid": 0, "seccomp": 2, "no_new_privs": 1},
        "root_shell": {"status": "ok", "su_path": "", "su_found": False},
        "selinux": {
            "status": "ok",
            "mode": "enforcing",
            "getenforce": "Enforcing",
            "enforce_value": "1",
        },
        "mounts": {"status": "ok", "protected_rw_mounts": []},
        "frida_ports": {"status": "ok", "open_ports": []},
        "instrumentation_threads": {
            "status": "ok",
            "frida_threads": [],
            "glib_threads": [],
            "token_threads": [],
            "thread_count": 42,
        },
        "exec_mappings": {
            "status": "ok",
            "wx_mappings": 0,
            "deleted_exec_mappings": 0,
            "deleted_exec_jit": 1,
            "anon_exec_labeled": 1,
            "anon_exec_unlabeled": 0,
            "deleted_exec_own_code": 0,
            "maps_lines": 412,
            "samples": [],
        },
        "code_integrity": {
            "status": "ok",
            "checked": True,
            "diff_bytes": 0,
            "core_compared_bytes": 614400,
            "core_diff_bytes": 0,
            "ext_compared_bytes": 2097152,
            "ext_diff_bytes": 0,
            "ext_libs_diff": 0,
            "app_compared_bytes": 4194304,
            "app_diff_bytes": 0,
            "app_libs_diff": 0,
            "diffed_libs": "",
            # Coverage, required by the Android evidence contract 3 (DESIGN.md 76).
            "core_expected_bytes": 614400,
            "core_skipped_bytes": 0,
            "core_unreadable_bytes": 0,
            "core_complete": True,
            "ext_expected_bytes": 2097152,
            "ext_skipped_bytes": 0,
            "ext_unreadable_bytes": 0,
            "ext_complete": True,
            "app_expected_bytes": 4194304,
            "app_skipped_bytes": 0,
            "app_unreadable_bytes": 0,
            "app_complete": True,
            "protect_restore_failures": 0,
        },
        "emulator": {"status": "ok", "suspected": False},
        "developer_settings": {
            "status": "ok",
            "developer_options_enabled": False,
            "adb_enabled": False,
        },
    }
    return {name: everything[name] for name in required if name in everything}


def submit_report(api, installation, token, mutate=None, cert=None, enabled=(), operation=None):
    """Run one full integrity round trip and return the server's decision.

    Answers like a current collector: the plan, the volunteered device and
    network probes, and each optional measurement the challenge asks for --
    measured where `enabled` lists it, else not_enabled (DESIGN.md 80). With
    operation, the challenge names the one request the scan is to approve
    (DESIGN.md 84.3)."""
    status, challenge = protected(
        api, installation, "POST", "/v1/integrity/challenge", token,
        {"operation": operation} if operation else {}
    )
    if status != 200:
        raise AssertionError("integrity challenge failed: %s %s" % (status, challenge))
    probes = clean_probes(
        challenge["required_probes"], cert=cert, platform=challenge["platform"]
    )
    for name, value in VOLUNTEERED_CLEAN.get(challenge["platform"], {}).items():
        probes.setdefault(name, copy.deepcopy(value))
    for name in challenge.get("optional_probes") or []:
        probes[name] = (copy.deepcopy(OPTIONAL_CLEAN[name])
                        if name in enabled and name in OPTIONAL_CLEAN
                        else {"status": "not_enabled"})
    if mutate:
        mutate(probes)
    report = {
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["nonce"],
        "installation_id": installation.installation_id,
        "platform": challenge["platform"],
        # The current collectors, Android 5 and iOS 4 (DESIGN.md 82), meet
        # evidence contracts 3 and 2 (DESIGN.md 76); an older version is
        # scored but labelled legacy.
        "collector_version": {"android": 5, "ios": 4}.get(challenge["platform"], 1),
        "collected_at": int(time.time()),
        "probe_results": probes,
        # Which optional measurements this app enabled (DESIGN.md 83).
        "enabled_measurements": [name for name in OPTIONAL_NAMES if name in enabled],
        "version": 1,
    }
    payload_b64 = b64u(json.dumps(report).encode("utf-8"))
    status, answer = protected(
        api,
        installation,
        "POST",
        "/v1/integrity/report",
        token,
        {
            "report_payload": payload_b64,
            "report_signature": installation.sign_b64(payload_b64),
        },
    )
    if status != 200:
        raise AssertionError("integrity report rejected: %s %s" % (status, answer))
    return answer["integrity"]


def codes(decision):
    return {reason["code"] for reason in decision.get("reasons", [])}


def reason_for(decision, code):
    """The full reason dict for one code, or None.

    codes() answers "did the rule fire"; this answers "and what did it
    actually contribute", which is the difference between a live rule and a
    report-only one.
    """
    for reason in decision.get("reasons", []):
        if reason.get("code") == code:
            return reason
    return None


def integrity_session(api):
    """A fresh installation with a device token, ready to report integrity."""
    installation = Installation()
    hint = {"kind": "android_id_sha256", "value": sha256_hex(secrets.token_bytes(16))}
    status, payload = enrol(api, installation, hint)
    if status not in (200, 201):
        raise AssertionError("enrol failed: %s %s" % (status, payload))
    return installation, device_token(api, installation), hint


def integrity_context(ctx):
    """Integrity checks depend on a usable scoring session.

    If the server does not trust the conformance certificate, every integrity
    report comes back as a certificate hard block, which would drown the real
    problem in a wall of unrelated failures. Skip with the reason instead.
    """
    if "integrity" not in ctx:
        raise Skip(ctx.get("integrity_unavailable_short", "no integrity session"))
    return ctx["integrity"]


@check("integrity: a pristine device scores zero and is trusted")
def check_integrity_clean(api, ctx):
    installation, token, hint = integrity_session(api)
    decision = submit_report(api, installation, token)
    if "android_signing_certificate_mismatch" in codes(decision):
        reason = (
            "server does not trust the conformance certificate; start it with "
            "INTEGRITY_ANDROID_CERT_SHA256=%s (or empty) to run the scoring checks"
            % CONFORMANCE_CERT
        )
        ctx["integrity_unavailable_short"] = (
            "conformance certificate not configured on the server"
        )
        raise Skip(reason)
    expect(
        decision["verdict"] == "trusted",
        "expected trusted, got %s (%s)" % (decision["verdict"], codes(decision)),
    )
    expect(decision["score"] == 0, "expected score 0, got %s" % decision["score"])
    ctx["integrity"] = (installation, token, hint)


@check("integrity: unreadable SELinux is telemetry, not evidence")
def check_selinux_unknown(api, ctx):
    """Regression guard for a fixed false positive: the OPPO's app sandbox could
    not query SELinux even though the device was enforcing."""
    installation, token, _ = integrity_context(ctx)

    def blank_selinux(probes):
        if "selinux" in probes:
            probes["selinux"].update({"mode": "", "getenforce": "", "enforce_value": ""})

    decision = submit_report(api, installation, token, blank_selinux)
    found = codes(decision)
    expect(
        not {"android_selinux_permissive", "android_selinux_disabled"} & found,
        "unknown SELinux must not be scored, got %s" % found,
    )
    expect(decision["verdict"] == "trusted", "expected trusted, got %s" % decision)


@check("integrity: SELinux permissive is scored")
def check_selinux_permissive(api, ctx):
    installation, token, _ = integrity_context(ctx)

    def permissive(probes):
        probes["selinux"].update(
            {"mode": "permissive", "getenforce": "Permissive", "enforce_value": "0"}
        )

    decision = submit_report(api, installation, token, permissive)
    expect(
        "android_selinux_permissive" in codes(decision),
        "expected android_selinux_permissive, got %s" % codes(decision),
    )


@check("integrity: Frida mapped into the process blocks")
def check_frida_runtime(api, ctx):
    installation, token, _ = integrity_context(ctx)

    def frida(probes):
        probes["runtime_maps"]["suspicious_tokens"] = ["frida", "gadget"]
        probes["runtime_maps"]["suspicious_line_count"] = 3

    decision = submit_report(api, installation, token, frida)
    expect(
        "android_frida_runtime_artifact" in codes(decision),
        "expected android_frida_runtime_artifact, got %s" % codes(decision),
    )
    expect(decision["verdict"] == "block", "expected block, got %s" % decision["verdict"])


@check("integrity: an open Frida port is caught")
def check_frida_port(api, ctx):
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api,
        installation,
        token,
        lambda probes: probes["frida_ports"].update({"open_ports": [27042]}),
    )
    expect(
        "android_frida_port_open" in codes(decision),
        "expected android_frida_port_open, got %s" % codes(decision),
    )


@check("integrity: root framework artifacts and su are caught")
def check_root(api, ctx):
    installation, token, _ = integrity_context(ctx)

    def rooted(probes):
        probes["root_files"]["found_paths"] = ["/data/adb/magisk"]
        probes["root_shell"].update({"su_found": True, "su_path": "/system/xbin/su"})

    decision = submit_report(api, installation, token, rooted)
    found = codes(decision)
    expect("android_root_framework_artifact" in found, "missing root framework: %s" % found)
    expect("android_su_on_path" in found, "missing su_on_path: %s" % found)
    expect(decision["verdict"] == "block", "expected block, got %s" % decision["verdict"])


@check("integrity: a writable system mount is caught")
def check_writable_mount(api, ctx):
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api,
        installation,
        token,
        lambda probes: probes["mounts"].update({"protected_rw_mounts": ["/system"]}),
    )
    expect(
        "android_protected_mount_writable" in codes(decision),
        "expected android_protected_mount_writable, got %s" % codes(decision),
    )


@check("integrity: a development OS image is caught")
def check_development_image(api, ctx):
    """Covers the userdebug gap found on the emulator: build type and test-keys."""
    installation, token, _ = integrity_context(ctx)

    def userdebug(probes):
        probes["system_properties"]["properties"]["ro.build.type"] = "userdebug"
        probes["system_properties"]["properties"]["ro.build.tags"] = "test-keys"
        probes["root_files"]["test_keys"] = True

    decision = submit_report(api, installation, token, userdebug)
    found = codes(decision)
    expect("android_build_type_not_user" in found, "missing build_type_not_user: %s" % found)
    expect("android_test_keys" in found, "missing test_keys: %s" % found)


@check("integrity: absent Verified Boot data is caught")
def check_boot_state_absent(api, ctx):
    installation, token, _ = integrity_context(ctx)

    def blank_boot(probes):
        for name in (
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
        ):
            probes["system_properties"]["properties"][name] = ""

    decision = submit_report(api, installation, token, blank_boot)
    expect(
        "android_boot_state_unavailable" in codes(decision),
        "expected android_boot_state_unavailable, got %s" % codes(decision),
    )


@check("integrity: a signing-certificate mismatch is a hard block")
def check_cert_mismatch(api, ctx):
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api, installation, token, cert=sha256_hex(b"an-attacker-resigned-this-apk")
    )
    if "android_signing_certificate_mismatch" not in codes(decision):
        # A server with no INTEGRITY_ANDROID_CERT_SHA256 allow-list cannot
        # produce a mismatch. That is a valid deployment, not a failure, so skip
        # rather than report a defect the operator cannot act on.
        raise Skip(
            "no certificate allow-list configured; set "
            "INTEGRITY_ANDROID_CERT_SHA256 to make this check meaningful"
        )
    expect(decision["verdict"] == "block", "expected block, got %s" % decision["verdict"])
    expect(decision["score"] == 100, "hard block should cap at 100, got %s" % decision["score"])


@check("integrity: a renamed Frida gadget is caught by its runtime thread")
def check_instrumentation_thread(api, ctx):
    """The DESIGN.md 27.11 evasion, as a permanent regression test.

    runtime_maps and frida_ports are left CLEAN - as they are when the injected
    library is renamed and moved off the default port - so only the structural
    signal is present. This must still block, or the rename evasion is back.
    """
    installation, token, _ = integrity_context(ctx)

    def renamed_gadget(probes):
        probes["runtime_maps"]["suspicious_tokens"] = []
        probes["frida_ports"]["open_ports"] = []
        probes["instrumentation_threads"]["frida_threads"] = ["gum-js-loop"]

    decision = submit_report(api, installation, token, renamed_gadget)
    expect(
        "android_instrumentation_runtime_thread" in codes(decision),
        "expected android_instrumentation_runtime_thread, got %s" % codes(decision),
    )
    expect(
        decision.get("verdict") == "block",
        "a renamed gadget must still block; got verdict %r" % decision.get("verdict"),
    )


@check("integrity: writable-executable memory is caught")
def check_wx_memory(api, ctx):
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api,
        installation,
        token,
        lambda probes: probes["exec_mappings"].update({"wx_mappings": 1}),
    )
    expect(
        "android_wx_memory" in codes(decision),
        "expected android_wx_memory, got %s" % codes(decision),
    )


@check("integrity: an inline hook in a system library is caught")
def check_code_integrity(api, ctx):
    """Native code_integrity: libc .text in memory diverging from disk is an
    inline hook, caught by byte comparison whatever the hooking tool is called."""
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api,
        installation,
        token,
        lambda probes: probes["code_integrity"].update(
            {"libc_diff_bytes": 71, "diff_bytes": 71}
        ),
    )
    expect(
        "android_code_integrity_violation" in codes(decision),
        "expected android_code_integrity_violation, got %s" % codes(decision),
    )
    expect(
        decision.get("verdict") == "block",
        "an inline hook must block; got %r" % decision.get("verdict"),
    )


@check("integrity: w^x still scores when the client sends no wx_bytes")
def check_wx_absent_field_still_scores(api, ctx):
    """Regression guard requested by the .NET SDK session.

    A proposed change scores writable-executable memory against a per-build
    baseline using a `wx_bytes` field that only some clients send. Implemented
    naively as `int(probe.get("wx_bytes") or 0)`, a client that does not send
    the field yields 0, the excess computes to zero, and W^X scoring is
    silently switched off for that client - a Flutter device with a live
    injected gadget would score nothing. Absence must not be read as zero.
    """
    installation, token, _ = integrity_context(ctx)

    def wx_without_bytes(probes):
        probes["exec_mappings"].update({"wx_mappings": 1})
        probes["exec_mappings"].pop("wx_bytes", None)

    decision = submit_report(api, installation, token, wx_without_bytes)
    expect(
        "android_wx_memory" in codes(decision),
        "a report with wx_mappings>0 and no wx_bytes must still score "
        "android_wx_memory; got %s" % codes(decision),
    )



CONFORMANCE_APK_SHA256 = hashlib.sha256(b"conformance-apk").hexdigest()
CONFORMANCE_WX_BASELINE = (1048576, 65536)  # the .NET build's measured shape (DESIGN.md 62)


@check("integrity: writable-executable memory is scored against the build's pinned baseline")
def check_wx_baseline(api, ctx):
    """DESIGN.md 62 and 69. With a baseline pinned for the conformance APK, a
    report at the baseline in whole granules scores nothing; a size the runtime
    never allocates scores the foreign-allocator reason; growth above the
    baseline up to the DBA's wx_far_above_baseline_percent (owner default 200)
    is advisory -- visible, 0 points -- and beyond it scores +40; a report
    without wx_bytes still scores today's +60 even for a baselined build. Skips
    unless the server pins INTEGRITY_ANDROID_WX_BASELINES=<conformance apk
    sha256>:1048576:65536."""
    installation, token, _ = integrity_context(ctx)
    total, granule = CONFORMANCE_WX_BASELINE
    percent = int(live_settings(api).get("wx_far_above_baseline_percent", "200"))

    def shape(granules, extra_classes="", drop_bytes=False):
        classes = "%d:%d%s" % (granule, granules, extra_classes)

        def mutate(probes):
            em = probes["exec_mappings"]
            em.update({"wx_mappings": sum(int(c.split(":")[1]) for c in classes.split(",")),
                       "wx_bytes": sum(int(c.split(":")[0]) * int(c.split(":")[1])
                                       for c in classes.split(",")),
                       "wx_size_classes": classes})
            if drop_bytes:
                em.pop("wx_bytes", None)
        return submit_report(api, installation, token, mutate)

    def wx(decision):
        return {r["code"]: r["points"] for r in decision.get("reasons", [])
                if r["code"] in ("android_wx_memory", "android_wx_foreign_allocator",
                                 "android_wx_above_baseline", "android_wx_far_above_baseline")}

    base = total // granule
    clean = wx(shape(base))
    if "android_wx_memory" in clean:
        raise Skip("no baseline pinned for the conformance APK; set "
                   "INTEGRITY_ANDROID_WX_BASELINES=%s:%d:%d to run this check"
                   % (CONFORMANCE_APK_SHA256, total, granule))
    expect(not clean, "a report at the baseline in whole granules must score no W^X reason, got %s"
           % clean)
    foreign = wx(shape(base - 1, ",4096:1"))
    expect(foreign.get("android_wx_foreign_allocator") == 45 and "android_wx_memory" not in foreign,
           "a 4096-byte W^X region must score android_wx_foreign_allocator, got %s" % foreign)
    if (base + 1) * granule * 100 <= total * percent:
        above = wx(shape(base + 1))
        expect(above == {"android_wx_above_baseline": 0},
               "growth just above the baseline must be advisory (0 points), got %s" % above)
    limit = total * percent // 100
    at = limit // granule
    if at * granule * 100 == total * percent:
        edge = wx(shape(at))
        expect(edge == {"android_wx_above_baseline": 0},
               "exactly %d%% of the baseline is still within the allowance, got %s" % (percent, edge))
    far = wx(shape(at + 1))
    expect(far == {"android_wx_far_above_baseline": 40},
           "growth beyond %d%% of the baseline must score +40, got %s" % (percent, far))
    absent = wx(shape(base, drop_bytes=True))
    expect(absent.get("android_wx_memory") == 60,
           "a baselined build's report without wx_bytes must still score android_wx_memory, got %s"
           % absent)


def _setting_words(settings, key, default):
    raw = str(settings.get(key, default))
    return {word.strip() for word in raw.replace(";", ",").split(",") if word.strip()}


def live_settings(api):
    """The server's risk_policy_settings, as /health/ready publishes them."""
    _, health = api.call("GET", "/health/ready")
    health = health if isinstance(health, dict) else {}
    return (health.get("scoring_flags") or {}).get("risk_policy_settings") or {}


def _setting_on(settings, key):
    return str(settings.get(key, "0")).strip().lower() in ("1", "true", "yes", "on")


@check("integrity: developer options and ADB are advisory and cost no points")
def check_developer_settings_advisory(api, ctx):
    """Joint review R1 (DESIGN.md 69): common on legitimate phones and not
    evidence of compromise, so they are recorded but never add up into a
    refusal. A deployment that wants them off uses an eligibility rule."""
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["developer_settings"].update(
            {"developer_options_enabled": True, "adb_enabled": True}))
    for code in ("android_developer_options", "android_adb_enabled"):
        reason = reason_for(decision, code)
        expect(reason is not None and reason["points"] == 0,
               "%s must be recorded at 0 points, got %s" % (code, reason))
    # Leave the shared installation's latest scan clean: with an eligibility
    # rule set and enforcement on, a later check would otherwise be refused
    # integrity_device_ineligible for a reason that is not its own.
    submit_report(api, installation, token)
    expect(decision["score"] == 0 and decision["verdict"] == "trusted",
           "developer options and ADB alone must leave a clean device trusted, got %s %s"
           % (decision["score"], decision["verdict"]))


@check("integrity: an eligibility rule refuses with its own code and remedy")
def check_eligibility_rule(api, ctx):
    """DESIGN.md 69. With developer_options_refuses or adb_enabled_refuses set to
    1, a scan reporting that setting on is refused in enforce mode with
    integrity_device_ineligible and a remedy, and reported in observe mode; a
    new scan with the setting off clears it. Skips unless a rule is set."""
    settings = live_settings(api)
    rules = [key for key in ("developer_options_refuses", "adb_enabled_refuses")
             if _setting_on(settings, key)]
    if not rules:
        raise Skip("no eligibility rule is set; set developer_options_refuses or "
                   "adb_enabled_refuses to 1 to run this check")
    integrity_context(ctx)
    inst, hint = Installation(), fresh_hint()
    st, pl = enrol(api, inst, hint)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token)
    st, pl = open_account(api, inst, token, "elig-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]
    submit_report(api, inst, token, lambda probes: probes["developer_settings"].update(
        {"developer_options_enabled": True, "adb_enabled": True}))
    st, pl = protected(api, inst, "GET", "/v1/account/me", access)
    if ctx["mode"] == "enforce":
        found = ((pl.get("error") or {}).get("details") or {}).get("eligibility") or []
        expect(st == 403 and error_code(pl) == "integrity_device_ineligible"
               and sorted(e.get("rule") for e in found) == sorted(rules)
               and all(e.get("remedy") for e in found),
               "expected 403 integrity_device_ineligible naming %s with a remedy, got %s %s %s"
               % (rules, st, error_code(pl), found))
    else:
        found = (pl.get("integrity") or {}).get("eligibility") or []
        expect(st == 200 and sorted(e.get("rule") for e in found) == sorted(rules),
               "observe mode must report the failed rules %s, got %s %s" % (rules, st, found))
    submit_report(api, inst, token)
    st, pl = protected(api, inst, "GET", "/v1/account/me", access)
    expect(st == 200 and not (pl.get("integrity") or {}).get("eligibility"),
           "a new scan with the settings off must clear it, got %s %s" % (st, error_code(pl)))

@check("integrity: a VPN and an HTTP proxy are measured and score the DBA's small points")
def check_network_probe(api, ctx):
    """DESIGN.md 80, 83. A current collector volunteers the network probe on
    every scan; a VPN and an HTTP proxy are recorded (android_vpn_active,
    android_http_proxy) at the DBA's vpn_active_points and http_proxy_points
    (owner defaults 10 and 15), conditions the device memory never keeps."""
    integrity_context(ctx)
    settings = live_settings(api)
    if _setting_on(settings, "vpn_active_refuses") or _setting_on(settings, "http_proxy_refuses"):
        raise Skip("a network eligibility rule is set here; this check needs neither")
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    plain = submit_report(api, inst, token)

    def tunnel(probes):
        probes["network"].update(vpn_active=True, http_proxy_configured=True,
                                 transports=["wifi", "vpn"], interfaces=["wlan0", "tun0"])

    decision = submit_report(api, inst, token, tunnel)
    points = {r["code"]: r["points"] for r in decision.get("reasons", [])}
    vpn = int(str(settings.get("vpn_active_points", "10")).strip() or "10")
    proxy = int(str(settings.get("http_proxy_points", "15")).strip() or "15")
    expect(points.get("android_vpn_active") == vpn and points.get("android_http_proxy") == proxy
           and decision["score"] == min(100, plain["score"] + vpn + proxy)
           and decision.get("finding_score") == plain.get("finding_score"),
           "a VPN and a proxy score %d + %d and are never remembered: %s, score %s -> %s"
           % (vpn, proxy, points, plain["score"], decision["score"]))


@check("integrity: optional measurements are asked for as the DBA lists them, kept only then")
def check_optional_measurements(api, ctx):
    """DESIGN.md 80. The challenge's optional_probes are the DBA's
    optional_measurements, never required; an app that did not enable one
    answers not_enabled at no cost. With the business token, a measurement
    the app sends is stored only while the DBA requests it."""
    integrity_context(ctx)
    settings = live_settings(api)
    requested = [name for name in OPTIONAL_NAMES
                 if name in _setting_words(settings, "optional_measurements", "")]
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    st, challenge = protected(api, inst, "POST", "/v1/integrity/challenge", token, {})
    expect(st == 200 and challenge.get("optional_probes") == requested
           and not set(requested) & set(challenge.get("required_probes", [])),
           "optional_probes must be the DBA's list, never required: %s %s"
           % (challenge.get("optional_probes"), requested))
    plain = submit_report(api, inst, token)
    expect(plain["verdict"] == "trusted" and not {c for c in codes(plain)
                                                  if c.startswith("integrity_")},
           "not_enabled answers cost nothing: %s" % codes(plain))
    business = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if not business:
        return
    # The app enabled them all; whether each is kept is the DBA's request alone.
    submit_report(api, inst, token, lambda probes: probes.update(
        {name: copy.deepcopy(OPTIONAL_CLEAN[name]) for name in OPTIONAL_NAMES}))
    st, feed = api.call("GET", "/v1/business/integrity-reports?" + urllib.parse.urlencode(
        {"device_id": inst.device_id, "limit": "10"}),
        headers={"Authorization": "Bearer " + business})
    latest = (feed.get("reports") or [{}])[-1].get("probe_results") or {}
    expect(st == 200 and {name for name in OPTIONAL_NAMES if name in latest} == set(requested)
           and all(latest[name] == OPTIONAL_CLEAN[name] for name in requested),
           "each optional measurement must be stored exactly while requested (%s): %s"
           % (requested, sorted(latest)))


@check("integrity: an app holding Accessibility is judged by its source; its rule refuses")
def check_access_holders(api, ctx):
    """DESIGN.md 82. Where the DBA requests accessibility, a sideloaded app with
    an Accessibility service on scores android_accessibility_sideloaded at the
    DBA's accessibility_sideloaded_points (owner default 45: a step-up), plus
    accessibility_non_system_points (0); with accessibility_sideloaded_refuses
    set it is refused in enforce mode (integrity_device_ineligible, with a
    remedy) and reported in observe mode; a scan without it clears it. Skips
    unless requested."""
    settings = live_settings(api)
    if "accessibility" not in _setting_words(settings, "optional_measurements", ""):
        raise Skip("the DBA does not request accessibility; add it to optional_measurements "
                   "to run this check")
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    plain = submit_report(api, inst, token, enabled=("accessibility",))
    st, pl = open_account(api, inst, token, "a11y-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]

    def trojan(probes):
        probes["accessibility"]["services"].append(copy.deepcopy(SIDELOADED_SERVICE))

    decision = submit_report(api, inst, token, trojan, enabled=("accessibility",))
    points = {r["code"]: r["points"] for r in decision.get("reasons", [])}
    side = int(str(settings.get("accessibility_sideloaded_points", "45")).strip() or "45")
    wide = int(str(settings.get("accessibility_non_system_points", "0")).strip() or "0")
    expect(points.get("android_accessibility_sideloaded") == side
           and points.get("android_accessibility_non_system") == wide
           and decision["score"] == min(100, plain["score"] + side + wide),
           "a sideloaded Accessibility service scores %d + %d: %s, score %s -> %s"
           % (side, wide, points, plain["score"], decision["score"]))
    st, pl = protected(api, inst, "GET", "/v1/account/me", access)
    rule = "accessibility_sideloaded_refuses"
    if ctx["mode"] == "enforce" and decision["verdict"] in ("review", "block"):
        expect(st == 403, "a %s verdict is refused, got %s %s"
               % (decision["verdict"], st, error_code(pl)))
    elif _setting_on(settings, rule) and ctx["mode"] == "enforce":
        found = ((pl.get("error") or {}).get("details") or {}).get("eligibility") or []
        expect(st == 403 and error_code(pl) == "integrity_device_ineligible"
               and rule in [e.get("rule") for e in found] and all(e.get("remedy") for e in found),
               "expected 403 integrity_device_ineligible naming %s, got %s %s %s"
               % (rule, st, error_code(pl), found))
    elif ctx["mode"] == "enforce" and decision["verdict"] == "elevated":
        expect(st == 403 and error_code(pl) == "integrity_step_up_required",
               "an elevated verdict asks for a step-up, got %s %s" % (st, error_code(pl)))
    else:
        found = [e.get("rule") for e in (pl.get("integrity") or {}).get("eligibility") or []]
        expect(st == 200 and (rule in found) == _setting_on(settings, rule),
               "%s=%s: reported %s, got %s" % (rule, settings.get(rule), found, st))
    submit_report(api, inst, token, enabled=("accessibility",))
    st, pl = protected(api, inst, "GET", "/v1/account/me", access)
    expect(st == 200 and not (pl.get("integrity") or {}).get("eligibility"),
           "a scan without it must clear it, got %s %s" % (st, error_code(pl)))


@check("integrity: every scan reports each measurement's status and its settings version")
def check_measurement_status(api, ctx):
    """Review F1 and F4 (DESIGN.md 83). Every scan's answer gives the status of
    every measurement the platform's collectors answer -- ok where measured,
    not_enabled where the server asked and the app had not enabled it,
    not_requested where the server did not ask -- with the app's
    enabled_measurements, and the version of the settings it was scored
    under, which the latest scan repeats as current."""
    installation, token, _ = integrity_context(ctx)
    sent = {}
    decision = submit_report(api, installation, token, lambda probes: sent.update(
        {name: (value or {}).get("status") for name, value in probes.items()}))
    measured = decision.get("measurements") or {}
    status = measured.get("status") or {}
    expected = {"ok": "ok", "not_enabled": "not_enabled", None: "not_requested"}
    wrong = {name: (state, sent.get(name)) for name, state in status.items()
             if state != expected.get(sent.get(name), "?")}
    expect(status and not wrong and set(sent) <= set(status),
           "each measurement's status: wrong %s, unreported %s" % (wrong, set(sent) - set(status)))
    expect(measured.get("enabled_by_app") == [], "enabled_by_app: %s" % measured.get("enabled_by_app"))
    version = decision.get("policy_version") or ""
    expect(len(version) == 16 and all(ch in "0123456789abcdef" for ch in version),
           "policy_version: %r" % version)
    st, me = protected(api, installation, "GET", "/v1/integrity/me", token)
    latest = (me or {}).get("integrity") or {}
    expect(st == 200 and latest.get("report_id") == decision.get("report_id")
           and latest.get("policy_version") == version and latest.get("policy_current") is True
           and latest.get("measurements") == measured,
           "the latest scan repeats them: %s %s" % (st, {k: latest.get(k) for k in (
               "report_id", "policy_version", "policy_current")}))


@check("integrity: a path's required measurements are met only by measuring them")
def check_required_measurements(api, ctx):
    """Review F1 (DESIGN.md 83). Where the DBA lists required_measurements, a
    scan without one -- the app did not enable it -- says requirements_satisfied
    false and names it in missing_requirements; a scan measuring them satisfies
    them. In enforce mode a request on a guarded path is refused
    (integrity_measurements_missing, or a step-up request under
    missing_measurement_action limit) until a scan has them. Skips unless the
    DBA requires measurements it also requests."""
    settings = live_settings(api)
    required = [name for name in OPTIONAL_NAMES
                if name in _setting_words(settings, "required_measurements", "")]
    if not required or not set(required) <= set(_setting_words(settings, "optional_measurements", "")):
        raise Skip("set required_measurements to optional measurements the DBA also requests "
                   "in optional_measurements to run this check")
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    full = submit_report(api, inst, token, enabled=tuple(required))
    expect(full.get("requirements_satisfied") is True and full.get("missing_requirements") == [],
           "measured, they are satisfied: %s" % full.get("missing_requirements"))
    st, pl = open_account(api, inst, token, "req-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]
    bare = submit_report(api, inst, token)
    missing = {m.get("measurement"): m.get("status") for m in bare.get("missing_requirements") or []}
    expect(bare.get("requirements_satisfied") is False
           and missing == {name: "not_enabled" for name in required},
           "not enabled, each is missing: %s" % bare.get("missing_requirements"))
    st, pl = protected(api, inst, "GET", "/v1/account/me", access)
    paths = _setting_words(settings, "required_measurements_paths", "")
    guarded = not paths or "/v1/account/me" in paths
    if ctx["mode"] == "enforce" and guarded:
        allowed = (("integrity_measurements_missing",)
                   if settings.get("missing_measurement_action") == "refuse"
                   else ("integrity_measurements_missing", "integrity_step_up_required"))
        expect(st == 403 and error_code(pl) in allowed,
               "a guarded path waits for the measurements: %s %s" % (st, error_code(pl)))
    else:
        state = (pl or {}).get("integrity") or {}
        expect(st == 200 and (state.get("requirements_satisfied") is False) == guarded,
               "observe reports, never refuses: %s %s" % (st, state.get("missing_requirements")))
    submit_report(api, inst, token, enabled=tuple(required))
    st, pl = protected(api, inst, "GET", "/v1/account/me", access)
    expect(st == 200, "a scan with them passes again: %s %s" % (st, error_code(pl)))


@check("integrity: conditions never block alone, and a clean scan restores access")
def check_conditions_cap(api, ctx):
    """Review F2 (DESIGN.md 83). A sideloaded Accessibility service, a remote-
    control app and a screen recording -- a support session -- scored 45 + 20
    + 30 = 95, a block the device memory kept for 24 hours. Conditions now add
    at most conditions_points_cap (owner default 60) together, a reduced one
    says points_before_cap, and only integrity findings are remembered: with
    SELinux permissive besides (45, an integrity finding) the scan may block,
    yet after a clean scan the device memory holds no block. Skips unless the
    DBA requests accessibility, other_access and screen_capture."""
    settings = live_settings(api)
    needed = ("accessibility", "other_access", "screen_capture")
    if not set(needed) <= set(_setting_words(settings, "optional_measurements", "")):
        raise Skip("the DBA does not request accessibility, other_access and screen_capture; add "
                   "them to optional_measurements to run this check")
    integrity_context(ctx)

    def points(key, default):
        return int(str(settings.get(key, default)).strip() or default)

    cap = points("conditions_points_cap", "60")
    raw = (points("accessibility_sideloaded_points", "45")
           + points("accessibility_non_system_points", "0")
           + points("remote_access_app_points", "20") + points("screen_capture_points", "30"))
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token, enabled=needed)
    st, pl = open_account(api, inst, token, "cap-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]

    def support_session(probes):
        probes["accessibility"]["services"].append(copy.deepcopy(SIDELOADED_SERVICE))
        probes["other_access"]["remote_access_apps"].append(
            {"package": "com.teamviewer.quicksupport.market", "system": False,
             "installer": "com.android.vending"})
        probes["screen_capture"]["recording"] = True
        probes["selinux"].update({"mode": "permissive", "getenforce": "Permissive",
                                  "enforce_value": "0"})

    scan = submit_report(api, inst, token, support_session, enabled=needed)
    conditions = [r for r in scan.get("reasons", []) if r.get("category") == "condition"]
    capped = sum(r.get("points", 0) for r in conditions)
    expect(capped == min(cap, raw) and scan.get("finding_score") == 45
           and any("points_before_cap" in r for r in conditions) == (raw > cap),
           "conditions add %d of %d, the cap %d; finding_score %s: %s"
           % (capped, raw, cap, scan.get("finding_score"),
              [(r["code"], r.get("points"), r.get("points_before_cap")) for r in conditions]))
    submit_report(api, inst, token, enabled=needed)
    st, pl = protected(api, inst, "GET", "/v1/policy/me", access)
    memory = (((pl or {}).get("policy") or {}).get("context") or {}).get("device_integrity_memory") or {}
    expect(st == 200 and memory.get("finding_verdict") != "block",
           "after a clean scan nothing holds the phone: %s %s %s"
           % (st, error_code(pl), memory.get("finding_verdict")))


@check("decisions: every scan and decision answers the four questions apart")
def check_four_answers(api, ctx):
    """DESIGN.md 84.2, item 8 of the eight of 2026-10-14. A scan's assessment
    says what proved it (challenge, signature, installation key), what it
    measured, what it found -- each reason, from the phone -- and what it calls
    for; a protected request's decision adds the relationship policy's reasons
    and what the request was granted."""
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    scan = submit_report(api, inst, token)
    answers = scan.get("assessment") or {}
    protocol, evidence = answers.get("protocol") or {}, answers.get("evidence") or {}
    expect(protocol.get("result") == "valid" and protocol.get("token") == "device"
           and protocol.get("installation_key") == "verified"
           and protocol.get("challenge") == "single_use"
           and protocol.get("report_signature") == "verified",
           "the scan says what proved it: %s" % protocol)
    expect(evidence.get("quality") == scan.get("evidence_quality")
           and evidence.get("report_id") == scan.get("report_id") and evidence.get("fresh") is True,
           "the scan says what it measured: %s" % evidence)
    expect([(f.get("code"), f.get("points"), f.get("provenance")) for f in answers.get("findings") or []]
           == [(r.get("code"), r.get("points"), "phone") for r in scan.get("reasons") or []],
           "the scan's findings are its reasons, from the phone: %s" % answers.get("findings"))
    decision = answers.get("decision") or {}
    expect(decision.get("recommended") in ("allow", "step_up", "scan", "review", "deny")
           and decision.get("relationship") is None,
           "the scan says what it calls for: %s" % decision)
    st, pl = open_account(api, inst, token, "four-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    granted = (((pl or {}).get("policy") or {}).get("assessment") or {}).get("decision") or {}
    expect(granted.get("allowed") == pl.get("scope"),
           "the new session says what it was granted: %s %s" % (pl.get("scope"), granted))
    st, me = protected(api, inst, "GET", "/v1/account/me", pl["access_token"])
    trust = (me or {}).get("trust_policy") or {}
    answers = trust.get("assessment") or {}
    decision = answers.get("decision") or {}
    found = {f.get("code") for f in answers.get("findings") or []}
    expect(st == 200 and (answers.get("protocol") or {}).get("token") == "account"
           and (answers.get("evidence") or {}).get("report_id") == scan.get("report_id")
           and decision.get("allowed") in ("full", "limited")
           and decision.get("relationship") in ("allow", "step_up", "review", "deny")
           and {r.get("code") for r in trust.get("reasons") or []} <= found,
           "a request's decision adds the policy and what was granted: %s %s" % (st, answers))


@check("integrity: a scan made for one operation approves that request once")
def check_operation_scan(api, ctx):
    """DESIGN.md 84.3, item 2 of the eight of 2026-10-14. On a path the DBA
    lists in operation_scan_paths, a request names the scan made for it
    (X-Integrity-Report): the server judges that scan, once. In enforce mode a
    request without one, or a second use, is refused; in observe mode the
    decision names the refusal. With DEVICE_TRUST_BUSINESS_TOKEN holding the
    operations role, a backend verifies a scan for its own operation once.
    Skips unless the protected echo is in operation_scan_paths."""
    path = "/v1/account/protected-echo"
    if path not in _setting_words(live_settings(api), "operation_scan_paths", ""):
        raise Skip("add %s to operation_scan_paths to run this check" % path)
    enforce = ctx.get("mode") == "enforce"
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    device = device_token(api, inst)
    submit_report(api, inst, device)
    st, pl = open_account(api, inst, device, "op-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]
    body = {"amount": 125, "payee": "p-%s" % secrets.token_hex(3)}
    body_text = json.dumps(body)
    operation = {"method": "POST", "path": path, "query": "",
                 "body_sha256": sha256_hex(body_text.encode("utf-8"))}

    def send(report_id=None):
        headers, text = build_proof(inst, "POST", path, access, body)
        if report_id:
            headers["X-Integrity-Report"] = report_id
        return api.call("POST", path, body_text=text, bearer=access, headers=headers)

    scan = submit_report(api, inst, access, operation=operation)
    expect(len(scan.get("operation_sha256") or "") == 64, "the scan names its operation: %s"
           % scan.get("operation_sha256"))
    st, pl = send(scan["report_id"])
    bound = ((pl or {}).get("trust_policy") or {}).get("context", {}).get("operation_scan") or {}
    expect(st == 200 and bound.get("report_id") == scan["report_id"],
           "the request is judged on the scan made for it: %s %s %s" % (st, error_code(pl), bound))
    st, pl = send(scan["report_id"])
    if enforce:
        expect(st == 409 and error_code(pl) == "integrity_operation_scan_used",
               "a second use is refused: %s %s" % (st, error_code(pl)))
        st, pl = send()
        expect(st == 403 and error_code(pl) == "integrity_operation_scan_required"
               and ((pl.get("error") or {}).get("details") or {}).get("operation") == operation,
               "without a scan the app is told what to scan for: %s %s" % (st, pl))
    else:
        named = ((pl or {}).get("trust_policy") or {}).get("context", {}).get("operation_scan") or {}
        expect(st == 200 and named.get("problem") == "integrity_operation_scan_used",
               "observe mode lets a second use through and names it: %s %s" % (st, named))
    token = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if not token:
        return
    theirs = {"method": "POST", "path": "/payments", "query": "",
              "body_sha256": sha256_hex(b'{"amount":125}')}
    scan = submit_report(api, inst, access, operation=theirs)
    ask = json.dumps({"report_id": scan["report_id"], "installation_id": inst.installation_id,
                      "operation": theirs})
    business = {"Authorization": "Bearer " + token}
    st, answer = api.call("POST", "/v1/business/operation-scans/verify", headers=business,
                          body_text=ask)
    if st == 403 and error_code(answer) == "business_role_missing":
        return
    decision = (answer or {}).get("decision") or {}
    expect(st == 200 and answer.get("report_id") == scan["report_id"]
           and decision.get("event_type") == "operation_check"
           and (decision.get("assessment") or {}).get("decision", {}).get("recommended"),
           "a backend verifies a scan for its own operation: %s %s" % (st, answer))
    st, again = api.call("POST", "/v1/business/operation-scans/verify", headers=business,
                         body_text=ask)
    expect(st == 409 and error_code(again) == "integrity_operation_scan_used",
           "once: %s %s" % (st, again))


@check("integrity: each installation is compared with its own earlier scans")
def check_installation_history(api, ctx):
    """DESIGN.md 84.4, item 5 of the eight of 2026-10-14. A first scan has no
    past; a later scan from the same installation claiming another phone model
    gets installation_device_changed (category history), at the DBA's points
    where history_checks_enabled is 1, at 0 otherwise; the scan after it,
    unchanged against that one, gets nothing new."""
    settings = live_settings(api)
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)

    def history(scan):
        return {r["code"]: r for r in scan.get("reasons", []) if r.get("category") == "history"}

    first = submit_report(api, inst, token)
    expect(not history(first), "a first scan has no past: %s" % history(first))
    moved = submit_report(api, inst, token, lambda probes: probes["device"].update(model="Elsewhere"))
    found = history(moved).get("installation_device_changed") or {}
    scored = str(settings.get("history_checks_enabled", "0")).strip() in ("1", "true", "yes", "on")
    wanted = int(str(settings.get("installation_device_changed_points", "60")).strip()) if scored else 0
    expect(found.get("points") == wanted,
           "another phone model under the same installation: %s points, wanted %d"
           % (found.get("points"), wanted))
    again = submit_report(api, inst, token, lambda probes: probes["device"].update(model="Elsewhere"))
    expect("installation_device_changed" not in history(again),
           "unchanged since: nothing new: %s" % history(again))


@check("risk: the source IP and User-Agent are kept only where the DBA says")
def check_request_metadata(api, ctx):
    """DESIGN.md 80. A decision's context carries source_ip only under
    record_source_ip and user_agent only under record_user_agent."""
    settings = live_settings(api)
    inst, _, _, access, _ = _pin_phone(api, settings, False)
    headers, _ = build_proof(inst, "GET", "/v1/policy/me", access, None)
    headers["User-Agent"] = "conformance-suite/80"
    st, pl = api.call("GET", "/v1/policy/me", bearer=access, headers=headers)
    context = ((pl.get("policy") or {}).get("context")) or {}
    expect(st == 200 and ("source_ip" in context) == _setting_on(settings, "record_source_ip")
           and (context.get("user_agent") == "conformance-suite/80")
           == _setting_on(settings, "record_user_agent")
           and ("user_agent" in context) == _setting_on(settings, "record_user_agent"),
           "context must follow record_source_ip=%s record_user_agent=%s: %s"
           % (settings.get("record_source_ip"), settings.get("record_user_agent"),
              {k: context.get(k) for k in ("source_ip", "user_agent")}))


@check("risk: every decision says what network the request came from")
def check_source_network(api, ctx):
    """DESIGN.md 81. A decision's context carries source_network: five yes/no
    answers, each None where the server cannot know -- vpn_observed while
    vpn_exit_learning is off. The suite cannot choose the address it comes
    from, so only the shape and the learning switch are checked here."""
    settings = live_settings(api)
    inst, _, _, access, _ = _pin_phone(api, settings, False)
    st, pl = protected(api, inst, "GET", "/v1/policy/me", access)
    network = (((pl.get("policy") or {}).get("context")) or {}).get("source_network")
    keys = {"vpn_listed", "tor_exit", "hosting", "vpn_observed", "vpn_observed_non_hosting"}
    expect(st == 200 and isinstance(network, dict) and set(network) == keys
           and all(value in (True, False, None) for value in network.values()),
           "source_network must carry its five answers: %s %s" % (st, network))
    learning = _setting_on(settings, "vpn_exit_learning")
    expect((network["vpn_observed"] is None) == (not learning),
           "vpn_observed is None exactly while learning is off (vpn_exit_learning=%s): %s"
           % (settings.get("vpn_exit_learning"), network))


@check("integrity: the ART JIT code cache is not mistaken for injection")
def check_jit_not_flagged(api, ctx):
    """deleted_exec_jit is the legitimate JIT cache; it must never score."""
    installation, token, _ = integrity_context(ctx)
    decision = submit_report(
        api,
        installation,
        token,
        lambda probes: probes["exec_mappings"].update(
            {"deleted_exec_jit": 3, "deleted_exec_mappings": 0}
        ),
    )
    expect(
        "android_deleted_code_mapping" not in codes(decision),
        "the JIT cache must not be flagged; got %s" % codes(decision),
    )
    expect(
        decision.get("verdict") == "trusted",
        "a device with only the JIT cache must stay trusted; got %r"
        % decision.get("verdict"),
    )


# ---------------------------------------------------------------------------
# iOS integrity scoring
#
# _score_ios_integrity had never been executed before these checks existed: the
# iOS client is new and no iPhone has run the battery yet. Exercising the rules
# against crafted reports proves the server half now, and would otherwise only
# be discovered when the hardware arrives.
# ---------------------------------------------------------------------------


def api_for(ctx):
    return ctx["_api"]


def ios_integrity_context(ctx):
    """One iOS installation with a device token, shared by the iOS checks."""
    if "ios_integrity" in ctx:
        return ctx["ios_integrity"]
    installation = Installation()
    status, payload = enrol(api_for(ctx), installation, None, platform="ios")
    if status not in (200, 201):
        raise Skip("iOS enrol failed: %s %s" % (status, payload))
    token = device_token(api_for(ctx), installation)
    ctx["ios_integrity"] = (installation, token)
    return ctx["ios_integrity"]


@check("ios integrity: a pristine iPhone scores zero and is trusted")
def check_ios_clean(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(api, installation, token)
    expect(
        decision["verdict"] == "trusted",
        "expected trusted, got %s (%s)" % (decision["verdict"], codes(decision)),
    )
    expect(decision["score"] == 0, "expected score 0, got %s" % decision["score"])


@check("ios integrity: jailbreak filesystem artifacts are caught")
def check_ios_jailbreak(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["jailbreak_files"].update(
            {"found_paths": ["/Applications/Cydia.app", "/var/jb"]}
        ),
    )
    expect(
        "ios_jailbreak_artifact" in codes(decision),
        "expected ios_jailbreak_artifact, got %s" % codes(decision),
    )


@check("ios integrity: Frida loaded into the process blocks")
def check_ios_frida(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["dyld_images"].update(
            {"suspicious_tokens": ["frida", "gadget"]}
        ),
    )
    expect(
        "ios_frida_runtime_artifact" in codes(decision),
        "expected ios_frida_runtime_artifact, got %s" % codes(decision),
    )
    expect(
        decision["verdict"] == "block",
        "expected block, got %r" % decision["verdict"],
    )


@check("ios integrity: a jailbreak hooking framework is caught")
def check_ios_hook_framework(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["dyld_images"].update(
            {"suspicious_tokens": ["substrate", "libhooker"]}
        ),
    )
    expect(
        "ios_hook_framework_artifact" in codes(decision),
        "expected ios_hook_framework_artifact, got %s" % codes(decision),
    )


@check("ios integrity: a sandbox escape is a hard block")
def check_ios_sandbox_escape(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["sandbox"].update(
            {"write_outside_sandbox_succeeded": True}
        ),
    )
    expect(
        "ios_sandbox_escape_signal" in codes(decision),
        "expected ios_sandbox_escape_signal, got %s" % codes(decision),
    )
    expect(
        decision["verdict"] == "block",
        "a sandbox escape must be a hard block; got %r" % decision["verdict"],
    )


@check("ios integrity: DYLD_INSERT_LIBRARIES is caught")
def check_ios_dyld_insert(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["environment"].update(
            {"dyld_insert_libraries": "/var/jb/usr/lib/libhooker.dylib"}
        ),
    )
    expect(
        "ios_dyld_injection_environment" in codes(decision),
        "expected ios_dyld_injection_environment, got %s" % codes(decision),
    )


@check("ios integrity: a traced process is caught")
def check_ios_traced(api, ctx):
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["debugger"].update({"traced": True}),
    )
    expect(
        "ios_process_traced" in codes(decision),
        "expected ios_process_traced, got %s" % codes(decision),
    )


@check("integrity: a probe that fails to run is penalised")
def check_probe_failure(api, ctx):
    installation, token, _ = integrity_context(ctx)

    def broken(probes):
        probes["mounts"] = {"status": "error", "error": "permission denied"}

    decision = submit_report(api, installation, token, broken)
    expect(
        any(code.startswith("integrity_probe_failed") for code in codes(decision)),
        "expected an integrity_probe_failed reason, got %s" % codes(decision),
    )


@check("enforcement: a blocked device cannot reach protected endpoints")
def check_enforcement(api, ctx):
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode")
    installation, token, _ = integrity_session(api)
    decision = submit_report(
        api,
        installation,
        token,
        lambda probes: probes["runtime_maps"].update({"suspicious_tokens": ["frida"]}),
    )
    expect(decision["verdict"] == "block", "setup failed, expected block: %s" % decision)
    status, payload = open_account(
        api, installation, token, "conf-%s" % secrets.token_hex(4)
    )
    expect(status == 403, "expected 403, got %s %s" % (status, payload))
    expect(
        error_code(payload) == "integrity_blocked",
        "expected integrity_blocked, got %s" % error_code(payload),
    )


@check("enforcement: reinstalling does not clear a blocked device", db_sensitive=True)
def check_device_memory(api, ctx):
    """Change (d): integrity verdicts are remembered per device_id, so a new
    installation on the same physical device inherits the block. Exercises a
    query keyed on device_id across installations."""
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode")
    first, first_token, hint = integrity_session(api)
    decision = submit_report(
        api,
        first,
        first_token,
        lambda probes: probes["runtime_maps"].update({"suspicious_tokens": ["frida"]}),
    )
    expect(decision["verdict"] == "block", "setup failed, expected block: %s" % decision)

    reinstalled = Installation()
    status, payload = enrol(api, reinstalled, hint)
    expect(status in (200, 201), "reinstall enrol failed: %s %s" % (status, payload))
    expect(
        payload["device_id"] == first.device_id,
        "reinstall should correlate to the same device",
    )
    token = device_token(api, reinstalled)
    clean = submit_report(api, reinstalled, token)
    expect(
        clean["verdict"] == "trusted",
        "the new installation's own scan should be clean, got %s" % clean["verdict"],
    )
    status, payload = open_account(
        api, reinstalled, token, "conf-%s" % secrets.token_hex(4)
    )
    expect(status == 403, "expected 403 from device memory, got %s %s" % (status, payload))
    expect(
        error_code(payload) == "integrity_device_blocked_recently",
        "expected integrity_device_blocked_recently, got %s" % error_code(payload),
    )


def _frida(probes):
    probes["runtime_maps"].update({"suspicious_tokens": ["frida"]})


def _device_with_owner(api):
    """The device's original installation, scanned clean, with one account."""
    owner, hint = Installation(), fresh_hint()
    st, pl = enrol(api, owner, hint)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, owner)
    clean = submit_report(api, owner, token)
    expect(clean["verdict"] == "trusted", "setup: owner scan %s" % clean["verdict"])
    handle = "r4-%s" % secrets.token_hex(4)
    st, pl = open_account(api, owner, token, handle)
    expect(st in (200, 201), "setup: account open failed: %s %s" % (st, pl))
    return owner, hint, token, handle, pl["access_token"]


def _reinstall(api, hint, owner, clean=True):
    installation = Installation()
    st, pl = enrol(api, installation, hint)
    expect(st in (200, 201) and pl.get("device_id") == owner.device_id,
           "the hint must correlate the reinstall: %s %s" % (st, pl))
    token = device_token(api, installation)
    if clean:
        submit_report(api, installation, token)
    return installation, token


def _expect_owner_unaffected(api, ctx, owner, owner_token, handle, access, why):
    st, pl = sign_in(api, owner, owner_token, handle)
    expect(st == 200, "%s: the owner's sign-in expected 200, got %s %s"
           % (why, st, error_code(pl)))
    st, pl = protected(api, owner, "GET", "/v1/policy/me", access)
    policy = _policy_of(pl)
    expect(st == 200 and "device_integrity_history_block" not in _reason_codes(policy),
           "%s: the owner must not inherit the block, got %s %s"
           % (why, st, sorted(_reason_codes(policy)) or error_code(pl)))


@check("integrity: a block from an unconfirmed reinstall does not reach the device's owner", db_sensitive=True)
def check_unconfirmed_reinstall_block(api, ctx):
    """Joint review R4 (DESIGN.md 68). A reinstall hint is client input: anyone
    holding a device's hint could link a proven key to it and report a block,
    which refused every installation on the device for the memory window. Only
    an established installation -- the original, or a reinstall confirmed by a
    returning account -- spreads its block now. The block still counts against
    the installation that reported it."""
    integrity_context(ctx)
    owner, hint, owner_token, handle, access = _device_with_owner(api)
    intruder, intruder_token = _reinstall(api, hint, owner, clean=False)
    blocked = submit_report(api, intruder, intruder_token, _frida)
    expect(blocked["verdict"] == "block", "setup failed, expected block: %s" % blocked)
    _expect_owner_unaffected(api, ctx, owner, owner_token, handle, access,
                             "unconfirmed reinstall")
    if ctx["mode"] == "enforce":
        st, pl = sign_in(api, intruder, intruder_token, handle)
        expect(st == 403 and error_code(pl) == "integrity_blocked",
               "the blocked installation itself expected 403 integrity_blocked, got %s %s"
               % (st, error_code(pl)))


@check("integrity: a reinstall confirmed by a returning account carries its block to the device", db_sensitive=True)
def check_confirmed_reinstall_block(api, ctx):
    """DESIGN.md 68: an account that already belonged to the device, signing in
    on a reinstall, confirms it; from then on its block reaches the rest of the
    device as before R4. The policy context reports which installations are
    established."""
    integrity_context(ctx)
    owner, hint, owner_token, handle, access = _device_with_owner(api)
    reinstall, token = _reinstall(api, hint, owner)
    st, pl = sign_in(api, reinstall, token, handle)
    expect(st == 200, "the returning account's sign-in expected 200, got %s %s"
           % (st, error_code(pl)))
    context = _policy_of(pl).get("context") or {}
    expect(context.get("installation_established") is False,
           "before confirmation the reinstall is not established: %s"
           % context.get("installation_established"))
    st, pl = protected(api, reinstall, "GET", "/v1/policy/me", pl["access_token"])
    context = _policy_of(pl).get("context") or {}
    expect(st == 200 and context.get("installation_established") is True
           and context.get("installation_device_confirmed_at"),
           "the sign-in must confirm the reinstall: %s %s %s"
           % (st, context.get("installation_established"),
              context.get("installation_device_confirmed_at")))
    blocked = submit_report(api, reinstall, token, _frida)
    expect(blocked["verdict"] == "block", "setup failed, expected block: %s" % blocked)
    st, pl = protected(api, owner, "GET", "/v1/policy/me", access)
    if ctx["mode"] == "enforce":
        expect(st == 403 and error_code(pl) == "integrity_device_blocked_recently",
               "expected 403 integrity_device_blocked_recently, got %s %s"
               % (st, error_code(pl)))
    else:
        expect(st == 200 and "device_integrity_history_block" in _reason_codes(_policy_of(pl)),
               "the confirmed reinstall's block must reach the owner (+50), got %s %s"
               % (st, sorted(_reason_codes(_policy_of(pl)))))


@check("integrity: accounts opened on a reinstall cannot confirm another reinstall", db_sensitive=True)
def check_reinstall_self_confirmation(api, ctx):
    """DESIGN.md 68: only an account first linked through an established
    installation confirms. Someone holding the hint who opens an account on one
    reinstall and signs in with it on a second has confirmed nothing, so a block
    on the second still does not reach the owner."""
    integrity_context(ctx)
    owner, hint, owner_token, handle, access = _device_with_owner(api)
    first, first_token = _reinstall(api, hint, owner)
    own_handle = "r4-%s" % secrets.token_hex(4)
    st, pl = open_account(api, first, first_token, own_handle)
    expect(st in (200, 201), "account open on the reinstall failed: %s %s" % (st, pl))
    second, second_token = _reinstall(api, hint, owner)
    st, pl = sign_in(api, second, second_token, own_handle)
    expect(st == 200, "sign-in on the second reinstall expected 200, got %s %s"
           % (st, error_code(pl)))
    st, pl = protected(api, second, "GET", "/v1/policy/me", pl["access_token"])
    expect((_policy_of(pl).get("context") or {}).get("installation_established") is False,
           "an account opened on a reinstall must not confirm another: %s %s"
           % (st, _policy_of(pl).get("context")))
    blocked = submit_report(api, second, second_token, _frida)
    expect(blocked["verdict"] == "block", "setup failed, expected block: %s" % blocked)
    _expect_owner_unaffected(api, ctx, owner, owner_token, handle, access,
                             "self-confirmed reinstall")


def _refresh(api, installation, refresh_token):
    status, challenge = api.call("POST", "/v1/auth/refresh/challenge", bearer=refresh_token)
    expect(status == 200, "refresh challenge failed: %s %s" % (status, challenge))
    body = {"challenge_id": challenge["challenge_id"], "payload": challenge["payload"],
            "signature": installation.sign_b64(challenge["payload"])}
    return api.call("POST", "/v1/auth/refresh", body_text=json.dumps(body), bearer=refresh_token)


def _elevate(probes):
    """Two mild findings, 25 + 15 = 40: elevated. Since DESIGN.md 76 a failed
    probe (collection problem) cannot be approved -- only a complete scan
    clears it -- so the limited-session checks need a finding an approval can
    accept: test-keys and no Verified Boot state reported."""
    probes["root_files"]["test_keys"] = True  # android_test_keys +25
    for key in ("ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state"):
        probes["system_properties"]["properties"].pop(key, None)  # android_boot_state_unavailable +15


@check("relationship: sign-ins at the same moment cannot exceed the devices-per-account limit",
       db_sensitive=True)
def check_parallel_first_sign_ins(api, ctx):
    """Review R2 (DESIGN.md 76). An account on one phone; four new phones sign in
    to it at the same moment. Each decision sees one device, so without a
    recheck all four would link -- five devices, which no decision allowed.
    With the recheck under locks at most one more device links (the second,
    within the counts); the others are refused, with risk_review_required (the
    third device) or 409 relationship_changed (decided on counts that changed).
    Runs when DEVICE_POLICY_MODE=enforce with the owner's review count of 3."""
    _, health = api.call("GET", "/health/ready")
    health = health if isinstance(health, dict) else {}
    settings = (health.get("scoring_flags") or {}).get("risk_policy_settings") or {}
    if health.get("device_policy_mode") != "enforce":
        raise Skip("DEVICE_POLICY_MODE is not enforce; nothing is refused to race against")
    if str(settings.get("account_devices_review_count", "3")) != "3":
        raise Skip("account_devices_review_count is not the owner's 3 on this server")
    owner = Installation()
    st, pl = enrol(api, owner, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, owner)
    submit_report(api, owner, token)
    handle = "race-%s" % secrets.token_hex(4)
    st, pl = open_account(api, owner, token, handle)
    expect(st in (200, 201), "open account failed: %s %s" % (st, pl))
    phones = []
    for _ in range(4):
        inst = Installation()
        st, pl = enrol(api, inst, fresh_hint())
        expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
        phone_token = device_token(api, inst)
        submit_report(api, inst, phone_token)
        phones.append((inst, phone_token))
    barrier, lock, results = threading.Barrier(len(phones)), threading.Lock(), []

    def go(inst, phone_token):
        client = Api(api.base_url)
        try:
            barrier.wait(timeout=30)
            st, pl = sign_in(client, inst, phone_token, handle)
            outcome = (st, pl.get("scope") if st == 200 else error_code(pl))
        except BaseException as error:  # a thread must report, never vanish
            outcome = (0, str(error)[:80])
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=go, args=phone) for phone in phones]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    linked = [r for r in results if r[0] == 200]
    refused = [r for r in results
               if r in ((403, "risk_review_required"), (409, "relationship_changed"))]
    expect(len(linked) <= 1 and len(linked) + len(refused) == len(phones),
           "at most one of four simultaneous sign-ins may link, the rest refused; got %s"
           % sorted(results))


@check("business: events are recorded once and combined with the phone-account graph")
def check_business_api(api, ctx):
    """DESIGN.md 76. Server to server: needs a token whose SHA-256 the server
    lists in BUSINESS_API_TOKENS with the events, graph and lapses roles (or in
    the older BUSINESS_API_TOKEN_SHA256), given to the suite as
    DEVICE_TRUST_BUSINESS_TOKEN; skips without it. A fresh account on a fresh
    phone gets two events (one sent twice); the graph from the account shows
    the phone, the link and the counts; the lapse feed answers."""
    token = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if not token:
        raise Skip("set DEVICE_TRUST_BUSINESS_TOKEN to the business API token to run this")
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    device = device_token(api, inst)
    submit_report(api, inst, device)
    st, pl = open_account(api, inst, device, "biz-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "open account failed: %s %s" % (st, pl))
    account_id = pl["account_id"]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tag = secrets.token_hex(4)
    events = [{"event_id": "suite-%s-1" % tag, "account_id": account_id, "type": "advance_disbursed",
               "occurred_at": now, "amount_minor": 2500, "currency": "USD",
               "subject_ref": "payee-%s" % tag},
              {"event_id": "suite-%s-2" % tag, "account_id": account_id, "type": "repayment_failed",
               "occurred_at": now}]
    business = {"Authorization": "Bearer " + token}
    st, pl = api.call("POST", "/v1/business/events", headers=business,
                      body_text=json.dumps({"events": events + events[:1]}))
    expect(st == 200 and [r["status"] for r in pl.get("results", [])]
           == ["accepted", "accepted", "duplicate"], "events: %s %s" % (st, pl))
    st, pl = api.call("POST", "/v1/business/events", headers={"Authorization": "Bearer wrong"},
                      body_text=json.dumps({"events": events}))
    expect(st == 401, "a wrong business token must be refused, got %s" % st)
    st, graph = api.call("GET", "/v1/business/graph?account_id=%s" % account_id, headers=business)
    node = ([a for a in graph.get("accounts", []) if a.get("account_id") == account_id] or [{}])[0]
    expect(st == 200 and [d["device_id"] for d in graph.get("devices", [])] == [inst.device_id]
           and node.get("business_events", {}).get("advance_disbursed", {}).get("30d") == 1
           and node["business_events"]["advance_disbursed"].get("amount_30d") == {"USD": 2500}
           and node["business_events"].get("repayment_failed", {}).get("1d") == 1,
           "the graph must show the phone and the events: %s %s" % (st, graph))
    st, feed = api.call("GET", "/v1/business/acceptance-lapses?limit=1", headers=business)
    expect(st == 200 and isinstance(feed.get("lapses"), list), "lapse feed: %s %s" % (st, feed))


@check("business: every integrity report, with its measurements, page by page")
def check_business_integrity_reports(api, ctx):
    """DESIGN.md 79 (G5). Needs DEVICE_TRUST_BUSINESS_TOKEN. A fresh phone
    sends two scans; the feed filtered to the phone returns both, oldest
    first, one per page, each with the phone's probe_results and the
    server's reasons; two filters at once are refused."""
    token = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if not token:
        raise Skip("set DEVICE_TRUST_BUSINESS_TOKEN to the business API token to run this")
    business = {"Authorization": "Bearer " + token}
    inst, device = _observing_phone(api)
    submit_report(api, inst, device)
    reports, cursor = [], None
    for _ in range(3):
        query = {"device_id": inst.device_id, "limit": "1"}
        if cursor:
            query["cursor"] = cursor
        st, page = api.call("GET", "/v1/business/integrity-reports?"
                            + urllib.parse.urlencode(query), headers=business)
        expect(st == 200 and len(page.get("reports", [])) <= 1, "a page: %s %s" % (st, page))
        reports += page["reports"]
        cursor = page["next_cursor"]
    expect(len(reports) == 2 and len({r["report_id"] for r in reports}) == 2
           and all(r["device_id"] == inst.device_id for r in reports)
           and reports[0]["created_at"] <= reports[1]["created_at"],
           "both scans, once each, oldest first: %s" % [(r["report_id"], r["created_at"])
                                                        for r in reports])
    first = reports[0]
    expect(isinstance(first.get("probe_results"), dict) and "app_identity" in first["probe_results"]
           and isinstance(first.get("reasons"), list) and first.get("platform") == "android"
           and len(first.get("report_sha256") or "") == 64,
           "a report carries the measurements and the reasons: %s" % sorted(first))
    st, pl = api.call("GET", "/v1/business/integrity-reports?" + urllib.parse.urlencode(
        {"device_id": inst.device_id, "installation_id": inst.installation_id}), headers=business)
    expect(st == 400 and error_code(pl) == "invalid_filter",
           "two filters must be refused: %s %s" % (st, pl))


def _support(api, token, action, body):
    st, pl = api.call("POST", "/v1/business/app-pin/%s" % action,
                      headers={"Authorization": "Bearer " + token}, body_text=json.dumps(body))
    if st == 403 and error_code(pl) == "business_role_missing":
        # Review F3: PIN support needs a token whose BUSINESS_API_TOKENS entry
        # names the role; the older BUSINESS_API_TOKEN_SHA256 tokens lack it.
        raise Skip("DEVICE_TRUST_BUSINESS_TOKEN lacks the pin_%s role (BUSINESS_API_TOKENS)"
                   % action)
    return st, pl


def _observing_phone(api):
    """A fresh phone with a device token and a clean report."""
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token)
    return inst, token


def _decision_of(payload):
    """The relationship decision in a sign-in answer, allowed or refused."""
    error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
    return payload.get("policy") or (error.get("details") or {}).get("policy") or {}


@check("observations: wrong passwords and unknown accounts are measured into decisions")
def check_server_observations(api, ctx):
    """DESIGN.md 77, measured whatever the DBA's switch. An account on one
    phone; a second phone sends it two wrong passwords and tries a handle no
    account has; a third sends one. The account's decisions count three
    failures from two other phones; the second phone's own decision
    counts two failures on one account and one unknown account; a phone
    joining the account now is judged by the three. Every 401 is the same."""
    owner, owner_token = _observing_phone(api)
    handle = "obs-%s" % secrets.token_hex(4)
    st, pl = open_account(api, owner, owner_token, handle)
    expect(st in (200, 201), "open account failed: %s %s" % (st, pl))
    access = pl["access_token"]
    guesser, guesser_token = _observing_phone(api)
    other, other_token = _observing_phone(api)
    for inst, token, who in ((guesser, guesser_token, handle), (guesser, guesser_token, handle),
                             (guesser, guesser_token, "nobody-%s" % secrets.token_hex(6)),
                             (other, other_token, handle)):
        st, pl = sign_in(api, inst, token, who, password="Wrong-Passw0rd")
        expect(st == 401 and error_code(pl) == "invalid_credentials",
               "a wrong password or unknown handle must answer 401 invalid_credentials: %s %s"
               % (st, pl))
    st, pl = protected(api, owner, "GET", "/v1/policy/me", access)
    expect(st == 200, "policy/me failed: %s %s" % (st, pl))
    seen = pl["policy"]["context"]["server_observations"]
    expect(seen["account"]["sign_in_failed"] == 3
           and seen["account"]["sign_in_failed_installations"] == 2
           and seen["account"]["sign_in_failed_elsewhere"] == 3,
           "the account's decision must count three failures from two phones: %s" % seen)
    expect(seen["newcomer"] is not None
           and seen["newcomer"]["sign_in_failed_elsewhere_before"] == 0,
           "the phone that opened the account before the failures is not judged by them: %s"
           % seen["newcomer"])
    expect(seen["scored"] is _setting_on(live_settings(api), "cross_checks_enabled"),
           "scored must follow cross_checks_enabled: %s" % seen)
    st, pl = open_account(api, guesser, guesser_token, "obs-own-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "the guessing phone's own account failed: %s %s" % (st, pl))
    device = pl["policy"]["context"]["server_observations"]["device"]
    expect(device["sign_in_failed"] == 2 and device["sign_in_failed_accounts"] == 1
           and device["sign_in_unknown_account"] == 1,
           "the guessing phone's own decision must count what it did: %s" % device)
    joining, joining_token = _observing_phone(api)
    st, pl = sign_in(api, joining, joining_token, handle)
    newcomer = (_decision_of(pl).get("context") or {}).get("server_observations", {}).get("newcomer")
    expect(newcomer and newcomer["sign_in_failed_elsewhere_before"] == 3,
           "a phone joining now is judged by the failures before it: %s %s" % (st, newcomer))


@check("observations: with cross-checks enabled, a phone joining after failures elsewhere is scored")
def check_server_observations_scored(api, ctx):
    """DESIGN.md 77. Runs where the DBA has set cross_checks_enabled = 1, with
    the account rule's count at most 10; derives its expectations from the
    live settings. A phone joining an account after that many wrong passwords
    from another phone carries account_sign_in_failures_elsewhere with the
    DBA's points and the count."""
    settings = live_settings(api)
    if not _setting_on(settings, "cross_checks_enabled"):
        raise Skip("cross_checks_enabled is off (the owner's default: observe first)")
    threshold = int(settings.get("account_sign_in_failures_elsewhere_count", "5") or "5")
    points = int(settings.get("account_sign_in_failures_elsewhere_points", "30") or "30")
    if not 0 < threshold <= 10:
        raise Skip("account_sign_in_failures_elsewhere_count=%s is off or too high to run"
                   % threshold)
    owner, owner_token = _observing_phone(api)
    handle = "obs-scored-%s" % secrets.token_hex(4)
    st, pl = open_account(api, owner, owner_token, handle)
    expect(st in (200, 201), "open account failed: %s %s" % (st, pl))
    guesser, guesser_token = _observing_phone(api)
    for _ in range(threshold):
        st, pl = sign_in(api, guesser, guesser_token, handle, password="Wrong-Passw0rd")
        expect(st == 401, "a wrong password must be refused: %s %s" % (st, pl))
    joining, joining_token = _observing_phone(api)
    st, pl = sign_in(api, joining, joining_token, handle)
    reason = reason_for(_decision_of(pl), "account_sign_in_failures_elsewhere")
    expect(reason is not None and reason.get("points") == points
           and reason.get("count") == threshold,
           "expected account_sign_in_failures_elsewhere +%d (count %d); got %s %s"
           % (points, threshold, st, _decision_of(pl).get("reasons")))


def _skip_unless_screen_lock(settings, sensitive_path=False):
    """These checks prove the screen-lock key's step-up (DESIGN.md 63, 70).
    Under the DBA's other step-up methods (DESIGN.md 78) -- or, for the checks
    on the sensitive path, where that path also needs the app PIN -- the app
    PIN checks cover the same flows."""
    method = _method(settings)
    if method != "screen_lock":
        raise Skip("stepup_method is %s; this check proves the screen-lock key, the app PIN "
                   "checks cover the same flows" % method)
    if sensitive_path and SENSITIVE_PATH in _setting_words(settings, "app_pin_required_paths", ""):
        raise Skip("the sensitive path also needs the app PIN here; check_app_pin covers it")


SENSITIVE_PATH = "/v1/account/sensitive-echo"


def _method(settings):
    """The live stepup_method; a missing row means the owner's default."""
    return settings.get("stepup_method") or "app_pin"


def _approver(api, settings):
    """A phone holding a full session on a new account, able to prove a
    step-up the way the live stepup_method asks (DESIGN.md 78): its step-up
    key, the account's app PIN (set here), or both. Returns (installation,
    handle, access token, prove, missing): prove(path, body) sends what is
    needed; missing is the code a request without any factor answers."""
    method = _method(settings)
    inst, _, handle, access, stepup = _pin_phone(api, settings, method != "app_pin")
    pin = None
    if method != "screen_lock":
        pin, _ = _two_pins(settings)
        st, pl = _set_pin(api, inst, access, pin)
        expect(st == 200, "setting the approver's app PIN: %s %s" % (st, pl))

    def prove(path, body=None):
        return pin_call(api, inst, path, access, body or {}, pin=pin, stepup=stepup)

    missing = "stepup_required" if method == "screen_lock" else "app_pin_required"
    return inst, handle, access, prove, missing


def _pin_factors(settings, path=SENSITIVE_PATH):
    """(the screen-lock key, the app PIN): what `path` needs under the live
    settings (DESIGN.md 78)."""
    method = _method(settings)
    required = path in _setting_words(settings, "stepup_required_paths", "")
    return (required and method != "app_pin",
            path in _setting_words(settings, "app_pin_required_paths", "")
            or (required and method != "screen_lock"))


def pin_call(api, installation, path, bearer, body, pin=None, stepup=None):
    """A protected POST with the app PIN, and a screen-lock proof when
    `stepup` = (step-up private key, factor)."""
    if stepup is not None:
        return stepup_call(api, installation, stepup[0], "POST", path, bearer, body, stepup[1],
                           app_pin=pin)
    headers, body_text = build_proof(installation, "POST", path, bearer, body)
    if pin is not None:
        headers["X-App-PIN"] = pin
    return api.call("POST", path, body_text=body_text, bearer=bearer, headers=headers)


def _pin_phone(api, settings, with_key):
    """A fresh phone -- with a step-up key when `with_key` -- and a full
    account on it: (installation, device token, handle, access token, step-up)."""
    inst = Installation()
    factor = settings.get("stepup_factor", "passcode")
    stepup, extra = None, {}
    if with_key:
        priv, jwk = stepup_jwk_pair()
        stepup = (priv, factor)
        extra = {"stepup_public_key": jwk,
                 "stepup_key_auth": {"factor": factor, "mode": "per_use", "window_seconds": 0}}
    st, pl = enrol(api, inst, fresh_hint(), **extra)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token)
    handle = "pin-%s" % secrets.token_hex(4)
    st, pl = open_account(api, inst, token, handle)
    expect(st in (200, 201) and pl.get("scope") == "full",
           "setup: a full account: %s %s" % (st, pl))
    return inst, token, handle, pl["access_token"], stepup


def _set_pin(api, inst, access, pin, password="Passw0rd123"):
    return protected(api, inst, "POST", "/v1/account/app-pin", access,
                     {"password": password, "pin": pin})


def _two_pins(settings):
    length = int(settings.get("app_pin_length", "6") or "6")
    pin = "".join(secrets.choice("0123456789") for _ in range(length))
    return pin, ("1" if pin[0] != "1" else "2") + pin[1:]


@check("step-up: the app PIN the server checks -- set, wrong, right, locked, reset")
def check_app_pin(api, ctx):
    """DESIGN.md 78. Runs where the sensitive path needs the app PIN
    (stepup_method app_pin or screen_lock_and_app_pin with the path in
    stepup_required_paths, or the path in app_pin_required_paths). A new
    account has none; asking costs no attempt; a wrong password cannot set
    one; a wrong PIN counts down, the right one passes and clears the count;
    app_pin_max_failures wrong ones lock it -- the right one is then refused
    too -- until a new PIN is set with the password. Each wrong PIN is
    counted for the account on the phone."""
    settings = live_settings(api)
    need_key, need_pin = _pin_factors(settings)
    if not need_pin:
        raise Skip("the sensitive path needs no app PIN here (stepup_method, "
                   "stepup_required_paths, app_pin_required_paths)")
    max_failures = int(settings.get("app_pin_max_failures", "5") or "5")
    if max_failures > 10:
        raise Skip("app_pin_max_failures=%s is too high for a bounded run" % max_failures)
    inst, _, _, access, stepup = _pin_phone(api, settings, need_key)
    stepup = stepup if need_key else None
    pin, wrong = _two_pins(settings)
    body = {"amount": 1}
    st, me = protected(api, inst, "GET", "/v1/account/me", access)
    expect(st == 200 and me["step_up"]["app_pin_set"] is False,
           "a new account has no app PIN: %s %s" % (st, me.get("step_up")))
    st, pl = pin_call(api, inst, SENSITIVE_PATH, access, body, stepup=stepup)
    expect(st == 403 and error_code(pl) == "app_pin_required"
           and "app_pin" in _details(pl)["step_up"]["needs"],
           "without the PIN: app_pin_required, got %s %s" % (st, pl))
    st, pl = pin_call(api, inst, SENSITIVE_PATH, access, body, pin=pin, stepup=stepup)
    expect(st == 403 and error_code(pl) == "app_pin_not_set",
           "before one is set: app_pin_not_set, got %s %s" % (st, pl))
    st, pl = _set_pin(api, inst, access, pin, password="Wrong-Passw0rd")
    expect(st == 401 and error_code(pl) == "invalid_credentials",
           "a wrong password must not set a PIN: %s %s" % (st, pl))
    st, pl = _set_pin(api, inst, access, pin)
    expect(st == 200 and pl["step_up"]["app_pin_set"] is True, "setting the PIN: %s %s" % (st, pl))
    st, pl = pin_call(api, inst, SENSITIVE_PATH, access, body, pin=wrong, stepup=stepup)
    expect(st == 403 and error_code(pl) == "app_pin_invalid"
           and _details(pl).get("attempts_left") == max_failures - 1,
           "a wrong PIN counts down: %s %s" % (st, pl))
    st, pl = pin_call(api, inst, SENSITIVE_PATH, access, body, pin=pin, stepup=stepup)
    expect(st == 200 and pl.get("app_pin") == "verified", "the right PIN passes: %s %s" % (st, pl))
    answers = [error_code(pin_call(api, inst, SENSITIVE_PATH, access, body, pin=wrong,
                                   stepup=stepup)[1]) for _ in range(max_failures)]
    expect(answers == ["app_pin_invalid"] * (max_failures - 1) + ["app_pin_locked"],
           "the right PIN cleared the count; then %d wrong ones lock it: %s"
           % (max_failures, answers))
    st, pl = pin_call(api, inst, SENSITIVE_PATH, access, body, pin=pin, stepup=stepup)
    expect(st == 403 and error_code(pl) == "app_pin_locked",
           "a locked PIN refuses the right PIN too: %s %s" % (st, pl))
    st, pl = _set_pin(api, inst, access, pin)
    expect(st == 200 and pl["step_up"]["app_pin_locked"] is False,
           "a new PIN with the password unlocks: %s %s" % (st, pl))
    st, pl = pin_call(api, inst, SENSITIVE_PATH, access, body, pin=pin, stepup=stepup)
    expect(st == 200, "and the PIN works again: %s %s" % (st, pl))
    st, pl = protected(api, inst, "GET", "/v1/policy/me", access)
    counted = pl["policy"]["context"]["server_observations"]["device_account"]["app_pin_failed"]
    expect(counted == max_failures + 1, "each wrong PIN is counted: %s" % counted)


@check("step-up: the app reads the DBA's step-up policy before sign-in")
def check_step_up_policy(api, ctx):
    """DESIGN.md 79 (G4). GET /v1/policy/step-up needs no token and answers
    what the live settings say -- the method, the factor, mode and window a
    screen-lock key is created with, the PIN's length, the paths; an
    account's own /v1/account/me carries the same."""
    settings = live_settings(api)
    mode = settings.get("stepup_mode", "per_use")
    expected = {
        "method": _method(settings),
        "factor": settings.get("stepup_factor", "passcode"),
        "mode": mode,
        "window_seconds": (int(settings.get("stepup_window_seconds", "0") or "0")
                           if mode == "windowed" else 0),
        "app_pin_length": int(settings.get("app_pin_length", "6") or "6"),
        "required_paths": sorted(_setting_words(settings, "stepup_required_paths", "")),
        "app_pin_required_paths": sorted(_setting_words(settings, "app_pin_required_paths", "")),
    }
    st, policy = api.call("GET", "/v1/policy/step-up")
    expect(st == 200 and policy == expected,
           "the policy must be the live settings: %s %s, expected %s" % (st, policy, expected))
    inst, _, _, access, _ = _pin_phone(api, settings, False)
    st, me = protected(api, inst, "GET", "/v1/account/me", access)
    expect(st == 200 and {key: me["step_up"].get(key) for key in expected} == expected,
           "the account's view carries the same: %s %s" % (st, me.get("step_up")))


@check("support: unlock a locked app PIN, as the DBA's app_pin_support allows")
def check_app_pin_support_unlock(api, ctx):
    """DESIGN.md 79. Needs DEVICE_TRUST_BUSINESS_TOKEN with the pin_unlock role
    (BUSINESS_API_TOKENS); skips without it. Off (the default),
    both support actions answer app_pin_support_disabled. Where the DBA
    allows unlock, a PIN locked by wrong attempts is unlocked by support --
    naming the account by handle, with a ticket reference -- and the right
    PIN passes again; the action is counted for the account. A reset is
    refused unless the DBA allows unlock_and_reset."""
    token = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if not token:
        raise Skip("set DEVICE_TRUST_BUSINESS_TOKEN to the business API token to run this")
    settings = live_settings(api)
    level = settings.get("app_pin_support", "off")
    echo = "/v1/account/protected-echo"
    if _pin_factors(settings, echo)[0]:
        raise Skip("the echo path needs the screen-lock key here")
    inst, _, handle, access, _ = _pin_phone(api, settings, False)
    st, me = protected(api, inst, "GET", "/v1/account/me", access)
    expect(st == 200, "setup: %s %s" % (st, me))
    account_id = me["account_id"]
    reference = "SUITE-%s" % secrets.token_hex(4)
    if level == "off":
        for action in ("unlock", "reset"):
            st, pl = _support(api, token, action, {"account_id": account_id,
                                                   "reference": reference})
            expect(st == 403 and error_code(pl) == "app_pin_support_disabled",
                   "app_pin_support is off: %s must refuse, got %s %s" % (action, st, pl))
        return
    max_failures = int(settings.get("app_pin_max_failures", "5") or "5")
    if max_failures > 10:
        raise Skip("app_pin_max_failures=%s is too high for a bounded run" % max_failures)
    pin, wrong = _two_pins(settings)
    st, pl = _set_pin(api, inst, access, pin)
    expect(st == 200, "setting the PIN: %s %s" % (st, pl))
    answers = [error_code(pin_call(api, inst, echo, access, {"x": 1}, pin=wrong)[1])
               for _ in range(max_failures)]
    expect(answers[-1] == "app_pin_locked", "%d wrong PINs lock it: %s" % (max_failures, answers))
    st, pl = _support(api, token, "unlock", {"handle": handle, "reference": reference})
    expect(st == 200 and pl == {"account_id": account_id, "unlocked": True, "reset_until": None},
           "support unlocks it: %s %s" % (st, pl))
    st, pl = pin_call(api, inst, echo, access, {"x": 1}, pin=pin)
    expect(st == 200, "the right PIN passes again: %s %s" % (st, pl))
    st, pl = protected(api, inst, "GET", "/v1/policy/me", access)
    counted = pl["policy"]["context"]["server_observations"]["account"]
    expect(counted.get("app_pin_support_unlocked") == 1,
           "the unlock is counted for the account: %s" % counted)
    if level == "unlock":
        st, pl = _support(api, token, "reset", {"account_id": account_id, "reference": reference})
        expect(st == 403 and error_code(pl) == "app_pin_support_disabled",
               "unlock alone allows no reset: %s %s" % (st, pl))


@check("support: a reset lets a limited session set a new app PIN, once")
def check_app_pin_support_reset(api, ctx):
    """DESIGN.md 79. Needs DEVICE_TRUST_BUSINESS_TOKEN with the pin_reset role
    (BUSINESS_API_TOKENS), app_pin_support =
    unlock_and_reset, and enforce mode. A limited session cannot set a PIN;
    after support opens a reset it can, with the password -- a wrong one
    leaves the reset open -- and only once."""
    token = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if not token:
        raise Skip("set DEVICE_TRUST_BUSINESS_TOKEN to the business API token to run this")
    settings = live_settings(api)
    if settings.get("app_pin_support", "off") != "unlock_and_reset":
        raise Skip("app_pin_support is %s here; a reset needs unlock_and_reset"
                   % settings.get("app_pin_support", "off"))
    inst, device, handle = _limited_setup(api, ctx)
    st, pl = sign_in(api, inst, device, handle)
    expect(st == 200 and pl.get("scope") == "limited", "setup: a limited session: %s %s" % (st, pl))
    limited = pl["access_token"]
    pin, _ = _two_pins(settings)
    st, pl = _set_pin(api, inst, limited, pin)
    expect(st == 403 and error_code(pl) == "session_limited",
           "without a reset a limited session sets no PIN: %s %s" % (st, pl))
    st, pl = _support(api, token, "reset", {"handle": handle,
                                            "reference": "SUITE-%s" % secrets.token_hex(4)})
    expect(st == 200 and pl.get("reset_until"), "support opens a reset: %s %s" % (st, pl))
    st, pl = _set_pin(api, inst, limited, pin, password="Wrong-Passw0rd")
    expect(st == 401 and error_code(pl) == "invalid_credentials",
           "a wrong password is refused: %s %s" % (st, pl))
    st, pl = _set_pin(api, inst, limited, pin)
    expect(st == 200 and pl["step_up"]["app_pin_set"] is True
           and pl["step_up"]["app_pin_reset_open"] is False,
           "with the reset open the limited session sets the PIN: %s %s" % (st, pl))
    st, pl = _set_pin(api, inst, limited, pin)
    expect(st == 403 and error_code(pl) == "session_limited", "the reset serves once: %s %s"
           % (st, pl))


@check("step-up: concurrent wrong app PINs never pass the attempt limit", db_sensitive=True)
def check_app_pin_concurrent(api, ctx):
    """DESIGN.md 78. Each attempt is claimed by one atomic UPDATE before the
    PIN is compared, so wrong PINs sent at the same moment count exactly up to
    app_pin_max_failures -- one fewer answered app_pin_invalid, the rest
    app_pin_locked -- and no more are compared."""
    settings = live_settings(api)
    need_key, need_pin = _pin_factors(settings)
    if not need_pin:
        raise Skip("the sensitive path needs no app PIN here")
    max_failures = int(settings.get("app_pin_max_failures", "5") or "5")
    if max_failures > 10:
        raise Skip("app_pin_max_failures=%s is too high for a bounded run" % max_failures)
    inst, _, _, access, stepup = _pin_phone(api, settings, need_key)
    stepup = stepup if need_key else None
    pin, wrong = _two_pins(settings)
    st, pl = _set_pin(api, inst, access, pin)
    expect(st == 200, "setting the PIN: %s %s" % (st, pl))
    count = max_failures + 4
    barrier, lock, results = threading.Barrier(count), threading.Lock(), []

    def guess():
        client = Api(api.base_url)
        try:
            barrier.wait(timeout=30)
            outcome = error_code(pin_call(client, inst, SENSITIVE_PATH, access, {"amount": 1},
                                          pin=wrong, stepup=stepup)[1])
        except BaseException as error:  # a thread must report, never vanish
            outcome = str(error)[:80]
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=guess) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    expect(results.count("app_pin_invalid") == max_failures - 1
           and results.count("app_pin_locked") == count - (max_failures - 1),
           "%d wrong PINs at once against a limit of %d: %s"
           % (count, max_failures, sorted(results)))
    st, pl = protected(api, inst, "GET", "/v1/policy/me", access)
    counted = pl["policy"]["context"]["server_observations"]["device_account"]["app_pin_failed"]
    expect(counted == max_failures, "exactly the claimed attempts were compared: %s" % counted)


@check("limited session: approving and route 1 prove the app PIN where the DBA chose it",
       db_sensitive=True)
def check_app_pin_approval(api, ctx):
    """DESIGN.md 78. Under stepup_method app_pin or screen_lock_and_app_pin,
    approving another phone's request needs the app PIN (and the screen-lock
    key where the method names both), and so does route 1 where it is on; the
    phone that asked then upgrades."""
    settings = live_settings(api)
    method = _method(settings)
    if method == "screen_lock":
        raise Skip("stepup_method is screen_lock; the route 2 check proves the screen-lock key")
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode; limited sessions exist only in enforce mode")
    if not _setting_on(settings, "upgrade_other_device_approval") and \
            "upgrade_other_device_approval" in settings:
        raise Skip("upgrade_other_device_approval is off on this server")
    integrity_context(ctx)
    with_key = method != "app_pin"
    approver, _, handle, approver_access, stepup = _pin_phone(api, settings, with_key)
    pin, _ = _two_pins(settings)
    st, pl = _set_pin(api, approver, approver_access, pin)
    expect(st == 200, "setting the PIN: %s %s" % (st, pl))
    phone = Installation()
    factor = settings.get("stepup_factor", "passcode")
    phone_key, extra = None, {}
    if with_key:
        phone_priv, jwk = stepup_jwk_pair()
        phone_key = (phone_priv, factor)
        extra = {"stepup_public_key": jwk,
                 "stepup_key_auth": {"factor": factor, "mode": "per_use", "window_seconds": 0}}
    st, pl = enrol(api, phone, fresh_hint(), **extra)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    phone_token = device_token(api, phone)
    submit_report(api, phone, phone_token, _elevate)
    st, pl = sign_in(api, phone, phone_token, handle)
    expect(st == 200 and pl.get("scope") == "limited", "a limited session: %s %s" % (st, pl))
    limited = pl["access_token"]
    st, req = protected(api, phone, "POST", "/v1/auth/upgrade/request", limited,
                        {"route": "approval"})
    expect(st == 201, "approval request: %s %s" % (st, req))
    path = "/v1/auth/approvals/%s/approve" % req["request_id"]
    st, pl = pin_call(api, approver, path, approver_access, {}, stepup=stepup)
    expect(st == 403 and error_code(pl) == "app_pin_required",
           "approving without the PIN must be refused: %s %s" % (st, pl))
    st, pl = pin_call(api, approver, path, approver_access, {}, pin=pin, stepup=stepup)
    expect(st == 200 and pl.get("approved") is True, "approving with the PIN: %s %s" % (st, pl))
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", limited,
                       {"route": "approval", "request_id": req["request_id"]})
    expect(st == 200 and up.get("scope") == "full", "the approved phone upgrades: %s %s" % (st, up))
    if _setting_on(settings, "upgrade_stepup_same_device"):
        # Route 1 clears integrity causes only: a single-phone account whose
        # own phone turns elevated, its PIN set while the session was full.
        single, single_token, single_handle, single_access, single_key = _pin_phone(
            api, settings, with_key)
        st, pl = _set_pin(api, single, single_access, pin)
        expect(st == 200, "setting the PIN: %s %s" % (st, pl))
        submit_report(api, single, single_token, _elevate)
        st, pl = sign_in(api, single, single_token, single_handle)
        expect(st == 200 and pl.get("scope") == "limited"
               and "stepup" in (pl.get("upgrade_routes") or []),
               "the limited login must offer route 1: %s %s" % (st, pl))
        limited = pl["access_token"]
        st, up = pin_call(api, single, "/v1/auth/upgrade", limited, {"route": "stepup"},
                          stepup=single_key)
        expect(st == 403 and error_code(up) == "app_pin_required",
               "route 1 without the PIN: %s %s" % (st, up))
        st, up = pin_call(api, single, "/v1/auth/upgrade", limited, {"route": "stepup"},
                          pin=pin, stepup=single_key)
        expect(st == 200 and up.get("scope") == "full" and up.get("upgraded_by") == "stepup",
               "route 1 with the PIN upgrades: %s %s" % (st, up))


@check("observations: a stolen token and a replayed request are recorded once each")
def check_stolen_token_recorded(api, ctx):
    """DESIGN.md 77, owner decision of 2026-10-14. A fresh account's access
    token is presented three times with proofs another phone signed, and one
    valid request is sent three times: each is refused as before, and the
    account's own decision then counts one stolen token and one replayed
    request -- once each, not once per attempt -- on the account and its phone."""
    owner, owner_token = _observing_phone(api)
    st, pl = open_account(api, owner, owner_token, "stolen-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "open account failed: %s %s" % (st, pl))
    access = pl["access_token"]
    thief = Installation()
    for _ in range(3):
        st, pl = protected(api, owner, "POST", "/v1/account/protected-echo", access, {"x": 1},
                           signer=thief)
        expect(st == 401 and error_code(pl) == "invalid_installation_signature",
               "a token without its key must answer 401 invalid_installation_signature: %s %s"
               % (st, pl))
    headers, body_text = build_proof(owner, "POST", "/v1/account/protected-echo", access,
                                     {"replay": True})
    statuses = [api.call("POST", "/v1/account/protected-echo", body_text=body_text,
                         bearer=access, headers=headers)[0] for _ in range(3)]
    expect(statuses == [200, 401, 401], "one send and two replays expected, got %s" % statuses)
    st, pl = protected(api, owner, "GET", "/v1/policy/me", access)
    expect(st == 200, "policy/me failed: %s %s" % (st, pl))
    seen = pl["policy"]["context"]["server_observations"]
    expect(seen["account"]["token_without_key"] == 1 and seen["account"]["request_replayed"] == 1
           and seen["device"]["token_without_key"] == 1 and seen["device"]["request_replayed"] == 1,
           "one stolen token and one replayed request, on the account and its phone: %s" % seen)


@check("session: sign-out revokes the family at once; a routine refresh does not")
def check_logout_revokes_the_family(api, ctx):
    """Review R6 (DESIGN.md 76). After a refresh the previous access token still
    works (requests in flight survive a rotation); after /v1/auth/logout every
    access token of the family is refused with session_revoked at once, and its
    refresh token no longer refreshes."""
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token)
    st, pl = open_account(api, inst, token, "lo-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "open account failed: %s %s" % (st, pl))
    first_access = pl["access_token"]
    st, rotated = _refresh(api, inst, pl["refresh_token"])
    expect(st == 200, "refresh failed: %s %s" % (st, rotated))
    st, me = protected(api, inst, "GET", "/v1/account/me", first_access)
    expect(st == 200, "an access token from before a routine refresh must still work, got %s %s"
           % (st, error_code(me)))
    st, out = protected(api, inst, "POST", "/v1/auth/logout", rotated["access_token"], {})
    expect(st == 200 and out.get("signed_out") is True, "logout failed: %s %s" % (st, out))
    for label, access in (("the current", rotated["access_token"]), ("the previous", first_access)):
        st, me = protected(api, inst, "GET", "/v1/account/me", access)
        expect(st == 401 and error_code(me) == "session_revoked",
               "%s access token must be refused after logout, got %s %s" % (label, st, error_code(me)))
    # The challenge itself changes nothing (DESIGN.md 66.2); the refresh must fail.
    refresh = rotated["refresh_token"]
    st, got = api.call("POST", "/v1/auth/refresh/challenge", bearer=refresh)
    if st == 200:
        body = {"challenge_id": got["challenge_id"], "payload": got["payload"],
                "signature": inst.sign_b64(got["payload"])}
        st, got = api.call("POST", "/v1/auth/refresh", body_text=json.dumps(body), bearer=refresh)
    expect(st == 401, "a signed-out refresh token must not refresh, got %s %s" % (st, got))


def _limited_setup(api, ctx):
    """An installation with an account, whose latest scan is elevated (+40)."""
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode; limited sessions exist only in enforce mode")
    if "elevated" not in _setting_words(live_settings(api), "limited_session_integrity_verdicts",
                                        "elevated"):
        raise Skip("elevated is not a limited-session outcome on this server")
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token)
    handle = "lim-%s" % secrets.token_hex(4)
    st, pl = open_account(api, inst, token, handle)
    expect(st in (200, 201) and pl.get("scope") == "full", "setup: account open: %s %s" % (st, pl))
    decision = submit_report(api, inst, token, _elevate)
    expect(decision["verdict"] == "elevated", "setup: expected elevated, got %s" % decision)
    return inst, token, handle


def _details(payload):
    return ((payload.get("error") or {}).get("details") or {}) if isinstance(payload, dict) else {}


@check("limited session: a soft verdict at login gives a limited session; a clean scan upgrades it")
def check_limited_session_login(api, ctx):
    """DESIGN.md 67, 70. An elevated integrity verdict at login no longer
    refuses: a valid password and key proof get a limited session, which
    reaches only the upgrade endpoints and the integrity scan. Once a new clean
    scan clears the cause, the upgrade needs no proof; the old limited token
    stays limited and cannot upgrade twice."""
    inst, token, handle = _limited_setup(api, ctx)
    st, pl = sign_in(api, inst, token, handle)
    expect(st == 200 and pl.get("scope") == "limited"
           and pl.get("limited_causes") == ["integrity_elevated"]
           and isinstance(pl.get("upgrade_routes"), list),
           "a soft verdict at login must give a limited session, got %s %s" % (st, pl))
    limited = pl["access_token"]
    st, me = protected(api, inst, "GET", "/v1/account/me", limited)
    expect(st == 403 and error_code(me) == "session_limited"
           and _details(me).get("limited_causes") == ["integrity_elevated"],
           "a limited token off its paths must get session_limited, got %s %s" % (st, me))
    submit_report(api, inst, limited, _elevate)
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", limited, {})
    expect(st == 403 and error_code(up) == "upgrade_proof_required",
           "still elevated, a proof-less upgrade must be refused, got %s %s" % (st, error_code(up)))
    clean = submit_report(api, inst, limited)
    expect(clean["verdict"] == "trusted", "setup: the clean scan must be trusted: %s" % clean)
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", limited, {})
    expect(st == 200 and up.get("scope") == "full" and up.get("upgraded_by") == "recheck",
           "with the cause cleared the upgrade must need no proof, got %s %s" % (st, up))
    st, me = protected(api, inst, "GET", "/v1/account/me", up["access_token"])
    expect(st == 200, "the upgraded session must be full, got %s %s" % (st, error_code(me)))
    st, me = protected(api, inst, "GET", "/v1/account/me", limited)
    expect(st == 403 and error_code(me) == "session_limited",
           "the old limited token must stay limited, got %s %s" % (st, error_code(me)))
    st, again = protected(api, inst, "POST", "/v1/auth/upgrade", limited, {})
    expect(st == 401 and error_code(again) == "session_rotated",
           "the same limited session must not upgrade twice, got %s %s" % (st, error_code(again)))


@check("limited session: a refresh never widens a session, and narrows a full one on soft risk")
def check_limited_session_refresh(api, ctx):
    inst, token, handle = _limited_setup(api, ctx)
    st, pl = sign_in(api, inst, token, handle)
    expect(st == 200 and pl.get("scope") == "limited", "setup: limited login: %s %s" % (st, pl))
    submit_report(api, inst, token)
    st, rotated = _refresh(api, inst, pl["refresh_token"])
    expect(st == 200 and rotated.get("scope") == "limited"
           and rotated.get("limited_causes") == ["integrity_elevated"],
           "a refresh must keep a limited session limited, got %s %s" % (st, rotated))
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", rotated["access_token"], {})
    expect(st == 200 and up.get("scope") == "full", "upgrade after the clean scan: %s %s" % (st, up))
    st, full = _refresh(api, inst, up["refresh_token"])
    expect(st == 200 and full.get("scope") == "full", "a full session must refresh full: %s %s"
           % (st, full))
    submit_report(api, inst, token, _elevate)
    st, narrowed = _refresh(api, inst, full["refresh_token"])
    expect(st == 200 and narrowed.get("scope") == "limited",
           "a full session must become limited when soft risk is found at refresh, got %s %s"
           % (st, narrowed))


@check("limited session: registration on soft risk creates the account, limited")
def check_limited_session_registration(api, ctx):
    """DESIGN.md 70: on a soft outcome the account is created and linked to the
    device -- links are permanent -- and its first session is limited."""
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode; limited sessions exist only in enforce mode")
    if "elevated" not in _setting_words(live_settings(api), "limited_session_integrity_verdicts",
                                        "elevated"):
        raise Skip("elevated is not a limited-session outcome on this server")
    integrity_context(ctx)
    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    decision = submit_report(api, inst, token, _elevate)
    expect(decision["verdict"] == "elevated", "setup: expected elevated, got %s" % decision)
    st, pl = open_account(api, inst, token, "limreg-%s" % secrets.token_hex(4))
    expect(st in (200, 201) and pl.get("scope") == "limited"
           and pl.get("limited_causes") == ["integrity_elevated"],
           "registration on soft risk must give a limited session, got %s %s" % (st, pl))


@check("limited session: route 1, a step-up on the same phone, upgrades where the DBA enabled it")
def check_upgrade_route_stepup(api, ctx):
    """DESIGN.md 70. Off by default; when on, it upgrades only a session whose
    causes are all integrity-related, with a step-up proof v2 over the upgrade
    request itself."""
    _skip_unless_screen_lock(live_settings(api))
    settings = live_settings(api)
    if not _setting_on(settings, "upgrade_stepup_same_device"):
        raise Skip("upgrade_stepup_same_device is off (the owner's default); set it to 1 "
                   "to run this check")
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode; limited sessions exist only in enforce mode")
    integrity_context(ctx)
    factor = settings.get("stepup_factor", "passcode")
    inst = Installation()
    stepup_priv, stepup_jwk = stepup_jwk_pair()
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=stepup_jwk,
                   stepup_key_auth={"factor": factor, "mode": "per_use", "window_seconds": 0})
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    token = device_token(api, inst)
    submit_report(api, inst, token)
    handle = "r1-%s" % secrets.token_hex(4)
    st, pl = open_account(api, inst, token, handle)
    expect(st in (200, 201), "setup: account open: %s %s" % (st, pl))
    submit_report(api, inst, token, _elevate)
    st, pl = sign_in(api, inst, token, handle)
    expect(st == 200 and pl.get("scope") == "limited" and "stepup" in (pl.get("upgrade_routes") or []),
           "the limited login must offer route 1, got %s %s" % (st, pl))
    limited = pl["access_token"]
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", limited, {"route": "stepup"})
    expect(st == 403 and error_code(up) == "stepup_required",
           "route 1 without a step-up proof must be refused, got %s %s" % (st, error_code(up)))
    st, up = stepup_call(api, inst, stepup_priv, "POST", "/v1/auth/upgrade", limited,
                         {"route": "stepup"}, factor)
    expect(st == 200 and up.get("scope") == "full" and up.get("upgraded_by") == "stepup"
           and up.get("acceptance_id"),
           "route 1 with a valid step-up proof must upgrade and name its acceptance, got %s %s"
           % (st, up))
    # DESIGN.md 76: the acceptance covers the reasons approved, nothing more.
    acceptance, full = up["acceptance_id"], up["access_token"]
    submit_report(api, inst, token, _elevate)
    st, me = protected(api, inst, "GET", "/v1/account/me", full)
    expect(st == 200 and (me.get("integrity") or {}).get("acceptance_id") == acceptance,
           "the approved reasons must stay covered, got %s %s" % (st, error_code(me) or me))

    def one_more_reason(probes):
        _elevate(probes)
        probes["app_identity"]["allow_backup"] = True  # android_backup_enabled +5: never approved

    submit_report(api, inst, token, one_more_reason)
    st, me = protected(api, inst, "GET", "/v1/account/me", full)
    expect(st == 403 and error_code(me) == "integrity_step_up_required",
           "a reason found after the approval must not be covered, got %s %s" % (st, error_code(me)))
    business = os.environ.get("DEVICE_TRUST_BUSINESS_TOKEN", "")
    if business:
        st, feed = api.call("GET", "/v1/business/acceptance-lapses?limit=1000",
                            headers={"Authorization": "Bearer " + business})
        expect(st == 200 and any(l["acceptance_id"] == acceptance
                                 and l["reason_code"] == "android_backup_enabled"
                                 for l in feed.get("lapses", [])),
               "the new reason must be recorded as a lapse: %s %s" % (st, feed))


@check("limited session: route 2, approval from another installation of the account", db_sensitive=True)
def check_upgrade_route_approval(api, ctx):
    """DESIGN.md 70. A second installation of the account, holding a full
    session, lists the request (no hardware attributes), approves it with its
    own step-up -- the key, the app PIN or both, as the live stepup_method
    says (DESIGN.md 78) -- and the limited session upgrades once. Without
    step-up, or denied, it does not; requests per account are budgeted."""
    settings = live_settings(api)
    if not _setting_on(settings, "upgrade_other_device_approval") and \
            "upgrade_other_device_approval" in settings:
        raise Skip("upgrade_other_device_approval is off on this server")
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode; limited sessions exist only in enforce mode")
    if int(settings.get("upgrade_approvals_per_hour", "3")) < 2:
        raise Skip("upgrade_approvals_per_hour is below 2; this check raises two requests")
    integrity_context(ctx)
    approver, handle, approver_access, prove, missing = _approver(api, settings)

    phone = Installation()
    st, pl = enrol(api, phone, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    phone_token = device_token(api, phone)
    submit_report(api, phone, phone_token, _elevate)

    def limited_login():
        st, pl = sign_in(api, phone, phone_token, handle)
        expect(st == 200 and pl.get("scope") == "limited"
               and "approval" in (pl.get("upgrade_routes") or []),
               "the second phone must get a limited session offering approval, got %s %s" % (st, pl))
        return pl["access_token"]

    def ask(access):
        st, pl = protected(api, phone, "POST", "/v1/auth/upgrade/request", access, {"route": "approval"})
        return st, pl

    limited = limited_login()
    st, req = ask(limited)
    expect(st == 201 and req.get("request_id"), "approval request failed: %s %s" % (st, req))
    rid = req["request_id"]
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", limited,
                       {"route": "approval", "request_id": rid})
    expect(st == 403 and error_code(up) == "approval_not_granted"
           and _details(up).get("state") == "pending",
           "a pending approval must not upgrade, got %s %s" % (st, up))
    st, listed = protected(api, approver, "GET", "/v1/auth/approvals", approver_access)
    mine = [a for a in (listed.get("approvals") or []) if a.get("request_id") == rid] if st == 200 else []
    expect(len(mine) == 1 and set(mine[0].get("requesting_installation") or {})
           == {"platform", "first_seen_at", "registration_method"},
           "the approver must see the request and only what it needs, got %s %s" % (st, listed))
    path = "/v1/auth/approvals/%s/approve" % rid
    st, pl = protected(api, approver, "POST", path, approver_access, {})
    expect(st == 403 and error_code(pl) == missing,
           "approving without step-up must be refused with %s, got %s %s"
           % (missing, st, error_code(pl)))
    st, pl = prove(path)
    expect(st == 200 and pl.get("approved") is True, "approving with step-up failed: %s %s" % (st, pl))
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", limited,
                       {"route": "approval", "request_id": rid})
    expect(st == 200 and up.get("scope") == "full" and up.get("upgraded_by") == "approval"
           and "integrity_elevated" in (up.get("accepted_causes") or []),
           "an approved request must upgrade and record what it accepted, got %s %s" % (st, up))
    # DESIGN.md 72: the acceptance sticks -- protected requests need no
    # step-up for the accepted cause, and a refresh keeps the session full.
    st, me = protected(api, phone, "GET", "/v1/account/me", up["access_token"])
    expect(st == 200 and (me.get("integrity") or {}).get("accepted_by_upgrade") is True,
           "the upgraded session must reach protected paths, got %s %s" % (st, error_code(me) or me))
    st, kept = _refresh(api, phone, up["refresh_token"])
    expect(st == 200 and kept.get("scope") == "full"
           and kept.get("accepted_causes") == up.get("accepted_causes"),
           "a refresh must keep an accepted session full, got %s %s" % (st, kept))
    accepted_access = kept["access_token"]

    second = limited_login()
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", second,
                       {"route": "approval", "request_id": rid})
    expect(st == 403 and error_code(up) == "approval_not_granted",
           "an approval must not upgrade another login, got %s %s" % (st, error_code(up)))
    st, req = ask(second)
    expect(st == 201, "second approval request failed: %s %s" % (st, req))
    st, pl = protected(api, approver, "POST", "/v1/auth/approvals/%s/deny" % req["request_id"],
                       approver_access, {})
    expect(st == 200 and pl.get("denied") is True, "denying failed: %s %s" % (st, pl))
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", second,
                       {"route": "approval", "request_id": req["request_id"]})
    expect(st == 403 and _details(up).get("state") == "denied",
           "a denied request must not upgrade, got %s %s" % (st, up))
    points = int(settings.get("device_approvals_denied_points", "30") or "0")
    if (_setting_on(settings, "cross_checks_enabled")
            and int(settings.get("device_approvals_denied_count", "1") or "0") == 1):
        # DESIGN.md 77: the denied phone's next decision carries the denial;
        # with the owner's effect, limit, it stays limited -- never blocked by
        # the denial alone -- and may ask again within the budget.
        st, pl = sign_in(api, phone, phone_token, handle)
        reason = reason_for(_decision_of(pl), "device_approvals_denied")
        expect(reason is not None and reason.get("points") == points and reason.get("count") == 1,
               "with cross-checks on, the denied phone's next decision must carry "
               "device_approvals_denied +%d: %s %s" % (points, st, _decision_of(pl).get("reasons")))
        if settings.get("device_approvals_denied_effect", "limit") == "limit":
            expect(st == 200 and pl.get("scope") == "limited"
                   and (pl.get("policy") or {}).get("context", {}).get("held_by_denial") is True,
                   "a denied phone must stay limited, not blocked: %s %s"
                   % (st, error_code(pl) or pl.get("scope")))
    budget = int(settings.get("upgrade_approvals_per_hour", "3"))
    for _ in range(max(0, budget - 2)):
        ask(second)
    st, pl = ask(second)
    expect(st == 429 and error_code(pl) == "upgrade_budget_exhausted",
           "request %d in an hour must exceed the budget of %d, got %s %s"
           % (budget + 1, budget, st, error_code(pl)))
    blocked = submit_report(api, phone, phone_token,
                            lambda probes: probes["runtime_maps"].update({"suspicious_tokens": ["frida"]}))
    expect(blocked["verdict"] == "block", "setup: expected block, got %s" % blocked)
    st, me = protected(api, phone, "GET", "/v1/account/me", accepted_access)
    expect(st == 403 and error_code(me) == "integrity_blocked",
           "a block after the acceptance must refuse, got %s %s" % (st, error_code(me)))


@check("limited session: asking again replaces the phone's pending request")
def check_upgrade_request_supersedes(api, ctx):
    """DESIGN.md 75. A phone that asks for approval again replaces its own
    pending request: the approver lists only the newest, the older one can be
    neither approved nor used, and the newest upgrades as usual. The approver
    proves the live stepup_method's factors (DESIGN.md 78)."""
    settings = live_settings(api)
    if not _setting_on(settings, "upgrade_other_device_approval") and \
            "upgrade_other_device_approval" in settings:
        raise Skip("upgrade_other_device_approval is off on this server")
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode; limited sessions exist only in enforce mode")
    if int(settings.get("upgrade_approvals_per_hour", "3")) < 2:
        raise Skip("upgrade_approvals_per_hour is below 2; this check raises two requests")
    integrity_context(ctx)
    approver, handle, approver_access, prove, _ = _approver(api, settings)

    phone = Installation()
    st, pl = enrol(api, phone, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    phone_token = device_token(api, phone)
    submit_report(api, phone, phone_token, _elevate)
    st, pl = sign_in(api, phone, phone_token, handle)
    expect(st == 200 and pl.get("scope") == "limited", "setup: limited session: %s %s" % (st, pl))
    limited = pl["access_token"]
    raised = []
    for _ in range(2):
        st, req = protected(api, phone, "POST", "/v1/auth/upgrade/request", limited, {"route": "approval"})
        expect(st == 201 and req.get("request_id"), "approval request failed: %s %s" % (st, req))
        raised.append(req)
    old, new = raised[0]["request_id"], raised[1]["request_id"]
    expect(raised[1].get("superseded") == 1,
           "the second request must report one superseded, got %s" % raised[1])
    st, listed = protected(api, approver, "GET", "/v1/auth/approvals", approver_access)
    ids = [a.get("request_id") for a in (listed.get("approvals") or [])] if st == 200 else []
    expect(ids == [new], "the approver must see only the newest request, got %s %s" % (st, ids))
    st, pl = prove("/v1/auth/approvals/%s/approve" % old)
    expect(st == 409 and error_code(pl) == "approval_superseded",
           "approving a replaced request must answer approval_superseded, got %s %s" % (st, error_code(pl)))
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", limited,
                       {"route": "approval", "request_id": old})
    expect(st == 403 and _details(up).get("state") == "superseded",
           "a replaced request must read as superseded, got %s %s" % (st, up))
    st, pl = prove("/v1/auth/approvals/%s/approve" % new)
    expect(st == 200 and pl.get("approved") is True, "approving the newest request failed: %s %s" % (st, pl))
    st, up = protected(api, phone, "POST", "/v1/auth/upgrade", limited,
                       {"route": "approval", "request_id": new})
    expect(st == 200 and up.get("scope") == "full",
           "the newest request must upgrade, got %s %s" % (st, up))


# The suite's deterministic route-3 signing key: a server configured with its
# public JWK (printed when the check skips) can run the assertion check.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def conformance_assertion_key():
    seed = int.from_bytes(hashlib.sha256(b"conformance-upgrade-assertion").digest(), "big")
    private = ec.derive_private_key(seed % (P256_ORDER - 1) + 1, ec.SECP256R1())
    nums = private.public_key().public_numbers()
    return private, {"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "conformance-upgrade",
                     "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}


def es256_assertion(private, header, payload):
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    head = b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    r, s_ = decode_dss_signature(private.sign((head + "." + body).encode("ascii"),
                                              ec.ECDSA(hashes.SHA256())))
    return head + "." + body + "." + b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))


@check("limited session: route 3, an assertion from the customer's identity backend")
def check_upgrade_route_assertion(api, ctx):
    """DESIGN.md 70. The customer's backend, after its own MFA, signs the claims
    the server handed out for this request; the session upgrades once, and the
    same assertion cannot serve another login."""
    private, jwk = conformance_assertion_key()
    _, health = api.call("GET", "/health/ready")
    health = health if isinstance(health, dict) else {}
    flags = (health.get("scoring_flags") or {}).get("limited_sessions") or {}
    if jwk["kid"] not in (flags.get("assertion_key_ids") or []):
        raise Skip("the server does not hold the conformance assertion key; to run this check "
                   "put %s in the file named by UPGRADE_ASSERTION_JWKS_FILE"
                   % json.dumps({"keys": [jwk]}, separators=(",", ":")))
    if not _setting_on(live_settings(api), "upgrade_mfa_assertion"):
        raise Skip("upgrade_mfa_assertion is off (the owner's default); set it to 1 to run this check")
    if flags.get("assertion_issuer_pinned"):
        raise Skip("the server pins UPGRADE_ASSERTION_ISSUER; this check signs without one")
    inst, token, handle = _limited_setup(api, ctx)
    st, pl = sign_in(api, inst, token, handle)
    expect(st == 200 and "assertion" in (pl.get("upgrade_routes") or []),
           "the limited login must offer route 3, got %s %s" % (st, pl))
    limited = pl["access_token"]
    st, req = protected(api, inst, "POST", "/v1/auth/upgrade/request", limited, {"route": "assertion"})
    claims = (req or {}).get("assertion_claims") or {}
    expect(st == 201 and claims.get("rid") == req.get("request_id") and claims.get("nonce")
           and claims.get("iid") == inst.installation_id,
           "the server must hand out the claims to sign, got %s %s" % (st, req))
    now = int(time.time())
    header = {"alg": "ES256", "kid": jwk["kid"]}
    signed = dict(claims, iat=now, exp=now + 120, amr=["otp"])
    wrong = es256_assertion(private, header, dict(signed, nonce="not-the-nonce"))
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", limited,
                       {"route": "assertion", "request_id": claims["rid"], "assertion": wrong})
    expect(st == 403 and error_code(up) == "upgrade_assertion_invalid",
           "an assertion over another nonce must be refused, got %s %s" % (st, error_code(up)))
    good = es256_assertion(private, header, signed)
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", limited,
                       {"route": "assertion", "request_id": claims["rid"], "assertion": good})
    expect(st == 200 and up.get("scope") == "full" and up.get("upgraded_by") == "assertion",
           "a valid assertion must upgrade, got %s %s" % (st, up))
    st, pl = sign_in(api, inst, token, handle)
    expect(st == 200 and pl.get("scope") == "limited", "setup: second limited login: %s %s" % (st, pl))
    st, up = protected(api, inst, "POST", "/v1/auth/upgrade", pl["access_token"],
                       {"route": "assertion", "request_id": claims["rid"], "assertion": good})
    expect(st == 403 and error_code(up) == "upgrade_assertion_invalid",
           "a used assertion must not serve another login, got %s %s" % (st, error_code(up)))


@check("enforcement: a step-up proof satisfies an elevated integrity verdict")
def check_elevated_step_up(api, ctx):
    """Review F11 (DESIGN.md 63). An elevated verdict used to answer
    integrity_step_up_required although no step-up proof could satisfy it. On
    an authenticated account request a valid step-up for that request now does
    -- the key, the app PIN or both, as the live stepup_method says (DESIGN.md
    78); without one the refusal stands."""
    if ctx["mode"] != "enforce":
        raise Skip("server is in observe mode")
    settings = live_settings(api)
    method = _method(settings)
    inst, tok, _, access, stepup = _pin_phone(api, settings, method != "app_pin")
    pin = None
    if method != "screen_lock":
        pin, _ = _two_pins(settings)
        st, pl = _set_pin(api, inst, access, pin)
        expect(st == 200, "setting the app PIN: %s %s" % (st, pl))
    decision = submit_report(api, inst, tok, lambda probes: probes.update(
        {"mounts": {"status": "error", "error": "permission denied"}}))
    expect(decision["verdict"] == "elevated", "setup: expected elevated, got %s" % decision)
    body = {"x": 1}
    st, pl = protected(api, inst, "POST", "/v1/account/protected-echo", access, body)
    expect(st == 403 and error_code(pl) == "integrity_step_up_required",
           "without step-up expected 403 integrity_step_up_required, got %s %s" % (st, error_code(pl)))
    st, pl = pin_call(api, inst, "/v1/account/protected-echo", access, body, pin=pin,
                      stepup=stepup)
    expect(st == 200 and (pl.get("integrity") or {}).get("satisfied_by_step_up") is True,
           "a step-up (%s) must satisfy the elevated verdict, got %s %s" % (method, st, pl))


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# iOS fake-signature detection (DESIGN.md 35.5, 35.6) and the key-security
# absence guard (35.7).
# ---------------------------------------------------------------------------

# Exactly what a TrollStore-installed build reported on the iPhone 7. This is
# an observation, not a model of the exploit: why the identifier comes out as
# another application's has not been established. See DESIGN.md 35.4.
IOS_FAKE_SIGNATURE = {
    "signing_identifier": "com.icraze.gtatracker",
    "team_identifier": "TROLLTROLL",
    "signed": True,
}


@check("ios integrity: a fake signature violates the identifier invariant")
def check_ios_fake_signature_detected(api, ctx):
    """A legitimately signed iOS app always has CodeDirectory identifier equal
    to its bundle identifier. TrollStore's grafted signature cannot, which is
    what makes this structural rather than a name match."""
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["code_signing"].update(IOS_FAKE_SIGNATURE),
    )
    expect(
        "ios_signing_identifier_bundle_mismatch" in codes(decision),
        "expected ios_signing_identifier_bundle_mismatch, got %s" % codes(decision),
    )


@check("ios integrity: the fake-signature rule ships report-only and scores 0")
def check_ios_fake_signature_report_only(api, ctx):
    """The rule is deliberately inert by default: its whole evidence base is one
    TrollStore install and no legitimately signed iOS build has been observed.
    This check pins that it is visible but contributes nothing, so flipping
    INTEGRITY_SCORE_IOS_FAKE_SIGNATURE is a conscious act."""
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["code_signing"].update(IOS_FAKE_SIGNATURE),
    )
    reason = reason_for(decision, "ios_signing_identifier_bundle_mismatch")
    expect(reason is not None, "the rule did not fire at all")
    if not reason.get("report_only"):
        raise Skip("INTEGRITY_SCORE_IOS_FAKE_SIGNATURE is enabled on this server")
    expect(reason["points"] == 0,
           "a report-only reason contributed %s points" % reason["points"])
    expect(reason.get("hard") is False, "a report-only reason claimed hard block")
    expect(reason.get("proposed_points") == 90,
           "expected proposed_points 90, got %s" % reason.get("proposed_points"))
    expect(decision["score"] == 0,
           "clean probes plus a report-only rule should score 0, got %s"
           % decision["score"])


@check("ios integrity: the TrollStore team marker is caught, weighted low")
def check_ios_fake_team_identifier(api, ctx):
    """The weaker half of the pair, and named so. It is a name match, which
    27.11 proved defeatable on Android by renaming a live Frida gadget."""
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["code_signing"].update(IOS_FAKE_SIGNATURE),
    )
    reason = reason_for(decision, "ios_known_fake_team_identifier")
    expect(reason is not None,
           "expected ios_known_fake_team_identifier, got %s" % codes(decision))
    proposed = reason.get("proposed_points", reason["points"])
    expect(proposed == 25, "expected a weight of 25, got %s" % proposed)
    expect(reason.get("hard") is False,
           "a name-match rule must never be a hard block")


@check("ios integrity: a correctly signed app does not trip the invariant")
def check_ios_signed_app_is_clean(api, ctx):
    """The false-positive guard. If this ever fails, the invariant claim in
    35.5 is wrong and the rule must not be scored."""
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["code_signing"].update({
            "signing_identifier": probes["app_identity"]["bundle_id"],
            "team_identifier": "ABCDE12345",
            "signed": True,
        }),
    )
    found = codes(decision)
    expect("ios_signing_identifier_bundle_mismatch" not in found,
           "a correctly signed app raised the mismatch rule: %s" % found)
    expect("ios_known_fake_team_identifier" not in found,
           "an ordinary team identifier matched a fake marker: %s" % found)
    expect(decision["score"] == 0, "expected score 0, got %s" % decision["score"])


@check("ios integrity: an unsigned build is not mistaken for a fake signature")
def check_ios_unsigned_is_not_a_finding(api, ctx):
    """An unsigned build reports an empty signing identifier. Absence of a
    measurement must never read as a finding -- the same trap as an integrity
    bucket reporting compared_bytes: 0 and scoring as clean (28.8), and as an
    absent wx_bytes computing to a harmless zero (34.3)."""
    ctx["_api"] = api
    installation, token = ios_integrity_context(ctx)
    decision = submit_report(
        api, installation, token,
        lambda probes: probes["code_signing"].update({
            "signing_identifier": "",
            "team_identifier": "",
            "signed": False,
        }),
    )
    expect("ios_signing_identifier_bundle_mismatch" not in codes(decision),
           "an unsigned build raised the mismatch rule: %s" % codes(decision))


@check("identity: an absent key_security records null, never false")
def check_key_security_absent_is_null(api, ctx):
    """A client that does not report key security must be stored as unknown.
    Collapsing a missing hardware_backed to false would mark every Android and
    .NET installation software-backed on no evidence."""
    installation = Installation()
    status, payload = enrol(api, installation)
    expect(status in (200, 201), "enrol failed: %s %s" % (status, payload))
    block = payload.get("key_security")
    if block is None:
        raise Skip("this server predates the key_security block (schema < 2)")
    for field in ("security_level", "hardware_backed", "provider"):
        expect(block.get(field) is None,
               "%s was %r, expected null for a client that did not report it"
               % (field, block.get(field)))


@check("identity: a reported key_security is recorded as sent")
def check_key_security_recorded(api, ctx):
    """The other half: when a client does report it, the value survives."""
    installation = Installation()
    status, payload = enrol(api, installation, key_security={
        "security_level": "secure_enclave",
        "hardware_backed": True,
        "provider": "SecureEnclave",
    })
    expect(status in (200, 201), "enrol failed: %s %s" % (status, payload))
    block = payload.get("key_security")
    if block is None:
        raise Skip("this server predates the key_security block (schema < 2)")
    expect(block.get("security_level") == "secure_enclave",
           "security_level round-tripped as %r" % block.get("security_level"))
    expect(block.get("hardware_backed") is True,
           "hardware_backed round-tripped as %r" % block.get("hardware_backed"))


@check("identity: unauthenticated re-registration cannot rewrite key security")
def check_key_security_not_rewritten(api, ctx):
    """Review F7. Registration is public and the public key is not a
    credential, so re-registering a known key must not change its stored
    key_security: not upgrade software to StrongBox, and not fill in a claim
    the installation never made (which INTEGRITY_HARDWARE_BACKING_POLICY=
    required would honour)."""
    installation = Installation()
    st, pl = enrol(api, installation, key_security={
        "security_level": "software", "hardware_backed": False, "provider": "AndroidKeyStore"})
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    if pl.get("key_security") is None:
        raise Skip("this server predates the key_security block (schema < 2)")
    st, pl = enrol(api, installation, key_security={
        "security_level": "strongbox", "hardware_backed": True, "provider": "claim-without-proof"})
    block = pl.get("key_security") or {}
    expect(st == 200 and block.get("hardware_backed") is False
           and block.get("security_level") == "software",
           "re-registration rewrote stored key security: %s %s" % (st, block))
    unreported = Installation()
    st, pl = enrol(api, unreported)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    st, pl = enrol(api, unreported, key_security={
        "security_level": "strongbox", "hardware_backed": True, "provider": "late-claim"})
    block = pl.get("key_security") or {}
    expect(st == 200 and block.get("hardware_backed") is None,
           "re-registration filled in an unreported claim: %s %s" % (st, block))


@check("risk: a per-key request-rate anomaly is scored when enabled")
def check_request_rate_anomaly(api, ctx):
    """Opt-in server-side signal. The DBA enables it in risk_policy_settings and
    sets a low max for the test run; the suite reads the live config from
    /health and skips when it is off, exactly like the enforce-mode checks. Uses
    an isolated session so the per-key counter cannot pollute other checks."""
    _, health = api.call("GET", "/health/ready")
    scoring = health.get("scoring_flags", {}) if isinstance(health, dict) else {}
    settings = scoring.get("risk_policy_settings", {})
    if settings.get("rate_anomaly_enabled") != "1":
        raise Skip("rate_anomaly_enabled is off; set it to 1 with a low max to run this check")
    limit = int(settings.get("rate_anomaly_max_requests", "120") or "120")
    if limit > 20:
        raise Skip("rate_anomaly_max_requests=%s is too high for a bounded test run" % limit)
    installation, token, _ = integrity_session(api)
    submit_report(api, installation, token)
    status, payload = open_account(
        api, installation, token, "rate-%s" % secrets.token_hex(4)
    )
    expect(status in (200, 201), "account open failed: %s %s" % (status, payload))
    access = payload["access_token"]
    seen = False
    last = None
    for _ in range(limit + 3):
        st, pl = protected(api, installation, "GET", "/v1/policy/me", access)
        last = (st, pl)
        if st == 200 and "request_rate_anomaly" in codes(pl.get("policy", {})):
            seen = True
            break
    expect(seen, "expected request_rate_anomaly after >%d calls; last=%s" % (limit, last))


@check("risk: a population-baseline outlier is scored when enabled")
def check_population_baseline(api, ctx):
    """Opt-in DBA-set threshold on a relationship metric. Skips unless enabled
    with a low threshold; builds threshold+1 of the metric on ONE device via a
    shared reinstall hint, then verifies the advisory reason fires."""
    _, health = api.call("GET", "/health/ready")
    scoring = health.get("scoring_flags", {}) if isinstance(health, dict) else {}
    settings = scoring.get("risk_policy_settings", {})
    if settings.get("population_baseline_enabled") != "1":
        raise Skip("population_baseline_enabled is off; set it with a low threshold to run this check")
    metric = settings.get("population_baseline_metric", "accounts_per_device")
    threshold = int(settings.get("population_baseline_threshold", "10") or "10")
    if threshold > 10:
        raise Skip("population_baseline_threshold=%s is too high for a bounded test run" % threshold)
    inst1, tok1, hint = integrity_session(api)
    sessions = [(inst1, tok1)]
    for _ in range(threshold):
        inst = Installation()
        st, pl = enrol(api, inst, hint)
        expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
        sessions.append((inst, device_token(api, inst)))
    if metric == "accounts_per_device":
        for inst, tok in sessions:
            submit_report(api, inst, tok)
            open_account(api, inst, tok, "pop-%s" % secrets.token_hex(4))
    inst, tok = sessions[-1]
    submit_report(api, inst, tok)
    st, pl = open_account(api, inst, tok, "popc-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    st2, pl2 = protected(api, inst, "GET", "/v1/policy/me", pl["access_token"])
    expect(st2 == 200, "policy/me failed: %s %s" % (st2, pl2))
    expect(
        "population_outlier" in codes(pl2.get("policy", {})),
        "expected population_outlier (%s>%d); reasons=%s"
        % (metric, threshold, codes(pl2.get("policy", {}))),
    )


def stepup_jwk_pair():
    """A software P-256 step-up key pair: (private key, public JWK)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    return priv, {
        "kty": "EC", "crv": "P-256", "alg": "ES256",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }


def fresh_hint():
    return {"kind": "android_id_sha256", "value": sha256_hex(secrets.token_bytes(16))}


@check("step-up: an optional step-up key registers with its reported auth, absent by default")
def check_stepup_key_registration(api, ctx):
    """The Android 9/10 shape (passcode, 30 s hardware window) registers, is
    echoed back, and is flagged as a downgrade exactly when policy says per_use.
    A malformed auth block is refused; a plain enrol registers nothing."""
    _, health = api.call("GET", "/health/ready")
    settings = (health.get("scoring_flags", {}) if isinstance(health, dict) else {}).get(
        "risk_policy_settings", {})
    policy_mode = settings.get("stepup_mode", "per_use")
    policy_window = int(settings.get("stepup_window_seconds", "0") or 0)
    windowed = {"factor": "passcode", "mode": "windowed", "window_seconds": 30}
    inst = Installation()
    _, stepup_jwk = stepup_jwk_pair()
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=stepup_jwk,
                   stepup_key_auth=windowed)
    expect(st in (200, 201), "enrol with step-up key failed: %s %s" % (st, pl))
    expect(pl.get("stepup_key_registered") is True,
           "expected stepup_key_registered=true, got %s" % pl.get("stepup_key_registered"))
    expect(pl.get("stepup_key_auth") == windowed,
           "reported auth not echoed: %s" % pl.get("stepup_key_auth"))
    want = True if policy_mode == "per_use" else 30 > policy_window
    expect(pl.get("stepup_policy_downgrade") is want,
           "stepup_policy_downgrade expected %s under policy %s/%s, got %s"
           % (want, policy_mode, policy_window, pl.get("stepup_policy_downgrade")))

    _, jwk_bad = stepup_jwk_pair()
    st, pl = enrol(api, Installation(), fresh_hint(), stepup_public_key=jwk_bad,
                   stepup_key_auth={"factor": "passcode", "mode": "per_use", "window_seconds": 30})
    expect(st == 400 and error_code(pl) == "invalid_stepup_key_auth",
           "per_use with a window expected 400 invalid_stepup_key_auth, got %s %s"
           % (st, error_code(pl)))

    same = Installation()
    st, pl = enrol(api, same, fresh_hint(), stepup_public_key=same.jwk,
                   stepup_key_auth={"factor": "passcode", "mode": "per_use", "window_seconds": 0})
    expect(st == 400 and error_code(pl) == "invalid_stepup_key",
           "the installation key offered as its own step-up key expected 400 "
           "invalid_stepup_key, got %s %s" % (st, error_code(pl)))
    _, jwk_no_auth = stepup_jwk_pair()
    st, pl = enrol(api, Installation(), fresh_hint(), stepup_public_key=jwk_no_auth)
    expect(st == 400 and error_code(pl) == "invalid_stepup_key_auth",
           "a step-up key without stepup_key_auth expected 400 invalid_stepup_key_auth, got %s %s"
           % (st, error_code(pl)))

    st2, pl2 = enrol(api, Installation(), fresh_hint())
    expect(st2 in (200, 201), "plain enrol failed: %s %s" % (st2, pl2))
    expect(not pl2.get("stepup_key_registered"),
           "a plain enrol must not register a step-up key")
    expect(pl2.get("stepup_key_auth") is None,
           "a plain enrol must report no step-up auth, got %s" % pl2.get("stepup_key_auth"))


@check("step-up: re-registration can never attach or replace a step-up key")
def check_stepup_key_immutable(api, ctx):
    """Registration is unauthenticated, so a step-up key binds only with a new
    installation key. Re-registering a known key with a different step-up key
    must leave the bound one in place (matches=false); an installation enrolled
    without one must stay without one."""
    auth = {"factor": "passcode", "mode": "per_use", "window_seconds": 0}
    inst = Installation()
    _, bound = stepup_jwk_pair()
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=bound, stepup_key_auth=auth)
    expect(st in (200, 201) and pl.get("stepup_key_registered") is True,
           "initial enrol failed: %s %s" % (st, pl))
    _, attacker = stepup_jwk_pair()
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=attacker,
                   stepup_key_auth={"factor": "passcode", "mode": "windowed", "window_seconds": 3600})
    expect(st == 200, "re-registration expected 200, got %s %s" % (st, pl))
    expect(pl.get("stepup_key_registered") is True and pl.get("stepup_key_matches") is False,
           "a different step-up key must not replace the bound one: registered=%s matches=%s"
           % (pl.get("stepup_key_registered"), pl.get("stepup_key_matches")))
    expect(pl.get("stepup_key_auth") == auth,
           "the bound key's auth must be unchanged, got %s" % pl.get("stepup_key_auth"))
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=bound, stepup_key_auth=auth)
    expect(st == 200 and pl.get("stepup_key_matches") is True,
           "the bound step-up key must match on re-registration: %s %s" % (st, pl))

    plain = Installation()
    st, pl = enrol(api, plain, fresh_hint())
    expect(st in (200, 201), "plain enrol failed: %s %s" % (st, pl))
    st, pl = enrol(api, plain, fresh_hint(), stepup_public_key=attacker, stepup_key_auth=auth)
    expect(st == 200, "re-registration expected 200, got %s %s" % (st, pl))
    expect(pl.get("stepup_key_registered") is False and pl.get("stepup_key_matches") is False,
           "re-registration must not attach a step-up key: registered=%s matches=%s"
           % (pl.get("stepup_key_registered"), pl.get("stepup_key_matches")))


@check("step-up: a sensitive path requires a valid step-up proof for that exact request")
def check_step_up(api, ctx):
    """Opt-in: skips unless the demo sensitive path is in stepup_required_paths.
    No proof -> 403 stepup_required; a valid step-up proof -> 200; wrong factor
    -> 403 stepup_factor_mismatch; an approval moved to another body (review
    F1) -> 403 stepup_binding_mismatch; a v1 proof -> 403
    stepup_proof_version_unsupported; a key registered with another factor ->
    403 stepup_factor_mismatch."""
    _skip_unless_screen_lock(live_settings(api), sensitive_path=True)
    _, health = api.call("GET", "/health/ready")
    scoring = health.get("scoring_flags", {}) if isinstance(health, dict) else {}
    settings = scoring.get("risk_policy_settings", {})
    if "/v1/account/sensitive-echo" not in (settings.get("stepup_required_paths") or ""):
        raise Skip("sensitive-echo not in stepup_required_paths; set it to run this check")
    factor = settings.get("stepup_factor", "passcode")
    inst = Installation()
    stepup_priv, stepup_jwk = stepup_jwk_pair()
    key_auth = {"factor": factor, "mode": "per_use", "window_seconds": 0}
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=stepup_jwk,
                   stepup_key_auth=key_auth)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    tok = device_token(api, inst)
    submit_report(api, inst, tok)
    st, pl = open_account(api, inst, tok, "su-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]
    body = {"move": "money"}
    st, pl = protected(api, inst, "POST", "/v1/account/sensitive-echo", access, body)
    expect(st == 403 and error_code(pl) == "stepup_required",
           "no-proof expected 403 stepup_required, got %s %s" % (st, error_code(pl)))
    st, pl = stepup_call(api, inst, stepup_priv, "POST", "/v1/account/sensitive-echo", access, body, factor)
    expect(st == 200, "valid step-up expected 200, got %s %s" % (st, pl))
    expect(pl.get("step_up") == "verified"
           and (pl.get("step_up_key") or {}).get("key_auth") == key_auth
           and (pl.get("step_up_key") or {}).get("policy_downgrade") is False,
           "verified response must carry the key's auth, got %s %s"
           % (pl.get("step_up"), pl.get("step_up_key")))
    wrong = "biometric" if factor != "biometric" else "passcode"
    st, pl = stepup_call(api, inst, stepup_priv, "POST", "/v1/account/sensitive-echo", access, body, wrong)
    expect(st == 403 and error_code(pl) == "stepup_factor_mismatch",
           "wrong-factor expected 403 stepup_factor_mismatch, got %s %s" % (st, error_code(pl)))

    # The review's reproduction: an approval signed for one body, attached to a
    # different body under a freshly signed access proof with the same nonce.
    st, pl = stepup_call(api, inst, stepup_priv, "POST", "/v1/account/sensitive-echo", access,
                         {"move": "all the money"}, factor, approve_body=body)
    expect(st == 403 and error_code(pl) == "stepup_binding_mismatch",
           "a retargeted approval expected 403 stepup_binding_mismatch, got %s %s"
           % (st, error_code(pl)))
    st, pl = stepup_call(api, inst, stepup_priv, "POST", "/v1/account/sensitive-echo", access,
                         body, factor, overrides={"path": "/v1/account/protected-echo"})
    expect(st == 403 and error_code(pl) == "stepup_binding_mismatch",
           "an approval for another path expected 403 stepup_binding_mismatch, got %s %s"
           % (st, error_code(pl)))
    headers, body_text = build_proof(inst, "POST", "/v1/account/sensitive-echo", access, body)
    nonce = json.loads(b64u_decode(headers["X-Access-Proof"]).decode("utf-8"))["nonce"]
    v1 = b64u(json.dumps({"version": 1, "installation_id": inst.installation_id,
                          "factor": factor, "nonce": nonce,
                          "timestamp": int(time.time())}).encode("utf-8"))
    headers["X-Step-Up-Proof"] = v1
    headers["X-Step-Up-Signature"] = b64u(stepup_priv.sign(b64u_decode(v1),
                                                           ec.ECDSA(hashes.SHA256())))
    st, pl = api.call("POST", "/v1/account/sensitive-echo", body_text=body_text,
                      bearer=access, headers=headers)
    expect(st == 403 and error_code(pl) == "stepup_proof_version_unsupported",
           "a v1 step-up proof expected 403 stepup_proof_version_unsupported, got %s %s"
           % (st, error_code(pl)))

    # The key's registered factor counts too, not only the proof's claim.
    other = Installation()
    other_priv, other_jwk = stepup_jwk_pair()
    st, pl = enrol(api, other, fresh_hint(), stepup_public_key=other_jwk,
                   stepup_key_auth={"factor": wrong, "mode": "per_use", "window_seconds": 0})
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    other_tok = device_token(api, other)
    submit_report(api, other, other_tok)
    st, pl = open_account(api, other, other_tok, "sf-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    st, pl = stepup_call(api, other, other_priv, "POST", "/v1/account/sensitive-echo",
                         pl["access_token"], body, factor)
    expect(st == 403 and error_code(pl) == "stepup_factor_mismatch",
           "a key registered as %s under a %s policy expected 403 stepup_factor_mismatch, "
           "got %s %s" % (wrong, factor, st, error_code(pl)))



def _policy_of(payload):
    """The risk decision from a success body or from a refusal's details."""
    if not isinstance(payload, dict):
        return {}
    if isinstance(payload.get("policy"), dict):
        return payload["policy"]
    details = (payload.get("error") or {}).get("details") or {}
    return details.get("policy") or {}


def _reason_codes(policy):
    return {r.get("code") for r in (policy.get("reasons") or []) if isinstance(r, dict)}


@check("risk: accounts per device follow the DBA policy (defaults 2 elevated, 3 review, 4 block)")
def check_device_account_bands(api, ctx):
    """Owner defaults (DESIGN.md 54), DBA-tunable in risk_policy_settings. A phone
    shared by two people is legitimate: the elevated account count is scored but,
    unless elevated_risk_refuses=1, neither user is refused. The review count is
    held for review and the block count is blocked. Expectations come from the
    live settings, so the check stays valid after a DBA retunes; the refusal half
    runs when DEVICE_POLICY_MODE=enforce."""
    _, health = api.call("GET", "/health/ready")
    health = health if isinstance(health, dict) else {}
    enforce = health.get("device_policy_mode") == "enforce"
    settings = (health.get("scoring_flags") or {}).get("risk_policy_settings") or {}

    def setting(key, default):
        try:
            return int(settings.get(key, default))
        except (TypeError, ValueError):
            return default

    elevated = setting("device_accounts_elevated_count", 2)
    review = setting("device_accounts_review_count", 3)
    block = setting("device_accounts_block_count", 4)
    refuses = str(settings.get("elevated_risk_refuses", "0")).strip().lower() in (
        "1", "true", "yes", "on")
    if not 1 < elevated < review < block <= 10:
        raise Skip("band layout %s/%s/%s is not ordered within 10 accounts" % (elevated, review, block))

    inst = Installation()
    st, pl = enrol(api, inst, fresh_hint())
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    tok = device_token(api, inst)
    submit_report(api, inst, tok)
    results = {}
    for n in range(1, block + 1):
        st, pl = open_account(api, inst, tok, "band%d-%s" % (n, secrets.token_hex(4)))
        results[n] = (st, pl, _policy_of(pl))
        if st not in (200, 201):
            break

    st, pl, pol = results[elevated]
    expect("device_has_multiple_accounts" in _reason_codes(pol),
           "account %d must be scored device_has_multiple_accounts, got %s"
           % (elevated, sorted(_reason_codes(pol))))
    if enforce and refuses:
        expect(st == 403 and error_code(pl) == "risk_step_up_required",
               "elevated_risk_refuses=1: account %d expected 403 risk_step_up_required, got %s %s"
               % (elevated, st, error_code(pl)))
        return
    for n in range(elevated, review):
        expect(results[n][0] in (200, 201),
               "account %d (elevated band) must never be refused, got %s %s"
               % (n, results[n][0], error_code(results[n][1])))
    for n in range(1, review):
        st, pl = protected(api, inst, "GET", "/v1/account/me", results[n][1].get("access_token"))
        expect(st == 200, "account %d on the shared device must keep working, got %s %s"
               % (n, st, error_code(pl)))

    st, pl, pol = results[review]
    expect("device_has_many_accounts" in _reason_codes(pol)
           and pol.get("recommended_action") in ("review", "block"),
           "account %d must be scored for review, got %s %s"
           % (review, pol.get("recommended_action"), sorted(_reason_codes(pol))))
    if enforce:
        # Never a limited session here (DESIGN.md 70): admitting the account
        # would link it for good and put every account on the device into review.
        expect(st == 403 and error_code(pl) in ("risk_review_required", "risk_policy_blocked"),
               "enforce: account %d must be held for review, got %s %s"
               % (review, st, error_code(pl)))
        return
    st, pl, pol = results[block]
    expect(st in (200, 201)
           and "device_account_count_block_threshold" in _reason_codes(pol)
           and pol.get("recommended_action") == "block",
           "account %d must be scored block, got %s %s %s"
           % (block, st, pol.get("recommended_action"), sorted(_reason_codes(pol))))



@check("risk: devices per account follow the DBA policy (defaults 2 elevated, 3 review)")
def check_account_device_bands(api, ctx):
    """Migration 012. One account signing in on more and more devices: the
    elevated count raises the score, the review count holds the decision for
    review (by default a third device), and in enforce mode that sign-in never
    gets a full session. Expectations come from the live settings."""
    settings = live_settings(api)
    _, health = api.call("GET", "/health/ready")
    enforce = (health if isinstance(health, dict) else {}).get("device_policy_mode") == "enforce"
    elevated = int(settings.get("account_devices_elevated_count", "2"))
    review = int(settings.get("account_devices_review_count", "3"))
    if not 1 < elevated < review <= 6:
        raise Skip("devices-per-account counts %s/%s are not ordered within 6" % (elevated, review))

    def device():
        inst = Installation()
        st, pl = enrol(api, inst, fresh_hint())
        expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
        token = device_token(api, inst)
        submit_report(api, inst, token)
        return inst, token

    first, token = device()
    handle = "devs-%s" % secrets.token_hex(4)
    st, pl = open_account(api, first, token, handle)
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    for n in range(2, review + 1):
        inst, token = device()
        st, pl = sign_in(api, inst, token, handle)
        pol = _policy_of(pl)
        if n == elevated:
            expect("account_has_multiple_devices" in _reason_codes(pol),
                   "device %d must be scored account_has_multiple_devices, got %s %s"
                   % (n, st, sorted(_reason_codes(pol))))
        if n == review:
            expect("account_has_many_devices" in _reason_codes(pol)
                   and pol.get("recommended_action") in ("review", "block"),
                   "device %d must be held for review, got %s %s %s"
                   % (n, st, pol.get("recommended_action"), sorted(_reason_codes(pol))))
            if enforce:
                # DESIGN.md 72: refused, never limited -- its permanent link
                # would hold every device of the account in review.
                expect(st == 403 and error_code(pl) in ("risk_review_required", "risk_policy_blocked"),
                       "enforce: device %d must be refused, got %s %s %s"
                       % (n, st, error_code(pl), pl.get("scope")))


def jwk_thumbprint(jwk):
    """The server's key thumbprint: SHA-256 hex of the sorted canonical JWK."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
                           sort_keys=True, separators=(",", ":"))
    return sha256_hex(canonical.encode("utf-8"))


@check("step-up: re-enrolment needs the password and the new key's own proof")
def check_stepup_reenrol(api, ctx):
    """DESIGN.md 58. An installation that lost its step-up key binds a new one
    only with the access proof, the account password and a signature by the new
    key bound to this request. A wrong password or a proof signed by another key
    is refused and changes nothing; the right one replaces the bound key."""
    auth = {"factor": "passcode", "mode": "per_use", "window_seconds": 0}
    inst = Installation()
    old_priv, old_jwk = stepup_jwk_pair()
    st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=old_jwk, stepup_key_auth=auth)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    tok = device_token(api, inst)
    submit_report(api, inst, tok)
    password = "Passw0rd123"
    st, pl = open_account(api, inst, tok, "re-%s" % secrets.token_hex(4), password)
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]
    new_priv, new_jwk = stepup_jwk_pair()
    other_priv, _ = stepup_jwk_pair()

    def reenrol(pw, signer, jwk=None, bearer=None):
        jwk = jwk or new_jwk
        bearer = bearer or access
        nonce_bytes = secrets.token_bytes(32)
        key_proof = b64u(json.dumps({
            "version": 1, "purpose": "stepup_reenrol",
            "installation_id": inst.installation_id,
            "stepup_key_thumbprint": jwk_thumbprint(jwk),
            "nonce": b64u(nonce_bytes), "timestamp": int(time.time()),
        }).encode("utf-8"))
        body = {"password": pw, "stepup_public_key": jwk, "stepup_key_auth": auth,
                "stepup_key_proof": key_proof,
                "stepup_key_signature": b64u(signer.sign(b64u_decode(key_proof),
                                                         ec.ECDSA(hashes.SHA256())))}
        headers, body_text = build_proof(inst, "POST", "/v1/installations/stepup-key",
                                         bearer, body, nonce_bytes=nonce_bytes)
        return api.call("POST", "/v1/installations/stepup-key", body_text=body_text,
                        bearer=bearer, headers=headers)

    def matches(jwk):
        st, pl = enrol(api, inst, fresh_hint(), stepup_public_key=jwk, stepup_key_auth=auth)
        expect(st == 200, "re-registration expected 200, got %s %s" % (st, pl))
        return pl.get("stepup_key_matches")

    st, pl = reenrol("wrong-" + password, new_priv)
    expect(st == 401 and error_code(pl) == "invalid_credentials",
           "wrong password expected 401 invalid_credentials, got %s %s" % (st, error_code(pl)))
    st, pl = reenrol(password, other_priv)
    expect(st == 403 and error_code(pl) == "stepup_reenrol_proof_invalid",
           "a proof by another key expected 403 stepup_reenrol_proof_invalid, got %s %s"
           % (st, error_code(pl)))
    expect(matches(new_jwk) is False, "refused re-enrolments must not change the bound key")
    st, pl = reenrol(password, new_priv)
    expect(st == 200 and pl.get("stepup_key_registered") is True,
           "valid re-enrolment expected 200, got %s %s" % (st, pl))
    expect(matches(new_jwk) is True and matches(old_jwk) is False,
           "after re-enrolment the new key must be bound and the old one not")

    # A second account opened on the same device (needs only the installation
    # key) may re-enrol with its own password, but that key must not pass
    # step-up for the first account. Needs the sensitive path gated.
    _, health = api.call("GET", "/health/ready")
    settings = ((health if isinstance(health, dict) else {}).get("scoring_flags") or {}).get(
        "risk_policy_settings") or {}
    if "/v1/account/sensitive-echo" not in (settings.get("stepup_required_paths") or ""):
        return
    if _method(settings) != "screen_lock" or SENSITIVE_PATH in _setting_words(
            settings, "app_pin_required_paths", ""):
        return  # the tail proves the screen-lock key alone on the sensitive path
    factor = settings.get("stepup_factor", "passcode")
    st, pl = open_account(api, inst, tok, "re2-%s" % secrets.token_hex(4), "Second0ne123")
    expect(st in (200, 201), "second account open failed: %s %s" % (st, pl))
    second_access = pl["access_token"]
    second_priv, second_jwk = stepup_jwk_pair()
    st, pl = reenrol("Second0ne123", second_priv, second_jwk, second_access)
    expect(st == 200, "the second account's re-enrolment expected 200, got %s %s" % (st, pl))
    body = {"move": "money"}
    st, pl = stepup_call(api, inst, second_priv, "POST", "/v1/account/sensitive-echo",
                         access, body, factor)
    expect(st == 403 and error_code(pl) == "stepup_key_other_account",
           "the first account must not pass step-up with the second account's key, got %s %s"
           % (st, error_code(pl)))
    st, pl = stepup_call(api, inst, second_priv, "POST", "/v1/account/sensitive-echo",
                         second_access, body, factor)
    expect(st == 200, "the second account's own key expected 200, got %s %s" % (st, pl))

@check("identity: registrations that never prove their key do not count toward a device", db_sensitive=True)
def check_unproven_registrations(api, ctx):
    """Review F6 (DESIGN.md 63). Registration is public: anyone holding a
    device's reinstall hint could register keys against it without ever proving
    them, and five such rows reached the reinstall block. Only installations
    that have answered a challenge with their key count; a proven reinstall
    still does."""
    owner, hint = Installation(), fresh_hint()
    st, pl = enrol(api, owner, hint)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    tok = device_token(api, owner)
    submit_report(api, owner, tok)
    st, pl = open_account(api, owner, tok, "f6-%s" % secrets.token_hex(4))
    expect(st in (200, 201), "account open failed: %s %s" % (st, pl))
    access = pl["access_token"]
    for _ in range(5):
        st, pl = enrol(api, Installation(), hint)
        expect(st in (200, 201) and pl.get("device_id") == owner.device_id,
               "the hint must still correlate an unproven key: %s %s" % (st, pl))
    st, pl = protected(api, owner, "GET", "/v1/policy/me", access)
    policy = _policy_of(pl)
    context = policy.get("context") or {}
    expect(st == 200 and not {"rapid_reinstall_block_threshold", "rapid_reinstall_high",
                              "rapid_reinstall_elevated"} & _reason_codes(policy),
           "five unproven registrations must not raise reinstall reasons: %s %s"
           % (st, sorted(_reason_codes(policy))))
    expect(context.get("device_installation_count") == 1
           and context.get("recent_reinstall_count") == 0,
           "unproven registrations counted: installations=%s reinstalls=%s"
           % (context.get("device_installation_count"), context.get("recent_reinstall_count")))
    proven = Installation()
    st, pl = enrol(api, proven, hint)
    expect(st in (200, 201), "enrol failed: %s %s" % (st, pl))
    device_token(api, proven)
    st, pl = protected(api, owner, "GET", "/v1/policy/me", access)
    context = _policy_of(pl).get("context") or {}
    expect(context.get("device_installation_count") == 2
           and context.get("recent_reinstall_count") == 1,
           "a proven reinstall must still count: installations=%s reinstalls=%s"
           % (context.get("device_installation_count"), context.get("recent_reinstall_count")))


@check("concurrency: parallel clients neither crash nor stall the server", db_sensitive=True)
def check_parallel_clients(api, ctx):
    """Four phone-like clients enrol, prove possession, report integrity and read
    /v1/device/me at the same time, three rounds. Every other check is
    sequential, which is how a heap-corrupting ODBC driver-manager pool on SQL
    Server went unseen until two handsets bootstrapped together (DESIGN.md 55).
    Every flow must succeed and no step may approach the handset client's 15 s
    timeout."""
    failures, slowest, lock = [], [0.0, ""], threading.Lock()

    def flow(tag):
        client = Api(api.base_url)
        try:
            inst = Installation()
            steps = []
            started = time.time()
            status, payload = enrol(client, inst, fresh_hint())
            steps.append(("register", time.time() - started))
            if status not in (200, 201):
                raise AssertionError("register %s" % status)
            started = time.time()
            token = device_token(client, inst)
            steps.append(("challenge+verify", time.time() - started))
            started = time.time()
            submit_report(client, inst, token)
            steps.append(("integrity", time.time() - started))
            started = time.time()
            status, payload = protected(client, inst, "GET", "/v1/device/me", token)
            steps.append(("device/me", time.time() - started))
            if status != 200:
                raise AssertionError("device/me %s %s" % (status, error_code(payload)))
            with lock:
                for step, seconds in steps:
                    if seconds > slowest[0]:
                        slowest[0], slowest[1] = seconds, step
        except BaseException as error:  # SystemExit/TimeoutError end a thread silently
            with lock:
                failures.append("%s: %s" % (tag, str(error)[:100]))

    for round_number in range(3):
        threads = [threading.Thread(target=flow, args=("r%d-c%d" % (round_number, i),))
                   for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    expect(not failures, "%d of 12 parallel flows failed: %s" % (len(failures), "; ".join(failures[:3])))
    expect(slowest[0] < 10.0,
           "slowest step %s took %.1fs under parallel load (handset timeout is 15s)"
           % (slowest[1], slowest[0]))

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
    backend = health.get("database") or {}
    engine = "%s %s" % (backend.get("engine", "unknown"), backend.get("version", ""))
    print("target   : %s" % arguments.base_url)
    print("database : %s   (minimum supported %s, supported=%s)" % (
        engine.strip(), backend.get("minimum_supported", "?"),
        backend.get("supported", "?")))
    print("integrity: %s" % mode)
    if mode != "observe":
        print(
            "WARNING  : this suite expects INTEGRITY_MODE=observe; "
            "enforce mode requires a fresh integrity report."
        )
    print()

    context = {"mode": mode}
    passed = failed = skipped = 0
    for name, function, db_sensitive in CHECKS:
        marker = " [db]" if db_sensitive else ""
        try:
            function(api, context)
        except Skip as reason:
            skipped += 1
            print("SKIP %s%s  (%s)" % (name, marker, reason))
        except Exception as error:  # noqa: BLE001 - report every failure
            failed += 1
            print("FAIL %s%s\n       %s" % (name, marker, error))
        else:
            passed += 1
            print("PASS %s%s" % (name, marker))

    print("\n%d passed, %d failed, %d skipped  (checks marked [db] are the ones "
          "whose behaviour differs between PostgreSQL and SQL Server)"
          % (passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
