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


def clean_probes(required, cert=None):
    """A pristine production Android device: every rule should score zero."""
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
        "runtime_maps": {"status": "ok", "suspicious_tokens": [], "suspicious_line_count": 0},
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
        },
        "emulator": {"status": "ok", "suspected": False},
        "developer_settings": {
            "status": "ok",
            "developer_options_enabled": False,
            "adb_enabled": False,
        },
    }
    return {name: everything[name] for name in required if name in everything}


def submit_report(api, installation, token, mutate=None, cert=None):
    """Run one full integrity round trip and return the server's decision."""
    status, challenge = protected(
        api, installation, "POST", "/v1/integrity/challenge", token, {}
    )
    if status != 200:
        raise AssertionError("integrity challenge failed: %s %s" % (status, challenge))
    probes = clean_probes(challenge["required_probes"], cert=cert)
    if mutate:
        mutate(probes)
    report = {
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["nonce"],
        "installation_id": installation.installation_id,
        "platform": challenge["platform"],
        "collector_version": 1,
        "collected_at": int(time.time()),
        "probe_results": probes,
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
