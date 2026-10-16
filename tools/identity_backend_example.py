"""A reference identity backend for route 3: the way back for users with one phone (DESIGN.md 84.8).

A user whose only phone holds a limited session has no second phone to approve
from (route 2). Route 3 lets YOUR identity system vouch instead: after its own
multi-factor check, your backend signs the claims this server handed the app,
and the app upgrades with that signature (INTEGRATION_GUIDE.md section 7). This
file is a small, working example of that backend, to copy into your own stack
or to try the route end to end. It is not an MFA product.

    # once: make the signing key and print the JWKS for the device-trust server
    python3 tools/identity_backend_example.py --state ./idp --jwks > assertion-jwks.json
    # put that file where UPGRADE_ASSERTION_JWKS_FILE names it, restart the server,
    # and set upgrade_mfa_assertion to 1 in risk_policy_settings

    # enrol an account in the example's one-time codes (an authenticator app)
    python3 tools/identity_backend_example.py --state ./idp --enrol <account_id>

    # serve POST /assertions behind your TLS proxy
    python3 tools/identity_backend_example.py --state ./idp --serve 127.0.0.1:8710

POST /assertions with {"claims": <assertion_claims from /v1/auth/upgrade/request>,
"otp": "<six digits>"}: when the code is right for the account the claims name
(sub), the answer is {"assertion": "<ES256 compact JWS>"}, valid for five
minutes, with amr ["otp"]. Five wrong codes for an account lock it for fifteen
minutes. Everything else answers 400 or 403.

What a real backend adds: it authenticates the person first (its own sign-in or
support verification), not only a code for the account the app names; it keeps
the signing key in a KMS or HSM; it rate-limits by source too, and logs every
assertion it signs. The device-trust server checks the rest: the signature, the
audience, the account, the installation, the request and its nonce, the expiry,
and that each request is upgraded once.

Standard library plus pycryptodome, which the server already needs.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

ASSERTION_SECONDS = 300
CLAIM_NAMES = ("aud", "sub", "iid", "rid", "nonce")
LOCK_FAILURES, LOCK_SECONDS = 5, 900


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _write_private(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)


def signing_key(state):
    path = os.path.join(state, "signing_key.pem")
    if not os.path.exists(path):
        os.makedirs(state, mode=0o700, exist_ok=True)
        _write_private(path, ECC.generate(curve="P-256").export_key(format="PEM"))
    with open(path) as handle:
        return ECC.import_key(handle.read())


def public_jwk(key):
    point = key.public_key().pointQ
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(int(point.x).to_bytes(32, "big")),
           "y": b64u(int(point.y).to_bytes(32, "big"))}
    # RFC 7638 thumbprint as the key ID, so a rotated key gets a new one.
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")},
                           separators=(",", ":"), sort_keys=True)
    jwk.update(alg="ES256", use="sig", kid=b64u(hashlib.sha256(canonical.encode()).digest()))
    return jwk


def es256(key, header, payload):
    head = b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = DSS.new(key, "fips-186-3", encoding="binary").sign(
        SHA256.new((head + "." + body).encode("ascii")))
    return head + "." + body + "." + b64u(signature)


def totp(secret_b32, at=None, step=30, digits=6):
    """RFC 6238 with HMAC-SHA1, as authenticator apps compute it."""
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = struct.pack(">Q", int((at if at is not None else time.time()) // step))
    mac = hmac.new(key, counter, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def otp_matches(secret_b32, otp, now=None):
    now = time.time() if now is None else now
    return isinstance(otp, str) and any(
        hmac.compare_digest(totp(secret_b32, now + drift), otp) for drift in (-30, 0, 30))


def load_accounts(state):
    path = os.path.join(state, "accounts.json")
    if not os.path.exists(path):
        return {}
    with open(path) as handle:
        return json.load(handle)


def enrol(state, account_id):
    accounts = load_accounts(state)
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    accounts[account_id] = secret
    os.makedirs(state, mode=0o700, exist_ok=True)
    _write_private(os.path.join(state, "accounts.json"), json.dumps(accounts, indent=2))
    return secret


class Signer(object):
    """Checks a code for the account the claims name and signs the claims."""

    def __init__(self, state, audience, issuer=None, clock=time.time):
        self.state, self.audience, self.issuer, self.clock = state, audience, issuer, clock
        self.key = signing_key(state)
        self.kid = public_jwk(self.key)["kid"]
        self.failures = {}
        self.lock = threading.Lock()

    def sign(self, claims, otp):
        """(status, answer) for one request."""
        if not isinstance(claims, dict) or set(claims) != set(CLAIM_NAMES) or not all(
                isinstance(claims[name], str) and claims[name] for name in CLAIM_NAMES):
            return 400, {"error": "claims must be exactly %s, as the server handed them out"
                                  % ", ".join(CLAIM_NAMES)}
        if claims["aud"] != self.audience:
            return 403, {"error": "these claims are for another audience"}
        now = self.clock()
        account = claims["sub"]
        with self.lock:
            failures = [t for t in self.failures.get(account, []) if now - t < LOCK_SECONDS]
            self.failures[account] = failures
            if len(failures) >= LOCK_FAILURES:
                return 403, {"error": "too many wrong codes; try again later"}
            secret = load_accounts(self.state).get(account)
            if secret is None or not otp_matches(secret, otp, now):
                failures.append(now)
                return 403, {"error": "the code is not right for this account"}
            self.failures[account] = []
        payload = dict(claims, iat=int(now), exp=int(now) + ASSERTION_SECONDS, amr=["otp"])
        if self.issuer:
            payload["iss"] = self.issuer
        return 200, {"assertion": es256(self.key, {"alg": "ES256", "kid": self.kid}, payload)}


def serve(signer, address):
    host, _, port = address.rpartition(":")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/assertions":
                return self._answer(404, {"error": "not found"})
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 16384)
                body = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return self._answer(400, {"error": "a JSON object is required"})
            if not isinstance(body, dict):
                return self._answer(400, {"error": "a JSON object is required"})
            status, answer = signer.sign(body.get("claims"), body.get("otp"))
            self._answer(status, answer)

        def _answer(self, status, answer):
            data = json.dumps(answer).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            sys.stderr.write("identity backend: %s\n" % (fmt % args))

    ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--state", required=True, help="directory for the key and enrolments")
    parser.add_argument("--jwks", action="store_true", help="print the JWKS for the server")
    parser.add_argument("--enrol", metavar="ACCOUNT_ID", help="enrol an account in one-time codes")
    parser.add_argument("--serve", metavar="HOST:PORT")
    parser.add_argument("--audience", default="device-trust-upgrade",
                        help="the audience the device-trust server expects (its default)")
    parser.add_argument("--issuer", help="the server's UPGRADE_ASSERTION_ISSUER, if it pins one")
    args = parser.parse_args()
    if args.jwks:
        print(json.dumps({"keys": [public_jwk(signing_key(args.state))]}))
    if args.enrol:
        secret = enrol(args.state, args.enrol)
        print("secret %s" % secret)
        print("otpauth://totp/DeviceTrust:%s?secret=%s&issuer=DeviceTrust" % (args.enrol, secret))
    if args.serve:
        serve(Signer(args.state, args.audience, args.issuer), args.serve)
    return 0


if __name__ == "__main__":
    sys.exit(main())
