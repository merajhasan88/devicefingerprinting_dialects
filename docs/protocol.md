# The wire protocol, as this client implements it

`DESIGN.md` is the authoritative record of why each rule is shaped the way it is. This file records
what the .NET SDK actually puts on the wire, so a reviewer can check the implementation against the
protocol without reading the server.

## Call order

| # | Call | Auth | Purpose |
|---|---|---|---|
| 1 | `POST /v1/installations/register` | none | Send the P-256 public JWK. The server's identity for this installation is the key thumbprint, not the client UUID. |
| 2 | `POST /v1/installations/challenge` | none | Get a challenge bound to the installation. |
| 3 | `POST /v1/installations/verify` | none | Return the signed challenge; receive a 10-minute **device** token. |
| 4 | `POST /v1/integrity/challenge` | device or account + access proof | The server chooses which probes to run. |
| 5 | `POST /v1/integrity/report` | device or account + access proof | Submit the signed report; receive the server's verdict. |
| 6 | `POST /v1/accounts/register` \| `/login` | **device** token + access proof | Issue account access and refresh tokens bound to `did` and `iid`. |
| 7 | `GET /v1/account/me`, `POST /v1/account/protected-echo`, `GET /v1/policy/me`, `GET /v1/device/me` | account token + access proof | Ordinary protected calls. |
| 8 | `POST /v1/auth/refresh/challenge` → `POST /v1/auth/refresh` | refresh token | Rotate the session. Reusing a rotated token revokes the family. |
| 9 | `POST /v1/account/sensitive-echo` | account token + access proof (+ step-up proof on a gated path) | The demo crown-jewel operation. Gated only when a DBA lists it in `risk_policy_settings.stepup_required_paths`. |
| 10 | `POST /v1/installations/stepup-key` | account token + access proof + password + new-key proof | Re-enrol a lost or replaced step-up key (DESIGN.md 58). |

Lifetimes: access 10 minutes, device 10 minutes, refresh 30 days, challenge 2 minutes, access-proof
skew ±120 seconds, integrity report skew ±90 seconds, integrity freshness 600 seconds.

The endpoint must be `https://`: `DeviceTrustOptions.ResolveBaseUri` refuses `http://` with
`api_base_url_insecure` unless `AllowInsecureHttp` is set for a local lab server (the counterpart of
the reference client's release-build rule, DESIGN.md 63 F8).

Only `android` and `ios` are accepted platforms. The client registers under the platform its
integrity collector can actually measure, which is why `DeviceTrustClient.Platform` defaults to
`IIntegrityProbeCollector.Platform` rather than to a constant.

## Registration: `key_security` and the step-up key

Since DESIGN.md 50 and 53 the registration body carries two optional blocks.

```json
"key_security":    {"security_level": "strongbox", "hardware_backed": true, "provider": "AndroidKeyStore"},
"stepup_public_key": {"kty": "EC", "crv": "P-256", "alg": "ES256", "x": "…", "y": "…"},
"stepup_key_auth": {"factor": "passcode", "mode": "per_use", "window_seconds": 0}
```

- `key_security` is always sent, from `InstallationKeyMetadata`. A level the store could not read is
  sent as `security_level: null, hardware_backed: null`, never as `"unknown", false`: `false` is a
  claim of software backing, which `INTEGRITY_HARDWARE_BACKING_POLICY=advisory` scores +30.
- The step-up key is sent only when an `IStepUpKeyStore` produced one. No screen lock means no key and
  no block, never a failed enrolment. `stepup_key_auth` is what the keystore **enforces**, read back
  from the key: Android 9/10 turns a per-use passcode request into `windowed`/30, and the server
  records that as `stepup_policy_downgrade: true`. iOS is always `per_use`.
- A step-up key binds **only when the installation key is new**. On re-registration the server never
  attaches or replaces one; it answers `stepup_key_registered`, `stepup_key_matches` (null when none
  was offered), `stepup_key_auth` and `stepup_policy_downgrade`. `stepup_key_auth` is required with a
  key, and the step-up key must differ from the installation key (`400 invalid_stepup_key_auth`,
  `400 invalid_stepup_key`).
- The client offers step-up only for **the key the server last confirmed as bound**: the key it
  offered at registration, when that registration bound it (new installation) or reported it
  matching (`DeviceTrustClient.BoundStepUpThumbprint`, `StepUpUsable`). "Not asked" (`matches` null
  because no key was offered) is not "matches": the reference iPhone otherwise offered a fresh,
  unbound key after a refused re-enrolment, and the server refused its signature (DESIGN.md 63.10).
- `key_security` is written once, at first registration; re-registering never changes it.
- A new installation key deletes the local step-up key, so the new installation enrols its own.

## Step-up proof (version 2)

On a gated path the request carries two extra headers:

| Header | Value |
|---|---|
| `X-Step-Up-Proof` | base64url of the proof JSON below |
| `X-Step-Up-Signature` | base64url DER signature by the **step-up** key over those exact bytes |

```json
{"version": 2, "purpose": "stepup", "installation_id": "…",
 "access_token_sha256": "<sha256 hex of the bearer token>", "method": "POST",
 "path": "/v1/account/sensitive-echo", "query": "", "body_sha256": "<sha256 hex of the body sent>",
 "factor": "passcode", "nonce": "<the access proof's nonce>", "timestamp": 1790000000}
```

Version 2 (DESIGN.md 63, review F1) approves **one complete request**. Version 1 signed only the
installation, factor and nonce, so whoever held the installation signer could move a fresh approval
onto a different body under a re-signed access proof with the same nonce; the server now refuses it
with `403 stepup_proof_version_unsupported`. Every request field — nonce, token hash, method, path,
query, body hash — is compared with the request received; a difference is
`403 stepup_binding_mismatch` with `details.field` naming it. `path` and `query` are exactly what
the access proof signs, and `body_sha256` is over the same bytes.

The nonce is this request's access-proof nonce, so the access proof's replay store protects the
step-up proof too and there is no step-up challenge. The client freezes the body and nonce, **signs
the step-up proof first** (the user may take a while at the prompt), then builds the access proof with
that nonce, so the access proof's ±120 s window starts after the prompt. Both proofs are built from
one description of the request (`DeviceTrustClient.SendStepUpProtectedAsync`). `factor` must equal
the deployment's `stepup_factor` **and** the factor the key was registered with. On any authenticated
account request — not only gated ones — a valid step-up proof also satisfies an `elevated` integrity
verdict (`integrity.satisfied_by_step_up`); login, account registration and refresh accept none and
answer `403 integrity_elevated`.

Codes: `stepup_required`, `stepup_key_not_registered`, `stepup_key_not_independent`,
`stepup_signature_invalid`, `stepup_proof_version_unsupported`, `stepup_installation_mismatch`,
`stepup_binding_mismatch`, `stepup_factor_mismatch`, `stepup_timestamp_invalid`,
`stepup_timestamp_outside_window`, `stepup_key_other_account`.

## Step-up re-enrolment

`POST /v1/installations/stepup-key`, account token plus access proof, body:

```json
{"password": "…", "stepup_public_key": {…}, "stepup_key_auth": {…},
 "stepup_key_proof": "<base64url>", "stepup_key_signature": "<base64url DER>"}
```

`stepup_key_proof` is `{"version":1,"purpose":"stepup_reenrol","installation_id":…,
"stepup_key_thumbprint":<RFC 7638 of the new key>,"nonce":<access-proof nonce>,"timestamp":…}`,
signed by the **new** step-up key — the screen-lock prompt is the point. Wrong password:
`401 invalid_credentials`; a proof not by the named key or not bound to the request:
`403 stepup_reenrol_proof_invalid`. The re-enrolled key is scoped to the re-enrolling account;
another account on the same installation gets `403 stepup_key_other_account`. The client
re-registers afterwards so `Registration` shows the server's view.

## Dead step-up keys (DESIGN.md 57)

A step-up key that can never sign again is deleted by its store and reported as
`STEPUP_KEY_INVALIDATED`, saying whether removal worked; the client clears `StepUpKey` and the
installation must re-enrol. Android: `UnrecoverableKeyException` at `getEntry` (Android 9), an alias
that is no longer a key entry (`isKeyEntry` false; `getEntry` then throws a bare
`UnsupportedOperationException` — the OPPO after its lock was set again, DESIGN.md 63.8), no private
key under the alias, or `KeyPermanentlyInvalidatedException` at `initSign`; an existing key is checked
before the screen-lock requirement. iOS: a key present while `LAContext` reports
`passcodeNotSet`, or a signature failing with CryptoTokenKit -3.

## Cryptography

- **Installation key:** ECDSA P-256, ES256. Public key sent as a JWK with `kty`, `crv`, `alg`, `x`,
  `y`, the coordinates base64url with no padding.
- **Thumbprint:** RFC 7638, lowercase hex SHA-256 over
  `{"crv":"P-256","kty":"EC","x":"…","y":"…"}` — lexicographic member order, no whitespace, and
  `alg` excluded.
- **Signatures:** ECDSA-SHA256 in **ASN.1 DER**, everywhere, with no exception.
- **Hash:** SHA-256 throughout. Digests travel as lowercase hex, not base64url.
- **Encoding:** base64url with no padding for every binary value on the wire.

There is deliberately **no canonical JSON**. The server verifies the signature over the bytes it
received and parses them only afterwards, so each client signs and transmits its own serialisation.
Adding RFC 8785, or re-serialising server-side before verification, would break every SDK that does
not serialise exactly like the reference one.

## The access proof

Three headers on every protected call:

```
Authorization:      Bearer <access or device token>
X-Access-Proof:     base64url(utf8(proofJson))                     no padding
X-Access-Signature: base64url(DER ECDSA-SHA256 over those bytes)   no padding
```

The proof JSON (version 2, since 2026-10-04) has exactly these nine fields:

```json
{
  "access_token_sha256": "<hex sha256 of the bearer token string>",
  "body_sha256":         "<hex sha256 of the exact body bytes; the empty string for GET>",
  "installation_id":     "<this installation's id>",
  "method":              "<UPPERCASE HTTP method>",
  "nonce":               "<base64url of 32 random bytes, no padding>",
  "path":                "<request path without the query, e.g. /v1/account/me>",
  "query":               "<raw query string as sent, without '?'; \"\" when none>",
  "timestamp":           1757090000,
  "version":             2
}
```

`query` is new in version 2 (DESIGN.md 63.9). The server compares `path` with its decoded
`request.path`, which excludes the query, so version 1 left every query parameter outside the
signature. The query is taken from the `Uri` the request is actually sent to — after `Uri`'s own
escaping — so a space signs as `%20`, as it travels (`DeviceTrustApi.ResolveSignedTarget`). A
mismatch is `401 access_proof_query_mismatch`. A server at the default `ACCESS_PROOF_MIN_VERSION=2`
answers a version 1 proof with `400 unsupported_access_proof_version` (`details.minimum`); one in
transition (`=1`) still refuses a version 1 proof on any request carrying a query string.
`/health/ready` lists `access_proof_versions`.

`timestamp` and `version` are JSON **numbers**; a timestamp sent as a string is rejected with
`invalid_access_proof_timestamp`. Field order carries no meaning, because the signature is verified
before the JSON is parsed, but this SDK writes them in the order above so captured traffic is
directly comparable with the Dart client's.

`path` must match the server's `request.path`. When the service sits behind a proxy that does not
strip a path prefix, that prefix is part of `request.path`, so `DeviceTrustApi.ResolveSignedPath`
prepends the base URL's path component to the signed value.

The nonce is single-use and is committed by the server **only after the signature verifies**, so a
rejected request cannot burn a nonce and a captured proof replayed verbatim fails with
`access_proof_replay`.

## The integrity report

The report is signed by the installation key and submitted inside a proof-protected request:

```json
{
  "challenge_id":    "<from the challenge>",
  "challenge_nonce": "<echoed exactly>",
  "installation_id": "<this installation's id>",
  "platform":        "android",
  "collector_version": 1,
  "collected_at":    1757090000,
  "probe_results":   { "<probe name>": { "status": "ok", "…": "…" } },
  "version":         1
}
```

It travels as `{"report_payload": base64url(reportBytes), "report_signature": base64url(derSig)}`.

The client checks the collector's platform and nonce echo against the challenge **before** signing.
A collector that answered a different challenge would otherwise produce a correctly signed report
the server has to reject, which is a much harder failure to read.

Every probe the server listed in `required_probes` must be present. An omitted probe is rejected
outright with `integrity_probe_missing`; a present probe whose `status` is not `ok` costs 30 points
each. Reporting `error` honestly is therefore correct behaviour — an unreadable measurement is not
a clean one.

## Error envelope

```json
{"error": {"code": "access_proof_replay", "message": "…", "details": {}}}
```

Nested, never flat. `DeviceTrustApiException.Code` is read from `error.code`, and `Details` carries
`error.details`, which on a policy or integrity rejection contains the decision that caused it.

Codes this SDK's tests assert against:

`api_base_url_missing` · `installation_not_found` · `installation_id_collision` ·
`registration_race_retry` · `invalid_installation_signature` · `access_proof_replay` ·
`access_proof_body_mismatch` · `access_proof_path_mismatch` · `access_proof_method_mismatch` ·
`access_proof_timestamp_outside_window` · `access_proof_installation_mismatch` ·
`refresh_token_reuse` · `refresh_session_revoked` · `integrity_blocked` ·
`integrity_device_blocked_recently` · `unsupported_platform`

## Identity edge cases the client must handle

- **The server returns a different `installation_id` than the one submitted.** That means it already
  knew this public key. Adopt the returned id; the thumbprint is the identity.
- **`registration_race_retry`.** Two installations raced on the same reinstall hint. The server
  rolled its transaction back and expects exactly one retry.
- **A stored UUID with a newly created key.** The keystore entry was lost while local state
  survived. Mint a *new* UUID: presenting the old one with a new public key is the collision the
  server refuses with `installation_id_collision`, and the reinstall hint is what correlates the
  fresh installation back to the same device.
