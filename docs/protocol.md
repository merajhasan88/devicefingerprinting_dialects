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

Lifetimes: access 10 minutes, device 10 minutes, refresh 30 days, challenge 2 minutes, access-proof
skew ±120 seconds, integrity report skew ±90 seconds, integrity freshness 600 seconds.

Only `android` and `ios` are accepted platforms. The client registers under the platform its
integrity collector can actually measure, which is why `DeviceTrustClient.Platform` defaults to
`IIntegrityProbeCollector.Platform` rather than to a constant.

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

The proof JSON has exactly these eight fields:

```json
{
  "access_token_sha256": "<hex sha256 of the bearer token string>",
  "body_sha256":         "<hex sha256 of the exact body bytes; the empty string for GET>",
  "installation_id":     "<this installation's id>",
  "method":              "<UPPERCASE HTTP method>",
  "nonce":               "<base64url of 32 random bytes, no padding>",
  "path":                "<request path, e.g. /v1/account/me>",
  "timestamp":           1757090000,
  "version":             1
}
```

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
