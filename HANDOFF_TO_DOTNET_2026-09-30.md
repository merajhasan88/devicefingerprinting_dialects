# Handoff to the .NET SDK session — 2026-09-30

From the reference session (Flutter client + `device_trust_server.py`). The authoritative record is
`DESIGN.md` §63 in `devicefingerprinting_dialects`. An external review (2026-09-29) found defects in the
server's step-up binding and evidence handling; they are fixed, and **one fix breaks your step-up path**.
Nothing in your repository was changed — whether and how this file reaches it is the owner's call.

## 1. Must change: step-up proof v2 (your step-up calls are refused until you do)

Your `DeviceTrustClient.BuildStepUpProof` sends v1 `{version:1, installation_id, factor, nonce,
timestamp}`. The server now answers **403 `stepup_proof_version_unsupported`** to that. Reason: v1 did
not sign the request, so whoever held the installation signer could attach a fresh approval to a
different body under a re-signed access proof with the same nonce (reproduced by the review).

v2, signed by the step-up key exactly as before (base64url JSON in `X-Step-Up-Proof`, base64url DER in
`X-Step-Up-Signature`):

```json
{
  "version": 2,
  "purpose": "stepup",
  "installation_id": "<canonical installation id>",
  "access_token_sha256": "<sha256 hex of the bearer token string>",
  "method": "POST",
  "path": "/v1/account/sensitive-echo",
  "query": "",
  "body_sha256": "<sha256 hex of the exact body bytes you will send>",
  "factor": "passcode",
  "nonce": "<the access proof's nonce>",
  "timestamp": 1790000000
}
```

- `method` upper-case; `path` exactly as sent; `query` the raw query string without `?` (`""` when
  none); `body_sha256` over the **same bytes** the access proof hashes. Each is compared with the real
  request — a mismatch is **403 `stepup_binding_mismatch`** with `details.field` naming it.
- Order unchanged: freeze body and nonce, sign the step-up proof (the prompt), then sign the access
  proof with that nonce.
- The factor must now match **both** the policy and the factor the key was **registered** with
  (`stepup_key_auth.factor`), else **403 `stepup_factor_mismatch`**.
- Re-enrolment's `stepup_reenrol` proof (version 1) is **unchanged**.

Your harness checks (`StepUpConformanceChecks.cs`) should add the review's attacks, as the reference
suite now does: an approval signed for body A sent with body B → `stepup_binding_mismatch`; the same
with another path; a v1 proof → `stepup_proof_version_unsupported`; a key registered with the other
factor → `stepup_factor_mismatch`.

## 2. Also changed at registration

- `stepup_key_auth` is **required** whenever `stepup_public_key` is sent (400 `invalid_stepup_key_auth`).
- The step-up key must differ from the installation key (400 `invalid_stepup_key`).
- Re-registering a known key no longer changes stored `key_security` (it is written once, at first
  registration); a different claim is ignored, a weaker one still comes back as `downgrade_reported`.

## 3. Integrity reports — checked against your stored reports, no action expected

- A requested probe that answers `ok` without its required fields scores like a failed probe (+30),
  and a known field with the wrong JSON type is **400 `invalid_integrity_probe`**. Your 11 Android and
  16 iOS reports on the test server all carry every required field.
- `collector_version` must be 1…1000 (you send 2).
- Code-integrity differences count from **1 byte** (was ≥ 4).
- The W^X baseline allowance now requires the shape to add up (classes cover every mapping and byte).
  All 11 of your stored reports carrying `wx_bytes` do.
- New optional coverage fields (`<bucket>_expected_bytes`, `_skipped_bytes`, `_unreadable_bytes`,
  `_complete`, `protect_restore_failures`) are what the Kotlin/NDK scanner now reports. You need not
  send them; if you do, they must add up (expected = compared + skipped + unreadable).
- With `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1` (as on the test stack) iOS `code_integrity` is a
  requested probe; your iOS collector already sends it.

## 4. Server behaviour you may see

- `/health/ready` answers **503 `not_ready`** (with `problems`) when the database, schema, policy
  snapshot or Redis nonce store is unavailable; 200 otherwise.
- Oversized bodies (> 256 KiB) are 413; an unreadable policy table is 503 `risk_policy_unavailable`.
- The shared stack runs Caddy → gunicorn with `TRUSTED_PROXY_COUNT=1`; nothing changes for a client.

## 5. The shared test stack

EC2 `i-0559685f02c4013b1`, PostgreSQL 16.15, schema 7, observe/observe. Ask the owner before starting
it. The reference suite now has 55 checks; `tools/check_security_regressions.py` is the offline gate for
server changes.
