# Handoff from the Flutter / server session — 2026-09-29

From the reference session (Flutter client + `device_trust_server.py`). The authoritative record is
`DESIGN.md` in `devicefingerprinting_dialects` `main` (at or after `7deb342`); **your copy stops at
§33, ours is at §61**. Everything below is traceable to a section there. Nothing else in this
repository was changed; this file is uncommitted so you decide how it enters your history.

---

## 1. Where you are (read from this repository, not changed)

- Branch `dotnet`, last commits `9d3a992` (2026-09-23, W^X baseline keyed on the APK hash) and
  `b99bff3` (2026-09-20, end-of-day state). Working tree clean.
- Handset battery 15/16 on hardware; your conformance harness 24/24 in enforce mode
  (`docs/validation.md`, `docs/session-state-2026-09-20.md`).
- Wire contract (`docs/protocol.md`): register → challenge/verify → integrity challenge/report →
  accounts → protected calls → refresh. **Not implemented** (grep of `src/` and `tests/`): the
  `key_security` block, the step-up key, step-up proofs, step-up re-enrolment.
- Your notes describe the shared server as `INTEGRITY_MODE=enforce`. **That is out of date** — see §3.

## 2. What changed on the server since your last session

| Change | DESIGN.md | Impact on a client |
|---|---|---|
| `risk_policy_settings`: DBA-owned policy table, seeded by migrations | §51.7, §52, §54 | none directly; every policy value is now a DBA-tunable default |
| Behavioural signals: per-key request rate, population baseline | §51.6, §52 | none — server-side, advisory, **off** by default |
| Hardware-backing policy `INTEGRITY_HARDWARE_BACKING_POLICY` (off / advisory / required) | §50 | acts only on an explicit `hardware_backed: false`; you send no `key_security`, so it never acts on you — and never helps you either |
| **Step-up key** (optional second key, user-auth gated) | §51–§53 | new, optional — see §4 |
| **Dead step-up keys** after a screen-lock change | §57 | client behaviour to mirror |
| **Step-up re-enrolment** `POST /v1/installations/stepup-key` | §58 | new endpoint |
| Accounts per device: 2 = elevated (never refused by default), 3 = review, **4 = block** (was 5) | §54 | the elevated band **no longer refuses** by default, so `risk_step_up_required` is not returned unless a DBA sets `elevated_risk_refuses=1`; adjust any test that expects it, or a block only at 5 |
| SQL Server crashed/deadlocked under concurrent requests (ODBC stack not thread-safe) | §55 | none for the client; it is why the reference suite now has a concurrency check |
| Serving model: gunicorn ×4 worker processes + per-process connection pool | §60 | faster, same contract; measured ~200 req/s on PostgreSQL, 53–64 req/s on SQL Server 2019/2022 at 64 clients |
| RDS maintenance (`DBCC CHECKDB`) starves db.t3.micro SQL Server Express → 15 s query timeouts | §60 | explains intermittent `500 internal_error` on tiny SQL Server instances; not a client issue |
| Schema **7** (migrations 003–007) | §52–§58 | none, unless you run your own database |

New error codes you may now see (envelope unchanged, read `error.code`): `stepup_required`,
`stepup_key_not_registered`, `stepup_signature_invalid`, `stepup_installation_mismatch`,
`stepup_binding_mismatch`, `stepup_factor_mismatch`, `stepup_timestamp_invalid`,
`stepup_timestamp_outside_window`, `stepup_key_other_account`, `invalid_stepup_key`,
`invalid_stepup_key_auth`, `stepup_reenrol_proof_invalid`, and `invalid_credentials` (401) from
re-enrolment.

## 3. The shared test stack now

- EC2 `i-0559685f02c4013b1` is **stopped**; its public IP changes on every start and DuckDNS follows.
  The stack belongs to the Flutter session; ask the owner before starting it. No RDS is running.
- PostgreSQL 16.15, schema 7, **`INTEGRITY_MODE=observe`, `DEVICE_POLICY_MODE=observe`**, every
  `risk_policy_settings` row at its default (step-up gate empty, signals off).
- To exercise step-up, a DBA-style change on the server:
  `UPDATE risk_policy_settings SET setting_value='/v1/account/sensitive-echo' WHERE setting_key='stepup_required_paths';`
  then restart the service (the settings cache has a short TTL). Put it back to `''` afterwards.
- The OPPO **device** now has four linked accounts on this database, so account-risk decisions for it
  read `block` (observe mode hides it). Expect that in policy responses from the OPPO.
- Handsets: the **OPPO has a screen-lock PIN** and the **iPhone has a passcode** set again (both were
  removed and restored in §57). Your harness is a separate app (`com.example.devicefingerprinting_dotnet`),
  so its keys are unaffected; the passcode matters only once you implement step-up.
- The reference suite now has **53 checks**; `check_parallel_clients` must pass on any new backend
  before handset time is spent on it (the §55 lesson).

## 4. What to build to catch up, in order

1. **Refresh your `DESIGN.md` copy** from ours and read §50–§61.
2. **Report `key_security`** at registration (recommended, small): `{"security_level", "hardware_backed",
   "provider"}` from what your key stores already know. Absent means "not reported", never "software".
3. **Step-up key** (§53) on MAUI Android and Apple. Optional feature: no screen lock → no step-up key,
   never a failed enrolment.
   - *Android*: API 30+ → `setUserAuthenticationParameters(0, AUTH_DEVICE_CREDENTIAL)` (or
     `AUTH_BIOMETRIC_STRONG`) and a `BiometricPrompt` + `CryptoObject` per signature (per-use).
     API < 30 with a passcode → `setUserAuthenticationValidityDurationSeconds(30)` and the
     confirm-credential screen before **every** signature. Read factor / mode / window **back from
     `KeyInfo`** and report what the keystore enforces, not what you asked for.
   - *Apple*: Secure Enclave, `[.privateKeyUsage, .devicePasscode]` (or `.biometryCurrentSet`),
     `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, a **fresh `LAContext` per signature**
     (per-use only; no windowed mode on iOS).
   - *Register* (same `POST /v1/installations/register`): add
     `"stepup_public_key": {JWK, ES256}` and `"stepup_key_auth": {"factor": "passcode"|"biometric",
     "mode": "per_use"|"windowed", "window_seconds": 0|N}`. A step-up key binds **only when the
     installation key is new**; re-registration never attaches or replaces one and instead returns
     `stepup_key_registered`, `stepup_key_matches`, `stepup_key_auth`, `stepup_policy_downgrade`.
   - *Sensitive call*: headers `X-Step-Up-Proof` = base64url of
     `{"version":1,"installation_id":…,"factor":…,"nonce":<the access proof's nonce>,"timestamp":<unix s>}`
     and `X-Step-Up-Signature` = base64url DER signature by the step-up key over those bytes. Generate
     the nonce first, **sign the step-up proof before the access proof** (the prompt can take a while;
     the access proof's ±120 s window should start after it), then build the access proof with that
     nonce. Demo endpoint: `POST /v1/account/sensitive-echo` (`step_up: verified | not_required`).
   - *UI/API rule*: offer the step-up action only when the server says the key is registered and
     `stepup_key_matches != false`.
4. **Dead keys** (§57) — found on hardware, mirror them:
   - Android 9: after the lock is removed the alias survives but `getEntry` throws
     `UnrecoverableKeyException`; newer keystores throw `KeyPermanentlyInvalidatedException` at
     `initSign`. Treat both (and an alias with no private key) as dead: delete, report
     `STEPUP_KEY_INVALIDATED`. Check an existing key **before** the lock-screen requirement. Android 9
     would not delete the alias while the lock was off — report whether removal worked.
   - iOS 15.8.5: removing the passcode did **not** delete the key; its public key stayed readable and
     every signature failed with **CryptoTokenKit error -3**, even after the passcode was set again.
     Dead if a key exists while `canEvaluatePolicy(.deviceOwnerAuthentication)` fails with
     `LAError.passcodeNotSet`, or if signing fails with CryptoTokenKit -3.
5. **Re-enrolment** (§58): `POST /v1/installations/stepup-key` with account token + access proof and
   body `{"password", "stepup_public_key", "stepup_key_auth", "stepup_key_proof", "stepup_key_signature"}`,
   where `stepup_key_proof` = base64url of
   `{"version":1,"purpose":"stepup_reenrol","installation_id":…,"stepup_key_thumbprint":<RFC 7638 SHA-256 hex of {crv,kty,x,y}>,"nonce":<access-proof nonce>,"timestamp":…}`
   signed by the **new** step-up key (the passcode prompt is the point). Errors: `401 invalid_credentials`,
   `403 stepup_reenrol_proof_invalid`. A re-enrolled key is **scoped to the re-enrolling account**;
   another account on the device gets `403 stepup_key_other_account`.
6. **Conformance parity**: the reference suite's new checks are `check_stepup_key_registration`,
   `check_stepup_key_immutable`, `check_step_up`, `check_stepup_reenrol` (including the second-account
   attack), `check_device_account_bands` and `check_parallel_clients`.
7. **Hardware battery for step-up** on the OPPO and the iPhone, as the reference did (§53.4, §57, §58).

Reference implementations to read: `android/…/StepUpKeyManager.kt`, `ios/Runner/InstallationKeyManager.swift`
(`StepUpKeyManager`), `lib/device_trust_client.dart` (`NativeStepUpKey`, `sensitiveEcho`,
`reenrolStepUpKey`), `device_trust_server.py` (`_verify_step_up`, `reenrol_stepup_key`) and
`conformance_suite.py` (`stepup_call`, `check_stepup_reenrol`).

## 5. Baseline-relative W^X scoring — now implemented (reference `2427e11`, DESIGN.md §62)

As you asked: `INTEGRITY_ANDROID_WX_BASELINES=<apk_sha256>:<bytes>:<granularity>` (comma-separated),
keyed on the APK hash. For a pinned build: at or under the baseline with every size a multiple of the
granularity scores **0**; a size that is not a multiple (checked across `wx_size_classes`,
`wx_smallest_bytes`, `wx_largest_bytes`) scores `android_wx_foreign_allocator` **+45**; above the baseline
`android_wx_above_baseline` **+15**, beyond twice it `android_wx_far_above_baseline` **+40**. Today's
`android_wx_memory` **+60** is kept for any build without an entry, a zero baseline, and **any report
without `wx_bytes`** or its size classes — your warning section, verbatim. A malformed entry stops the
server at start-up; `/health/ready.scoring_flags.android_wx_baselines` shows how many builds are pinned.

Validated: an offline test of the rule, a new `check_wx_baseline`, the existing no-`wx_bytes` check still
passing, the full reference suite 49/0/5, and the OPPO's Flutter scan unchanged at 18/trusted.

**What you need to do:** the shared server pins only the synthetic conformance APK so far. Append your
build's entry — the one your `baseline` command prints — to the `INTEGRITY_ANDROID_WX_BASELINES=` line in
`/etc/devicetrust.env` on the EC2 host (comma-separated, keep the existing entry), restart `devicetrust`,
and your clean OPPO scan should drop from 78/review to trusted. Remember a new APK needs a new entry.
