# Device Trust .NET/C# client SDK — handoff brief for a fresh session

Give this file to a new Claude Code session. It is a self-contained spec for building a
.NET/C# client SDK that mirrors the Flutter client (`lib/device_trust_client.dart`) and talks to the
**same** server (`device_trust_server.py`) — the one already running on AWS EC2 + RDS. Read it
alongside `DESIGN.md` (the full validation history) and `lib/device_trust_client.dart` (the reference
implementation) in this repository.

## 0. Scope — what to build and what NOT to build

- **Build:** a .NET/C# **client SDK** plus a small console/MAUI test harness that exercises the same
  flows the Flutter app does. Payactiv's app is .NET, so this SDK is what their app would embed.
- **Do NOT build a second server.** The server is `device_trust_server.py`; .NET is a client only.
  The SDK points at the existing HTTPS endpoint via config, exactly as the Flutter app uses
  `--dart-define=API_BASE_URL`.
- Target framework: .NET 8/9 (Payactiv uses .NET releases of the last ~3 years). For device-bound
  keys on mobile, **.NET MAUI** (Android + iOS) is the natural fit; a Windows/console build is fine
  for protocol testing against RDS but cannot provide a hardware-backed key (see §5).

## 1. How to start the forked session (mechanics)

Do not literally clone this conversation — it is enormous and unfocused. Instead:

1. Create a new repo/dir for the SDK, e.g. `devicetrust-dotnet-sdk` (clone-with-history is not
   needed; this is new code). Keep professional, descriptive names, matching this repo's convention.
2. Copy this brief and `DESIGN.md` into it (or reference this repo path).
3. In a new terminal: `cd` into the new dir and run `claude`. Paste: "Read DOTNET_SDK_BRIEF.md and
   DESIGN.md, then build the .NET client SDK it describes." That session starts fresh with only the
   curated context — cheaper and sharper than resuming this one.
4. `claude --resume` / `--continue` would carry THIS session's full history; avoid that here, it is
   the opposite of a clean fork.
5. The in-tool `fork` subagent runs work *in the current session*, which is not what you want — it
   would build the .NET app here.

## 2. Protocol contract (endpoints, in call order)

Base URL from config (e.g. `appsettings.json` / env `API_BASE_URL`). All bodies are JSON; all
protected calls carry the three headers in §4.

1. `POST /v1/installations/register` — send the P-256 public JWK; the server's authoritative identity
   is the **key thumbprint**, not any client UUID.
2. `POST /v1/installations/challenge` -> `POST /v1/installations/verify` — sign the challenge with the
   native key to obtain a **device token** (`role:"device"`, 10 min).
3. `POST /v1/accounts/register` | `/v1/accounts/login` — issue **account** access + refresh tokens
   bound to `did`/`iid`.
4. `GET /v1/account/me`, `POST /v1/account/protected-echo`, `GET /v1/device/me`, `GET /v1/policy/me`.
5. `POST /v1/auth/refresh/challenge` -> `POST /v1/auth/refresh` — rotate the refresh token; reuse of a
   rotated token revokes the whole family.
6. `POST /v1/integrity/challenge` -> `POST /v1/integrity/report` — see §6.

Lifetimes: access 10 min, device 10 min, refresh 30 days, challenge 2 min, proof skew ±120 s.

## 3. Cryptography (this is where a naive .NET port fails)

- Installation key: **ECDSA P-256 (ES256)**. Public key sent as a JWK (`kty:"EC"`, `crv:"P-256"`,
  `alg:"ES256"`, `x`, `y` as base64url).
- **Signatures MUST be ASN.1 DER (`DSASignatureFormat.Rfc3279DerSequence`).** .NET's default
  `ECDsa.SignData` emits IEEE-P1363 fixed-width `r||s`, which the server (PyCryptodome, DER) will
  reject. Use the `DSASignatureFormat` overloads:
  `ecdsa.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)`.
- Hash is SHA-256 throughout.
- The server verifies over the **exact bytes the client signed**, so there is **no need for
  canonical JSON (no RFC 8785)** across languages. Each client signs and transmits its own bytes.

## 4. Access proof-of-possession (per protected request)

Three headers on every protected call:
- `Authorization: Bearer <access token>`
- `X-Access-Proof: base64url(utf8(proofJson))`  — no padding
- `X-Access-Signature: base64url(DER ECDSA-SHA256 over the utf8 proof bytes)` — no padding

The proof JSON has exactly these fields (values shown; the Dart reference uses this key order, but
order does not matter across languages because the server verifies the signature over the received
proof bytes and only then parses):

```json
{
  "access_token_sha256": "<hex sha256 of the bearer token string>",
  "body_sha256": "<hex sha256 of the exact request body bytes; empty string for GET>",
  "installation_id": "<this installation's id>",
  "method": "<UPPERCASE HTTP method>",
  "nonce": "<base64url(32 random bytes), no padding>",
  "path": "<request path, e.g. /v1/account/me>",
  "timestamp": <unix seconds>,
  "version": 1
}
```

Critical: **sign the raw utf8 proof bytes** (the base64url-decoded value of `X-Access-Proof`), DER
signature. The body hash must be over the byte-identical body actually sent. GET bodies hash the
empty string. Rebuild the nonce and timestamp per request; the nonce is single-use (replay ->
`access_proof_replay`).

Server rejection codes to test against: `invalid_installation_signature` (wrong key),
`access_proof_replay`, `access_proof_body_mismatch`, `access_proof_path_mismatch`,
`access_proof_method_mismatch`, `access_proof_timestamp_outside_window`.

## 5. Device-bound key storage (platform-specific, mirrors the two MethodChannels)

The Flutter app uses AndroidKeyStore (StrongBox attempted, graceful fallback) and iOS Secure
Enclave; the private key never leaves the OS keystore, only the JWK and DER signatures cross the
boundary. The .NET SDK needs the same non-exportability per platform:
- **MAUI Android:** call AndroidKeyStore via the Android API (`KeyPairGenerator` with
  `KeyProperties`, `setIsStrongBoxBacked` where available). This is the direct analogue of the
  Kotlin `InstallationKeyManager`.
- **MAUI iOS:** Secure Enclave via `SecKeyCreateRandomKey` with a key stored in the keychain.
- **Windows/console:** CNG/DPAPI or TPM via `CngKey` (`CngKeyCreationOptions`, machine/user key
  store). Note honestly: a desktop key is not equivalent to a mobile hardware-backed key; use the
  console build for protocol testing only, not as a security claim.

Design the SDK with an `IInstallationKeyStore` abstraction (getOrCreateKey -> JWK, sign(bytes) ->
DER, deleteKey) so each platform plugs in behind it, mirroring the `installation_key_v2` channel.

## 6. Integrity (platform-specific; do not fake it)

The server randomly selects probes, the client runs them, the installation key signs the **complete
report**, and the server scores the raw measurements — **the client never sends a score.** The
Android probe set is Kotlin (`IntegrityProbeManager`), including the structural hook detection added
this session (thread names, w^x memory, and a native `code_integrity` that diffs libc/libart .text
in memory vs disk). A .NET port must supply platform-appropriate probes:
- MAUI Android: the same measurements are available via Android APIs / a small native lib.
- Windows: entirely different signals (Authenticode of loaded modules, debugger present, known
  hooking DLLs, etc.). Treat Windows integrity as its own design, not a copy of the Android probes.

For a first milestone it is acceptable to implement the identity + possession + access-proof + refresh
flows and send a minimal honest integrity report, running the server in `INTEGRITY_MODE=observe`, then
add real probes. Do not invent probe results to pass the gate.

## 7. Error envelope

All errors are nested: `{"error": {"code": "...", "message": "...", "details": {...}}}`. Parse
`error.code` for control flow (not a flat `code`).

## 8. Config

Mirror `--dart-define=API_BASE_URL`. Read the base URL from `appsettings.json` or an env var; no
hard-coded default (the Dart client fails loudly with `api_base_url_missing` when unset — do the
same). For stolen-token boundary tests, allow injecting a foreign access/refresh token via config,
the way the Flutter app takes `--dart-define=STOLEN_ACCESS_TOKEN`.

## 9. Test plan (mirror what was validated here)

- **Conformance:** port or reuse `conformance_suite.py`'s assertions. Better: point the existing
  Python `conformance_suite.py` at the same server — it is client-agnostic and already proves the
  server side. The .NET-specific need is a harness proving the .NET *client* produces proofs the
  server accepts and that its boundary cases are rejected with the right codes.
- **Handset battery (per §25.11 of DESIGN.md):** clean baseline; account through the enforce gate;
  stolen access token (fails `invalid_installation_signature` after reaching proof verification);
  stolen refresh token (challenge 200 then refresh 401); the four access-proof boundary tests within
  10 minutes of a refresh; and, where a real device permits, a compromise test.
- Run against the same AWS RDS-backed server already stood up (PostgreSQL and SQL Server both pass).

## 10. Reference files in this repo

- `lib/device_trust_client.dart` — the client to mirror (esp. `buildAccessProofFixture`,
  challenge/verify, refresh).
- `device_trust_server.py` — the server; `_require_access_proof` is the authority on proof fields.
- `conformance_suite.py` — the assertions to reproduce.
- `DESIGN.md` — every property already validated and why each rule is shaped the way it is.
- `android/app/src/main/kotlin/.../InstallationKeyManager.kt` and `IntegrityProbeManager.kt` — the
  native key and probe implementations the .NET side must find platform analogues for.

---

# UPDATE — 2026-09-06

Everything above still holds. This section records what changed in the reference implementation
**after** this brief was written, limited to what actually changes decisions on the .NET side.
`DESIGN.md` in this repository has been refreshed to match; it now runs through §33.

## 1. Extended code-integrity scoring is ON by default (was off)

When this SDK was started, `INTEGRITY_SCORE_EXTENDED_LIBS` defaulted to `0`: the `code_integrity`
probe's **ext** and **app** buckets were collected but not scored. Both handsets have since been
baselined clean and the default is now **`1`** (§30.2).

**What this changes for you:** the bucket fields your Android collector already emits are now
load-bearing. `ext_diff_bytes >= 4` raises `android_code_integrity_violation` +90 and
`app_diff_bytes >= 4` raises `android_app_code_modified` +90 — both block on their own. A collector
that over-reports a diff will now **block real users**, where before it was merely noisy.

Follow the same discipline the reference implementation used, and do not skip it: ship the buckets
**report-only first**, capture the values on a real clean device, confirm every bucket has a
**non-zero `compared_bytes` and a zero `diff_bytes`**, and only then let them score. A
`compared_bytes` of **zero means the bucket is inert, not clean** — that exact defect shipped once
and was caught only by looking at the raw numbers (§28.8, §30.1).

## 2. .NET can do the in-memory comparison without a native component

The reference collector needed an **NDK/C component** for `code_integrity`, because Kotlin cannot
dereference an arbitrary address and SELinux blocks `untrusted_app` from opening `/proc/self/mem`
(§28.6).

.NET does not have that problem. `/proc/self/maps` is an ordinary file read, and
`Marshal.Copy(IntPtr, byte[], int, int)` reads the process's own mapped pages directly — no JNI, no
native library. If you implement `code_integrity` for MAUI Android, you can do it in pure C#.

Two implementation details that cost the reference version real debugging time:

- **Iterate every executable VMA of a target library, not just the first.** An inline hooker flips
  individual code pages writable to patch them, which splits the library's single `r-x` mapping into
  several, and the patched page is usually *not* the first. An early single-VMA version compared
  114 KB of libc and reported `diff_bytes: 0` against a live hook — a false negative.
- **Exclude the ART JIT code cache.** It legitimately presents as executable and `(deleted)`
  (`/memfd:/jit-cache`, `/dev/ashmem/dalvik-jit-code-cache`). Without that exclusion every clean
  device is a false positive.

## 3. Name-based hook detection is defeatable — proven, not theorised

`runtime_maps`-style token scanning matches on the *name* of a mapped file. A real Frida Gadget
renamed to `libhelper.so` and moved off port 27042 scored **`18/trusted`** while fully active
(§27.11). Renaming a file is free for an attacker who is already repackaging your app.

If your collector's hook detection is name-based, describe it as such. The structural answers that
actually work are in §28: instrumentation-runtime **thread names** (`gum-js-loop`, `pool-frida` —
compiled into the framework, so a rename does not touch them), **writable-and-executable** memory,
and the in-memory-versus-on-disk code comparison above.

## 4. The battery is now 15 items, and items 12/13 differ by platform

`§25.11` has been rewritten as the canonical list — your `CLAUDE.md` already points readers there,
so re-read it rather than relying on the four-group version this brief originally described.

The part that matters for a cross-platform SDK: **iOS keychain items survive app uninstall; Android
Keystore entries do not.** On Android, uninstall destroys the key so a reinstall necessarily enrols
a new one. On iOS the same key comes back, so a reinstall proves nothing about re-enrolment.

- Items **12** and **13** therefore use uninstall on Android and an explicit **`DeleteKey`** on iOS.
- New item **15**, iOS only: uninstall and reinstall *without* deleting the key must return
  `created: false`, the **same** key thumbprint and the same `installation_id`.

Your `IInstallationKeyStore` needs a delete that genuinely destroys the key material on every
platform, because on iOS that is the only way to simulate a fresh installation.

## 5. An iOS reference implementation now exists — mirror it

`ios/Runner/InstallationKeyManager.swift` and `ios/Runner/IntegrityProbeManager.swift` in the
reference repository are the Secure Enclave key store and the iOS probe collector (§32, §33). For
MAUI iOS the same Security-framework calls are available through the .NET bindings.

Two details worth copying rather than rediscovering:

- Sign with the equivalent of `ecdsaSignatureMessageX962SHA256`, which yields **X9.62/DER** —
  the same requirement that makes `DSASignatureFormat.Rfc3279DerSequence` mandatory in .NET.
- Attempt the Secure Enclave first and fall back to a software keychain key, then report the truth
  through `security_level` / `hardware_backed`. The Simulator has no Secure Enclave, and a fallback
  that lies about its own strength is worse than one that admits it.

The exact iOS probe field contract the server reads is tabulated in §33.1. iOS hook detection there
is currently **name-based only** and is documented as not yet equivalent to the Android collector —
do not assume parity.

## 6. `collector_version` is per-platform

Android is at **2** (baseline probes plus `instrumentation_threads`, `exec_mappings`,
`code_integrity`); iOS is at **1** (its baseline set). Every stored report carries the value, so a
report says which probe set produced it. Version your own collectors the same way — §29.2 exists
because every database battery in the project ran on Android collector v1 and that had to be
stamped after the fact so the results were not misread later.

## 7. A blocked device now returns 403 regardless of the password

`account_login` used to check credentials **before** the integrity gate, so a blocked device
answered `401 invalid_credentials` for a wrong password and `403 integrity_blocked` for a correct
one — a credential oracle on exactly the device class the gate exists to distrust. The gate now runs
first and both cases return `403` (§27.5.1).

If your harness asserts on login failures for a blocked device, expect **403**, not 401. Note also
that input-shape validation still precedes the gate, so a malformed request can return `400` —
that is not the same leak, because it says nothing about whether an account or password exists.

## 8. Test infrastructure state

The AWS test stack is **down**: the RDS instance is deleted and the EC2 instance is stopped, with no
Elastic IP. On restart it receives a **new public IP**, so the Caddy site block and any hard-coded
`API_BASE_URL` must be updated each time. Do not bake an endpoint into the SDK or its tests — read
it from configuration, exactly as the Flutter client takes `--dart-define=API_BASE_URL` and fails
loudly with `api_base_url_missing` when it is unset.

The Python conformance suite now carries **30 checks** and is client-agnostic — pointing it at the
same server is still the cheapest way to prove the *server* side, leaving your harness to prove that
the *.NET client* produces proofs the server accepts.
