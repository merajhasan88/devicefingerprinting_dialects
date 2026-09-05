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
