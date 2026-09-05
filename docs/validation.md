# Validation record

Every result below was produced by running this SDK, on this machine, against the live deployment.
Nothing here is projected or assumed. Where something could not be tested it is listed under
[Not covered](#not-covered) rather than omitted.

Date: 2026-09-05.

## Target

```
Endpoint      https://54-203-12-110.nip.io   (AWS EC2, Caddy, Let's Encrypt)
Database      SQL Server 2025, 17.0.4065.4   (RDS; minimum supported 2017)
Integrity     INTEGRITY_MODE=enforce
Nonces        Redis, AOF persistence on
Rate limiting on
Client        DeviceTrust.Client (.NET) on Linux x64, .NET 9.0.19 runtime
```

The server was in **enforce** mode throughout, so every account operation had to pass the integrity
gate with a fresh signed report. That is the harder configuration; the Python suite's own README
expects observe mode.

## 1. Reference suite, for comparison

The Python `conformance_suite.py` from the reference repository was run first against the same
endpoint, to establish that the server was healthy before any .NET result was attributed to the
server:

```
30 passed, 0 failed, 0 skipped
```

## 2. Offline unit tests

```
$ dotnet test
Passed! - Failed: 0, Passed: 54, Skipped: 0, Total: 54  (net6.0)
Passed! - Failed: 0, Passed: 54, Skipped: 0, Total: 54  (net8.0)
```

Run against **both** target frameworks. That is what makes the ".NET 6 and onwards" claim a tested
property rather than a statement of intent.

Coverage: DER-versus-P-1363 signature encoding, base64url without padding, the RFC 7638 thumbprint
against an independently computed vector, the eight access-proof fields and their JSON types, the
empty-body hash, nonce length and uniqueness, the nested error envelope, `api_base_url_missing`,
reinstall-hint normalisation and domain separation, probe JSON typing, and the key-store contract.

## 3. .NET client conformance suite

```
$ dotnet run --project src/DeviceTrust.Cli -- conformance
PASS config: a client with no endpoint fails api_base_url_missing
PASS crypto: the client signs ASN.1 DER, not IEEE P-1363
PASS identity: a new key enrols as a new installation
PASS identity: the client's RFC 7638 thumbprint matches the server's
PASS identity: the key thumbprint, not the UUID, is authoritative
PASS possession: a signed challenge yields a device token
PASS integrity: a pristine fixture scores zero and is trusted
PASS integrity: Frida mapped into the process blocks
PASS integrity: a renamed gadget is still caught by its runtime thread
PASS integrity: a probe that fails to run is penalised
PASS account: a device token opens an account
PASS access proof: a correctly signed request is accepted
PASS access proof: an exact replay is rejected
PASS access proof: a tampered body is rejected
PASS access proof: a tampered path is rejected
PASS access proof: a tampered method is rejected
PASS access proof: a stale timestamp is rejected
PASS access proof: a proof signed by another installation is rejected
PASS errors: the nested error envelope is parsed
PASS refresh: rotation issues a new family member
PASS refresh: a stolen refresh token fails at the signature, not the token
PASS refresh: reusing a rotated token revokes the family
PASS enforcement: a blocked device cannot reach protected endpoints
PASS enforcement: reinstalling does not clear a blocked device

24 passed, 0 failed, 0 skipped
```

What each group establishes:

- **crypto** — the client's signatures are ASN.1 DER. This is the check that would have caught a
  naive port on its first run instead of after a day of debugging `invalid_installation_signature`.
- **identity** — the client computes the same RFC 7638 thumbprint the server does, and the server
  treats that thumbprint, not the client UUID, as the identity.
- **integrity** — a pristine report scores 0/trusted; a Frida artefact blocks; a *renamed* gadget
  still blocks on the structural thread signal alone, which is the permanent regression test for the
  evasion in DESIGN.md 27.11; a failed probe is penalised.
- **access proof** — the happy path, then each boundary case with its exact server code.
- **errors** — the code is read from the nested `error.code`, not a flat one.
- **refresh** — rotation works, a stolen refresh token fails at the *signature* (not at the token),
  and reusing a rotated token revokes the family.
- **enforcement** — a blocked device is refused, and reinstalling with a new key does not clear it.

## 4. The DESIGN.md 25.11 battery

```
$ dotnet run --project src/DeviceTrust.Cli -- battery
Battery summary
---------------
PASS 0. Clean baseline scan
       score=0 verdict=trusted
PASS 1. Account created through the enforce gate
       POST /v1/accounts/register -> 201
PASS 2. Stolen access token
       HTTP 401 invalid_installation_signature
PASS 3. Stolen refresh token
       HTTP 401 invalid_installation_signature
PASS 4a. Exact signed-request replay
       HTTP 401 access_proof_replay
PASS 4b. Request-body tampering
       HTTP 401 access_proof_body_mismatch
PASS 4c. HTTP path and method binding
       path: HTTP 401 access_proof_path_mismatch; method: HTTP 401 access_proof_method_mismatch
PASS 4d. Access-proof timestamp window
       HTTP 401 access_proof_timestamp_outside_window
PASS 5. Device memory across a reinstall
       HTTP 403 integrity_device_blocked_recently
NOT RUN 6. Frida Gadget compromise
       requires physical hardware

9 passed, 0 failed, 1 skipped
  Cross-device checks used two software keys, so they establish the protocol
  binding only. Key non-exportability still requires the handset battery.
```

Observed codes, in order: `invalid_installation_signature` (stolen access token, after reaching
proof verification), refresh challenge `200` then `invalid_installation_signature` (stolen refresh
token), `access_proof_replay`, `access_proof_body_mismatch`, `access_proof_path_mismatch` and
`access_proof_method_mismatch`, `access_proof_timestamp_outside_window`, and
`integrity_device_blocked_recently`.

The four access-proof boundary tests ran within seconds of a session refresh, satisfying the
"within 10 minutes of a refresh" condition that stops an expired access token from making them
inconclusive.

## 5. The command surface, end to end

Every CLI command was run against the live server, not only the two suites.

`health` reported the engine and mode above. `keyinfo` printed the software key and warned that it
is not hardware-backed. `enroll` registered, proved possession, scored 0/trusted and read the device
record. `account register`, `me`, `echo`, `policy`, `refresh`, `me` again, and `account login` all
succeeded; `echo` confirmed `access_proof: accepted` with the body round-tripped, and the session id
in `me` changed after `refresh`, which is the rotation actually taking effect rather than a cached
token being reused.

Two behaviours are worth recording separately.

**A run with no endpoint fails closed.** Unsetting `API_BASE_URL` produced
`api_base_url_missing` and exit code 2, before any network call.

**Reinstall recognition works from .NET.** After `reset` — which deletes the installation key and
all local state — a fresh `enroll` presented a new key and a new UUID, and the server correlated it
back to the *same* `device_id` through the reinstall hint:

\`\`\`
Installation id     b50b2407-27d5-4b08-b8ed-acfa467155a0   (new)
Device id           36ba72bf-9f39-4bb4-808f-63a751d4eef4   (unchanged)
Recognition         reinstall_hint / medium
Known installations 2
\`\`\`

Running the commands rather than assuming them found a real defect: `account register --handle x
--password y` failed with "Both --handle and --password are required", because the subcommand
re-parsed the leftover positional arguments after the top-level parser had already consumed those
switches. Fixed by threading the single parse result through.

## 6. Builds

```
DeviceTrust.Client           net6.0, net8.0                    0 warnings, 0 errors
DeviceTrust.Client.Windows   net6.0-windows, net8.0-windows    0 warnings, 0 errors
DeviceTrust.Cli              net8.0                            0 warnings, 0 errors
DeviceTrust.Client.Tests     net6.0, net8.0                    0 warnings, 0 errors
DeviceTrust.Client.Maui      net8.0-android                    0 warnings, 0 errors
```

Warnings are errors across the whole repository (`TreatWarningsAsErrors`), including the platform
compatibility analyzer, so every Android API newer than the API 23 floor is guarded by an
`OperatingSystem.IsAndroidVersionAtLeast` check that the analyzer can actually see.

Compiling the Android package was worth doing rather than assuming: it surfaced sixteen real errors
first time, among them `IECPublicKey.GetW()` being a method rather than a `W` property,
`KeyInfo.SecurityLevel` being an `int` that needs casting to `KeyStoreSecurityLevel`, an
`Android.Provider.AggregateException` shadowing `System.AggregateException`, and every
version-gated call needing the analyzer-visible guard form.

## Not covered

These are gaps, not oversights.

**Key non-exportability.** The cross-device checks use two *software* keys in two directories. They
establish the protocol property — the server refuses a token presented with a signature from the
wrong installation key — and say nothing about whether a key can be copied off a device. Only the
handset battery on real hardware covers that, and both test phones were unavailable during this
work.

**The Frida Gadget compromise test.** Needs a release APK with an embedded gadget on a physical
device. The battery reports it as NOT RUN rather than skipping it silently.

**iOS compilation.** The `ios` workload cannot install on Linux — it needs Xcode — so
`SecureEnclaveInstallationKeyStore` and `AppleIntegrityCollector` have been written against the
documented Xamarin.iOS Security and dyld APIs but **have not been compiled**. Build them on macOS
with `dotnet workload install ios` before relying on them. The Android half of the same package is
compiled and clean.

**Windows runtime behaviour.** `CngInstallationKeyStore` and `WindowsIntegrityCollector` compile
for `net6.0-windows` and `net8.0-windows` but have not been executed, because this machine is
Linux. The Windows collector also cannot be submitted to the current server at all, which reports
`unsupported_platform` for anything that is not `android` or `ios`.

**Integrity measurements in the harness are fixtures.** Every integrity result above came from
`ConformanceProbeCollector`, which is synthetic by design and labels every probe it emits with
`harness_fixture`. It proves the server's scoring and this client's report path. It is not
evidence about the state of any real device, and the CLI prints that warning on every run that uses
it.
