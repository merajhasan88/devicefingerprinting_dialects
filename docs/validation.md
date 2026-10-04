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

```
Installation id     b50b2407-27d5-4b08-b8ed-acfa467155a0   (new)
Device id           36ba72bf-9f39-4bb4-808f-63a751d4eef4   (unchanged)
Recognition         reinstall_hint / medium
Known installations 2
```

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

## 7. Catch-up with the reference session: key_security, step-up, re-enrolment (2026-09-29)

What changed: the client now reports `key_security` at registration, supports the optional step-up
key (`IStepUpKeyStore`: `AndroidStepUpKeyStore`, `SecureEnclaveStepUpKeyStore`, and the test-only
`SoftwareStepUpKeyStore`), sends step-up proofs bound to the access-proof nonce, handles dead keys,
and re-enrols (DESIGN.md 50-58). The Android and iOS harnesses have the three step-up buttons the
Flutter app has. `DESIGN.md` here was replaced by the reference copy (to section 62).

Target: `https://devicefingerprinting.duckdns.org`, PostgreSQL 16.15, schema 7,
`INTEGRITY_MODE=observe`, `DEVICE_POLICY_MODE=observe`, every `risk_policy_settings` row at its
default (step-up gate empty).

| What | Result |
|---|---|
| Offline tests (`dotnet test`) | **106 passed** on net6.0 and net8.0, including 17 new step-up tests (wire shape, nonce binding, signature by the step-up key and not the installation key, dead-key handling, re-enrolment proof, `unknown` level sent as null) |
| .NET conformance (`conformance`) | **28 passed, 0 failed, 3 skipped**. New and passing: key_security recorded, step-up key registration (the Android 9 windowed shape, downgrade flag), step-up immutability, re-enrolment (wrong password 401, foreign-key proof 403, valid 200, old key unbound), account bands (2 elevated and never refused, 3 review, 4 block), parallel clients. Skipped: the two enforce-mode checks, and the gated step-up check because `stepup_required_paths` is empty |
| `DeviceTrust.Client.Maui` (net8.0-android) and the Android harness (Release) | build clean, warnings as errors |
| iOS sources, `tools/ioscheck` + `tools/obsscan` | compile clean; no new obsoleted call sites |
| W^X baseline for build `834a5a23…` | `3735552:65536`, four agreeing cold starts on the OPPO; pinned on the server by the owner; the OPPO's scan then read **18/100 trusted** (developer options +8, adb +10) with `android_wx_memory` gone |

## 8. Access proof v2, step-up proof v2, and the two hardware-found step-up gaps (2026-10-04)

From the reference session's `HANDOFF_TO_DOTNET_2026-09-30.md` (DESIGN.md 63):

- **Access proof v2**: the proof gains `query` (the raw query string as sent) and `version: 2`.
  The query is read from the `Uri` actually sent, so `Uri`'s escaping and the signature agree.
- **Step-up proof v2**: the step-up key approves one complete request (token hash, method, path,
  query, body hash, nonce), built from the same request description as the access proof.
- **Step-up offered only for the key the server last confirmed as bound**
  (`BoundStepUpThumbprint`), not for any local key the server has not called different.
- **Android: an alias with no private key is a dead key** (`IsKeyEntry` false, or a bare
  `UnsupportedOperationException` from `GetEntry`), deleted and reported `STEPUP_KEY_INVALIDATED`.
- `http://` endpoints are refused (`api_base_url_insecure`) unless `AllowInsecureHttp` is set.

Target: `https://devicefingerprinting.duckdns.org`, PostgreSQL 16.15, **schema 8**,
`INTEGRITY_MODE=observe`, `DEVICE_POLICY_MODE=observe`, `ACCESS_PROOF_MIN_VERSION=1` (versions 1 and
2 accepted), `stepup_required_paths=/v1/account/sensitive-echo`, factor `passcode`, mode `per_use`.

| What | Result |
|---|---|
| Offline tests | **112 passed** on net6.0 and net8.0 — new: both proofs sign the query the request carries (a space signs as `%20`), the step-up proof's request fields equal the access proof's, a refused re-enrolment leaves the fresh key unusable (the iPhone sequence), a key reported different is unusable, `http://` refused |
| .NET conformance | **31 passed, 0 failed, 3 skipped** (the three enforce-mode checks). Passing with the gate on: the client signs v2 and an appended query is refused `401 access_proof_query_mismatch`; a v1 proof accepted where allowed and refused with a query; step-up v2 verified; wrong factor, an approval moved to another body (`stepup_binding_mismatch`, field `body_sha256`), to another path (field `path`), a v1 step-up proof (`stepup_proof_version_unsupported`) and a key registered with another factor (`stepup_factor_mismatch`) all refused; re-enrolment including the second-account attack (`stepup_key_other_account`) |
| Android harness, release APK (`58396d51…`, harness key `664e9c8e…e3`) | builds clean; **not yet installed** |
| iOS sources (`tools/ioscheck`, `tools/obsscan`) | compile clean, no new obsoleted call sites; **no Codemagic build yet** |

## Not covered

These are gaps, not oversights.

**Step-up on hardware.** `AndroidStepUpKeyStore` and `SecureEnclaveStepUpKeyStore` have been
compiled, not run (as of section 8). Neither the BiometricPrompt path (API 30+), the confirm-credential path
(Android 9/10), the Secure Enclave passcode prompt, nor the dead-key handling has been exercised on a
phone. The conformance run proves the wire contract with software step-up keys only, which sign
with nobody present.

**The biometric factor.** Not exercised anywhere; the iOS harness also lacks the
`NSFaceIDUsageDescription` a Face ID device would need.

**Access proof v2 only.** The shared server accepted v1 and v2 during the section 8 run, so the
client's v2 proofs passed, but no .NET run has yet been made with the server refusing v1
(`ACCESS_PROOF_MIN_VERSION=2`).

**A new APK needs a new W^X baseline.** Any rebuild of the Android harness changes its APK hash, so
the pinned `834a5a23…` entry no longer applies and the device reads 78/review until the new build's
entry is appended.

**Key non-exportability.** The cross-device checks use two *software* keys in two directories. They
establish the protocol property — the server refuses a token presented with a signature from the
wrong installation key — and say nothing about whether a key can be copied off a device. Only the
handset battery on real hardware covers that, and both test phones were unavailable during this
work.

**The Frida Gadget compromise test.** Needs a release APK with an embedded gadget on a physical
device. The battery reports it as NOT RUN rather than skipping it silently.

**iOS runtime behaviour.** The iOS sources **now compile**, against Apple's genuine `Microsoft.iOS`
reference assembly, via `dotnet build tools/ioscheck`. That check found four real defects in
`SecureEnclaveInstallationKeyStore` that reading the code had not: `SecAccessControl` has a
constructor rather than a static `Create`, and `SecKeyChain.QueryAsReference` returns an
`INativeObject[]` and requires an explicit maximum, so the two-argument call had silently bound the
status variable to the count parameter.

**The iOS collector has now run on hardware** — an iPhone 7 (`iPhone9,3`, A10, iOS 15.8.5),
TrollStore, built by Codemagic and pre-signed by `tools/presign_trollstore_ipa.sh`. This is the
first execution of any of it; before this the sources were only compiled and reviewed. What the two
local, endpoint-free actions reported, read over USB with `idevicesyslog`:

- **Installation key** — `provider: iOS Keychain`, `security_level: secure_enclave`,
  `hardware_backed: True`, `private_key_exportable: False`, and a real thumbprint. The Secure
  Enclave minted the key. This is the store that had four API defects at first compile; it works.
- **Code-signing identity** — `signed: True`, `entitlement_count: 4`, and **`get_task_allow: False`**,
  which is the pre-sign doing its job: the TrollStore +35 floor is gone. `signing_identifier` is
  `com.icraze.gtatracker`, not the bundle id — the CoreTrust donor identity, exactly what the Swift
  client measured on the same phone. The server's `ios_signing_identifier_bundle_mismatch` (+90,
  report-only until baselined) is a true positive here: this is a fake signature, and the probe
  surfaces the tell.
- **App identity** — `bundle_id: com.example.devicefingerprinting_dotnet`, `executable_readable: True`,
  and an `executable_sha256` of `826211b3…`. That hash is the device's own post-rewrite value, which
  is what `INTEGRITY_IOS_EXECUTABLE_SHA256` would be pinned to, never the file's.
- **Code integrity (item 16)** — `checked: True`, `app_images_compared: 1`, `app_diff_bytes: 0`
  against the app's own `__TEXT,__text`, and `system_images_unreadable: 272` with
  `system_bucket_reason: dyld_shared_cache_has_no_backing_files`. The shared-cache images are counted,
  never read as clean, exactly as designed.

Two bugs surfaced on that first run, both now fixed for the next build:

- **The harness crashed on every action** with `ArgumentOutOfRangeException` from
  `StringBuilder.ToString`. The probe body runs on a `Task.Run` worker and appended to the transcript
  while the main thread read it to fill the text view; `StringBuilder` is not thread-safe, so the
  concurrent append corrupted the chunk chain mid-read. Append and snapshot now happen together under
  a lock, and only the finished string crosses to the UI thread. This is harness plumbing, not the
  SDK — the measurements above all completed before the crash.
- **Item 16 compared only the first 4 MiB** of a 12 MiB binary, because the app bucket used the
  Android per-image cap. A patch past the 4 MiB mark would have read as clean. The app-bucket cap is
  now 64 MiB — enough to cover the whole executable in one sub-second pass, since iOS has exactly one
  bundle image with a backing file.

**The full battery has now run against a live server** (`https://devicefingerprinting.duckdns.org`,
PostgreSQL 16.15, both modes `observe`), read off the iPhone over USB:

| item | result |
| --- | --- |
| enrol / native scan | score 0, `trusted` |
| account register / login | created and logged in |
| risk evaluation | score 10, `allow` |
| 5 exact replay | 401 `access_proof_replay` |
| 6 body tampering | 401 `access_proof_body_mismatch` |
| 7a/7b path & method | 401 `access_proof_path_mismatch` / `_method_mismatch` |
| 8 stale timestamp | 401 `access_proof_timestamp_outside_window` |
| bound refresh | rotated; new access token works |
| 3 stolen access (iPhone→Android) | 401 `invalid_installation_signature` |
| 4 stolen refresh (iPhone→Android) | challenge 200, then 401 `invalid_installation_signature` |
| 12/13 delete key → new identity | `8c80ea71…` became `91725560…`, new thumbprint, `created_this_launch` |
| 15 reinstall keeps identity | `8c80ea71…` survived the session's TrollStore reinstalls |
| 16 app bucket | `app_diff_bytes 0` over the whole executable |

The cross-device tests are genuine two-device runs: the iPhone minted, the Huawei replayed. Token
entry went through Android intent extras over adb (`am start --es stolen_access_token …`), not
`adb shell input text`, which silently truncated a 639-character token to 414 and produced a
misleading `invalid_token` rather than the signature rejection. The truncation was caught by dumping
the field with `uiautomator` and comparing lengths; the binder carries the full value. The CLI
`battery --stolen-access-token …` reaches the same verdict from this machine, since the server cannot
distinguish a second device from any other key that did not mint the token.

With the server flipped to `integrity_mode: enforce`, the CLI conformance suite runs all 24 checks
with none skipped — including the two enforcement checks that observe mode cannot exercise: a blocked
device cannot reach protected endpoints, and reinstalling does not clear a block. These are driven
from this machine with software keys, since the server cannot distinguish that from any other client.

One consequence of enforce, relevant only to the physical Android handset: the cert allow-list
(`INTEGRITY_ANDROID_CERT_SHA256`) is active, so enrolling that handset now requires a release build
whose signing certificate is allow-listed, or the report hard-blocks with
`android_signing_certificate_mismatch` (+100) and a debug build additionally trips `ro.debuggable`
(+35). The iPhone and the CLI are unaffected.

The iOS target framework is `net9.0-ios`, chosen so that what Codemagic builds is what this machine
can check. iOS bindings are versioned against Xcode: .NET 8's stop at the iOS 18 family, which a
current Xcode has moved past, and .NET 10's iOS 26 bindings cannot be referenced from a net9.0
compilation at all — that fails with CS1705, an error rather than a waivable warning, and only the
.NET 9 SDK is installed here. .NET 9 has iOS 26 bindings and is checkable, so it is the one runtime
where the compile check and the real build agree. These sources build clean against both
`Microsoft.iOS.Ref.net9.0_26.0` and `net9.0_26.5`, which brackets whichever family the workload
resolves on the build machine:

```bash
dotnet build tools/ioscheck                                     # 26.0, the default
dotnet build tools/ioscheck -p:IosRefPackage=Microsoft.iOS.Ref.net9.0_26.5 \
                            -p:IosRefVersion=26.5.9004
```

What that still does not prove: a reference assembly is an API surface, not a toolchain. It does
not link against a real iOS SDK, run the AOT compiler, or produce a bundle, and the deployment
target this app needs is `15.0` — the iPhone 7 cannot go past iOS 15.8.5 — which is close enough to
a current Xcode's floor to be worth confirming rather than assuming.

**iOS items 16, 10 and 12 now pass on hardware** via the get-task-allow + JIT route (see
`docs/handset-battery.md`, 2026-09-20): the app's own `__text` was inline-hooked under JIT (DDI
debugserver via `pymobiledevice3` + `frida` spawn), raising `ios_app_code_modified +90` → block
(item 16), a login on the blocked device returned `403 integrity_blocked` (item 10), and a new
hardware key on the recently-blocked device returned `403 integrity_device_blocked_recently`
(item 12 — cleaner on iOS than Android, which W^X keeps at 78/review). **Item 14 is structurally
impossible on iOS**: there is no readable system library to hook, since the dyld shared cache has no
backing file. Item 16's isolation is also unavailable on iOS — modifying one's own `__text` needs
get-task-allow (+35), which always rides along; that is itself the finding, not a gap.

Two blind spots in the compile check are now known, both paid for by a failed build:

- **The platform analysers do not run.** CA1416 and CA1422 need a platform in the target framework,
  and `tools/ioscheck` is plain `net9.0`. Adding `[assembly: SupportedOSPlatform("ios15.0")]` does
  not wake them; that was tried and measured. So calling an API Apple obsoleted on a newer iOS
  passes locally and fails the real build, which is what `new UIWindow(CGRect)` did.
  `tools/obsscan` closes it by reading the obsoletion metadata out of the reference assembly and
  matching it against the sources; it reports one call site, suppressed in place with the reason
  written next to it, because the only device this harness will run on is pinned at iOS 15.8.5.

  ```bash
  dotnet run --project tools/obsscan -- \
    tools/ioscheck/packages/microsoft.ios.ref.net9.0_26.5/26.5.9004/ref/net9.0/Microsoft.iOS.dll \
    ios26 src/DeviceTrust.iOS.Harness src/DeviceTrust.Client.Maui/Apple
  ```
- **CS8765 is not reported** — a parameter whose nullability disagrees with the member it overrides.
  `AppDelegate.cs` is genuinely compiled by the tool against the same reference assembly, and the
  diagnostic still only appeared on the real build. There are three overrides in the iOS sources;
  a fourth needs its signature checked against the binding by hand.
- **Runtime behaviour of a correct signature is invisible to it.** The compile check verifies that a
  method exists with the types used; it cannot see what the method does with the values at runtime.
  `SecKeyChain.QueryAsReference(query, 1, out status)` compiled cleanly and aborted on the device the
  moment a key existed: `max = 1` sets `kSecMatchLimitOne`, the keychain returns a single `SecKeyRef`
  rather than a one-element array, and the array-returning binding sends `-count` to it —
  `-[__NSCFType count]: unrecognized selector`. The single-item `QueryAsConcreteType` is the correct
  call. Nothing on Linux would have caught this; a keychain query that returns one item is worth
  exercising on hardware with an item present, which by definition a first launch never does.

**The Mach-O reader and the signing script, against real binaries.** `MachOImage` and
`EntitlementsPlist` were unit-tested against synthetic images, which proves a parser matches its
author's belief about the format — the one thing it cannot check. Both have now been run over a
genuine arm64 iOS app (the Flutter client's unsigned Codemagic `.ipa`, borrowed as input only).
The unsigned executable correctly reports no code signature; after
`tools/presign_trollstore_ipa.sh`, the same reader recovers the CodeDirectory identifier
`com.example.devicefingerprinting_dotnet` — the field the server compares against
`app_identity.bundle_id` — flags `0x0`, and all four entitlements, matching `ldid` byte for byte.

Rehearsing the script on that bundle found two defects that would otherwise have surfaced with the
phone in hand:

- `ios/trollstore-entitlements.plist` contained `--` inside an XML comment, which is malformed XML.
  Python refused it outright; `ldid` had been accepting it, which is worse, because it means the
  entitlements actually embedded were whatever a lenient parser made of a broken file.
- The nested-binary search matched `*.dylib` and `*.so` and found **nothing** in a real bundle. The
  objects that need signing are framework binaries — `Frameworks/Flutter.framework/Flutter` and two
  others — which carry no extension. Signing now selects by Mach-O magic number, which found all
  three. This is the documented cause of a sideloaded app that flashes and closes, and it fails
  silently: the script reports success and the app dies on launch.

A relative output path was also being resolved against the temporary work directory rather than the
caller's, so the finished `.ipa` went missing.

**Windows runtime behaviour.** `CngInstallationKeyStore` and `WindowsIntegrityCollector` compile
for `net6.0-windows` and `net8.0-windows` but have not been executed, because this machine is
Linux. The Windows collector also cannot be submitted to the current server at all, which reports
`unsupported_platform` for anything that is not `android` or `ios`.

**Integrity measurements in the harness are fixtures.** Every integrity result above came from
`ConformanceProbeCollector`, which is synthetic by design and labels every probe it emits with
`harness_fixture`. It proves the server's scoring and this client's report path. It is not
evidence about the state of any real device, and the CLI prints that warning on every run that uses
it.
