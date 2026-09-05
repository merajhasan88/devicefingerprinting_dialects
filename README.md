# Device Trust .NET client SDK

A .NET client SDK for the device-trust server described in `DESIGN.md`. It gives a .NET
application a device-bound installation identity, proof of possession on every protected request,
sender-constrained refresh tokens, and server-scored native integrity reporting — the same protocol
the Flutter reference client speaks, against the same server.

**This is a client, not a second server.** The server is `device_trust_server.py`. Two independent
implementations of signature verification, nonce handling and scoring would double the
security-review surface and risk a divergence in one of them becoming a vulnerability. One server,
many clients.

## What it does

| Capability | Where |
|---|---|
| Register a P-256 installation key and be recognised by its thumbprint | `DeviceTrustClient.RegisterInstallationAsync` |
| Prove possession of the private key for a 10-minute device token | `AcquireDeviceTokenAsync` |
| Sign a per-request access proof binding token, method, path, body, time and a single-use nonce | `SendProtectedAsync` |
| Collect native measurements the server asked for and sign the whole report | `SubmitIntegrityReportAsync` |
| Rotate a refresh session with a signed challenge, with reuse revoking the family | `RefreshAccountSessionAsync` |
| Hold the private key where it cannot be exported | `IInstallationKeyStore` implementations |

Nothing in this SDK makes a trust decision. Recognition, integrity scoring, relationship risk and
whether a request is allowed are all decided server-side; the client's job is honest measurements
and correct signatures.

## Layout

```
src/DeviceTrust.Client            net6.0; net8.0            The SDK. No package dependencies.
src/DeviceTrust.Client.Windows    net6.0-windows; net8.0-…  CNG/TPM key store, Windows probe set.
src/DeviceTrust.Client.Maui       net8.0-android (+ios)     AndroidKeyStore and Secure Enclave
                                                            key stores, Android and iOS probes.
src/DeviceTrust.Cli               net8.0                    Console harness: examples, conformance,
                                                            the boundary battery.
tests/DeviceTrust.Client.Tests    net6.0; net8.0            Offline unit tests.
```

`DeviceTrust.sln` contains everything that builds without a workload. The mobile package is built
separately because it needs the platform workloads — see [Mobile](#mobile-android-and-ios).

## Framework support

The SDK targets **.NET 6 and .NET 8**, so it runs on .NET 6 and every later release. The tests are
multi-targeted and run against **both** target frameworks, which is what keeps the ".NET 6 and
onwards" claim honest rather than aspirational.

## Quick start

```bash
export API_BASE_URL=https://<your-endpoint>
dotnet build DeviceTrust.sln
dotnet run --project src/DeviceTrust.Cli -- health
dotnet run --project src/DeviceTrust.Cli -- enroll
dotnet run --project src/DeviceTrust.Cli -- account register --handle alice --password Passw0rd123
dotnet run --project src/DeviceTrust.Cli -- me
dotnet run --project src/DeviceTrust.Cli -- refresh
```

In code:

```csharp
using var keyStore = new CngInstallationKeyStore();            // or AndroidKeyStore / Secure Enclave
var options = DeviceTrustOptions.FromEnvironment();            // API_BASE_URL, no default
using var client = new DeviceTrustClient(
    options,
    keyStore,
    new FileInstallationStateStore("state.json"),
    new AndroidIntegrityCollector(context));

await client.BootstrapAsync(reinstallHint);
var session = await client.LoginAccountAsync("alice", password);
var me = await client.GetAccountMeAsync();                     // access proof built and sent for you
```

### Configuration

`API_BASE_URL` **has no default and never will.** A client with no endpoint fails immediately with
`api_base_url_missing`, exactly as the Flutter client fails a build without
`--dart-define=API_BASE_URL`. A default would let a build ship pointing at a lab, a colleague's
laptop, or another customer's environment, and nobody would notice until it mattered.

The console harness reads, in order of precedence: `--base-url`, the `API_BASE_URL` environment
variable, then `ApiBaseUrl` in `appsettings.json`.

## The four things a .NET port gets wrong

1. **Signatures must be ASN.1 DER.** `ECDsa.SignData(data, HashAlgorithmName.SHA256)` returns IEEE
   P-1363 fixed-width `r || s`. The server verifies DER and rejects P-1363 on every single call —
   with `401 invalid_installation_signature`, which reads like a stolen token rather than an
   encoding bug. All signing goes through `EcdsaSignatureFormat.SignDer`, which uses the
   `DSASignatureFormat.Rfc3279DerSequence` overload, and `SignatureFormatTests` fails offline if
   that ever regresses.

2. **The error envelope is nested.** Failures are `{"error": {"code": ..., "message": ...}}`.
   Reading a flat top-level `code` yields `null` for every rejection, and all control flow keyed on
   the code silently stops working.

3. **The body hash covers the exact bytes sent.** Bodies travel as pre-serialised `byte[]`, never as
   objects re-serialised after hashing. Anything that could re-encode between hashing and sending —
   a different encoder, a BOM, reordered properties — produces `access_proof_body_mismatch` for
   reasons invisible in the source.

4. **There is no canonical JSON, and adding some would break things.** The server verifies the
   signature over the bytes it received and parses them only afterwards, so Dart, .NET and Python
   do not need byte-identical serialisation. No RFC 8785. Any server-side re-serialisation before
   verification would break every SDK that does not serialise exactly like the reference one.

## Key storage

| Store | Where the key lives | Non-exportable | Use |
|---|---|---|---|
| `AndroidKeyStoreInstallationKeyStore` | AndroidKeyStore, StrongBox when available | Yes, by the OS | Production Android |
| `SecureEnclaveInstallationKeyStore` | Secure Enclave, keychain reference | Yes, by the hardware | Production iOS |
| `CngInstallationKeyStore` | Windows CNG, TPM where present | Yes, by CNG policy | Windows desktop |
| `SoftwareInstallationKeyStore` | A file | **No** | Protocol testing only |

A desktop CNG key is **not** equivalent to a phone's keystore key: an attacker with administrator
rights on the machine can use it as a signing oracle, and without a TPM it is protected by DPAPI
rather than hardware. The property that survives in both cases is that a token stolen from the
machine cannot be replayed from another one, because the signature cannot be produced there. See
[`docs/key-stores.md`](docs/key-stores.md).

`SoftwareInstallationKeyStore` requires `acknowledgeNotHardwareBacked: true` at construction, so no
application can select it by accident or by copying a sample.

## Integrity

The server picks the probes, the client runs exactly those, the installation key signs the complete
report, and **the server scores the raw measurements — the client never sends a score.** A probe
that cannot read what it needs reports `error` or `unsupported` and takes the server's penalty;
filling in a plausible clean value to avoid that penalty is the one thing a collector must never do.

- **Android** (`AndroidIntegrityCollector`) is a port of the Kotlin `IntegrityProbeManager`,
  including the structural probes — `instrumentation_threads`, `exec_mappings`, `code_integrity` —
  that survive the rename-and-move-port evasion recorded in DESIGN.md 27.11.
- **iOS** (`AppleIntegrityCollector`) covers what an iOS app can actually observe: loaded dyld
  images, tracing, sandbox integrity, jailbreak artefacts and entitlements.
- **Windows** (`WindowsIntegrityCollector`) is its own design, not a translation of the Android one:
  Authenticode trust on the process image and every loaded module, debugger and kernel-debugger
  presence, Secure Boot and test-signing state, elevation. **The server does not score Windows
  yet** — it accepts `android` and `ios` and answers anything else with `unsupported_platform` — so
  this collector is currently for local diagnostics and as the client half of that future work.
  Reporting a Windows machine as `android` to get past the gate would be exactly the dishonesty the
  integrity mechanism exists to prevent.

See [`docs/integrity.md`](docs/integrity.md).

## Testing

```bash
dotnet test                                                    # 54 offline unit tests, net6.0 + net8.0
dotnet run --project src/DeviceTrust.Cli -- conformance        # 24 checks against a live server
dotnet run --project src/DeviceTrust.Cli -- battery            # the DESIGN.md 25.11 battery
```

The Python `conformance_suite.py` already proves the server and is client-agnostic; point it at the
same endpoint. What only a .NET harness can establish is that **this client's bytes** are
acceptable, and that its boundary cases are refused with the right codes. Results from the runs
performed so far are in [`docs/validation.md`](docs/validation.md).

The console harness signs with a software key and submits **integrity fixtures, not measurements**.
It prints a warning saying so on every run that uses them. That is legitimate for a conformance
harness, whose purpose is to check how the server scores a given input; it is not legitimate in a
client SDK, and the shipped collectors contain no fixtures at all.

## Mobile (Android and iOS)

```bash
dotnet workload install android          # plus: dotnet workload install ios, on macOS only
dotnet build src/DeviceTrust.Client.Maui
```

The package needs only the `android` and `ios` workloads, not MAUI itself, so it drops into a MAUI
app, a .NET for Android app or a .NET for iOS app equally. It is kept out of `DeviceTrust.sln` so
the solution still builds for anyone without those workloads.

**iOS can only be built on macOS.** The `ios` workload does not install on Linux or Windows, because
the build needs Xcode. The Android half compiles clean here; the iOS half is written against the
documented Xamarin.iOS APIs and has not been compiled. Build it on macOS before relying on it.

## What has and has not been proven

**Proven**, against a live AWS deployment on SQL Server 2025 in `INTEGRITY_MODE=enforce` with Redis
nonces and rate limiting on:

- 24/24 client conformance checks, including every access-proof boundary case with its exact
  rejection code.
- The full boundary battery: stolen access token, stolen refresh token, replay, body/path/method
  tampering, stale timestamp, and device memory surviving a reinstall.
- 54 offline unit tests on both net6.0 and net8.0.
- Every project compiles with warnings as errors, including the Android package.

**Not proven here:**

- **Key non-exportability.** The cross-device checks use two *software* keys, so they establish the
  protocol binding — the server refuses a token presented with the wrong installation key — and say
  nothing about whether a key can be copied. That needs the handset battery on real hardware.
- **The Frida Gadget compromise test**, which needs a release APK with an embedded gadget on a
  physical device.
- **The iOS code**, which cannot be compiled anywhere but macOS, so it has not been compiled at all.
- **Windows runtime behaviour.** The Windows package compiles for both target frameworks but has
  not been executed, because this is a Linux machine.

Those gaps are named rather than papered over. The known and accepted boundary from DESIGN.md still
applies to every client: a fully compromised OS can falsify local measurements and may use a
legitimate non-exportable key as a signing oracle. Without an independent hardware root of trust
this is strong risk-based defence in depth, not perfect attestation.
