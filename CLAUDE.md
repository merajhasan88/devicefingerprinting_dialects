# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this repository is

The **.NET/C# client SDK** for the device-trust server described in `DESIGN.md`. It gives a .NET
application a device-bound installation identity, per-request proof of possession, sender-constrained
refresh tokens and server-scored native integrity reporting.

**This is a client, not a second server.** The server is `device_trust_server.py`, in the reference
repository. Two independent implementations of signature verification, nonce handling and scoring
would double the security-review surface and risk a divergence in one becoming a vulnerability. One
server, many clients. Do not add server-side logic here.

The server, not Google or Apple, owns the risk score. There is deliberately no Play Integrity,
SafetyNet, App Attest or DeviceCheck anywhere in this design. Do not introduce one.

## Read this first

- `DESIGN.md` — the authoritative design and validation record for the whole system. Section 24 holds
  the client-SDK contract invariants; section 25.11 defines the standard battery.
- `DOTNET_SDK_BRIEF.md` — the brief this SDK was built from.
- `docs/protocol.md` — what this client actually puts on the wire.
- `docs/validation.md` — what has been run, and what has not.

## Hard rules

**Never fabricate a probe result.** A collector reports what it measured. A probe that cannot read
what it needs reports `error` or `unsupported` and takes the server's 30-point penalty; an
unavailable measurement is not a clean one. The console harness has fixtures because a conformance
harness's job is to check how the server scores a given input — that code must never migrate into a
shipped collector.

**Signatures are ASN.1 DER, always.** All signing goes through `EcdsaSignatureFormat.SignDer`.
`ECDsa.SignData(data, HashAlgorithmName.SHA256)` emits IEEE P-1363 and fails every server
verification with `invalid_installation_signature`, which reads like a stolen token rather than an
encoding bug.

**No canonical JSON.** The server verifies the signature over the bytes it received and parses them
afterwards. Adding RFC 8785 canonicalisation, or re-serialising a body after hashing it, breaks the
protocol rather than tightening it.

**The endpoint has no default.** `API_BASE_URL` is required and a run without it fails with
`api_base_url_missing`. Never add a fallback, not even for tests.

**Read `error.code`, never a flat `code`.** The envelope is `{"error": {"code": …}}`.

**Warnings are errors.** That includes the platform-compatibility analyzer: guard version-gated
Android APIs with `OperatingSystem.IsAndroidVersionAtLeast(n)`, which the analyzer understands, not
with a `Build.VERSION.SdkInt` comparison, which it does not.

**Say what was tested and what was not.** `docs/validation.md` lists gaps explicitly. Keep it that
way; do not describe an untested path as working.

## Commands

```bash
dotnet build DeviceTrust.sln            # everything that builds without a workload
dotnet test                             # 54 offline tests, net6.0 and net8.0
dotnet build src/DeviceTrust.Client.Maui   # needs: dotnet workload install android

export API_BASE_URL=https://<endpoint>
dotnet run --project src/DeviceTrust.Cli -- health
dotnet run --project src/DeviceTrust.Cli -- conformance   # 24 checks against a live server
dotnet run --project src/DeviceTrust.Cli -- battery       # the DESIGN.md 25.11 battery
```

The Python `conformance_suite.py` in the reference repository is client-agnostic and already proves
the server. Point it at the same endpoint when a result here is ambiguous, to tell a client defect
apart from a server one.

## Test environment notes

- Only the .NET 9 runtime may be installed. The CLI and test projects set `RollForward=LatestMajor`
  so net6.0 and net8.0 assemblies run on it.
- Two test handsets exist but are frequently unavailable. Never install anything on them without
  asking, and never root, wipe or modify their OS.
- The integrity scoring checks need the server's `INTEGRITY_ANDROID_CERT_SHA256` to contain the
  conformance certificate the harness prints, or to be empty.
