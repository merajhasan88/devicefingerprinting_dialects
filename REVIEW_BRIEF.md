# Review brief — Device Trust .NET client SDK (2026-10-04)

This archive is the .NET/C# client SDK for the device-trust server described in `DESIGN.md`: a
device-bound installation key, a signed proof of possession on every request, sender-constrained
refresh tokens, server-scored native integrity reports, and an optional step-up key for sensitive
operations. The server itself (`device_trust_server.py`) lives in the reference repository and is not
included; the parts of its rules that matter here are quoted in the documents below.

## The question we need answered first

**Why does a clean, correctly pinned .NET Android build keep scoring `android_wx_above_baseline` +15,
and what should be done about it?** Full write-up, evidence and options: `docs/wx-session-growth.md`.

In short:

- The server allows a .NET Android build a fixed amount of writable-and-executable (W^X) memory, a
  **baseline** measured at the first integrity report after a cold start and pinned per APK hash.
  Above it, up to 2 ×, the report scores **+15**.
- The .NET runtime on Android (Mono) **JIT-compiles each method on its first call** into W^X memory,
  in 64 KiB units, and never releases it while the process runs. So W^X memory **only grows** as the
  app does more.
- A cold start plus one scan always runs the same code, so the baseline is reproducible to the byte
  (16 of 18 runs: exactly 3,735,552). But every report the app makes **later in the same process** —
  after a login, a step-up re-enrolment, a step-up signature — has compiled more code and reads more:
  up to 4,194,304 (+12 %, seven more 64 KiB units). Each scores +15.
- On the test handset (developer options +8, ADB +10) that is **33 = `elevated`**, and in enforce
  mode `elevated` refuses login, account registration and refresh. On a phone with both off it would
  be 15, still trusted; a real app with a larger user interface will likely grow further, possibly
  past 2 ×, where it becomes +40.

The options — full-AOT build, the Mono interpreter, a runtime without a JIT, a session-plateau
baseline, a server tolerance for growth in the runtime's own units, or a pinned per-build ceiling —
are compared in that file with our recommendation (measure full AOT first; if growth remains, a server
tolerance), followed by four specific questions for you.

## What to read, in order

1. `docs/wx-session-growth.md` — the open problem above.
2. `docs/wx-memory.md`, `docs/wx-baseline-process.md` — why .NET maps W^X memory at all, and how the
   per-build baseline is measured.
3. `docs/protocol.md` — what this client puts on the wire (access proof v2, step-up proof v2,
   registration, re-enrolment, dead step-up keys).
4. `docs/validation.md` — every result, and an explicit list of what has **not** been tested.
5. `DESIGN.md` — the authoritative design record of the whole system (§50–63 are the recent rounds:
   step-up, the external review's fixes, access proof v2). `CLAUDE.md` — the project's working rules.

## Where the code is

| Path | What |
|---|---|
| `src/DeviceTrust.Client` | The SDK: `DeviceTrustClient` (orchestration), `Protocol/` (wire format, `AccessProof`, `DeviceTrustApi`), `Keys/` (installation and step-up key abstractions), `Integrity/` (report model, `/proc/self/maps` parsing, the W^X measurement) |
| `src/DeviceTrust.Client.Maui` | Platform key stores and collectors: `Android/` (AndroidKeyStore installation and step-up keys, the Android integrity collector) and `Apple/` (Secure Enclave keys, iOS collector) |
| `src/DeviceTrust.Client.Windows` | CNG key store and a Windows collector |
| `src/DeviceTrust.Cli` | Console harness: the live conformance suite (34 checks), the `baseline` command that measures W^X on a handset, the battery |
| `src/DeviceTrust.Android.Harness`, `src/DeviceTrust.iOS.Harness` | On-device test apps with a button per test |
| `tests/DeviceTrust.Client.Tests` | 112 offline tests |
| `tools/` | `ioscheck`/`obsscan` (compile-check the iOS sources on Linux), `presign_trollstore_ipa.sh` |

## Current state, in one table

| Area | Result (details in `docs/validation.md`) |
|---|---|
| Offline tests | 112 passed (net6.0, net8.0) |
| Live conformance, server accepting access proof v2 only | 31 / 0 / 3 in observe; **34 / 0 / 0 in enforce** |
| iPhone 7, iOS 15.8.5 | 0 / trusted; step-up v2 verified; both dead-key paths handled |
| OPPO, Android 9 | 18 / trusted on a cold start; step-up v2 verified (30 s window, downgrade recorded); dead key handled — **but 33 / elevated on later reports in a session: the question above** |
| Not tested | Android 11+ step-up (`BiometricPrompt`); the Android "alias without a private key" dead-key branch on hardware; the biometric factor |

## Building and running

```bash
dotnet build DeviceTrust.sln                    # everything that builds without a workload
dotnet test                                     # offline tests
dotnet build src/DeviceTrust.Client.Maui        # needs the android workload
export API_BASE_URL=https://<endpoint>
dotnet run --project src/DeviceTrust.Cli -- conformance
```

## Not in this archive

Build output (`bin/`, `obj/`, restored packages), the signing keystore, and the owner's private notes.
