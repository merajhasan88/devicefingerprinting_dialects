# Integrity collection

## The contract

The server chooses the probes, the client runs exactly those, the installation key signs the
complete report, and **the server scores the raw measurements**. The client never computes or sends
a score — a client-supplied score would be the first thing an attacker forged.

`IIntegrityProbeCollector` is the .NET analogue of the Flutter client's `integrity_v1` method
channel:

```csharp
string Platform { get; }          // what these measurements describe, and what the client registers as
int CollectorVersion { get; }
Task<IntegrityCollection> CollectAsync(IReadOnlyList<string> requiredProbes, string challengeNonce, ...);
```

`Platform` doubles as the platform the client registers under, so the identity a device claims and
the measurements it can produce always describe the same thing.

## Reporting failure honestly

Every `ProbeResult` carries a `status`:

- `ok` — the probe ran.
- `error` — it threw, or could not read what it needed.
- `unsupported` — this platform cannot run it at all.

A required probe with a non-`ok` status costs 30 risk points. That penalty is correct: an
unavailable measurement is not a clean measurement. **Filling in a plausible clean-looking value to
avoid the penalty is the one thing a collector must never do**, and it is why the shipped collectors
contain no test fixtures. The console harness has fixtures, because a conformance harness's purpose
is to check how the server scores a given input; that code cannot reach a customer's application.

Two failures that look like probe bugs and are not:

- **SELinux unreadable on Android.** Some OEMs prevent an ordinary sandboxed app from reading
  `getenforce` or `/sys/fs/selinux/enforce` even on an enforcing device. The collector reports
  `mode: "unknown"` and the server scores nothing; only an explicit `permissive` or `disabled`
  earns points. This is a fixed false positive, recorded in DESIGN.md against the OPPO test handset.
- **The ART JIT code cache.** It is always an executable, `(deleted)`-backed mapping on a clean
  device. `exec_mappings` counts it separately as `deleted_exec_jit`, which the server does not
  score. Without that exclusion every Android device is a false positive.

## Android — `AndroidIntegrityCollector`

A port of the Kotlin `IntegrityProbeManager`. Probes:

| Probe | What it measures |
|---|---|
| `app_identity` | package name, version, debuggable and backup flags, signing certificate SHA-256s, APK hash, installer, source dir |
| `debug_state` | debugger connected, waiting for debugger |
| `tracer` | `TracerPid`, `Seccomp`, `NoNewPrivs` from `/proc/self/status` |
| `root_files` | known root/su paths that are visible, build tags, test-keys |
| `root_shell` | whether `su` is discoverable from the app process |
| `system_properties` | `ro.secure`, `ro.debuggable`, `ro.build.type`, Verified Boot and VBMeta state |
| `selinux` | mode, from `getenforce` and `/sys/fs/selinux/enforce` independently |
| `mounts` | protected system mounts that appear writable |
| `runtime_maps` | suspicious tokens in `/proc/self/maps` |
| `frida_ports` | whether 27042/27043 accept a local connection |
| `instrumentation_threads` | Gum/Frida and GLib thread names in `/proc/self/task/*/comm` |
| `exec_mappings` | writable-and-executable mappings, executable mappings backed by deleted files |
| `code_integrity` | in-memory `.text` versus the on-disk image, via a native library |
| `emulator`, `developer_settings` | telemetry-weight signals |

### Why the structural probes matter more

DESIGN.md 27.11 records a **confirmed evasion**: renaming an injected Frida library and moving it
off the default port defeats `runtime_maps` and `frida_ports` completely, because both are name and
port denylists. The last three probes in the table are structural and survive it:

- `instrumentation_threads` reads thread names that are compiled into Frida's Gum runtime
  (`gum-js-loop`, `pool-frida`) and into its GLib dependency. Renaming the injected `.so` does not
  rename its threads, and a process may always read `/proc/self/task/<tid>/comm` for its own threads
  whatever SELinux says.
- `exec_mappings` looks for the *shape* of injection — writable-and-executable memory, executable
  memory backed by a deleted file — rather than for a name.
- `code_integrity` compares libc and libart `.text` in memory against the same bytes on disk. An
  inline hook overwrites a function prologue, so any difference at or above one arm64 branch (4
  bytes) is a modification, whatever the hooking tool is called. Clean devices measure exactly zero,
  so the threshold is margin rather than tuning.

`code_integrity` needs `libcodeintegrity.so` — the same native library the Kotlin collector loads —
packaged into `lib/<abi>`. When it is absent the probe reports `checked: false` with a reason, which
the server can see and weigh, rather than silently reporting a clean measurement it never took.

## iOS — `AppleIntegrityCollector`

iOS gives an app far less visibility into its own device: no `/proc`, no mount enumeration, no
system properties. What remains is still meaningful.

| Probe | What it measures |
|---|---|
| `app_identity` | bundle id, version, executable SHA-256 |
| `code_signing` | `application-identifier` and team-identifier entitlements, `get-task-allow` |
| `debugger` | `P_TRACED` via `sysctl(KERN_PROC)`, managed debugger attached |
| `jailbreak_files` | visible jailbreak artefacts, including rootless `/var/jb` |
| `sandbox` | whether a write outside the container succeeds |
| `dyld_images` | suspicious tokens across every loaded image |
| `environment` | `DYLD_INSERT_LIBRARIES` |
| `simulator` | whether this is the simulator |

`dyld_images` is the strongest single signal: on a jailbroken device a hooking framework must be
loaded into the process to do anything, and it is visible in the image list whatever it is called.

`code_signing` reads entitlements through `SecTaskCopyValueForEntitlement`, because iOS has no
public `SecCodeCopySigningInformation`. `signing_identifier` is reported as the
`application-identifier` entitlement (`<TEAMID>.<bundle-id>`); an operator configuring
`INTEGRITY_IOS_SIGNING_ID` should use that form.

## Windows — `WindowsIntegrityCollector`

**A different design, not a translation.** Root binaries, SELinux, `/proc/self/maps` and Verified
Boot have no Windows meaning. What a Windows process can observe about itself is:

| Probe | What it measures |
|---|---|
| `app_identity` | image path, SHA-256, Authenticode verdict, signer subject and thumbprint, file version |
| `debugger` | managed debugger, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, kernel-debug boot options |
| `loaded_modules` | every loaded module's Authenticode verdict; unsigned, untrusted, known-hooking and user-writable-location modules |
| `os_integrity` | Secure Boot state, `TESTSIGNING`, `DISABLE_INTEGRITY_CHECKS`, OS build |
| `process_state` | elevation, session, interactivity |

Authenticode is verified with `WinVerifyTrust`, not by reading the embedded certificate. Reading the
certificate alone — `X509Certificate.CreateFromSignedFile` — is a trap worth naming: it returns
whatever certificate a file carries without checking that the signature covers the file or that the
chain is trusted, so a tampered or self-signed binary looks "signed".

**The server does not score Windows yet.** It accepts `android` and `ios` and answers anything else
with `unsupported_platform`, so a report from this collector cannot be submitted until a Windows
scoring table exists server-side. `CollectAll()` runs the whole set regardless, for local
diagnostics. Reporting a Windows machine as `android` to get past the gate would be exactly the
dishonesty the integrity mechanism exists to prevent, so this collector does not do it.

## The boundary

On a fully compromised OS these local measurements can be falsified. The server therefore combines
them with cryptographic key possession, per-request proofs, replay prevention, and server-observed
account and device relationships — and it remembers a blocked verdict against the *device*, so
reinstalling the app does not clear it.
