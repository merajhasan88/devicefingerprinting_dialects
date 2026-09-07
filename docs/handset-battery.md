# Handset battery — .NET client on real hardware (2026-09-06)

Run against **PostgreSQL 18.6** (RDS, schema v1, Redis nonces, rate limiting on) with the .NET
harness app `com.example.devicefingerprinting_dotnet`, a **release, non-debuggable, full-AOT** APK
signed with a dedicated release key. The keystore lives at `~/.devicetrust-harness/harness.keystore`;
it was regenerated once after the original was lost with a cleaned temp directory, so the
certificate digest a server allow-list needs is whatever `apksigner verify --print-certs` reports for
the current build (at the time of writing, `664e9c8e…e3`).

| Device | Model | Android | Build | Verified boot | Key |
|---|---|---|---|---|---|
| Huawei | AQM-LX1 | 10 (API 29) | user | green | AndroidKeyStore, `secure_hardware`, non-exportable |
| OPPO | CPH2083 | 9 (API 28) | user | green | AndroidKeyStore, `secure_hardware`, non-exportable |

## Results

| # | Item | Huawei | OPPO | Mode |
|---|---|---|---|---|
| 1 | Clean baseline scan | 78 / review | 78 / review | enforce |
| 2 | Account through the enforce gate | **BLOCKED** | **BLOCKED** | enforce |
| 3 | Stolen **device** token, cross-device | — | **PASS** `invalid_installation_signature` | **enforce** |
| 3 | Stolen **account access** token, cross-device | — | **PASS** `invalid_installation_signature` | observe |
| 4 | Stolen refresh token, cross-device | — | **PASS** challenge 200 then 401 | observe |
| 5 | Exact replay | **PASS** | **PASS** | observe |
| 6 | Body tampering | **PASS** | **PASS** | observe |
| 7 | Path + method tampering | **PASS** | **PASS** | observe |
| 8 | Stale timestamp | **PASS** | **PASS** | observe |
| 9 | Frida Gadget — detection by name | n/a, see below | n/a, see below | enforce |
| 10 | Frida Gadget — enforcement (login 403) | not run | not run | — |
| 11 | Frida Gadget — restore | **PASS** | **PASS** | enforce |
| 12 | Device memory across a new hardware key | not run | not run | — |
| 13 | Pristine re-enrolment (enrolment half) | **PASS** | **PASS** | enforce |
| 14 | Structural code-integrity, ext bucket | **PASS** | **PASS** | **enforce** |

Items 3 and 4 are cross-device by construction: the Huawei minted, the OPPO replayed with its own
keystore key. That is the property the desktop harness could only approximate with two software
keys, and it is now proven with two genuinely non-exportable hardware keys on two vendors.

Item 13: uninstalling destroyed the AndroidKeyStore entry, so the reinstall enrolled a **new**
hardware key (`88387af3…` → `e356cee7…`) under a new `installation_id`, and the server still
correlated it to the **same** `device_id` through the reinstall hint — `reinstall_hint / medium`,
installations 1 → 2.

## Item 14 — detecting an inline hook by behaviour, not by name

Item 14 is the item that proves the code-integrity probe *detects* something. Every other
code-integrity result above is a zero on a clean device, and a probe that always returned zero would
look exactly the same.

A real Frida Gadget was embedded in the release APK, **renamed to `libhelper.so` and moved to port
27999**, so that the name-based probes are blind — which is the point. DESIGN.md 27.11 records that
exact evasion scoring `18/trusted` against token scanning while the gadget was fully active.

Two scans, one process, the session held open across the second:

| | Huawei run A | Huawei run B | OPPO run A | OPPO run B |
|---|---|---|---|---|
| core diff | 71 | 71 | 71 | 71 |
| ext diff | 0 | **105** | 0 | **100** |
| ext_libs_diff | 0 | **1** | 0 | **1** |
| diffed_libs | `libc.so` | `libc++.so,libc.so` | `libc.so` | `libc.so,libc++.so` |

Run A has the gadget loaded but nothing hooked; run B has eight inline hooks placed in `libc++`.
The ext bucket moving 0 → 105 is the measurement under test, and it raised
`android_code_integrity_violation +90` → `block`.

**The name-based probes never fired.** No `android_frida_runtime_artifact`, no
`android_frida_port_open` — the library is not called frida and the port is not 27042. What caught
it was `android_code_integrity_violation` (bytes in memory differing from bytes on disk) and
`android_instrumentation_runtime_thread` (Gum thread names compiled into the framework). Both are
structural; neither can be renamed away.

The `core diff = 71` in *both* runs is Frida's own patch to libc at gadget load. DESIGN.md 28.8
records "the recurring `core_diff=71`" from the NDK implementation, and 28.8's hooked run recorded
`ext_diff_bytes=105`, `ext_libs_diff=1`, `diffed_libs=libc.so,libc++.so`. This pure-C# port
reproduces all four numbers.

Item 11 (restore) passed on both: reinstalling the clean APK returned every bucket to `diff 0` and
`diffed_libs=<none>`.

Items 9, 10 and 12 were not run. Item 9 as written asks for detection *by name*, and this run
deliberately defeated that; the harder structural version is item 14 above. Items 10 and 12 both end
in an account operation, which the W^X finding below makes unreachable.

## Requirement 3 — an attacker altering the app's own bytes is caught

Item 14 proves the *ext* bucket fires on a hooked system library. This proves the *app* bucket fires
when the application's own native code is altered, which is the property that matters most to a
customer: it is their code an attacker wants to patch.

Same method, aimed at a library under `/data/app` instead of a system one. One variable changed
between the runs — eight inline hooks placed in the app's own `libSystem.Native.so`:

| run | app compared | app diff | app libs | diffed_libs | new reason |
|---|---|---|---|---|---|
| A — gadget loaded, app untouched | 12,797,736 | **0** | 0 | `libc.so` | — |
| B — 8 hooks in the app's own library | 13,070,504 | **108** | **1** | `libSystem.Native.so,libc.so` | **`android_app_code_modified +90`** |

The hooked module's path confirms the bucket:
`/data/app/com.example.devicefingerprinting_dotnet-…/lib/arm64/libSystem.Native.so`.

Restoring the clean APK returned every bucket to `diff 0` with `diffed_libs=<none>`, and six
consecutive scans of the restored build completed cleanly at `78/review`.

**A known limitation of the managed implementation.** Lifting `PROT_READ` on an execute-only mapping
and reading it with `Marshal.Copy` is a pointer read: if a mapping were unmapped between the
`/proc/self/maps` snapshot and the copy, the result is a SIGSEGV, which .NET cannot catch and which
would take the process down. The targets are libraries that are never `dlclose`d, and one incomplete
run was seen immediately after a reinstall and did not reproduce in six further attempts, so this is
recorded as a bounded risk rather than an observed defect.

## The finding that blocks item 2: the Mono runtime maps W^X memory

A clean .NET Android device scores **78 / review**, not the 18 / trusted a clean Flutter device
scores. The whole difference is `android_wx_memory +60`.

It is not a false positive. The Mono runtime really does map writable-and-executable pages — 20
anonymous `rwxp` regions with the JIT, and still **14 with full AOT**, because Mono allocates
trampolines regardless. The probe is reporting the truth.

The consequence is not "a worse score". `_enforce_integrity_gate` admits **only** `trusted`;
`elevated` (≥30), `review` (≥60) and `block` (≥90) all return 403. Since W^X alone is +60, a .NET
Android client scores at least 60 even with developer options and ADB off, so **it can never pass
the gate as the server currently scores Android**. Account registration, login, `/v1/account/me`,
`/v1/policy/me` and refresh are all unreachable in enforce mode.

### Why Flutter does not trip this and .NET does

The difference is not "native versus managed". It is one runtime's allocator policy, and both
behaviours are visible **in a single .NET process on one handset**, because that process runs ART and
Mono side by side:

```
--- WRITABLE + EXECUTABLE (what android_wx_memory counts) ---
regions=6  anonymous=6  file_backed=0  total=384 KB
  rwxp      64 KB  anonymous (no backing file)     <- Mono's code manager

--- ART JIT CODE CACHE (same pages, separate views) ---
  rw-s   32768 KB  /memfd:/jit-cache (deleted)     <- ART writes here
  r-xs   32768 KB  /memfd:/jit-cache (deleted)     <- ART executes here
  r--s   32768 KB  /memfd:/jit-cache (deleted)
```

ART has a JIT and compiles code at runtime, exactly as Mono does, and it contributes **zero** to
`wx_mappings` — because it maps the same memfd three times and never grants write and execute
together. That is deliberate W^X separation.

Mono's code manager maps one anonymous region that is writable and executable at once, and does so
even in an AOT build, because trampolines (delegate invoke, generic sharing, interface dispatch,
marshalling stubs) are still generated at runtime.

So a Flutter release build scores zero for three reasons that all hold at once: its Dart code is
AOT-compiled into `libapp.so` and mapped `r-xp`, the Dart AOT runtime has no JIT at all, and the ART
underneath it separates write from execute. A .NET build inherits the same clean ART, then adds
Mono.

**The consequence for any server-side rule.** "Trust managed runtimes" is the wrong shape, because
ART is a managed runtime with a JIT and it already passes. The real distinguishing property is the
allocator's W^X policy, whose observable signature is *anonymous, unbacked, simultaneously writable
and executable*. That is honest, but it is not a clean discriminator either: an injected hook
trampoline has the same signature. Mono's regions are uniform 64 KB blocks and there are few of
them, so count and size may help, but this should be treated as a heuristic to be measured, not a
property to be assumed.

### Everything tried, and what it measured

| Attempt | Result |
|---|---|
| Default build (Mono JIT) | 20 anonymous `rwxp` regions |
| `RunAOTCompilation=true` (normal AOT) | **14** regions — reduced, not eliminated |
| Same AOT build, measured seconds after launch | **7** regions — the count grows as Mono compiles, and is never zero |
| `AndroidAotMode=Full` (aot-only) | **app dies on launch**; Android needs JIT-capable paths |
| Search `libmonosgen-2.0.so` for a W^X / dual-mapping switch | no such option exists for android-arm64 |
| NativeAOT / CoreCLR on Android | not available on `net8.0-android` |

The runtime does contain an aot-only mode in which it refuses to "allocate from the global code
manager" — the RWX allocator — which is why that mode was worth trying. It is not usable on Android:
the process terminates during startup.

So there is no honest client-side fix available today. Nothing was changed to hide the signal, and
nothing was changed server-side either — scoring belongs to the server, and this repository is a
client.

**This needs a server-side decision**, and it is the single most consequential result of the .NET
work:

- recognise a managed runtime and weight its trampoline pages differently, or
- score W^X by shape (count, size, provenance) rather than presence, or
- accept that .NET Android clients sit at `review` and give the gate a policy for that.

Items 3–8 above were therefore run with the server in `INTEGRITY_MODE=observe`. That does not
weaken them: proof of possession is verified in `_require_access_proof`, before and independently of
the integrity gate, so `invalid_installation_signature`, `access_proof_replay` and the rest are
exactly as strong in either mode. Item 3's device-token variant was additionally run under
**enforce**, because installation challenge/verify does not pass through the gate at all.

## Code integrity, measured in pure C#

The reference implementation needed an NDK component for this. The .NET port does it with
`/proc/self/maps` and `Marshal.Copy`, no native library — and reproduces the reference's own
numbers on the same handset.

| Bucket | Huawei | OPPO |
|---|---|---|
| core (libc, libart) | 4,808,704 B / diff 0 | 5,058,560 B / diff 0 |
| ext (libc++, libssl, libcrypto, libandroid_runtime, libbinder) | 4,943,872 B / diff 0 | 5,742,592 B / diff 0 |
| app (the app's own native code) | 8,568,272 B / diff 0 | 8,849,720 B / diff 0 |
| execute-only regions unlocked | 11 | 0 |

The Huawei core and ext figures — 4,808,704 and 4,943,872 — are **byte-for-byte the values DESIGN.md
§28.8 recorded from the NDK implementation** on that handset. Two independent implementations
measuring the same thing is the strongest available evidence that the port is correct.

**Android 10 maps system libraries execute-only.** On the Huawei, 283 of 336 executable mappings are
`--xp`, including every core and ext target: `libc.so`, `libart.so`, `libc++.so`, `libssl.so`,
`libcrypto.so`, `libandroid_runtime.so`, `libbinder.so`. A first version skipped unreadable
mappings and both buckets reported `compared_bytes = 0` — **inert, which is indistinguishable from
clean in the score**, and exactly the defect §28.8 records the reference implementation shipping
once. The probe now adds `PROT_READ` for the duration of the copy and restores the original
protection immediately, and reports `xom_regions_unlocked` / `xom_regions_unreadable` so an operator
can see the difference. The OPPO on Android 9 needs no unlocking (`unlocked=0`) and still compares
in full, which exercises both paths.
