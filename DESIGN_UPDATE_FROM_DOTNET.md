# Proposed DESIGN.md updates, from the .NET SDK session

**What this is.** Changes to `DESIGN.md` section 25.11 that were made while building and validating
the .NET/C# client, written up here rather than applied directly, because `DESIGN.md` is owned by
this repository and the .NET repo only holds a copy that gets refreshed from here. Apply what you
agree with; the .NET repo's copy already carries both edits, so anything not applied here will be
lost the next time that copy is refreshed.

**Why it matters to you and not only to .NET.** One of the findings below is a defect the *server*
would ship if the W^X scoring change is implemented naively — it would silently switch off
writable-executable scoring for the **Flutter** client. That section is the one worth reading even if
you reject the battery edits.

Source: `devicetrust-dotnet-sdk`, validated on the Huawei AQM-LX1 (Android 10) and OPPO CPH2083
(Android 9) against PostgreSQL 18.6 on the shared AWS stack, 2026-09-07.

---

## Change 1 — rename item 9 to say what it actually tests

Item 9 tests detection by *filename*, which §27.11 in this document already proved defeatable: a real
gadget renamed to `libhelper.so` and moved off port 27042 scored `18/trusted` while fully active. The
row does not say so, and a reader may take a passing item 9 as evidence of gadget detection in
general.

**Replace this row:**

```
| 9 | Frida Gadget — detection | `score=100 verdict=block`, `frida_runtime_artifact` +90 | each |
```

**with:**

```
| 9 | Frida Gadget — **name-based** detection (gadget left named `libfrida-gadget.so` on port 27042) | `score=100 verdict=block`, `frida_runtime_artifact` +90 | each |
```

**And add this note** alongside the existing platform notes:

> **Item 9 is the weakest item in the list, and is named to say so.** It tests detection by
> *filename*, which §27.11 already proved defeatable. It is retained because an attacker who does not
> bother to rename should still be caught cheaply, but a passing item 9 says much less than a passing
> item 14 or 16. When running 14 and 16, rename the gadget and move its port deliberately, so that
> only the structural signals can fire — otherwise those items are not testing what they claim.

That last sentence is the operationally important one. When the .NET client ran item 14 with the
gadget renamed and moved to port 27999, neither `android_frida_runtime_artifact` nor
`android_frida_port_open` fired; the detection came only from `android_code_integrity_violation` and
`android_instrumentation_runtime_thread`. Run with the gadget *unrenamed*, item 14 passes for the
wrong reason and proves nothing about the structural probes.

## Change 2 — add item 16, the app bucket

§30.4 records the app bucket being closed on device by controlled byte modification, but the battery
has no item for it. §25.11 is described as the single source of truth, so the item belongs in it.

**Add after item 15:**

```
| 16 | Structural code-integrity (**app bucket**) | hook the app's **own** native code → `app_diff_bytes > 0` → `android_app_code_modified` +90 → `block` | each |
```

**With this note:**

> **Item 16 is item 14 aimed at the application's own code rather than a system library.** It is
> separated because the two catch different attacks and are configured by different server settings:
> 14 raises `android_code_integrity_violation` from the ext bucket, 16 raises
> `android_app_code_modified` from the app bucket, and both are gated behind
> `INTEGRITY_SCORE_EXTENDED_LIBS`. For a customer, 16 is the more directly meaningful of the two —
> it is *their* code an attacker wants to patch — and an app bucket reporting
> `app_compared_bytes: 0` is inert rather than clean, which is invisible in the score.

**Evidence from the .NET run** (Huawei, enforce mode, one variable changed between runs — eight
inline hooks placed in the app's own `libSystem.Native.so`):

| run | app compared | app diff | app libs | diffed_libs | new reason |
|---|---|---|---|---|---|
| A — gadget loaded, app untouched | 12,797,736 | 0 | 0 | `libc.so` | — |
| B — 8 hooks in the app's own library | 13,070,504 | **108** | **1** | `libSystem.Native.so,libc.so` | **`android_app_code_modified +90`** |

---

## The part that affects the Flutter client directly

The .NET client cannot pass the integrity gate at all as Android is scored today, and the fix is a
server-side scoring change. That change has a trap in it that would damage **your** client, so it is
recorded here in full.

### Why .NET is blocked

A clean .NET Android device — locked bootloader, verified boot green, hardware-backed non-exportable
key, every code-integrity bucket at zero — scores `android_wx_memory +60` and is refused, because
`_enforce_integrity_gate` admits only `trusted` (<30). The Mono runtime maps writable-and-executable
memory by design: 20 anonymous `rwxp` regions with the JIT, still 13-16 with full AOT. There is no
client-side fix — `AndroidAotMode=Full` terminates the process on Android, `libmonosgen` exposes no
W^X switch for android-arm64, and NativeAOT is unavailable on `net8.0-android`.

Both behaviours are visible in one .NET process, because it runs ART and Mono side by side:

```
--- WRITABLE + EXECUTABLE (what android_wx_memory counts) ---
regions=16  anonymous=16  file_backed=0  total=1024 KB
  rwxp      64 KB  anonymous (no backing file)     <- Mono's code manager

--- ART JIT CODE CACHE (same pages, separate views) ---
  rw-s   32768 KB  /memfd:/jit-cache (deleted)     <- ART writes here
  r-xs   32768 KB  /memfd:/jit-cache (deleted)     <- ART executes here
```

**ART has a JIT, compiles at runtime exactly as Mono does, and contributes zero** — it maps one
memfd several times and never grants write and execute together. This is why a Flutter release build
scores zero: Dart is AOT-compiled into `libapp.so` and mapped `r-xp`, the Dart AOT runtime has no
JIT, and the ART beneath it separates write from execute. A .NET build inherits that same clean ART
and then adds Mono.

**So "trust managed runtimes" is the wrong rule** — ART is a managed runtime with a JIT and already
passes. The property that differs is the *allocator's* W^X policy.

### The proposed rule

Score W^X against a **per-build baseline pinned by the operator**, keyed on `apk_sha256`, which the
server already pins — never on a runtime name the client reports. A client that could declare "I am
.NET" could claim the allowance from inside a compromised Flutter app; the installation key signs the
report, but the compromised process composes it.

| condition | points |
|---|---|
| no baseline pinned for this APK | `+60`, unchanged — unconfigured deployments are not weakened |
| `wx_bytes` ≤ baseline and every size class a multiple of the granularity | `0` |
| a size class that is not a multiple of the granularity | `+45` — a foreign allocator |
| `wx_bytes` above the baseline | `+15`, or `+40` beyond twice it |

### ⚠ The trap — this would silently disable W^X scoring for Flutter

A naive implementation computes `excess = wx_bytes - baseline`. **`wx_bytes` is a field the .NET
collector added. The Kotlin collector does not send it.** A server reading
`int(exec_maps.get("wx_bytes") or 0)` gets **0** for every Flutter report — not because the device is
clean, but because the field was never sent. Excess computes to zero, and a Flutter device with a
live Frida gadget mapping executable memory would score **nothing at all**.

The rule must branch on the field being *absent*, not treat absence as zero:

```python
wx_count = int(exec_maps.get("wx_mappings") or 0)
wx_bytes = exec_maps.get("wx_bytes")            # None on a client that does not report it

if wx_bytes is None or baseline_bytes <= 0:
    # Today's rule, unchanged. Covers every Flutter report and every
    # unconfigured build.
    if wx_count > 0:
        _integrity_reason(reasons, "android_wx_memory", 60, "...")
        score += 60
else:
    ...                                          # baseline-relative logic
```

This is the same class of defect as an integrity bucket reporting `compared_bytes: 0` and reading as
clean — an absent measurement mistaken for a good one, which §28.8 records shipping once already.
**Suggested conformance check:** a report carrying `wx_mappings > 0` and **no** `wx_bytes` field must
still score `android_wx_memory +60`.

### Net effect per client

| client | today | after the change |
|---|---|---|
| Flutter/Dart release | 0 points (no W^X present) | **0 points, identical path** |
| Flutter/Dart with an injected gadget | +60 | **+60, identical path** via the absence fallback |
| .NET Android, clean, baseline pinned | +60 → refused | **0 → passes the gate** |
| .NET Android with an injected gadget | +60 | **+45 foreign allocator, plus excess over baseline** |
| .NET Android, no baseline pinned | +60 | **+60, unchanged — fails closed** |

A Flutter build cannot accidentally acquire an allowance: the .NET repo's `baseline` command refuses
to emit one when no writable-executable memory is observed, so the only baseline a Dart AOT build can
be given is effectively zero, which is defined above to mean today's rule.

### Where the baseline comes from

It is derived by a command against a device, not written down, because it is a property of the
runtime that changes when the app changes — removing one redundant measurement pass from the .NET
harness moved it from 1,114,112 to 1,048,576 bytes. Measured identically on both handsets:

| device | Android | runs | reserved total | granularity |
|---|---|---|---|---|
| Huawei AQM-LX1 | 10 | 4 | **1,048,576** | 65,536 |
| OPPO CPH2083 | 9 | 4 | **1,048,576** | 65,536 |

Identical across two vendors and two OS versions, so the baseline belongs to the **build**, not the
device. It must be measured at *report* time, not at launch: the same build reads 393,216 bytes at
startup, before the runtime has compiled the network, TLS, JSON and signing paths, and pinning that
figure would flag every real user.

---

## Two smaller notes

**A managed `code_integrity` needs no NDK component.** §28.6 records the Kotlin probe needing native
code because Kotlin cannot dereference an arbitrary address and SELinux blocks `/proc/self/mem`. .NET
does it with `Marshal.Copy`, and reproduces this repository's own Huawei figures exactly — core
4,808,704, ext 4,943,872, the recurring `core_diff=71` from Frida's libc patch, and
`ext_diff_bytes=105` / `ext_libs_diff=1` under a libc++ hook. Not a change request; recorded because
two independent implementations agreeing to the byte is useful evidence that both are right.

**Android 10 maps system libraries execute-only.** On the Huawei, 283 of 336 executable mappings are
`--xp`, including every core and ext target. A reader that skips unreadable mappings reports
`compared_bytes: 0` — inert, and indistinguishable from clean in the score. The .NET probe lifts
`PROT_READ` for the duration of the copy and restores it, and reports `xom_regions_unlocked` /
`xom_regions_unreadable` so the difference is visible. Worth checking that the NDK component handles
the same case, since the OPPO on Android 9 needs no unlocking and would not reveal the problem.
