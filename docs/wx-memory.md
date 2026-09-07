# Writable-and-executable memory: why .NET trips it, and what can be measured

## The problem

A clean .NET Android device — locked bootloader, verified boot green, hardware-backed
non-exportable key, every code-integrity bucket at zero — scores `android_wx_memory +60` and is
refused at the gate, which admits only `trusted`. There is no configuration of a *healthy* .NET
device that passes. A Flutter device on the same handset scores 18 and passes.

## Why the two differ

Both behaviours are visible in a single .NET process, because it runs ART and Mono side by side:

```
--- WRITABLE + EXECUTABLE (what android_wx_memory counts) ---
regions=14  anonymous=14  file_backed=0  total=1088 KB
  rwxp      64 KB  anonymous (no backing file)     <- Mono's code manager

--- ART JIT CODE CACHE (same pages, separate views) ---
  rw-s   32768 KB  /memfd:/jit-cache (deleted)     <- ART writes here
  r-xs   32768 KB  /memfd:/jit-cache (deleted)     <- ART executes here
  r--s   32768 KB  /memfd:/jit-cache (deleted)
```

ART has a JIT, compiles at runtime exactly as Mono does, and contributes **zero** — it maps one
memfd several times and never grants write and execute together. Mono's code manager maps anonymous
regions that are both at once, and does so even in an AOT build, because trampolines are generated
at runtime regardless.

A Flutter release build scores zero for three reasons at once: Dart is AOT-compiled into `libapp.so`
and mapped `r-xp`, the Dart AOT runtime has no JIT, and the ART beneath it separates write from
execute. A .NET build inherits the same clean ART and then adds Mono.

**So "trust managed runtimes" is the wrong rule.** ART is a managed runtime with a JIT and already
passes. The property that differs is the *allocator's* W^X policy.

## What was tried, client-side

| Attempt | Result |
|---|---|
| Default build (Mono JIT) | 20 anonymous `rwxp` regions |
| `RunAOTCompilation=true` | 13-16 regions — reduced, not eliminated |
| `AndroidAotMode=Full` (aot-only) | **app dies on launch**; Android needs JIT-capable paths |
| Search `libmonosgen-2.0.so` for a W^X switch | no such option for android-arm64 |
| NativeAOT / CoreCLR on Android | not available on `net8.0-android` |

There is no honest client-side fix on .NET 8.

## The finer measurement, and what it shows

`exec_mappings` now reports the *shape* of writable-executable memory rather than only its presence.
All fields are raw measurements; the client computes no verdict.

`wx_bytes`, `wx_mappings`, `wx_unlabeled`, `wx_labeled`, `wx_file_backed`, `wx_smallest_bytes`,
`wx_largest_bytes`, `wx_size_classes`, `dual_mapped_files`, `dual_mapped_runtime_code`,
`execute_only_mappings`, `readable_exec_mappings`.

Measured on a Huawei AQM-LX1, same release binary, cold start each time, read back from the server's
own store:

| run | verdict | regions | wx_bytes | size classes | ext_diff |
|---|---|---|---|---|---|
| clean | review | 13 | **1,114,112** | `196608:2,65536:11` | 0 |
| clean | review | 15 | **1,114,112** | `131072:2,65536:13` | 0 |
| clean | review | 15 | **1,114,112** | `131072:2,65536:13` | 0 |
| clean | review | 16 | **1,114,112** | `131072:1,65536:15` | 0 |
| + Frida gadget, no hooks | block | 19 | 1,175,552 | `131072:1,65536:15,`**`28672:2,4096:1`** | 0 |
| + Frida gadget, 8 hooks in libc++ | block | 20 | 1,241,088 | `131072:1,65536:16,`**`28672:2,4096:1`** | 105 |

Three things fall out.

**1. `wx_bytes` is exactly constant across clean runs.** 1,114,112 bytes in all four, even though the
region count varied 13-16 and the size classes varied. Mono reserves a fixed total and merely splits
it differently between runs. Count is noisy; the total is not. Any rule should key on the total, not
the count.

**2. Frida exceeds that total.** 1,175,552 and 1,241,088, both above the clean constant.

**3. Every clean size class is a multiple of 65,536.** Frida introduces `28672` and `4096`, neither
of which is. That is a different allocator's granularity showing through, and it appears as soon as
the gadget is *loaded* — before any hook is placed.

## What this does and does not support

It supports a rule of the shape *"compare against this build's measured baseline"* — the same move
that makes `code_integrity` strong. `code_integrity` does not ask "is executable memory present", it
asks "does it differ from the image on disk". W^X scored by presence is the naive form of the same
question; scored against a per-build baseline it becomes useful.

It does **not** support treating shape as proof, and the data says so directly. The increment from
actually placing the hooks was one more 65,536-byte region — the same size class Mono uses,
indistinguishable in isolation. What gave Frida away was its *runtime's* own 4 KB and 28 KB
allocations, not the trampolines. An attacker who confined every allocation to 64 KB multiples and
stayed inside the baseline total would blend in.

And the whole channel is self-reported: an attacker in the process can edit these numbers before the
report is signed. This is baselining, not attestation — useful exactly as far as the rest of the
local measurements are, and no further.

In this experiment the gadget was caught regardless, by `android_code_integrity_violation` and
`android_instrumentation_runtime_thread`, both structural and neither defeatable by renaming. Those
remain the load-bearing probes. W^X shape is corroboration worth having, not a replacement.
