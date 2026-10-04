# Why a pinned .NET build keeps scoring `android_wx_above_baseline` +15

**Status: open.** Measured on 2026-10-04 on the OPPO CPH2083 (Android 9). This file states the problem
and its cause, gives the evidence, and lays out the options with their trade-offs, so that a decision
can be made. The background — why .NET maps writable-and-executable (W^X) memory at all, and why the
server scores it against a per-build baseline — is in `docs/wx-memory.md` and
`docs/wx-baseline-process.md`.

## The problem in one paragraph

The server allows a .NET Android build a fixed amount of W^X memory: a **baseline** measured from four
cold starts and pinned per APK hash. A report at or under it scores 0; anything above, up to twice
the baseline, scores `android_wx_above_baseline` **+15**. The baseline is measured at the **first**
integrity report after a cold start. But the .NET runtime on Android (Mono) **compiles code while the
app runs**, every method on its first call, into W^X memory that is never released while the process
lives. So the total only ever grows: every report made later in the same process — after a login, a
step-up or anything else the first report had not exercised — exceeds the pinned figure and scores
+15. On the test handset, which already carries 18 points (developer options +8, ADB +10), that is
**33, `elevated`** — which, in enforce mode, refuses login, account registration and token refresh
(`integrity_elevated`).

## The rule the server applies

From `device_trust_server.py` in the reference repository (`_score_wx_memory`, DESIGN.md §62–63),
for a build with a pinned baseline `<apk_sha256>:<bytes>:<granularity>`:

| Condition | Points |
|---|---|
| no baseline pinned, no `wx_bytes`, or figures that contradict each other | `android_wx_memory` +60 |
| a mapping size that is not a multiple of the granularity | `android_wx_foreign_allocator` +45 |
| `wx_bytes` > 2 × baseline | `android_wx_far_above_baseline` +40 |
| baseline < `wx_bytes` ≤ 2 × baseline | `android_wx_above_baseline` **+15** |
| `wx_bytes` ≤ baseline, every size a multiple of the granularity | 0 |

Verdict bands (`_integrity_verdict`): `trusted` < 30 ≤ `elevated` < 60 ≤ `review` < 90 ≤ `block`.
In enforce mode an `elevated` verdict refuses login, account registration and refresh outright; on
other account requests a step-up proof for that request satisfies it (DESIGN.md 63.9).

## Why the total grows: the mechanism

- **Mono JIT-compiles each managed method on its first call** and places the code in memory that is
  mapped readable, writable and executable at once (`rwxp`, anonymous). ART — and therefore Flutter
  and Kotlin — keeps write and execute in separate views of one `memfd` and contributes nothing
  (`docs/wx-memory.md`).
- **That memory comes in 64 KiB units.** Every size the collector has ever seen from a clean .NET
  build is a multiple of 65,536 (classes of 64, 128 and 192 KiB). This is consistent with Mono's code
  manager reserving executable memory in chunks of at least 64 KiB; when the current chunk is full, a
  new one is mapped. *(The allocator detail is inferred from the measurements and Mono's code manager;
  a reviewer who knows `mono-codeman` should confirm it.)*
- **Nothing is unmapped while the process lives.** Compiled code stays for reuse, so `wx_bytes` is
  monotonic within a process.
- **The amount depends on which code has run.** A cold start followed by an integrity scan always
  runs the same code, so it always reserves the same total — which is why the four-run baseline is
  reproducible to the byte. A login, a step-up re-enrolment or a step-up signature each run methods
  the scan never called (account JSON, the AndroidKeyStore step-up key, the confirm-credential and
  BiometricPrompt paths, more HTTP and JSON shapes). Each crosses into new 64 KiB chunks.
- **Nothing in the report says which point of the app's life it was taken at.** The server compares
  every report from the build with one figure measured at one point.

This repository's own record already showed the effect at a coarser scale: the same earlier build
measured 393,216 bytes at launch and 1,048,576 once the network, TLS, JSON and signing paths had run
(`docs/wx-baseline-process.md`). The baseline command was built to measure "at report time" for that
reason. What was not measured until now is that report time is not one point: an app reports again
and again in one process, after doing more each time.

## Evidence (build `58396d51…`, OPPO CPH2083, Android 9)

Read back from the server's own `integrity_reports` table; the pinned baseline is `3735552:65536`.

**Cold starts agree.** Of 18 runs of the `baseline` command (each a cold start followed by one scan),
16 read exactly 3,735,552 bytes, including ten consecutive runs. The two exceptions read 3,801,088
(one 64 KiB chunk more): the very first launch after install, which also created the step-up key, and
one run that has not been explained.

**One process, one session, growing.** The owner's step-up session on the same handset, each row a
report the app made before the operation named (the app was not restarted between them):

| UTC | Operation | `wx_bytes` | Mappings | Size classes | Score |
|---|---|---|---|---|---|
| 18:04:02 | scan (cold start) | **3,735,552** | 46 | `196608:4,131072:3,65536:39` | 18 trusted |
| 18:05:42 | log in | 4,063,232 | 49 | `196608:5,131072:3,65536:41` | **33 elevated** |
| 18:05:56 | re-enrol step-up key | 4,128,768 | 49 | `196608:5,131072:4,65536:40` | **33 elevated** |
| 18:06:13 | sensitive op without step-up | 4,128,768 | 49 | `196608:5,131072:4,65536:40` | **33 elevated** |
| 18:06:23 | sensitive op with step-up | 4,194,304 | 50 | `196608:5,131072:4,65536:41` | **33 elevated** |

The same pattern recurred during the dead-key test that evening: the first scan read 3,735,552,
and the scans made after the owner had logged in and run the step-up flows read 4,128,768 (33,
`elevated`). Every size remained a multiple of
65,536, so `android_wx_foreign_allocator` never fired, and every total stayed far below twice the
baseline, so `android_wx_far_above_baseline` never fired either. Growth after the scan: at most 458,752 bytes (+12 %) so far,
exactly seven 64 KiB units.

**iOS is not affected.** .NET on iOS is fully AOT-compiled (Apple forbids a JIT), and the W^X probe is
an Android probe.

## What it means in practice

| Device | Base score | First report after a cold start | Any later report in the same process |
|---|---|---|---|
| Test handset (developer options and ADB on) | 18 | 18, trusted | **33, elevated** — enforce refuses login, registration and refresh |
| Typical consumer phone (both off) | 0 | 0, trusted | 15, trusted |
| Any phone with one other ≥ 15-point signal | ≥ 15 | trusted or elevated | **≥ 30, elevated** |

A real application exercises far more code than this harness — a MAUI user interface JIT-compiles its
screens as the user visits them — so its growth after the baseline point is likely to be larger than
the +12 % measured here, possibly past 2 × the baseline, where the score becomes +40 and even a
consumer phone reads `elevated`. That has not been measured.

## Options

| | Option | What it changes | For | Against |
|---|---|---|---|---|
| A | **AOT-compile the app** (`RunAOTCompilation=true`, all assemblies rather than a startup profile) | Most methods are precompiled into file-backed `r-x` code, so far less is compiled at run time | Fixes the cause on the client; keeps the server rule strict | Not eliminated: Mono still generates trampolines and code AOT cannot cover (some generics, dynamic methods). An earlier measurement saw the region count fall from 20 to 13–16, not to 0. Larger APK, longer builds. `AndroidAotMode=Full` (no JIT at all) made the app die at launch on .NET 8. **Not yet measured for session growth.** |
| B | **Mono interpreter** (`UseInterpreter=true`) | Methods are interpreted instead of compiled to native code | Might stop the growth entirely | Slower; whether trampolines still grow is unknown; unusual for a release build. Not measured. |
| C | **A runtime without a JIT** (NativeAOT, or CoreCLR, on Android) | No `rwxp` memory at all, as with Flutter | The clean answer: the probe stops needing an allowance | Not available on `net8.0-android`; the status for .NET 9/10 Android needs checking. A platform migration. |
| D | **Measure the baseline at the end of a full session**, not at the first report | Pins the plateau a complete session reaches | No server change; strict above the plateau | For a real app the plateau depends on which screens the user visits, so a measured session can still be exceeded in the field. The four-run agreement rule gets harder to meet. |
| E | **Server tolerance for consistent growth** — score `android_wx_above_baseline` lower (≤ 11, so that 18 + it stays < 30) or report-only, while the shape stays consistent and every size stays a multiple of the build's granularity | Growth is still recorded; the strong signals still fire (`foreign_allocator` +45, `far_above` +40, and above all `code_integrity` and the instrumentation-thread probe) | Matches what the data says: legitimate growth is in the runtime's own units | Weakens one signal: an attacker who allocates in 64 KiB units and stays under 2 × the baseline would gain nothing from it. `docs/wx-memory.md` already records that such an attacker blends in on shape alone; the load-bearing probes are `code_integrity` and the instrumentation-thread check. A server decision, not this SDK's. |
| F | **A per-build ceiling** — pin `<apk>:<baseline>:<granularity>:<ceiling>`, with the ceiling taken from a measured session | Allows measured growth explicitly, per build | Explicit and auditable | Needs a session measurement procedure (D) and a server change (E). |

## The .NET session's recommendation

1. **Measure A first.** It is the only option that removes the cause on the client and leaves the
   server rule as strict as it is. Build with `RunAOTCompilation=true` and full (not profiled) AOT, pin
   its baseline, then repeat the session above and compare the growth.
2. **If growth remains, decide between E and F on the server.** The data so far supports E: in every
   clean measurement the growth came only in the runtime's own 64 KiB units and stayed far below 2 ×,
   which are the conditions E keeps. F is more conservative but depends on a session measurement that
   a real app cannot reproduce exactly.
3. **Track C** as the long-term answer for Android, as Flutter already gets it.

## Questions for the reviewer

1. Is it acceptable to stop scoring (or to score below 12) W^X growth that keeps the build's own
   granularity and stays under 2 × its baseline, given that `code_integrity` and the
   instrumentation-thread probe are the load-bearing detections? If not, what bound would be?
2. Should the baseline describe the first report after a cold start (today) or a session plateau?
3. Is a full-AOT release build the right client fix for .NET 8 on Android, and is there a known way to
   stop Mono mapping RWX memory for trampolines?
4. Is NativeAOT or CoreCLR on Android in a state worth planning towards for .NET 10?
