# Pinning a build's W^X baseline

## Why a baseline exists

A managed runtime maps writable-and-executable memory by design, so scoring its *presence* refuses
every device running one — which is why a clean .NET Android device scores `android_wx_memory +60`
and cannot pass a gate that admits only `trusted`. Scoring the *excess over what this build is known
to reserve* does not.

That is the same shape as `code_integrity`, the strongest probe in the set: it does not ask whether
executable memory exists, it asks whether it differs from the known image.

## Why it is a build step, not a number someone writes down

The reserved total is a property of the runtime, not of anything a developer can read off a design
document, and **it changes when the app changes**. During this work, removing one redundant
measurement pass from the harness moved the baseline from 1,114,112 to 1,048,576 bytes. Nobody would
have thought to revise a hand-written constant for that, and the stale value would have flagged
every user of the new build.

So it is derived by a command, in the pipeline, from the artefact being shipped.

```bash
export API_BASE_URL=https://<test-endpoint>
dotnet run --project src/DeviceTrust.Cli -- baseline \
    --device <adb-serial> --runs 4 \
    --apk-sha256 $(sha256sum app.apk | cut -d' ' -f1)
```

It exits non-zero and emits nothing unless four cold-start runs agree exactly. On success it prints
the settings to pin next to the APK hash the release already computes:

```
INTEGRITY_ANDROID_APK_SHA256=1509183a…18ee
INTEGRITY_ANDROID_WX_BASELINE_BYTES=1048576
INTEGRITY_ANDROID_WX_GRANULARITY=65536
```

## Three things the command does deliberately

**It measures at report time, not at launch.** Mono compiles more code as the app works, so the
same build measures 393,216 bytes at launch and 1,048,576 bytes once the network, TLS, JSON and
signing paths have run. Pinning the launch figure would flag every real user for legitimately
exceeding it. Each run is therefore a cold start followed by a full scan, and the number is taken at
the moment the integrity report is composed — the moment the server scores.

**It refuses rather than averages.** If the four runs disagree, no baseline is emitted. The likely
cause of disagreement is that something else was running in the process during measurement, and a
baseline derived from that would permanently tolerate it. Taking the maximum, or the mean, would
bake a compromise into the allowance.

**It needs a device, not a guess.** There is no way to compute this from the source.

## Measured

The same release APK, four cold-start runs on each handset:

| device | Android | runs | reserved total | granularity | blocks |
|---|---|---|---|---|---|
| Huawei AQM-LX1 | 10 | 4 | **1,048,576** | 65,536 | 16 |
| OPPO CPH2083 | 9 | 4 | **1,048,576** | 65,536 | 16 |

Identical across two vendors and two OS versions, so the baseline belongs to the **build**, not to
the device — one pinned value covers the fleet. The region *count* varies (the kernel coalesces
adjacent mappings differently run to run, and the Huawei reported 13-14 regions where the OPPO
reported a uniform 16); the total does not. Any rule must key on the total.

## What a server would do with it

Not implemented here — this repository is a client — but the shape the measurements support:

| condition | suggested points |
|---|---|
| no baseline pinned for this APK | `+60`, unchanged, so an unconfigured deployment is not silently weakened |
| `wx_bytes` ≤ baseline and every size class a multiple of granularity | `0` |
| a size class that is not a multiple of the granularity | `+45` — a foreign allocator |
| `wx_bytes` above the baseline | `+15`, or `+40` beyond twice it |

With a Frida gadget present, the measured device reported both signals at once: totals of 1,175,552
and 1,241,088 against a 1,048,576 baseline, and size classes of 4,096 and 28,672 that are not
multiples of 65,536.

**Keyed on the APK hash, never on a runtime name the client reports.** A client that could declare
"I am .NET" could claim the allowance from inside a compromised Flutter app; the installation key
signs the report, but the compromised process composes it. The APK hash is pinned by the operator,
so it cannot be forged by the process under suspicion — and a Flutter build simply pins a baseline
of zero, keeping it exactly as strict as it is today.

## What this change does to the Flutter/Dart client

Short answer: **nothing, by construction** — and the design is arranged so that it cannot,
even if someone configures it carelessly.

### Why Flutter is untouched in the normal case

A Flutter release build maps **no** writable-and-executable memory at all: Dart is AOT-compiled into
`libapp.so` and mapped `r-xp`, the Dart AOT runtime has no JIT, and the ART beneath it separates
write from execute. It scores zero on this probe today and would score zero after the change.

The new logic only engages for a build that has a **non-zero** baseline pinned. A build with no
baseline pinned keeps exactly today's rule — `+60` if any writable-executable mapping is present. So
a Flutter build is in the unchanged path whether or not anyone remembers to configure it.

### The trap, and it is a real one

A naive implementation would compute `excess = wx_bytes - baseline` and score the excess. **That
would silently switch off W^X scoring for the Flutter client entirely.**

`wx_bytes` is a field this .NET collector added. The Flutter collector does not emit it. A server
reading `int(probe.get("wx_bytes") or 0)` gets **0** for every Flutter report — not because the
device is clean, but because the field was never sent. Excess would compute as zero, and a Flutter
device with a live Frida gadget mapping executable memory would score nothing at all.

The rule must therefore be written to fall back on absence, not to treat absence as zero:

```python
wx_count = int(exec_maps.get("wx_mappings") or 0)
wx_bytes = exec_maps.get("wx_bytes")            # None on a client that does not report it

if wx_bytes is None or baseline_bytes <= 0:
    # Today's rule, unchanged. Covers every Flutter report and every
    # unconfigured build.
    if wx_count > 0:
        reason("android_wx_memory", 60)
else:
    ...                                          # baseline-relative logic
```

This is the same class of defect as an integrity bucket reporting `compared_bytes: 0` — an absent
measurement reading as a clean one. It is worth a conformance check of its own: *a report with no
`wx_bytes` field and a non-zero `wx_mappings` must still score 60.*

### Why a Flutter build cannot accidentally acquire an allowance

Someone could try to pin a baseline for the Flutter APK. They cannot get a non-zero one: the
`baseline` command refuses when no writable-executable memory is observed, emitting *"no
writable-and-executable memory was observed, so there is nothing to baseline"* and exiting non-zero.
There is a unit test for exactly that case. The only baseline a Flutter build can be given is
effectively zero, which is defined above to mean today's rule.

### Where Flutter would have to change, if you wanted it to

Nowhere, for this to be safe. But two optional improvements would be available once the server reads
the richer fields:

- Adding `wx_bytes` and `wx_size_classes` to the Kotlin collector would give Flutter reports the same
  forensic detail — useful when investigating an incident, not needed for scoring.
- The `dual_mapped_runtime_code` count would show ART's JIT cache on Flutter devices too, which is a
  positive signal (a runtime that separates write from execute) rather than a risk one.

Neither is required, and neither changes any verdict.

### Net effect per client

| client | today | after the change |
|---|---|---|
| Flutter/Dart release | 0 points (no W^X present) | **0 points, identical path** |
| Flutter/Dart with an injected gadget | +60 | **+60, identical path** (absence-fallback rule) |
| .NET Android, clean, baseline pinned | +60 → refused | **0 points → passes the gate** |
| .NET Android with an injected gadget | +60 | **+45 foreign allocator, plus excess-over-baseline** |
| .NET Android, no baseline pinned | +60 | **+60, unchanged — fails closed** |
