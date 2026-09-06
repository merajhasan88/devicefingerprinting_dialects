# Handset battery — .NET client on real hardware (2026-09-06)

Run against **PostgreSQL 18.6** (RDS, schema v1, Redis nonces, rate limiting on) with the .NET
harness app `com.example.devicefingerprinting_dotnet`, a **release, non-debuggable, full-AOT** APK
signed with a dedicated release key (`9020 70b6 ... a663`).

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
| 9-11 | Frida Gadget detect / enforce / restore | not run | not run | — |
| 12 | Device memory across a new hardware key | not run | not run | — |
| 13 | Pristine re-enrolment (enrolment half) | **PASS** | — | enforce |
| 14 | Structural code-integrity, ext bucket | not run | not run | — |

Items 3 and 4 are cross-device by construction: the Huawei minted, the OPPO replayed with its own
keystore key. That is the property the desktop harness could only approximate with two software
keys, and it is now proven with two genuinely non-exportable hardware keys on two vendors.

Item 13: uninstalling destroyed the AndroidKeyStore entry, so the reinstall enrolled a **new**
hardware key (`88387af3…` → `e356cee7…`) under a new `installation_id`, and the server still
correlated it to the **same** `device_id` through the reinstall hint — `reinstall_hint / medium`,
installations 1 → 2.

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

Nothing was changed client-side to hide this, because there is nothing honest to change: full AOT
was tried and reduced the count without eliminating it, and NativeAOT for Android is not available
on `net8.0-android`. Nothing was changed server-side either — scoring belongs to the server, and
this repository is a client.

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
