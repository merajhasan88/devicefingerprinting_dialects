# Session state — 2026-09-20 (end of day)

Where the .NET client stands, so the next session resumes without re-deriving it.

## Battery: 15 of 16 demonstrated on real hardware

| # | item | status |
|---|---|---|
| 1 | clean baseline | iPhone 0/trusted; OPPO/Huawei 78/review (Mono W^X +60) |
| 2 | account through gate | register 201 (+ conformance in enforce) |
| 3 | stolen access token | PASS, cross-device (iPhone→Android) |
| 4 | stolen refresh token | PASS, cross-device |
| 5–8 | access-proof boundaries | PASS (iPhone; correct codes) |
| 9 | Frida name-based detection | **NOT DONE** — deliberately defeated (weakest item; renamed gadget) |
| 10 | Frida enforcement (login 403) | PASS on OPPO and iPhone |
| 11 | Frida restore | PASS on OPPO |
| 12 | device memory, new key | PASS on iPhone (cleanest — no W^X); blocked on Android by W^X |
| 13 | pristine re-enrolment | PASS |
| 14 | ext-bucket code integrity | PASS on OPPO/Huawei; **impossible on iOS** (shared cache has no backing file) |
| 15 | key survives reinstall (iOS) | PASS on iPhone |
| 16 | app-bucket code integrity | PASS on OPPO and iPhone |

**Only item 9 is left as a positive test.** It needs a named-gadget build on the
OPPO (gadget left `libfrida-gadget.so` on 27042) → `android_frida_runtime_artifact`
+ `android_frida_port_open`. Low value; the runbook calls it the weakest item.

## The one standing server-side decision: Mono W^X +60

The .NET Android client scans 78/review because Mono maps writable-executable
memory; Flutter (Dart) does not, so it reads 18/trusted. This caps Android items
1, 2 and 12, and is not a client bug. The fix is server-side baseline-relative
W^X scoring — spec in `docs/wx-baseline-process.md` and
`DESIGN_UPDATE_FROM_DOTNET.md`. Payactiv's/the owner's call, not this SDK's.

## Git

Branch `dotnet`, **2 commits unpushed** (`cb1f45b`, `c1526e9`). Push needs the
user's GitHub credentials (HTTPS, interactive). Everything else is pushed.
`main` is untouched; the .NET tree is an unrelated root on the shared
`devicefingerprinting_dialects` repo.

## Shared test stack (owned by the Flutter session)

- EC2 + local PostgreSQL 16.15 + Redis at `https://devicefingerprinting.duckdns.org`.
- Left in `INTEGRITY_MODE=enforce`, `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1`,
  `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0`. Reverting to observe is the Flutter
  session's call.
- The OPPO's release cert `664e9c8e…de3` is on the Android allow-list.

## Device state

- **iPhone 7** (iOS 15.8.5, TrollStore): clean build installed, but holds a
  blocked verdict in device memory for ~24 h from the item-12 run, so logins
  return `integrity_device_blocked_recently` until it ages out. The
  DeveloperDiskImage mount is benign and clears on reboot.
- **OPPO** (Android 9): clean build, 78/review. Huawei was unavailable today.

## Tooling installed this session (on the Linux workstation)

`~/bin/ldid`, `~/.frida-venv` (frida + frida-tools + lief + pymobiledevice3,
all 17.17.0 where versioned), `libusbmuxd-tools` (iproxy). iOS Frida gadget at
`~/.cache/frida/gadget-ios.dylib` and `~/frida-gadget-ios.dylib`.

## How iOS item 16/10/12 were driven (for repeat)

Re-sign the unsigned IPA with `get-task-allow` (keychain-access-groups kept
byte-identical), no embedded gadget. `pymobiledevice3 mounter auto-mount`, then
`frida.spawn()` the app (DDI debugserver sets `CS_DEBUGGED`), attach, place inline
hooks in the app-bucket image, and **hold the session open across the scan** —
detaching on jailed iOS unloads the agent and crashes the process.
