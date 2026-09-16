# Bringing the .NET client up on iOS

**Status of your iOS code today.** `docs/validation.md` says it plainly: `Apple/SecureEnclaveInstallationKeyStore.cs`
and `Apple/AppleIntegrityCollector.cs` were written against documented Xamarin.iOS APIs and **have
never been compiled**. That is exactly where the Flutter reference client was on 2026-09-08. It is
now enrolling, reporting integrity and being correctly blocked on a physical iPhone 7, with no Mac
and no paid Apple Developer account anywhere in the path.

This document is what that cost to find out, written so you do not pay it again. Everything here was
measured on the device unless explicitly marked as untested.

Reference material in the other repository: `DESIGN.md` §35 (first run), §37 (the `+35` floor),
§39 (what the device reports), §40 (enforce-mode proof), §41 (a contract bug your collector would
have tripped).

---

## 1. Read this first — a contract bug that affects your collector directly

Your `AppleIntegrityCollector.ProbeCodeSigning()` does this:

```csharp
var applicationIdentifier = ReadStringEntitlement("application-identifier")
                            ?? ReadStringEntitlement("com.apple.application-identifier");
...
.With("signing_identifier", applicationIdentifier ?? string.Empty)
```

The Swift collector puts a **different value** in that same field: the **CodeDirectory identifier**,
read out of the Mach-O signature. On a legitimately signed app the two look like this:

| collector | value |
|---|---|
| Swift | `com.example.app` |
| .NET (yours) | `ABCDE12345.com.example.app` |

The server gained a rule on 2026-09-14, `ios_signing_identifier_bundle_mismatch` (+90), which
compares `signing_identifier` to `app_identity.bundle_id`. It originally required **exact** equality.
Under your convention that is never true, so the rule would have raised +90 on every clean .NET iOS
device — and 90 is the block band.

**This is already fixed server-side**: the rule now accepts `signing_id == bundle_id` *or*
`signing_id.endswith("." + bundle_id)`, so both conventions pass and a fake signature
(`TROLLTROLL.com.someone.else`) is still caught. You do not need to change anything to be safe.

**But prefer the CodeDirectory identifier if you can read it.** It is the stronger measurement: it
describes what is embedded in the binary rather than what the kernel was told at launch, and it
degrades honestly on an unsigned build. The Swift implementation parses `LC_CODE_SIGNATURE` into the
embedded SuperBlob and takes the CodeDirectory's `identOffset` — about 60 lines, no private API. If
you do switch, say so, because the server rule's tolerance exists only to accommodate the entitlement
form.

The general lesson, recorded as §41: **a probe field is a contract between two independently written
collectors, and the field name alone does not pin it down.** This was found only by reading both
implementations side by side. Neither test suite could have found it — each was written from its own
client's convention and would have agreed with itself indefinitely.

## 2. `SecTask*` — your P/Invoke may or may not resolve

`AppleIntegrityCollector.cs` P/Invokes `SecTaskCreateFromSelf` and `SecTaskCopyValueForEntitlement`
from `Security.framework`. Those are declared in `Security/SecTask.h`, which Apple ships as public
API on **macOS only**; on iOS they are private.

The Swift client used the same functions and **failed to compile** — the symbols are not in the iOS
SDK's module map. Your P/Invoke is a different situation and I have **not** tested it: `DllImport`
resolves at runtime, so it will build cleanly either way, and whether it works depends on whether the
symbol is exported from the iOS Security binary. Treat it as unverified, and note that a probe that
silently returns nothing is worse than one that fails loudly — your `entitlements_readable` field is
the right instinct, so make sure it reports `false` rather than letting the probe look clean.

The replacement that is known to work is parsing the app's own Mach-O, which needs no Apple API at
all. `Bundle.main.executableURL` → walk load commands for `LC_CODE_SIGNATURE` (`0x1d`) → the embedded
SuperBlob (`0xfade0cc0`) → slot 0 is the CodeDirectory (`0xfade0c02`, identifier at `identOffset`),
slot 5 is the entitlements plist (`0xfade7171`). All fields inside the signature are **big-endian**
regardless of host. Fat images resolve to the arm64 slice. Read the bytes one at a time rather than
loading through a typed pointer — the offsets are not guaranteed to be aligned.

## 3. The Mac-free build and install path

Every step runs on Linux.

1. **Codemagic** builds the `.ipa`. The free tier is 500 macOS minutes/month; an iOS build costs
   10–20. Note your own `DeviceTrust.Client.Maui.csproj` only enables `net8.0-ios` under
   `Condition="$([MSBuild]::IsOSPlatform('OSX'))"` — Codemagic's `mac_mini_m2` satisfies that, so
   the conditional is fine as written. Build **unsigned**; `flutter build ipa`'s .NET equivalent
   still wants signing, so produce the `.app` and zip it into `Payload/` yourself.
2. **A free Apple ID** — needed only to sign an installer once. See the trap in §4.
3. **Sideloader** (Dadoum) signs and installs over `usbmuxd`. It ships a prebuilt Linux x86_64
   binary; PlumeImpactor is source-only and AltServer-Linux is from 2022.
4. **TrollInstallerX** exploits the kernel, installs a persistence helper into **Tips**, and installs
   **TrollStore**.
5. **TrollStore** installs your unsigned `.ipa` permanently — no 7-day certificate expiry, because
   TrollStore signs it, not Apple.

Once TrollStore is on the device, steps 2–4 never repeat. You only need step 1 and an install.

## 4. The traps, in descending order of time lost

**A browser-created Apple ID is not activated.** Developer-session creation fails with
`-22411 "This action cannot be completed at this time"`. Apple completes account setup on the first
sign-in **on a device**, when the iCloud terms are accepted. Sign in on the phone, then immediately
turn **Find My off** — Find My *is* Activation Lock, and leaving it on binds the device to that Apple
ID for every future restore.

**A sideloaded app that flashes and closes is an unsigned nested binary.** This will bite you harder
than it bit Flutter: a MAUI bundle carries many more nested dylibs. The device crash report names it
exactly, and is readable over USB with `pymobiledevice3 crash ls` / `crash pull`:

```
termination: DYLD "Library missing"
  Library not loaded: '@loader_path/libxpf.dylib'
  Reason: code signature invalid (errno=1)
```

Signing tools walk `Frameworks/` and `PlugIns/`. A dylib sitting at the **bundle root** is missed.
The fix is to move it into `Frameworks/` and patch the load command with `llvm-install-name-tool`.

**Everything TrollStore installs gets `get-task-allow`**, so its JIT option works. That is +35 from
`ios_get_task_allow`, and it gave the test iPhone a permanent floor — the device could never read
`trusted`. Do **not** work around it with `INTEGRITY_ALLOW_DEBUG=1`: that flag gates **six** rules
across both platforms, including `ios_process_traced` (+50), so it would blind the server to a
debugger actually attaching.

The real fix is to pre-sign before TrollStore sees the file. TrollStore *preserves* entitlements
already present in a binary instead of applying its defaults:

```
ldid -S<entitlements.plist> -I<bundle-id> <the app's main executable>
```

Supply exactly the entitlements TrollStore would have granted, minus `get-task-allow`. Read them off
the device rather than guessing — `pymobiledevice3 apps list` exposes the installed app's
`Entitlements` dictionary. For the Flutter client they were:

```
application-identifier                          TROLLTROLL.*
com.apple.developer.team-identifier             TROLLTROLL
com.apple.private.security.container-required   <your bundle id>
keychain-access-groups                          [TROLLTROLL.*, com.apple.token]
```

**`keychain-access-groups` must be reproduced byte for byte.** The Secure Enclave key lives in that
access group. Change the value and the existing key becomes unreachable, the app silently generates a
new one, and your installation identity resets on every rebuild. Verified: after re-signing with the
value unchanged, the app reported `Key created this launch: No` and kept the same key thumbprint
across a rebuild, a re-sign and a reinstall.

There is a working script in the other repository: `tools/presign_trollstore_ipa.sh`. It fails closed
if `get-task-allow` survives signing. `ldid` has no Debian package; use the static Linux build from
`ProcursusTeam/ldid` releases.

**You cannot pin `INTEGRITY_IOS_EXECUTABLE_SHA256` to the artifact you built.** TrollStore rewrites
the binary during installation:

```
Codemagic, unsigned      382,016 bytes
after ldid pre-sign      386,384 bytes   ← what you ship
on device, as reported   425,123 bytes   ← what the probe measures
```

The baseline must be the device-reported value. Pinning the build artifact's hash would hard-block
every device on first contact.

## 5. What the server does with an iOS report now

Two rules landed on 2026-09-14, **both report-only by default** behind
`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE` (default `0`):

| rule | weight | fires when |
|---|---|---|
| `ios_signing_identifier_bundle_mismatch` | 90 | identifier is neither `bundle_id` nor `TEAMID.bundle_id` |
| `ios_known_fake_team_identifier` | 25 | team identifier is in `IOS_KNOWN_FAKE_TEAM_IDS` (`TROLLTROLL`) |

A report-only reason appears with `points: 0`, `hard: false`, plus `report_only: true` and
`proposed_points`, so an operator can see what enabling it would cost. Those two keys appear **only**
in the report-only case, so nothing downstream changes shape when the flag is flipped.

`/health/ready` now reports `scoring_flags`, which tells you whether a low score means "clean" or
"the rule is inert".

**Expect a TrollStore-installed app to be blocked once that flag is on.** Measured on the iPhone 7 in
enforce mode: `score 100`, `verdict block`, `hard_block false`, and `POST /v1/accounts/register`
refused with `403 integrity_blocked`. The score is 100 rather than 115 because `_score_integrity`
caps the total — two rules at 90 and 25 present identically to one rule at 100, so weights order
which combinations reach a band rather than accumulating without limit.

The second rule is deliberately the weaker of the two and is commented as such: it is a **name
match**, and §27.11 already proved on Android how those end, with a renamed Frida gadget scoring
`18/trusted` while fully active. One patched constant in a TrollStore fork defeats it.

## 6. Things that should be easier for you than they were for Flutter

**The W^X problem probably does not exist on iOS.** `android_wx_memory` blocks the .NET Android
client because Mono's code manager maps writable-executable memory. iOS forbids JIT for ordinary
apps and .NET for iOS is fully AOT, and the iOS scorer has **no W^X rule at all**. I have not
measured this — check it early, because if it holds, the iOS client may reach `trusted` on a path the
Android client cannot.

**Your Secure Enclave access control already matches what works.**
`SecAccessControl.Create(SecAccessible.AfterFirstUnlockThisDeviceOnly, SecAccessControlCreateFlags.PrivateKeyUsage)`
is exactly what the Swift client uses, and it is verified on the iPhone 7 — including the part that
mattered: the key is usable unattended with **no passcode set** on the device.

**`SHA256withECDSA` and `ecdsaSignatureMessageX962SHA256` both emit ASN.1 DER**, and the server
accepted the iOS signature with no server change. Your `EcdsaSignatureFormat.SignDer` rule is the
right one; `SecKeyCreateSignature` with `ecdsaSignatureMessageX962SHA256` is the Apple equivalent.

## 7. The hardware, and the standing conditions

**One iPhone 7** (`iPhone9,3`, A10, arm64, iOS 15.8.5, no passcode, TrollStore installed). It is
shared, and it is **not disposable** — the owner has said so explicitly. It is not jailbroken; it
runs stock iOS. A DFU restore always works because the A10 bootrom is checkm8-vulnerable, but Apple
no longer signs 15.8.5, so a restore lands on 15.8.8. Coordinate before doing anything that needs a
restore.

**AWS.** `docs/aws-test-stack.md` is binding and unchanged. The account is personal, roughly
PKR 500/month. Never create resources unasked, never allocate an Elastic IP, never a NAT Gateway,
stop the EC2 instance rather than terminating it, and delete any database in the session that created
it.

One change worth knowing: on 2026-09-14 PostgreSQL 16.15 was installed **locally on the EC2
instance** for a run where the question was not a database question. It persists across stop/start,
so a session that only needs *a* working backend can skip RDS entirely. **Results intended as
portability evidence should still be taken on RDS**, and the backend should be named in whatever
record you write.

## 8. What is verified, and what is not

**Verified on the device:** Secure Enclave P-256 key creation and loading, hardware backing recorded
server-side, ES256/DER signature accepted, iOS reinstall correlation, the integrity gate both
refusing and admitting, `get-task-allow` removal via `ldid`, key survival across rebuild and
reinstall, and the fake-signature rule firing on a real TrollStore install in enforce mode.

**Not verified, by anyone:** a **legitimately Apple-signed** iOS build. Nothing in this rig can
produce one, because that needs a paid developer account. This is why
`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE` stays `0` — the false-positive side of both rules rests on
conformance fixtures rather than a real signed app. If your side ever gets access to a paid account,
that single observation is the most valuable thing you could contribute to the iOS work.

**Not verified for .NET specifically:** anything in your `Apple/` folder. It has still never been
compiled.

## 9. Which of the 16 battery items apply on iOS

`docs/handset-battery.md` here, and §25.11 in the reference repository, both define the canonical
**16-item** battery. It was written for two Android handsets, before an iPhone existed. Roughly ten
of the sixteen transfer; the rest are Android-specific by construction, not by omission.

| # | Item | iOS | note |
|---|---|---|---|
| 1 | Clean baseline scan | ⚠️ restate | `score=18` is Android (developer options +8, ADB +10). The iOS equivalent is `score 0 / trusted`, and only on a pre-signed build — see §4 |
| 2 | Account creation through the enforce gate | ✅ | protocol-level |
| 3 | Stolen access token | ✅ | cross-device; iPhone paired with an Android handset works |
| 4 | Stolen refresh token | ✅ | cross-device, same pairing |
| 5 | Boundary: exact replay | ✅ | platform-agnostic |
| 6 | Boundary: body tampering | ✅ | platform-agnostic |
| 7 | Boundary: path + method tampering | ✅ | platform-agnostic |
| 8 | Boundary: stale timestamp | ✅ | platform-agnostic |
| 9 | Frida Gadget — name-based detection | ❌ | written for injecting a gadget into an APK |
| 10 | Frida Gadget — enforcement | ❌ | depends on 9 |
| 11 | Frida Gadget — restore | ❌ | depends on 9 |
| 12 | Device memory across a new hardware key | ✅ | iOS variant already defined: `deleteKey`, **not** uninstall |
| 13 | Pristine re-enrolment (recognition) | ✅ | iOS variant already defined |
| 14 | Structural code-integrity (**ext bucket**) | ❌ blocked | asserts `android_code_integrity_violation`; no iOS `code_integrity` probe exists |
| 15 | Key survives app reinstall (**iOS only**) | ✅ iOS only | has no Android counterpart, and has **never been run** |
| 16 | Structural code-integrity (**app bucket**) | ❌ blocked | asserts `android_app_code_modified`; same missing probe |

**Items 5–8 must run within 10 minutes of a session refresh**, or an expired access token makes them
inconclusive. Items 3 and 4 are cross-device by construction — one run exercises both handsets.

### Why 12, 13 and 15 differ by platform

Android Keystore entries are destroyed when the app is uninstalled, so a reinstall necessarily
enrols a new hardware key — which is what 12 and 13 exercise. **iOS keychain items survive app
uninstall**, so on iPhone a reinstall returns the *same* Secure Enclave key and proves nothing about
re-enrolment. The iOS parallel of "uninstall" is an explicit `deleteKey` on the installation-key
channel. Item 15 exists because that divergence is itself worth asserting: on iOS the installation
identity survives reinstall, which is a *stronger* recognition guarantee than Android's.

This is directly relevant to your `SecureEnclaveInstallationKeyStore`. Confirmed on the device on
2026-09-14: the same key thumbprint and the same installation id survived a rebuild, an `ldid`
re-sign and a TrollStore reinstall — but **only** because `keychain-access-groups` was reproduced
byte for byte (§4). Get that value wrong and item 15 fails, and every rebuild silently mints a new
device identity.

### The blocked items may be easier for you than for Flutter

14 and 16 are blocked because the iOS collector has no `code_integrity` probe — it reports eight
probes and `collector_version 1`. **Your `AppleIntegrityCollector` is in the same position**: the
same eight probes, no `code_integrity`.

But you may have a shorter route to it than the Flutter client does. §28.6 records that the Kotlin
probe needed a native NDK component, because Kotlin cannot dereference an arbitrary address and
SELinux blocks `/proc/self/mem`. Your Android collector does it in pure C# with `Marshal.Copy`, and
§34.6 records that it reproduced the reference repository's Huawei figures exactly — core 4,808,704,
ext 4,943,872, the recurring `core_diff=71` from Frida's libc patch.

The same approach should carry to iOS: `_dyld_image_count` / `_dyld_get_image_header` /
`_dyld_get_image_vmaddr_slide` to enumerate loaded images, `Marshal.Copy` to read the in-memory
`__TEXT`, and compare against the same section read from the file on disk. That is the analogue
§33.4 describes and nobody has written, on either client.

I have **not** attempted this and it is not a promise — iOS may restrict reading another image's
pages in ways Android does not, and the on-disk comparison has to account for the dyld shared cache,
where system libraries have no ordinary file to read. Both are real unknowns. But if it does work,
the .NET client would reach items 14 and 16 on iOS **before** the reference client does, which is
worth knowing while you plan.

### Engine coverage, so nobody assumes more than exists

The SQL Server battery runs (§27.4–27.8) are dated **2026-09-05**. The iPhone arrived **2026-09-09**.
So **iOS has been exercised against PostgreSQL only** — 18.3 on RDS, and 16.15 local to the EC2
instance. No iOS result exists on any SQL Server version.

And stated plainly: the iPhone has never had the battery run on it **as a battery**. What exists is
ad-hoc verification — enrolment, possession, integrity reporting, the gate both refusing and
admitting, reinstall correlation. Real results, but not the numbered list executed in order. Do not
read the iOS work as battery coverage.

## 10. Later the same day: item 15 passed, item 16 became reachable, item 14 did not

### Item 15 — PASS, and it pins something about your key store

First battery item formally executed on iOS. Installation id, key thumbprint and
`created this launch` were all unchanged across **Remove App → Delete App** and a TrollStore
reinstall, with `deleteKey` deliberately not called.

The reinstall was genuine — iOS reassigned **both** container identifiers:

```
bundle container   228B6059-…  →  9429B222-…
data container     (previous)  →  AE1820C2-…
```

The data container is the load-bearing one. It is the app's entire sandbox, so anything that
survived came from the Keychain. That makes the run pin two properties:

1. The Secure Enclave key survives app deletion — `created: No`, same thumbprint.
2. The client's secure storage genuinely backs onto the **Keychain, not the sandbox**, because the
   installation id survived a wiped data container.

**Check the second one for your own storage.** If whatever holds your installation id is
sandbox-backed, every reinstall mints a new installation id while reusing the same key, and the two
silently disagree — the key says "same installation", the id says "new one". Nothing would fail
loudly; you would just get a slow drift of orphaned installation rows.

A useful control ran by accident on the same device: **Simulate fresh installation** (which calls
`deleteKey`) produced a genuinely new key and a new installation correlated back to the same
`device_id` by the reinstall hint. Deleting the key changes identity; deleting the app does not.

### Item 1 now has an iOS criterion

```
Android: score=18 verdict=trusted   (developer options +8, ADB +10)
iOS:     score=0  verdict=trusted   on a pre-signed build,
                                    with INTEGRITY_ALLOW_DEBUG=0
                                    and  INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0
```

Both flag states are named because each changes the expected number. `INTEGRITY_ALLOW_DEBUG=1` masks
the `+35` rather than removing it (and disables `ios_process_traced` with it), and
`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=1` scores the same clean device at 100, because a TrollStore
install trips the fake-signature rules by construction.

### Item 16 is reachable on iOS; item 14 is not, and the reason is structural

A `code_integrity` probe now exists on the Swift collector (`collector_version` 2). It walks each
loaded image's load commands for `__TEXT,__text`, reads the same range from the file on disk, and
compares byte for byte — the same field names your Android probe emits.

**Only the app bucket can be measured.** Android compares libc and libart against real files. iOS
system libraries have no individual files at all: dyld merges them into the shared cache, so there is
nothing to open for UIKit or libobjc. Those images are reported as `system_images_unreadable` with an
explicit `system_bucket_reason`, **never** as zero-diff. An implementation that skipped them silently
would emit `ext_compared_bytes: 0, ext_diff_bytes: 0`, which scores exactly like a pristine device
while having measured nothing.

Server side: `ios_app_code_modified` (+90), gated behind `INTEGRITY_SCORE_IOS_CODE_INTEGRITY`,
default `0`. `checked` gates the rule as on Android, and the 4-byte floor is one arm64 branch.

**The collector volunteers the probe rather than waiting to be asked**, and this is deliberate on
your account. The server rejects a report that omits a *requested* probe but tolerates extra ones, so
promoting `code_integrity` to the iOS mandatory list would break every client that predates it —
starting with your `AppleIntegrityCollector`, which has the same eight probes ours had. Volunteering
lets each client adopt it independently. It becomes mandatory only once both report it.

### A tension worth knowing before you plan item 16

Android closed item 16 with Frida's raw `Memory.write`, flipping the reserved `EI_PAD` bytes of an
ELF header that happened to be mapped inside an `r-x` segment — reserved bytes, never executed, and
a raw write persists after Frida disconnects where an `Interceptor` hook would be reverted on script
unload.

The iOS equivalent needs in-memory modification too, and **on-disk modification is not an
alternative**: iOS code signatures carry per-page hashes which AMFI validates on fault-in, so editing
the installed binary would kill the process rather than produce a diff. (That is reasoning from the
CodeDirectory structure, not something tested here — treat it as the expected behaviour rather than a
measured one.)

So item 16 on iOS needs a **separate test build** carrying frida-gadget. Which entitlement it also
needs is worth getting right, because the two obvious candidates do different things:

| entitlement | permits |
|---|---|
| `get-task-allow` | another process to attach a debugger (`task_for_pid`) |
| `dynamic-codesigning` | **this** process to create or modify executable memory — what JIT needs |

An in-process frida-gadget writing into its own `__TEXT` needs the second, not the first. TrollStore
can grant arbitrary entitlements, so it is obtainable — but I have **not** tested which is sufficient
in practice, and `get-task-allow` alone is probably not.

Either way the test build is separate from the clean one, since `get-task-allow` is exactly what was
removed to make item 1 passable. That is the same shape as Android, where items 9–11 use a
gadget-carrying APK and item 11 is literally "restore the clean APK and confirm it returns to
baseline".

One probe detail if you implement this: comparing only `__TEXT,__text` excludes the Mach-O header,
so there is no direct `EI_PAD` analogue to flip safely. `mach_header_64.reserved` is the obvious
equivalent — four unused bytes — but reaching it means comparing the whole `__TEXT` **segment** rather
than just the `__text` section. Neither client does that yet.

### Engine coverage, corrected

Item 15's pass criteria are all read from the device; that run touched no server at all. So unlike
items 2–8, 12 and 13, it exercises no database behaviour and cannot distinguish one engine from
another. Whether to reclassify it in the battery as "run once, engine-independent" is open and not
decided.
