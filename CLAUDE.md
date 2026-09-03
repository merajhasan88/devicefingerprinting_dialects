# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Hard rules

**Claude does the shell work; the user does three things.** Claude runs `adb`, `logcat`, `grep`,
`scp`/`ssh` to the server laptop, `flutter run`, `git`, and applies its own changes. The user only:
(1) presses buttons in the running app ("Run native integrity scan" etc.) — say when and how many
times, then read the result with `adb logcat` yourself; (2) physically connects the OPPO when asked;
(3) enters credentials. For credentials never ask for the secret in chat — give the user a way to
enter it themselves, typically `! <command>` typed at the Claude Code prompt (e.g.
`! ssh-copy-id john@192.168.100.13`), and prefer one-time setups (SSH keys, a `chmod 600` env file
on the server) so it is entered once. Keep the user's steps minimal, literal and non-redundant.

**Never root, wipe, or modify the OS of the OPPO.** Installing a debug build of the app is fine.

**Every change is its own git commit, so `git revert <sha>` is exact.** `yamaha.py` goes to the
server as a complete file: back up the server copy to `.bak-<timestamp>`, `diff -u` old vs new
before replacing, then restart. Never reference a patch or file that only appeared inline in a
message.

**`yamaha.py` must keep running on the old test laptop: Debian Bullseye, Python 3.9, a curated set of
system packages.** AWS RDS is a future goal, not a present one. Do not propose anything that assumes
a newer Python, newer libraries, extra dependencies, or managed-database features. Verify every
server change with `ast.parse(src, feature_version=(3, 9))`.

## Read this first

`Device Recognition Authentication.md` in the repo root is the authoritative handoff document. It
records the project goal, every test already run with its PASS/FAIL result, the scoring tables, the
bugs already found and fixed, and the exact next step. **Read it before proposing work**, and update
it as milestones complete. This file is the short orientation; that file is the state of the project.

**File names are deliberately non-descriptive. Do not rename anything and do not treat the naming as
a problem.** `yamaha.py` is the Flask API server. `lib/chatroompage.dart` is the Device Recognition
Lab client — there is no chat room.

## What this project is

A security proof of concept: a Flutter Android/iOS client plus a Python 3.9 / Flask / PostgreSQL
backend that recognizes the same physical device across reinstalls and accounts, authenticates with
non-exportable device-bound keys, makes stolen tokens useless on another device, and detects
root/jailbreak, Frida, hooking frameworks, tampering and debugger activity. The long-term target is
the same server-side risk architecture on Payactiv infrastructure.

**The server, not Google or Apple, owns the risk score.** There is intentionally no Play Integrity,
SafetyNet, App Attest or DeviceCheck. Do not introduce one unless explicitly asked.

Known and accepted boundary: a fully compromised OS can falsify local measurements and may use a
legitimate non-exportable key as a signing oracle. Without an independent hardware root of trust this
is strong risk-based defense in depth, not mathematically perfect attestation. Say so honestly rather
than overclaiming what a passing test proves.

## Environments

| | |
|---|---|
| Client dev machine | Ubuntu, `~/flutter_dev/devicefingerprinting`, Flutter 3.47.2 / Dart 3.13.2, SDK at `/home/developer/Android/Sdk`, Java 17 |
| Backend | Separate box at **192.168.100.13:5000**, **Python 3.9**, runs from `/home/john` |
| Physical phone | **OPPO** — the clean baseline. **Never root or wipe it** without explicit agreement. Clean scan is `score=18 verdict=trusted` (`android_developer_options +8`, `android_adb_enabled +10`) |
| Emulator | **emulator-5554**, AOSP, KVM working, `adb root` gives genuine `uid=0 / u:r:su:s0`. This is the disposable root laboratory where real compromise tests belong |

`adb root` proving root for `adbd` does **not** prove a sandboxed app can see or execute `su`. Keep
that distinction when interpreting probe output.

## Commands

```bash
# Client
flutter pub get
flutter analyze                                # see baseline below
flutter run -d emulator-5554 --dart-define=API_BASE_URL=http://192.168.100.13:5000
flutter run -d <oppo-id>    --dart-define=API_BASE_URL=http://192.168.100.13:5000
# API_BASE_URL defaults to http://10.0.2.2:5000 (emulator -> host loopback)

# Server, normal development modes
export INTEGRITY_MODE=observe
export DEVICE_POLICY_MODE=observe
export INTEGRITY_ALLOW_DEBUG=1
export INTEGRITY_ALLOW_EMULATOR=1              # only for emulator root tests, keeps the
                                               # emulator signal from polluting the score
export INTEGRITY_ANDROID_CERT_SHA256='<current debug cert>'
export DB_USERNAME=... DB_PASSWORD=...         # required, no defaults
export DEVICE_ID_MASTER_SECRET=...             # 32+ random bytes, or place in ./jwtkey.txt
python3.9 yamaha.py
```

Other DB env: `DB_HOST` (localhost), `DB_PORT` (5432), `DB_NAME` (familyappdb). Health:
`GET /health/live`, `GET /health/ready`. Server deps: Flask, Flask-JWT-Extended 4.x,
psycopg2-binary, bcrypt, pycryptodome.

Production eventually means `INTEGRITY_ALLOW_DEBUG=0`, `INTEGRITY_ALLOW_EMULATOR=0`,
`INTEGRITY_MODE=enforce` — only after enough observation and tuning.

**The server is always `yamaha.py` — edit it in place.** The handoff sometimes names the server by
milestone, e.g. `yamaha_integrity_fk_cleanup_fixed.py`; those are labels for a state of the code, not
files. There is no such variant, and none should be created. The user also applies fixes by hand
outside of these sessions (the FK-cleanup fix is already in `yamaha.py`), so re-read the relevant
code before assuming a described fix is still pending.

## Architecture

### Identity

`recognized_devices.device_id` (canonical server device) is deliberately separate from
`app_installations.installation_id`. Each installation holds one non-exportable P-256 key —
AndroidKeyStore with StrongBox attempted first and a graceful fallback
(`InstallationKeyManager.generateKeyPair`), Secure Enclave on iOS hardware. The private key never
leaves the OS keystore; only the P-256 JWK and DER ECDSA signatures cross the platform channels
(`devicefingerprinting/installation_key_v2` — `getOrCreateKey` / `sign` / `deleteKey` — and
`devicefingerprinting/integrity_v1`). PyCryptodome verifies server-side.

At `POST /v1/installations/register` the **key thumbprint is the authoritative identity**, not the
client-supplied UUID, which is how a lost UUID recovers onto the same installation.

### Reinstall correlation is not authentication

Android hashes `ANDROID_ID`, iOS hashes IDFV; the server HMAC-peppers the digest before storing it.
It only correlates reinstalls onto one `device_id` — the key stays authoritative.

Known gotcha, already hit once: on Android 8+ `ANDROID_ID` is scoped to device + user + **app signing
key**. A new laptop with a fresh Flutter debug keystore produced a different ANDROID_ID, hence a new
reinstall hint and a new server device for the same OPPO. That is correct behavior, not a bug. Fix it
by updating the server's accepted debug cert, or by reusing one debug keystore across machines.

### Proof of possession — validated, do not redesign

1. `POST /v1/installations/challenge` → `/verify`, signed by the native key → **device token**
   (`role: "device"`, 10 min, carries `did`/`iid`/`key_thumbprint`).
2. `/v1/accounts/register|login` issue **account** access + refresh tokens bound to `did`/`iid`.
   Refresh rotates, needs its own signed challenge (`/v1/auth/refresh/challenge`), and reuse revokes
   the whole family.
3. Every protected request carries `Authorization: Bearer`, `X-Access-Proof` (base64url JSON) and
   `X-Access-Signature`. The proof binds `access_token_sha256`, `body_sha256`, `installation_id`,
   `method`, `nonce`, `path`, `timestamp`, `version`. The nonce row is inserted **only after the
   signature verifies**, which is what makes replay fail atomically.

Client and server build that JSON independently, so field names and key order in
`DeviceApi.buildAccessProofFixture` are load-bearing against `_require_access_proof`.

Lifetimes: access 10 min, device 10 min, refresh 30 days, challenge 2 min, proof skew ±120 s, nonce
retention 10 min.

Already passing, with the server's rejection code: stolen refresh and stolen access
(`invalid_installation_signature`), exact replay (`access_proof_replay`), body/path/method tampering
(`access_proof_*_mismatch`), stale timestamp (`access_proof_timestamp_outside_window`).

### Integrity flow

Valid session → access PoP → server mints a fresh challenge and **randomly selects probes** → native
collector runs them → the installation key signs the **complete report** → server verifies challenge
and signature → server scores the raw measurements → server stores the report → server combines
integrity with relationship risk → allow / elevated / review / block.

**The phone never sends its own score.** Mandatory Android probes: `app_identity`, `debug_state`,
`root_files`, `system_properties`, `runtime_maps`, `tracer`. Randomly added:
`root_shell`, `selinux`, `mounts`, `frida_ports`, `emulator`, `developer_settings`.

Representative weights in `_score_android_integrity`: Frida/Gadget/Objection in `/proc/self/maps`
+90; hook/root framework +80; Frida port 27042/27043 open +75; Magisk/KernelSU/APatch artifact +75;
Verified Boot not green / bootloader unlocked / VBMeta unlocked +60 each; writable protected mount
(`/system`, `/vendor`, `/product`, `/odm`, `/system_ext`) +55; `ro.secure=0` +50; generic su artifact
+50; `ro.debuggable=1` +35; test-keys +25; developer options +8; ADB +10. Signing-certificate
mismatch is +100 and a hard block. Hard-block reasons participate in the numeric score, capped at 100
— that consistency fix is already in.

SELinux policy, after a false positive on the OPPO whose app sandbox could not query SELinux even
though ADB could: enforcing +0, permissive +45, disabled +70, **unknown +0**. Unknown is not evidence
of compromise; preserve that.

Verdict bands (both integrity and relationship risk): 0–29 trusted/allow, 30–59 elevated/step-up,
60–89 review, 90+ block. Relationship risk (`_evaluate_risk_policy`) uses only opaque
device/account/installation relationships — device age, installations per device, accounts per
device, devices per account, reinstall velocity, active status. **No PII and no hardware
fingerprint.** Observe mode computes and stores decisions without rejecting; administrative
revocation is always enforced.

### Schema

All DDL lives in the `_SCHEMA_SQL` string, applied idempotently by a `before_request` guard — extend
it with `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` rather than adding a migration tool. Tables:
`recognized_devices`, `app_installations`, `installation_challenges`, `demo_accounts`,
`device_account_links`, `refresh_sessions`, `access_proof_nonces`, `risk_policy_decisions`,
`integrity_challenges`, `integrity_reports`. RS256 columns (`public_key_n`/`_e`) are kept so
first-prototype rows stay verifiable next to ES256 keys.

Two fixed traps worth not reintroducing:

- Expired-challenge cleanup must skip challenges that have a report
  (`AND NOT EXISTS (SELECT 1 FROM integrity_reports ...)`). A blind `DELETE` caused
  `ForeignKeyViolation` → HTTP 500 on `/v1/integrity/challenge`. **Do not use `ON DELETE CASCADE`** —
  reported challenges are audit evidence.
- bcrypt on this old server has legacy return-type behavior. `_bcrypt_hash_bytes` /
  `_bcrypt_db_bytes` normalize `bytes`/`str`/`bytearray`/`memoryview` deliberately. Pass raw bytes to
  psycopg2 BYTEA; do not switch to `psycopg2.Binary`, and do not suggest upgrading bcrypt or Python.

## Test harness

The debug-only synthetic fixtures (`frida_runtime`, `frida_port`, `hook_framework`, `root_su`,
`writable_mount`) are injected by `IntegrityProbeManager.applyDebugTestFixture` and refuse to run on
a non-debuggable APK. Tests 1–6 all PASS, including test 6, which proved the most important property:
a valid JWT plus a valid access PoP plus a valid installation key still gets `403 integrity_blocked`
when the device verdict is block.

**These fixtures are pipeline validation, never proof that real tooling is detected.** Synthetic
testing is finished; work has moved to real compromise conditions.

Stolen-token tests are a two-device workflow: on phone A tap "Copy my refresh/access token", then
launch phone B with `--dart-define=STOLEN_REFRESH_TOKEN=...` / `--dart-define=STOLEN_ACCESS_TOKEN=...`.
`AccessProofFixture` deliberately separates the *signed* method/path/body from what is *actually
sent*; keep that split when adding boundary tests.

## Current point of work

Real-root testing on emulator-5554. Collect emulator ground truth (`getprop ro.build.type`,
`ro.debuggable`, `ro.secure`, `ro.build.tags`, `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`,
`ro.boot.vbmeta.device_state`, `getenforce`, and whether `su` is visible), then run **only** "Run
native integrity scan" — no synthetic buttons — and compare what the unchanged collector genuinely
observes against that ground truth. The emulator registering as a new server device is expected.
`android_su_on_path` not firing may well be correct. Classify the result explicitly as PASS, FAIL or
INCONCLUSIVE. After that: real `frida-server` on the emulator, checking whether
`android_frida_runtime_artifact` / `android_frida_port_open` fire with no fixture. See handoff §17–19.

## Delivering changes

**`yamaha.py`** — edit the repo copy in place, verify it parses under the 3.9 grammar, commit it as
its own revert point, then deploy it yourself:

```bash
python3 -c "import ast,io; ast.parse(io.open('yamaha.py',encoding='utf-8').read(), feature_version=(3,9)); print('3.9 syntax OK')"
git add yamaha.py && git commit -m "<one change>"
ssh john@192.168.100.13 'cp /home/john/yamaha.py /home/john/yamaha.py.bak-$(date +%Y%m%d-%H%M)'
scp yamaha.py john@192.168.100.13:/home/john/yamaha.py.new
ssh john@192.168.100.13 'diff -u /home/john/yamaha.py /home/john/yamaha.py.new; mv /home/john/yamaha.py.new /home/john/yamaha.py && ./run-yamaha.sh'
curl -s http://192.168.100.13:5000/health/ready
```

Always look at that `diff -u` — the server copy may carry a hand-edit the repo copy lacks, and a
wholesale replace would silently drop it. `run-yamaha.sh` on the server sources `~/yamaha.env`
(mode 600, holds the export lines; never print its values) and restarts the process under `nohup`
with output in `~/yamaha.log`.

**Dart, Kotlin, config** — edit in the repo, commit, and `flutter run -d <device>` yourself once the
user has connected the device.

**Reading scan results** — `adb -s <device> logcat -c` before asking for button presses, then
`adb -s <device> logcat -d -s flutter:V | grep -E 'INTEGRITY(:| REASON:)'` afterwards. The user does
not need a logcat terminal open.

### Python 3.9 / Bullseye limits for `yamaha.py`

No `match`/`case` and no PEP 604 `X | Y` annotations (both 3.10+). No new pip dependencies beyond
Flask, Flask-JWT-Extended 4.x, psycopg2-binary, bcrypt and pycryptodome without asking first. Do not
suggest upgrading Python or bcrypt, keep the `_bcrypt_hash_bytes` / `_bcrypt_db_bytes` normalization,
pass raw bytes to psycopg2 BYTEA rather than `psycopg2.Binary`, and keep the schema plain PostgreSQL
that the laptop's server version accepts.

## Repo state

`flutter analyze` has a pre-existing non-clean baseline: `test/widget_test.dart` still references the
deleted template class `MyApp` (an error, so `flutter test` fails), plus lints from the archived
snapshots. Diff against that baseline instead of expecting zero issues.

In `lib/`, only `main.dart` and `chatroompage.dart` are live. `chatroompage - before integrity attack
tests.dart`, `chatroompage.before_boundary_tests.dart`, `chatroompage_access_proof_boundary_tests.dart`
and `chatroompage_refresh_test_results.dart` are milestone snapshots kept for comparison — not
imported, but still analyzed, and they redeclare the same class names. Do not edit them or copy fixes
into them.

Dart and the server both handle `platform: "ios"`, but there is no Swift implementation of the two
MethodChannels — `AppDelegate.swift` is stock, so iOS paths are untested and the fixtures throw
`android_test_only`.
