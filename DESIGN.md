# Device Recognition / Authentication / Integrity Project — Complete Handoff

> **File naming.** This repository is the product line and uses descriptive
> names: the server is `device_trust_server.py` and the client is
> `lib/device_trust_client.dart`. Sections 1-23 below are the historical record
> of the proof of concept, where those files were named `device_trust.py` and
> `lib/device_trust_client.dart`; that wording is left as written because it describes
> what was actually done at the time. The proof of concept is frozen in the
> original repository at the tag `poc-validated-2026-09-05`. The lab server on
> 192.168.100.13 still runs the PoC deployment (`/home/john/device_trust.py` under
> `device_trust.service`), so those infrastructure names are current, not historical.


This is an ongoing security POC. Continue from the current state rather than redesigning it.

## 1. Overall Goal

Build a Flutter Android/iOS application with a Python/Flask/Postgres backend that can:

- Recognize the same physical device across reinstalls and different user accounts.
- Use non-exportable device-bound cryptographic keys for authentication.
- Prevent stolen refresh/access tokens from being useful on another device.
- Detect root/jailbreak, Frida, hooking frameworks, tampering, debugger activity, signing-certificate mismatch, suspicious boot state, writable system partitions, etc.
- Have the **server**, rather than Google Play Integrity / Apple App Attest, calculate the authoritative risk score.
- Have the server decide whether a device/request/account should be:
  - trusted
  - elevated
  - review
  - blocked
- Ultimately use the same type of server-side logic on Payactiv infrastructure.

There is deliberately **no Google/Apple remote attestation** in this POC.

Important security boundary:

A fully compromised rooted/jailbroken OS can falsify local measurements and may potentially invoke legitimate non-exportable keys as signing oracles. Without an independent hardware/vendor remote-attestation root of trust, this system cannot cryptographically prove OS integrity. It is therefore a strong risk-based defense-in-depth system rather than mathematically perfect device attestation.

---

# 2. Current Development Environment

## Flutter / Ubuntu machine

Current development machine:

```text
Ubuntu
user: developer
project:
~/flutter_dev/devicefingerprinting
```

Android SDK:

```text
/home/developer/Android/Sdk
```

Relevant environment:

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=/home/developer/Android/Sdk
export ANDROID_SDK_ROOT=/home/developer/Android/Sdk
export PATH="/home/developer/development/flutter/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
```

Flutter doctor is otherwise healthy:

```text
Android SDK 37.0.0
Platform android-37
build-tools 37.0.0
Java 17
licenses accepted
```

## Physical Android test device

Current physical test phone is the **OPPO**.

Earlier testing also used Huawei, but current plan is to use OPPO as the clean physical baseline.

The OPPO is **not to be rooted or wiped for attack testing**.

The clean OPPO currently returns approximately:

```text
INTEGRITY: score=18 verdict=trusted mode=observe
INTEGRITY REASON: android_developer_options +8
INTEGRITY REASON: android_adb_enabled +10
```

This is the expected clean development baseline.

## Disposable Android emulator

A CLI-only Android AOSP emulator has now been successfully created.

Current device:

```text
emulator-5554
```

KVM is configured correctly.

VT-x is enabled.

The user was added to the `kvm` group.

`emulator -accel-check` is now good.

Most importantly:

```bash
adb -s emulator-5554 root
adb -s emulator-5554 shell id
```

returns:

```text
restarting adbd as root
uid=0(root) gid=0(root) ...
context=u:r:su:s0
```

So the emulator is now our disposable root-capable Android laboratory.

This is where the next real, non-synthetic root/Frida tests should happen.

---

# 3. Backend Environment

Server is an old Linux laptop/server:

```text
server IP: 192.168.100.13
port: 5000
Python: 3.9
```

Typical server directory:

```text
/home/john
```

Do **not** recommend upgrading Python or bcrypt.

The old environment has legacy bcrypt behavior that has already been handled carefully.

Preserve this compatibility:

```python
def _bcrypt_hash_bytes(password_bytes):
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    if isinstance(hashed, bytes): return hashed
    if isinstance(hashed, str): return hashed.encode("ascii")
    if isinstance(hashed, bytearray): return bytes(hashed)
    if isinstance(hashed, memoryview): return hashed.tobytes()
    raise RuntimeError(...)

def _bcrypt_db_bytes(value):
    if isinstance(value, bytes): return value
    if isinstance(value, memoryview): return value.tobytes()
    if isinstance(value, bytearray): return bytes(value)
    if isinstance(value, str): return value.encode("ascii")
    raise RuntimeError(...)
```

Pass raw bytes to psycopg2 BYTEA.

Do not switch to `psycopg2.Binary`.

---

# 4. Core Device Identity Design

The backend deliberately separates:

```text
canonical server device_id
```

from:

```text
installation_id
```

Each installation gets a non-exportable P-256 key.

Android:

```text
AndroidKeyStore
StrongBox if available
```

iOS:

```text
Secure Enclave on physical hardware
simulator fallback
```

Flutter communicates with native code using platform-channel methods roughly equivalent to:

```text
getOrCreateKey
sign
deleteKey
```

The private key never leaves the OS keystore.

Public key representation is P-256 JWK.

The Python server verifies ECDSA using PyCryptodome.

---

# 5. Reinstall Recognition

Reinstall correlation is not authentication.

Android reinstall hint is derived from:

```text
ANDROID_ID → SHA-256
```

Server then HMAC-peppers the hint before storing/comparing it.

iOS equivalent uses IDFV-derived digest.

The hint is used only for correlation.

Cryptographic installation key remains authoritative for authentication.

Important discovery:

On Android 8+, `ANDROID_ID` is scoped to the combination of:

```text
device
user
app signing key
```

Therefore a fresh laptop with a new Flutter/debug keystore can produce a different ANDROID_ID namespace.

This actually happened.

The same OPPO was reinstalled from a new laptop with a fresh Flutter install.

Result:

```text
new installation ID
new server device ID
reinstall hint available = yes
```

This was initially surprising.

The likely reason was:

```text
old laptop debug signing key A
→ ANDROID_ID A
→ reinstall hint A

new laptop debug signing key B
→ ANDROID_ID B
→ reinstall hint B
→ no old server-device match
→ new server device ID
```

The user updated the server's accepted debug signing certificate for the new laptop.

After doing that, integrity returned to:

```text
score=18
verdict=trusted
```

For production, this is not expected to be a problem because the Payactiv app should use a stable production signing identity.

For cross-laptop development testing, using the same debug keystore would preserve the same signing-key-scoped Android identity.

---

# 6. Main Database Tables

Core tables include:

```text
recognized_devices
app_installations
installation_challenges
demo_accounts
device_account_links
refresh_sessions
access_proof_nonces
risk_policy_decisions
integrity_challenges
integrity_reports
```

`recognized_devices` contains the canonical server device.

`app_installations` maps installation-specific keys to that device.

---

# 7. Authentication / Proof-of-Possession Already Validated

These are already working and should NOT be redesigned.

## Installation authentication

Installation challenge + native key signature works.

## Refresh-token PoP

Stolen refresh-token test passed.

Phone B used Phone A's refresh token but signed with B's native key.

Expected result occurred:

```text
401
invalid_installation_signature
```

Legitimate refresh on A succeeds.

## Access-token PoP

Protected requests use a single-request proof.

Example signed proof:

```json
{
  "access_token_sha256": "...",
  "body_sha256": "...",
  "installation_id": "...",
  "method": "POST",
  "nonce": "...",
  "path": "/v1/account/protected-echo",
  "timestamp": 123,
  "version": 1
}
```

Headers:

```text
Authorization: Bearer <token>
X-Access-Proof: <base64url proof>
X-Access-Signature: <P-256 signature>
```

Server verifies:

```text
JWT
JWT device/install binding
installation ID
HTTP method
path
body SHA256
bearer-token SHA256
timestamp window
nonce size
native P-256 signature
atomic nonce insertion
```

Validated attacks:

### Stolen access token

PASS:

```text
401
invalid_installation_signature
```

### Exact replay

PASS:

```text
first request 200
replay 401
access_proof_replay
```

### Body tampering

PASS:

```text
401
access_proof_body_mismatch
```

### Path tampering

PASS:

```text
401
access_proof_path_mismatch
```

### Method tampering

PASS:

```text
401
access_proof_method_mismatch
```

### Stale timestamp

PASS:

```text
401
access_proof_timestamp_outside_window
```

Relevant constants:

```python
ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
DEVICE_TOKEN_LIFETIME = timedelta(minutes=10)
REFRESH_TOKEN_LIFETIME = timedelta(days=30)
CHALLENGE_LIFETIME = timedelta(minutes=2)

ACCESS_PROOF_MAX_SKEW_SECONDS = 120
ACCESS_PROOF_NONCE_RETENTION = timedelta(minutes=10)
```

---

# 8. Server Relationship Risk Layer

Separate from native integrity.

Relationship-based risk considers:

```text
device age
number of installations/device
number of accounts/device
number of devices/account
reinstall velocity
installation/device active status
```

Default score bands:

```text
0–29   allow
30–59  step_up/elevated
60–89  review
90+    block
```

`DEVICE_POLICY_MODE`:

```text
observe
enforce
```

Observe mode calculates recommendations but does not reject.

Administrative device/install revocation is always enforced.

---

# 9. Native Integrity Architecture

Current server-owned integrity flow:

```text
valid JWT/session
↓
request PoP
↓
server creates fresh integrity challenge
↓
server randomly selects probes
↓
native Android/iOS collector runs them
↓
existing non-exportable installation key signs COMPLETE report
↓
server verifies challenge + signature
↓
server scores raw measurements
↓
server stores report
↓
server combines integrity + behavioral risk
↓
allow / elevated / review / block
```

The phone never sends its own final score.

The server owns:

```text
scoring
thresholds
baselines
hard-block rules
```

---

# 10. Android Integrity Probes

Mandatory probes generally include:

```text
app_identity
debug_state
root_files
system_properties
runtime_maps
tracer
```

Random additional probes can include:

```text
root_shell
selinux
mounts
frida_ports
emulator
developer_settings
```

Integrity report contains something like:

```json
{
  "challenge_id": "...",
  "challenge_nonce": "...",
  "installation_id": "...",
  "platform": "android",
  "collector_version": 1,
  "collected_at": 123456789,
  "probe_results": {},
  "version": 1
}
```

The entire report is signed with the installation key.

The integrity HTTP submission itself also uses normal access PoP.

---

# 11. Important Android Detectors

## App identity

Collects:

```text
package name
version/version code
debuggable flag
allowBackup flag
APK signing certificate SHA256
signing history/rotation
base APK SHA256
installer/source
```

Server can baseline package + allowed certificate digest(s).

Signing certificate mismatch is a hard block.

## Root files

Looks for items such as:

```text
/system/bin/su
/system/xbin/su
/sbin/su
/su/bin/su
/data/local/su
/data/local/bin/su
/data/local/xbin/su
/system/app/Superuser.apk
/system/app/SuperSU.apk
/sbin/magisk
/data/adb/magisk
/data/adb/modules
/data/adb/ksu
/data/adb/ap
/metadata/adb/magisk
```

Typical scoring:

```text
Magisk / KernelSU / APatch style artifact   +75
generic root/su artifact                    +50
su discoverable                             +50
```

## System properties

Checks:

```text
ro.secure
ro.debuggable
ro.build.type
ro.build.tags
ro.boot.verifiedbootstate
ro.boot.flash.locked
ro.boot.vbmeta.device_state
ro.boot.veritymode
```

Examples:

```text
Verified Boot != green        +60
flash lock != 1               +60
VBMeta != locked              +60
ro.secure=0                   +50
ro.debuggable=1               +35
test-keys                     +25
```

## Runtime hooks

Reads `/proc/self/maps`.

Suspicious strings include:

```text
frida
gadget
objection
xposed
lsposed
substrate
zygisk
riru
magisk
kernelsu
apatch
```

Representative scoring:

```text
Frida/Gadget/Objection         +90
hook/root framework            +80
```

## Frida ports

Checks localhost:

```text
27042
27043
```

Open port:

```text
+75
```

## Writable protected mounts

Checks `/proc/mounts`.

Protected prefixes:

```text
/system
/vendor
/product
/odm
/system_ext
```

Writable protected mount:

```text
+55
```

## Developer options / ADB

Supporting signals only:

```text
Developer Options   +8
ADB                  +10
```

These are deliberately low-weight signals.

---

# 12. SELinux Bug and Final Policy

Originally the collector produced a false positive:

```text
android_selinux_not_enforcing +45
```

But direct ADB showed:

```text
getenforce = Enforcing
/sys/fs/selinux/enforce = 1
ro.secure = 1
ro.debuggable = 0
Verified Boot = green
flash lock = 1
VBMeta = locked
build tags = release-keys
```

The app sandbox on the OPPO could not reliably query SELinux, even though ADB shell could.

Collector was changed to distinguish:

```text
enforcing
permissive
disabled
unknown
```

Final server policy:

```text
Enforcing       +0
Permissive      +45
Disabled        +70
Unknown         +0
```

Unknown is not treated as evidence of compromise.

This brought the clean phone back to:

```text
18 trusted
```

---

# 13. Signing-Certificate Test

The server certificate baseline was intentionally changed to a fake certificate.

Result:

```text
android_signing_certificate_mismatch +100
verdict=block
```

There was initially a score-reporting inconsistency where the server showed:

```text
score=35
verdict=block
```

even though reasons contained +100.

That was fixed so hard-block reasons participate in numeric scoring and the total is capped at 100.

Retest:

```text
INTEGRITY: score=100 verdict=block
android_signing_certificate_mismatch +100
developer_options +8
adb +10
```

PASS.

---

# 14. Synthetic Attack Tests 1–6 — ALL PASS

A debug-only deterministic attack-test harness was built.

It must never be considered proof that real adversarial tooling is always detected.

Its purpose was to verify the entire challenge → signed report → server scoring → enforcement pipeline.

## Test 1 — Frida runtime maps

Result:

```text
PASS
Fixture: frida_runtime
Reason: android_frida_runtime_artifact
Score: 100
Verdict: block
Signed native report: accepted
Server challenge: accepted
```

## Test 2 — Frida local port

```text
PASS
Reason: android_frida_port_open
Score: 93
Verdict: block
```

## Test 3 — Xposed / LSPosed / Zygisk

```text
PASS
Reason: android_hook_framework_artifact
Score: 98
Verdict: block
```

## Test 4 — Root / su

```text
PASS
Expected:
android_root_framework_artifact
android_su_on_path
Score: 100
Verdict: block
```

## Test 5 — Writable system mount

```text
PASS
android_protected_mount_writable +55
Score: 55
Verdict: elevated
```

## Test 6 — Real server enforcement

This test used an already authenticated account.

A malicious Frida fixture was submitted.

Then a normal signed protected request was attempted.

Result:

```text
PASS: INTEGRITY_MODE=enforce rejected a protected request
Injected integrity verdict: block
Injected integrity score: 100
GET /v1/account/me: 403
Server error: integrity_blocked
Access PoP reached server: yes
Business request allowed through: no
```

This proved:

```text
JWT valid
+
access PoP valid
+
native installation key valid

BUT

device integrity now blocked
→ request rejected
```

This is one of the most important validated properties of the system.

---

# 15. Integrity Challenge Foreign-Key Bug — FIXED

After integrity testing had existed for more than a day, the server suddenly started returning:

```text
POST /v1/integrity/challenge → 500
```

Postgres error:

```text
ForeignKeyViolation

update or delete on table "integrity_challenges"
violates foreign key constraint
"integrity_reports_challenge_id_fkey"

Key challenge_id is still referenced from integrity_reports.
```

Cause:

The integrity challenge endpoint was doing:

```sql
DELETE FROM integrity_challenges
WHERE expires_at < NOW() - INTERVAL '1 day'
```

But `integrity_reports.challenge_id` references `integrity_challenges.challenge_id`.

Reported challenges are legitimate audit evidence and should not be deleted.

The fix was to delete only expired **unreported** challenges:

```sql
DELETE FROM integrity_challenges AS c
WHERE c.expires_at < NOW() - INTERVAL '1 day'
  AND NOT EXISTS (
      SELECT 1
      FROM integrity_reports AS r
      WHERE r.challenge_id = c.challenge_id
  )
```

Do NOT use `ON DELETE CASCADE` because we want to retain integrity history.

After this fix the 500 disappeared.

Current latest server file is conceptually:

```text
device_trust_integrity_fk_cleanup_fixed.py
```

It contains the prior score-consistency and SELinux fixes plus the FK cleanup fix.

---

# 16. Current Server Modes for Development

Normal baseline development environment:

```bash
export INTEGRITY_MODE=observe
export DEVICE_POLICY_MODE=observe
export INTEGRITY_ALLOW_DEBUG=1
export INTEGRITY_ANDROID_CERT_SHA256='<CURRENT DEBUG CERT>'
```

For emulator-isolated root testing also use:

```bash
export INTEGRITY_ALLOW_EMULATOR=1
```

This prevents the emulator signal itself from polluting root-test scores.

Production would eventually use:

```text
INTEGRITY_ALLOW_DEBUG=0
INTEGRITY_ALLOW_EMULATOR=0
INTEGRITY_MODE=enforce
```

after sufficient observation/tuning.

---

# 17. CURRENT EXACT POINT — REAL ROOT ENVIRONMENT TEST

Synthetic tests are finished.

We are now beginning tests against **real compromise conditions**.

The disposable AOSP emulator is currently booted as:

```text
emulator-5554
```

We have already confirmed:

```bash
adb -s emulator-5554 root
adb -s emulator-5554 shell id
```

returns:

```text
uid=0(root)
context=u:r:su:s0
```

This means `adbd` genuinely has root privileges.

Important distinction:

`adb root` does NOT automatically prove that an ordinary sandboxed Android application:

```text
can execute su
can see a su binary
can obtain uid 0
```

So the next test is to see what the existing, non-fixture native collector can genuinely observe.

---

# 18. NEXT COMMANDS TO RUN

First collect emulator ground truth:

```bash
adb -s emulator-5554 shell getprop ro.build.type
adb -s emulator-5554 shell getprop ro.debuggable
adb -s emulator-5554 shell getprop ro.secure
adb -s emulator-5554 shell getprop ro.build.tags
adb -s emulator-5554 shell getprop ro.boot.verifiedbootstate
adb -s emulator-5554 shell getprop ro.boot.flash.locked
adb -s emulator-5554 shell getprop ro.boot.vbmeta.device_state
adb -s emulator-5554 shell getenforce
```

Then:

```bash
adb -s emulator-5554 shell 'command -v su || which su || true'
```

and:

```bash
adb -s emulator-5554 shell \
  'ls -l /system/bin/su /system/xbin/su /sbin/su /su/bin/su 2>/dev/null'
```

Start server with:

```bash
export INTEGRITY_MODE=observe
export DEVICE_POLICY_MODE=observe
export INTEGRITY_ALLOW_DEBUG=1
export INTEGRITY_ALLOW_EMULATOR=1
export INTEGRITY_ANDROID_CERT_SHA256='<CURRENT DEBUG CERT>'

python3.9 device_trust_integrity_fk_cleanup_fixed.py
```

Then run the Flutter application on the emulator:

```bash
flutter run -d emulator-5554 \
  --dart-define=API_BASE_URL=http://192.168.100.13:5000
```

The emulator should register as its own new server device. That is expected.

Do NOT press synthetic compromise buttons.

Press only:

```text
Run native integrity scan
```

Then capture:

```text
INTEGRITY: ...
INTEGRITY REASON: ...
```

The purpose is to see whether the unchanged native collector naturally discovers real root/development-state properties.

Possible findings include:

```text
android_root_artifact
android_root_framework_artifact
android_su_on_path
android_test_keys
android_verified_boot_not_green
android_bootloader_not_locked
android_vbmeta_not_locked
android_ro_secure_disabled
```

If `android_su_on_path` does NOT fire, that may be correct: root adbd does not necessarily expose a `su` executable to the application process.

This test should be classified explicitly as:

```text
PASS
FAIL
or INCONCLUSIVE
```

based on what the collector actually sees compared with the emulator ground truth.

---

# 19. AFTER THE REAL ROOT TEST

Once the emulator baseline/root-environment test is understood, the next major test is **real Frida**, not the synthetic fixture.

Plan:

```text
root-capable emulator
↓
install real frida-server
↓
launch frida-server
↓
instrument the actual Flutter/Android process
↓
existing runtime_maps + frida_ports collectors
↓
signed integrity report
↓
server scorer
```

We want to see whether the real system produces:

```text
android_frida_runtime_artifact
and/or
android_frida_port_open
```

without any synthetic fixture.

Later we can also test:

```text
actual Frida Gadget on OPPO without root
real root management frameworks in emulator if useful
real hooking framework behavior
enforcement against real compromise
```

Do not root/wipe the OPPO unless explicitly agreed.

---

# 20. Working Style / Constraints

Please follow these preferences during continuation:

- Make one change/test at a time.
- Give exact shell/Flutter/Python/SQL commands.
- Do not redesign already-working authentication architecture.
- Preserve Python 3.9 compatibility.
- Do not suggest upgrading bcrypt/Python.
- Distinguish:
  - environment/tooling issue
  - client/native collector issue
  - server-scoring issue
  - actual security finding
- For every test, explicitly say:
  - PASS
  - FAIL
  - INCONCLUSIVE
- Give expected logs before testing when practical.
- Prefer full replacement files when code changes are substantial.
- Tiny patches are fine for very localized fixes.
- Preserve the existing clean OPPO baseline.
- Synthetic fixture tests have already passed; focus now on **real attack conditions**.
- Server scoring is authoritative; the client never decides its own trust level.
- Do not introduce Google Play Integrity, SafetyNet, Apple App Attest, or DeviceCheck unless explicitly requested.
- The final production goal is server-side Payactiv risk assessment using the same conceptual architecture.

## Immediate continuation request

Continue from the real root-emulator test described above. The emulator is already running as root (`uid=0`, `u:r:su:s0`). First interpret the emulator ground-truth commands and then run the ordinary native integrity scan without synthetic fixtures. After that, proceed to real `frida-server` testing.

---

# 21. Emulator Real-Environment Results — 2026-09-03

Recorded from the live Claude Code session. Emulator `emulator-5554`, AOSP x86_64, `userdebug`, adbd running as root. Server modes throughout: `INTEGRITY_MODE=observe`, `DEVICE_POLICY_MODE=observe`, `INTEGRITY_ALLOW_DEBUG=1`, `INTEGRITY_ALLOW_EMULATOR=1`. **No synthetic fixtures were used in any test below.**

## 21.1 Emulator ground truth

```text
ro.build.type                 userdebug
ro.debuggable                 1
ro.secure                     1
ro.build.tags                 test-keys
ro.boot.verifiedbootstate     (empty)
ro.boot.flash.locked          (empty)
ro.boot.vbmeta.device_state   (empty)
getenforce                    Enforcing
su                            /system/xbin/su   -rwsr-x--- root shell
```

## 21.2 Test A — real root-capable image, unmodified collector: FAIL, then fixed

Three scans with the unchanged collector and server:

```text
score=35 verdict=elevated   android_test_keys +25, android_adb_enabled +10
score=25 verdict=trusted    android_test_keys +25
score=35 verdict=elevated   android_test_keys +25, android_adb_enabled +10
```

Findings:

- `android_root_artifact` never fired even though `root_files` ran on every scan and `/system/xbin/su` exists. `File.exists()` returns false from the app sandbox. Working hypothesis: SELinux — the binary carries the `su_exec` label and `untrusted_app` is denied `getattr`. Verification is still pending (§21.5).
- `android_su_on_path` did not fire (`root_shell` was drawn in two scans). Predicted and correct: the app uid is neither root nor in group `shell`, so `su` is not executable from the process. Root `adbd` does not imply an app-visible `su`.
- The three verified-boot properties are empty on the emulator. The scorer's `if value and ...` guard treats absence as telemetry (+0), consistent with the SELinux "unknown is not compromise" policy.
- `android_developer_options` did not fire; only `android_adb_enabled` did.

**Classification: FAIL.** A root-capable `userdebug` image scored `trusted` on one scan in three and was indistinguishable from the clean OPPO baseline (18).

**Fix applied to `device_trust.py`** (`_score_android_integrity`): `ro.build.type` was collected by the probe but never scored. Added `android_build_type_not_user +45` for any non-empty build type other than `user`. Not gated by `INTEGRITY_ALLOW_DEBUG`. Python 3.9-safe; no schema or dependency change. Reason: a userdebug/eng image is root-capable by construction, and a property read survives the sandbox where a file stat does not.

Retest, three scans:

```text
score=70 verdict=review   android_test_keys +25, android_build_type_not_user +45
score=80 verdict=review   + android_adb_enabled +10   (developer_settings drawn)
score=70 verdict=review
```

OPPO after the fix: `ro.build.type=user`, `score=18 verdict=trusted` — unchanged. **PASS.**

Consequence to remember: `_enforce_integrity_gate` rejects `elevated`, `review` **and** `block` — only `trusted` passes. The emulator is therefore permanently 403 in enforce mode. Enforce-mode tests must run on the OPPO unless an `INTEGRITY_ALLOW_USERDEBUG`-style lab switch is added (undecided).

## 21.3 Test B — real frida-server and real attach: PASS (all phases)

frida-server (version matched to frida-tools, `android-x86_64`) pushed to `/data/local/tmp`, started as root, confirmed listening on `127.0.0.1:27042` with `netstat -ltn`.

Phase 1 — server listening, nothing attached:

```text
score=100 verdict=block   android_frida_port_open +75          (frida_ports drawn)
score=80  verdict=review  no Frida reason                       (frida_ports NOT drawn)
score=100 verdict=block   android_frida_port_open +75          (frida_ports drawn)
```

`android_frida_runtime_artifact` absent on all three — correct; nothing was inside the process yet.

Phase 2 — `frida -U -p <pid>` attached, REPL held open, `frida-agent` confirmed in `/proc/<pid>/maps`:

```text
score=100 verdict=block   android_frida_runtime_artifact +90 (+ port reason when drawn)
score=100 verdict=block   android_frida_runtime_artifact +90
score=100 verdict=block   android_frida_runtime_artifact +90   (frida_ports NOT drawn — still caught)
```

`runtime_maps` is mandatory, so an attached Frida is caught on every scan regardless of the optional draw.

Phase 3 — after `exit`: runtime artifact gone. After `pkill frida-server`: a scan that drew `frida_ports` fired nothing. Back to 70/80 `review`. No stale state.

## 21.4 Design observations — decisions pending

1. **Optional-probe miss rate.** `frida_ports` (+75), `root_shell` (+50), `mounts` (+55) and `selinux` (+45/+70) all sit in the optional pool with 4 of 6 drawn, so each is skipped in one scan of three. The client chooses when to scan and `_latest_integrity_state` uses only the newest report, so a compromised client can simply rescan until a favourable draw. Proposal: block-weight probes become mandatory; randomness stays only for low-weight telemetry. The challenge nonce already prevents precomputed reports.
2. **Integrity memory does not cross a reinstall.** `_latest_integrity_state` and `_evaluate_risk_policy` look up integrity by `installation_id` only. A reinstall creates a new installation with no integrity state; a previous `block` verdict on the same `device_id` is not carried over. Only the relationship layer (reinstall velocity) and administrative `recognized_devices.status` persist across reinstalls. Proposal to discuss: device-level integrity memory (worst verdict per `device_id` inside a window).
3. **Empty verified-boot properties score +0.** A production Android 8+ device with AVB always publishes `ro.boot.verifiedbootstate`; the OPPO publishes all three. Whether "all three absent" deserves a low-weight reason is undecided.
4. **`INTEGRITY_ALLOW_USERDEBUG` lab switch** — undecided; lab-only, never production.

## 21.5 `su` invisibility — CONFIRMED (2026-09-04)

```text
ls -lZ /system/xbin/su                 -rwsr-x--- root shell u:object_r:su_exec:s0
run-as <app> id -Z                     u:r:runas_app:s0:c150,c256,c512,c768
run-as <app> ls -l /system/xbin/su     ls: /system/xbin/su: Permission denied
logcat -b all / dmesg | grep su_exec   (no audit record)
```

Under DAC, `stat()` needs only search permission on the parent directories, which are world-searchable; the file's own mode bits do not apply to `stat()`. `Permission denied` on a bare `ls -l` can therefore only come from SELinux (`untrusted_app` denied `getattr` on `su_exec`). The absent audit line is consistent with AOSP `dontaudit` rules for app probing of system paths. Conclusion: file-presence root detection is a low-confidence signal on any device with a sane policy. Keep `root_files` for sloppy roots; never rely on it.

## 21.6 Decisions taken (2026-09-04)

All four proposals in §21.4 approved, each to land as its own revertable commit, in this order: (a) block-weight probes mandatory; (b)+(c) development-image signals and lab switch; (d) device-level integrity memory. Then the Frida Gadget test on the OPPO. Note for (c): suppressing only the build-type reason would leave the emulator at 35 (`test-keys +25`, `adb +10`) = `elevated`, still 403 in enforce mode, so the lab switch must cover the whole development-image set (build type, test-keys, boot-state-unavailable).

## 21.7 Change (a) verified against real Frida (2026-09-04)

`_integrity_probe_plan`: `root_shell`, `selinux`, `mounts`, `frida_ports` moved from the optional pool to mandatory (commit `2fafa33`), deployed via the new systemd service. A/B against §21.3 Phase 1 with frida-server listening and nothing attached:

```text
before (optional frida_ports):  block / review / block   (2 of 3 — the review scan had not drawn frida_ports)
after  (mandatory frida_ports): block / block  / block   (3 of 3 — all twelve probes present every scan)
```

Every scan now carries `android_frida_port_open +75`; `android_adb_enabled +10` also appears every scan because its probe is likewise always drawn. **PASS.** A client can no longer rescan to dodge a block-weight probe.

## 21.9 Open items

- Next test: **Frida Gadget embedded in the APK on the OPPO** (`user` build, no root, `INTEGRITY_MODE=enforce`). Expect `android_frida_runtime_artifact` via the `gadget` token in `runtime_maps`, then 403 `integrity_blocked` on a protected request. This is the first enforcement-against-real-compromise test on production-class hardware.

## 21.8 Server run model (2026-09-04)

The backend was moved off a hand-started root process to a **systemd service** to make deploys and restarts unattended. `device_trust.service` runs `python3.9 /home/john/device_trust.py` as user `john` (`WorkingDirectory=/home/john`, so `jwtkey.txt` and the file-based JWT secret still resolve), config from `/etc/device_trust.env` (root:root, mode 600, captured verbatim from the previously running process so DB credentials, integrity mode and the JWT secret are unchanged). `john` — who is not otherwise a sudoer — was granted passwordless sudo for only `systemctl <verb> device_trust.service` via `/etc/sudoers.d/device_trust`, and added to `systemd-journal` for log reads. The one-time converter is `/home/john/claude-root-setup.sh`. Deploy is now `scp device_trust.py` (john owns the file) + `sudo systemctl restart device_trust.service`; logs are `journalctl -u device_trust`. The service is enabled, so it also survives reboot.

## 21.10 Change (b)+(c) — absent AVB scored; lab switch added (2026-09-04)

(b) verified with the lab switch OFF, no Frida, emulator: two scans, both `score=95 verdict=block`, new reason `android_boot_state_unavailable +15` alongside `android_test_keys +25`, `android_build_type_not_user +45`, `android_adb_enabled +10`. Emulator baseline moved 80 review -> 95 block; the OPPO (green/locked AVB, user build) is unaffected. **PASS.**

(c) verified in two parts with `INTEGRITY_ALLOW_USERDEBUG=1`, identical server configuration in both:

```text
part 1  no Frida:        score=10  verdict=trusted   only android_adb_enabled +10
part 2  Frida attached:  score=100 verdict=block     android_frida_runtime_artifact +90,
                                                     android_frida_port_open +75, adb +10
```

The switch suppresses only the development-image signals (build type, test-keys, absent AVB) and never suppresses compromise evidence, so a userdebug emulator can hold a `trusted` baseline for enforce-mode testing while a genuinely compromised one still blocks. **PASS.** Must remain 0 in production.

## 21.11 Passwordless lab toggling (2026-09-04)

To toggle lab-only settings without root each time, `device_trust.service` gains a second, optional, john-writable `EnvironmentFile=-/home/john/device_trust.lab.env` that overrides `/etc/device_trust.env`. It holds no secrets — only lab switches such as `INTEGRITY_ALLOW_USERDEBUG=1` or `INTEGRITY_MODE=enforce`. Toggling is then entirely passwordless: write the file as john, `sudo systemctl restart device_trust.service`. Keep it empty (or absent) for a production-representative run.

## 21.12 Change (d) — device-level integrity memory: PASS (2026-09-04)

Commit `5d80e34`. `_device_integrity_memory(device_id)` returns the worst integrity report recorded against the canonical `device_id` within `INTEGRITY_DEVICE_MEMORY_HOURS` (default 24, `0` disables). `_enforce_integrity_gate` consults it **after** the current installation's own verdict passes and rejects with `integrity_device_blocked_recently`; `_evaluate_risk_policy` adds `device_integrity_history_block +50` when a *different* installation on the same device was blocked in the window, and both the memory and the window are recorded in the decision context. Deployed and live, but **not yet exercised**.

### Server state left running

```text
INTEGRITY_MODE=enforce                 (in /home/john/device_trust.lab.env)
INTEGRITY_ALLOW_USERDEBUG=1            (in /home/john/device_trust.lab.env)
INTEGRITY_DEVICE_MEMORY_HOURS=24       (default, not overridden)
DEVICE_POLICY_MODE=observe             (unchanged, /etc/device_trust.env)
```

Emulator is clean: frida-server stopped, agent unloaded, logcat cleared. The device carries a `block` report from the §21.10 (c) part-2 Frida test, recorded ~01:45 local on 2026-09-04 against the installation that was current at that time.

### Resume here — the (d) test

Two presses in the app, in order:

1. **Simulate fresh installation** — deletes the Keystore key and registers a new `installation_id` against the same `device_id` via the ANDROID_ID hint (a genuine reinstall), then auto-scans. Expect `score=10 verdict=trusted`.
2. **Create account** (handle `dtest1`, password `Passw0rd123`) — `/v1/accounts/register` is integrity-gated. Expect **403 `integrity_device_blocked_recently`**: the new installation's own scan is clean, but the device was blocked inside the memory window.

Then the counterfactual, to prove the rejection came from (d) and nothing else: set `INTEGRITY_DEVICE_MEMORY_HOURS=0` in `device_trust.lab.env`, `sudo systemctl restart device_trust.service`, press **Create account** again — expect success. Restore the value afterwards.

**If more than 24 hours have passed**, the stored block has aged out of the window: re-create it first (start frida-server, attach, scan to `block`, detach) before step 1, or the test is vacuous.

### Still open after (d)

- Frida Gadget on the OPPO (`user` build, no root) with `INTEGRITY_MODE=enforce` — enforcement against real compromise on production-class hardware. Requires an APK change (gadget `.so` in `jniLibs/arm64-v8a/` plus a load line in `MainActivity.kt`) and `flutter run` to the OPPO. Approved by the user; the OPPO is never to be rooted or wiped.
- Reset `device_trust.lab.env` to empty for any production-representative measurement.

### 21.12.1 (d) test result — PASS (2026-09-04 12:16-12:28)

End-to-end reinstall-laundering test on emulator-5554. Server: `INTEGRITY_MODE=enforce`, `INTEGRITY_ALLOW_USERDEBUG=1`, `DEVICE_POLICY_MODE=observe`. The device carried a `block` from the §21.10 real-Frida test recorded ~10.5 hours earlier, well inside the 24 h window. No Frida was present during this test.

Sequence:

```text
1. Simulate fresh installation
   POST /v1/installations/register -> 201 Created      (new installation_id, new Keystore key)
   Registration method: reinstall_hint                 (correlated to the SAME device_id)
   auto integrity scan -> score=10 verdict=trusted     (the new installation is spotless)

2. Create account (dtest1)
   POST /v1/accounts/register -> 403
   integrity_device_blocked_recently
   "This device recorded a blocked integrity verdict recently;
    reinstalling the app does not clear it."
```

Counterfactual, to prove the rejection came from (d) and not from another gate — `INTEGRITY_DEVICE_MEMORY_HOURS=0`, service restarted, fresh scan (`score=10 verdict=trusted`), same handle, same installation:

```text
   POST /v1/accounts/register -> 201 Created
```

Setting restored to the 24 h default afterwards. **PASS.** This is the project goal demonstrated literally: a device compromised by real Frida, then reinstalled with a new cryptographic identity and a clean local measurement, is still refused, because recognition of the physical device carries the integrity verdict across the reinstall.

Note on scope: the gate rejects on any recent device-level block, including one recorded by the *same* installation. The policy reason `device_integrity_history_block` is narrower and fires only when a *different* installation on the device was blocked, which is the specific reinstall-laundering signal. That asymmetry is deliberate but worth revisiting if it proves noisy.

### 21.12.2 Emulator input note

The AVD `integrity_root_lab` has `hw.keyboard=no`, so host keystrokes never reach the emulator and text fields cannot be typed into directly. Use `adb -s emulator-5554 shell input text "..."` and `input tap X Y` (screen is 320x640) instead, or set `hw.keyboard=yes` in `~/.android/avd/integrity_root_lab.avd/config.ini` and restart the emulator.

## 22. Frida Gadget on the OPPO (real compromise, production hardware) — PASS (2026-09-04)

The first enforcement-against-real-compromise test on a production-class device, and the strongest result in the project.

### Device (unchanged, never rooted)

```text
CPH2083, arm64-v8a, API 28, build=user tags=release-keys
ro.secure=1 ro.debuggable=0
verifiedbootstate=green flash.locked=1 vbmeta.device_state=locked
SELinux=Enforcing
```

Baseline scan on the clean app, enforce mode: `score=18 verdict=trusted` (developer_options +8, adb +10). Today's (a)/(b) changes do not disturb it — no boot_state_unavailable, no dev-image reasons.

### Method

Frida Gadget (`frida-gadget-17.17.0-android-arm64`) bundled inside the app's own APK — `jniLibs/arm64-v8a/libfrida-gadget.so` plus a `libfrida-gadget.config.so` set to `listen` on 127.0.0.1:27042 with `on_load: resume`, `System.loadLibrary("frida-gadget")` in `MainActivity`'s companion `init`, and `packaging { jniLibs.useLegacyPackaging = true }` in the app Gradle so the config is extracted next to the .so. No root, no `adb root`, no OS modification. This instruments the app process the way a repackaged-malware build would.

Gotchas hit and fixed: `android:extractNativeLibs="true"` in the manifest is rejected by AGP — use the Gradle `useLegacyPackaging` instead. `flutter build apk` drops `--dart-define`, so the first rebuild pointed at the default `10.0.2.2:5000` and timed out; rebuild with `--dart-define=API_BASE_URL=http://192.168.100.13:5000`. The gadget adds ~20 s to first launch.

### Result

Ground truth: gadget listening on 127.0.0.1:27042 (that port is opened only by the gadget, inside our process). App-process `/proc/<pid>/maps` is unreadable from `adb shell` on this enforcing device — the same SELinux restriction that hid `su` — but the collector reads its *own* maps, so it is unaffected.

```text
Bootstrap scan (gadget in process), enforce mode:
  score=100 verdict=block
  android_frida_runtime_artifact +90    <- collector found the gadget in its OWN /proc/self/maps
  android_frida_port_open        +75
  android_developer_options       +8
  android_adb_enabled            +10
```

Enforcement, using account `oppo1` (created earlier while the device was trusted — proving the gate is not simply refusing everything: that registration returned 201):

```text
POST /v1/accounts/login -> 403   integrity_blocked
  (login first ran a fresh scan: integrity/challenge 200, integrity/report 200 -> block)
App: "The latest device-integrity verdict is blocked. [integrity_blocked]"
```

**PASS.** Correct credentials + a hardware-backed (`secure_hardware`) installation key + a valid access proof were refused on a production, non-rooted device solely because a real Frida Gadget was detected in the process. `android_frida_runtime_artifact` firing is the property `root_files` could not deliver: an in-process compromise is caught despite enforcing SELinux, because it is a self-process read rather than a file stat.

### Cleanup / device restored

All gadget scaffolding was reverted (MainActivity, Gradle, manifest, jniLibs removed — these were never committed). A clean APK was rebuilt (`0` Frida entries verified in the APK) and installed over the compromised one; the OPPO now scans `score=18 verdict=trusted` with no listener on 27042. The server lab overrides were cleared back to empty, so `INTEGRITY_MODE=observe` (production-representative) and enforcement is off. The phone's OS was never touched.

Caveat: the gadget test wrote a `block` report against the OPPO's `device_id`, so device-level integrity memory (change d) holds it for ~24 h. Irrelevant in observe mode; but if someone flips `INTEGRITY_MODE=enforce` within that window the OPPO will be refused with `integrity_device_blocked_recently` until the report ages out (or its `integrity_reports` rows are deleted).

### Emulator input note

The AVD `integrity_root_lab` has `hw.keyboard=no`, so host keystrokes never reach it; drive text with `adb -s emulator-5554 shell input text "..."` / `input tap X Y`. The OPPO accepts `adb input` too.

## 23. Frida Gadget on a Huawei (second-vendor confirmation) — PASS (2026-09-04)

Repeated the §22 real-compromise test on a Huawei to confirm it is not OPPO-specific.

### Device (unchanged, never rooted)

```text
HUAWEI AQM-LX1 (Y6p), arm64-v8a, API 29, build=user tags=release-keys
ro.secure=1 ro.debuggable=0
verifiedbootstate=green flash.locked=1 vbmeta.device_state=locked veritymode=enforcing
SELinux=Enforcing   su=none   GMS packages=0 (no Google Play Services — irrelevant, no Play Integrity is used)
```

Host setup notes: the P10-class USB descriptor needed the phone switched to Transfer files (MTP) before adb saw it, then a udev rule for Huawei's vendor id `12d1` (`/etc/udev/rules.d/51-android-huawei.rules`, MODE 0666 GROUP plugdev) to clear "no permissions". The pre-existing app was signed with a different debug keystore, so it was uninstalled before installing the current build (signature mismatch is expected across machines — see the ANDROID_ID signing-scope note).

### Result (enforce mode, secure_hardware-backed key)

```text
clean baseline:              score=18  verdict=trusted   developer_options +8, adb +10
real gadget in process:      score=100 verdict=block     android_frida_runtime_artifact +90,
                                                          android_frida_port_open +75, +dev/adb
POST /v1/accounts/register:  403  integrity_blocked
counterfactual (observe):    POST /v1/accounts/register -> 201   (same compromised device)
```

The Huawei registered as its own server device (device_id `65aeb493…`), distinct from the OPPO — expected. `android_frida_runtime_artifact` fired from the collector's own `/proc/self/maps` read despite enforcing SELinux, exactly as on the OPPO. **PASS.** Detection and enforcement are vendor-independent.

### Cleanup / device restored

Gadget scaffolding reverted (never committed), clean APK rebuilt (`0` Frida entries) and installed over the compromised one; the Huawei scans `18/trusted` with no listener on 27042. Server left in observe mode (production-representative). Same 24 h device-memory caveat as the OPPO applies to this device's `device_id`. OS never touched.

## 24. Product direction and database portability (2026-09-05)

### What is being built

The proof of concept becomes a reusable framework: **client SDKs in Flutter/Dart, .NET and Python**, one **server implementation** (this Python service), and **database setup scripts** so a customer runs *their app + this server + their database*. Payactiv runs mostly SQL Server with some PostgreSQL.

**.NET is a client SDK, not a second server.** That decision matters: two independent implementations of signature verification, nonce handling and scoring would double the security-review surface and risk a subtle divergence being a vulnerability in one of them. One server, many clients.

### Supported database matrix

| Engine | Syntax floor | Tested range | Rationale |
|---|---|---|---|
| PostgreSQL | 13 | **13 - 18** | Lab runs 13.23; RDS covers 14-18. All verified. |
| SQL Server | 2016 | **2017 - 2025** | Written to 2016-compatible T-SQL, but 2016 is untestable: no RDS edition offers it, and SQL Server on Linux began with 2017, so there is no container either. Testing 2016 would need a Windows host. Decision (2026-09-05): keep 2016 syntax compatibility, set the **tested floor at 2017** and the **ceiling at 2025**. |

SQL Server releases in range: **2017 (14.00), 2019 (15.00), 2022 (16.00), 2025 (17.00)** - four releases. There is no SQL Server 2018, 2020 or 2021.

Both floors are 2016-era, so the supported window is roughly a decade. `/health/ready` now reports `database.engine`, `.version`, `.minimum_supported` and `.supported`, and the server logs an error when running below the floor. `DB_ENGINE` (`postgresql` | `sqlserver`) is the dialect selector.

### Compatibility policy — do not use

*PostgreSQL (13 floor):* no `MERGE` (15+), no `JSON_TABLE` (17+), no `NULLS NOT DISTINCT` (15+), no multirange types (14+).

*SQL Server (2016 floor):* no `STRING_AGG` (2017+), no `_UTF8` collations (2019+), no `GENERATE_SERIES` (2022+). There is **no `CREATE TABLE IF NOT EXISTS` in any version** — DDL needs `sys.tables`/`sys.columns` guards.

### Type mapping

| Purpose | PostgreSQL 13+ | SQL Server 2016+ |
|---|---|---|
| UUID keys | `uuid` | `char(36) COLLATE Latin1_General_BIN2` |
| SHA-256 hex digests | `char(64)` | `char(64) COLLATE Latin1_General_BIN2` |
| Timestamps | `timestamptz` | `datetimeoffset(3)`, always UTC |
| JSON documents | `jsonb` | **`nvarchar(max)`** + optional `CHECK (ISJSON(col)=1)` |
| bcrypt hash | `bytea` | `varbinary(255)` |
| Booleans | `boolean` | `bit` |
| "now" | `NOW()` | **`SYSUTCDATETIME()`**, never `GETDATE()` |
| Interval math | `NOW() - INTERVAL '1 day'` | `DATEADD(day, -1, SYSUTCDATETIME())` |
| Partial/filtered index | `CREATE INDEX ... WHERE used_at IS NULL` | same syntax; SQL Server filtered indexes permit `IS NULL` |

**`nvarchar(max)` for JSON is not cosmetic.** SQL Server 2016/2017 have no UTF-8 collation, and probe output (`build_tags`, `su_path`, OEM error strings) can contain non-ASCII. `varchar` would corrupt it.

**BIN2 collation on key columns is not cosmetic either.** The RDS default `SQL_Latin1_General_CP1_CI_AS` is case-insensitive, so any base64url value used as a unique key would collide (`aB` == `Ab`). Every unique text column is hex today, so we are safe by luck rather than design; BIN2 makes it design.

### The two security-critical dialect differences

1. **Replay defence** (`access_proof_nonces`). Postgres uses `INSERT ... ON CONFLICT DO NOTHING RETURNING`. SQL Server has no equivalent, and both tempting translations are traps: `MERGE` is racy without `HOLDLOCK`, and `IF NOT EXISTS(...) INSERT` under READ COMMITTED lets two concurrent identical proofs both succeed. **Portable fix, simpler than the current code: plain `INSERT`, treat a driver duplicate-key error as the replay signal.** Identical atomicity on both engines.
2. **Refresh-reuse detection** (`SELECT ... FOR UPDATE`, 2 sites). SQL Server needs `WITH (UPDLOCK, ROWLOCK)`; Postgres is MVCC and SQL Server's READ COMMITTED is not. Getting this wrong lets family revocation be raced.

Driver: **pyodbc + msodbcsql18** with the RDS CA bundle installed. Never `TrustServerCertificate=yes`.

### Client-SDK contract invariants (do not "optimise" these away)

- **The signature covers exactly the bytes the client sent.** `X-Access-Proof` is base64url-decoded, the signature is verified over those bytes, and only then parsed. Therefore Dart, .NET and Python do **not** need byte-identical JSON serialisation — no RFC 8785 canonicalisation. Any server-side re-serialisation before verification would silently break every non-Dart SDK.
- **Signatures are ASN.1 DER.** In .NET, `ECDsa.SignData()`'s default overload emits IEEE-P1363 (`r||s`) and will fail every verification; the SDK must pass `DSASignatureFormat.Rfc3279DerSequence`.
- **The error envelope is `{"error": {"code": ..., "message": ...}}`** — nested, not flat. All SDKs read `error.code` from that shape.

### Runtime DDL must become migrations before this ships

`schema_guard` executes `_SCHEMA_SQL` on every request. Acceptable for a PoC, unacceptable for a product: enterprise DBAs will reject an application that issues `CREATE`/`ALTER` against production, and it forces the app's database principal to hold DDL rights permanently — a finding in its own right. Ship versioned migration scripts per dialect; the app should verify schema version at boot and refuse to start on mismatch.

### Phase plan

| Phase | Work | Status |
|---|---|---|
| 0 | Conformance suite (`conformance_suite.py`) | **DONE** — 13/13 on PostgreSQL 13.23 |
| 0b | Extend to integrity scoring and the enforcement gate | **DONE** — 26/26 on PostgreSQL 13.23 |
| 1 | RDS PostgreSQL + Supabase, HTTPS | pending |
| 2 | Database abstraction, PostgreSQL only, suite stays green | pending |
| 3 | SQL Server dialect, same suite, diff the results | pending |
| 4 | Package Dart / .NET / Python SDKs | pending |

Phase 2 precedes 3 deliberately: the abstraction lands while PostgreSQL is still the reference, so a regression is caught against known-good behaviour rather than while also debugging T-SQL.

### 24.1 Conformance suite coverage (phase 0 + 0b complete, 2026-09-05)

`conformance_suite.py` now has **26 checks, all passing against PostgreSQL 13.23**, and runs unchanged in either integrity mode (it scans before account operations, as a real client does; the two enforcement checks SKIP in observe mode).

*Protocol and identity:* enrolment, key-thumbprint authority over the client UUID, signed-challenge device token, account opening.

*Access proof:* happy path, exact replay, body/path/method tampering, stale timestamp, and a proof signed by the wrong key.

*Refresh:* rotation, and reuse revoking the family.

*Integrity scoring* (crafted probe payloads, no phone needed): pristine device scores 0/trusted; **unreadable SELinux stays telemetry** — the regression guard for the OPPO false positive; permissive SELinux; Frida in `/proc/self/maps`; open Frida port; root framework + `su`; writable protected mount; development OS image (build type + test-keys); absent AVB data; signing-certificate mismatch as a capped hard block; failed-probe penalty.

*Enforcement:* a blocked device is refused with `integrity_blocked`, and **reinstalling does not clear a blocked device** (`integrity_device_blocked_recently`) — change (d), keyed on `device_id` across installations.

Five checks are tagged `[db]` as the ones whose behaviour depends on the engine: replay (upsert/duplicate-key), refresh rotation and reuse (row locking), thumbprint identity (JSON round-trip), stale timestamp (timezone round-trip), device memory (cross-installation `device_id` query).

**To run the scoring checks**, start the server with `INTEGRITY_ANDROID_CERT_SHA256` set to the certificate the suite prints (it fails with that instruction otherwise), or empty to disable the allow-list. Restore the real certificate afterwards or the physical phones will hard-block.

### 24.2 Agreed: versioned migration scripts per dialect

The runtime DDL in `schema_guard` will be replaced by **versioned migration scripts per dialect**, run by a DBA, with the application verifying schema version at boot and refusing to start on mismatch. Agreed 2026-09-05. Rationale: enterprise DBAs reject applications that issue `CREATE`/`ALTER` against production, and runtime DDL forces the application's database principal to hold DDL rights permanently. This also shapes the "server file(s) to set up their database" deliverable — those files become the migration set.

## 25. Phase 1a — AWS, HTTPS, PostgreSQL RDS — PASS (2026-09-05)

First deployment off the lab laptop. Everything below ran against AWS in `us-west-2`, created for the test and torn down afterwards.

### Infrastructure

```text
EC2      t4g.micro, Ubuntu 24.04.4 LTS arm64, Python 3.12.3, Redis 7 installed (not yet wired in)
RDS      devicetrust-pg, PostgreSQL 18.1, db.t4g.micro, private, encrypted,
         backup-retention-period 0 (so no snapshot can survive teardown)
Network  default VPC. No NAT Gateway, no Elastic IP, no load balancer
TLS      Caddy serving <dashed-ip>.nip.io with a real Let's Encrypt certificate -
         HTTPS with no domain purchase and no DNS work
Cost     ~USD 0.031/hour (~PKR 9/hour)
```

The client now takes its endpoint only from `--dart-define=API_BASE_URL`; there is no default, and a build without one fails with `api_base_url_missing`.

### Results

Conformance suite against PostgreSQL 18.1 over HTTPS, enforce mode, real certificate allow-list:

```text
26 passed, 0 failed, 0 skipped
```

The lab proved PostgreSQL 13.23 and this proves 18.1, so both ends of the supported range are now covered by the same 26 assertions.

Physical OPPO CPH2083 against the same stack:

```text
debug APK:    score=53 verdict=elevated   android_app_debuggable +35, dev options +8, adb +10
release APK:  score=18 verdict=trusted    dev options +8, adb +10
              POST /v1/accounts/register -> 201 through the enforce-mode gate
```

**The debug-build result is a finding, not a nuisance.** The lab server had `INTEGRITY_ALLOW_DEBUG=1` set, which had been silently suppressing `android_app_debuggable +35` for the whole proof of concept. A production-representative server rejects a debug build in enforce mode, exactly as it should. The release build scores the historical clean baseline of 18 with no lab switches enabled at all — no `INTEGRITY_ALLOW_DEBUG`, no `INTEGRITY_ALLOW_EMULATOR`, no `INTEGRITY_ALLOW_USERDEBUG`.

### Notes for the next round

- `psycopg2`'s default `sslmode=prefer` already negotiates TLS against RDS, so no code change was needed to connect. Explicit `sslmode=verify-full` with the RDS CA bundle remains the production hardening, and is still worth doing.
- Redis is installed on the instance and answering, ready to be wired in as the nonce replay cache and rate limiter.
- SQL Server cannot be tested until the dialect work exists; an RDS SQL Server instance would have nothing to run against.

### 25.1 OPPO full battery on AWS, release builds only (2026-09-05)

All builds release (`flutter build apk --release`), server in enforce mode with `verify-full` database TLS, a real certificate allow-list, and no `INTEGRITY_ALLOW_*` switches set.

```text
1  clean release                     score=18  trusted   -> POST /v1/accounts/register 201
2  debug build (for comparison)      score=53  elevated  android_app_debuggable +35
3  release + embedded Frida Gadget   score=100 block      frida_runtime_artifact +90, frida_port_open +75
4  account attempt while compromised 403 integrity_blocked
5  gadget removed, clean release     score=18  trusted
6  new install, new key, clean scan  403 integrity_device_blocked_recently
```

Step 6 is the first proof of change (d) on production hardware. The installation was new, its key thumbprint was new, and its own integrity scan was clean at 18/trusted - yet the server refused it because the physical device had been Frida-compromised minutes earlier. Recognition of the device outlived both the application install and the cryptographic identity.

Step 2 is a finding rather than a nuisance: the lab server had `INTEGRITY_ALLOW_DEBUG=1` set, which suppressed `android_app_debuggable +35` for the entire proof of concept. A production-representative server refuses a debug build in enforce mode. **All builds are release from now on.**

The Frida Gadget works in a release build: it is an ordinary bundled native library loaded with `System.loadLibrary`, so it does not depend on the app being debuggable. Only the synthetic debug fixtures are unavailable in release, and they are not needed for real-compromise testing.

Operational note: one bootstrap timed out client-side with the request never reaching the server, and a plain relaunch succeeded. The phone's Wi-Fi showed 120-700 ms jitter to 8.8.8.8 at the time. Retry before investigating; the 15 s client timeout is tight for a congested link.

### 25.2 Huawei full battery on AWS — identical to the OPPO (2026-09-05)

Same six steps, same release-only builds, same server (PostgreSQL 18.1 on RDS, enforce mode, `verify-full` TLS, real certificate allow-list, no `INTEGRITY_ALLOW_*` switches).

```text
1  clean release                     score=18  trusted   -> POST /v1/accounts/register 201 (hw1)
2  release + embedded Frida Gadget   score=100 block      frida_runtime_artifact +90, frida_port_open +75
3  account attempt while compromised 403 integrity_blocked
4  gadget removed, clean release     score=18  trusted
5  new install, new key, clean scan  403 integrity_device_blocked_recently
```

**No behavioural difference between the two handsets.** Both are `user`/`release-keys` builds with green Verified Boot, enforcing SELinux and `secure_hardware`-backed keys, and both produced identical scores, identical reason codes and identical verdicts at every step. The Huawei's lack of Google Play Services is irrelevant, as expected, because no Play Integrity or remote attestation is used.

### 25.3 Results matrix

Full battery = both phones, six steps each, real Frida Gadget. Conformance = the 26-check suite.

| Backend | Version | Conformance | Full battery | Notes |
|---|---|---|---|---|
| PostgreSQL (lab) | 13.23 | 26/26 | n/a | Debian 11 laptop, the supported floor |
| PostgreSQL (RDS) | 18.1 | 26/26 | OPPO + Huawei, both clean | HTTPS, verify-full TLS, enforce |
| PostgreSQL (RDS) | 17.11 | 26/26 (x2, incl. verify-full) | covered by 18.1 | |
| PostgreSQL (RDS) | 16.15 | 26/26 (x2, incl. verify-full) | covered by 18.1 | |
| PostgreSQL (RDS) | 15.19 | 26/26 (x2, incl. verify-full) | covered by 18.1 | |
| PostgreSQL (RDS) | 14.24 | 26/26 (x2, incl. verify-full) | covered by 18.1 | |
| PostgreSQL (RDS) | 13.x | not run | | past RDS standard support; needs paid Extended Support, and 13.23 is already proven in the lab |
| SQL Server (RDS) | 2017 (14.00) | pending | pending | needs dialect + Redis |
| SQL Server (RDS) | 2019 (15.00) | pending | pending | |
| SQL Server (RDS) | 2022 (16.00) | pending | pending | |
| SQL Server (RDS) | 2025 (17.00) | pending | pending | |
| SQL Server | 2016 (13.00) | not testable | | no RDS edition, no Linux build; syntax compatibility retained |
| Supabase | - | pending | | |

Per-phone differences observed so far: **none**.

Cross-device tests (require two physical handsets, cannot be simulated by the harness):

| Test | Result |
|---|---|
| Stolen refresh token, Phone A -> Phone B | PASS, `invalid_installation_signature` |
| Stolen access token, Phone A -> Phone B | PASS, `invalid_installation_signature` |
| Legitimate bound refresh on Phone A | PASS, session rotated |
| Legitimate protected request on Phone A | PASS, full proof accepted |

### 25.4 PostgreSQL version sweep — complete (2026-09-05)

Four instances were created in parallel rather than sequentially: five `db.t4g.micro` instances cost about USD 0.09/hour combined and existed for well under an hour, so the spend was the same as doing it one at a time while saving roughly forty minutes of waiting. Each was tested by repointing `DB_HOST` and restarting the service; every database starts empty and the schema guard builds it on first request.

```text
PostgreSQL 13.23  (lab, Debian 11)  26/26     the supported floor
PostgreSQL 14.24  (RDS)             26/26
PostgreSQL 15.19  (RDS)             26/26
PostgreSQL 16.15  (RDS)             26/26
PostgreSQL 17.11  (RDS)             26/26
PostgreSQL 18.1   (RDS)             26/26     plus the full battery on both handsets
```

**The entire supported range 13 through 18 behaves identically**, including the five database-sensitive checks (replay upsert, refresh rotation and reuse row-locking, thumbprint JSON round-trip, timestamp timezone round-trip, cross-installation device memory). No version-specific behaviour was found, so the PostgreSQL floor of 13 is justified by evidence rather than assumption.

PostgreSQL 13 on RDS was deliberately skipped: it is past RDS standard support and would require opting into paid Extended Support at roughly USD 0.10 per vCPU-hour, about seven times the instance cost, to re-prove a minor version (13.23) the lab has already validated.

### 25.5 Cross-device stolen-token tests on AWS — PASS (2026-09-05)

The one property the software conformance harness cannot demonstrate: it generates both keys in the same process, so "signed by the wrong key" is simulated. This ran with **two physically separate hardware keystores**, OPPO as Phone A and Huawei as Phone B, against PostgreSQL 18.1 on RDS over HTTPS in enforce mode. Release builds throughout.

```text
stolen refresh token   challenge 200  -> refresh 401  invalid_installation_signature
stolen access token    protected 401                  invalid_installation_signature
                       "access token reached proof verification: yes"
```

Both results have the same important shape: **the stolen credential was accepted as genuine** — the refresh challenge returned 200 and the access token reached proof verification — and the rejection happened at *signature verification*, because Phone B signed with its own Keystore key. The binding is to the hardware key, not to token validity or freshness.

Contrast, on Phone A in the same session:

```text
legitimate bound refresh   PASS  session aab35032 -> fab74388, native signature accepted
legitimate protected call  PASS  body SHA-256, timestamp window, one-time nonce,
                                 native signature all accepted
```

So the same server, in the same minute, accepted the legitimate device and refused the thief.

**Method note.** Injecting the token by `adb shell input text` corrupted it — the predictive keyboard inserted spaces — and the app correctly reported `INCONCLUSIVE: refresh challenge was rejected before key proof` with `invalid_token` rather than claiming a pass. That is the test harness behaving well: a malformed-token rejection is not evidence of key binding. The tokens were then supplied through the app's designed `--dart-define=STOLEN_REFRESH_TOKEN` / `STOLEN_ACCESS_TOKEN` build-time mechanism, which is keyboard-free and exact. Use that route; the access token's 10-minute lifetime means minting it immediately before the build.

### 25.6 Access-proof boundary tests on both handsets — PASS (2026-09-05)

Release builds, PostgreSQL 18.1 on RDS, enforce mode. Identical results on OPPO and Huawei:

```text
1  exact signed-request replay   401 access_proof_replay                   (first 200; same proof, signature and nonce reused)
2  body tampering                401 access_proof_body_mismatch            (signed original, sent modified)
3  path tampering                401 access_proof_path_mismatch
   method tampering              401 access_proof_method_mismatch
4  stale proof                   401 access_proof_timestamp_outside_window (age 180s vs 120s allowed)
```

An earlier attempt returned INCONCLUSIVE with `expired_token` because the access token had passed its 10-minute life. **Operationally: run the boundary tests within 10 minutes of a session refresh**, since a token-expiry rejection proves nothing about proof binding. The app distinguishes the two, which is why the first attempt was not miscounted as a pass.

### 25.7 Scope decision: controlled Android compromise fixtures retired (2026-09-05)

The six debug-only fixtures are **removed from the test plan**. They are gated by `applyDebugTestFixture`, which refuses to run on a non-debuggable APK, so they are incompatible with the release-only build policy; and running them would require `INTEGRITY_ALLOW_DEBUG=1`, the very switch that concealed `android_app_debuggable +35` throughout the proof of concept.

They are also superseded: fixtures 1, 2 and 6 (Frida runtime, Frida port, enforcement rejection) are proven far better by the embedded Frida Gadget on real hardware, and all six scoring rules are asserted deterministically by the conformance suite. Fixtures 3, 4 and 5 (hook framework, root/su, writable mount) have no real-tooling equivalent yet and remain covered only by the suite.

### 25.8 PostgreSQL 18.1 — full suite complete, both handsets

| Test | OPPO | Huawei |
|---|---|---|
| Clean baseline | 18/trusted | 18/trusted |
| Account creation through enforce gate | 201 | 201 |
| Stolen refresh token (cross-device) | PASS | n/a (was Phone B) |
| Stolen access token (cross-device) | PASS | n/a (was Phone B) |
| Real Frida Gadget -> block | PASS | PASS |
| Account refused while compromised | PASS | PASS |
| Device memory after reinstall | PASS | PASS |
| Access-proof boundary tests (4) | PASS | PASS |

Note the stolen-token rows: the OPPO was Phone A (victim) and the Huawei Phone B (thief), so the pair is tested once, not once per handset.

### 25.9 PostgreSQL phase closed (2026-09-05)

Second sweep of 17.11, 16.15, 15.19 and 14.24 under `verify-full` database TLS: **26/26 each**, matching the first sweep. Each instance was torn down as it passed.

Decision taken: the full manual handset suite was run once on PostgreSQL 18.1 (both handsets, every test) rather than repeated per version. What differs between these versions is only the PostgreSQL minor version, which the handset cannot observe - the Dart client, the Kotlin collector and the server code are byte-identical across the runs, and the conformance suite is the instrument that detects dialect behaviour. Repeating the manual suite four more times would have cost roughly three hours of hands-on work for no additional signal.

**PostgreSQL support is now evidence-backed across 13 through 18**, with the full handset suite proven on 18.1 and the 26-check suite green on every version.

Teardown verified: no snapshots, no instances, no unattached volumes, no unattached Elastic IPs, no NAT gateways. Only the EC2 host remains, deliberately.

### 25.10 Next: SQL Server dialect

No further database testing is possible until the dialect exists. `DB_ENGINE=sqlserver` currently has a version-detection branch and nothing else: no driver, no T-SQL schema, no dialect-aware queries. See section 24 for the type mapping, the compatibility policy and the two security-critical dialect differences (replay upsert semantics and refresh-reuse row locking).

Supabase needs **no dialect** - it is PostgreSQL. It will be a connection-configuration test (direct connection on 5432 versus the pooler on 6543), not an engineering phase.

### 25.11 The standard per-engine handset suite — canonical list (updated 2026-09-06)

Fixed definition, so each engine family is tested identically and results are comparable. Run once
per **engine family**, on **both handsets**, with **release builds only**. Items 13 and 14 were added
after the original four groups and are folded in here so this list is the single source of truth.

| # | Item | Pass criterion | Phones |
|---|---|---|---|
| 1 | Clean baseline scan | **Android:** `score=18 verdict=trusted` (dev options +8, adb +10). **iOS:** `score=0 verdict=trusted` on a build put through `tools/presign_trollstore_ipa.sh`, with `INTEGRITY_ALLOW_DEBUG=0` and `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0` | each |
| 2 | Account creation through the enforce gate | `POST /v1/accounts/register` 201 | each |
| 3 | Stolen access token | `invalid_installation_signature`, refused *after* reaching proof verification | **both, simultaneously** |
| 4 | Stolen refresh token | refresh challenge 200 (token genuine) **then** refresh 401 | **both, simultaneously** |
| 5 | Boundary: exact replay | 200 then 401 `access_proof_replay` | each |
| 6 | Boundary: body tampering | 401 `access_proof_body_mismatch` | each |
| 7 | Boundary: path + method tampering | 401 `access_proof_path_mismatch` and `_method_mismatch` | each |
| 8 | Boundary: stale timestamp | 401 `access_proof_timestamp_outside_window` | each |
| 9 | Frida Gadget — **name-based** detection (gadget left named `libfrida-gadget.so`, port 27042) | `score=100 verdict=block`, `frida_runtime_artifact` +90 | each |
| 10 | Frida Gadget — enforcement | `POST /v1/accounts/login` 403 `integrity_blocked` | each |
| 11 | Frida Gadget — restore | clean APK (0 frida entries) returns `18/trusted` | each |
| 12 | Device memory across a new hardware key | **Android:** full uninstall + reinstall. **iOS:** `deleteKey` then re-enrol (see below). Either way a new hardware key → 403 `integrity_device_blocked_recently` | each |
| 13 | Pristine re-enrolment (recognition) | **Android:** uninstall + reinstall. **iOS:** `deleteKey` then re-enrol. `devices` unchanged, `installations` +1, same `device_id`, **login 200** | each |
| 14 | Structural code-integrity (ext bucket) | deferred libc++ hook → `ext_diff_bytes > 0` → `android_code_integrity_violation` +90 → `block` | each |
| 15 | Key survives app reinstall (**iOS only**) | uninstall + reinstall **without** `deleteKey` → `getOrCreateKey` returns `created: false`, the **same** key thumbprint, and the same `installation_id` | iPhone |
| 16 | Structural code-integrity (**app bucket**) | hook or modify the app's **own** native code → `app_diff_bytes > 0` → `android_app_code_modified` +90 → `block` | each |

**Item 9 is the weakest item in the list, and is now named to say so.** It tests detection by
*filename*, which §27.11 proved defeatable — a real gadget renamed `libhelper.so` and moved off port
27042 scored `18/trusted` while fully active. It is kept because an attacker who does not bother to
rename should still be caught cheaply, but a passing item 9 proves far less than a passing item 14
or 16.

**When running items 14 and 16, rename the gadget and move its port deliberately.** Otherwise the
name-based signals fire, the verdict is over-determined, and those items pass for the wrong reason
without testing the structural probes at all. This is a correction to how item 14 was first run in
§30.3: `android_frida_runtime_artifact` fired alongside the structural reasons, so the block was
over-determined. The bucket evidence (`ext_diff_bytes 100`) was still unambiguous, but the run did
not isolate what it claimed to. The .NET session ran it correctly — gadget renamed, port 27999 —
and saw only `android_code_integrity_violation` and `android_instrumentation_runtime_thread` fire.

**Item 16 is item 14 aimed at the application's own code rather than a system library.** They are
separated because they catch different attacks and report through different reasons: 14 raises
`android_code_integrity_violation` from the ext bucket, 16 raises `android_app_code_modified` from
the app bucket. For a customer, 16 is the more directly meaningful — it is *their* code an attacker
wants to patch. An app bucket reporting `app_compared_bytes: 0` is inert rather than clean, and that
is invisible in the score.

**Item 1's two criteria are not arbitrary.** The Android figure is 18 because the test handsets run
with developer options and ADB enabled, which are real signals the server is right to score. The iOS
figure is 0 because an iPhone has no equivalent pair of switches — but only on a **pre-signed** build.
TrollStore grants `get-task-allow` to everything it installs, which is `ios_get_task_allow` +35, and
before §37 that made `trusted` unreachable on iOS at all. Both flag states are named in the criterion
because each changes the expected number: `INTEGRITY_ALLOW_DEBUG=1` would mask the +35 rather than
remove it (and would also disable `ios_process_traced`), and
`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=1` scores the same clean device at 100, since a TrollStore
install trips the fake-signature rules by construction. A bare "score 0" would therefore be
unreproducible.

**Items 12, 13 and 15 differ by platform, deliberately.** Android Keystore entries are destroyed
when the app is uninstalled, so a reinstall necessarily enrols a new hardware key — which is exactly
what items 12 and 13 exercise. **iOS keychain items survive app uninstall**, so on iPhone a reinstall
returns the *same* Secure Enclave key and proves nothing about re-enrolment. The iOS parallel of
"uninstall" is therefore an explicit `deleteKey` on the installation-key channel, which destroys the
Secure Enclave key and forces a genuinely new installation. That preserves each item's *intent* — a
new hardware key on the same physical device must still correlate to the same `device_id`, and must
still be refused while the device is blocked — rather than pretending the platforms behave alike.

Item 15 exists because that divergence is itself a property worth asserting rather than assuming.
On iOS the installation identity survives app reinstall, which is a *stronger* recognition guarantee
than Android's; the test makes it explicit and would catch a future iOS change that silently
weakened it. It has no Android counterpart, because there the key is gone by design.

**Items 5–8 must run within 10 minutes of a session refresh**, or an expired access token makes them
inconclusive. Items 3 and 4 are cross-device by construction — one run exercises both handsets.

Surrounding every run: the device is returned to the clean release build and must scan `trusted`
again before the engine is torn down.

**Item 14 notes.** It is the only item that needs no tap: the gadget script defers its hook with
`setTimeout(..., 4000)` so the libraries are mapped, then the app's own launch scan catches it.
Two things make it work, both learned the hard way — use the Frida 17 API
(`Process.getModuleByName(n).enumerateExports()`, not the removed `Module.*` statics, which throw
and get swallowed), and defer, because at gadget-load time the target libraries are not yet mapped.
It requires `INTEGRITY_SCORE_EXTENDED_LIBS` (on by default since 2026-09-06).

Individual database **versions** within a family get the conformance suite only.
**This reduction was agreed for the PostgreSQL sweep specifically and must not be generalised to
another engine family without asking** — see §27.3, where applying it to SQL Server was wrong. The
handset exercises the client and the native collector, which are byte-identical across versions and
cannot observe the database; the suite is what detects dialect behaviour.

### 25.12 Redis is in scope for the SQL Server phase (2026-09-05)

Redis must be incorporated as part of the SQL Server work, not deferred again. Already installed and answering on the EC2 host. Intended uses, in order of value:

1. **Access-proof nonce replay cache.** `SET <nonce_hash> 1 NX PX <ttl>` is a better fit than a table plus a cleanup sweep: same atomicity, automatic expiry, no `DELETE` pass. It also sidesteps the sharpest dialect difference, since the replay defence stops depending on `ON CONFLICT` versus duplicate-key handling. Must stay switchable (`NONCE_BACKEND=redis|database`) with the database path retained, must enable AOF persistence, and the replay conformance check must pass on both backends.
2. **Rate limiting** on `/v1/accounts/login|register`, `/v1/auth/refresh` and `/v1/installations/register`, per IP and per installation. New protection the system does not have today.
3. Optional short-TTL caching of `_device_integrity_memory`.

Redis is a new dependency (`redis`), the first added since the proof of concept.

---

# 26. Phase 1b — the dialect abstraction, Redis, and SQL Server preparation (2026-09-05)

The server now speaks to both engines through a `Dialect` object chosen by `DB_ENGINE`. What is
worth recording is not that the layer exists but **which constructs refused to be translated
mechanically**, because those are the ones that would have shipped as silent defects.

## 26.1 What token substitution can and cannot do

`SqlServerDialect.sql()` safely rewrites `%s` → `?`, `NOW()` → `SYSUTCDATETIME()`, trailing
`LIMIT n` → leading `TOP n`, and `NOW() - INTERVAL '1 day'` → `DATEADD`. Interval arithmetic must
be rewritten *before* `NOW()` is substituted, or the pattern is no longer recognisable.

Everything else was converted by hand at its call site, deliberately. A regex that rewrote the
locking or replay paths could produce statements that run without error and are silently wrong,
and a wrong lock is not visible in a test that runs one request at a time.

`tools/check_sqlserver_translation.py` walks the module AST, pushes all 51 literal statements
through the SQL Server dialect and fails if any PostgreSQL-only syntax survives. It exists because
adding one more `LIMIT 1` while developing against PostgreSQL is a natural thing to do and would
otherwise surface only on a customer's SQL Server.

## 26.2 The replay defence stopped depending on either engine's upsert

`ON CONFLICT (nonce_hash) DO NOTHING RETURNING nonce_hash` became a plain `INSERT` whose
duplicate-key error *is* the replay signal.

This is not merely portability. Both natural SQL Server translations are **wrong**: `MERGE` is racy
without `HOLDLOCK`, and `IF NOT EXISTS(...) INSERT` is racy under `READ COMMITTED`. Either would
let two concurrent identical proofs through — precisely the attack the nonce exists to stop. The
plain insert has identical atomicity on both engines and is simpler to review.

Single-use challenge consumption moved from `RETURNING challenge_id` to `cursor.rowcount`: the
conditional `UPDATE` is itself the atomic check. **`SET NOCOUNT` must stay OFF** on SQL Server or
`rowcount` stops reporting truthfully.

Row locking is now `DIALECT.row_lock_suffix()` / `row_lock_hint()` — `FOR UPDATE` on PostgreSQL,
`WITH (UPDLOCK, ROWLOCK)` on SQL Server, which is required because `READ COMMITTED` there takes
only shared locks and refresh-reuse detection could otherwise be raced.

## 26.3 Two latent defects found by writing the abstraction

**JSON read-back.** psycopg2 returns parsed `dict`/`list`; pyodbc returns raw text. Only two
columns are read back, and one of them mattered: `integrity_challenges.required_probes` was guarded
by `if not isinstance(required_probes, list): required_probes = []`. On SQL Server that branch
would always have been taken, turning every mandatory-probe requirement into a vacuous one — a
report that omitted **every** probe would have scored as pristine. It now normalises through
`DIALECT.json_value()` and **fails closed** if the stored list is unreadable.

**datetimeoffset.** pyodbc has no native mapping for it and returns the raw 20-byte
`SQL_SS_TIMESTAMPOFFSET` struct, so every timestamp would have arrived as bytes. Worse in the write
direction: pyodbc binds a `datetime` as `SQL_TIMESTAMP` and **drops** `tzinfo` rather than
converting, so a token expiring at `20:00:45+05:30` would be stored as `20:00:45+00:00` and live
five and a half hours longer than intended. An output converter and a `bind_parameters()` hook fix
both directions; verified against a constructed struct.

## 26.4 Redis — implemented, with the failure modes chosen deliberately

Nonces **fail closed**, rate limits **fail open**. Allowing requests when the nonce store is
unreachable would turn a Redis outage into an open replay window; refusing all traffic when the
rate limiter is down would turn a cache outage into a total outage.

`NONCE_BACKEND` defaults to `database`. Redis is faster and removes write load, but it is a weaker
durability guarantee: a committed row survives anything, whereas `appendfsync=everysec` can lose up
to a second of nonces on an unclean stop, and any nonce lost that way stays replayable until its
original expiry. `/health/ready` therefore reports whether AOF is actually enabled, because
`NONCE_BACKEND=redis` without it is a silent downgrade of the replay defence.

Rate limiting keys on the installation id, falling back to the source address. An installation is
bound to a non-exportable key, so unlike an IP an attacker cannot rotate it for a fresh budget.

**Item 3 of §25.12 (caching `_device_integrity_memory`) was deliberately not implemented.** A cached
*block* is harmless, but a cached *trusted* verdict would let a device that has just been
compromised keep passing until the TTL expired. The read is one indexed lookup; the latency saved
does not justify a window in which the system knowingly serves a stale trust decision.

### Results (PostgreSQL 18.1, RDS, through the new layer)

| Configuration | Result |
|---|---|
| `NONCE_BACKEND=database` | 24 passed, 0 failed, 2 skipped |
| `NONCE_BACKEND=redis` | 24 passed, 0 failed, 2 skipped (27 nonce keys present afterwards) |
| Redis stopped, `NONCE_BACKEND=redis` | every access-proof request refused; nothing let through |
| Rate limiter | budget honoured exactly, 429 `rate_limited` on the next attempt, per-installation budgets independent, allows traffic when Redis is down |

The two skips are the enforcement checks, which need `INTEGRITY_MODE=enforce`.

The Redis nonce count is the load-bearing detail: it proves the Redis path was genuinely exercised
rather than silently falling through to the database.

## 26.5 Schema review before first contact with SQL Server

The two migrations declare identical table sets. The only structural difference is
`recognized_devices_platform_hint_unique`, an inline `UNIQUE` constraint on PostgreSQL and a
**filtered** unique index on SQL Server — the documented fix for SQL Server treating NULLs as equal.
Auditing every other uniqueness rule confirmed the remaining three (`key_thumbprint`,
`handle_lookup`, `challenge_id`) are all on `NOT NULL` columns, so `reinstall_hint_hash` was the
only column exposed to that difference.

The SQL Server migration's `schema_migrations` seed row was not guarded, unlike every other
statement in the file, so a second run failed with a primary-key violation after appearing to
succeed. Fixed.

## 26.6 SQL Server version coverage

RDS `sqlserver-ex` offers 2017 (14.00.3540.1), 2019 (15.00.4480.2), 2022 (16.00.4265.3) and
2025 (17.00.4065.4). All four were provisioned in parallel on `db.t3.micro`, `--backup-retention-period 0`,
private, reachable only from the application security group. 2016 remains untestable, as recorded
in §24.

TLS is verified, not merely encrypted: the Amazon RDS CA bundle is installed into the EC2 host's
system trust store, so `Encrypt=yes` with `TrustServerCertificate=no` — and `sqlcmd` without `-C` —
actually validate the certificate. This is the SQL Server equivalent of the `verify-full` decision
taken for PostgreSQL.

---

# 27. Phase 1c — SQL Server 2017 / 2019 / 2022 / 2025 — PASS (2026-09-05)

All four RDS `sqlserver-ex` versions run the conformance suite **identically to PostgreSQL**, with
`NONCE_BACKEND=redis` and rate limiting enabled.

| Engine | Version | Migration | Suite |
|---|---|---|---|
| SQL Server 2017 | 14.0.3540.1 (RTM-CU31-GDR) | 11 tables, 24 indexes, schema v1 | **24 passed, 0 failed, 2 skipped** |
| SQL Server 2019 | 15.0.4480.2 (RTM-CU32-GDR) | 11 tables, schema v1 | **24 passed, 0 failed, 2 skipped** |
| SQL Server 2022 | 16.0.4265.3 (RTM-CU26) | 11 tables, schema v1 | **24 passed, 0 failed, 2 skipped** |
| SQL Server 2025 | 17.0.4065.4 (RTM-CU7) | 11 tables, schema v1 | **24 passed, 0 failed, 2 skipped** |
| PostgreSQL 18.1 | re-run on the final build | — | **24 passed, 0 failed, 2 skipped** |

The two skips are the enforcement checks, which need `INTEGRITY_MODE=enforce`. The final PostgreSQL
re-run matters because the last two fixes changed SQL shared by both engines; it confirms the SQL
Server work cost PostgreSQL nothing.

## 27.1 Three defects found only by running against a real SQL Server

Each of these passed every static check and would have shipped.

**1. Filtered indexes require `SET QUOTED_IDENTIFIER ON` (Msg 1934).** The migration failed at the
filtered unique index. This is nastier than it looks: SQL Server also refuses `INSERT`/`UPDATE`
against a table carrying a filtered index from any session where the option is OFF. SSMS and the
ODBC drivers default it ON; **sqlcmd defaults it OFF**. A migration inheriting the caller's default
therefore succeeds in SSMS and fails in sqlcmd, which reads as a tooling problem rather than a
schema one. The file now sets it explicitly.

**2. `datetimeoffset` is not supported by pyodbc out of the box.** `ODBC SQL type -155 is not yet
supported`. Every timestamp read returned raw bytes until an output converter was registered. The
write direction was the more dangerous half and is described in §26.3.

**3. `DELETE FROM t AS alias` is PostgreSQL-only.** SQL Server answers *Incorrect syntax near the
keyword 'AS'* and wants `DELETE alias FROM t AS alias`. Dropping the alias suits both. This was the
expired-challenge cleanup that must preserve challenges owning a report — the `ForeignKeyViolation`
trap from the proof of concept — so the `NOT EXISTS` guard was retained exactly.

The lesson worth carrying into the SDK work: the dialect differences that hurt were **not** the ones
in the obvious list (`LIMIT`, `NOW()`, `ON CONFLICT`). Those were anticipated and translated. The
ones that bit were a driver type gap, a session option that varies by *client tool*, and an alias in
a `DELETE`. Static translation checking cannot find any of them; only executing against the real
engine can.

## 27.2 TLS

Certificates are verified, not merely encrypted. The Amazon RDS CA bundle is installed in the EC2
host's system trust store, so `Encrypt=yes` with `TrustServerCertificate=no` — and `sqlcmd` run
without `-C` — validate the server certificate. This is the SQL Server equivalent of the
`verify-full` decision recorded for PostgreSQL in §25.

## 27.3 Remaining for this phase — the handset battery runs on EVERY SQL Server version

**Correction (2026-09-05).** The "once per engine family" rule in §25.11 was agreed for the
**PostgreSQL** version sweep and does not carry over to SQL Server. The instruction for SQL Server
is explicit: all versions deployed simultaneously, then each one tested on **both physical
handsets**, and each torn down only once **its own** tests have passed.

So the required work is, for each of 2017, 2019, 2022 and 2025:

1. Apply migration 001 and confirm 11 tables at schema version 1.
2. Conformance suite (done for all four — see the table above).
3. **Handset battery on both the OPPO and the Huawei**, release builds only: stolen access token,
   stolen refresh token, the four access-proof boundary tests, and the Frida Gadget build.
4. Tear that instance down.

The argument that a handset cannot observe the database version is technically true — the Dart
client and Kotlin collector are byte-identical across the runs — but it is not the criterion here.
SQL Server is the platform this proof of concept exists to convince Payactiv about, and a
per-version pass on real hardware is the evidence being assembled. Reduced coverage is not a
substitute for it.

2019, 2022 and 2025 were briefly torn down after the suite passed, on a mistaken reading of §25.11,
and were recreated. 2017 stayed up throughout.

## 27.4 SQL Server 2017 — handset battery on both phones — PASS (2026-09-05)

First full battery (§25.11) against SQL Server, run on real hardware in `INTEGRITY_MODE=enforce`
with `NONCE_BACKEND=redis` and rate limiting on. OPPO CPH2083 (Android 9) and Huawei AQM-LX1
(Android 10), release builds only.

| # | Test | OPPO | Huawei | Evidence |
|---|---|---|---|---|
| 1 | Clean baseline scan | PASS | PASS | `score=18 verdict=trusted` (dev options +8, adb +10) |
| 2 | Account creation through the enforce gate | PASS | PASS | `POST /v1/accounts/register` 201 |
| 3 | Stolen access token | PASS | — | client `PASS: stolen access token rejected`, `invalid_installation_signature`, `GET /v1/account/me` 401 |
| 4 | Stolen refresh token | PASS | — | challenge **200** then refresh **401** `invalid_installation_signature` |
| 5 | Boundary: exact replay | PASS | PASS | 200 then 401 `access_proof_replay` |
| 6 | Boundary: body tampering | PASS | PASS | 401 `access_proof_body_mismatch` |
| 7 | Boundary: path + method | PASS | PASS | 401 `access_proof_path_mismatch` and `access_proof_method_mismatch` |
| 8 | Boundary: stale timestamp | PASS | PASS | 401 `access_proof_timestamp_outside_window` (age 180s, skew 120s) |
| 9 | Frida Gadget — detection | PASS | PASS | `score=100 verdict=block`, `frida_runtime_artifact +90`, `frida_port_open +75` |
| 10 | Frida Gadget — enforcement | PASS | PASS | `POST /v1/accounts/login` **403** |
| 11 | Frida Gadget — restore | PASS | PASS | clean APK (0 frida entries) returns `score=18 trusted` |
| 12 | Device memory across reinstall | PASS | PASS | full uninstall + new key → `403 integrity_device_blocked_recently` |

Tests 3 and 4 are cross-device by construction: the OPPO is the victim, the Huawei the attacker
holding its tokens, so a single run exercises both handsets.

### What this run adds beyond the PostgreSQL result

**The replay defence ran on Redis, on real hardware.** After the handset boundary tests: **18 keys
under `dt:nonce:*` in Redis and 0 rows in `dbo.access_proof_nonces`.** The rewritten replay path —
a plain `INSERT` on the database backend, `SET NX PX` on Redis — was exercised end to end by a
phone, not just by the software conformance client, with no silent fallback to the database.

**Row locking was exercised.** `Test bound refresh` rotated the session (`cd2b35c0` → `6eb74be6` on
the OPPO), which is the `WITH (UPDLOCK, ROWLOCK)` path written for SQL Server; refresh-reuse
revocation depends on it.

**Reinstall correlation holds on SQL Server.** Wiping the app destroys the AndroidKeyStore key, so
the reinstall enrols a genuinely new installation. Counts moved `installations` 8 → 9 → 10 across
the two wipes while `devices` stayed at **8**: both reinstalls correlated back to the same
`device_id` rather than creating new devices. The `char(36) COLLATE Latin1_General_BIN2` hint
columns and the filtered unique index behave as the PostgreSQL originals do.

**The device-memory refusal is the project's stated objective, demonstrated.** After the gadget was
removed both phones scanned `trusted` again, yet login was still refused — and refused with
`integrity_device_blocked_recently`, not `integrity_blocked`. The live measurement was clean; only
the server's memory of *that physical device* being compromised minutes earlier produced the
refusal, and it survived a full app uninstall and a fresh hardware key. That is "a rooted or
compromised device is still caught across reinstalls of an app", shown rather than argued.

`hard_block=0` on the gadget reports is worth noting: the block came from the weighted score
reaching the 100 cap, not from a hard-block rule. The scoring model, not a special case, did the work.

## 27.5 SQL Server 2019 — handset battery on both phones — PASS (2026-09-05)

Same battery as §27.4, `sqlserver 15.0.4480.2`, enforce mode, Redis nonces, rate limiting on.
Migration clean (11 tables, schema v1); conformance suite 24 passed / 0 failed / 2 skipped.

All twelve rows of the §27.4 table repeated with identical results on both handsets. Reinstall
correlation again held: two full app wipes with new hardware keys moved `installations` 4 → 6 while
`devices` stayed at **4**.

### 27.5.1 Defect found on real hardware: the login credential oracle

The user mistyped a password on a Frida-compromised OPPO, and the response differed from the
correct-password case:

```text
blocked device + wrong password    -> 401 invalid_credentials
blocked device + correct password  -> 403 integrity_blocked
```

`account_login` ran `_enforce_integrity_gate` **after** the account lookup and the bcrypt
comparison. The attacker could not obtain tokens — the gate still stopped that — but could
distinguish valid credentials from invalid ones on exactly the device class the gate exists to
distrust, then reuse the confirmed credentials from a clean device or another channel. Rate
limiting throttles the volume but does not remove the oracle.

Fixed by moving the gate ahead of the lookup; it needs only `device_id` and `installation_id`.
Both cases now answer `403` identically, verified on the same compromised handset.
`/v1/accounts/register` already had the correct ordering and is the only other credential-touching
endpoint, so login was the sole instance.

Worth noting how this was found: every synthetic suite run and both prior handset batteries used
the *correct* password, so the oracle was invisible to them. It took a human typo on a
genuinely compromised device. Negative-path inputs deserve a place in the battery.

## 27.6 Factory reset defeats device reputation, not device detection (analysis, 2026-09-05)

Raised during the 2019 run: if a factory reset breaks reinstall correlation, can a compromised
device wipe itself and escape?

**Detection is unaffected.** The gate is a live measurement, not a memory lookup. Every protected
operation mints a challenge, the collector reads its own `/proc/self/maps`, and the report is
scored fresh. A factory-reset phone still running the gadget presents a new `device_id` and still
scores `frida_runtime_artifact +90`, `frida_port_open +75`, `block`. It gets no further than an
un-reset one. To use the app the attacker must remove the compromise, which is the desired outcome.

**Reputation is defeated.** A reset changes `ANDROID_ID`, so the hint changes, so the `device_id`
changes, and the 24-hour block memory is shed.

The consequence for product design is concrete: **permanent device-level blocking is worth less
than it appears**, because a factory reset launders the device. What survives a wipe is the
account. Relationship risk — devices per account, accounts per device, reinstall velocity — keeps
working, and a brand-new device appearing on an established account is itself a signal. Durable
enforcement belongs at the account and relationship layer; device blocking is a short-window
tactical control, which is what the 24-hour retention already encodes.

Beneath this is the boundary recorded from the start: with no independent hardware root of trust
there is nothing to bind to that a factory reset cannot change. This is a limit of the
architecture, honestly stated, not a defect in it.

**Not tested, and deliberately so** — the physical handsets are never wiped. This is analysis, and
is recorded as analysis.

## 27.7 SQL Server 2022 — handset battery on both phones — PASS (2026-09-05)

`sqlserver 16.0.4265.3`, enforce mode, Redis nonces, rate limiting on. Migration clean (11 tables,
schema v1); conformance suite 24 passed / 0 failed / 2 skipped. All twelve rows of the §27.4 table
repeated with identical results on both handsets, on the build carrying the §27.5.1 gate fix.

### 27.7.1 New test: pristine device reinstall (the recognition direction)

Added because every reinstall test so far had been run on a device that was **already blocked**, so
the project had demonstrated the *security* half — a compromised device cannot launder a block —
while only inferring the *recognition* half, which is the product's primary claim.

Run on the OPPO with no block history on this database, before the gadget step:

```text
device -> installation map BEFORE wipe     AFTER wipe
  2e0a5467 | 1                               2e0a5467 | 1
  640be460 | 1                               640be460 | 1
  b73cd620 | 1                               b73cd620 | 1
  dba7ccf3 | 1                    ------>    dba7ccf3 | 2
```

The device_id set is unchanged and the OPPO's new installation joined its existing device. The
fresh install scanned `18/trusted` and **`POST /v1/accounts/login` returned 200** —
"Account authenticated on the recognized device".

That last step is what the earlier tests never showed: a full uninstall, a brand-new
non-exportable hardware key, and the same physical device is recognised and **still usable**,
reaching the account created by the previous installation. Correlation works to recognise, not only
to punish.

The contrast within one session makes the control legible: the same handset, the same wipe
procedure, returned `200` before the gadget run and `403 integrity_device_blocked_recently` after
it. The only variable was the device's own recent history.

### 27.7.2 A 400 seen during the run, and why it is not a second oracle

One login returned `400` before the expected `403`. Cause: after a wipe the app's password field is
empty, and `_password_bytes` enforces a 10–72 byte password before the gate is reached.

This ordering is safe and is *not* the §27.5.1 defect repeated. `_handle_lookup` is a pure HMAC and
`_password_bytes` is a length check; neither touches the database. A `400` tells the caller only
that its own request was malformed, and discloses nothing about whether an account exists or a
password is correct — which is precisely what the fixed oracle did disclose. Input-shape validation
before the gate is fine; credential *comparison* before the gate is not.

## 27.8 SQL Server 2025 — handset battery on both phones — PASS (2026-09-05)

`sqlserver 17.0.4065.4`, enforce mode, Redis nonces, rate limiting on. Migration clean (11 tables,
schema v1); conformance suite 24 passed / 0 failed / 2 skipped. All twelve rows of the §27.4 table
repeated with identical results on both handsets. Reinstall correlation held again: two wipes moved
`installations` 4 → 6 with `devices` unchanged at 4.

## 27.9 SQL Server phase closed — the complete matrix

| Engine version | Migration | Conformance suite | Handset battery, both phones |
|---|---|---|---|
| SQL Server 2017 — 14.0.3540.1 | 11 tables, v1 | 24/0/2 | **PASS** (§27.4) |
| SQL Server 2019 — 15.0.4480.2 | 11 tables, v1 | 24/0/2 | **PASS** (§27.5) |
| SQL Server 2022 — 16.0.4265.3 | 11 tables, v1 | 24/0/2 | **PASS** (§27.7, plus the pristine-reinstall test) |
| SQL Server 2025 — 17.0.4065.4 | 11 tables, v1 | 24/0/2 | **PASS** (§27.8) |

Every version was deployed simultaneously and torn down only once its own battery had passed, with
`--skip-final-snapshot --delete-automated-backups`; the manual and automated snapshot listings were
verified empty. PostgreSQL 18.1 was re-verified on the final build and then removed.

Four defects were found across this phase, and **none of them were findable by static analysis**:
`QUOTED_IDENTIFIER` for filtered indexes, pyodbc's missing `datetimeoffset` support, the
PostgreSQL-only aliased `DELETE`, and the login credential oracle (§27.5.1) — the last of which took
a human mistyping a password on a genuinely compromised handset.

## 27.10 Known limitation: hook detection is a name denylist

Recorded because it bounds what today's PASS results actually prove.

`IntegrityProbeManager` scores `/proc/self/maps` by matching tokens: `frida`, `gadget`, `objection`,
`xposed`, `lsposed`, `substrate`, `cydia`, `zygisk`, `riru`, `magisk`. Every real-compromise test so
far — emulator frida-server, and the Gadget on both handsets — used tooling whose mapped path
contains one of those strings. So the passing results demonstrate that **in-process instrumentation
is caught when it identifies itself by name**, which is weaker than "hooking is caught".

Candidate additions, ordered by value, all runnable without rooting the handsets because they are
repackaged-app vectors:

1. **Gadget in script mode with no listener.** Costs nothing new. Today `android_frida_runtime_artifact`
   and `android_frida_port_open` always fire together, so it is not yet established that the maps
   read stands on its own.
2. **An unnamed inline-hooking library** (Dobby, ShadowHook, And64InlineHook) embedded in the APK.
   None carries a denylisted token. Expected to **evade** current detection; that is the point of
   running it.
3. **App-cloning containers** (VirtualApp derivatives — Parallel Space, Dual Space, VirtualXposed).
   No root, and a common multi-accounting fraud vector in fintech, so directly relevant to the
   target deployment. Probably undetected today.
4. **LSPatch**, which embeds LSPosed into an APK without root.

The durable answer is not a longer denylist but **structural detection**: comparing the prologue
bytes of critical libc/JNI functions against their on-disk originals, or diffing a loaded library's
in-memory `.text` against the file on disk. That catches an unnamed hooking library; no name list
ever will.

## 27.11 Hook-detection probe tests — one reassuring, one a confirmed evasion (2026-09-05)

Two follow-up tests on the OPPO to characterise the §27.10 limitation. Both use a real, active Frida
Gadget in a release APK; neither needs a login tap, because the app scans on launch. Ground truth in
each case is the gadget's own `I Frida : Listening on 127.0.0.1 TCP port <n>` line in logcat, which
proves the framework loaded and is live regardless of what the collector concludes.

| Test | Gadget name | Port | Gadget live? | `frida_port_open` | `frida_runtime_artifact` | Verdict |
|---|---|---|---|---|---|---|
| Default (all prior tests) | libfrida-gadget.so | 27042 | yes | fires | fires | block |
| **A** | libfrida-gadget.so | **27100** | yes | absent | **fires** | block (score 100) |
| **B** | **libhelper.so** | 27100 | yes | absent | absent | **trusted (score 18)** |

### Test A — the maps read is independent of the port probe (reassuring)

Moving the listener to 27100, a port `probeFridaPorts` does not check, removed the
`android_frida_port_open` signal but `android_frida_runtime_artifact +90` still fired and the verdict
was still `block`. This answers the open question in §27.10: the two signals had always fired
together, so their independence was unproven. It is now established — an attacker who avoids the
default Frida port is still caught by the `/proc/self/maps` read. Detection does not depend on the
default port.

### Test B — a rename defeats detection entirely (CONFIRMED evasion)

The identical gadget, renamed `libhelper.so` (config `libhelper.config.so`) and left on 27100,
loaded and listened exactly as before — logcat shows `Frida : Listening on 127.0.0.1 TCP port 27100`
— yet the collector scored **18/trusted** and the server stored `18 | trusted`. The login gate would
admit it.

`probeRuntimeMaps` lowercases each `/proc/self/maps` line and matches it against a fixed token list.
`libhelper.so` contains none of those tokens, so the mapped, active instrumentation framework is
invisible. Two changes an attacker fully controls when repackaging an APK — rename the shared object,
move the port — reduce the score from 100 to 18.

**Severity.** This is the realistic attack path for this project. The whole point of the Gadget (as
opposed to frida-server) is that it ships inside a repackaged app and needs no root; an attacker who
can embed it can trivially rename it. Name-based matching raises the bar only against an adversary
who does not bother to rename, which is not the adversary that matters.

**The fix is structural, not a longer list.** Detection must key on *behaviour that hooking requires*
rather than on *what the tool is called*:

- Diff the first bytes (the prologue) of security-critical libc/JNI functions against a known-good
  copy; an inline hook overwrites them with a trampoline.
- Diff a loaded library's in-memory `.text` against the same section on disk; any patched code
  diverges.
- Flag `rwx` or writable-then-executable mappings and code pages whose backing file has been
  deleted, both of which legitimate libraries rarely present.

These catch an unnamed hooking library, and would have caught Test B. A name denylist never will.
The name list still has value as a cheap first pass against lazy tooling and should stay, but it
cannot be the only mechanism. **Recommend implementing structural detection as the next hardening
step; it is scoped native work and belongs in its own change.** Not implemented in this session,
which was scoped to running the tests.

Both handsets were returned to the clean release build (`18/trusted`, zero gadget artefacts) after
the tests.

---

# 28. Structural hook detection — implemented and verified (2026-09-05)

Closes the rename evasion confirmed in §27.11. Detection no longer relies solely on the injected
library's filename; three new mandatory probes report raw measurements that the server scores. The
phone still never scores itself.

## 28.1 The three probes

- **`instrumentation_threads`** reads `/proc/self/task/<tid>/comm` for Frida/Gum runtime threads
  (`gum-js-loop`, `pool-frida`) and, separately, GLib threads (`gmain`, `gdbus`). These names are
  compiled into the framework, so renaming the injected `.so` does not rename them. This is the
  signal that catches the renamed gadget.
- **`exec_mappings`** flags writable-and-executable memory and executable memory backed by a
  `(deleted)` file — both rare in a W^X-compliant app. The ART JIT code cache, which legitimately
  presents as executable and `(deleted)` (`/memfd:/jit-cache`, `/dev/ashmem/dalvik-jit-code-cache`),
  is excluded client-side; without that exclusion every clean device is a false positive.
- **`code_integrity`** compares libc's in-memory `.text` against the on-disk file. On Android 9/10
  SELinux blocks `untrusted_app` from reading `/proc/self/mem`, so it returns `checked:false` there
  and is not scored — kept as best-effort telemetry. Reliable text-diffing needs a native (NDK)
  component and is deferred; it is the one probe that would catch a non-Frida inline hooker such as
  Dobby, so it remains the recommended follow-on.

## 28.2 Scoring, tuned to a measured clean baseline

Before wiring any scoring, the three probes were shipped in report-only mode and the raw output was
captured from both handsets. The baseline decided the thresholds:

| Signal | Clean OPPO | Clean Huawei | Decision |
|---|---|---|---|
| `frida_threads` | `[]` | `[]` | score 90 (block) |
| `wx_mappings` | 0 | 0 | score 60 |
| `deleted_exec_mappings` (non-JIT) | 0 | 0 | score 55 |
| `deleted_exec_jit` | 1 (JIT cache) | 1 (JIT cache) | never scored |
| `glib_threads` | `[]` | `[]` | score 40 (elevated, not block) |
| `code_integrity` | `checked:false` (SELinux) | `checked:false` | not scored |

GLib threads score only 40 because an app could in principle bundle GLib; Frida-specific threads are
unambiguous and score 90.

## 28.3 Verification on real hardware

- **No false positive:** with scoring live, both clean handsets still scored **18/trusted**, the JIT
  cache correctly ignored.
- **Evasion closed:** the exact Test B build — Frida Gadget renamed `libhelper.so`, listening on
  27100 — now scores **100/block** via `android_instrumentation_runtime_thread +90` and
  `android_wx_memory +60`. Neither `runtime_maps` nor `frida_ports` fired, proving the block came
  from name-independent signals. The same build scored 18/trusted before this change (§27.11).

## 28.4 Regression tests

The conformance suite gains three checks (now **27 passed, 0 failed** on SQL Server 2025):

- *a renamed Frida gadget is caught by its runtime thread* — encodes the §27.11 evasion with
  `runtime_maps` and `frida_ports` explicitly clean, so a future change that reintroduced
  name-only detection would fail here.
- *writable-executable memory is caught*.
- *the ART JIT code cache is not mistaken for injection* — guards the false-positive exclusion.

`clean_probes` gained the three probes' clean defaults, which the mandatory-probe requirement now
demands of every report.

## 28.5 What this does and does not close

It closes the realistic Frida-repackaging evasion: rename plus port change no longer helps, because
the Gum runtime thread and the rwx trampoline memory remain. It does **not** yet catch a bespoke,
non-Frida inline-hooking library that spawns no recognizable thread and allocates no rwx page — that
needs the `code_integrity` text-diff, which requires a native component to read process memory under
SELinux. That component is now implemented — see §28.6. Both handsets were returned to the clean
release build (`18/trusted`) after the tests.

---

# 28.6 Native code_integrity — implemented and verified (2026-09-05)

The Kotlin `code_integrity` probe reported `checked:false` because SELinux denies `untrusted_app`
access to `/proc/self/mem` on Android 9/10. The fix is an NDK component that runs in-process and
reads the app's own already-mapped, readable `r-x` pages by direct pointer — no `/proc/self/mem`,
no ptrace, so the SELinux block does not apply. For libc and libart it compares every executable
mapping against the same bytes on disk.

**Iterating every VMA is essential, and a first cut got it wrong.** An inline hooker flips
individual code pages writable to patch them, splitting a library's single `r-x` mapping into
several; the patched page is usually not the first. An early single-VMA version compared only
114 KB of libc and read `diff_bytes:0` against an active hook — a false negative caught during
testing. Scanning all executable VMAs of the target library fixed it (libc then compares in full,
~864 KB).

**Scoring** is behaviour-based: any difference of 4+ bytes (one arm64 branch, the smallest inline
hook) raises `android_code_integrity_violation +90`, which blocks on its own — modified
system-library code is as definitive as a mapped Frida artifact. Clean devices measured exactly
zero across libc (614 KB) and libart (to the 4 MB cap) on both handsets, so the threshold is margin.

**Verified on real hardware.** A Frida Gadget in script mode inline-hooked five libc functions
(`strcmp`, `strlen`, `memcmp`, `open`, `fopen`) at load. The scan read `libc_diff_bytes:71` and
`android_code_integrity_violation +90` fired; both clean phones read `libc_diff_bytes:0` and stayed
`18/trusted`. Unlike the thread-name probe, this catches **any** inline hooker — Frida or a bespoke
library such as Dobby — because it compares bytes rather than recognizing a framework. The
conformance suite gains a check for it: 28 passed, 0 failed on SQL Server 2025.

Build wiring is a CMake `externalNativeBuild`; the library loads best-effort, so a build without it
degrades to `checked:false` rather than crashing. Nothing extra to install — the Android SDK ships
the NDK and CMake 3.22.1.

**Remaining gap, now smaller.** This probe compares libc and libart. An attacker who hooks a
library outside that set, or who tampers only with the app's own Dart/Flutter code rather than a
system library, is not covered as configured; extending the target-library set and adding the app's
own mapped code are the follow-ons.

## 28.7 Extended code_integrity — prepared, gated pending on-device baseline (2026-09-05)

Bridges the gap noted in §28.6: the native probe now covers three buckets instead of only libc/libart.

- **core** — libc, libart. Scored today (validated at zero on both handsets).
- **ext** — libc++, libssl, libcrypto, libandroid_runtime, libbinder. TLS is the notable addition:
  cert-pinning bypasses patch libssl/libcrypto, so this is a high-value target.
- **app** — libflutter, libapp (the Flutter engine and the Dart AOT snapshot). Catches in-memory
  patching of the application's own native code, scored under a new reason
  `android_app_code_modified`.

The native component compares every executable VMA of each target against disk and returns a JSON
summary (per-bucket compared/diff plus the names of any libraries that differ); Kotlin parses it with
the framework's `org.json`. Each bucket is capped at 4 MiB per library.

**Scoring of ext and app is gated behind `INTEGRITY_SCORE_EXTENDED_LIBS`, default off.** Core keeps
scoring unconditionally. This preserves the discipline used throughout: a signal is measured on real
hardware and confirmed zero on clean devices before it is allowed to reject anyone. The flag is off
until the ext/app buckets are baselined on both handsets.

**Validated server-side already:** with the flag on, a report carrying `ext_diff_bytes` raises
`android_code_integrity_violation` and blocks, and one carrying `app_diff_bytes` raises
`android_app_code_modified` and blocks (conformance suite, flag-on run: 30 passed, 0 failed). What
remains is the on-device step — install the new client on both phones, confirm the ext and app
buckets read zero on a clean device, then enable the flag — plus a real-hardware hook test against
libssl (`hooktest-ext.apk` is built and staged for it). Deferred only because the handsets were in
use.

## 28.8 Extended code_integrity — on-device validation (Huawei, 2026-09-05)

The §28.7 extended buckets were validated on real hardware (Huawei AQM-LX1), driven entirely
foreground (no background tasks).

**App-bucket fix found during Stage 1.** A normal Flutter release APK does not extract its native
libraries; libflutter/libapp map straight out of `base.apk`, so `/proc/self/maps` shows them backed
by `.../base.apk`, not `.../lib/arm64/libflutter.so`. The first clean baseline read
`app_compared_bytes=0` — the bucket was inert. Adding `.apk` to the app-bucket suffix set made it
scan (7.6 MB), still diff 0.

**Stage 1 — clean baseline, extended flag off.** core 4,808,704 B / ext 4,943,872 B /
app 7,593,984 B, all diff 0, verdict `18/trusted`.

**Stage 2 — extended flag on.**
- Clean device stayed `18/trusted` (no false positive).
- With eight inline hooks placed in `libc++.so` (ext bucket) via a held Frida session, a fresh scan
  read `ext_diff_bytes=105`, `ext_libs_diff=1`, `diffed_libs=libc.so,libc++.so`, and
  `android_code_integrity_violation +90` fired → **block**. This is the ext bucket catching a hook in
  a non-core system library on real hardware.

**A Frida-API trap worth recording.** Earlier attempts to land ext/app hooks read zero because the
scripts used the Frida-16 `Module.getExportByName`/`Module.enumerateExports` statics, removed in
Frida 17 (`Process.getModuleByName(name).enumerateExports()`); the calls threw and were swallowed, so
nothing was hooked except Frida's own libc startup patch (the recurring `core_diff=71`). A second
subtlety: Frida 17 batches Interceptor patches and flushes them at end-of-tick, so a byte read
immediately after `attach()` still shows the original prologue — the patch is real, just deferred.
Script-mode hooks at gadget-load also missed libflutter because it is not yet mapped that early
(its 66 function exports appear only after engine init).

**Still gated, deliberately.** `INTEGRITY_SCORE_EXTENDED_LIBS` remains **off** by default. ext/app
were baselined only on the Huawei; the OPPO must be baselined too before enabling by default, since a
different vendor/version could carry a benign in-memory difference in some ext library. The app bucket
is validated two ways short of a live on-device hook (clean 7.6 MB scan on-device; scoring proven
server-side) — a live libflutter hook was not attempted because it instruments the UI engine and
risks crashing a phone that must not be disturbed.

**Remaining to enable extended scoring by default:** baseline ext/app clean on the OPPO, then flip
the flag; optionally a careful live libflutter hook to close the app-bucket demonstration.

---

# 29. Collector versions, and which battery runs used which (2026-09-05)

Raised by the question "what does the extended flag being off mean for the databases we already ran
on?". The database conclusions are unaffected, but the battery results needed stamping so they are
not misread later.

## 29.1 The two collector versions

`collector_version` is sent in every integrity report and stored in `integrity_reports`, so any
stored report is self-describing.

| Version | Probes |
|---|---|
| **1** | `app_identity`, `debug_state`, `root_files`, `system_properties`, `runtime_maps`, `tracer`, `root_shell`, `selinux`, `mounts`, `frida_ports`, `emulator`, `developer_settings` — hook detection is **name-based only** (token scan of `/proc/self/maps`) |
| **2** | everything in 1, plus the structural probes: `instrumentation_threads`, `exec_mappings`, and the native three-bucket `code_integrity` |

## 29.2 Stamping the completed runs

**Every database battery in this project ran on collector v1.** The structural detection (§28) was
built *after* the SQL Server phase closed (§27.9).

| Run | Collector | Note |
|---|---|---|
| PostgreSQL 18.1 — full battery, both handsets (§25.8) | **v1** | |
| PostgreSQL 17.11 / 16.15 / 15.19 / 14.24 (§25.4) | **v1** | conformance suite only, by agreement |
| SQL Server 2017 / 2019 / 2022 / 2025 — full batteries (§27.4–27.8) | **v1** | |
| SQL Server 2025 — structural validation (§28.8) | **v2** | Huawei only; extended flag on for the test |

So "full battery PASS on SQL Server 2017" means **the 13-item battery as it existed then, with the
v1 collector**. It does not mean structural detection was exercised there.

## 29.3 Why this does not invalidate the database work

Dialect parity is what the database phase proves, and it is orthogonal to which probes the client
runs. The collector measures on the phone; the server scores; the database only stores the report
and serves the dialect-sensitive paths (replay nonce, row locking, reinstall correlation, device
memory). The only database-facing change in v2 is **more fields inside the `probe_results` JSON**,
and that is already re-validated on SQL Server 2025 — the conformance suite now carries 30 checks
including the four structural ones and passes 28/0/2.

Re-running the five engines with v2 was considered and judged unnecessary for the dialect claim.
That is a recommendation, not a decision taken unilaterally: if a "current battery passed on every
engine" statement is wanted for Payactiv, the engines must be recreated and the batteries re-run.
A cheaper middle path is to run the v2 battery on the next engine stood up anyway (Supabase is
still outstanding).

## 29.4 What the extended flag being off actually costs

`INTEGRITY_SCORE_EXTENDED_LIBS=0` (the default) still scores, unconditionally:
`android_instrumentation_runtime_thread` +90, `android_glib_runtime_thread` +40,
`android_wx_memory` +60, `android_deleted_code_mapping` +55, and
`android_code_integrity_violation` +90 for the **core** bucket (libc/libart).

Gated off are only the **ext** bucket (libc++, libssl, libcrypto, libandroid_runtime, libbinder)
and the **app** bucket (`android_app_code_modified`).

Consequence: the renamed-gadget evasion is closed by default, and any Frida-based attacker is still
caught by the thread / w^x / libc signals. The genuine remaining gap is narrow and specific — **a
bespoke, non-Frida inline hooker that patches only an ext library**, the classic case being a
cert-pinning bypass that patches `libssl`. Today that is measured and stored but not scored.

## 29.5 Queued: the OPPO baseline (blocks enabling the flag by default)

The flag stays off until the OPPO is baselined, because ext/app were measured clean only on the
Huawei and a different vendor/Android version could carry a benign in-memory difference in some ext
library. Procedure, for when the OPPO is free:

0. **Read the new public IP first — it changes on every start.** The instance runs without an
   Elastic IP by choice, so each `start-instances` assigns a fresh auto-assigned address and the
   previous one cannot be reclaimed (auto-assigned addresses return to the AWS pool; only
   previously-allocated Elastic IPs are recoverable). Each restart therefore needs:
   - `aws ec2 describe-instances ... PublicIpAddress` to read the new address,
   - the Caddy site block pointed at the new `<a-b-c-d>.nip.io` name (Let's Encrypt re-issues
     automatically), and
   - the client rebuilt with `--dart-define=API_BASE_URL=https://<a-b-c-d>.nip.io`, because staged
     APKs reference the previous host.

   An Elastic IP would remove this step permanently but accrues about USD 3.60/month while
   allocated, so it was deliberately not kept.

1. Stand up an engine (SQL Server or PostgreSQL) and the EC2 server; server in `enforce`,
   `INTEGRITY_SCORE_EXTENDED_LIBS` **off**.
2. Install the current clean client (v2 collector) on the OPPO; launch; it auto-scans.
3. Read the stored report's `code_integrity` and confirm **`core_diff_bytes`, `ext_diff_bytes` and
   `app_diff_bytes` are all 0**, and `*_compared_bytes` are all non-zero (a zero `compared` means the
   bucket is inert, which is exactly the defect found on the Huawei in §28.8).
4. Turn the flag on and re-scan the clean OPPO; it must stay `18/trusted` (no false positive).
5. Only then flip the flag on by default in `device_trust_server.py`.

Optional, to close the app-bucket demonstration: a careful live `libflutter` hook. Not attempted on
the Huawei because it instruments the UI engine and risks crashing a handset that must not be
disturbed.

---

# 30. OPPO baseline, extended scoring enabled by default, and battery item 14 (2026-09-06)

Closes the work queued in §29.5. Run on a fresh SQL Server 2025 instance; no other tests were
repeated on it.

## 30.1 OPPO baseline — PASS

Collector v2, extended flag off, enforce mode:

```text
core: 5,058,560 B  diff 0
ext : 5,742,592 B  diff 0
app : 4,194,304 B  diff 0
instrumentation_threads: none    exec_mappings: wx 0, deleted 0 (jit 1, excluded)
verdict 18/trusted
```

All three buckets have **non-zero `compared_bytes`**, which is the check that matters: a zero there
means the bucket is inert rather than clean, the defect found on the Huawei in §28.8. The numbers
differ from the Huawei's (different vendor and Android version) but every diff is zero.

## 30.2 Extended scoring enabled by default

With `INTEGRITY_SCORE_EXTENDED_LIBS=1` the clean OPPO still scored `18/trusted` — no false positive.
Both handsets are now baselined clean, so the default in `device_trust_server.py` was flipped from
`0` to `1`. Verified by redeploying with **no environment override** and rescanning the clean OPPO:
still `18/trusted`, carried by the code default.

This closes the gap described in §29.4: a non-Frida inline hooker patching only an ext library — the
cert-pinning-bypass case against `libssl` — is now scored by default.

## 30.3 Item 14 is a real battery item, and needs no tap

The §28.8 ext-bucket demonstration needed a held Frida session and a manual rescan, which is why it
was not promoted then. It is now a one-step item, because the reason it previously failed was
understood:

- use the **Frida 17** API (`Process.getModuleByName(n).enumerateExports()`); the removed
  `Module.*` statics throw and the exception was being swallowed, so nothing was ever hooked;
- **defer** the hook (`setTimeout(..., 4000)`) — at gadget-load time the target libraries are not yet
  mapped, which is why script-mode attempts measured zero even with the right API;
- Frida batches Interceptor patches, so call `Interceptor.flush()`.

With that, the hook lands before the app's own launch scan and the item runs unattended — install,
launch, read. Validated on the OPPO:

```text
ext_diff_bytes 100   ext_libs_diff 1   diffed_libs libc.so,libc++.so
android_code_integrity_violation +90  ->  score 100, verdict block
```

`§25.11` has been rewritten as the canonical **14-item** battery, folding in item 13 (pristine
reinstall, added in §27.7.1) and item 14, so that section is now the single source of truth rather
than the original four groups.

## 30.4 App bucket closed on device by controlled byte modification (2026-09-06)

The app bucket was the last unproven one. A live `libflutter` hook was rejected as the vehicle: that
library is the whole Flutter runtime — Dart VM, rasterizer, platform-channel plumbing, task runners —
so an inline hook risks prologue-relocation corruption, per-frame overhead leading to an ANR,
re-entrancy against engine locks, and, worst for a test, breaking the very MethodChannel path the
integrity scan travels on. It is also unstable as a fixed battery target, since "the first N exports"
changes between Flutter builds.

**Correction to an earlier statement:** this was described as risking "crashing a handset that must
not be disturbed". That overstated it. The gadget runs inside the app sandbox and cannot touch the
OS; the worst case is the app crashing and being reinstalled. The risk is to the test's reliability,
not to the hardware.

The chosen vehicle instead tests exactly what the probe asserts — *in-memory differs from on-disk* —
without inserting a live trampoline: flip `e_ident` bytes 9–15 (`EI_PAD`), which are reserved, never
read after load, and never executed. A raw `Memory.write` also **persists after Frida disconnects**,
unlike Interceptor hooks which are reverted on script unload, so the session can be dropped before
triggering the rescan.

Result on the OPPO:

```text
app_diff_bytes 7   app_libs_diff 1   diffed_libs libc.so,libflutter.so
android_app_code_modified +90  ->  block
```

The diff is exactly the seven bytes written — an unambiguous match rather than an inferred one.

**A per-library detail worth keeping.** `libflutter.so` maps its ELF header inside the `r-x`
segment, so the header is within what `code_integrity` scans and was flippable. `libapp.so` maps its
header `r--`, so the guard correctly skipped it. This does **not** mean libapp is unscanned: the
probe compares every executable mapping matching the suffix, so libapp's own `.text` is still
covered — only its header happens to fall outside an executable range, which is why libflutter was
used for the demonstration. `libapp.so` also exports no functions, so symbol-based hooking is
impossible there regardless.

## 30.5 All three buckets now proven on real hardware

| Bucket | Vehicle | Measured diff | Handset |
|---|---|---|---|
| core | Frida's own libc patching at gadget load | 71 B (`libc.so`) | OPPO + Huawei |
| ext | deferred inline hooks in `libc++.so` | 100–105 B | OPPO + Huawei |
| app | controlled `EI_PAD` flip in `libflutter.so` | 7 B | OPPO |

Clean baselines remain zero on both handsets with extended scoring enabled by default.

---

# 31. iOS toolchain smoke test, and the hardware it implies (2026-09-06)

## 31.1 The Mac-free build path works

Corellium was ruled out (Solo is students/faculty only; other tiers are unavailable in Pakistan), so
the plan is a physical jailbroken iPhone plus cloud macOS for builds. A Codemagic workflow
(`codemagic.yaml`) was added and smoke-tested against the current repo, whose iOS side is still the
stock Flutter template — the point was to prove the toolchain before writing any Swift.

It produced a genuine, installable artifact:

```text
Payload/Runner.app        valid IPA layout
Runner                    Mach-O arm64, PIE
Frameworks                Flutter.framework, App.framework, objective_c.framework
embedded.mobileprovision  ABSENT  -> unsigned, as intended
```

**No Apple Developer account is required for this path.** Codemagic builds with `--no-codesign`, and
a checkm8-jailbroken device bypasses AMFI signature enforcement, so an unsigned `.ipa` installs
directly. An earlier claim in this project that a paid account was needed for "any real device" was
wrong and is corrected here: the paid programme only buys App Store distribution and ad-hoc UDID
profiles for third-party device farms, neither of which this path uses.

Codemagic's free tier is 500 macOS minutes/month on a personal account; an iOS build costs roughly
10–20, so the workflow deliberately has **no `triggering:` block** and is started by hand.

## 31.2 The real minimum iOS version is 15.0, not 13.0

`IPHONEOS_DEPLOYMENT_TARGET` in the Xcode project reads **13.0**, but the built binary declares
`MinimumOSVersion` **15.0**. The cause is `flutter_secure_storage: 10.3.1`, whose v10 Darwin
implementation requires iOS 15 — its `flutter_secure_storage_darwin` bundle is visible inside the
IPA. Trust the binary, not the project setting.

## 31.3 Which iPhone to buy

Two constraints, and the second is the one that is easy to get wrong:

1. **iOS 15.0 floor** (§31.2).
2. **checkm8 jailbreakability.** `checkm8` is a bootrom vulnerability — unpatchable in software —
   present in **A7–A11 only**, i.e. up to iPhone X. From A12 (iPhone XR) onward it is gone and
   jailbreaks become version-specific and unreliable. The iOS probes the server already scores
   include `ios_jailbreak_artifact` and `ios_sandbox_escape_signal`, so a non-jailbreakable device
   would leave them untestable — the very gap that sent us looking at Corellium.

| Device | Chip | Max iOS | vs the 15.0 floor | checkm8 |
|---|---|---|---|---|
| iPhone 6s / SE1 | A9 | 15.8 | works, **no headroom** | yes |
| iPhone 7 | A10 | 15.8 | works, **no headroom** | yes |
| **iPhone 8 / X** | **A11** | **16.7** | **headroom** | **yes** |

**Recommendation: iPhone 8 or iPhone X.** A 6s or 7 clears 15.0 by less than one version and would
be stranded by the next plugin bump, for roughly the same money.

**Non-PTA is fine** and much cheaper: the lab needs only WiFi (to reach the server) and USB, never
cellular. Indicative pricing at the time of writing: iPhone 8 non-PTA around PKR 14,000.

A useful property of checkm8: the jailbreak is *semi-tethered*, so a reboot returns the device to a
clean state and re-running the exploit compromises it again. One handset therefore provides both the
clean baseline and the jailbroken case on demand, which suits the battery well.

## 31.4 Costs compared

| Option | Rate | Catch | Minimum for one session |
|---|---|---|---|
| AWS EC2 Mac (`mac2.metal`) | ~USD 0.65/hr | **24-hour minimum allocation** (Apple licence) | ~USD 15.60 |
| **Codemagic** | 500 free macOS min/month, then ~USD 0.095/min | free minutes are personal accounts, not Teams | **USD 0** |

Codemagic plus a one-time handset is far cheaper than any cloud-Mac arrangement, and unlike a device
farm it gives the same depth of access already available on the two Android handsets.

---

# 32. iOS identity and possession — Swift implementation (2026-09-06)

First native iOS code in the project. Covers battery items 1–4's prerequisite: an installation
identity and proof of possession. The integrity collector is deliberately not part of this step.

## 32.1 What was written

- `ios/Runner/InstallationKeyManager.swift` — one non-exportable P-256 key in the Secure Enclave.
- `ios/Runner/AppDelegate.swift` — registers `devicefingerprinting/installation_key_v2` with the
  same three methods the Android host exposes: `getOrCreateKey`, `sign`, `deleteKey`.
- `ios/Runner.xcodeproj/project.pbxproj` — the new Swift file had to be registered by hand
  (PBXBuildFile, PBXFileReference, group membership, Sources build phase). Xcode is not available on
  the Linux dev machine, and a `.swift` file that is not referenced simply never compiles.

**No Dart changes were needed.** `NativeInstallationKey` is platform-agnostic; it calls the channel
by name and validates the returned map. iOS satisfies the same contract.

## 32.2 The two properties that had to match Android exactly

- **The payload arrives as base64url text, is decoded, and the raw bytes are signed.** The server
  verifies over exactly the bytes the client signed, which is why no canonical JSON is needed across
  platforms.
- **The signature is ASN.1 DER.** `ecdsaSignatureMessageX962SHA256` yields X9.62/DER, matching
  Android's `SHA256withECDSA` and what PyCryptodome verifies. A raw `r||s` signature would be
  rejected — the same trap already documented for the .NET SDK, where the default .NET signature
  format is IEEE-P1363.

Secure Enclave is attempted first with a graceful fallback to a software keychain key, mirroring the
Android host's StrongBox-then-fallback shape (the Simulator has no Secure Enclave). The honest
result is reported to the server through `security_level` and `hardware_backed` rather than being
hidden.

## 32.3 A platform divergence that will affect battery items 12 and 13

**iOS keychain items survive app uninstall; Android Keystore entries do not.**

On Android, deleting the app destroys the key, so a reinstall necessarily enrols a *new*
installation — which is exactly what items 12 (device memory across reinstall) and 13 (pristine
reinstall) rely on. On iOS the keychain item, and therefore the Secure Enclave key, will normally
still be there after a reinstall, so `getOrCreateKey` returns the **same** key and `created` is
`false`.

This is not a bug in either platform, but it means those two items cannot be run on iOS by simply
uninstalling and reinstalling. The iOS equivalent must either call `deleteKey` explicitly to
simulate a fresh installation, or the test must be redefined for iOS. This needs deciding before
items 12 and 13 are attempted on the iPhone; it is flagged here rather than discovered mid-test.

## 32.4 Not yet verified

Written but not yet compiled — the Linux dev machine cannot build iOS. The next Codemagic run is the
first compile. Two things are most likely to need a fix: whether
`FlutterPluginRegistry.registrar(forPlugin:)` is nullable in this Flutter version (the code assumes
it is, via `guard let`), and the exact `SecAccessControlCreateWithFlags` overload resolution.

---

# 33. iOS integrity collector (2026-09-06)

`ios/Runner/IntegrityProbeManager.swift` implements the eight probes
`_score_ios_integrity` already scores, on the `devicefingerprinting/integrity_v1` channel. As on
Android, **the collector computes no score** — it reports raw measurements and the server decides.

## 33.1 The probes and what each maps to

| Probe | Fields the server reads | Implementation |
|---|---|---|
| `app_identity` | `bundle_id`, `executable_sha256` | `Bundle.main` + SHA-256 of the main executable |
| `code_signing` | `signing_identifier`, `team_identifier`, `get_task_allow` | `SecTaskCreateFromSelf` + entitlement lookups |
| `debugger` | `traced` | `sysctl` `KERN_PROC` / `P_TRACED` — the standard non-private check |
| `jailbreak_files` | `found_paths` | 20 artifact paths incl. rootless `/var/jb` layouts (palera1n, Dopamine) |
| `sandbox` | `write_outside_sandbox_succeeded` | attempts a write to `/private/`, removes it if it unexpectedly works |
| `dyld_images` | `suspicious_tokens` | `_dyld_image_count` / `_dyld_get_image_name` — the iOS analogue of `/proc/self/maps` |
| `environment` | `dyld_insert_libraries` | `DYLD_INSERT_LIBRARIES` |
| `simulator` | `is_simulator` | `targetEnvironment(simulator)` + device model |

## 33.2 Honest reporting over flattering reporting

`code_signing` returns empty `signing_identifier` and `team_identifier` for the unsigned builds the
jailbroken-device workflow produces. That is reported as-is rather than faked; the server only
compares those fields when a baseline is configured, so an unsigned test build simply does not
trigger the mismatch rules.

`jailbreak_files` will return an empty list on a clean device partly because the sandbox makes most
of those paths unreadable, which is indistinguishable from their being absent. That false negative
is acceptable: the `dyld_images` and `environment` probes catch in-process instrumentation whether
or not the filesystem is legible, and the same reasoning already applies to Android's `root_files`
under SELinux (§21.5).

## 33.3 The known weakness, carried over deliberately

`dyld_images` matches on **image name**, exactly like Android's original `runtime_maps` token scan —
and it inherits the same defeat: rename the injected dylib and it goes unseen. That evasion was
demonstrated on Android in §27.11 and closed there by structural detection (§28). The iOS structural
answer is not yet written; until it is, iOS hook detection is name-based only and should be
described that way rather than as equivalent to the Android collector.

## 33.4 Next: the iOS code-integrity analogue

There is no `/proc/self/maps` and no readable `/proc/self/mem` on iOS. The equivalent of the Android
`code_integrity` probe is to walk loaded images with `_dyld_image_count` /
`_dyld_get_image_header`, resolve each image's `__TEXT` segment, and compare the in-memory bytes
against the same range of the on-disk Mach-O — including the `slide` returned by
`_dyld_get_image_vmaddr_slide`. That is a genuinely different design from the Linux version rather
than a port, and it is the natural `collector_version` 2 for iOS.

---

# 34. Adopting the .NET session's findings, and first iOS scoring checks (2026-09-07)

`DESIGN_UPDATE_FROM_DOTNET.md` arrived from the .NET SDK session. Its battery edits were adopted
(§25.11), and it found a genuine defect here.

## 34.1 A latent crash in the native code-integrity probe

Android 10+ maps system libraries **execute-only** (`--xp`). The native probe selected mappings on
the executable bit and then read through the pointer, so on any device using XOM it would have
segfaulted. It had not fired on the OPPO (Android 9, no XOM) or the Huawei only by luck. The .NET
implementation hit it directly: **283 of 336 executable mappings on the Huawei are `--xp`**.

The probe now lifts `PROT_READ` for the duration of the copy and restores the original protection on
every exit path. Where `mprotect` is refused it skips the mapping and **counts** it, reporting
`xom_regions_unlocked` and `xom_regions_unreadable`. Skipping silently is exactly how a bucket ends
up inert while still reading as clean — the failure mode §28.8 records shipping once already.

**Not yet verified on hardware.** The AWS stack is down, so this compiles but has not run on a
handset. It must be re-baselined on both phones before it is trusted.

## 34.2 Item 9 was over-claiming, and items 14/16 were run wrongly

Item 9 tests detection **by filename**, which §27.11 proved defeatable. It is renamed to say so.

More important operationally: when items 14 and 16 are run with the gadget left named
`libfrida-gadget.so` on port 27042, the name-based signals fire too and the verdict is
over-determined — the item passes without demonstrating the structural probes. **That is how item 14
was first run here** (§30.3): `android_frida_runtime_artifact` fired alongside the structural
reasons. The bucket evidence (`ext_diff_bytes 100`) was still unambiguous, so the conclusion holds,
but the run did not isolate what it claimed. The .NET session ran it properly — gadget renamed, port
27999 — and saw only the two structural reasons fire.

## 34.3 The W^X trap, guarded before it can be introduced

A clean .NET Android device scores `android_wx_memory +60` and is refused: Mono maps
writable-and-executable memory by design and there is no client-side fix. ART, which also has a JIT,
contributes zero because it never grants write and execute on the same mapping — so "trust managed
runtimes" is the wrong rule; the property that differs is the allocator's W^X policy.

The proposed fix scores W^X against an operator-pinned per-build baseline keyed on `apk_sha256`
— correctly **not** on a runtime name the client reports, since a compromised app could then claim
the allowance. **That rule is not implemented here; it is a security-posture change and belongs to
the owner.**

What *is* implemented is the guard against its trap. `wx_bytes` is a field only the .NET collector
sends. A naive `int(probe.get("wx_bytes") or 0)` reads **absent as zero**, computes no excess, and
silently switches off W^X scoring for every Flutter report — a Flutter device with a live injected
gadget would score nothing. A conformance check now asserts that a report with `wx_mappings > 0` and
**no** `wx_bytes` still scores `android_wx_memory`. Same class of defect as a bucket reporting
`compared_bytes: 0` and reading as clean.

## 34.4 First checks for the iOS scoring rules

`_score_ios_integrity` had **never been executed**. Seven checks now exercise it against crafted
reports: pristine iPhone scores zero, jailbreak artifacts, Frida in dyld images, a hooking
framework, sandbox escape as a hard block, `DYLD_INSERT_LIBRARIES`, and a traced process. The suite
gains an iOS registration path and an iOS clean probe set, and `clean_probes` now dispatches on
platform because the two collectors report entirely different measurements.

This proves the server half before any iPhone exists. The collector half still needs hardware.

## 34.5 A Simulator false positive, closed

The iOS Simulator's filesystem is the **Mac's** filesystem, and macOS genuinely ships `/bin/bash`,
`/bin/sh`, `/usr/bin/ssh` and `/usr/sbin/sshd` — four entries in `jailbreakPaths`. Running the probe
there would report a confident jailbreak on a clean machine. It now returns `unsupported` with the
reason `simulator_filesystem_is_the_host` rather than a fabricated clean result or a false positive.

## 34.6 Independent agreement is evidence

The .NET `code_integrity`, implemented in pure C# with `Marshal.Copy` and no NDK component,
reproduces this repository's Huawei figures exactly: core 4,808,704, ext 4,943,872, the recurring
`core_diff=71` from Frida's own libc patch, and `ext_diff_bytes=105` / `ext_libs_diff=1` under a
libc++ hook. Two independent implementations agreeing to the byte is meaningful evidence that both
are right.

# 35. First iOS run on hardware, and what TrollStore's signature revealed (2026-09-09)

Everything up to this point on iOS was written blind. `InstallationKeyManager.swift` and
`IntegrityProbeManager.swift` had never been compiled by Xcode, never run on an ARM device, and
never spoken to the server. This section records the first end-to-end run on a physical iPhone, the
one compile error that mattered, and two findings that came out of it — one of which is a defect in
this repository that had been present since the beginning.

Hardware: **iPhone 7 (iPhone9,3, A10 Fusion, arm64), iOS 15.8.5 (19H394)**, no passcode, no Apple ID
signed in at purchase. Backend: the AWS stack, PostgreSQL 18.3, `INTEGRITY_MODE=observe`.

## 35.1 Getting an unsigned build onto a stock iPhone, without a Mac

The constraint that shaped this whole path is that there is no Mac and no paid Apple Developer
account. The chain that worked, all of it from Linux:

1. **Codemagic** builds `flutter build ios --release --no-codesign` and packages `Runner.app` into
   `Payload/` by hand, because `flutter build ipa` demands signing. Free tier, manual trigger only.
2. A **free Apple ID**, created in a browser. This is the step with a trap: an Apple ID created only
   in a browser is not fully activated, and developer-session creation fails with
   **`-22411 "This action cannot be completed at this time"`**. Apple completes account setup on
   first sign-in *on a device*, when the iCloud terms are accepted. Signing in on the phone and then
   immediately turning **Find My off** activates the account without creating an Activation Lock,
   which would otherwise bind the device to that Apple ID for every future restore.
3. **Sideloader** (Dadoum) signs and installs `TrollInstallerX.ipa` over `usbmuxd`. It ships a
   prebuilt Linux x86_64 binary; PlumeImpactor is source-only and AltServer-Linux is dated.
4. **TrollInstallerX** exploits the kernel (`kfd`/physical use-after-free), installs a persistence
   helper into **Tips** — a stock app with no system function — and installs **TrollStore**.
5. TrollStore installs our unsigned `.ipa` permanently, served over HTTPS from the EC2 host via
   `apple-magnifier://install?url=…`.

The device is **not jailbroken**. It runs stock iOS 15.8.5, and DFU restore remains available
because the A10 bootrom is checkm8-vulnerable and unpatchable. The only irreversible element is the
firmware version: Apple no longer signs 15.8.5, so a restore lands on 15.8.8, which is still inside
both the TrollStore and TrollRestore version windows.

**The signing defect worth recording.** The first install of TrollInstallerX crashed instantly at
launch with no visible error. The device crash report named it exactly:

```
termination: DYLD "Library missing"
  Library not loaded: '@loader_path/libxpf.dylib'
  Reason: code signature invalid (errno=1) sliceOffset=0x00004000
```

`libxpf.dylib` sits at the **bundle root**, not in `Frameworks/`, and signing tools walk
`Frameworks/` and `PlugIns/`. It kept its original signature, invalid under our certificate. Thinning
it to `arm64`, moving it into `Frameworks/`, and patching the load command with
`llvm-install-name-tool` fixed it. Worth remembering generally: a sideloaded app that flashes and
closes is usually an unsigned nested binary, and the crash report says so precisely.

## 35.2 `SecTask` is macOS-only, so read our own Mach-O instead

The `code_signing` probe was written against `SecTaskCreateFromSelf`,
`SecTaskCopySigningIdentifier` and `SecTaskCopyValueForEntitlement`. Those are declared in
`Security/SecTask.h`, which Apple ships as public API on **macOS only** — on iOS the symbols are
private, and the build failed with three `Cannot find … in scope` errors.

The replacement reads the app's **own executable** and walks `LC_CODE_SIGNATURE` into the embedded
signature SuperBlob: the signing identifier comes from the CodeDirectory's `identOffset`, and the
team identifier and `get-task-allow` from the entitlements plist. Fat images resolve to their arm64
slice, and integers are assembled byte by byte because the offsets are not guaranteed to be aligned
and `loadUnaligned` is unavailable at the iOS 15.0 deployment target.

This is a better measurement than the API it replaces, for exactly the reason the Android buckets
report `compared_bytes`: it describes **what is actually in the file** rather than what the kernel
was told at launch. It also degrades honestly — an unsigned build carries no `LC_CODE_SIGNATURE`
at all and now reports `signed: false, signature_absent: true`, rather than presenting as a signed
app whose fields happen to be empty.

## 35.3 The run

Every step of the critical path worked on the first attempt:

| step | result |
|---|---|
| `POST /v1/installations/register` | `201` — ES256, EC P-256, `new_device`/`new` |
| `POST /v1/installations/challenge` → `/verify` | `200` — **Secure Enclave DER signature accepted** |
| `POST /v1/integrity/challenge` → `/report` | `200` — `collector_version 1`, all 8 probes `status: ok` |
| `GET /v1/device/me` | `200` |
| score | **35, `elevated`**, `hard_block: false` |

The signature interop is the result that mattered most. Android produces its signature through
`SHA256withECDSA` and iOS through `ecdsaSignatureMessageX962SHA256`; both are ASN.1 DER, and the
server's PyCryptodome verification accepted the iOS one with **no server change**. The decision
recorded in §4 — sign the transmitted bytes, never a canonically re-serialised structure — is what
made that possible.

Every other probe read correctly: sandbox write refused, not traced, not a simulator, 437 dyld
images with zero suspicious tokens, no `DYLD_INSERT_LIBRARIES`, and no jailbreak files. That last
one is the *right* answer: TrollStore is not a jailbreak, and there is no Cydia, Sileo or `/var/jb`
on this device.

## 35.4 What TrollStore's signature looks like from inside the app

The `.ipa` we built had **zero** `LC_CODE_SIGNATURE`. TrollStore adds one during installation, and
the new parser read it back out of the installed binary:

```json
"code_signing": {
    "signed": true,
    "get_task_allow": true,
    "team_identifier": "TROLLTROLL",
    "signing_identifier": "com.icraze.gtatracker",
    "entitlement_count": 5,
    "code_directory_flags": 0
}
```

Two things are visible here that no baseline was needed to see.

**`team_identifier` is literally `TROLLTROLL`** — a hardcoded fake team.

**`signing_identifier` is `com.icraze.gtatracker`, not our bundle identifier.**

That sentence is the measurement. The paragraph that originally followed it was not, and has been
replaced, because it described the wrong bug. CVE-2023-41991 is a **multiple-signer confusion**
vulnerability: a single CMS blob carries two signers, and CoreTrust decides the binary is
Apple-signed from the *first* signer's certificate chain while validating the binary against the
*second* signer's CodeDirectory hashes ([The Apple Wiki][ct]). TrollStore supplies a real App Store
binary's signature as the first signer.

What has **not** been established is which part of that assembly produces the identifier our probe
reads. The probe reads slot 0 of the SuperBlob; whether the donor identifier reliably lands there
across TrollStore versions and donor binaries is unknown. So the rule in §35.5 may be keying on an
artifact of how TrollStore builds the blob rather than on something intrinsic to the exploit — which
is a further reason, beyond the missing clean baseline, for it to stay report-only.

Settling it needs the collector to report the full SuperBlob slot inventory rather than slot 0
alone, which is a probe change and a rebuild.

[ct]: https://theapplewiki.com/wiki/CoreTrust_Multiple_Signer_Validation_Vulnerability

Only `get-task-allow` scored, for `+35`. The far stronger signals were sitting in the same probe
output unscored, which is what the observe run was for.

## 35.5 Action item 1 — a structural fake-signature rule

**Proposed:** `ios_signing_identifier_bundle_mismatch`, raised when
`code_signing.signing_identifier` is non-empty and differs from `app_identity.bundle_id`.

A legitimately signed iOS application always has CodeDirectory identifier equal to its bundle
identifier; Xcode derives one from the other. A mismatch is an **invariant violation**, not a
heuristic. It requires no configured baseline, which matters because
`ios_signing_identifier_mismatch` and `ios_team_identifier_mismatch` already exist but fire only
when `EXPECTED_IOS_SIGNING_ID` / `EXPECTED_IOS_TEAM_ID` are set — and an unconfigured deployment
therefore scores a fake-signed app at zero for this.

Suggested weight `+90`, not a hard block on its own, pending observation on a legitimately signed
build. **This rule cannot be adopted until a normally signed iOS build has been observed**, because
the entire evidence base for it is one TrollStore installation; the discipline in §28 applies —
ship report-only, baseline on real hardware, only then score.

**Action — DONE (report-only), 2026-09-14.** Implemented as `ios_signing_identifier_bundle_mismatch`, gated behind `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE` (default `0`). **Still open:** observe one legitimately signed iOS build not raising it, then flip the default.

## 35.6 Action item 2 — the `TROLLTROLL` marker, and why it is the weaker rule

**Proposed:** `ios_known_fake_team_identifier`, raised when `team_identifier` matches a known
fake-signing marker such as `TROLLTROLL`.

This is deliberately recorded as the *secondary* rule, because it is a **name match**, and §27.11
already proved on Android exactly how that ends: a Frida gadget renamed to `libhelper.so` and moved
off port 27042 scored `18/trusted` while fully active. One patched constant in a TrollStore fork
defeats this rule completely, and it is a one-line change in a public repository.

It is still worth having — an attacker who does not bother to change it should be caught cheaply —
but it must be weighted and documented as corroborating evidence, not as the detection. Suggested
weight `+25`, never a hard block, and §25.11 should say plainly that a passing test of this rule
proves much less than a passing test of 35.5.

**Action — DONE (report-only), 2026-09-14.** Implemented as `ios_known_fake_team_identifier`, weight 25, never a hard block, behind the same flag. `IOS_KNOWN_FAKE_TEAM_IDS` currently holds one entry, `TROLLTROLL`.

## 35.7 The defect this run exposed: hardware backing was never recorded

The run enrolled successfully with a Secure Enclave key — and that fact was **unprovable from the
server**, because the server never stored it.

`InstallationKeyManager` on both platforms reports `security_level`, `hardware_backed` and
`provider`. The Dart client parses all three and *requires* them to be present and correctly typed
(`NativeKeyMetadata.fromPlatform` throws otherwise). It then never sent them. `device_trust_server.py`
referenced none of the three names anywhere, and `app_installations` had no column for them.

The consequence is worth stating plainly. `InstallationKeyManager` falls back to a software
keychain key when the Secure Enclave path fails, and reports that honestly — but a software-backed
installation and a Secure Enclave installation were **indistinguishable to the server**. A
successful enrolment proved that *a* P-256 key existed, not that it was hardware-protected. The
same held for StrongBox versus a software fallback on Android.

**Fixed in migration 002 and the accompanying server and client changes:**

- `app_installations` gains `key_security_level`, `key_hardware_backed` and `key_provider`.
- The Dart client sends a `key_security` block at registration.
- The server parses, validates and persists it, and returns it in the registration response.

**Every column is nullable, and that is the load-bearing part.** `NULL` means *this client did not
report it* and must never be read as `software`. The Kotlin and .NET collectors do not send the
block at all, and a server that collapsed a missing `hardware_backed` to `False` would mark every
Android installation software-backed on no evidence. This is the third appearance of one defect
class in this project — an absent measurement mistaken for a benign one — after the integrity
bucket reporting `compared_bytes: 0` and scoring as clean (§28.8), and the .NET session's `wx_bytes`
field being absent on Flutter reports and computing to a harmless zero (§34.3). It is worth naming
as a recurring hazard rather than three coincidences.

**What this value is and is not.** It is a *client claim* about its own keystore. A compromised
client can lie about it, so it is a risk input and never proof — the boundary in §2 is unchanged.
Its value is comparative: the key thumbprint is the authoritative identity, and a non-exportable
hardware key cannot migrate into software. The same thumbprint later claiming a weaker level is
therefore a contradiction, and the server logs it, refuses to downgrade the stored value, and
returns `key_security.downgrade_reported`. Re-registration otherwise uses `COALESCE`, so a client
that does not report the block cannot erase a value another one recorded.

**Deliberately not done:** no scoring weight is attached to a software-backed key yet. That changes
verdicts and needs a decision about whether hardware backing is required, advisory, or
policy-driven per deployment. The measurement is now recorded; the policy is a separate choice.

**Action — conformance check DONE, 2026-09-14** (`identity: an absent key_security records null,
never false`, plus its positive counterpart). **Still open:** the policy decision on what, if
anything, a software-backed key should score.

### Verified on hardware, 2026-09-09

Three registrations, exercising all three paths on the iPhone 7:

| time | call | path | stored |
|---|---|---|---|
| 19:35:02 | `201` | first enrolment, old client | `NULL / NULL / NULL` |
| 19:49:25 | `201` | fresh install, old client, `INSERT` | `NULL / NULL / NULL` |
| 20:10:53 | `200` | rebuilt client, `COALESCE` update | `secure_enclave / true / SecureEnclave` |

The middle row is the one that matters for correctness: a genuine `INSERT` through the new code
with the block absent stored `NULL`, not `false`. Across the table, `null_not_reported: 1`,
`false_software: 0`, `true_hardware: 1` — a not-reported installation and a hardware-backed one
coexisting, with nothing wrongly claiming software.

**The substantive answer: the key is genuinely Secure Enclave-backed.** The graceful fallback in
`InstallationKeyManager.generateKey` did not fire, `kSecAttrTokenIDSecureEnclave` was accepted with
`.privateKeyUsage` and `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, and the key remained
usable unattended with no passcode set on the device. That last point had been reasoned about but
never demonstrated.

Incidentally confirmed in the same sequence: the Secure Enclave key **survives a TrollStore app
upgrade** — the 20:10:53 call returned `200` on the existing thumbprint rather than enrolling a new
installation — and **iOS reinstall correlation works on hardware**. The 19:49:25 registration
produced a second, genuinely distinct key thumbprint that the IDFV-derived hint correlated back onto
the same `device_id`, giving one device with two installations. The key stayed authoritative
throughout; the hint only merged the device record.


# 36. The two fake-signature rules, and a way to test scoring for free (2026-09-14)

§35 left three action items. Two are now implemented, both **report-only by default**, and the
third — the conformance check — is written. What remains open is deliberate and recorded at the end.

## 36.1 What shipped

| rule | weight | fires when | hard block |
|---|---|---|---|
| `ios_signing_identifier_bundle_mismatch` | 90 | CodeDirectory identifier ≠ bundle identifier, both non-empty | no |
| `ios_known_fake_team_identifier` | 25 | team identifier is in `IOS_KNOWN_FAKE_TEAM_IDS` | never |

Both sit behind `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`, default `0`. Neither needs `EXPECTED_IOS_*`
to be configured, which is the point: an unconfigured deployment previously scored a fake-signed
application at **zero** for its signature.

`_integrity_reason` gained a `report_only` parameter. A report-only reason appears in the stored
report and the API response with `points: 0` and `hard: false`, plus two extra keys —
`report_only: true` and `proposed_points` — so an operator can see what enabling the rule *would*
cost before enabling it. Those two keys appear **only** in the report-only case, so a rule that is
actually scoring produces output byte-identical to every other rule and nothing downstream changes
shape when the flag is flipped. `/health/ready` now reports `scoring_flags`, because a reader
looking at a low score needs to distinguish a signal that was absent from one that was merely inert.

## 36.2 Why they ship inert

The entire evidence base for §35.5 is one TrollStore installation. **No legitimately signed iOS
build has ever been observed by this server** — the rig cannot produce one, since a properly signed
build needs a paid Apple Developer account, which is precisely what the Mac-free path exists to
avoid. The invariant claimed in §35.5 (Xcode derives the CodeDirectory identifier from the bundle
identifier, so they always match) is well founded, but "well founded" is not "observed", and §28
exists because this project has previously shipped a signal that read as clean when it was
measuring nothing at all.

`ios_known_fake_team_identifier` could safely be scored today — no legitimate application has team
identifier `TROLLTROLL` — but it is held behind the same flag so the pair is enabled together, after
one clean baseline, rather than leaving a half-armed rule to be forgotten.

## 36.3 Scoring changes are now testable without spending money

Previously the only way to exercise a scoring rule was `conformance_suite.py`, which needs a running
server and therefore a live RDS instance. That made the cheapest possible check of a pure function
cost real money and several minutes — the wrong shape for something with no I/O in it.

`tools/check_ios_scoring_rules.py` calls `_score_ios_integrity` directly, with the server's
third-party imports stubbed out, so it runs on the **system interpreter with no virtualenv and no
installed dependencies** — like the other tools in that directory. Twenty-three assertions, well
under a second.

The assertions that earn their keep are the false-positive guards, not the detections:

- a correctly signed application does **not** raise the invariant rule;
- an **unsigned** build, which honestly reports an empty signing identifier, is not mistaken for a
  fake signature;
- a client that omits the fields entirely raises nothing.

That third one is the recurring hazard named in §35.7 — absence read as a finding — approached from
the opposite direction to the `compared_bytes: 0` and `wx_bytes` cases. There, an absent measurement
was mistaken for a *benign* value; here it could be mistaken for a *damning* one. Both are the same
error, and both are now pinned by a test.

The tool also pins the arithmetic on the real device, in both flag states: the observed iPhone 7
scores **35** today and would score **150** (35 + 90 + 25) with the rules enabled. That number is
the actual cost of flipping the flag, stated before anyone flips it.

## 36.4 Still open

- **Observe a legitimately signed iOS build.** Until then `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`
  stays `0`. This is the only thing standing between these rules and being scored.
- **Decide what a software-backed key should score** (§35.7). The measurement is recorded; the
  policy is not, and it changes verdicts.
- **The rig's permanent +35 floor.** Every iOS measurement from this device carries
  `ios_get_task_allow`, because TrollStore grants that entitlement to everything it installs. A
  genuinely trusted iOS reading is not obtainable here at all.

# 37. Removing the rig's +35 floor at the source (2026-09-14)

§36.4 listed the permanent `+35` on every iOS measurement as an accepted limitation of the test rig.
It was not a limitation; it was a thing nobody had tried to remove. This section records removing it,
and the two claims that had to be checked rather than assumed along the way.

## 37.1 Why `INTEGRITY_ALLOW_DEBUG` was the wrong answer

The obvious workaround — the one used for the enforce-mode test in §35 — is to set
`INTEGRITY_ALLOW_DEBUG=1`. Measured rather than assumed, that flag gates **six** rules, not one:

```
android_debuggable          android_debugger_connected / waiting_for_debugger
android_tracer_pid          ro.debuggable
ios_get_task_allow (+35)    ios_process_traced (+50)
```

So clearing the +35 that way also blinds the server to a debugger actually attaching to the
process. That makes it usable for a single controlled test and unusable as the rig's normal state,
which is not how it was presented in §35 when it was proposed.

## 37.2 The entitlement is TrollStore's, not ours

Our Codemagic artifact ships with **zero** `LC_CODE_SIGNATURE` and no entitlements file — there is
no `CODE_SIGN_ENTITLEMENTS` in the Xcode project and no `.entitlements` in the bundle. So
`get-task-allow` is not something the build asks for. TrollStore adds it, along with four others, so
its JIT option works.

Read off the device rather than guessed, TrollStore granted exactly five:

```
application-identifier                          TROLLTROLL.*
com.apple.developer.team-identifier             TROLLTROLL
com.apple.private.security.container-required   com.example.devicefingerprinting
get-task-allow                                  true          <- the +35
keychain-access-groups                          [TROLLTROLL.*, com.apple.token]
```

TrollStore's documentation states that it **preserves** entitlements already present in a binary
instead of applying its defaults. That is the whole mechanism this rests on, and it was confirmed on
device rather than taken on trust.

## 37.3 What was done

`ldid -S<entitlements> -I<bundle-id>` pseudo-signs the main executable with those same four
entitlements minus `get-task-allow`, before the `.ipa` reaches TrollStore.

`keychain-access-groups` is reproduced **byte for byte**, and that is the load-bearing detail. The
Secure Enclave key lives in the `TROLLTROLL.*` access group; change that value and the existing key
becomes unreachable, the app silently generates a new one, and the installation identity resets on
every rebuild — turning a one-line entitlement change into a device-identity reset.

The CodeDirectory identifier is set explicitly to the bundle identifier, because that is what a
legitimately signed application has and because leaving `ldid` to derive it from the file name would
produce `Runner`.

## 37.4 Measured on the device

| | before | after |
|---|---|---|
| entitlement count | 5 | **4** |
| `get-task-allow` | `true` | **absent** |
| other four entitlements | — | **unchanged** |
| `Key created this launch` | — | **No** |
| provider / security level | — | `SecureEnclave` / `secure_enclave` |

Entitlements are embedded in the code signature, so they cannot change unless the binary was
replaced — which is what establishes that the install landed. TrollStore reported nothing and the
Apps list looked identical, because it was an in-place upgrade onto the same bundle identifier and
the same container path.

`Key created this launch: No` is the result that matters beyond the score: the existing Secure
Enclave key was **loaded, not regenerated**, so this is still the same installation with the same
hardware key. The +35 is gone with no server-side suppression and `ios_process_traced` fully live.

Reproducible via `tools/presign_trollstore_ipa.sh`, which fails closed if `get-task-allow` survives
signing or the entitlements do not match the checked-in plist exactly. It was verified by running it
against the same Codemagic artifact and confirming it produces a byte-identical signed executable to
the one installed by hand — `sha256 c019a07e…`.

## 37.5 What this does not settle

The device now carries a CodeDirectory identifier of `com.example.devicefingerprinting`, written by
`ldid` **before** TrollStore resigned it. Whether TrollStore left that alone or replaced it with the
donor binary's identifier is unknown, and it decides something important: if ours survived, then
`ios_signing_identifier_bundle_mismatch` (§35.5) does **not** detect a TrollStore installation in
the general case, and the rule is considerably weaker than §35.4 claimed.

Reading it needs the `code_signing` probe, which needs a server. No prediction is recorded here on
purpose; the last one in this document was wrong.

Also unresolved: the app's executable hash has necessarily changed, from
`2cd1903b…` (425,171 bytes) to `c019a07e…` (386,384 bytes), because the signature is part of the
file. Any deployment that pins `INTEGRITY_IOS_EXECUTABLE_SHA256` must be updated whenever the
pre-signing step runs.

# 38. A shared-fixture bug the new checks exposed (2026-09-14)

Running the seven checks from §36 for the first time produced two failures, both reporting a score of
100 where 0 was expected. The cause was not in the new checks.

`clean_probes()` builds the Android fixture as a dict literal, fresh on every call. The iOS branch
did not:

```python
if platform == "ios":
    return {name: IOS_CLEAN[name] for name in required if name in IOS_CLEAN}
```

That hands out **references into the module-level `IOS_CLEAN`**. Every iOS check that does
`probes["jailbreak_files"].update({...})` to simulate a compromise was therefore mutating the shared
fixture permanently, and each later iOS check ran against a progressively dirtier "pristine" device.
By the end of the iOS block the accumulated penalties exceeded the cap, which is where the 100 came
from.

Demonstrated directly rather than inferred:

```
IOS_CLEAN jailbreak found_paths before : []
                            AFTER      : ['/Applications/Cydia.app']
a FRESH "clean" probe set now returns  : ['/Applications/Cydia.app']
same object? True
```

**Why it survived until now.** Every pre-existing iOS check asserts only that a particular reason
code is *present*. That assertion still holds on a dirty fixture — an extra `ios_jailbreak_artifact`
does not stop `ios_process_traced` from appearing. Only a check asserting an **exact score** can see
the pollution, and until §36 no iOS check did. `check_ios_clean` asserts `score == 0` and passed
throughout, because it runs before any mutating iOS check.

So the earlier iOS results in §34.4 were not wrong, but they were weaker than they read: from the
second mutating check onward, each was verifying its signal on a device that also had every previous
check's compromise applied. Fixed with `copy.deepcopy`, after which the suite is **43 passed, 0
failed, 2 skipped** — the two skips being the enforcement checks, which correctly skip in observe
mode.

The general lesson is worth keeping separate from the specific bug: **a test that only asserts
"the signal fired" cannot detect contamination of its own fixture.** Asserting the exact score is
what made the suite able to see this, and it is cheap to do wherever a fixture is meant to be clean.

# 39. The device answers both open questions (2026-09-14)

§37.5 left one question open and deliberately recorded no prediction. The device has now answered it,
along with confirming the +35 removal end to end. Backend for this run was **PostgreSQL 16.15 local
to the EC2 instance**, not RDS — chosen because neither question is a database question and RDS
bills by the hour. Results that are meant as portability evidence should still be taken on RDS.

## 39.1 The identifier mismatch is TrollStore's, not an artifact

`ldid` wrote `com.example.devicefingerprinting` into slot 0 of the SuperBlob before the `.ipa`
reached TrollStore. The device reports:

```json
"code_signing": {
    "signed": true,
    "get_task_allow": false,
    "team_identifier": "TROLLTROLL",
    "signing_identifier": "com.icraze.gtatracker",
    "entitlement_count": 4
}
```

Our identifier **did not survive**. So `ios_signing_identifier_bundle_mismatch` (§35.5) does detect a
TrollStore installation, and the doubt raised in §37.5 — that the rule might be keying on an artifact
of default entitlements — is resolved in the rule's favour. It survives the strongest test available
here: everything a legitimate signer would do was done first, and the mismatch reappeared anyway.

This also states TrollStore's behaviour more precisely than §37.2 could. It is not simply that
TrollStore "preserves entitlements": **it preserves the entitlements supplied to it — four, exactly
ours — while replacing the CodeDirectory.** Entitlements and CodeDirectory are handled differently,
which is why the +35 fix works and the detection rule survives it.

## 39.2 The +35 removal, confirmed end to end

```
get_task_allow  false          entitlement_count  4
score           0              verdict  trusted          hard_block  false
```

Taken with `INTEGRITY_ALLOW_DEBUG=0`, so nothing is suppressed and `ios_process_traced` stays live.
This is the first genuinely trusted iOS reading this rig has produced, and it retires the "permanent
+35 floor" recorded as an accepted limitation in §36.4.

**Trusted under the rules currently enabled**, and the qualifier matters. Both fake-signature rules
fired and contributed nothing by design:

```json
{"code": "ios_signing_identifier_bundle_mismatch", "points": 0, "report_only": true, "proposed_points": 90}
{"code": "ios_known_fake_team_identifier",         "points": 0, "report_only": true, "proposed_points": 25}
```

With `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=1` this device scores **115**, which is the block band. So
the rig can now produce either a clean baseline or a caught-red-handed reading from the same
hardware, depending on one flag — which is considerably more useful than a device permanently stuck
at 35.

## 39.3 Identity survived everything

```
installation 39f14bc7   thumbprint 06163520a5d2   secure_enclave / true / SecureEnclave
```

The same thumbprint and the same installation id as the 2026-09-09 run, across a **fresh database**,
a Codemagic rebuild, an `ldid` re-sign and a TrollStore reinstall. The installation id persists
because the client stores it; the thumbprint persists because `keychain-access-groups` was
reproduced byte for byte (§37.3). Had that value drifted, every rebuild would have silently minted a
new device identity.

## 39.4 The executable hash baseline cannot come from the build

| stage | bytes | sha256 |
|---|---|---|
| Codemagic, unsigned | 382,016 | `33331b93…` |
| after `ldid` pre-sign, shipped | 386,384 | `c019a07e…` |
| **on device, as reported** | **425,123** | **`07b56611…`** |

TrollStore rewrites the binary during installation, so the artifact hash and the installed hash are
necessarily different. **Any deployment setting `INTEGRITY_IOS_EXECUTABLE_SHA256` must use the
device-reported value, not the hash of the `.ipa` it built.** Pinning the build artifact's hash
would hard-block every device on first contact.

Incidentally confirmed: the Codemagic iOS host build is **reproducible**. `Runner` was byte-identical
between two separate builds (`33331b93…`), because no Swift source changed between them; only the
Dart snapshot in `App.framework` differed, carrying the new server URL. So a pinned hash is stable
across rebuilds that do not touch the Swift host — though it still has to be taken from the device.

## 39.5 What is still open

- **`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE` stays `0`.** §39.1 removed one of the two reasons for that,
  but not the other: no legitimately signed iOS build has been observed, and the false-positive
  guard for the rule is still only a conformance fixture rather than a real Apple-signed app.
- **The policy decision on software-backed keys** (§35.7) is unchanged.
- **The enforcement checks** skip in observe mode; the suite has not been run in enforce against this
  backend.

# 40. The fake-signature rule, proven on hardware in enforce mode (2026-09-14)

§39 measured the rules report-only. This records enabling them and running the whole thing for real,
plus a scoring detail that a prediction in this session got wrong.

## 40.1 The run

`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=1`, `INTEGRITY_MODE=enforce`, `INTEGRITY_ALLOW_DEBUG=0`,
PostgreSQL 16.15 local to the instance.

| | result |
|---|---|
| conformance suite | **44 passed, 0 failed, 1 skipped** |
| device report | `score 100`, `verdict block`, `hard_block false` |
| reasons | `ios_signing_identifier_bundle_mismatch +90`, `ios_known_fake_team_identifier +25` |
| `POST /v1/accounts/register` | **403 `integrity_blocked`** |

Across the two configurations run today, **every one of the 45 checks has passed**:

```
observe + scoring off   43 passed, 0 failed, 2 skipped   (the enforcement checks skip)
enforce + scoring on    44 passed, 0 failed, 1 skipped   (the report-only check skips)
```

The single skip in each case is a check correctly standing down because its precondition is absent,
which is the behaviour those checks were written to have.

**This is the part that matters.** The rule caught a *real* TrollStore installation, on real
hardware, in enforce mode, and the gate refused a session holding a valid device token, a valid
access proof and a genuine Secure Enclave key. Every previous demonstration of these two rules was
against a conformance fixture. §28 exists to insist on exactly this distinction.

## 40.2 The score is capped, and the cap is not the hard-block flag

The prediction recorded before the run was `115`. The device reported **`100`**, and the reasons
show `+90` and `+25` exactly as expected. The difference is the cap in `_score_integrity`:

```python
score = min(sum(max(0, int(reason.get("points", 0))) for reason in reasons), 100)
```

Worth reading the stored row carefully, because two things that look like one thing are not:

```
score 100    verdict block    hard_block FALSE
```

Neither rule is a hard block — deliberately, since §35.6 requires a name match never to be one. The
`block` verdict comes purely from the numeric band (100 ≥ 90). Score and `hard_block` are
independent controls, and this is a clean instance of the band alone doing the work with no
fail-closed override involved.

A consequence worth stating for anyone tuning weights: **once the total exceeds 100, additional
points are invisible.** Two rules at 90 and 25 present identically to one rule at 100. Weights are
therefore an ordering over which combinations reach a band, not a quantity that keeps accumulating.

## 40.3 The battery is 16 items, and two more are proposed

Confirmed against both `§25.11` here and `docs/handset-battery.md` in the .NET repository: the
canonical battery is **16 items**. Today's work suggests two additions, recorded as proposals rather
than folded in, because adding to the battery changes what every future engine run must cover.

```
| 17 | iOS clean baseline (**iOS only**) | pre-signed TrollStore build → `get_task_allow: false`, `score 0`, `trusted`, with INTEGRITY_ALLOW_DEBUG=0 | iPhone |
| 18 | iOS fake-signature detection (**iOS only**) | INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=1 → `ios_signing_identifier_bundle_mismatch` +90 → `score 100`, `block`, login 403 | iPhone |
```

Item 17 is the iOS counterpart of item 1, which is written in Android terms (`18/trusted`, from
developer options and ADB). It is only meaningful on a build that has been through
`tools/presign_trollstore_ipa.sh`; without that step the device sits at `35` and can never be
`trusted`, which is what §37 removed.

Item 18 depends on a flag that is **off by default** and should stay off until §39.5's open item is
closed, so it would have to be marked as conditional in the battery rather than unconditional.

## 40.4 Corrections to earlier sections

- §36.4 listed "the rig's permanent +35 floor" under *Still open* and described it as a property of
  the rig. §37 removed it. That entry is superseded.
- §35.4 stated the CoreTrust mechanism incorrectly; corrected in place with a citation, and §39.1
  supplies what was actually measured.

# 41. Two clients, one field, and a false positive caught before it shipped (2026-09-14)

Reviewing the .NET SDK's `AppleIntegrityCollector` while preparing its iOS handoff exposed a defect
in the rule added earlier the same day.

**The two collectors put different values into `code_signing.signing_identifier`.**

| client | source | value on a *legitimately signed* app |
|---|---|---|
| Swift (`IntegrityProbeManager.swift`) | CodeDirectory `identOffset` | `com.example.app` |
| .NET (`AppleIntegrityCollector.cs`) | `application-identifier` entitlement | `ABCDE12345.com.example.app` |

`ios_signing_identifier_bundle_mismatch` compared that field to `bundle_id` for **exact** equality.
Under the Swift convention that is the invariant §35.5 describes. Under the .NET convention the two
values are never equal, because the entitlement is always `TEAMID.` + bundle id — so the rule would
have raised `+90` on **every clean .NET iOS device**, and at `90` that is the block band.

Neither client is wrong. Both values are reasonable readings of "the signing identifier", and the
field name did not say which was meant.

**Fixed** by accepting either shape:

```python
identifier_is_consistent = signing_id == bundle_id or signing_id.endswith("." + bundle_id)
```

A fake signature matches neither, which the offline tool now pins in both directions: a
`TEAMID.`-prefixed identifier belonging to *this* bundle is accepted, and a `TEAMID.`-prefixed
identifier belonging to a *different* bundle (`TROLLTROLL.com.someone.else`) is still caught. The
rule therefore cannot be evaded by adopting the prefixed shape.

**The general point.** A probe field is a contract between two independently written collectors, and
a name alone does not pin it down. This was caught only because the two implementations were read
side by side; the conformance suite could not have caught it, because its iOS fixtures were written
from the Swift client's convention and would have agreed with themselves forever. §34.6 noted that
two independent implementations agreeing to the byte is good evidence — this is the same coin's
other face: where they silently *disagree*, only reading both finds it.

Recorded in the .NET handoff as a contract item, with the field defined as the CodeDirectory
identifier where a collector can read it.

# 42. Battery item 15 — PASS on the iPhone 7 (2026-09-14)

The first item of §25.11 formally executed on iOS. Item 15 exists because Android and iOS diverge on
what an app uninstall destroys, and that divergence is a property worth asserting rather than
assuming.

## 42.1 The run

| | before | after |
|---|---|---|
| Installation ID | `28a07714-ed32-4774-80a2-b60304f58f36` | **identical** |
| Key thumbprint | `c0063a46887778dc78d6b93c2399c00b8538785f4d982cea5f20560294b4cbae` | **identical** |
| Key created this launch | `No` | **`No`** |

The app was removed through the home screen (**Remove App → Delete App**) and reinstalled from a
pre-signed `.ipa` via TrollStore. `deleteKey` was **not** called, which is the whole point: item 12
and item 13 use `deleteKey` to force a new key, and item 15 asserts that an ordinary uninstall does
not.

**PASS.**

## 42.2 What makes the evidence strong

The reinstall was genuine, not an in-place upgrade, and both container identifiers prove it:

```
bundle container   228B6059-5358-434D-8D48-9BD4C93E5DA2  →  9429B222-9E7A-4B31-B1A2-0D61FCC9BBDD
data container     (previous)                            →  AE1820C2-692D-4F39-AC71-03B8E1917432
```

The **data container** is the one that matters. It is the app's entire sandbox — Documents,
`UserDefaults`, caches — and iOS assigned a new one, so everything stored there was destroyed.
Anything that survived can only have come from the Keychain.

So the run pins two properties, not one:

1. **The Secure Enclave key survives app deletion.** `created this launch: No` means
   `getOrCreateKey` *loaded* the existing key rather than generating one, and the thumbprint proves
   it is the same key.
2. **`flutter_secure_storage` genuinely backs onto the Keychain, not the sandbox.** The installation
   id survived a wiped data container, which it could not have done from `UserDefaults` or a file.
   Nothing had previously checked this, and it is load-bearing: if that storage were sandbox-backed,
   every reinstall would mint a new installation id while reusing the same key, and the two would
   disagree.

## 42.3 A control ran by accident, and it helps

At 16:06 the same day, **Simulate fresh installation** was pressed on the same device. That is the
opposite operation — it calls `deleteKey`, destroying the Secure Enclave key — and the database
records exactly what item 15 says must *not* happen on an ordinary uninstall:

```
39f14bc7 | 06163520a5d2 | secure_enclave | new_device      | 15:51:32
28a07714 | c0063a468877 | secure_enclave | reinstall_hint  | 16:06:21
```

A genuinely new key, a new installation, correlated back onto the same `device_id` by the
IDFV-derived reinstall hint. Set beside §42.1, the pair shows the mechanism is discriminating rather
than simply inert: **deleting the key changes identity, deleting the app does not.** A test that only
showed the second could not distinguish "the key survived" from "the client never re-checks".

## 42.4 Item 15 is engine-independent

Worth recording because it affects how the battery is scheduled: **every pass criterion for item 15
is read from the device**, and this run touched no server at all. The instance was running only to
serve the `.ipa` over HTTPS, and the app's baked-in `API_BASE_URL` still pointed at a previous
public IP throughout.

So unlike items 2–8, 12 and 13, item 15 exercises no database behaviour and cannot distinguish one
engine from another. Re-running it per engine family would cost device time and prove nothing new.
Whether to record it as "run once, engine-independent" rather than "each" is a change to the battery
and therefore not made here.

## 43. Whole-`__TEXT` telemetry measured on hardware (2026-09-16)

First run of the segment-wide `code_integrity` measurement added in `4bd6a78`, on the iPhone 7
(iOS 15.8.5, TrollStore), against the EC2 server in `observe` mode with
`INTEGRITY_SCORE_IOS_CODE_INTEGRITY` off. Build: Codemagic from `9bac726`, pre-signed with
`tools/presign_trollstore_ipa.sh` (`get_task_allow false`, 4 entitlements), served over HTTPS from
the instance and installed through TrollStore.

### 43.1 The measurement

```json
"code_integrity": {
    "checked": true,
    "app_images_compared": 3,
    "app_compared_bytes": 10505140,   "app_diff_bytes": 0,   "app_libs_diff": 0,
    "app_segment_compared_bytes": 14811136,   "app_segment_diff_bytes": 0,
    "core_compared_bytes": 0, "ext_compared_bytes": 0,
    "system_bucket_reason": "dyld_shared_cache_has_no_backing_files",
    "system_images_unreadable": 434,
    "diffed_libs": ""
}
```

`score 0`, `verdict trusted`, `collector_version 2`, nine probes.

**`app_segment_diff_bytes` is 0 on real hardware.** That is the result `4bd6a78` was waiting for: the
whole `__TEXT` segment — Mach-O header, `__stubs`, `__cstring`, `__unwind_info` and all — measures
byte-identical between memory and disk on a clean device. **`mach_header_64.reserved` is therefore a
validated safe flip target**, the Mach-O analogue of the ELF `EI_PAD` bytes used to close the app
bucket on Android (§30.4): writing to it cannot be mistaken for ordinary runtime variation, because
there is none to be mistaken for.

That is a measurement result, not a green light for battery item 16. §43.4 states what item 16
still needs.

### 43.2 One bundle framework is not measured at all

The Python model in `4bd6a78` predicted `app_segment_compared_bytes` 14,925,824 across four bundle
images. The device measured **14,811,136 across three**. The shortfall is exactly **114,688 bytes**,
and the arithmetic closes without remainder:

| bundle image | `__TEXT` filesize | measured? |
|---|---|---|
| `Runner` | 180,224 | yes |
| `App.framework/App` | 5,914,624 | yes |
| `Flutter.framework/Flutter` | 8,716,288 | yes |
| **`objective_c.framework/objective_c`** | **114,688** | **no** |
| device total | **14,811,136** | = 180,224 + 5,914,624 + 8,716,288 |

`app_compared_bytes` is short by 50,840 against the model for the same reason. And nothing was
silently dropped by a `continue`: `dyld_images.image_count` is 437, `system_images_unreadable` is
434, `app_images_compared` is 3, and 434 + 3 = 437. **Every image dyld had loaded was accounted
for** — `objective_c.framework` was simply not loaded at the moment the startup scan ran.
(Inference, not measurement: it is the Dart FFI ObjC interop framework and is loaded lazily on
first use, after the scan.)

**Why this matters.** The probe measures what dyld has already mapped, not what the bundle contains,
and it reports `checked: true` with no signal that a bundle framework went unmeasured. This is the
§28.8 defect class in a subtler form: there the bucket was inert and read zero, here the bucket is
populated and merely incomplete, which is harder to notice. A framework modified on disk and loaded
after the scan is invisible to it.

**Proposed, not implemented:** enumerate the Mach-O files under the bundle directory, compare that
set against the loaded images, and report the count not loaded as its own field. A non-zero value is
then telemetry to reason about rather than a silent omission. Whether it should ever score is a
separate question — lazy loading is normal behaviour, not evidence of compromise.

### 43.3 A stale process can serve an old collector after a reinstall

The first launch after installing over the existing app produced `collector_version 1` and eight
probes — the pre-`bf30934` collector — while `app_identity.executable_bytes` already read 427,475,
today's build. The contradiction resolved only after **Remove App → Delete App → reinstall →
launch**, which produced `collector_version 2` and nine probes from the same staged `.ipa`.
The two reports carry the same `executable_bytes` and different `executable_sha256`
(`9483a8e5…` then `3ca34db7…`), consistent with TrollStore re-signing the same input binary.

The exact mechanism is **not pinned down** and is recorded here as an observation, not a diagnosis.
The operational rule it yields is firm, though: **after installing over an existing build, delete and
reinstall before trusting a collector-version-sensitive measurement**, because `app_identity` reads
the new file from disk while the running process can still be executing old code — the one
combination that makes a stale build look current.

### 43.4 What battery item 16 still needs — a correction to §43.1

§43.1 first said item 16 was "unblocked". That was wrong, and the error is worth stating precisely
because it would have cost a device session to discover.

**The flip target and the scored field are not the same field.** `4bd6a78` deliberately split the
measurement in two: `app_diff_bytes` counts differing bytes inside `__TEXT,__text` only, and
`app_segment_diff_bytes` counts them across the whole `__TEXT` segment. `mach_header_64.reserved`
lives in the segment but **ahead of** `__text`, which is exactly why the pre-`4bd6a78` probe could
not see it. So flipping it increments `app_segment_diff_bytes` and leaves `app_diff_bytes` at 0.

`ios_app_code_modified` reads `app_diff_bytes >= 4` and nothing else, and **no rule anywhere reads
`app_segment_diff_bytes`** — it is telemetry by construction, as `4bd6a78` intended while it had no
hardware baseline. Item 16's criterion is `app_diff_bytes > 0` → `ios_app_code_modified` +90 →
`block`, so a reserved-field flip satisfies none of it. Two things are therefore outstanding, and
they are independent:

**1. A scoring decision.** The segment measurement now has the clean hardware baseline it was
waiting for, so the question `4bd6a78` deferred is live: should the header range be scored, and if
so as its own reason or by folding it into `app_diff_bytes`? Keeping them separate is probably
right — a `__text` difference is an inline hook, while a header difference is not executable code
and deserves its own weight — but that is a design call, not a measurement.

**2. A way to modify the app's memory on this device, which we do not currently have.** §37 removed
`get-task-allow` from the pre-signed build on purpose, and without it no debugger or Frida can
attach on a device that is **not jailbroken** — the iPhone 7 runs stock iOS 15.8.5 with TrollStore,
which is not a jailbreak (§31). Android closed item 16 with a Frida `Memory.write`; that route does
not exist here as things stand. The options, none of them free:

- **A one-off test build carrying `get-task-allow`.** Cheapest, and reversible by reinstalling the
  normal pre-signed build. Costs isolation: `ios_get_task_allow` +35 fires alongside, so the run is
  partly over-determined — the §25.11 warning about items 14 and 16 applies. The reason is named
  separately in the report, so `ios_app_code_modified` is still distinguishable.
- **checkm8 jailbreak.** The A10 bootrom is unpatchable and the jailbreak is semi-tethered, so a
  reboot restores the clean state and the same handset gives both baselines on demand — the property
  the device was bought for. It gives real Frida with no entitlement change, and so is the only
  option that tests item 16 the way item 14 was tested on Android. It changes the state of a
  physical test phone and therefore needs an explicit decision.
- **An in-app debug fixture that modifies its own `__text`.** Rejected by default: `bf30934` left
  iOS fixtures unimplemented deliberately, and §28 is explicit that a fixture validates the pipeline
  and never proves that real tooling is detected. It would close the item on paper only.

Until one of these is chosen, item 16 stays **blocked on iOS**, and §43.1's clean segment baseline is
a prerequisite that has been met rather than the item itself.

## 45. Battery item 16 on iOS — embedded gadget blocked by codesigning (2026-09-17) — INCONCLUSIVE

First on-device attempt at item 16 (modify the app's own `__text` so `ios_app_code_modified` fires).
Approach chosen with the user: embed a **real Frida Gadget**, renamed so `dyld_images` does not flag
it, and have its script hook a function in an app-bucket module so the code_integrity probe sees a
runtime `__text` divergence. No jailbreak, no Codemagic build — assembled locally.

### 45.1 What was built

From the existing Codemagic-unsigned build (`9bac726`), entirely on the Linux client:
- **LIEF** added `LC_LOAD_DYLIB @executable_path/Frameworks/CoreSupport.dylib` to `Runner`.
- Frida Gadget **17.18.0**, arm64 slice byte-extracted from the ios-universal dylib for the A10,
  embedded as `CoreSupport.dylib` (renamed to dodge the suspicious-token scan: `frida`, `gadget`,
  … ; install-id patched in place to match). `CoreSupport.config` + `CoreSupport.js` alongside it.
- `CoreSupport.js` attaches an interceptor to a function export in Runner/App/Flutter and
  `Interceptor.flush()`es — an inline branch into `__text`, behaviour preserved.
- Signed with `ldid`: the four shipping entitlements **plus `dynamic-codesigning`**, no
  `get-task-allow`. Chosen because no scoring rule reads `entitlement_count` or
  `code_directory_flags` (only `get_task_allow`), so adding it preserves score isolation while — in
  theory — granting the JIT right needed to write code. Verified: 5 keys, `get_task_allow` false.

### 45.2 What happened — a CODESIGNING kill in the gadget's initializer

The app **launches** (`runningboardd` tracks it `running-active`), then dies immediately. All three
crash reports (one per launch attempt) are identical:

```
EXC_BAD_ACCESS (SIGKILL - CODESIGNING)      termination namespace CODESIGNING, code 2
  0  libsystem_platform.dylib  sys_icache_invalidate
  1..N  CoreSupport.dylib        (Frida Gum internals)
  N+1  dyld  dyld4::Loader::findAndRunAllInitializers(...)
faulting address in a PRV r-x/rwx page (Frida's own code buffer) next to CoreSupport.dylib __LINKEDIT
```

Two facts follow directly, and they point in opposite directions:

1. **The embedded, renamed, `ldid`-signed gadget LOADED.** No `dyld`, `amfi`, "Library not loaded"
   or "code signature invalid" line appears in the syslog around the launch; dyld ran the gadget's
   initializers. So the signing-and-loading half of the approach works on non-jailbroken TrollStore
   iOS — a renamed gadget can be shipped inside the app and dyld will map it.
2. **It cannot create executable memory.** The kill is in Frida Gum's **own bootstrap** (inside the
   gadget's initializer, before `CoreSupport.js` ever runs), the instant it flushed the icache on a
   page it had made executable. The kernel's W^X/codesigning enforcement terminated the process.

### 45.3 The conclusion: `dynamic-codesigning` self-applied is not honored

`dynamic-codesigning` added with `ldid` to a CoreTrust-bypassed TrollStore app on stock iOS 15.8.5
**does not actually grant JIT.** The entitlement is present in the signature but the kernel does not
honour a self-asserted JIT right on a non-platform binary; genuine JIT requires the process to be in
the `CS_DEBUGGED` state, which is set by a debugger attaching (`get-task-allow` + TrollStore's
"Enable JIT", which runs debugserver), or by a jailbreak that disables codesign enforcement. This
resolves the assumption recorded in §43.4 as **disproved**, on device.

### 45.4 The deeper asymmetry — item 16 may have no clean-isolation form on iOS

Android closed item 14/16 with a gadget on an **unrooted** OPPO/Huawei, because Android permits an
app to modify its own code in-process. iOS does not: runtime `__text` modification is a **privileged
operation**, and every route to it trips an *independent* sensor this server already scores:

| route to modify app `__text` at runtime | independent signal it trips |
|---|---|
| `get-task-allow` + TrollStore "Enable JIT" (debugserver) | `ios_get_task_allow` +35, and `ios_process_traced` +50 while attached |
| checkm8 jailbreak | `ios_jailbreak_artifact` +75 |
| `dynamic-codesigning` alone | **none — but it does not work** (this section) |

Static patching is not item 16: if the on-disk binary is patched, memory matches disk, the probe
reads `app_diff_bytes 0`, and the tamper is instead caught by `ios_executable_hash_mismatch` /
signing checks. So the runtime-divergence signal item 16 exists to test can only be produced under a
condition iOS makes independently visible. The pristine "only `ios_app_code_modified` fires" result
that item 14 achieved on Android **may be structurally unavailable on iOS** — itself a security
finding (the OS forces the attacker to also do something detectable), not merely a test-rig
limitation. In each contaminated route the `+90` would still dominate and drive `block`, so item 16's
detection+enforcement can still be shown; its *isolation* cannot.

### 45.5 Decision pending (the user paused here)

Not decided unilaterally — narrowing or re-routing an agreed test is the user's call. The options are
§45.4's two working routes (get-task-allow+JIT, or checkm8), each with its named contamination, or
accepting that item 16-on-iOS is demonstrated in a non-isolated form, or recording it as
"iOS-structurally-privileged" and moving on. Resume at §45.6.

### 45.6 Resume-here state (2026-09-17)

- **Server:** EC2 `i-0559685f02c4013b1` **stopped** on pause (was running at the time of test);
  PostgreSQL 16.15 local, `observe` mode, `INTEGRITY_SCORE_IOS_CODE_INTEGRITY` **off**. The item-16
  build never produced a report (it crashes before scanning), so nothing new is stored.
- **Staged, left in place:** `devicetrust-item16.ipa` at `/srv/artifacts/e2a890/item16.ipa` and the
  clean `dt.ipa` beside it, behind the temporary Caddy `/artifacts/*` block. Local copies and the
  three crash reports are in the session scratchpad (ephemeral).
- **Phone:** the crashing item-16 build is the currently-installed app on the iPhone 7. Identity is
  unaffected (Secure Enclave key untouched). To restore a working app, reinstall the clean
  `dt.ipa` (needs the server started to serve it) — deletion keeps the key.
- **Local tooling proven this session:** LIEF in a venv adds the load command; the arm64 gadget
  slice extracts and signs; `libimobiledevice` (`idevicecrashreport`, `idevicesyslog`) pulls crash
  reports and streams the log over USB — the diagnostic path that produced §45.2.

## 46. Battery item 16 on iOS — get-task-allow + JIT route: PASS (non-isolated) (2026-09-19)

Resolves §45.5. The owner chose §45.4 route 1 (recorded in `owner_decisions.md`: "item 16:
get-task-allow + JIT"). This section records the build, the run, and the on-device result — a **PASS
in the non-isolated form** §45.4 anticipated.

### 46.1 The build — one entitlement changed

The §45.1 gadget build (`item16.ipa`) already embeds a renamed Frida Gadget (`CoreSupport.dylib`)
whose script inline-hooks a Flutter app-bucket export and `Interceptor.flush()`es. It crashed (§45.2)
because self-applied `dynamic-codesigning` does not grant JIT (§45.3). The only change for this route
is the entitlement: the main `Runner` executable was re-signed locally with `ldid`, swapping
`dynamic-codesigning` for **`get-task-allow`** and keeping the four shipping entitlements — crucially
`keychain-access-groups = [TROLLTROLL.*, com.apple.token]` — byte for byte, so the Secure Enclave key
and the installation identity survive (§37.3). No LIEF, no Codemagic rebuild.

Result: `item16-jit.ipa`, five entitlements, `get-task-allow` present, `dynamic-codesigning` gone,
`sha256 0ba88f43…`, staged at `/srv/artifacts/e2a890/item16-jit.ipa`.

### 46.2 The run and the result

Installed over the crashing build via TrollStore (in-place, same bundle id → key retained), launched
via **TrollStore "Enable JIT"** (debugserver attaches, sets `CS_DEBUGGED`), then "Run native
integrity scan". Server: local PostgreSQL 16.15 on the EC2 instance, `observe` mode,
`INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1` (enabled this session). The stored `integrity_reports` row:

    score 100, verdict block, hard_block false
    ios_app_code_modified                   +90   "the application's own code differs in memory from its packaged image"
    ios_get_task_allow                      +35
    ios_signing_identifier_bundle_mismatch  +0    (report_only; proposed 90)
    ios_known_fake_team_identifier          +0    (report_only; proposed 25)

    code_integrity: checked true, app_diff_bytes 16, app_segment_diff_bytes 16,
                    diffed_libs "Flutter", app_libs_diff 1, ext_diff_bytes 0,
                    app_compared_bytes 24,215,520, app_images_compared 4

A 16-byte runtime divergence in the Flutter app-bucket `__text` — the gadget's inline hook — detected
exactly as designed, driving `block`.

### 46.3 What it settles

- **§45.3's blocker is lifted on device.** The app produced a report instead of the CODESIGNING
  SIGKILL of §45.2, so `get-task-allow` + TrollStore "Enable JIT" genuinely grants JIT where
  self-applied `dynamic-codesigning` did not.
- **Detection + block-weight are proven.** `ios_app_code_modified +90` alone reaches the block band
  and is named as its own reason, so the item-16 signal is cleanly attributable.
- **Isolation, honestly: not achieved — and that is the finding.** `ios_get_task_allow +35` rode
  along; the enabling condition is itself independently visible, exactly §45.4's thesis that iOS
  makes runtime `__text` modification a privileged, separately-detectable act. One nuance in our
  favour: `ios_process_traced +50` did **not** fire, because TrollStore's debugserver detaches after
  setting `CS_DEBUGGED`, so the process is JIT-capable but not traced at scan time. The only
  contamination is +35, and the verdict does not depend on it.
- Classification: **PASS** for item 16 detection in non-isolated form. Enforcement was then confirmed
  on hardware in enforce mode — see §46.6.

### 46.4 Should `ios_get_task_allow` be scored +0? — recommendation: no

Raised by the owner: zero the +35 so item 16 reads in isolation. It removes the contamination but at a
cost to the product that outweighs the cosmetic gain, and it does not change item 16's verdict (the
+90 blocks on its own):

- A genuine App-Store build never carries `get-task-allow`; distribution signing strips it. In
  production its presence means the running app is **not** the distributed app — a dev build, a
  TrollStore/AltStore/enterprise-resigned copy, or an app a debugger can attach to. For a financial
  client that is a signal worth keeping, and it fires **before** any code is modified, catching
  attackers who only observe or resign rather than hook.
- Its production false-positive cost is ~zero (legitimate users cannot have it), so +35 is almost
  pure signal, already weighted "elevated/step-up", not a hard block.
- The reason it contaminates *our* measurements is a **lab** artifact — every TrollStore build carries
  it. §37 already solved that the right way: strip `get-task-allow` from the pre-signed baseline so
  the clean phone reads trusted, rather than blinding the scorer. `INTEGRITY_ALLOW_DEBUG` was rejected
  there for the same reason — it gates six rules including `ios_process_traced`.
- If an isolated *measurement* is wanted for the record, the correct mechanism is a report-only toggle
  (default scored +35), mirroring `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`, so a run can show
  `ios_app_code_modified` alone without ever shipping +0 as policy. Not yet built; offered.

Owner confirmed on 2026-09-19: **keep +35**. The stated concern was legitimate users being penalised,
which does not arise — an App-Store build never carries `get-task-allow`, so only sideloaded / resigned
/ debuggable copies trip it. A report-only switch for isolated demos remains available if wanted, not
yet built.

### 46.5 State after this run

- **Server:** EC2 `i-0559685f02c4013b1` running, local PostgreSQL 16.15, **`enforce`** (flipped from
  `observe` for §46.6; revert to `observe` for a production-representative resting state),
  `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1`. SG port 22 now also allows the current dev IP
  `39.58.208.8/32` (the three prior `/32`s left in place).
- **Staged:** `item16-jit.ipa` beside `item16.ipa` and `dt.ipa` under `/srv/artifacts/e2a890/`.
- **Phone:** iPhone 7 now runs the `get-task-allow` item-16 build (identity intact — a `+35` baseline
  is expected on it). Restore with the clean `dt.ipa` when done; deletion keeps the key.
- **Hygiene note:** the local Postgres password was printed to a session transcript this round (the
  systemd drop-in ExecStart was catted); rotating `dtadmin` is advisable, though the DB is bound to
  localhost and its SG admits 5432 only from the app SG.

### 46.6 Enforcement confirmed on hardware (enforce mode)

With `INTEGRITY_MODE=enforce`, the item-16 build (launched via TrollStore "Enable JIT" so the gadget
hooks) attempted `POST /v1/accounts/register`. The server ran the full possession + integrity flow and
refused it:

    15:57:37  POST /v1/installations/challenge  200
    15:57:38  POST /v1/installations/verify     200
    15:57:38  POST /v1/integrity/challenge      200
    15:57:39  POST /v1/integrity/report         200   (score 100, verdict block, ios_app_code_modified +90)
    15:57:39  POST /v1/accounts/register        403   integrity_blocked

The `403` code is `integrity_blocked` by construction, not inference: `_enforce_integrity_gate` maps
`verdict == "block"` to `integrity_blocked`, and the report persisted in the same second is
`verdict = block`. So a device that had just proven possession of its installation key was still
refused a protected operation solely because its live scan detected the in-memory `__text`
modification — detection and enforcement, on hardware. Item 16 is therefore **PASS** for both, in the
non-isolated form of §45.4. (The werkzeug access log records only the HTTP status; the JSON error code
is not logged, which is why the mapping was confirmed from source.)

## 47. Operational state and the confirmed iOS JIT-arming recipe (2026-09-20)

State save. Item 16 (§46) was reproduced by the .NET session on the same iPhone 7; this section records
the reusable JIT recipe that emerged and the exact server/device/repo state at the save point.

### 47.1 The iOS JIT-arming recipe that reproduces item 16 (confirmed twice)

1. **The build must carry `get-task-allow`.** A pre-signed clean build (`tools/presign_trollstore_ipa.sh`)
   has it stripped (§37), and TrollStore preserves that absence — so "Enable JIT" fails with
   **`trollstorehelper returned 3`**. Verify with `ldid -e <Runner>` → `get-task-allow: true`.
   `item16-jit.ipa` carries it; `dt.ipa` does not.
2. Install via TrollStore; **launch via TrollStore "Enable JIT"**, not the home icon — this attaches
   debugserver and sets `CS_DEBUGGED`, without which the embedded gadget's Frida-Gum bootstrap hits
   W^X and is SIGKILLed (§45.2).
3. **Wait ~10–15 s** after launch before scanning — the gadget defers its inline hook. Scanning too
   early gives `score 35 / app_diff_bytes 0` (only `ios_get_task_allow`, no `ios_app_code_modified`),
   with a non-scoring `app_segment_diff_bytes` (a `__TEXT`-segment, non-`__text` diff — telemetry
   only, §43.4).
4. Run the native integrity scan → `app_diff_bytes ≥ 4` (Flutter) → `ios_app_code_modified +90` → block.

Failure-mode map: `returned 3` = missing get-task-allow; `+35 only / app_diff 0` = scanned before the
deferred hook landed.

### 47.2 Server / infrastructure state

- EC2 `i-0559685f02c4013b1` **running** (t4g.micro, us-west-2). Endpoint
  `https://devicefingerprinting.duckdns.org` (DuckDNS, auto-updated on start).
- Local **PostgreSQL 16.15** + Redis on the instance; **no RDS**.
- `INTEGRITY_MODE=enforce`, `DEVICE_POLICY_MODE=observe`, `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1`,
  `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0`, `INTEGRITY_ALLOW_DEBUG=0`. Left in **enforce** for the .NET
  session's battery.
- Android cert allow-list: **3 certs** — the two prior handset certs plus the .NET client's
  `664e9c8e…de3` (added this session).
- `dtadmin` DB password **rotated** this session (root-600 drop-in + Postgres role; never printed).
  The previously-leaked password is dead.
- SG `sg-0a7e35ab397d765e8`: port 22 now also allows dev IP `39.58.208.8/32` (the three prior `/32`s
  remain).
- Staged under `/srv/artifacts/e2a890/`: `dt.ipa` (clean), `item16.ipa` (crashing dynamic-codesigning
  build, §45), `item16-jit.ipa` (get-task-allow build, §46 — the working item-16 build).

### 47.3 Device state (iPhone 7)

- Currently runs **`item16-jit.ipa`** (the get-task-allow item-16 build) — the .NET session reinstalled
  it to reproduce item 16. **Not** the clean `dt.ipa`. Identity intact (Secure Enclave key preserved;
  keychain group unchanged).
- Latest verdict `100/block` (`ios_app_code_modified`). Block reports sit on the device's `device_id`
  for 24 h — in enforce, the clean `dt.ipa` would be refused `integrity_device_blocked_recently` until
  they age out or the server returns to observe. To restore a clean baseline: reinstall `dt.ipa`, then
  wait out the window or run in observe.

### 47.4 Repo / battery state

- DESIGN.md §46 (item 16 PASS) and `NEXT_BATTERY_ITEM.md` are committed **and pushed** (origin/main was
  current before this section; this §47 commit is a new local one to push).
- Next battery item (`NEXT_BATTERY_ITEM.md`): item 17 (iOS clean baseline) already satisfied by the
  2026-09-19 restore; item 18 (iOS fake-signature enforcement) is the next test, gated by §39.5.
- Account/token battery (items 3–8, 12/13) + two-phone stolen-token: with the .NET session against this
  endpoint.

### 47.5 Teardown — completed 2026-09-20

The .NET session finished. Executed: `INTEGRITY_MODE` reverted to **observe**; iPhone 7 reinstalled with
the clean **`dt.ipa`** (verified `score 0 / trusted`, identity intact); EC2 `i-0559685f02c4013b1`
**stopped** (not terminated; ~USD 0.64/mo EBS at rest), Elastic IPs 0, no NAT, no RDS. Resting config
persists `INTEGRITY_MODE=observe` and `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1` for the next start; the
DuckDNS endpoint repoints on start. To resume: start the instance, refresh the dev IP in SG 22 if it
changed, and point clients at `https://devicefingerprinting.duckdns.org`.
