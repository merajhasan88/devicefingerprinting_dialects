# Device Recognition / Authentication / Integrity Project — Complete Handoff

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
yamaha_integrity_fk_cleanup_fixed.py
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

python3.9 yamaha_integrity_fk_cleanup_fixed.py
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

**Fix applied to `yamaha.py`** (`_score_android_integrity`): `ro.build.type` was collected by the probe but never scored. Added `android_build_type_not_user +45` for any non-empty build type other than `user`. Not gated by `INTEGRITY_ALLOW_DEBUG`. Python 3.9-safe; no schema or dependency change. Reason: a userdebug/eng image is root-capable by construction, and a property read survives the sandbox where a file stat does not.

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

## 21.5 Open items

- Verify the `su` invisibility cause: `ls -lZ /system/xbin/su`, `run-as com.example.devicefingerprinting ls -l /system/xbin/su`, `dmesg | grep avc`.
- Next test: **Frida Gadget embedded in the APK on the OPPO** (`user` build, no root, `INTEGRITY_MODE=enforce`). Expect `android_frida_runtime_artifact` via the `gadget` token in `runtime_maps`, then 403 `integrity_blocked` on a protected request. This is the first enforcement-against-real-compromise test on production-class hardware.
