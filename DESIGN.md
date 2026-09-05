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

### 25.11 The standard per-engine handset suite (2026-09-05)

Fixed definition, so each engine family is tested identically and results are comparable. Run once per **engine family**, on **both handsets**, with **release builds only**:

1. **Stolen access token** - Phone A mints it, Phone B replays it with its own hardware key. Must fail `invalid_installation_signature` *after* reaching proof verification.
2. **Stolen refresh token** - same shape, via the refresh challenge. The challenge must return 200 (token genuine) before the refresh is refused.
3. **Access-proof boundary tests (4)** - replay, body tampering, path+method tampering, stale timestamp. Must run **within 10 minutes of a session refresh**, or an expired access token makes them inconclusive.
4. **Frida Gadget** - real gadget embedded in a release APK: scan must reach `block`, a protected call must be refused, and after restoring the clean build the device must return to `trusted`.

Surrounding each run, and implied by the above: clean baseline scan, account creation through the enforce gate, and the device-memory check that a reinstall with a new hardware key is still refused.

Individual database **versions** within a family get the 26-check conformance suite only.
**This reduction was agreed for the PostgreSQL sweep specifically and must not be generalised to
another engine family without asking** — see §27.3, where applying it to SQL Server was wrong. The handset exercises the client and the native collector, which are byte-identical across versions and cannot observe the database; the suite is what detects dialect behaviour.

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
