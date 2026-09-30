# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A reusable device-trust framework that customers embed in their own stack: **client SDKs in
Flutter/Dart, .NET and Python**, one **server implementation**, and **database setup scripts**, so
that *their app + this server + their database* recognises devices across reinstalls, authenticates
with non-exportable device-bound keys, makes stolen tokens useless on another device, and detects
root, Frida, hooking frameworks and tampering.

The server, not Google or Apple, owns the risk score. There is deliberately no Play Integrity,
SafetyNet, App Attest or DeviceCheck. Do not introduce one.

The headline requirement is **database portability**. Payactiv runs mostly **SQL Server** with some
**PostgreSQL**, so the same server must behave identically on both across a wide version range.
Hence the repository name.

**.NET is a client SDK, not a second server.** Two independent implementations of signature
verification, nonce handling and scoring would double the security-review surface and risk a
divergence becoming a vulnerability in one of them. One server, many clients.

Known and accepted boundary: a fully compromised OS can falsify local measurements and may use a
legitimate non-exportable key as a signing oracle. Without an independent hardware root of trust
this is strong risk-based defence in depth, not perfect attestation. Say so rather than overclaiming.

## Read this first

**`DESIGN.md` is the authoritative design and validation record** — the goal, every test with its
PASS/FAIL result, the scoring tables, the bugs found and fixed, the database portability design
(section 24) and the phase plan. Read it before proposing work and update it as milestones complete.
Sections 1-23 are the validation history that produced this design; they are evidence, not
aspiration.

## Hard rules

**Claude does the shell work; the user does three things.** Claude runs `adb`, `logcat`, `ssh`/`scp`,
`aws`, `flutter`, `git` and applies its own changes. The user only: presses buttons in the running
app (say when and how many times, then read the result with `adb logcat` yourself); physically
connects a phone when asked; enters credentials. Never ask for a secret in chat — give the user a way
to enter it themselves, and prefer one-time setups.

**Never root, wipe, or modify the OS of a physical test phone.** Installing a debug build is fine.

**The conformance suite is the gate.** `conformance_suite.py` is the regression harness for every
change and the instrument that proves PostgreSQL and SQL Server behave identically. No database
change ships without it passing on both.

**Keep the server Python 3.9-compatible.** No `match`/`case`, no PEP 604 `X | Y` annotations.
Verify with `ast.parse(src, feature_version=(3, 9))`. This keeps deployment options open, including
Lambda runtimes and older customer environments.

**The API endpoint is always supplied at build time.** `API_BASE_URL` has no default; a build with
none fails fast with `api_base_url_missing`. Never hardcode an environment into the client.

**Every change is its own git commit**, so `git revert <sha>` is exact.

## Supported databases

| Engine | Syntax floor | Tested range | Role |
|---|---|---|---|
| PostgreSQL | 13 | **13 - 18, all green** | Some Payactiv systems |
| SQL Server | 2016 | **2017 - 2025** | The main Payactiv target. 2016 is untestable (no RDS edition, no Linux build) so syntax compatibility is kept but the tested floor is 2017 |

SQL Server releases in range: 2017, 2019, 2022, 2025. There is no 2018, 2020 or 2021.
Redis is in scope for the SQL Server phase - see DESIGN.md section 25.12.

`DB_ENGINE` (`postgresql` or `sqlserver`) selects the dialect. `/health/ready` reports the detected
engine, version, and whether it meets the floor. DESIGN.md section 24 holds the type mapping, the
per-engine "do not use" list, and the two security-critical dialect differences — replay upsert
semantics and refresh-reuse row locking. Read it before touching SQL.

## Deployment

AWS, created for a test round and torn down afterwards. Cost is measured in hours, not months, so
the create-test-delete cycle keeps a test round inside a trivial budget. Avoid NAT Gateway
(~$33/month), ALB (~$16/month) and ElastiCache; none are needed.

Teardown discipline matters more than provisioning: RDS final snapshots and manual snapshots outlive
the instance and keep billing, unattached Elastic IPs bill hourly, and a Route 53 hosted zone deleted
within 12 hours of creation is not charged.

The test server is EC2 `i-0559685f02c4013b1` (stopped between sessions; public IP changes on every
start, DuckDNS `devicefingerprinting.duckdns.org` follows it). It runs **gunicorn with 4 worker
processes** from the systemd drop-in, with a per-process connection pool (`DB_POOL_SIZE`,
`DB_POOL_RECHECK_SECONDS`) and, on SQL Server, a 15 s statement timeout (`DB_QUERY_TIMEOUT`) —
DESIGN.md 55 and 60. Serve SQL Server with processes, never threads.

**Schema is migrations, DBA-applied.** `migrations/<dialect>/001…007`, applied in order; the server
refuses to serve unless `schema_migrations` holds the version it requires (currently **7**). A new
table needs its grant (`GRANT`/`ALTER DEFAULT PRIVILEGES` on PostgreSQL). Risk and step-up policy
values live in `risk_policy_settings`, seeded by the migrations with the owner's defaults, which a DBA
may change — never hard-code a policy value.

## Commands

```bash
# Conformance suite — the gate. 55 checks; needs `cryptography` (harness only).
python3 conformance_suite.py --base-url https://<endpoint>
#   Scoring checks need the server started with INTEGRITY_ANDROID_CERT_SHA256 set to the
#   certificate the suite prints, or empty to disable the allow-list.
#   Enforcement checks SKIP unless INTEGRITY_MODE=enforce; opt-in checks (rate anomaly,
#   population baseline, step-up) SKIP until their risk_policy_settings rows are enabled.
#   check_parallel_clients (4 concurrent flows) must pass on any new backend BEFORE handset
#   or paid-database time is spent on it.

# Offline security regression gate (review F1-F10, DESIGN.md 63): no database needed
python3 tools/check_security_regressions.py
# Native scanner on the host (from a scratch dir; clang++ or g++)
clang++ -std=c++17 -O1 -Wall -Wextra -Itools/native -Iandroid/app/src/main/cpp \
    tools/native/check_code_integrity.cpp -o check_code_integrity && ./check_code_integrity
# Live first-link race on a real engine (server env; --compare an older server file)
python3 tools/race_first_link.py

# Server syntax gate
python3 -c "import ast,io; ast.parse(io.open('device_trust_server.py',encoding='utf-8').read(), feature_version=(3,9)); print('3.9 OK')"

# Client — endpoint is mandatory; Android builds are release builds
flutter analyze
flutter build apk --release --dart-define=API_BASE_URL=https://<endpoint>
# iOS: Codemagic (manual trigger), then tools/presign_trollstore_ipa.sh, then TrollStore
```

## Test devices

OPPO CPH2083 (Android 9) and Huawei AQM-LX1 (Android 10), clean `user` builds, never rooted; Vivo
V2118 (Android 12, logcat empty — read results from the server); iPhone 7 (iOS 15.8.5, TrollStore,
not jailbroken). The emulator AVD `integrity_root_lab` is the disposable root laboratory; it has
`hw.keyboard=no`, so drive text with `adb shell input text`.

## Current point of work

See the end of DESIGN.md: section 63 records the 2026-09-29 external review, what was repaired, the
owner decisions it leaves open and what is still to run on handsets; sections 51–62 cover the step-up
key, dead-key recovery, the account policy, SQL Server concurrency, the serving model and W^X
baselines. Step-up proofs are **v2** (they sign the whole request); behind a TLS-terminating proxy set
`TRUSTED_PROXY_COUNT`, or `REQUIRE_HTTPS=1` answers 426 to everything.
