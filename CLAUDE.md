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

| Engine | Floor | Role |
|---|---|---|
| PostgreSQL | **13+** | First test target, and some Payactiv systems |
| SQL Server | **2016+** | AWS RDS. The main Payactiv target. First version with `OPENJSON`/`JSON_VALUE` |

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

## Commands

```bash
# Conformance suite — the gate. 26 checks; needs `cryptography` (harness only).
python3 conformance_suite.py --base-url https://<endpoint>
#   Scoring checks need the server started with INTEGRITY_ANDROID_CERT_SHA256 set to the
#   certificate the suite prints, or empty to disable the allow-list.
#   The two enforcement checks SKIP unless INTEGRITY_MODE=enforce.

# Server syntax gate
python3 -c "import ast,io; ast.parse(io.open('device_trust_server.py',encoding='utf-8').read(), feature_version=(3,9)); print('3.9 OK')"

# Client — endpoint is mandatory
flutter analyze
flutter run -d <device> --dart-define=API_BASE_URL=https://<endpoint>
```

## Test devices

OPPO CPH2083 and Huawei AQM-LX1, both clean production `user` builds, neither rooted, both used to
validate real Frida detection and enforcement. The emulator AVD `integrity_root_lab` is the
disposable root laboratory; it has `hw.keyboard=no`, so drive text with `adb shell input text`.

## Current point of work

DESIGN.md section 24 phase plan. Phases 0 and 0b are done: 26 conformance checks green against
PostgreSQL 13.23.

Next: deploy to AWS behind HTTPS and re-run the suite against **PostgreSQL RDS**, then **SQL Server
RDS**, then **Supabase**, pointing the client at each with `--dart-define`. The one code change the
RDS round needs is TLS support in the database connection for `rds.force_ssl`.

Agreed and not yet built: the runtime DDL in the schema guard becomes **versioned migration scripts
per dialect**, DBA-run, with the app verifying schema version at boot and refusing to start on
mismatch. Those migration files are the "database setup scripts" deliverable. This matters more on
Lambda, where a cold start would otherwise attempt DDL and concurrent cold starts could race.
