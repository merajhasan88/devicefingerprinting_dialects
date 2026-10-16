# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

An open-source device-trust platform that customers — financial apps, games, government mobile apps —
embed in their own stack: **client SDKs** (native Android in Kotlin, native iOS in Swift, Flutter/Dart,
.NET and React Native — owner decision of 2026-10-15, each built in a session of its own; Python is not
an app SDK), one **server implementation**, and **database setup scripts**, so that *their app + this
server + their database* recognises devices across reinstalls, authenticates with non-exportable
device-bound keys, makes stolen tokens useless on another device, and detects root, Frida, hooking
frameworks and tampering. This repository holds the server, the Flutter client and its harness, and the
native Android and iOS code the other SDKs package. It is meant to be published by the owner (planned:
necessary.com or necessary.io); write for any customer, never one company.

The server, not Google or Apple, owns the risk score. There is deliberately no Play Integrity,
SafetyNet, App Attest or DeviceCheck, and — owner decision of 2026-10-06, DESIGN.md 66 — no local
verification of Android key-attestation chains either (Remote Key Provisioning is not banned, but
nothing relies on it). Phone signals are untrusted evidence; the server's own logic, with velocity
and fraud signals, decides. Do not introduce attestation.

The headline requirement is **database portability**: customers run **SQL Server** or **PostgreSQL**,
so the same server must behave identically on both across a wide version range.
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
| PostgreSQL | 13 | **13 - 18, all green** | Customers on PostgreSQL |
| SQL Server | 2016 | **2017 - 2025** | The engine most enterprise customers run. 2016 is untestable (no RDS edition, no Linux build) so syntax compatibility is kept but the tested floor is 2017 |

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

**Schema is migrations, DBA-applied.** `migrations/<dialect>/001…025`, applied in order; the server
refuses to serve unless `schema_migrations` holds the version it requires (currently **25**). A new
table needs its grant (`GRANT`/`ALTER DEFAULT PRIVILEGES` on PostgreSQL). Risk and step-up policy
values live in `risk_policy_settings`, seeded by the migrations with the owner's defaults, which a DBA
may change — never hard-code a policy value; the gate fails when the server reads a setting no
migration seeds, or falls back to a value other than the seeded one. The settings reference in
`INTEGRATION_GUIDE.md` §5 and `WHO_CONFIGURES_WHAT.md` §2 is generated: after changing a migration's
settings run `python3 tools/settings_reference.py --write`. Every reason code, observation kind and
probe field the server can emit must be named in `MEASUREMENTS.md` (also gated). `GAME_THREATS.md` maps game
bots and exploits onto those codes; every code it names must exist (gated).

**A new probe is volunteered, never planned.** The server refuses a report that lacks a planned probe,
so adding one to `_integrity_probe_plan` breaks every older client, the .NET collectors included. New
collectors send it unasked (`device`, `network`, iOS `code_integrity`); promote it to the plan only once
every client sends it. A measurement that identifies a person's phone or network is collected only
where the DBA asks for it (`optional_measurements`) and the app enables it (its build setting;
DESIGN.md 80). Every report stores every measurement's status, so the server always knows what was and
was not measured (DESIGN.md 83).

## Commands

```bash
# Conformance suite — the gate. 94 checks; needs `cryptography` (harness only).
python3 conformance_suite.py --base-url https://<endpoint>
#   Scoring checks need the server started with INTEGRITY_ANDROID_CERT_SHA256 set to the
#   certificate the suite prints, or empty to disable the allow-list.
#   Enforcement and limited-session checks SKIP unless INTEGRITY_MODE=enforce; opt-in checks
#   (rate anomaly, population baseline, step-up, eligibility rules, upgrade routes 1 and 3,
#   scored cross-checks, the app PIN where no path needs it) SKIP
#   until their risk_policy_settings rows are enabled; route 3 also needs the suite's JWKS
#   (it prints it) in the file named by UPGRADE_ASSERTION_JWKS_FILE. The business API checks
#   (events, the report feed, PIN support) need DEVICE_TRUST_BUSINESS_TOKEN in the environment;
#   PIN support needs a token whose BUSINESS_API_TOKENS entry names pin_unlock and pin_reset.
#   check_parallel_clients (4 concurrent flows) must pass on any new backend BEFORE handset
#   or paid-database time is spent on it.

# Offline security regression gate (118 checks; DESIGN.md 63, 76-83): no database needed
python3 tools/check_security_regressions.py
# The generated settings reference (G7): print, or rewrite it in the two documents
python3 tools/settings_reference.py [--write]
# Refresh the public VPN, data-centre and Tor lists in data/network_lists (DevOps, daily)
python3 tools/fetch_network_lists.py
# Native scanner on the host (from a scratch dir; clang++ or g++)
clang++ -std=c++17 -O1 -Wall -Wextra -Itools/native -Iandroid/app/src/main/cpp \
    tools/native/check_code_integrity.cpp -o check_code_integrity && ./check_code_integrity
# Live races on a real engine (server env; --compare an older server file)
python3 tools/race_first_link.py
python3 tools/race_admission.py   # review R2: parallel sign-ins cannot exceed the counts

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

See the end of DESIGN.md: section 83 records the critical review of 2026-10-16 and what was built from
it — conditions capped at 60 together and kept out of the device memory, each measurement's status
with the measurements a path requires, malformed app lists refused, business API tokens per caller with
roles, every scan and decision stamped with its settings version and server build, VPN learning by
latest sighting and phone age, event-ID conflicts, recording apart from another display, old fake-GPS
fixes unscored, and owner defaults for the signals that scored 0 (schema 25); section 82 records six optional measurements — the apps holding
Accessibility, the keyboard, notification access and device administration with their source (system,
store by the DBA's `app_store_installers`, sideloaded), remote-control apps, screen capture, the location
and mock locations — each finding at the DBA's points (owner defaults: sideloaded holders 30-45, the broad
ones 0) with an eligibility rule, the security patch age rule (365 days, 10 points), the
protected app PIN entry, and that deleting VPN sightings is the DBA's job (schema 24; collectors
Android 5, iOS 4 — the Swift not yet compiled); section 81 records the source-network signals — public VPN, data-centre and
Tor lists shipped with the server, and VPN exits learned from the deployment's own Android phones
(`vpn_exit_learning`, off by default), all at 0 points (schema 23) — and the platform scope; section 80
records the device and network probes (the OS version and
patch level, a VPN or proxy at 0 points with optional eligibility rules), optional measurements behind
two keys (the DBA's `optional_measurements` and the app's build setting) and request metadata the DBA
may record (schema 22; collectors Android 4, iOS 3 — the Swift not yet compiled); section 79 records the owner's answers to the who-configures-what audit
(`WHO_CONFIGURES_WHAT.md`) and what was built — the relationship rules and session lifetimes as DBA
settings, support unlock and reset of an app PIN, the step-up policy read by the app at runtime, the
business feed of integrity reports, the measurement catalog and the generated settings reference
(schema 21); G2, G3, G6 and G10 are deferred by the owner; section 78 records the step-up method — the screen lock, an app PIN the
server checks, or both, the DBA's choice (schema 20); section 77 the server's own observations
(cross-checks measured into every decision, scored only where the DBA enables them); section 76 the critical review of
2026-10-13 and what was built from it (sign-out and family checks, admission under locks, evidence
quality, scoped acceptances, the business API, carried-over approvals); sections 73–75 the handset rounds and SQL Server; sections 66–72 record the 2026-10-05 joint review, the declined attestation
proposal, the limited-session design (67) and its implementation (70, 72), R4 (68), R1 (69) and
the DBA-tunable bands (71), each with its state;
section 64 is an open question for the reviewer (the .NET W^X allowance); section 63 records the
2026-09-29 external review, what was repaired and the owner's decisions; sections 51–62 cover the step-up
key, dead-key recovery, the account policy, SQL Server concurrency, the serving model and W^X
baselines. Access proofs and step-up proofs are **v2** (they sign the whole request, query string
included; `ACCESS_PROOF_MIN_VERSION` lets a transition accept v1); behind a TLS-terminating proxy set
`TRUSTED_PROXY_COUNT`, or `REQUIRE_HTTPS=1` answers 426 to everything. Device-account links are
permanent evidence: nothing may delete, expire or retire one. `INTEGRATION_GUIDE.md` is the
customer-facing configuration guide; keep it true when behaviour changes.
