# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

The **product line**: a reusable device-trust framework that customers embed in their own stack —
client SDKs in Flutter/Dart, .NET and Python, one server implementation, and database setup scripts,
so that *their app + this server + their database* recognises devices across reinstalls,
authenticates with non-exportable device-bound keys, makes stolen tokens useless on another device,
and detects root, Frida, hooking frameworks and tampering.

The headline requirement is **database portability**: Payactiv runs mostly **SQL Server** with some
**PostgreSQL**, so the same server must behave identically on both, across a wide version range.
Hence the repository name.

**.NET is a client SDK, not a second server.** Two independent implementations of signature
verification, nonce handling and scoring would double the security-review surface and risk a
divergence being a vulnerability in one of them. One server, many clients.

### Lineage

Cloned with full history from the proof-of-concept repository `devicefingerprinting`, which is frozen
at the tag **`poc-validated-2026-09-05`**. That tag is the reference implementation: real Frida
detected and blocked on an OPPO and a Huawei, both production `user` builds, neither rooted. When
behaviour here diverges from that tag, the tag is right until proven otherwise.

Files were renamed for the product; `git log --follow` traces through the old names.

| Now | Was (in the PoC repo) |
|---|---|
| `device_trust_server.py` | `yamaha.py` |
| `lib/device_trust_client.dart` | `lib/chatroompage.dart` |
| `DESIGN.md` | `Device Recognition Authentication.md` |

The archived `chatroompage.*` milestone snapshots were dropped here; the PoC tag preserves them.

## Read this first

**`DESIGN.md` is the authoritative design and validation record.** It holds the project goal, every
test with its PASS/FAIL result, the scoring tables, the bugs already found and fixed, the database
portability design (section 24), and the phase plan. Read it before proposing work; update it as
milestones complete. Sections 1-23 are PoC history and deliberately still say `yamaha.py`.

## Hard rules

**Claude does the shell work; the user does three things.** Claude runs `adb`, `logcat`, `ssh`/`scp`,
`flutter`, `git` and applies its own changes. The user only: presses buttons in the running app (say
when and how many times, then read the result with `adb logcat` yourself); physically connects a
phone when asked; enters credentials. Never ask for a secret in chat — give the user a way to enter
it themselves, and prefer one-time setups.

**Never root, wipe, or modify the OS of a physical test phone.** Installing a debug build is fine.

**The conformance suite is the gate.** `conformance_suite.py` is the regression harness for every
change, and the instrument that proves PostgreSQL and SQL Server behave identically. No database
change ships without it passing on both.

**Keep the server Python 3.9-compatible.** No `match`/`case`, no PEP 604 `X | Y` annotations. The
lab server is Debian 11 / Python 3.9.2, and staying compatible means one file runs everywhere.
Verify with `ast.parse(src, feature_version=(3, 9))`.

**Every change is its own git commit**, so `git revert <sha>` is exact.

## Supported databases

| Engine | Floor | Notes |
|---|---|---|
| PostgreSQL | **13+** | Lab server is 13.23. Verified. |
| SQL Server | **2016+** | AWS RDS. First version with `OPENJSON`/`JSON_VALUE`. |

`DB_ENGINE` (`postgresql` or `sqlserver`) selects the dialect. `/health/ready` reports the detected
engine, version, and whether it is at or above the floor. DESIGN.md section 24 carries the full type
mapping, the per-engine "do not use" list, and the two security-critical dialect differences
(replay upsert semantics and refresh-reuse row locking) — read it before touching SQL.

## Commands

```bash
# Conformance suite — the gate. 26 checks; needs `cryptography` (harness only).
python3 conformance_suite.py --base-url http://192.168.100.13:5000
#   Scoring checks need the server started with INTEGRITY_ANDROID_CERT_SHA256 set to the
#   certificate the suite prints, or empty to disable the allow-list. Restore the real
#   certificate afterwards or the physical phones hard-block.
#   The two enforcement checks SKIP unless INTEGRITY_MODE=enforce.

# Server syntax gate
python3 -c "import ast,io; ast.parse(io.open('device_trust_server.py',encoding='utf-8').read(), feature_version=(3,9)); print('3.9 OK')"

# Client
flutter analyze
flutter run -d <device> --dart-define=API_BASE_URL=https://<host>
```

## Lab environment

| | |
|---|---|
| Server | 192.168.100.13:5000, Debian 11 / Python 3.9.2, PostgreSQL 13.23 |
| Service | systemd `yamaha.service`, user `john`, config `/etc/yamaha.env` (root 600, never print) |
| Lab overrides | `/home/john/yamaha.lab.env` — john-writable, no secrets, overrides `/etc/yamaha.env`. Toggle `INTEGRITY_MODE`, `INTEGRITY_ALLOW_USERDEBUG`, `INTEGRITY_ANDROID_CERT_SHA256` here, passwordless |
| Deploy | `scp` the server file, then `ssh john@192.168.100.13 'sudo systemctl restart yamaha.service'` — both passwordless |
| Phones | OPPO CPH2083 and Huawei AQM-LX1, both clean production devices. Emulator `integrity_root_lab` is the disposable root lab (`hw.keyboard=no`, so drive text with `adb shell input text`) |

The lab service still runs the PoC deployment at `/home/john/yamaha.py`. Deploying
`device_trust_server.py` under its new name needs the systemd unit updated, which requires root —
hand that to the user as a script rather than attempting it.

## Delivering changes

Whole replacement files are fine. Every change must be revertable: commit before deploying, back up
the server copy to `.bak-<timestamp>`, and `diff -u` before replacing — the server copy may carry a
hand-edit. Write files to disk and give real paths; never reference a patch that exists only in a
message.

## Current point of work

DESIGN.md section 24 phase plan. Phases 0 and 0b are done (26 conformance checks green on
PostgreSQL 13.23). Next: `sslmode` support in the database connection for `rds.force_ssl`, then
Phase 1 — RDS PostgreSQL and Supabase behind HTTPS — then the dialect abstraction, then SQL Server.

Agreed and not yet built: the runtime DDL in `schema_guard` becomes **versioned migration scripts per
dialect**, DBA-run, with the app verifying schema version at boot. Those migration files are the
"database setup scripts" deliverable.
