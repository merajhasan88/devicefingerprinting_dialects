# Handoff to the .NET SDK session — 2026-09-30

From the reference session (Flutter client + `device_trust_server.py`). The authoritative record is
`DESIGN.md` §63 in `devicefingerprinting_dialects`. An external review (2026-09-29) found defects in the
server's step-up binding and evidence handling; they are fixed, and **one fix breaks your step-up path**.
Nothing in your repository was changed — whether and how this file reaches it is the owner's call.

## 1. Must change: step-up proof v2 (your step-up calls are refused until you do)

Your `DeviceTrustClient.BuildStepUpProof` sends v1 `{version:1, installation_id, factor, nonce,
timestamp}`. The server now answers **403 `stepup_proof_version_unsupported`** to that. Reason: v1 did
not sign the request, so whoever held the installation signer could attach a fresh approval to a
different body under a re-signed access proof with the same nonce (reproduced by the review).

v2, signed by the step-up key exactly as before (base64url JSON in `X-Step-Up-Proof`, base64url DER in
`X-Step-Up-Signature`):

```json
{
  "version": 2,
  "purpose": "stepup",
  "installation_id": "<canonical installation id>",
  "access_token_sha256": "<sha256 hex of the bearer token string>",
  "method": "POST",
  "path": "/v1/account/sensitive-echo",
  "query": "",
  "body_sha256": "<sha256 hex of the exact body bytes you will send>",
  "factor": "passcode",
  "nonce": "<the access proof's nonce>",
  "timestamp": 1790000000
}
```

- `method` upper-case; `path` exactly as sent; `query` the raw query string without `?` (`""` when
  none); `body_sha256` over the **same bytes** the access proof hashes. Each is compared with the real
  request — a mismatch is **403 `stepup_binding_mismatch`** with `details.field` naming it.
- Order unchanged: freeze body and nonce, sign the step-up proof (the prompt), then sign the access
  proof with that nonce.
- The factor must now match **both** the policy and the factor the key was **registered** with
  (`stepup_key_auth.factor`), else **403 `stepup_factor_mismatch`**.
- Re-enrolment's `stepup_reenrol` proof (version 1) is **unchanged**.

Your harness checks (`StepUpConformanceChecks.cs`) should add the review's attacks, as the reference
suite now does: an approval signed for body A sent with body B → `stepup_binding_mismatch`; the same
with another path; a v1 proof → `stepup_proof_version_unsupported`; a key registered with the other
factor → `stepup_factor_mismatch`.

## 2. Also changed at registration

- `stepup_key_auth` is **required** whenever `stepup_public_key` is sent (400 `invalid_stepup_key_auth`).
- The step-up key must differ from the installation key (400 `invalid_stepup_key`).
- Re-registering a known key no longer changes stored `key_security` (it is written once, at first
  registration); a different claim is ignored, a weaker one still comes back as `downgrade_reported`.

## 3. Integrity reports — checked against your stored reports, no action expected

- A requested probe that answers `ok` without its required fields scores like a failed probe (+30),
  and a known field with the wrong JSON type is **400 `invalid_integrity_probe`**. Your 11 Android and
  16 iOS reports on the test server all carry every required field.
- `collector_version` must be 1…1000 (you send 2).
- Code-integrity differences count from **1 byte** (was ≥ 4).
- The W^X baseline allowance now requires the shape to add up (classes cover every mapping and byte).
  All 11 of your stored reports carrying `wx_bytes` do.
- New optional coverage fields (`<bucket>_expected_bytes`, `_skipped_bytes`, `_unreadable_bytes`,
  `_complete`, `protect_restore_failures`) are what the Kotlin/NDK scanner now reports. You need not
  send them; if you do, they must add up (expected = compared + skipped + unreadable).
- With `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1` (as on the test stack) iOS `code_integrity` is a
  requested probe; your iOS collector already sends it.

## 4. Server behaviour you may see

- `/health/ready` answers **503 `not_ready`** (with `problems`) when the database, schema, policy
  snapshot or Redis nonce store is unavailable; 200 otherwise.
- Oversized bodies (> 256 KiB) are 413; an unreadable policy table is 503 `risk_policy_unavailable`.
- The shared stack runs Caddy → gunicorn with `TRUSTED_PROXY_COUNT=1`; nothing changes for a client.

## 5. The shared test stack

EC2 `i-0559685f02c4013b1`, PostgreSQL 16.15, **schema 8**, observe/observe, `ACCESS_PROOF_MIN_VERSION=1`
(see 6). Ask the owner before starting it. The reference suite now has 59 checks;
`tools/check_security_regressions.py` is the offline gate for server changes. `INTEGRATION_GUIDE.md`
in the reference repository is the customer-facing configuration guide.

## 6. Added 2026-10-04 (owner-approved, DESIGN.md 63.9)

**Must change: access proof v2.** Every protected request's access proof gains `"query"` — the raw
query string exactly as sent, without `?` (`""` when there is none) — and `"version": 2`. Everything
else in the proof is unchanged. A server with the default `ACCESS_PROOF_MIN_VERSION=2` answers a v1
proof with **400 `unsupported_access_proof_version`** (`details.minimum`). The shared stack is set to 1
for the transition, so your v1 proofs still work there — except on a request that carries a query
string, which a v1 proof can never cover (401 `access_proof_query_mismatch`). The same code answers a
v2 proof whose `query` differs from the request's. `/health/ready` lists `access_proof_versions`.

Also new, no client change required:

- **Elevated integrity** (enforce mode): on an authenticated account request, attaching a valid step-up
  proof v2 for that request now satisfies an `elevated` verdict (`integrity.satisfied_by_step_up`).
  Login, account registration and refresh accept none; there an elevated verdict now answers
  **403 `integrity_elevated`** (a clean scan is needed) instead of `integrity_step_up_required`.
- **Admission budgets** (only with `RATE_LIMIT_ENABLED=1`, as on the shared stack): per source address on
  registration, challenge, verify, account registration and login (120 per minute by default), and per
  account handle on login (20 per minute). Expect **429 `rate_limited`** from a tight loop.
- At five open challenges for one installation the oldest unused one is now dropped instead of
  answering 429, so verifying a dropped challenge answers 404 `challenge_not_found`; request a new one.
- Registrations that never proved their key no longer count toward a device's installation and
  reinstall totals (migration 008, `verified_at`).

## 7. Two client-side step-up gaps found on hardware on 2026-10-04 — your SDK has both

Read from your repository at `1065b33` (nothing there was changed).

**a. Step-up offered for a key the server never bound** (reference fix `215768b`, DESIGN.md 63.10).
On the iPhone the passcode was off at launch, so the old step-up key was dead and none was offered at
registration (`stepup_key_matches` came back null). With the passcode back on, a re-enrolment attempt
created a fresh key and was refused (wrong password, 401); the app then enabled step-up anyway and the
server refused the unbound key's signature (`stepup_signature_invalid`). Your
`DeviceTrustClient.StepUpUsable` has the same condition (`StepUpKeyMatches != false`), so a null
"never asked" passes. The fix: remember the thumbprint of the key you offered at registration when the
server bound it (new installation) or reported it matching, and treat only that key as usable; any other
local key gets the re-enrol path.

**b. An Android step-up alias that has lost its private key** (reference fix `b74ff1e`, DESIGN.md 63.8).
On the OPPO (Android 9), after the screen lock had been off and was set again, the alias still existed
but held no private key: `containsAlias` true, `isKeyEntry` false, and `getEntry(alias, null)` threw a
bare `UnsupportedOperationException` — not `UnrecoverableKeyException`, not
`KeyPermanentlyInvalidatedException` — so the app showed an unexplained native error and never offered
re-enrolment. Your `AndroidStepUpKeyStore` follows the same `ContainsAlias` → `LiveEntry` shape. Treat
`!IsKeyEntry(alias)` (and that exception) as a dead key: delete the alias, report
`STEPUP_KEY_INVALIDATED`.

**Results on the shared stack today**, with the server refusing v1 access proofs for each run: the OPPO
(18/trusted, every code-integrity bucket complete — core 7.1 MB, ext 5.7 MB, app 15.2 MB in ~440 ms —
step-up v2 verified) and the iPhone (0/trusted, step-up v2 verified, per-use passcode). The stack is back
to `ACCESS_PROOF_MIN_VERSION=1` until you move to v2.

## 8. From the joint review (2026-10-05) — the .NET items

The reviewer read your SDK at `924c42e` (nothing in your repository was changed here). Server-side
items from the same review are fixed in the reference (DESIGN.md 66); these are yours.

- **R2, code-integrity coverage.** `ManagedCodeIntegrity.cs` still spends a 4 MiB budget per backing
  file from the lowest address (`MaxBytesPerLibrary`), so later pages are never compared — and libraries
  mapped out of one APK share one budget. Port the reference scanner's contract (`904b383`/`6e846eb`):
  compare every target mapping in full, in chunks, under a large ceiling; report
  `<bucket>_expected_bytes / _skipped_bytes / _unreadable_bytes / _complete`; report failed protection
  restores (`protect_restore_failures`; your restore at line 328 ignores `mprotect`'s result). Also:
  `Checked=true` is set even when no target contributed a byte, an unreadable backing file adds nothing
  to a denominator, and W+X mappings are skipped wholesale. The iOS scanner's 64 MiB per-image cap has
  the same missing denominator.
- **The server now refuses empty scans** (R3, `fad5c20`): a requested `code_integrity` with
  `checked=true` but zero bytes compared in a bucket that always holds code (Android core/ext/app; the
  iOS app bucket) is `integrity_probe_incomplete` +30. Your stored reports all pass; a scanner fault
  that zeroes a bucket will now show.
- **R3, swallowed read failures.** `ReadLines` returns an empty array on `IOException` /
  `UnauthorizedAccessException`, and its callers then report `status: ok` with clean defaults (no
  suspicious lines, tracer PID 0, no executable mappings). Let the failure reach the probe as an error.
- **R6, command deadline.** `RunCommand` calls `StandardOutput.ReadToEnd()` before
  `WaitForExit(2000)`, so a child that keeps stdout open blocks forever; stderr is never drained and the
  timeout result is ignored. Use one deadline over start, both reads and exit, kill the child on expiry,
  and return a failed observation (the reference did this in `e24cae2`).
- **R7, concurrent refresh.** Only identity loading is serialised; two callers can rotate the same
  refresh token and the second trips family revocation. Coalesce refreshes into one in-flight operation
  and persist the replacement before dependents continue. Server side, the challenge step no longer
  revokes anything (`b8ec78a`): reuse is judged only after the key signs, in `/v1/auth/refresh`; your
  harness already accepts either point.
- **R8, size classes.** Send the complete W^X class list (no `Take(12)`), or an aggregate the server
  can check (allocation-size GCD, class count, a truncation flag). The server now gives the allowance
  only to a list that accounts for every mapping and byte (`56ec6d8`), so a report with more than twelve
  classes scores +60 until this is fixed. Your stored reports have three to five classes.
- **Docs.** `docs/wx-baseline-process.md` says the operator-pinned APK hash cannot be forged by the
  process under suspicion. The allow-list is server-controlled; the hash that selects an entry is
  client-supplied — the reviewer changed only that claim and moved a report from 60 to 0.
- **Mono AOT experiment** the reviewer suggests: Release with `RunAOTCompilation=true`,
  `AndroidEnableProfiledAot=false`; capture the evaluated properties and build log, then repeat the full
  session measurement. Not promised to remove runtime-generated code.
- **Still open on the server side (owner decision):** how W^X growth within a session is scored (R1).
  Until decided, a warm session on a phone with developer options and ADB reads 33 / elevated.

Server behaviour you may see from these changes: installation challenges are now stateless until used
(`5adbab7`) — the payload is still opaque to you. Verification answers **401 `challenge_used`** on a
second use and **401 `challenge_payload_mismatch`** for a challenge the server did not issue or that was
modified (an unknown challenge ID used to be 404 `challenge_not_found`). There is no longer a
five-open-challenges cap or a per-installation challenge budget.

## 9. Added 2026-10-07 — R4 (server only, no client change)

DESIGN.md §68, `1b7d3c5`, **schema 9** (migration 009, `app_installations.device_confirmed_at`).

- An integrity block now spreads only from a device's **established** installations: the original one,
  or a hint-linked one confirmed when an account first linked through an established installation signs
  in on it. A block reported by an unconfirmed hint-linked installation refuses only that installation.
  Nothing changed for data that existed before the migration.
- Two additive fields in every risk decision's `context`: `installation_established` (bool) and
  `installation_device_confirmed_at` (ISO time or null). Nothing to parse unless you want to show them.
- The reference suite gained three checks you may want to mirror (63 now): a block from an unconfirmed
  reinstall does not reach the device's owner; a reinstall confirmed by a returning account carries its
  block to the device; accounts opened on a reinstall cannot confirm another reinstall.

## 10. Added 2026-10-07 — R1 (server; one SDK change requested)

DESIGN.md §69, `c966ffb`, **schema 10** (migration 010 seeds three settings).

- **Requested: profile a full session in the `baseline` command.** The pin is now treated as the
  build's full-session envelope (the reviewer's R1): growth above it is advisory only up to
  `wx_far_above_baseline_percent` (default 200 %), and +40 beyond. Your command measures the first scan
  after four cold starts; it should drive representative sessions (login, registration, refresh,
  step-up, background and resume, repeated scans, a long session) and print the largest total, still
  refusing to emit anything when runs show a foreign allocation size. `docs/wx-baseline-process.md`'s
  scoring table (+15 above the baseline) is out of date.
- `android_wx_above_baseline` is now 0 points (advisory); `android_developer_options` and
  `android_adb_enabled` are 0 points. Your warm session on a developer phone reads 0 / trusted (was 33).
- New refusal, only when a DBA sets `developer_options_refuses` or `adb_enabled_refuses` to 1:
  **403 `integrity_device_ineligible`**, `details.eligibility[]` = {rule, reason, remedy}. Show the
  remedy; the fix is the phone setting plus a new scan, not step-up.
- `developer_settings` is requested on every Android scan (it already was with the default draw count).
- The reference suite has 65 checks: the W^X check now asserts points and reads the live percentage;
  new: developer settings advisory, and an eligibility check that runs when a rule is set.

## 11. Added 2026-10-07 — limited sessions (server; SDK work needed before enforce mode)

DESIGN.md §70 (design §67), **schema 11**. Nothing changes in observe mode. In enforce mode:

- **Responses.** Login, registration and refresh carry `scope` (`full` or `limited`); a limited one also
  `limited_causes` and `upgrade_routes` (`stepup`, `approval`, `assertion` — whichever are open to this
  user now; empty means send the user to support). Both tokens carry a `scope` claim; refreshing never
  widens it.
- **New refusal: 403 `session_limited`** (`details.limited_causes`, `details.upgrade_routes`) for a
  limited token anywhere except `/v1/auth/upgrade`, `/v1/auth/upgrade/request`, `/v1/integrity/*` and
  the DBA's `limited_session_paths`.
- **Upgrade:** `POST /v1/auth/upgrade` `{"route": "recheck" | "stepup" | "approval" | "assertion", ...}`
  returns a full token pair in the same family. `recheck` works once the cause is gone (e.g. after a
  clean scan); `stepup` needs a step-up proof v2 over the upgrade request; `approval` and `assertion`
  start with `POST /v1/auth/upgrade/request` `{"route": ...}` (→ `request_id`, and for an assertion the
  `assertion_claims` the customer's backend signs). A second phone approves with
  `GET /v1/auth/approvals` and `POST /v1/auth/approvals/<id>/approve` (step-up required; its newest
  token) or `/deny`.
- **Codes to handle:** `upgrade_proof_required`, `upgrade_route_unavailable`, `session_not_limited`,
  `session_rotated` (upgrade with the newest token), `approval_not_granted` (`details.state`: pending,
  denied, expired, used, unknown — poll no faster than every 5 s), `no_approving_device`,
  `upgrade_budget_exhausted` (429), `full_session_required`, `approval_not_pending`,
  `upgrade_assertion_invalid` (`details.field`).
- **Behaviour you may hit in tests:** an elevated verdict at login now gives a limited session instead
  of 403 `integrity_elevated` (unless the DBA empties `limited_session_integrity_verdicts`); a new
  account, or a first sign-in onto a device other accounts use, under relationship risk is still
  refused.
- The reference suite has 71 checks: limited login and clean-scan recheck, refresh, registration, and
  one check per route (route 3 with a deterministic key whose public JWK the suite prints).

## 12. Added 2026-10-12 — DBA-tunable bands (server only, no client change)

DESIGN.md §71, **schema 12** (migration 012). The relationship bands (30 / 60 / 90) and the
devices-per-account counts (2 elevated, 3 review, 5 block) are now `risk_policy_settings` rows; every
decision's `thresholds` reports the live bands. Nothing changes at the defaults. The reference suite
has 72 checks (new: devices per account, expectations from the live settings).

## 13. Added 2026-10-12 — an upgrade's acceptance; first sign-ins within the counts

DESIGN.md §72, **schema 13** (migration 013). Server only; nothing changes in observe mode.

- After an upgrade made with a proof, the response carries `accepted_causes` and `accepted_until`, and
  the session keeps them (both tokens, and across refreshes) for `upgrade_acceptance_hours` (720).
  Protected requests then pass those causes — an accepted `integrity_elevated` no longer needs a
  step-up proof per ordinary request — and a refresh stays `full`. Anything worse refuses or narrows
  the session again. No client change is needed; a client that attaches step-up proofs pre-emptively
  may stop doing so while an elevated verdict is accepted.
- A first sign-in under relationship risk that would make the phone's third account or the account's
  third device is refused (403 `risk_review_required` / `risk_policy_blocked`), never limited.

## 14. Added 2026-10-13 — limited sessions on a phone: what the reference client does

The Dart reference client now implements §11 and has been run on the Huawei (Android 10), the OPPO
(Android 9) and the Vivo (Android 12), against PostgreSQL and SQL Server (DESIGN.md §73–§75). These are
the client behaviours your SDK needs before a customer turns enforce mode on:

- **Wait for an approval by itself** (`f264b36`). After `POST /v1/auth/upgrade/request`
  `{"route": "approval"}`, send `POST /v1/auth/upgrade` `{"route": "approval", "request_id": ...}` every
  5 s — never faster — until it returns the full token pair, or `approval_not_granted` with a terminal
  `details.state` (`denied`, `expired`, `used`, `unknown`, `superseded`); stop at the request's
  `expires_at`. On `integrity_scan_required`, scan again and carry on.
- **`stepup_key_other_account`** (`8a85ea9`). On approve, this means the phone's step-up key was
  re-enrolled by another account on the phone (DESIGN.md §58) and cannot sign for the signed-in one: stop
  offering Approve and offer re-enrolment with this account's password. A key bound at registration
  (no account) serves every account on the phone.
- **The approvals list** (`ab04822`). After approve or deny — whatever the answer — fetch the list again;
  drop a request locally once its `expires_at` has passed; never ask for the screen lock for a request
  that is no longer open. (The Vivo asked for its PIN for a lapsed request and then got 404.)
- **Access-token renewal** (`ab04822`). Access tokens live ten minutes. Before a call that will ask for
  the screen lock, renew with a bound refresh if the token expires within 30 s (read `exp` for timing
  only); on 401 `expired_token`, renew once and retry. (The Huawei's approvals list answered
  `expired_token` after ten idle minutes.)
- **A saved session at start** (`ea00d0d`). Refresh it once before showing anything from it. On a 401
  (`unknown_refresh_session`, `refresh_session_expired`, `refresh_binding_mismatch`, `invalid_token`,
  `expired_token`) discard it and the risk decision stored with it; on anything else (network, 5xx, 403
  `risk_policy_blocked`) keep it. After a server-side reset the app had shown the old server's decision
  as current. Each app start then costs one refresh and one risk evaluation.
- **The approver is judged too.** Approving runs a relationship evaluation (`approval_grant`) on the
  approving phone. Under the owner's defaults, a phone first seen today with two accounts, approving the
  account's second device, scores 80 and gets 403 `risk_review_required` (seen on the Vivo). Show the
  code; it is policy, not a fault.

Still open from earlier sections: §10's full-session profiling in the `baseline` command, and §11's
client work, which the points above complete.

## 15. Added 2026-10-13 — a newer approval request replaces the same phone's pending ones

DESIGN.md §75, `c6a79c2`, **schema 14** (migration 014, `session_upgrade_requests.superseded_at`). Server,
with a small client change:

- `POST /v1/auth/upgrade/request` may return `"superseded": <n>`, the number of this installation's
  pending requests for the account that it replaced.
- The approving phone's `GET /v1/auth/approvals` lists one request per requesting phone. Approving or
  denying a replaced request answers **409 `approval_superseded`**: refresh the list and offer the newer
  one.
- `approval_not_granted` gains `details.state` = **`superseded`**, a terminal state: stop waiting; the
  newer request is the live one.
- Unchanged: the per-account budget counts every request raised; another phone's or another account's
  requests are never touched; an approval granted before the phone asked again stays usable once.
- The reference suite has 73 checks (new: `check_upgrade_request_supersedes`).

## 16. Added 2026-10-13 — the app's own recompiled code (one collector change requested)

DESIGN.md §75, `4a6f75e`. A false positive found on the Huawei: Android recompiles an app in the
background after an install or update, and the running process keeps the replaced
`…/oat/<isa>/base.odex` mapped as executable and `(deleted)`. That scored `android_deleted_code_mapping`
+55 (elevated) until the app restarted, and a new account was refused.

- **Requested** in `AndroidIntegrityCollector.ProbeExecMappings`: count a deleted, non-JIT executable
  mapping as **`deleted_exec_own_code`** (a new field) when its path, without ` (deleted)`, starts with
  `<parent folder of ApplicationInfo.SourceDir>/oat/` and ends in `.odex`, `.vdex`, `.art` or `.oat`.
  Everything else stays in `deleted_exec_mappings`. Do not exempt `base.apk` or anything outside `oat/`.
  The method is static today, so it needs the source folder passed in.
- The server records `deleted_exec_own_code` as `android_app_code_recompiled` at 0 points. Until your
  collector sends the field, the same event keeps scoring +55. The server cannot classify from
  `samples`: they are cut at 160 characters, which drops the ` (deleted)` suffix and can cut the path.
- To reproduce: `adb shell cmd package compile -m speed -f <package>` while the app is running, then
  scan.

## 17. Added 2026-10-13 — SQL Server notes (no protocol change)

- The server code since §8 has run on SQL Server 2022 Express on RDS, with the same suite results as on
  PostgreSQL (DESIGN.md §74).
- **Finding, not yet fixed in the Python dialect.** The schema's IDs are `char(36) COLLATE
  Latin1_General_BIN2`. A Unicode parameter (pyodbc `str`; SqlClient `string` with `AddWithValue`) makes
  SQL Server convert the column side, so an index lookup becomes a dynamic seek plus a sort that needs a
  memory grant. If you ever write a .NET data layer for this schema, declare ID parameters as
  `SqlDbType.Char` or `VarChar` with length 36 (Dapper: `DbString { IsAnsi = true, Length = 36 }`; EF
  Core: `IsUnicode(false)` and `HasColumnType("char(36)")`).
- Test-stack sizing: on db.t3.micro SQL Server got 3 MB of query workspace; Amazon's own consistency
  checks held the grant queue and statements timed out (`HYT00` after `DB_QUERY_TIMEOUT`, 15 s). Use
  db.t3.small (2 GB) or larger for SQL Server tests.

## 18. Added 2026-10-13 — the critical review: what the SDK must do

DESIGN.md §76, schema **17** (migrations 015–017). The server side is done and green on PostgreSQL
(suite 72/0/4 with integrity enforce and routes 1–3; 61/0/15 observe); SQL Server pending. For the SDK:

- **Sign out on the server.** `POST /v1/auth/logout` (access token + access proof, body `{}`) before
  dropping tokens; it revokes the family and its acceptances. Afterwards every access token of the
  family answers **401 `session_revoked`** — treat it like an unknown session (discard, sign in).
- **409 `relationship_changed`** at login or registration: another sign-in linked the same phone or
  account meanwhile and nothing was written; ask once more.
- **Approvals accept exactly what was approved.** The upgrade response adds `acceptance_id`. Handle
  **403 `complete_scan_required`** (at request or upgrade: the cause is collection problems only —
  scan again, and the session upgrades by itself) and **409 `upgrade_scope_changed`** (something new
  since the request — ask again). The approvals listing adds `limited_causes` and `reasons`
  (`code`, `points`, `message`, `source`): show them to the approving user; approving accepts exactly
  those. A route-3 request returns the same `reasons` for your backend to show.
- **Evidence contract 3 for your Android collector** (the server labels lower versions `legacy`:
  scored as before, never `complete`, refused on `complete_evidence_paths`):
  - send `collector_version` 3 once the following hold;
  - `runtime_maps` and `exec_mappings` carry `maps_lines` (lines read) and answer `status: error`
    when `/proc/self/maps` cannot be read or returns nothing — never `ok` with empty lists;
  - `instrumentation_threads` answers `status: error` when no thread could be enumerated;
  - `exec_mappings` carries `deleted_exec_own_code` (§16 above) as an integer — the field is typed
    now: a string makes the report malformed (400);
  - `code_integrity` with `checked: true` carries `<bucket>_expected_bytes` for core, ext and app;
  - figures must agree: zero `wx_mappings` with sizes listed, or coverage that does not add up, is
    `invalid` (+30).
- **Evidence quality** is in every report response and integrity state: `complete`, `partial`,
  `legacy`, `incomplete`, `invalid`; `finding_score` is the score without collection problems.
  Collection problems now add +30 once (`integrity_evidence_incomplete`), never per probe.
- **Sensitive operations.** On the DBA's `complete_evidence_paths` the server answers **403
  `integrity_complete_evidence_required`** unless the latest scan is `complete` and fresh: scan right
  before such an operation.
- **The business API is not the SDK's.** `/v1/business/*` is server to server, called by the
  customer's backend with its own bearer token.

The reference suite has **76** checks (new: logout, parallel sign-ins, business API, the contract-3
fixture — its "elevated" fixture is now test-keys + no boot state, since a failed probe can no longer be
approved); the offline gate **72**.

## 19. Added 2026-10-13 (later) — after your catch-up to §75

Read against your `1d212da` (DESIGN.md refreshed to §75; `docs/validation.md` §9, offline only). Your
`f3604dc`, `2c72c18` and `08f52b1` already cover most of §10–§16: limited sessions with the automatic
wait, supersede, lapsed requests dropped, token renewal before a prompt, the saved-session check at
start, eligibility remedies, `deleted_exec_own_code`, read failures as probe errors, full coverage
figures, and `baseline --session`. Today's reference work is DESIGN.md **§76** (pull it with §75) and
schema **18** (migrations 015–018). What it needs from you, checked against your code:

**Breaks your conformance port — fix first.** `LimitedSessionConformanceChecks.Elevate()` (and the
step-up check's scenario) makes the `mounts` probe fail. A failed probe is now a collection problem,
which can never be approved: requesting an approval, or a route-1 upgrade, for a cause made only of
collection problems answers **403 `complete_scan_required`**. The reference suite's fixture is now two
mild findings an approval can accept — `root_files.test_keys = true` (+25) and no
`ro.boot.verifiedbootstate` / `ro.boot.flash.locked` / `ro.boot.vbmeta.device_state` in
`system_properties` (+15): 40, elevated (`conformance_suite._elevate`). Your approver-view assertion
(`requesting_installation` holds exactly three keys) still holds: the listing's new `limited_causes`
and `reasons` sit beside it, not inside.

**Still to do in the SDK** (none found in `src/`):
- `POST /v1/auth/logout` before dropping a session; **401 `session_revoked`** afterwards → discard.
- **409 `relationship_changed`** at login or registration → ask once more.
- **403 `complete_scan_required`** (request or upgrade) → scan; the session then upgrades by recheck.
  **409 `upgrade_scope_changed`** (something new since the request) → ask again.
- The approvals listing's `limited_causes` and `reasons` (`code`, `points`, `message`, `source`): show
  them to the approving user — approving accepts exactly those. The upgrade response adds
  `acceptance_id`.
- Android collector **3**: `maps_lines` in `runtime_maps` and `exec_mappings`; `status: error` when
  `/proc/self/maps` returns no lines and when no thread could be enumerated (you already fail on an
  unreadable file); then `CollectorVersion` 3. Until then your reports read **`legacy`**: scored as
  before, never `complete`, refused only on a DBA's `complete_evidence_paths` (empty by default), never
  counted by the escalation.
- Read `evidence_quality` and `finding_score` from report responses and the integrity state, if your
  harness shows them.

**Server-only, nothing for you:**
- Approvals granted before 016 are carried over at their first use (`legacy_acceptances`, migration
  018, default `carry`); `drop` makes them cover nothing.
- The business API (`/v1/business/*`) is server to server; its lapse feed now pages with
  `next_cursor`.
- Acceptance records, lapses, collection-problem grouping, evidence quality, the admission recheck
  under locks.

**What exists, and what was not run, on our side.** Offline gate **72/72**. Suite **76** checks: new
since §18 are route 1 proving reason-level coverage and the lapse record live. On EC2 PostgreSQL 16.15
at schema 17: observe 61/0/15; integrity enforce with routes 1–3 72/0/4; both modes 15/15 targeted;
`tools/race_admission.py` 5 links before the fix, 2 after. **Not run:** migration 018 and the
carry-over on any database (gate only); anything from 015 on against SQL Server; collector 3 on a
handset; an iPhone round. Your `validation.md` §"Not covered" can point here for the server side.

## 20. Added 2026-10-14 — the server's own observations (DESIGN.md §77, schema 19)

Server-side; **nothing is required of the SDK** while the DBA leaves `cross_checks_enabled` at its
default, 0. Pull DESIGN.md §77 and migration 019. What you may see, and what to tolerate:

- **Decision `context`** gains `server_observations` (counts of what the server itself saw: wrong
  passwords, sign-ins to unknown accounts, failed step-up proofs, denied approval requests, exhausted
  approval budgets, step-up re-enrolments — for the phone, the account, this account on this phone
  (`device_account`, which the approval-flow rules count, `e289a65`) and a `newcomer`), plus
  `held_by_denial`: when true, `recommended_action` is `review` even if the score is in the block
  band — read the action; `request_rate` (`off` / `measured` / `unavailable`); and, when this
  request's rate limiter could not run, `rate_limiter: "unavailable"`. Read them if your harness shows
  the context; never require them.
- **Relationship reasons may carry `count`.** With cross-checks enabled, seven codes can appear —
  `account_sign_in_failures_elsewhere`, `device_sign_in_failures_many_accounts`,
  `device_sign_in_unknown_accounts`, `device_stepup_failures`, `device_approvals_denied`,
  `device_approval_budget_exhausted`, `device_stepup_reenrolments` — each with `count`. Your reason
  model must accept the extra key. They reach the approver through the existing listing (`code`,
  `points`, `message`, `source`); the message states the count.
- **`request_rate_unavailable` at 0 points** appears whenever the DBA's request-rate rule is on and its
  counter is unreadable. Do not present a 0-point reason as a problem.
- **A denied phone stays limited** (owner decision, `0a77436`). With cross-checks on and the default
  `device_approvals_denied_effect` = `limit`, the denied phone's next sign-in answers 200 with a
  limited session, its decision lists `device_approvals_denied` (+30, `count`) and
  `context.held_by_denial` is true; it may ask again within the budget. Your route-2 port can keep its
  order (deny, then exhaust the budget) — the reference went back to it (`9f5ab0c`). Note the other
  order fails with cross-checks on: an exhausted budget adds +30 with no hold, and on a phone already
  at review that blocks (403 `risk_policy_blocked`).
- **Suite:** 78 checks — `check_server_observations` (runs in any mode: two other phones' wrong
  passwords and an unknown handle are counted in the account's decision, the guessing phone's own, and
  a phone joining afterwards, not the opener's) and `check_server_observations_scored` (skips unless
  enabled).

**Verified on our side:** offline gate 81/81; EC2 PostgreSQL 16.15 at schema 19: observe 61/0/17, both
enforce with cross-checks on 71/0/7, both enforce at the owner's defaults 70/0/8, a Redis outage
recorded as degraded and unscored, `tools/race_admission.py` PASS, and the §19 carry-over (018) now
verified live. **Not run:** migrations 015–019 against SQL Server.

## 21. Added 2026-10-14 (later) — stolen tokens recorded; the step-up method and the app PIN (DESIGN.md §77, §78, schema 20)

**The owner's default is now the app PIN** (`stepup_method` = `app_pin`, `4fff85d`): approving another
phone's request needs the approver's app PIN, so the SDK must offer setting a PIN (the account has
none until it does: `app_pin_not_set`) and send it when approving. `screen_lock` and
`screen_lock_and_app_pin` remain DBA choices. The exhausted-budget cross-check now counts budget
periods and fires at 2 (`b90ad27`). What a deployment can turn on, and what the SDK needs for it:

- **The app PIN.** `POST /v1/account/app-pin` `{"password", "pin"}` with a full session sets or replaces it
  (`invalid_app_pin` 400 for a wrong format; `invalid_credentials` 401). Send it as the `X-App-PIN`
  header on the request it approves — a sensitive path, approving another phone's request, a route-1
  upgrade — where the DBA's `stepup_method` (`app_pin`, `screen_lock_and_app_pin`) or
  `app_pin_required_paths` ask. Handle `app_pin_required` and `stepup_required` (403, both with
  `details.step_up.needs`), `app_pin_invalid` (403, `details.attempts_left`), `app_pin_locked` (403: offer
  "set a new PIN with your password"), `app_pin_not_set` (403). `/v1/account/me` carries `step_up`
  (method, `app_pin_set`, `app_pin_locked`, `app_pin_length`) so the UI can ask up front. Never log the
  header.
- **Approving without a step-up key** works under `app_pin`: send the PIN alone — the reference
  client's `approveUpgrade` now takes `signStepUp` as optional and an `appPin`; mirror that signature,
  and give the approver UI a PIN entry for deployments that choose `app_pin`. Route 1 is now listed in
  `upgrade_routes` when the phone can give what the method asks (a bound key and/or a set, unlocked PIN).
- **New observation kinds** in `context.server_observations`: `token_without_key` and `request_replayed`
  (once per token / per request), `app_pin_failed`, `app_pin_set`; `device_account.app_pin_failed` feeds
  a new rule, `device_app_pin_failures`. Tolerate the keys.
- **Suite:** 82 checks — `check_stolen_token_recorded`, `check_app_pin`, `check_app_pin_concurrent`,
  `check_app_pin_approval`; the six screen-lock checks skip under another method, naming why.

**Verified on our side:** gate 88/88; EC2 PostgreSQL 16.15 at schema 20: observe 62/0/20, enforce with
cross-checks 74/0/8, each method's PIN checks PASS (incl. 9 concurrent wrong PINs against a limit of 5:
exactly 5 compared). **Not run:** migrations 015–020 on SQL Server; the harness build on a phone.

## 22. Added 2026-10-14 (latest) — the step-up policy at runtime, session lifetimes, PIN support (DESIGN.md §79, schema 21)

The server requires **schema 21**. What the SDK must do:

- **Create the step-up key as the server's policy says.** `GET /v1/policy/step-up` needs no token and
  answers `method`, `factor`, `mode`, `window_seconds`, `app_pin_length`, `required_paths`,
  `app_pin_required_paths`. Read it before registering and create the key with that factor, mode and
  window. An existing key satisfies the policy when its factor matches and it is per-use, or windowed no
  longer than the policy's window (a per-use key satisfies a windowed policy). One that does not: delete
  and recreate it while the server holds no key for the installation; once one is bound, show "re-enrol
  your step-up key" (password + the new key's proof, `/v1/installations/stepup-key`) and recreate it
  there — the server refuses a key of another factor (`stepup_factor_mismatch`). Your build settings
  remain only the fallback when the server cannot be asked. The reference is
  `_prepareStepUpKey` / `StepUpPolicy` in `lib/device_trust_client.dart` (`5e269c5`).
- **`/v1/account/me` `step_up`** now also carries `factor`, `mode`, `window_seconds`, `required_paths`,
  `app_pin_required_paths` and `app_pin_reset_open`. Tolerate the keys.
- **Session lifetimes are the DBA's.** A refresh token now lives `refresh_idle_days` (30 by default,
  1–90), and a DBA may cap a session from its first sign-in (`session_max_days`): handle 401
  `session_max_age_reached` — on refresh and on requests that check the session — by signing in again,
  like `refresh_session_expired`.
- **A support reset.** Where the business enables it, its support staff can open a reset of an
  account's app PIN; then a **limited** session may `POST /v1/account/app-pin` `{"password", "pin"}`
  once. Offer "set a new PIN" in the limited-session screen; `session_limited` means no reset is open,
  `app_pin_reset_lapsed` (403) that it lapsed or was used meanwhile. The support endpoints themselves
  (`/v1/business/app-pin/unlock`, `/reset`) are server to server — not the SDK's.
- **New observation kinds and code**: `app_pin_support_unlocked`, `app_pin_support_reset` (no phone),
  and `app_pin_set_after_support_reset`. Tolerate them. Every code is now listed in `MEASUREMENTS.md`.
- **Suite:** 86 checks — `check_step_up_policy`, `check_business_integrity_reports`,
  `check_app_pin_support_unlock`, `check_app_pin_support_reset`.

**Verified on our side:** gate 97/97; EC2 PostgreSQL 16.15 at schema 21: observe 66/0/20, enforce
with support reset on 80/0/6 (the reset used once by a limited session), `session_max_age_reached` on
refresh and on a full-session request, a refresh token living `refresh_idle_days`. The Dart client's
policy reading is analysed, not yet run on a phone. **Not run:** migrations 015–021 on SQL Server.

## 23. Added 2026-10-15 — the device and network probes, optional measurements (DESIGN.md §80, schema 22)

The server requires **schema 22**. Nothing breaks for an SDK that changes nothing: the new probes are
volunteered, never planned. What the SDK should do to match the reference collectors (Android 4, iOS 3):

- **Volunteer `device` and `network` on every scan**, beside the planned probes. Android: `device` —
  `release`, `sdk_int`, `security_patch`, `manufacturer`, `brand`, `model`, `device`, `build_id`,
  `fingerprint`; `network` — `vpn_active` (any network with `TRANSPORT_VPN`), `http_proxy_configured`
  (`ConnectivityManager.getDefaultProxy()` or `http.proxyHost`), `transports`, `interfaces` (names
  only); needs `ACCESS_NETWORK_STATE`. iOS: `device` — `os_version`, `model_identifier`; `network` —
  `vpn_active` inferred from `CFNetworkCopySystemProxySettings()["__SCOPED__"]` keys starting `utun`,
  `ipsec`, `ppp`, `tun` or `tap`, `http_proxy_configured` (`HTTPEnable`, `HTTPSEnable`,
  `ProxyAutoConfigEnable`), `scoped_interfaces`. Report your collector version as 4 / 3 once you do.
  Field types are checked: a wrong type is 400 `invalid_integrity_probe`.
- **Read `optional_probes`** in the challenge (absent before schema 22). For each name your app's
  configuration enables, add the measurement; for every other one, `{"status": "not_enabled"}`. Today
  only `local_addresses`: `{"status": "ok", "addresses": [{"interface", "address"}, ...]}`, link-local
  left out. Expose it as an SDK option, off by default.
- **New reason codes** at 0 points, and a new eligibility refusal: `android_vpn_active`,
  `ios_vpn_active`, `android_http_proxy`, `ios_http_proxy`; 403 `integrity_device_ineligible` where the
  DBA sets `vpn_active_refuses` or `http_proxy_refuses` — show `details.eligibility[].remedy`.
- **User-Agent**: the server can record it (`record_user_agent`); send a meaningful one.
- **No MAC address, no IMEI**: the owner dropped both (2026-10-15). Do not collect them.
- **Suite:** 89 checks — `check_network_probe`, `check_optional_measurements`, `check_request_metadata`;
  every suite report now carries the two probes as collector 4 / 3 would.

**Verified on our side** (DESIGN.md §80): gate 101/101; EC2 PostgreSQL 16.15 at schema 22, observe
69/0/20, enforce with every new setting on 83/0/6, the VPN eligibility rule refusing and clearing
live. The Kotlin collector builds into the release APK; the Swift is not compiled yet; neither
has run on a phone.

