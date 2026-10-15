# Integration guide

For the engineers, DBAs and security reviewers who put this device-trust server and its client SDKs
into their own stack. `DESIGN.md` is the full design and test record; this guide is what you must
decide and configure. The Flutter app in this repository is a **test harness**, not a product: your
app embeds an SDK (Flutter/Dart, .NET, Python) and your deployment owns every secret and signing key.

## 1. What it gives you, and what it does not

The server recognises a device across reinstalls, authenticates each installation with a
non-exportable key, makes copied tokens useless on another device, scores local integrity
measurements (root, Frida, hooking, tampering, debuggers) and relationship risk (accounts per device,
devices per account, reinstall velocity), and returns allow / step-up / review / block. **The server
owns the score**; no Google or Apple attestation service is used.

Be precise about what that proves:

- A valid signature proves possession or use of the registered key — nothing about the code that
  asked for it. A custom client can generate an ordinary key and send a well-formed clean report. On an
  enrolled device, compromise of the app *process* (not only the OS) is enough to use the installation
  key through its normal signing API.
- "Trusted" is a policy outcome on the evidence received, not a certificate of a clean device.
  Integrity reports are periodic (fresh for 10 minutes), not continuous.
- Keep account authorisation, transaction limits and recovery enforced by your own business server.
  Treat this system as strong defence in depth and a risk input.
- No platform attestation is used — not Google's or Apple's verdict services, and not local
  verification of Android key-attestation chains. So a fully synthetic client (a script or emulator
  that invents a clean report and signs it with its own key) looks like a genuine phone. Catching those,
  and fraud farms in general, is a job for **velocity measured on things a client cannot mint for
  free**: source networks and address ranges, the rate of new accounts across your whole service,
  timing and behaviour, and business data (identity checks, payment instruments). This server's device
  counts (accounts per device, reinstall velocity) key on installation keys and reinstall hints, which a
  farm can regenerate for every account, so they will not catch it on their own.

## 2. The root secret — `DEVICE_ID_MASTER_SECRET`

One high-entropy secret, set as `DEVICE_ID_MASTER_SECRET` (or in the file named by
`DEVICE_ID_MASTER_SECRET_FILE`, default `jwtkey.txt`). The server refuses to start with fewer than 32
bytes. Three keys are derived from it:

| derived key | protects |
|---|---|
| token signing key | every device, access and refresh token |
| reinstall-hint pepper | the stored HMAC of each device's ANDROID_ID / IDFV hash — how a reinstall is recognised |
| account-lookup pepper | the stored HMAC of each account handle — how a login finds its account |

**Generate it once** with a cryptographic random generator (for example `openssl rand -base64 48`),
keep it in your secret manager, give it only to the server processes, never commit or log it.

**Changing it is not a rotation.** The server has no versioned rotation today. After a change:
every issued token stops verifying (users sign in again — tolerable); **every stored reinstall hint
and account lookup stops matching** — devices are no longer recognised across reinstalls and logins
by handle no longer find their accounts. Treat a leaked secret as an incident that needs a planned
data migration, not an environment-variable edit. Choosing, storing and protecting it is yours.

## 3. Your app's signing identity

The server can pin what it expects the app to be. Pin your **production** values, never a debug build's.

**Android**

- `INTEGRITY_ANDROID_PACKAGE` — your package name.
- `INTEGRITY_ANDROID_CERT_SHA256` — the SHA-256 of the certificate that signs the APK **as installed on
  the phone**. With Google Play App Signing that is **Google's app-signing certificate** (Play Console →
  App integrity), not your upload key. Comma-separate several (for example during a key upgrade).
  A mismatch is a hard block.
- `INTEGRITY_ANDROID_APK_SHA256` (optional) — exact build hashes; each release needs its entry.
- Changing the signing key changes **ANDROID_ID** for your app on Android 8+ (it is scoped to signing
  key, user and device), so every device's reinstall hint changes once and devices appear new.

**iOS**

- `INTEGRITY_IOS_BUNDLE_ID`, `INTEGRITY_IOS_TEAM_ID`, `INTEGRITY_IOS_SIGNING_ID`; optionally
  `INTEGRITY_IOS_EXECUTABLE_SHA256` per build.
- The fake-signature rules (`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`) and the iOS app-code comparison
  (`INTEGRITY_SCORE_IOS_CODE_INTEGRITY`) ship report-only. Enable them only after your App Store or
  TestFlight build has been observed clean on your own server.
- IDFV changes when every app from your vendor ID is removed and one is reinstalled; such a reinstall
  is a new device.

**.NET on Android** maps writable-and-executable (W^X) memory by design, and keeps generating code as a
session warms. Pin each build's envelope in
`INTEGRITY_ANDROID_WX_BASELINES=<apk_sha256>:<bytes>:<granularity>`; every new build needs its own
entry, and a build without one scores +60.

- **Pin the largest W^X total the build reaches over full sessions on your own clean test phones,** not
  the first scan's figure: install, first scan, login, registration, refresh, step-up, background and
  resume, repeated scans, a long session. When this was written the .NET SDK's `baseline` command
  measured the first scan after four cold starts (which must agree); until it profiles a session, run
  the release build through representative sessions on controlled phones against a test server in
  observe mode, and pin the largest value those scans report. Never derive the pin from production
  data: a compromised session's memory would become the allowance.

  ```sql
  -- PostgreSQL; on SQL Server use JSON_VALUE(probe_results, '$.exec_mappings.wx_bytes').
  SELECT probe_results->'app_identity'->>'apk_sha256' AS apk_sha256,
         MAX((probe_results->'exec_mappings'->>'wx_bytes')::bigint) AS largest_wx_bytes,
         COUNT(*) AS scans
  FROM integrity_reports
  WHERE platform = 'android' AND probe_results->'exec_mappings' ? 'wx_bytes'
  GROUP BY 1;
  ```
- Growth above the pin up to `wx_far_above_baseline_percent` (section 5; default 200, twice the pin)
  is expected runtime growth: recorded as `android_wx_above_baseline` at 0 points. Beyond it,
  `android_wx_far_above_baseline` scores +40 (elevated) on its own. Allocation sizes the runtime never
  produces still score +45 whatever the total.
- What the size rule cannot do: code injected in the runtime's own allocation sizes, inside the
  allowance, looks exactly like normal growth. Hooks in existing code are caught by the code comparison
  (+90), odd allocation sizes by the shape rule; the rest falls to your server-side controls.

## 4. Deploying the server

**Process model.** Run worker processes, not threads, behind a WSGI server, for example
`gunicorn --workers 4 --bind 127.0.0.1:5000 device_trust_server:app`. The SQL Server ODBC stack is not
thread-safe. Per-process connection pool: `DB_POOL_SIZE` (4), `DB_POOL_RECHECK_SECONDS` (30); SQL Server
statement timeout `DB_QUERY_TIMEOUT` (15 s).

**Transport.**

- Terminate TLS at your proxy and bind the server to a private address only.
- `REQUIRE_HTTPS=1` refuses plain HTTP with 426. Behind a proxy set **`TRUSTED_PROXY_COUNT`** to the
  number of proxies that *replace* `X-Forwarded-For`/`X-Forwarded-Proto` (1 for a single nginx/Caddy);
  otherwise every request is 426, and per-source rate limits see only the proxy's address. A forwarded
  header from anything else is never trusted.
- `MAX_REQUEST_BYTES` (256 KiB) refuses larger bodies with 413.
- The Flutter client's release builds refuse a non-`https://` endpoint and its Android manifest refuses
  cleartext; require the same of every client build you ship.

**Database.** PostgreSQL 13+ or SQL Server 2017+ (`DB_ENGINE`). Your DBA applies
`migrations/<engine>/001…019` in order; the server only reads `schema_migrations` and refuses to serve
on any other version (`/health/ready` says why). Use verified TLS: PostgreSQL `DB_SSLMODE=verify-full`
with `DB_SSLROOTCERT`; SQL Server always connects with `Encrypt=yes` and `TrustServerCertificate=no`.

**Grant the application principal no DDL, and DELETE only where it needs it.** The server deletes
rows from exactly three tables — `access_proof_nonces`, `installation_challenges`,
`integrity_challenges` (expired, ephemeral rows) — and never from anything that records a relationship
or a verdict. Grant `DELETE` on those three only; `SELECT, INSERT, UPDATE` on the other operational
tables; only `SELECT` on `schema_migrations` and `risk_policy_settings`, which the server never writes.
That makes the rule in section 5 hold at the database too.

**Replay store and rate limits.** Nonces default to the database (`NONCE_BACKEND=database`). Redis
(`REDIS_URL`, `NONCE_BACKEND=redis`) is faster but needs `appendonly yes`; the nonce store fails closed.
Rate limiting is opt-in (`RATE_LIMIT_ENABLED=1`, needs Redis) and fails open: per identity
(`RATE_LIMIT_MAX_ATTEMPTS`, 20 per `RATE_LIMIT_WINDOW_SECONDS`, 60) for installations, account handles
and accounts, and per source address (`RATE_LIMIT_SOURCE_MAX_ATTEMPTS`, 120) on registration,
challenge, verify, account registration and login. Put admission limits at your edge as well.

**Health.** `/health/live` is liveness. `/health/ready` answers 200 only when the database, schema,
policy snapshot and (if used) Redis nonce store are all usable, and 503 `not_ready` naming the problems
otherwise.

**Modes.** Start with `INTEGRITY_MODE=observe` and `DEVICE_POLICY_MODE=observe`: every decision is
computed, stored and returned, nothing is refused (administrative revocation always is). Move to
`enforce` per mode once your observed false-refusal rate is acceptable. `INTEGRITY_ALLOW_DEBUG`,
`INTEGRITY_ALLOW_EMULATOR` and `INTEGRITY_ALLOW_USERDEBUG` are lab switches: keep them `0` in production.

**Protocol versions.** Access proof v2 and step-up proof v2 sign the whole request, query string
included. `ACCESS_PROOF_MIN_VERSION` (default 2) may be set to 1 while older clients move; even then a
v1 proof is refused on any request with a query string. Step-up proofs must be v2.

## 5. The risk policy is your DBA's

Policy values live in `risk_policy_settings`, seeded by the migrations with the product owner's
defaults and changed by your DBA, never by the server. Every setting follows, generated from the
migrations by `tools/settings_reference.py`; the gate fails when this list and the migrations
differ, or when the PostgreSQL and SQL Server migrations seed different rows. A count of `0`
switches its rule off; the server holds a value to the bounds its description states.

<!-- settings-reference:begin (tools/settings_reference.py --write; do not edit by hand) -->
94 settings, seeded by migrations 003-022 with the owner's defaults; each row's own description.

**Migration 003** — DBA-tunable risk policy settings

| Setting | Default | What it decides |
|---|---|---|
| `stepup_mode` | `per_use` | Step-up mode for sensitive ops: per_use (a) or windowed (b). |
| `stepup_window_seconds` | `0` | Hardware-enforced reuse window for windowed step-up; 0 = per-use. |
| `stepup_factor` | `passcode` | Required device auth factor: passcode or biometric. |
| `stepup_required_paths` | *(empty)* | Comma-separated request paths requiring a valid step-up proof (empty = none). |
| `rate_anomaly_enabled` | `0` | Enable per-key request-rate anomaly signal (advisory). |
| `rate_anomaly_max_requests` | `120` | Requests per key per window before the signal trips. |
| `rate_anomaly_window_seconds` | `60` | Window length for the request-rate anomaly signal. |
| `rate_anomaly_points` | `30` | Advisory risk points added when the rate signal trips. |
| `population_baseline_enabled` | `0` | Enable population-baseline deviation signal (advisory). |
| `population_baseline_metric` | `accounts_per_device` | Relationship metric to threshold: accounts_per_device or installations_per_device. |
| `population_baseline_threshold` | `10` | Advisory when the chosen metric exceeds this consumer-set base. |
| `population_points` | `30` | Advisory risk points added when the population signal trips. |

**Migration 006** — DBA-tunable accounts-per-device policy

| Setting | Default | What it decides |
|---|---|---|
| `device_accounts_elevated_count` | `2` | Accounts on one device that raise the score (elevated band). |
| `device_accounts_elevated_points` | `35` | Risk points at the elevated account count. |
| `device_accounts_review_count` | `3` | Accounts on one device that are held for review. |
| `device_accounts_review_points` | `60` | Risk points at the review account count. |
| `device_accounts_block_count` | `4` | Accounts on one device that are blocked outright. |
| `elevated_risk_refuses` | `0` | In enforce mode, 1 = an elevated (step-up band) decision refuses the request; 0 = recorded, not refused. |

**Migration 010** — DBA-tunable W^X growth allowance and eligibility rules

| Setting | Default | What it decides |
|---|---|---|
| `wx_far_above_baseline_percent` | `200` | W^X memory above this percentage of the build's pinned baseline scores +40 (android_wx_far_above_baseline); between the baseline and this percentage it is expected runtime growth, advisory. 200 = twice the baseline. Minimum 100. |
| `developer_options_refuses` | `0` | Eligibility rule. 1 = in enforce mode an installation whose latest scan reports Developer options on is refused (integrity_device_ineligible) until they are off and a new scan is sent; 0 = advisory only. |
| `adb_enabled_refuses` | `0` | Eligibility rule. 1 = in enforce mode an installation whose latest scan reports USB debugging (ADB) on is refused (integrity_device_ineligible) until it is off and a new scan is sent; 0 = advisory only. |

**Migration 011** — limited sessions and their upgrade

| Setting | Default | What it decides |
|---|---|---|
| `limited_session_paths` | *(empty)* | Paths a limited session may reach besides the upgrade endpoints and the integrity scan, comma-separated. Empty: nothing else. |
| `limited_session_integrity_verdicts` | `elevated` | Integrity verdicts that give a limited session instead of a 403 at login, registration and refresh (enforce mode): elevated and/or review. Empty: they refuse. A block always refuses. |
| `limited_session_policy_actions` | `step_up,review` | Relationship outcomes that give a limited session instead of a 403 (enforce mode): step_up (refused only with elevated_risk_refuses=1) and/or review. Empty: they refuse. A block always refuses. |
| `upgrade_stepup_same_device` | `0` | 1 = a limited session may upgrade with a step-up proof from the same phone, only when every cause is integrity-related. Proves the screen lock, not who the user is. |
| `upgrade_other_device_approval` | `1` | 1 = a limited session may upgrade with an approval signed, with step-up, by another installation of the same account that holds a full session. |
| `upgrade_mfa_assertion` | `0` | 1 = a limited session may upgrade with an ES256 assertion signed by your identity backend (keys in UPGRADE_ASSERTION_JWKS_FILE). As strong as your MFA. |
| `upgrade_request_ttl_seconds` | `300` | Seconds an upgrade request (an approval request or an assertion nonce) stays valid. Minimum 30. |
| `upgrade_approvals_per_hour` | `3` | Approval requests one account may raise per hour, against prompt fatigue. 0 = none. |

**Migration 012** — DBA-tunable relationship-risk bands and devices-per-account policy

| Setting | Default | What it decides |
|---|---|---|
| `policy_step_up_score` | `30` | Relationship-risk score from which a decision is step_up (recorded, allowed unless elevated_risk_refuses=1). Must be below policy_review_score. |
| `policy_review_score` | `60` | Relationship-risk score from which a decision is review (refused in enforce mode, or a limited session where listed). Must be below policy_block_score. |
| `policy_block_score` | `90` | Relationship-risk score from which a decision is block (always refused). |
| `account_devices_elevated_count` | `2` | Devices one account may use before its decisions are raised (elevated band). 0 = off. |
| `account_devices_elevated_points` | `35` | Risk points at the elevated devices-per-account count. |
| `account_devices_review_count` | `3` | Devices one account may use before its decisions are held for review. 0 = off. |
| `account_devices_review_points` | `60` | Risk points at the review devices-per-account count. |
| `account_devices_block_count` | `5` | Devices one account may use before it is blocked. 0 = off. |

**Migration 013** — an upgrade's acceptance, kept with the session

| Setting | Default | What it decides |
|---|---|---|
| `upgrade_acceptance_hours` | `720` | Hours an upgrade keeps accepting the soft causes its proof covered (never past the 30-day refresh lifetime). 0 = none: protected requests and refreshes judge them again. |

**Migration 015** — evidence quality kept apart from findings

| Setting | Default | What it decides |
|---|---|---|
| `collection_problems_block` | `0` | 1 = each failed or incomplete probe adds +30, three make a block, and that block is remembered for the device (every account on the phone) like a finding. 0 (owner default) = collection problems add +30 once and never enter the device memory. |
| `integrity_device_memory_hours` | `24` | Hours a blocked finding stays with the physical device across reinstalls. 0 = off. |
| `complete_evidence_paths` | *(empty)* | Paths that need a fresh, complete integrity scan (no failed, incomplete, contradictory or legacy evidence), comma-separated. Empty: none. |
| `complete_evidence_max_age_seconds` | `600` | How fresh that scan must be on complete_evidence_paths, in seconds. Minimum 30. |
| `incomplete_evidence_review_after` | `3` | Consecutive incomplete or invalid scans of one installation, with no complete scan between them, that escalate the verdict to review. 0 = off. Legacy collectors never count. |

**Migration 016** — an upgrade accepts exactly what was approved

| Setting | Default | What it decides |
|---|---|---|
| `acceptance_auto_cover_reasons` | *(empty)* | Reason codes an approved session accepts automatically even if they appear after the approval, comma-separated. A business decision; empty (owner default) = every new reason needs a new decision. Collection problems are never covered. |

**Migration 017** — business events, combined with the phone-account graph

| Setting | Default | What it decides |
|---|---|---|
| `business_event_types` | *(empty)* | Business event types the server accepts, comma-separated. Empty: any well-formed type (a-z, 0-9, _). |
| `business_graph_depth` | `2` | Hops the phone-account graph API follows from its starting account or phone (account to phones is one hop). 1-4. |
| `business_graph_max_nodes` | `200` | Most accounts and phones the graph API returns; a larger component is cut and marked truncated. |

**Migration 018** — approvals granted before migration 016 are carried over

| Setting | Default | What it decides |
|---|---|---|
| `legacy_acceptances` | `carry` | Approvals granted before migration 016: carry (owner default) = keep each as what it covers at its first use, until its expiry; drop = they cover nothing and their users re-confirm. |

**Migration 019** — the server's own observations, measured into every decision

| Setting | Default | What it decides |
|---|---|---|
| `cross_checks_enabled` | `0` | Score the server's own observations with the rules below (DESIGN.md 77). 0 (owner default: observe first) = counted into every decision's context, scored nowhere; 1 = each rule adds its points once its count is reached. |
| `cross_check_window_hours` | `24` | Hours the server's observations are counted over, for the context and every rule below. |
| `account_sign_in_failures_elsewhere_count` | `5` | Wrong-password sign-ins to the account from OTHER phones in the window before a phone joined it. Judges only a phone joining now or within the window, never one there before them; a user mistyping on their own phone is not counted. |
| `account_sign_in_failures_elsewhere_points` | `30` | Points for account_sign_in_failures_elsewhere. |
| `device_sign_in_failures_many_accounts_count` | `3` | Different accounts with a wrong-password sign-in from this phone in the window. |
| `device_sign_in_failures_many_accounts_points` | `60` | Points for device_sign_in_failures_many_accounts. |
| `device_sign_in_unknown_accounts_count` | `5` | Sign-ins from this phone to accounts that do not exist, in the window. |
| `device_sign_in_unknown_accounts_points` | `30` | Points for device_sign_in_unknown_accounts. |
| `device_stepup_failures_count` | `3` | Step-up (screen-lock) proofs from this phone that did not verify, in the window. A request sent without a proof is not one. |
| `device_stepup_failures_points` | `30` | Points for device_stepup_failures. |
| `device_approvals_denied_count` | `1` | Approval requests from this phone for one account that the account's other phone denied, in the window. Another account on the same phone is not affected. |
| `device_approvals_denied_points` | `30` | Points for device_approvals_denied. |
| `device_approvals_denied_effect` | `limit` | limit (owner default) = a denied phone is held at review, a limited session, for the window, and a denial alone never blocks it; points = its points are added like any rule's, and can reach block. |
| `device_approval_budget_exhausted_count` | `2` | Budget periods in which this phone found one account's hourly approval budget spent, in the window: counted once per period however often it asked, so one impatient hour is one. |
| `device_approval_budget_exhausted_points` | `30` | Points for device_approval_budget_exhausted. |
| `device_stepup_reenrolments_count` | `2` | Step-up keys one account re-enrolled on this phone in the window (after a screen-lock change each user of a shared phone re-enrols once). |
| `device_stepup_reenrolments_points` | `30` | Points for device_stepup_reenrolments. |

**Migration 020** — an app PIN the server checks, beside the screen-lock key

| Setting | Default | What it decides |
|---|---|---|
| `stepup_method` | `app_pin` | How a step-up is proven wherever one is required (the step-up paths, approving another phone, the same-phone upgrade, an elevated scan): app_pin (owner default, checked by the server), screen_lock or screen_lock_and_app_pin. |
| `app_pin_required_paths` | *(empty)* | Paths that need the app PIN in addition to anything else, comma-separated (for example payee changes, large transfers). Empty: none. |
| `app_pin_length` | `6` | Digits in an app PIN, 4-12. |
| `app_pin_max_failures` | `5` | Wrong app PINs in a row before the PIN locks; the user then sets a new one with the account password. At least 1. |
| `device_app_pin_failures_count` | `3` | Wrong app PINs for one account from this phone in the window (DESIGN.md 77). |
| `device_app_pin_failures_points` | `30` | Points for device_app_pin_failures. |

**Migration 021** — the rest of the policy in the DBA's hands; session lifetimes; support unlock and reset of an app PIN; the integrity-report feed

| Setting | Default | What it decides |
|---|---|---|
| `new_device_points` | `10` | Points for a phone first seen less than new_device_hours ago. 0 switches the rule off. |
| `new_device_hours` | `24` | How long a newly recognized phone counts as new. |
| `known_device_new_installation_points` | `15` | Points for a new installation correlated to a phone already recognized (a reinstall). 0 switches the rule off. |
| `reinstall_window_hours` | `24` | Hours over which proven reinstalls on one phone are counted. |
| `reinstall_elevated_count` | `3` | Reinstalls in the window that add reinstall_elevated_points. 0 switches the rule off. |
| `reinstall_elevated_points` | `35` | Points at reinstall_elevated_count. |
| `reinstall_high_count` | `4` | Reinstalls in the window that add reinstall_high_points. 0 switches the rule off. |
| `reinstall_high_points` | `60` | Points at reinstall_high_count. |
| `reinstall_block_count` | `5` | Reinstalls in the window that block the phone. 0 switches the rule off. |
| `integrity_report_missing_points` | `40` | Points when an installation has never sent a signed integrity scan. |
| `integrity_report_stale_points` | `35` | Points when the latest scan is older than integrity_freshness_seconds. |
| `integrity_freshness_seconds` | `600` | How old the latest integrity scan may be and still count as fresh. |
| `device_integrity_history_block_points` | `50` | Points when another installation on the same phone was blocked by integrity within integrity_device_memory_hours. |
| `hardware_backing_policy` | `off` | off, advisory or required: how a software-backed installation key is scored (it is only ever the phone's claim). This one adds integrity points. |
| `refresh_idle_days` | `30` | A session ends after this many days without a refresh; each refresh extends it (owner default 30). 1-90. |
| `session_max_days` | `0` | A session ends this many days after its first sign-in, however often it refreshes. 0 = no limit (owner default). Up to 365. |
| `app_pin_support` | `off` | What support staff may do to a customer's app PIN through the business API, after verifying the customer: off, unlock, or unlock_and_reset. |
| `app_pin_support_reset_minutes` | `15` | After a support reset, minutes within which the customer may set a new PIN, once, even from a limited session, with the password. |

**Migration 022** — the network probe's eligibility rules, optional measurements, and request metadata

| Setting | Default | What it decides |
|---|---|---|
| `vpn_active_refuses` | `0` | Eligibility rule: 1 refuses a phone whose latest scan reports a VPN active (android_vpn_active, ios_vpn_active), with its own code and remedy; 0 (owner default) = recorded at 0 points. A phone whose app predates the network probe reports none. |
| `http_proxy_refuses` | `0` | Eligibility rule: 1 refuses a phone whose latest scan reports an HTTP proxy configured (android_http_proxy, ios_http_proxy); 0 (owner default) = recorded at 0 points. |
| `optional_measurements` | *(empty)* | Optional measurements the server asks each scan for, comma-separated: local_addresses = the phone's own IP addresses. Empty (owner default) = none. Sent only if the app enables it too; anything not listed is dropped, never stored. |
| `record_source_ip` | `0` | 1 = keep the IP address each request came from in its risk decision's context (source_ip); 0 (owner default) = not kept. Personal data: kept as long as the decisions are. |
| `record_user_agent` | `0` | 1 = keep each request's User-Agent header in its risk decision's context (user_agent); 0 (owner default) = not kept. |
<!-- settings-reference:end -->

**Shared phones and several devices are a business decision.** By default a third account on one
phone, or one account on a third device, is held for review and refused in enforce mode. A business
whose users legitimately share phones (a kiosk, a field team) or carry several devices raises the
counts, or the bands, for its own deployment; a `0` count switches that rule off. The
`POLICY_*_SCORE` and `POLICY_ACCOUNT_DEVICE_BLOCK_COUNT` environment variables are only fallbacks for
a missing row.

**Developer options and USB debugging (ADB)** are measured on every Android scan and recorded
(`android_developer_options`, `android_adb_enabled`), but cost no points: they are common on legitimate
phones and are not evidence of compromise, so they must not add up with other weak signals into a
refusal. If your deployment requires them off, set `developer_options_refuses` and/or
`adb_enabled_refuses` to 1. That is an **eligibility rule**, not a score:

- In enforce mode, a request from an installation whose latest scan reports the setting on is refused
  with **403 `integrity_device_ineligible`**; `details.eligibility` names each rule broken with a remedy
  your app should show ("Turn off Developer options, then send a new integrity scan"). A new scan with
  the setting off clears it at once. In observe mode nothing is refused; the integrity state carries
  the same `eligibility` list.
- It applies from the moment the DBA sets it, to every installation's latest stored scan: users with
  the setting on are refused at their next request, so tell them before you turn it on.
- A step-up proof does not satisfy it; only the setting does.
- The phone reports the setting. A modified client can claim it is off, so this is a policy for honest
  and managed devices, not a compromise check.

The server re-reads the table every `RISK_SETTINGS_CACHE_TTL_SECONDS` (30). A value that does not parse,
or a missing `stepup_required_paths` / `stepup_factor` / `stepup_mode` row, makes the snapshot invalid:
a worker keeps its last valid one for `RISK_SETTINGS_MAX_STALE_SECONDS` (300) and then refuses
policy-dependent requests with 503 rather than run without a policy. An *empty*
`stepup_required_paths` is valid and means "step-up nowhere".

**Device-account links are permanent evidence.** The server never deletes, expires or retires a link,
and the counts above are over the device's whole history. That is deliberate: removing history is how
a fraudster's record would be laundered. If your review decides that an account held back by these
counts is legitimate, **record that decision in your own systems** — for example a reviewed-accounts
table your API layer consults when it receives `risk_review_required` or `risk_policy_blocked`, or a
DBA change to the thresholds above. Never delete or edit link rows to get the same effect. The server
has no built-in "mark safe" flag, and **nothing you record elsewhere changes its decision**: it will
keep answering `risk_review_required` or `risk_policy_blocked` (in enforce mode) for that account on
that device, so it is your API layer that must act on your review. How you mark and honour one is yours.

**Reviewing a device held back by its account count.** The counts include every account linked to the
device, whoever opened it; the server discounts none. When a device reaches review or block, look first
at accounts whose link was made from a **hint-linked installation that was never confirmed**: the
reinstall hint (a hash of ANDROID_ID or IDFV) is sent by the client, so someone who obtained the
device's hint could have linked their own installation and opened those accounts from it. Each link
records the installation that made it, and each installation how it joined the device:

```sql
-- PostgreSQL; on SQL Server prefix the tables with dbo.
SELECT l.account_id, l.first_seen_at, l.last_seen_at,
       i.installation_id, i.registration_method,
       i.created_at AS installation_created_at, i.device_confirmed_at
FROM device_account_links l
JOIN app_installations i ON i.installation_id = l.first_installation_id
WHERE l.device_id = '<device_id>'
ORDER BY l.first_seen_at;
```

- `registration_method = 'new_device'`: opened from the device's original installation.
- `'reinstall_hint'` with `device_confirmed_at` set: from a reinstall on which an account that already
  belonged to the device later signed in.
- `'reinstall_hint'` with `device_confirmed_at` NULL: from a reinstall no existing account has signed in
  on — look here first.
- Installations that existed when migration 009 ran were treated as confirmed and carry
  `device_confirmed_at = created_at`.
- A confirmation shows that someone holding an existing account's password used that installation, not
  that it is the same physical phone.

Each risk decision's `context` carries the same facts for the installation that made the request
(`registration_method`, `installation_established`, `installation_device_confirmed_at`). Record your
conclusion in your own systems as above; never edit or delete the rows.

**A blocked integrity verdict follows the device, one way.** A scan that ends in block keeps refusing
the device's installations for `INTEGRITY_DEVICE_MEMORY_HOURS` (default 24) after it, so reinstalling
the app does not clear it (`integrity_device_blocked_recently`). Only the device's **established**
installations spread a block to the others: its original installation, and reinstalls confirmed as
above. A block reported by an unconfirmed hint-linked installation refuses only that installation, so
someone holding a copied hint cannot lock the real owner out. The trade-off: a block first recorded on
an unconfirmed reinstall does not follow the device into the next reinstall; reinstall velocity still
counts every proven reinstall.

**Step-up.** The optional step-up key needs the device passcode (or biometric) for each signature.
Android 9 and 10 cannot bind a passcode to each use; there the key unlocks for a 30-second window and
the server accepts it while recording `policy_downgrade`. Decide per operation whether that is enough.
On authenticated requests a step-up proof also satisfies an `elevated` integrity verdict; login,
registration and refresh accept none.

## 6. Before you trust a deployment

- Run `conformance_suite.py --base-url https://<your endpoint>` against it — including
  `check_parallel_clients`, from inside your network so the link is not what is measured.
- Run `tools/check_security_regressions.py` after any server change; it needs no database.
- `tools/race_first_link.py` races two first logins on a real database. It leaves synthetic rows
  behind (it never deletes a link), so run it against a test database only.
- Pilot in observe mode with your release builds and measure the false-refusal rate, the share of
  reports with incomplete evidence, and scan latency before enabling enforcement.

## 7. Limited sessions: soft risk at sign-in

In enforce mode, a *soft* outcome at login, account registration or refresh no longer refuses: it
issues a **limited session** (`DESIGN.md` §67, §70). Hard outcomes refuse exactly as before — an
integrity `block` (or a `review` you have not listed), a device-memory block, an eligibility rule, a
relationship `block`, and every invalid signature, replay or revoked device. At login the integrity
checks still refuse hard outcomes before the password is compared; only a soft verdict is deferred, so
a device with soft risk learns whether a password is right, as any client does from a successful
login. Each mode applies separately (an integrity cause needs `INTEGRITY_MODE=enforce`, a relationship
cause `DEVICE_POLICY_MODE=enforce`); observe mode issues no limited sessions.

**What counts as soft** (DBA settings; `block` can never be listed):

| setting | default | meaning |
|---|---|---|
| `limited_session_integrity_verdicts` | `elevated` | integrity verdicts that give a limited session (`elevated` and/or `review`) |
| `limited_session_policy_actions` | `step_up,review` | relationship outcomes that do (`step_up` refuses at all only where `elevated_risk_refuses` is 1) |
| `limited_session_paths` | empty | what a limited session may reach besides the upgrade endpoints and the integrity scan |

Two rules, not settings, keep a limited session from costing anyone else, because device-account links
are permanent:

- **A new account under relationship risk is refused**, as before. Under a soft *integrity* verdict
  the account is created — and linked — with a limited session.
- **A first sign-in under relationship risk is refused if its link would make the phone's third
  account or the account's third device** — your review counts in section 5, or the elevated counts
  where `elevated_risk_refuses` is 1. Such a link is permanent: every account on that phone, or every
  device of that account, would be refused from then on, and anyone holding only a password could
  cause it from a fresh phone, since a phone cannot prove it is new. Within the counts — two people
  sharing a phone, a user's own second phone — the sign-in gets a limited session, and its link is
  written. Raising the counts raises these limits with them.

**What your app sees.** Login, registration and refresh responses carry `scope` (`full` or `limited`);
a limited one also carries `limited_causes` (`integrity_elevated`, `integrity_review`, `risk_step_up`,
`risk_review`) and `upgrade_routes` — the routes open to *this* user now; an empty list means none is,
so send the user to support. A limited token reaches the upgrade endpoints, the integrity scan
(`/v1/integrity/challenge`, `/report`, `/me`) and your `limited_session_paths`; anything else answers
**403 `session_limited`** with the same two lists. A refresh never widens a session, and a full session
refreshed under soft risk becomes limited.

**Upgrading.** `POST /v1/auth/upgrade` with the limited token and its access proof, body
`{"route": ...}`. The server re-runs the integrity and relationship checks first — an upgrade never
overrides a hard outcome — and issues a full session in the same refresh family; the old limited
token stays limited, and a second upgrade of the same session answers 401 `session_rotated`.

**What an upgrade accepts — exactly what was approved.** An upgrade made with a proof (routes 1–3)
while soft causes remain records an **acceptance** (`DESIGN.md` §76): the reasons behind those causes
with their points, the relationship counts seen then (accounts on the phone, devices on the account),
who approved, which scan and build. The response carries `accepted_causes`, `accepted_until` and
`acceptance_id`. Until then — `upgrade_acceptance_hours` (default 720, the refresh lifetime, never
longer; `0` keeps nothing) or until the user signs out — a protected request passes only if every
reason found now was approved: the same reason with no more points, or, for the accounts-per-phone and
devices-per-account reasons, no more than the approved counts. The outcome is then marked
`accepted_by_upgrade` with its `acceptance_id`, and the stored decision row names it. **A new reason,
more points or a higher count is not covered**, even in the same band — approved runtime growth does
not cover a debugger found later: the request is judged afresh (a step-up proof per request for an
`elevated` integrity verdict, a refusal for `review`) and the session narrows at its next refresh. A
block, an eligibility rule or a device-memory block refuses as always. An accepted `elevated` verdict
needs no step-up per ordinary request (your `stepup_required_paths` still do), and a phone approving
someone else's upgrade gets no acceptance of its own — it must be clean.

**Collection problems are never approved.** A probe that could not measure (section 8) is not a
finding anyone can vouch for: an acceptance never covers one, and a cause made of collection problems
alone cannot be requested or approved — **403 `complete_scan_required`**, before anyone is prompted.
A complete scan clears it by itself (route `recheck`).

**What the approver sees, and accepts.** An approval request records the reasons it shows; the
listing returns them (`limited_causes`, `reasons` with `code`, `points` and the server's `message`),
and your approving app must show them — approving accepts exactly those. If anything new is found
between the request and the upgrade, the upgrade answers **409 `upgrade_scope_changed`**: ask again,
so the approver sees it. An assertion request (route 3) returns the same `reasons`, for your identity
backend to show; its signature over the request ID binds them.

**Auto-cover is your business's decision, and this is the measurement it needs.** By default every
new reason after an approval needs a new decision. `acceptance_auto_cover_reasons` lists reason codes
an approved session accepts even when they appear later — for example runtime growth after an app
update, if your data shows it re-limits genuine users and never fraud. The product does not choose
these for you; collection problems can never be listed. To decide, read **when an approved session
was limited again, and by which new reason**: the first time each new reason meets an approved
session it is written to `acceptance_lapses`, and `GET /v1/business/acceptance-lapses` returns them
(section 10). Compare them with your own outcomes (re-approved, denied, fraud) before listing
anything.

- **`recheck`** (no proof): succeeds once no soft cause remains — for example after a new clean
  integrity scan. A relationship review does not clear by itself (links are permanent): once your own
  review is done, upgrade through route 3. While a cause remains: 403 `upgrade_proof_required`.
- **Route 1, `stepup`** (`upgrade_stepup_same_device`, default 0): a step-up proof v2 over the upgrade
  request itself; only when every cause is integrity-related.
- **Route 2, `approval`** (`upgrade_other_device_approval`, default 1): the limited session calls
  `POST /v1/auth/upgrade/request` with `{"route": "approval"}` and gets a `request_id`. Another
  installation of the same account, holding a current full session (its newest token), lists pending
  requests with `GET /v1/auth/approvals` and calls `POST /v1/auth/approvals/<request_id>/approve` with a
  step-up proof — or `/deny`. The limited session then sends `{"route": "approval", "request_id": ...}`;
  until the approval exists it answers 403 `approval_not_granted` with `details.state` (`pending`,
  `denied`, `expired`, `used`, `superseded`), so poll no faster than every five seconds (with rate
  limiting on, a faster poller gets 429 `rate_limited`). When the same installation asks again for the
  same account, its earlier pending requests are superseded: the approving phone lists one request per
  phone, approving or denying a superseded one answers 409 `approval_superseded`, and the old request
  reads `superseded` (stop waiting on it). Requests expire after
  `upgrade_request_ttl_seconds` (300) and are budgeted per account, `upgrade_approvals_per_hour` (3,
  then 429 `upgrade_budget_exhausted`); with no other full session to approve from, the request answers
  409 `no_approving_device`.
- **Route 3, `assertion`** (`upgrade_mfa_assertion`, default 0, and usable only once keys are
  configured): `POST /v1/auth/upgrade/request` with `{"route": "assertion"}` returns
  `assertion_claims` (`aud`, `sub`, `iid`, `rid`, `nonce`). Your backend runs its own MFA for that
  account, then signs an ES256 compact JWS: header `{"alg": "ES256", "kid": ...}`, payload = the
  claims plus `iat` and `exp` at most 600 seconds apart, optionally `amr` (recorded) and `iss`
  (required if you set `UPGRADE_ASSERTION_ISSUER`). The app sends
  `{"route": "assertion", "request_id": ..., "assertion": "<JWS>"}`; each request works once. Put your
  P-256 public keys in a JWKS file named by **`UPGRADE_ASSERTION_JWKS_FILE`** (a key without `kid` is
  addressed by its thumbprint); it is read at start, so restart after a rotation. `/health/ready` lists
  the key IDs and reports an unusable file as `upgrade_assertion_keys_invalid`.

| Route | Default | Proves | Caveats |
|---|---|---|---|
| 1. Step-up on the same phone (device passcode or biometric) | off | possession of the phone and its screen lock | It is the same phone the soft risk came from, and it proves nothing about who the user is. On Android 9 and 10 the key unlocks for a 30-second window rather than per use. It never clears relationship risk. |
| 2. Approval from another of the user's devices | on | that someone holding another installation already signed in to the account, with its own step-up, approved | Works only for users with a second phone or tablet that has your app enrolled and fully signed in — not a laptop or a browser. The approving device must show what it approves (the listing gives platform, first seen, how it joined its device), or users will approve prompts they did not cause; the server budgets the prompts. The second device sees the request when your app opens; waking it with a push notification is yours to build. |
| 3. A signed MFA assertion from your identity backend | off | whatever your MFA proves (SMS, e-mail, authenticator app) | Its strength is your MFA's: SMS codes inherit SIM-swap risk. You hold the signing key and rotate it. Short-lived and single-use. |

**Users with one device, and laptops.** With the defaults, route 2 is the only route on, and it needs a
second enrolled phone or tablet. A user with one phone stays limited until the cause clears — unless
you turn on **route 3**, the only route that covers every user. Route 3 is also how your support team
restores a user it has verified by its own means: your backend signs the assertion for that one
limited session. A laptop cannot approve through route 2 — only Android and iOS installations can
enrol here, and this server never sees your website's sessions — but it can through route 3: the user
approves on your website, and your backend signs. That is as strong as your website's own login.

**How it is enforced.** Entirely on the server; a modified app gains nothing. The limited mark is inside
the tokens the server signs and in the refresh-session row, and every request's access proof ties the
token to the phone's key. An approval is accepted only from a *different* installation, linked to the
*same account*, holding a *current full* session by its refresh row, that passes the integrity checks
(no step-up allowance) and the risk checks itself and signs with its own step-up key; the requester
cannot approve or deny itself. Approvals and assertions are bound to the requesting account,
installation and refresh family, expire, and are consumed exactly once inside the upgrade.

**Database.** Migration 011 adds `session_upgrade_requests`: every approval request and assertion
nonce and what became of it. It is audit evidence — grant the application principal `SELECT, INSERT,
UPDATE` on it, never `DELETE`.

**Before you rely on it:** list only low-value paths in `limited_session_paths`; decide per route
whether its proof is enough for your users; **turn on route 3 if users with one phone must be able to
recover**; make your app handle `scope`, `session_limited`, `upgrade_routes`, the upgrade flows,
`complete_scan_required` and `upgrade_scope_changed`, and show the approver the reasons — the Flutter
reference client does; the .NET SDK does not yet; and measure in observe mode, from the stored
decisions, how many sign-ins would have been limited.

**Database.** Migration 016 adds `session_acceptances` (grant `SELECT, INSERT, UPDATE`) and
`acceptance_lapses` (grant `SELECT, INSERT`); both are audit evidence, never deleted.

**Approvals granted before you upgrade are carried over.** They recorded only their categories, not
the reasons they approved. With `legacy_acceptances` at its default, `carry` (migration 018), the
first time such an approval is used — by a request or a refresh — the server records what it covers at
that moment and keeps that record until the approval's own expiry: your users do nothing, and their
sessions stay full. From then on the reason-by-reason rule applies. Two things are not carried: a
collection problem (never approved; the app's next complete scan clears it) and anything after the
approval's expiry. Set `drop` to have approvals not yet carried over cover nothing instead: those
sessions narrow at their next refresh and their users re-confirm. A record carried over before you
switch stays until it expires.

## 8. Evidence quality, collection problems and sensitive operations

Every integrity scan now says what it actually measured (`DESIGN.md` §76), as `evidence_quality` in
the report response, the integrity state and the stored report:

| quality | meaning |
|---|---|
| `complete` | every requested probe ran and returned measurements that agree |
| `partial` | code integrity compared only part of its targets (an advisory; the score is unchanged) |
| `legacy` | the collector predates its platform's evidence contract (Android 3, iOS 2): scored as before, never complete — update the app |
| `incomplete` | a requested probe failed, answered without its measurements, or could not measure (an unreadable process map, no thread enumerated) |
| `invalid` | measurements that cannot all be true (for example zero writable-executable mappings with their sizes listed) |

**Collection problems count once.** A probe that could not measure is not a finding, and one problem
— an unreadable process map — can break three probes at once. Each is listed at 0 points
(`integrity_probe_failed:<probe>`, `integrity_probe_incomplete:<probe>`,
`integrity_evidence_invalid:<probe>`), and together they add **+30 once**
(`integrity_evidence_incomplete`): an elevated verdict, cleared by the next complete scan. They never
enter the device memory: only findings do (`finding_score`, the score without them). Set
`collection_problems_block` to 1 to have each problem add +30, three of them block, and that block
follow the device — every account on the phone — for `integrity_device_memory_hours`.

**Evidence that stays incomplete is escalated.** `incomplete_evidence_review_after` (3) incomplete or
invalid scans of one installation in a row add +30 more — review, refused in enforce mode — so a phone
whose probes are deliberately blinded cannot stay merely elevated. A passing glitch never gets there:
one complete scan resets the count. Legacy scans never count. `0` turns it off.

**Sensitive operations need complete evidence.** List payment, advance or similar paths in
`complete_evidence_paths`: there, only a scan that is `complete` and at most
`complete_evidence_max_age_seconds` old (600) passes; anything else answers **403
`integrity_complete_evidence_required`** (`details.evidence_quality`, `age_seconds`,
`max_age_seconds`), whatever the verdict, step-up proof or acceptance. Your app's remedy is to scan
again right before the operation, and to update itself if it reports `legacy`. Listing a path forces
users of older app versions to update before using it.

**Reading the scores.** A report's `score` and `verdict` include collection problems; `finding_score`
does not. Analytics that look for compromise should read findings and quality separately: three
observations from one app process are not three independent sources.

## 9. Signing out, and revoked sessions

`POST /v1/auth/logout` (access token and access proof, body `{}`) revokes the caller's refresh family
on the server: its refresh token stops working, and so does every access token of the family — account
requests check that the family still has a current session and answer **401 `session_revoked`**. It
also revokes the family's acceptances. A limited session may sign out. Clearing tokens on the phone
alone is not a sign-out: a copied token, used with the phone's key, would stay valid until it
expired. A routine refresh rotates the session but leaves the family current, so requests in flight
with the previous access token still pass.

**Relationship changes during sign-in.** Sign-ins re-read the relationship counts, under locks, inside
the transaction that writes the link. If another sign-in linked the same phone or account in between,
the sign-in answers **409 `relationship_changed`** and writes nothing; ask once more, and the server
decides on the new counts. (Without this, simultaneous sign-ins could each pass the
devices-per-account limit — `tools/race_admission.py` shows it on a real database.)

## 10. The business API: events, the phone-account graph, integrity reports, PIN support

The server guarantees the measurements; **what they should refuse is your business's decision**, so
nothing here is scored (`DESIGN.md` §76). It is server to server — your backend calls it, never the
app.

**Access.** Set `BUSINESS_API_TOKEN_SHA256` to the SHA-256 digests (hex) of one or more random bearer
tokens, comma-separated so you can rotate without a gap; unset, the API answers 404. Calls carry
`Authorization: Bearer <token>`; anything else answers 401 `business_token_invalid`. Expose
`/v1/business/*` only to your backend network.

**`POST /v1/business/events`**, `{"events": [...]}`, 1–100 per call. Each event:

| field | required | notes |
|---|---|---|
| `event_id` | yes | your idempotency key, 1–64 of `A-Z a-z 0-9 . _ : -`; each is recorded once |
| `account_id` or `handle` | one of them | the server's opaque account ID, or the sign-in handle (resolved through the same keyed lookup, never stored) |
| `type` | yes | a short code (`a-z`, `0-9`, `_`), for example `advance_disbursed`, `repayment_failed`, `chargeback`, `credential_changed`; `business_event_types` may restrict them |
| `occurred_at` | yes | ISO 8601 with offset; not in the future |
| `amount_minor` + `currency` | no | a whole number of minor units and its ISO 4217 code |
| `outcome` | no | a short code |
| `subject_ref` | no | a payee, a destination: stored **only as a keyed hash**, so accounts sharing one can be linked without storing it |

Any other field, free text, an amount without its currency or a future time is refused (400
`invalid_business_event`, with the event's index and field). The answer lists each event as
`accepted`, `duplicate` or `rejected` (`unknown_account` — accounts are never created). Events are
evidence, never updated or deleted.

**`GET /v1/business/graph?account_id=…`** (or `device_id=`, or `handle=`): the phones and accounts
around one node, to `business_graph_depth` hops (2: the account, its phones, the accounts on them),
cut at `business_graph_max_nodes` (`truncated: true`). Each account carries its events by type for 1,
7 and 30 days with 30-day amounts per currency, and how many other accounts share a subject with it;
each phone its platform, status, first and last seen, installations, latest integrity verdict and
evidence quality, and whether its integrity memory holds a block; each link its first and last seen;
and the component its 30-day totals per type. Each account and phone also carries
`server_observations`: what the server itself saw on it, by kind, for 1, 7 and 30 days (section 11) —
on a phone, its denied approval requests among them (`approval_denied`).

**`GET /v1/business/acceptance-lapses?since=<ISO time>&limit=<n>`**: when an approved session met a
reason its approval did not cover, oldest first — `acceptance_id`, `account_id`, `installation_id`,
`reason_code`, `source`, `points`, `event_type`, `occurred_at`. `since` is exclusive; then page with
`?cursor=<next_cursor>`, which carries the last row's time and key, so rows sharing one instant at a
page edge are never skipped. Each `(acceptance_id, reason_code)` appears once.

**`GET /v1/business/integrity-reports?since=<ISO time>&limit=<n>`**: every integrity report as
stored, oldest first — the phone's own measurements (`probe_results`), the reasons and score the server
derived from them, the verdict, the evidence quality, `report_sha256`, `created_at`. At most one filter:
`device_id=`, `installation_id=`, or `account_id=` (the reports of every phone linked to the account,
from before the link too: a report describes the phone). `limit` 1–200, default 50; page with
`?cursor=<next_cursor>` as above. Every field is listed in [MEASUREMENTS.md](MEASUREMENTS.md).
**`probe_results` identify a phone** — its model, OS build, installed tools, the app's install source:
hold them as device-identifying data.

**`POST /v1/business/app-pin/unlock`** and **`/reset`**: your support staff, after verifying the
customer, unlock their app PIN or allow one reset of it — section 12.

**In every decision.** With the business API configured, each risk decision's `context` carries
`business_events_30d`: this account's counts by type, and those of every account on this phone.

**Not personal data.** Accounts are opaque IDs; subjects are keyed hashes; types and outcomes are short
codes; nothing else is accepted. Business rules over these measurements — "three failed repayments
across a phone's accounts adds points" — are yours to run, in your engine, from the graph and the
decision context; the server can apply such rules too, but only if you decide it should.

**Database.** Migration 017 adds `business_events`: grant `SELECT, INSERT`, never `UPDATE` or
`DELETE`; migration 021 adds the index the report feed pages through. The server serves only at its
schema version (21): a database behind it answers 503 `schema_version_mismatch` everywhere but
`/health`, so no decision ever reads a missing table.

## 11. The server's own observations (cross-checks)

A phone can send a clean scan that is not true. What it cannot hide is what the **server** sees when
it refuses or changes something, so the server records those itself (`DESIGN.md` §77) — never what a
phone reports, and no personal data: the account's opaque ID when there is one, the phone and the
installation whose key made the request.

| kind | recorded when |
|---|---|
| `sign_in_failed` | a wrong password at sign-in (code `invalid_credentials`), or at step-up re-enrolment (`stepup_reenrol_invalid_credentials`) |
| `sign_in_unknown_account` | a sign-in to a handle no account has — recorded without an account; the answer is the same 401 |
| `stepup_failed` | a step-up (screen-lock) proof that did not verify — on a sensitive path, the same-phone upgrade route, or an approver's phone — with its refusal code. A request sent without a proof is not one: that is the ordinary first leg, after which your app asks for the screen lock |
| `approval_budget_exhausted` | an approval request refused because the account's hourly budget was spent |
| `stepup_reenrolled` | a step-up key re-enrolled (in the same transaction as the change) |
| `token_without_key` | one of this phone's tokens — access or refresh — presented with a proof its key did not sign: copied to another phone. Once per token |
| `request_replayed` | one of this phone's signed requests sent again. Once per request |
| `app_pin_failed` / `app_pin_set` | a wrong app PIN; a PIN set or replaced — `app_pin_set_after_support_reset` when a support reset was used (section 12) |
| `app_pin_support_unlocked` / `app_pin_support_reset` | your support staff unlocked the account's PIN, or opened a reset; the code is their ticket reference, and no phone is named |
| denied approval requests | already rows of `session_upgrade_requests` (`denied_at`), counted per requesting phone |

**Measured always.** Every risk decision's `context.server_observations` carries the counts over
`cross_check_window_hours` (24): for the phone, across every account (`sign_in_failed`,
`sign_in_failed_accounts` — how many different accounts, `sign_in_unknown_account`, `stepup_failed`,
`approval_denied`, `approval_budget_exhausted`, `stepup_reenrolled`); for the account, from every
phone (`sign_in_failed`, `sign_in_failed_installations`, `sign_in_failed_elsewhere` — from
phones other than the one asking, and the other kinds); for this account on this phone
(`device_account`: `approval_denied`, `approval_budget_exhausted`, `stepup_reenrolled`); `newcomer`,
for a phone joining the account now or within the window (`joined_at`,
`sign_in_failed_elsewhere_before`), else null; `window_hours`; and `scored`. The graph (section 10)
carries them per account and phone.

**Scored only where your DBA switches them on** (`cross_checks_enabled`, default 0 — observe first).
Then each rule adds its points once its count is reached; `0` as a count switches a rule off. The
counts and points below are the defaults migration 019 seeds — proposals for you to tune:

| reason | count / points | counts |
|---|---|---|
| `account_sign_in_failures_elsewhere` | 5 / 30 | wrong passwords sent to the account by **other** phones in the window **before this phone joined it** — judged only for a phone joining now or within the window |
| `device_sign_in_failures_many_accounts` | 3 / 60 | different accounts this phone sent a wrong password to |
| `device_sign_in_unknown_accounts` | 5 / 30 | this phone's sign-ins to accounts that do not exist |
| `device_stepup_failures` | 3 / 30 | this phone's step-up proofs that did not verify |
| `device_approvals_denied` | 1 / 30 | this account's approval requests from this phone, denied by its other phone — and, with `device_approvals_denied_effect` = `limit` (default), the phone is held at review for this account (below) |
| `device_approval_budget_exhausted` | 2 / 30 | budget periods in which this phone found this account's hourly approval budget spent — counted once per period, however often it asked, so one impatient hour is one |
| `device_stepup_reenrolments` | 2 / 30 | this account's step-up keys re-enrolled on this phone |

What they do not do, by design:

- **On a shared phone, what one account did never counts against another**: a denial, an exhausted
  budget or a re-enrolment is counted for that account on that phone only.
- **A user mistyping on their own phone is never counted against anyone**, even after reinstalling the
  app there: the account's rule counts other phones only, and a phone's own rules need several accounts
  or unknown accounts.
- **Failures someone causes on an account never restrict a phone that was there before them** — a
  long-standing phone, or the one that opened the account this morning. Only a phone that joined
  after them is judged, so an attacker guessing a password cannot degrade the owner's phones.
- They are velocity signals: each holds for the window and then lapses. A lasting mark is your
  business's — your DBA's settings, or your own engine over the graph and the decision context.
- **A denied phone stays limited.** With `device_approvals_denied_effect` = `limit` (the default), a
  denial holds the phone at review — a limited session — for the window, even if the cause it was
  limited for clears, and a denial alone never blocks it; anything else that blocks still does. It may
  ask again within the hourly budget, and the approver sees the earlier denial among the reasons, so a
  mistaken "deny" is undone by approving the next request. `context.held_by_denial` says when the hold
  decided. `points` instead adds `device_approvals_denied_points` like any rule, which can reach block.
- Exhausting the approval budget has no such hold: its +30 on a phone already in review blocks it for
  the window. Lower `device_approval_budget_exhausted_points` (or set its count to 0) if you prefer
  that phone to stay limited.
- An approval covers one of these reasons only up to the count the approver saw (`count` on the
  reason); more failures afterwards need a new approval.

**A counter that could not be read is degraded evidence, not zero.** With `rate_anomaly_enabled` on
and its Redis counter unreachable (or no Redis configured), the decision says
`request_rate: {"state": "unavailable"}` and lists `request_rate_unavailable` at **0 points** — an
outage must not restrict everyone — instead of reading it as a rate of zero. A request whose rate
limiter could not run carries `context.rate_limiter = "unavailable"`. The observations themselves are
in the database, so a Redis outage does not touch them.

**Database.** Migration 019 adds `server_observations` (grant `SELECT, INSERT` — the server never
updates or deletes it), an index for denied approvals per phone, and the settings above. Each decision
runs more indexed queries: two without an account, five with one, six for a phone that joined it
within the window.

Every kind and code, and every other measurement, is listed in [MEASUREMENTS.md](MEASUREMENTS.md).

**Reading stored decisions.** A phone held by a denial can show a score in the block band with
`recommended_action` = `review` and `held_by_denial` true: read the action, not the band of the score.

## 12. Step-up: the screen lock, an app PIN the server checks, or both

A step-up is the user proving they are present for one operation. Your DBA chooses how
(`DESIGN.md` §78):

| `stepup_method` | the request must carry |
|---|---|
| `app_pin` (default) | the account's app PIN, which the server checks |
| `screen_lock` | a proof signed by the phone's step-up key, which the phone's screen lock (passcode or biometric) unlocks |
| `screen_lock_and_app_pin` | both |

It applies wherever a step-up is required: the paths in `stepup_required_paths`, approving another
phone's request, route 1 (the same-phone upgrade) and an elevated scan satisfied by a step-up. Paths in
`app_pin_required_paths` need the PIN **in addition**, whatever the method — for example the screen
lock everywhere and the PIN on payee changes and large transfers.

**What each protects against.** A thief who watched the phone's passcode passes the screen lock but
not an app PIN. Malware on the phone with Android's Accessibility permission can read either as it is
typed and type it back itself; a **biometric** screen lock (`stepup_factor` = `biometric`) is the one
factor it cannot observe. The server sees, counts and locks app PIN attempts; it sees nothing of the
screen lock. The screen lock keeps nothing on your server; the app PIN keeps a verifier.

**Every account needs a PIN before it can approve.** Under the default, approving another phone's
request needs the approver's app PIN; an account without one is answered `app_pin_not_set`. Your app
must offer the screen to set it — the reference harness has one — and should ask for it before the
first approval, not at it.

**Setting the PIN.** `POST /v1/account/app-pin` with `{"password": …, "pin": "123456"}` — a current full
session (a limited one is refused) and the account password. `app_pin_length` digits. It replaces any
earlier PIN and clears its count and lock; this is also how a user with a forgotten or locked PIN gets
back in: **the user**, in your app, with their password, from a full session on any of their phones —
no administrator is involved. A user whose only session is limited has no full session to do it from;
their way back is a clean scan (the session upgrades by itself), your support staff (below), or route
3 through your identity backend. The server never requires the PIN to set one, nor the screen-lock key
to re-enrol one (`/v1/installations/stepup-key`), whatever the paths list: a locked PIN or a dead key
could otherwise never be replaced.

**Support staff** (`DESIGN.md` §79). Your DBA chooses what they may do, `app_pin_support`: `off` (the
default), `unlock`, or `unlock_and_reset`. Your support tool calls the business API (section 10) after
verifying the customer, naming the account and its own ticket reference:

```
POST /v1/business/app-pin/unlock    {"handle": "…", "reference": "TICKET-4711"}
POST /v1/business/app-pin/reset     {"account_id": "…", "reference": "TICKET-4711"}
```

Exactly one of `account_id` or `handle`; `reference` is 1–64 of `A-Z a-z 0-9 . _ : -`, and nothing else
is accepted (400 `invalid_support_request`, naming the field). **Unlock** clears the count and the lock
of an existing PIN — for a customer who remembers it (404 `app_pin_not_set` when there is none).
**Reset**, only under `unlock_and_reset`, also opens a window of `app_pin_support_reset_minutes` (15) in
which the customer may set a new PIN **even from a limited session** — still with the password, still
refused if the phone is blocked — once: setting it closes the window, and a second attempt is refused.
The answer carries `reset_until`; `/v1/account/me` shows `app_pin_reset_open`. Each action is recorded
for the account (`app_pin_support_unlocked`, `app_pin_support_reset`, with the reference), and the PIN
set through a reset as `app_pin_set_after_support_reset`, with the phone that set it. Off, both answer
403 `app_pin_support_disabled`.

**The risk lands on your verification procedure.** Whoever convinces your support staff that they are
the customer gets the unlock or the reset; during a reset window the password alone sets the PIN, from
any phone holding a session on the account. Verify as you would for a password reset, keep the window
short, and check afterwards which phone set the PIN.

**Sending it.** The `X-App-PIN` header, on the request it approves. Never log it — check your proxies
(the reference server's gunicorn and Caddy write no headers). Refusals:

| code | meaning |
|---|---|
| `app_pin_required` / `stepup_required` (403) | a factor is missing; `details.step_up.needs` lists what this request needs |
| `app_pin_invalid` (403) | wrong; `details.attempts_left` |
| `app_pin_locked` (403) | after `app_pin_max_failures` wrong PINs in a row; even the right PIN is refused until a new one is set |
| `app_pin_not_set` (403) | the account has none yet |
| `invalid_app_pin` (400) | setting a PIN of the wrong length or with non-digits |
| `app_pin_reset_lapsed` (403) | a limited session tried to use a support reset that lapsed or was used in the meantime |

**Your app follows the DBA's policy.** `GET /v1/policy/step-up` needs no token — the app creates its
step-up key when it first registers, before any account exists — and answers the `method`, the
`factor`, `mode` and `window_seconds` the screen-lock key must be created with, `app_pin_length`,
`required_paths` and `app_pin_required_paths`; never cached, rate-limited per source.
`/v1/account/me` reports the same in `step_up`, with `app_pin_set`, `app_pin_locked` and
`app_pin_reset_open`. The reference client reads it before registering and creates the key to match;
an existing key of another factor is replaced while no key is bound, and once one is bound the user is
asked to re-enrol it with the password (the server would refuse the old one,
`stepup_factor_mismatch`). A per-use key satisfies a windowed policy. The build's `STEPUP_*` values are
only the fallback when the server cannot be asked.

**Storage.** One PIN per account (migration 020, `app_pins`; grant `SELECT, INSERT, UPDATE`), kept only as
bcrypt over an HMAC keyed by a secret derived from `DEVICE_ID_MASTER_SECRET`: a copy of the table alone
cannot be searched. With the table **and** the root secret, a 4–12 digit PIN can be found by brute
force in hours — protect the root secret as you would a signing key.

**Route 1 and single-phone users.** Under `app_pin` the same-phone upgrade proves the account's PIN,
which an attacker signing in on their own phone does not have — unlike that phone's screen lock. It is
off by default (`upgrade_stepup_same_device`); turning it on gives single-phone users a way to clear an
integrity-limited session, at the cost that wrong PINs from an attacker's phone can lock the user's PIN
until they set a new one with their password.

## 13. How long a session lives

Your DBA's choice (`DESIGN.md` §79), within limits we fix:

| setting | default | meaning |
|---|---|---|
| `refresh_idle_days` | 30 | a session ends after this many days without a refresh; each refresh extends it — a user who opens the app weekly stays signed in. 1–90 |
| `session_max_days` | 0 | a session ends this many days after its first sign-in, however often it refreshes; 0 = no limit. Up to 365 |

A session past `session_max_days` is refused with 401 **`session_max_age_reached`**, at the refresh and
on requests that check the session row; the user signs in again. It applies at once to sessions opened
before the DBA set it. A refresh token is issued for at most the time left. The access token (10
minutes) and the device token (10 minutes) are ours, not settings. `/health/ready` reports the
effective values.

## 14. The phone's OS and network, and measurements you switch on

`DESIGN.md` §80. Every measurement is listed in [MEASUREMENTS.md](MEASUREMENTS.md).

**On every scan** (collectors from Android 4 and iOS 3): the **`device`** probe — the OS version, on
Android also the API level and **the security patch level**, the manufacturer, model and build — and
the **`network`** probe: whether a **VPN** is up and an **HTTP proxy** is set, as yes/no, with interface
names and never an address. They are sent outside the server's probe plan, so an app built before them
keeps working and simply sends neither. On Android the network probe needs `ACCESS_NETWORK_STATE`, a
normal permission granted at install (no prompt); add it to your app's manifest. iOS gives other apps
no VPN API, so the collector **infers** a VPN from the interfaces the system proxy settings are scoped
to — a heuristic, reported with the interface names.

A VPN or a proxy costs **no points** (`android_vpn_active`, `ios_vpn_active`, `android_http_proxy`,
`ios_http_proxy`): people use them for privacy and at work. If your deployment refuses them, your DBA
sets the eligibility rules `vpn_active_refuses` and/or `http_proxy_refuses` to 1, which work like the
developer-options rule in section 5: in enforce mode 403 `integrity_device_ineligible` with a remedy
your app shows ("Turn off the VPN, then send a new integrity scan"). A phone whose app predates the
network probe reports neither, and a modified app can hide them: a policy for honest phones, not a
compromise check. Known VPN exit addresses are a separate matter: record the source address (below)
and match it against your own list.

**Optional measurements, two keys.** A measurement that identifies a person's phone or network is
collected only where **your DBA** asks for it **and your app's developers** enabled it:

| Name | DBA | App (reference client) | What |
|---|---|---|---|
| `local_addresses` | `optional_measurements` = `local_addresses` | `--dart-define=MEASURE_LOCAL_ADDRESSES=true` | the phone's own IP addresses per interface |

Each challenge lists what the DBA asks for in `optional_probes`; it is never required. An app that did
not enable one answers `not_enabled`, at no cost. Whatever the DBA does not ask for is dropped before
a report is stored, even if a phone sends it.

**Recorded by the server** — no app change: `record_source_ip` keeps the address each request came from
(as seen through your configured proxies, `TRUSTED_PROXY_COUNT`) and `record_user_agent` its
User-Agent header (cut at 256 characters), both in each risk decision's context (`source_ip`,
`user_agent`). Both 0 by default. The Flutter client sends `Dart/<version> (dart:io)` unless your app
sets its own User-Agent. Both are personal data, kept as long as the decisions are: your retention
policy applies.

**What a phone will not give.** An ordinary app cannot read the **MAC address** (iOS since 7, Android's
Wi-Fi API since 6 answer a constant; Android 11 hides it from apps targeting it, and Android 10 randomises
it per network) or the **IMEI** (no iOS API; on Android 10 and later only system and device-owner apps;
on Android 9 and earlier only behind the "make and manage phone calls" prompt and Google Play's
identifier disclosures). Neither is collected: the owner dropped both (`DESIGN.md` §80).

