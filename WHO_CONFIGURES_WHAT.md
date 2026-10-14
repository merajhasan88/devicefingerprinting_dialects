# Who configures what

The owner's division of labour (2026-10-14): *"Leave it to them to figure out business logic but our
job is 1) give them defaults, 2) give them every possible measurement from app, 3) a means to apply
logic on servers and the app that may differ from defaults."* This map checks the project against that
rule, item by item: what the product fixes, what a company's DBA and business analysts set, what its
platform team runs, what its app developers build, and where we have not delivered yet (section 7).

Checked against the code at schema 20 (`device_trust_server.py`, migrations 001–020, the Flutter
client and the Android and iOS native code). Where a row says a value is in the code, it is.

## The parties

The owner named two teams. The code has two more, and each needs an owner in the customer's company,
even if the same people wear two hats.

| Party | Decides | Where it lives | Documented today |
|---|---|---|---|
| **Us**, the product | how phones are measured and how much each finding weighs; the protocol | code | `DESIGN.md` (internal) |
| **DBA and business analysts** | what is refused, limited, counted, for how long | `risk_policy_settings`, 71 rows | `INTEGRATION_GUIDE.md` §5, §7–§12; the rows' own descriptions |
| **Platform / operations** | running the server: database, Redis, TLS, secrets, rollout modes, the app's identity pins | about 60 environment variables | guide §2–§4, §6 |
| **App developers** | the app: native keys and collector, SDK calls, the screens users see, release values handed to operations | build settings, native modules, UI | scattered through the guide — **no app-developer guide** (gap G3) |
| **Backend developers** | business events in, the graph and lapse feed out; route-3 assertions from their identity system | business API, JWKS file | guide §10, §7 |

## 1. What we fix — measurement and protocol

| What | Values | Why it is ours |
|---|---|---|
| The integrity findings and their points | e.g. Frida in memory +90, a hooking framework +80, a Frida port +75, Magisk/KernelSU/APatch +75, bootloader unlocked +60, writable system partition +55, `ro.secure=0` +50, test-keys +25, signing-certificate mismatch +100 and a hard block (`_score_android_integrity`, `_score_ios_integrity`) | Measured on our handset battery. What a finding weighs is the product's expertise and the same for every customer |
| The integrity verdict bands | 0–29 trusted, 30–59 elevated, 60–89 review, 90+ block | Owner decision: not DBA-configurable |
| How evidence quality is judged | complete, partial, incomplete, invalid, legacy; collection problems +30 once; evidence contracts Android 3, iOS 2 | Our measurement rules |
| The probe plan | six mandatory Android probes plus four random optional ones (`INTEGRITY_RANDOM_OPTIONAL_PROBES`) | Collection design |
| The protocol | ES256 installation key, access-proof v2 over the whole request, single-use nonces, step-up proof v2, MACed challenges, replay defence | Security; changing it breaks every client |
| Lifetimes | access token 10 min, device token 10 min, **refresh 30 days**, challenge 2 min, proof clock skew ±120 s, nonce retention 10 min | Security parameters. The refresh lifetime is the one a business may reasonably want to choose (gap G8) |
| Invariants | links and observations are never deleted; a block always refuses; a limited session never sets a PIN; neither the PIN nor the key is ever required to replace itself; PIN attempts are claimed before they are compared; a stolen token is recorded once | The guarantees the product makes |
| **Still in the code, but policy** | a new phone +10 for 24 h; a known phone's new installation +15; reinstalls 3 → +35, 4 → +60 (the block count and the window are environment variables); no scan yet +40; a stale scan +35; another installation on the phone blocked +50 (`_evaluate_risk_policy`) | **Not ours** by the owner's own rule — every policy value is a DBA setting with the owner's default. Gap G1 |

## 2. DBA and business analysts — every policy value, with its default

All 71 settings, generated from migrations 003–020 with each row's own description. The server
re-reads the table every 30 seconds; a value that does not parse makes the snapshot invalid, and the
server keeps its last good one for five minutes, then refuses rather than run without a policy. A
count of `0` switches a rule off. `POLICY_*` environment variables answer only for a missing row.

**Step-up and opt-in behavioural signals** (migration 003)

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

**Relationships: accounts per phone, phones per account, the bands** (migration 006, 012)

| Setting | Default | What it decides |
|---|---|---|
| `device_accounts_elevated_count` | `2` | Accounts on one device that raise the score (elevated band). |
| `device_accounts_elevated_points` | `35` | Risk points at the elevated account count. |
| `device_accounts_review_count` | `3` | Accounts on one device that are held for review. |
| `device_accounts_review_points` | `60` | Risk points at the review account count. |
| `device_accounts_block_count` | `4` | Accounts on one device that are blocked outright. |
| `elevated_risk_refuses` | `0` | In enforce mode, 1 = an elevated (step-up band) decision refuses the request; 0 = recorded, not refused. |
| `policy_step_up_score` | `30` | Relationship-risk score from which a decision is step_up (recorded, allowed unless elevated_risk_refuses=1). Must be below policy_review_score. |
| `policy_review_score` | `60` | Relationship-risk score from which a decision is review (refused in enforce mode, or a limited session where listed). Must be below policy_block_score. |
| `policy_block_score` | `90` | Relationship-risk score from which a decision is block (always refused). |
| `account_devices_elevated_count` | `2` | Devices one account may use before its decisions are raised (elevated band). 0 = off. |
| `account_devices_elevated_points` | `35` | Risk points at the elevated devices-per-account count. |
| `account_devices_review_count` | `3` | Devices one account may use before its decisions are held for review. 0 = off. |
| `account_devices_review_points` | `60` | Risk points at the review devices-per-account count. |
| `account_devices_block_count` | `5` | Devices one account may use before it is blocked. 0 = off. |

**Integrity policy choices and sensitive operations** (migration 010, 015)

| Setting | Default | What it decides |
|---|---|---|
| `wx_far_above_baseline_percent` | `200` | W^X memory above this percentage of the build's pinned baseline scores +40 (android_wx_far_above_baseline); between the baseline and this percentage it is expected runtime growth, advisory. 200 = twice the baseline. Minimum 100. |
| `developer_options_refuses` | `0` | Eligibility rule. 1 = in enforce mode an installation whose latest scan reports Developer options on is refused (integrity_device_ineligible) until they are off and a new scan is sent; 0 = advisory only. |
| `adb_enabled_refuses` | `0` | Eligibility rule. 1 = in enforce mode an installation whose latest scan reports USB debugging (ADB) on is refused (integrity_device_ineligible) until it is off and a new scan is sent; 0 = advisory only. |
| `collection_problems_block` | `0` | 1 = each failed or incomplete probe adds +30, three make a block, and that block is remembered for the device (every account on the phone) like a finding. 0 (owner default) = collection problems add +30 once and never enter the device memory. |
| `integrity_device_memory_hours` | `24` | Hours a blocked finding stays with the physical device across reinstalls. 0 = off. |
| `complete_evidence_paths` | *(empty)* | Paths that need a fresh, complete integrity scan (no failed, incomplete, contradictory or legacy evidence), comma-separated. Empty: none. |
| `complete_evidence_max_age_seconds` | `600` | How fresh that scan must be on complete_evidence_paths, in seconds. Minimum 30. |
| `incomplete_evidence_review_after` | `3` | Consecutive incomplete or invalid scans of one installation, with no complete scan between them, that escalate the verdict to review. 0 = off. Legacy collectors never count. |

**Limited sessions, upgrades and approvals** (migration 011, 013, 016, 018)

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
| `upgrade_acceptance_hours` | `720` | Hours an upgrade keeps accepting the soft causes its proof covered (never past the 30-day refresh lifetime). 0 = none: protected requests and refreshes judge them again. |
| `acceptance_auto_cover_reasons` | *(empty)* | Reason codes an approved session accepts automatically even if they appear after the approval, comma-separated. A business decision; empty (owner default) = every new reason needs a new decision. Collection problems are never covered. |
| `legacy_acceptances` | `carry` | Approvals granted before migration 016: carry (owner default) = keep each as what it covers at its first use, until its expiry; drop = they cover nothing and their users re-confirm. |

**Business API** (migration 017)

| Setting | Default | What it decides |
|---|---|---|
| `business_event_types` | *(empty)* | Business event types the server accepts, comma-separated. Empty: any well-formed type (a-z, 0-9, _). |
| `business_graph_depth` | `2` | Hops the phone-account graph API follows from its starting account or phone (account to phones is one hop). 1-4. |
| `business_graph_max_nodes` | `200` | Most accounts and phones the graph API returns; a larger component is cut and marked truncated. |

**Cross-checks: the server's own observations** (migration 019)

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

**Step-up method and the app PIN** (migration 020)

| Setting | Default | What it decides |
|---|---|---|
| `stepup_method` | `app_pin` | How a step-up is proven wherever one is required (the step-up paths, approving another phone, the same-phone upgrade, an elevated scan): app_pin (owner default, checked by the server), screen_lock or screen_lock_and_app_pin. |
| `app_pin_required_paths` | *(empty)* | Paths that need the app PIN in addition to anything else, comma-separated (for example payee changes, large transfers). Empty: none. |
| `app_pin_length` | `6` | Digits in an app PIN, 4-12. |
| `app_pin_max_failures` | `5` | Wrong app PINs in a row before the PIN locks; the user then sets a new one with the account password. At least 1. |
| `device_app_pin_failures_count` | `3` | Wrong app PINs for one account from this phone in the window (DESIGN.md 77). |
| `device_app_pin_failures_points` | `30` | Points for device_app_pin_failures. |

## 3. Platform / operations — running the server

| Area | Variables | Notes |
|---|---|---|
| Database | `DB_ENGINE`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, `DB_PASSWORD`, `DB_SSLMODE`, `DB_SSLROOTCERT`, `DB_CONNECT_TIMEOUT`, `DB_QUERY_TIMEOUT`, `DB_POOL_SIZE`, `DB_POOL_RECHECK_SECONDS` | Verified TLS in production |
| Redis and throttles | `REDIS_URL`, `NONCE_BACKEND`, `RATE_LIMIT_ENABLED`, `RATE_LIMIT_MAX_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS`, `RATE_LIMIT_SOURCE_MAX_ATTEMPTS` | A Redis outage is recorded as degraded evidence (DESIGN.md 77) |
| HTTP | `REQUIRE_HTTPS`, `TRUSTED_PROXY_COUNT`, `MAX_REQUEST_BYTES`, `FLASK_HOST`, `FLASK_PORT`, `LOG_LEVEL` | Never log `X-App-PIN` (guide §12) |
| Secrets | `DEVICE_ID_MASTER_SECRET` or `DEVICE_ID_MASTER_SECRET_FILE`, `BUSINESS_API_TOKEN_SHA256` | The root secret keys the JWTs, the hint and handle lookups and the app-PIN verifiers |
| Rollout | `INTEGRITY_MODE`, `DEVICE_POLICY_MODE` (observe / enforce) | A business decision that operations carries out |
| The app's identity — **values from the app's release pipeline** | `INTEGRITY_ANDROID_CERT_SHA256`, `INTEGRITY_ANDROID_APK_SHA256`, `INTEGRITY_ANDROID_PACKAGE`, `INTEGRITY_ANDROID_WX_BASELINES`, `INTEGRITY_IOS_TEAM_ID`, `INTEGRITY_IOS_BUNDLE_ID`, `INTEGRITY_IOS_SIGNING_ID`, `INTEGRITY_IOS_EXECUTABLE_SHA256` | App developers produce them per release; operations sets them (guide §3) |
| Lab only — 0 in production | `INTEGRITY_ALLOW_DEBUG`, `INTEGRITY_ALLOW_EMULATOR`, `INTEGRITY_ALLOW_USERDEBUG` | |
| Scoring switches, ours | `INTEGRITY_SCORE_EXTENDED_LIBS`, `INTEGRITY_SCORE_IOS_CODE_INTEGRITY`, `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`, `INTEGRITY_RANDOM_OPTIONAL_PROBES` | Staged rollout of rules not yet baselined on hardware |
| Protocol transitions | `ACCESS_PROOF_MIN_VERSION`, `INTEGRITY_MIN_COLLECTOR_VERSION`, `INTEGRITY_CHALLENGE_LIFETIME_SECONDS`, `INTEGRITY_REPORT_MAX_SKEW_SECONDS` | Raise a floor to retire an old client |
| Route 3 | `UPGRADE_ASSERTION_JWKS_FILE`, `UPGRADE_ASSERTION_ISSUER` | The customer's identity backend's public keys |
| Housekeeping | `MAINTENANCE_INTERVAL_SECONDS`, `RISK_SETTINGS_CACHE_TTL_SECONDS`, `RISK_SETTINGS_MAX_STALE_SECONDS` | |
| **Policy that sits here, but is the DBA's** | `INTEGRITY_FRESHNESS_SECONDS` (600), `INTEGRITY_HARDWARE_BACKING_POLICY` (off / advisory / required), `POLICY_REINSTALL_WINDOW_HOURS` (24), `POLICY_REINSTALL_BLOCK_COUNT` (5) | Gap G1 |
| Fallbacks only | `POLICY_STEP_UP_SCORE`, `POLICY_REVIEW_SCORE`, `POLICY_BLOCK_SCORE`, `POLICY_DEVICE_ACCOUNT_BLOCK_COUNT`, `POLICY_ACCOUNT_DEVICE_BLOCK_COUNT`, `INTEGRITY_DEVICE_MEMORY_HOURS` | Used only when the settings row is missing |

## 4. App developers — the app

**Build settings** (Flutter `--dart-define`):

| Setting | Default | Meets |
|---|---|---|
| `API_BASE_URL` | none: a build without it fails fast | operations' endpoint |
| `STEPUP_ENABLED` | `true` in the reference harness | the DBA's `stepup_method` (needed for `screen_lock` and both) |
| `STEPUP_FACTOR` | `passcode`; `biometric` possible | the DBA's `stepup_factor` — **they must agree**, or every step-up fails `stepup_factor_mismatch` (gap G4) |
| `STEPUP_MODE`, `STEPUP_WINDOW_SECONDS` | `per_use`, 0 | the DBA's `stepup_mode`, `stepup_window_seconds` |

**Native code they embed** — Android: `InstallationKeyManager.kt` (the non-exportable installation key),
`StepUpKeyManager.kt` (the screen-lock key: passcode, or `BIOMETRIC_STRONG` from Android 9; per-use or
windowed), `IntegrityProbeManager.kt` (the collector, contract 3). iOS: `InstallationKeyManager.swift`
(Secure Enclave keys, including the step-up key: `.devicePasscode` or `.biometryCurrentSet`),
`IntegrityProbeManager.swift` (contract 2). Method channels: `devicefingerprinting/installation_key_v2`,
`devicefingerprinting/stepup_key_v1`, `devicefingerprinting/integrity_v1`.

**The Dart client** — `DeviceApi`, the `Native*` wrappers, `SecureIdentityStore` and the models — lives
in `lib/device_trust_client.dart` together with the 3,000-line reference harness (gap G2).

**Screens their app must provide** (the harness shows one way): set and enter the app PIN — needed
before an account can approve another phone under the default method; the approval list with the
reasons the server shows, approve and deny; the limited-session state with its upgrade routes; a scan
prompt when the server asks for a complete or fresh scan; sign-out; re-enrolling the step-up key when
the screen lock changed (only under `screen_lock` or both); and a message for each refusal code the
guide lists.

**Values they hand to operations, per release**: the signing certificate's SHA-256, the APK SHA-256
and its W^X baseline (DESIGN.md 62), the iOS team, bundle and signing identifiers and executable hash.

## 5. Measurements — what they get

| Measurement | Where | Reachable by |
|---|---|---|
| Every probe's raw result from every scan | `integrity_reports.probe_results` | SQL only (gap G5) |
| Each scan's reasons, points, verdict, evidence quality, finding score | the scan response; `integrity_reports` | the app; SQL |
| Each decision: relationship counts, integrity state, device memory, the server's own observations, request rate, business-event counts, reasons, action | `risk_policy_decisions`; returned on sign-in, refresh and `/v1/policy/me` | the app; SQL |
| What the server itself saw (wrong passwords, unknown accounts, failed step-ups and PINs, denials, exhausted budgets, re-enrolments, stolen tokens, replays) | `server_observations` | decisions; the business graph; SQL |
| The phone–account graph with business events and observations | `GET /v1/business/graph` | the customer's backend |
| When an approval stopped covering, and why | `GET /v1/business/acceptance-lapses` | the customer's backend |
| A catalog of every reason code, observation kind and context field | — | **missing** (gap G5) |

## 6. Answers to the owner's four questions

1. **What we fix** — the integrity weights and bands, measurement rules, the protocol and its
   lifetimes, the invariants. Except the relationship rules in section 1's last row, which are policy
   and should move to the DBA (G1); the refresh lifetime is arguable (G8).
2. **The DBA's and business analysts' domain** — 71 settings, each with the owner's default and a
   description in the row; a handful of policy values are still in code or environment (G1); the guide
   lists only "notable keys" (G7).
3. **The app developers' domain** — the native code and a working reference client exist, but there is
   no package to depend on (G2), no guide written for them (G3), and the step-up factor is fixed at build
   time rather than read from the server (G4).
4. **Options, defaults and documentation** — on the server side, largely yes; on the app side, no; the
   integration documents miss a front page (G6), a measurement catalog (G5) and a complete settings
   reference (G7).

## 7. Gaps, most important first

| # | Gap | Proposed fix | Owner decision |
|---|---|---|---|
| G1 | Relationship policy still in code or environment: new phone +10/24 h, a known phone's new installation +15, reinstall velocity (3 → +35, 4 → +60, block at 5, 24 h), no scan +40, stale scan +35, another installation blocked +50, scan freshness 600 s, hardware-backing policy | Migration 021 seeding each as a DBA setting at today's value; the code reads them like the others | No (the owner's standing rule); confirm the list |
| G2 | No Flutter package: an app developer copies code out of the harness | Extract a Flutter plugin package — the Dart API, models and the Android and iOS native code — and make the harness depend on it | Yes: package name, versioning, where it is published |
| G3 | No guide for app developers | An app-developer guide: installing the package, the calls and their order, the screens, every refusal code and its remedy, the release values for operations | No |
| G4 | The app's step-up factor and mode are fixed at build time; the server's choice cannot be read at runtime | `/v1/account/me` also returns factor, mode and window; the SDK creates the matching key itself; the build setting stays as a fallback | Yes |
| G5 | No catalog of measurements; raw probe results only by SQL | A catalog of every reason code, observation kind and context field; optionally `GET /v1/business/integrity-reports` for raw measurements | Yes, for the endpoint |
| G6 | `README.md` is the Flutter template | An orientation page for the four parties | No |
| G7 | Guide §5 lists "notable" settings, not all | A settings reference generated from the migrations, as in section 2, checked by the gate | No |
| G8 | The refresh lifetime (30 days) is fixed | A DBA setting within a floor and ceiling we fix | Yes |
| G9 | Python is named as a client SDK; there is none beyond the conformance suite's reference client | Build one, or correct the claim | Yes |
| G10 | Migrations 015–020 have not run on SQL Server | One RDS round | Already asked |
