# Who configures what

The owner's division of labour (2026-10-14): *"Leave it to them to figure out business logic but our
job is 1) give them defaults, 2) give them every possible measurement from app, 3) a means to apply
logic on servers and the app that may differ from defaults."* This map checks the project against that
rule, item by item: what the product fixes, what a company's DBA and business analysts set, what its
DevOps team runs, what its app developers build, and where we have not delivered yet (section 7).

Checked against the code at schema 21 (`device_trust_server.py`, migrations 001–021, the Flutter
client and the Android and iOS native code). Where a row says a value is in the code, it is. First
written at schema 20; the gaps the owner answered on 2026-10-14 are marked in section 7.

## The parties

The owner named two teams. The code has two more, and each needs an owner in the customer's company,
even if the same people wear two hats.

| Party | Decides | Where it lives | Documented today |
|---|---|---|---|
| **Us**, the product | how phones are measured and how much each finding weighs; the protocol | code | `DESIGN.md` (internal) |
| **DBA and business analysts** | what is refused, limited, counted, for how long; what support staff may do to a PIN | `risk_policy_settings`, 89 rows | `INTEGRATION_GUIDE.md` §5 (every row, generated), §7–§13; the rows' own descriptions |
| **DevOps** | running the server: database, Redis, TLS, secrets, rollout modes, the app's identity pins | about 60 environment variables | guide §2–§4, §6 |
| **App developers** | the app: native keys and collector, SDK calls, the screens users see, release values handed to DevOps | build settings, native modules, UI | scattered through the guide — **no app-developer guide** (gap G3) |
| **Backend developers** | business events in; the graph, the lapse feed and every integrity report out; the support tool's PIN unlock and reset; route-3 assertions from their identity system | business API, JWKS file | guide §10, §12, §7; [MEASUREMENTS.md](MEASUREMENTS.md) |

## 1. What we fix — measurement and protocol

| What | Values | Why it is ours |
|---|---|---|
| The integrity findings and their points | e.g. Frida in memory +90, a hooking framework +80, a Frida port +75, a root-management framework +75, Verified Boot not green or the bootloader unlocked +60, writable system partition +55, `ro.secure=0` +50, test-keys +25, signing-certificate mismatch +100 and a hard block (`_score_android_integrity`, `_score_ios_integrity`) | Measured on our handset battery. What a finding weighs is the product's expertise and the same for every customer |
| The integrity verdict bands | 0–29 trusted, 30–59 elevated, 60–89 review, 90+ block | Owner decision: not DBA-configurable |
| How evidence quality is judged | complete, partial, incomplete, invalid, legacy; collection problems +30 once; evidence contracts Android 3, iOS 2 | Our measurement rules |
| The probe plan | fourteen mandatory Android probes plus `emulator` drawn at random (`INTEGRITY_RANDOM_OPTIONAL_PROBES`); six mandatory iOS probes | Collection design |
| The protocol | ES256 installation key, access-proof v2 over the whole request, single-use nonces, step-up proof v2, MACed challenges, replay defence | Security; changing it breaks every client |
| Lifetimes | access token 10 min, device token 10 min, challenge 2 min, proof clock skew ±120 s, nonce retention 10 min | Security parameters. How long a session lives is the DBA's since migration 021: `refresh_idle_days` (30, 1–90) and `session_max_days` (0, up to 365) — G8, done |
| Invariants | links and observations are never deleted; a block always refuses; a limited session never sets a PIN; neither the PIN nor the key is ever required to replace itself; PIN attempts are claimed before they are compared; a stolen token is recorded once | The guarantees the product makes |
| Relationship rules — **moved to the DBA** | a new phone, a known phone's new installation, reinstall velocity, no scan or a stale one, another installation blocked, scan freshness, the hardware-backing policy | DBA settings since migration 021, seeded at the values the code used (G1, done); the gate fails if the server reads a setting no migration seeds |

## 2. DBA and business analysts — every policy value, with its default

Every setting, generated from the migrations by `tools/settings_reference.py` and checked by the
gate. The server re-reads the table every 30 seconds; a value that does not parse makes the snapshot
invalid, and the server keeps its last good one for five minutes, then refuses rather than run
without a policy. A count of `0` switches a rule off. Environment variables answer only for a
missing row.

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

## 3. DevOps — running the server

| Area | Variables | Notes |
|---|---|---|
| Database | `DB_ENGINE`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, `DB_PASSWORD`, `DB_SSLMODE`, `DB_SSLROOTCERT`, `DB_CONNECT_TIMEOUT`, `DB_QUERY_TIMEOUT`, `DB_POOL_SIZE`, `DB_POOL_RECHECK_SECONDS` | Verified TLS in production |
| Redis and throttles | `REDIS_URL`, `NONCE_BACKEND`, `RATE_LIMIT_ENABLED`, `RATE_LIMIT_MAX_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS`, `RATE_LIMIT_SOURCE_MAX_ATTEMPTS` | A Redis outage is recorded as degraded evidence (DESIGN.md 77) |
| HTTP | `REQUIRE_HTTPS`, `TRUSTED_PROXY_COUNT`, `MAX_REQUEST_BYTES`, `FLASK_HOST`, `FLASK_PORT`, `LOG_LEVEL` | Never log `X-App-PIN` (guide §12) |
| Secrets | `DEVICE_ID_MASTER_SECRET` or `DEVICE_ID_MASTER_SECRET_FILE`, `BUSINESS_API_TOKEN_SHA256` | The root secret keys the JWTs, the hint and handle lookups and the app-PIN verifiers |
| Rollout | `INTEGRITY_MODE`, `DEVICE_POLICY_MODE` (observe / enforce) | A business decision that DevOps carries out |
| The app's identity — **values from the app's release pipeline** | `INTEGRITY_ANDROID_CERT_SHA256`, `INTEGRITY_ANDROID_APK_SHA256`, `INTEGRITY_ANDROID_PACKAGE`, `INTEGRITY_ANDROID_WX_BASELINES`, `INTEGRITY_IOS_TEAM_ID`, `INTEGRITY_IOS_BUNDLE_ID`, `INTEGRITY_IOS_SIGNING_ID`, `INTEGRITY_IOS_EXECUTABLE_SHA256` | App developers produce them per release; DevOps sets them (guide §3) |
| Lab only — 0 in production | `INTEGRITY_ALLOW_DEBUG`, `INTEGRITY_ALLOW_EMULATOR`, `INTEGRITY_ALLOW_USERDEBUG` | |
| Scoring switches, ours | `INTEGRITY_SCORE_EXTENDED_LIBS`, `INTEGRITY_SCORE_IOS_CODE_INTEGRITY`, `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`, `INTEGRITY_RANDOM_OPTIONAL_PROBES` | Staged rollout of rules not yet baselined on hardware |
| Protocol transitions | `ACCESS_PROOF_MIN_VERSION`, `INTEGRITY_MIN_COLLECTOR_VERSION`, `INTEGRITY_CHALLENGE_LIFETIME_SECONDS`, `INTEGRITY_REPORT_MAX_SKEW_SECONDS` | Raise a floor to retire an old client |
| Route 3 | `UPGRADE_ASSERTION_JWKS_FILE`, `UPGRADE_ASSERTION_ISSUER` | The customer's identity backend's public keys |
| Housekeeping | `MAINTENANCE_INTERVAL_SECONDS`, `RISK_SETTINGS_CACHE_TTL_SECONDS`, `RISK_SETTINGS_MAX_STALE_SECONDS` | |
| Fallbacks only, since migration 021 | `INTEGRITY_FRESHNESS_SECONDS`, `INTEGRITY_HARDWARE_BACKING_POLICY`, `POLICY_REINSTALL_WINDOW_HOURS`, `POLICY_REINSTALL_BLOCK_COUNT` | The DBA's settings decide; these answer only a missing row (G1, done) |
| Fallbacks only | `POLICY_STEP_UP_SCORE`, `POLICY_REVIEW_SCORE`, `POLICY_BLOCK_SCORE`, `POLICY_DEVICE_ACCOUNT_BLOCK_COUNT`, `POLICY_ACCOUNT_DEVICE_BLOCK_COUNT`, `INTEGRITY_DEVICE_MEMORY_HOURS` | Used only when the settings row is missing |

## 4. App developers — the app

**Build settings** (Flutter `--dart-define`):

| Setting | Default | Meets |
|---|---|---|
| `API_BASE_URL` | none: a build without it fails fast | DevOps' endpoint |
| `STEPUP_ENABLED` | `true` in the reference harness | the DBA's `stepup_method` (needed for `screen_lock` and both) |
| `STEPUP_FACTOR` | `passcode`; `biometric` possible | only the fallback: the app reads the DBA's `stepup_factor` from `GET /v1/policy/step-up` before it creates the key, and replaces or asks to re-enrol a key of another factor (G4, done; analysed, not yet run on a phone) |
| `STEPUP_MODE`, `STEPUP_WINDOW_SECONDS` | `per_use`, 0 | only the fallback for the DBA's `stepup_mode`, `stepup_window_seconds`, read the same way |
| `MEASURE_LOCAL_ADDRESSES` | `false` | the app's key to the optional measurement `local_addresses`; the DBA holds the other (`optional_measurements`). Both must be on (DESIGN.md 80) |

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

**Permissions they declare**: `ACCESS_NETWORK_STATE` on Android (normal, no prompt) for the network
probe — whether a VPN or a proxy is in use (DESIGN.md 80).

**Values they hand to DevOps, per release**: the signing certificate's SHA-256, the APK SHA-256
and its W^X baseline (DESIGN.md 62), the iOS team, bundle and signing identifiers and executable hash.

## 5. Measurements — what they get

| Measurement | Where | Reachable by |
|---|---|---|
| Every probe's raw result from every scan | `integrity_reports.probe_results` | `GET /v1/business/integrity-reports`, paged, filtered by phone, installation or account (G5, done) |
| Each scan's reasons, points, verdict, evidence quality, finding score | the scan response; `integrity_reports` | the app; SQL |
| Each decision: relationship counts, integrity state, device memory, the server's own observations, request rate, business-event counts, reasons, action | `risk_policy_decisions`; returned on sign-in, refresh and `/v1/policy/me` | the app; SQL |
| What the server itself saw (wrong passwords, unknown accounts, failed step-ups and PINs, denials, exhausted budgets, re-enrolments, stolen tokens, replays) | `server_observations` | decisions; the business graph; SQL |
| The phone–account graph with business events and observations | `GET /v1/business/graph` | the customer's backend |
| When an approval stopped covering, and why | `GET /v1/business/acceptance-lapses` | the customer's backend |
| A catalog of every reason code, observation kind, probe field and context field | [MEASUREMENTS.md](MEASUREMENTS.md) | the gate fails if the source can emit a code it does not name (G5, done) |
| The OS version and security patch level, a VPN, an HTTP proxy | the `device` and `network` probes, every scan (collectors Android 4, iOS 3) | the report feed; reasons at 0 points (DESIGN.md 80) |
| Optional: the phone's own IP addresses; the request's source address and User-Agent | `local_addresses` (DBA + app); `source_ip`, `user_agent` in decisions (DBA) | the report feed; SQL (DESIGN.md 80) |

## 6. Answers to the owner's four questions

1. **What we fix** — the integrity weights and bands, measurement rules, the protocol and its token
   lifetimes, the invariants. The relationship rules and how long a session lives moved to the DBA in
   migration 021 (G1, G8).
2. **The DBA's and business analysts' domain** — 89 settings, each with the owner's default and a
   description in the row, all of them in the guide, generated from the migrations (G7).
3. **The app developers' domain** — the native code and a working reference client exist, and the
   client now follows the server's step-up policy (G4); there is still no package to depend on (G2) and
   no guide written for them (G3), both deferred by the owner until testing is finished.
4. **Options, defaults and documentation** — on the server side, yes, with a measurement catalog (G5)
   and a complete settings reference (G7); on the app side, not yet (G2, G3); the front page (G6) comes
   after G3.

## 7. Gaps, most important first

The owner's answers of 2026-10-14 are quoted; `DESIGN.md` §79 records what was built.

| # | Gap | Owner's answer | Status |
|---|---|---|---|
| G1 | Relationship policy still in code or environment | *"put them under DBA"* | **Done** — migration 021, seeded at the values the code used (`b714b88`) |
| G2 | No Flutter package: an app developer copies code out of the harness | *"defer it to later after we have finished testing. It will be done. Note it down. Just not now."* | **Deferred** — after testing; a Flutter plugin package with the Dart API, models and the Android and iOS native code, the harness depending on it. Package name, versioning and where it is published are the owner's to decide then |
| G3 | No guide for app developers | *"do after G2"* | **Deferred** — after G2 |
| G4 | The app's step-up factor and mode were fixed at build time | *"modify it so it can follow DBA choice"* | **Done** — `GET /v1/policy/step-up`, `step_up` in `/v1/account/me`, the Dart client creates the key to match (`493fc5c`, `5e269c5`); analysed, **not yet run on a phone** |
| G5 | No catalog of measurements; raw probe results only by SQL | *"build it"* | **Done** — `GET /v1/business/integrity-reports` (`598e610`) and [MEASUREMENTS.md](MEASUREMENTS.md), checked by the gate (`651791e`) |
| G6 | `README.md` is the Flutter template | *"after G3"* | **Deferred** — after G3 |
| G7 | Guide §5 listed "notable" settings, not all | *"update it now"* | **Done** — generated from the migrations by `tools/settings_reference.py`, checked by the gate (`7dda77b`) |
| G8 | The refresh lifetime (30 days) was fixed | *"make it DBA configurable. 30-day is default but to check with /advisor"* | **Done** — `refresh_idle_days` 30 (1–90), each refresh extending it, the default the advisor confirmed; `session_max_days` 0 (off, up to 365) caps a session from its first sign-in (`b714b88`) |
| G9 | Python is named as a client SDK; there is none beyond the conformance suite's test client | *"can you elaborate?"*; then (2026-10-15) *"Should we include native android/kotlin instead? Or both? What other options are there?"* | **Recommended, awaiting the owner**: native Android (Kotlin) and iOS (Swift) SDKs as the base — the native code exists — with Flutter, .NET MAUI and React Native as thin wrappers; Python only as a server-side client of the business API. Packaging belongs with G2 |
| G10 | Migrations 015–021 have not run on SQL Server | *"fill the gaps, we will do that afterwards"* | **Deferred** — one RDS round, afterwards |
| — | Support staff could not unlock a PIN | *"Support unlock: build the mechanism. Add this to one of the options available to the relevant team."* | **Done** — `POST /v1/business/app-pin/unlock` and `/reset`, the DBA's `app_pin_support`, off by default (`68393c5`); guide §12 |
