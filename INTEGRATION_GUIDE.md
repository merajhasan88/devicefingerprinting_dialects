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
`migrations/<engine>/001…013` in order; the server only reads `schema_migrations` and refuses to serve
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
defaults and changed by your DBA, never by the server. Notable keys:

| setting | default | meaning |
|---|---|---|
| `policy_step_up_score` / `policy_review_score` / `policy_block_score` | 30 / 60 / 90 | the relationship-risk bands: below 30 allow; 30–59 step-up (recorded, allowed unless `elevated_risk_refuses` is 1); 60–89 review (refused in enforce mode); 90 and above block. They must rise |
| `device_accounts_elevated_count` / `_points` | 2 / 35 | a phone shared by two people: scored, never refused by itself |
| `device_accounts_review_count` / `_points` | 3 / 60 | a third account on one phone: held for review, so refused in enforce mode |
| `device_accounts_block_count` | 4 | blocked |
| `account_devices_elevated_count` / `_points` | 2 / 35 | one account on a second device: scored, never refused by itself |
| `account_devices_review_count` / `_points` | 3 / 60 | a third device: held for review, so refused in enforce mode |
| `account_devices_block_count` | 5 | blocked |
| `elevated_risk_refuses` | 0 | 1 makes an elevated decision refuse in enforce mode |
| `stepup_required_paths` | empty | comma-separated request paths that require a step-up proof |
| `stepup_factor` / `stepup_mode` / `stepup_window_seconds` | passcode / per_use / 0 | the step-up policy |
| `wx_far_above_baseline_percent` | 200 | W^X growth above a build's pin is advisory up to this percentage of it and +40 beyond (section 3); minimum 100 |
| `developer_options_refuses` / `adb_enabled_refuses` | 0 / 0 | eligibility rules: 1 refuses a device whose latest scan reports the setting on (below) |
| `rate_anomaly_*`, `population_baseline_*` | off | advisory signals |

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

**What an upgrade accepts.** An upgrade made with a proof (routes 1–3) while soft causes remain
accepts exactly those causes for that sign-in: the response carries `accepted_causes` and
`accepted_until`, and both tokens carry them. Until then — `upgrade_acceptance_hours` (default 720,
the refresh lifetime, never longer; `0` keeps nothing) or until the user signs out — protected
requests pass those causes (the outcome is marked `accepted_by_upgrade`) and a refresh keeps the
session full. Anything worse is judged afresh: a cause the proof did not cover refuses the request and
narrows the session at its next refresh (dropping the acceptance), and a block, an eligibility rule or
a device-memory block refuses as always. Two consequences to know: an accepted `elevated` integrity
verdict no longer needs a step-up proof on every ordinary request (your `stepup_required_paths`
still do), and a phone approving someone else's upgrade gets no acceptance of its own — it must be
clean.

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
  `denied`, `expired`, `used`), so poll no faster than every five seconds (with rate limiting on, a
  faster poller gets 429 `rate_limited`). Requests expire after
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
recover**; make your app handle `scope`, `session_limited`, `upgrade_routes` and the upgrade flows —
**the Flutter and .NET SDKs do not handle them yet**; and measure in observe mode, from the stored
decisions, how many sign-ins would have been limited.
