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
`migrations/<engine>/001…010` in order; the server only reads `schema_migrations` and refuses to serve
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
| `device_accounts_elevated_count` / `_points` | 2 / 35 | a phone shared by two people: scored, never refused by itself |
| `device_accounts_review_count` / `_points` | 3 / 60 | held for review |
| `device_accounts_block_count` | 4 | blocked |
| `elevated_risk_refuses` | 0 | 1 makes an elevated decision refuse in enforce mode |
| `stepup_required_paths` | empty | comma-separated request paths that require a step-up proof |
| `stepup_factor` / `stepup_mode` / `stepup_window_seconds` | passcode / per_use / 0 | the step-up policy |
| `wx_far_above_baseline_percent` | 200 | W^X growth above a build's pin is advisory up to this percentage of it and +40 beyond (section 3); minimum 100 |
| `developer_options_refuses` / `adb_enabled_refuses` | 0 / 0 | eligibility rules: 1 refuses a device whose latest scan reports the setting on (below) |
| `rate_anomaly_*`, `population_baseline_*` | off | advisory signals |

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
