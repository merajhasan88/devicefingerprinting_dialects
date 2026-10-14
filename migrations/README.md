# Database migrations

Versioned schema for the Device Trust server, one directory per dialect. **The
application never creates or alters schema.** It reads `schema_migrations` at
startup, compares it to the version it requires, and refuses to serve on a
mismatch.

That separation is deliberate. An application that issues `CREATE`/`ALTER`
against production needs DDL rights permanently, which is a finding in its own
right, and most database administrators will refuse to deploy it.

## Applying

**PostgreSQL 13+**

```bash
psql "host=<host> dbname=<db> user=<ddl-user> sslmode=verify-full sslrootcert=<ca.pem>" \
     -v ON_ERROR_STOP=1 -f postgresql/001_initial.sql
```

**SQL Server 2016+** (the scripts use `GO` batch separators, so run them with
`sqlcmd` or SSMS rather than through a driver)

```bash
sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i sqlserver/001_initial.sql
```

Apply migrations **in ascending version order**; each one records its own row in
`schema_migrations`, and the server requires the highest version it knows about.

| version | file | what it adds |
|---|---|---|
| 1 | `001_initial.sql` | the eleven base tables |
| 2 | `002_key_security.sql` | `app_installations.key_security_level` / `key_hardware_backed` / `key_provider` |
| 3 | `003_risk_policy_settings.sql` | DBA-tunable `risk_policy_settings` (step-up + behavioural-signal knobs) |
| 4 | `004_stepup_key.sql` | optional per-installation `stepup_public_key_jwk` / `stepup_key_algorithm` |
| 5 | `005_stepup_key_auth.sql` | reported step-up key `stepup_key_factor` / `stepup_key_mode` / `stepup_key_window_seconds` |
| 6 | `006_device_account_policy.sql` | seeds the DBA-tunable accounts-per-device policy (owner defaults: 2 elevated, 3 review, 4 block; elevated never refuses) |
| 7 | `007_stepup_key_account.sql` | `app_installations.stepup_key_account_id`: the account a re-enrolled step-up key belongs to |
| 8 | `008_installation_verified.sql` | `app_installations.verified_at`: when the installation first proved its key; only proven installations count toward a device (backfilled from existing evidence; no row deleted) |
| 9 | `009_installation_device_confirmed.sql` | `app_installations.device_confirmed_at`: a hint-linked installation confirmed by a returning account; only established installations spread an integrity block to the rest of the device (existing hint-linked rows backfilled as confirmed; no row deleted) |
| 10 | `010_runtime_growth_and_eligibility.sql` | seeds `wx_far_above_baseline_percent` (200), `developer_options_refuses` (0), `adb_enabled_refuses` (0): W^X growth up to the percentage is advisory, developer options and ADB become optional eligibility rules (joint review R1) |
| 11 | `011_limited_sessions.sql` | `refresh_sessions.scope` / `limited_causes`, the `session_upgrade_requests` table (audit evidence: grant SELECT, INSERT, UPDATE — never DELETE), and the eight limited-session settings at the owner's defaults |
| 12 | `012_policy_bands_and_devices_per_account.sql` | seeds the relationship-risk bands (`policy_step_up_score` 30, `policy_review_score` 60, `policy_block_score` 90) and the devices-per-account policy (`account_devices_*`: 2 elevated, 3 review, 5 block) at the owner's defaults |
| 13 | `013_upgrade_acceptance.sql` | `refresh_sessions.accepted_causes` / `accepted_until`: the soft causes an upgrade's proof accepted, kept with the session; seeds `upgrade_acceptance_hours` (720) |
| 14 | `014_superseded_requests.sql` | `session_upgrade_requests.superseded_at`: a newer approval request from the same installation for the same account supersedes its pending ones, so an approver sees one request per phone (rows kept as evidence) |
| 15 | `015_evidence_quality.sql` | `integrity_reports.evidence_quality` / `finding_score`: what a scan measured, and the score of its findings alone (only findings enter the device memory); an index for the per-request family check; seeds `collection_problems_block` (0), `integrity_device_memory_hours` (24), `complete_evidence_paths` (''), `complete_evidence_max_age_seconds` (600), `incomplete_evidence_review_after` (3) |
| 16 | `016_scoped_acceptances.sql` | `session_acceptances` (what each upgrade accepted: reasons, points, counts, approver, scan and build; revocable) and `acceptance_lapses` (when an approved session met a reason it did not cover — the business's measurement); `refresh_sessions.acceptance_id`; `session_upgrade_requests.causes` / `reasons` / counts (what the approver is shown); `risk_policy_decisions.acceptance_id`; seeds `acceptance_auto_cover_reasons` ('') |
| 17 | `017_business_events.sql` | `business_events` (events the customer's backend reports for an account: opaque IDs, short codes, an amount, a keyed hash of a subject — no personal data; never updated or deleted); seeds `business_event_types` (''), `business_graph_depth` (2), `business_graph_max_nodes` (200) |
| 18 | `018_legacy_acceptances.sql` | seeds `legacy_acceptances` (`carry`): an approval granted before 016 is kept as what it covers at its first use, until its expiry; `drop` makes it cover nothing |
| 19 | `019_server_observations.sql` | `server_observations` (what the server itself saw: wrong passwords, sign-ins to unknown accounts, step-up proofs that did not verify, exhausted approval budgets, step-up re-enrolments — opaque IDs only; never updated or deleted) and an index for denied approvals per phone; seeds `cross_checks_enabled` (0: measured into every decision, scored nowhere), `cross_check_window_hours` (24), each rule's `_count` / `_points`, and `device_approvals_denied_effect` (`limit`: a denied phone is held at review, never blocked by the denial) |
| 20 | `020_app_pin.sql` | `app_pins` (one app PIN per account, stored only as bcrypt over a keyed HMAC, with its failure count and lock; never deleted); seeds `stepup_method` (`screen_lock`, the interim default), `app_pin_required_paths` (''), `app_pin_length` (6), `app_pin_max_failures` (5) and the `device_app_pin_failures` rule |

All scripts are guarded and safe to re-run.

## Application privileges

Grant the application principal DML only — never DDL:

```sql
-- PostgreSQL
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- SQL Server
ALTER ROLE db_datareader ADD MEMBER app_user;
ALTER ROLE db_datawriter ADD MEMBER app_user;
```

**New tables from later migrations.** On **PostgreSQL** the grant above is point-in-time — it does
**not** cover tables a later migration adds (this bit `risk_policy_settings` in migration 003). Set it
once with default privileges, run as the migration/DDL role:

```sql
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
```

or re-run `GRANT ... ON ALL TABLES` after each migration. On **SQL Server**, `db_datareader` /
`db_datawriter` membership already covers future tables, so nothing extra is needed.
`risk_policy_settings` is **read-only** for the application (the DBA writes it), so `SELECT` alone
suffices there.

**Migration 011 adds `session_upgrade_requests`.** Without default privileges it needs its own grant
(the test database did): `GRANT SELECT, INSERT, UPDATE ON session_upgrade_requests TO app_user;`. It
is audit evidence — every approval request and assertion nonce and what became of it — and the server
never deletes from it, so it needs no `DELETE`.

**Migration 020 adds `app_pins`.** Without default privileges: `GRANT SELECT, INSERT, UPDATE ON
app_pins TO app_user;` — a credential store: the server never deletes from it (DESIGN.md 78).

**Migration 019 adds `server_observations`.** Without default privileges: `GRANT SELECT, INSERT ON
server_observations TO app_user;` — the server only ever inserts into it (DESIGN.md 77).

## Version contract

`schema_migrations(version, applied_at, description)` holds one row per applied
migration. The server requires the highest version it knows about; a database
that is behind or ahead fails startup with a clear message rather than
misbehaving at runtime.

## Dialect differences that matter

These are not stylistic. Each one changes behaviour if translated naively.

| Concern | PostgreSQL | SQL Server | Why |
|---|---|---|---|
| Nullable unique key | `UNIQUE (platform, reinstall_hint_hash)` | **filtered unique index** `WHERE reinstall_hint_hash IS NOT NULL` | SQL Server treats NULLs as *equal* in a unique constraint, so a plain constraint allows only ONE device per platform without a reinstall hint |
| Key comparison | default collation | `COLLATE Latin1_General_BIN2` | The RDS default collation is case-insensitive, under which `'aB' = 'Ab'`. Binary collation keeps key comparison byte-exact |
| UUIDs | `uuid` | `char(36)` binary collation | `uniqueidentifier` has a mixed-endian representation that differs across drivers |
| Timestamps | `timestamptz`, `NOW()` | `datetimeoffset(3)`, **`SYSUTCDATETIME()`** | `GETDATE()` is server-local and would silently shift every expiry window |
| JSON | `jsonb` | **`nvarchar(max)`** + `ISJSON` check | SQL Server 2016/2017 have no UTF-8 collation; probe output can be non-ASCII and `varchar` would corrupt it |
| Binary | `bytea` | `varbinary(255)` | bcrypt hashes |
| Booleans | `boolean` | `bit` | |

## Anti-replay, and how not to break it

`access_proof_nonces` has one job: its primary key. The row is inserted only
after a request signature verifies, so a duplicate key *is* the replay. On
PostgreSQL that is `INSERT ... ON CONFLICT DO NOTHING RETURNING`.

SQL Server has no equivalent, and both obvious translations reopen replay:
`MERGE` is racy without `HOLDLOCK`, and `IF NOT EXISTS(...) INSERT` under READ
COMMITTED lets two concurrent identical proofs both succeed. **Insert, and treat
a duplicate-key error (2627/2601) as the replay signal** — identical atomicity on
both engines, and simpler than either alternative.

Similarly, `SELECT ... FOR UPDATE` (refresh-session reuse detection) becomes
`WITH (UPDLOCK, ROWLOCK)`. PostgreSQL is MVCC; SQL Server's READ COMMITTED is
not, and missing this lets family revocation be raced.
