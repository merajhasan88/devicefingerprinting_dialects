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
