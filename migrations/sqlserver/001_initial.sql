-- Device Trust schema, SQL Server 2016+
-- Migration 001: initial schema
--
-- Run with sqlcmd or SSMS as a DDL role (GO batch separators are used):
--   sqlcmd -S host,1433 -d DeviceTrust -U user -P pass -i 001_initial.sql
--
-- The application does NOT create or alter schema at runtime; it verifies the
-- version in schema_migrations at startup and refuses to serve on a mismatch.
-- Grant the application principal only DML rights on these tables.
--
-- Dialect notes, each deliberate:
--
--  * char(36)/char(64) COLLATE Latin1_General_BIN2 for UUIDs and SHA-256 hex.
--    The RDS default collation is CASE-INSENSITIVE, under which 'aB' = 'Ab';
--    a binary collation keeps key comparison byte-exact. uniqueidentifier is
--    avoided because its string/binary byte order differs across drivers.
--  * datetimeoffset(3) with SYSUTCDATETIME(). Never GETDATE(): it returns
--    server-local time and would silently shift every expiry window.
--  * nvarchar(max) for JSON, not varchar. SQL Server 2016/2017 have no UTF-8
--    collation and probe output can contain non-ASCII (OEM build tags, error
--    strings); varchar would corrupt it.
--  * The unique constraint on (platform, reinstall_hint_hash) is expressed as a
--    FILTERED UNIQUE INDEX. SQL Server treats NULLs as EQUAL in a unique
--    constraint, so a plain constraint would permit only ONE device per
--    platform without a reinstall hint. PostgreSQL permits many. Filtering on
--    IS NOT NULL restores PostgreSQL's behaviour.

IF OBJECT_ID('dbo.schema_migrations', 'U') IS NULL
CREATE TABLE dbo.schema_migrations (
    version     int NOT NULL PRIMARY KEY,
    applied_at  datetimeoffset(3) NOT NULL CONSTRAINT df_schema_migrations_applied DEFAULT SYSUTCDATETIME(),
    description nvarchar(400) NOT NULL
);
GO

IF OBJECT_ID('dbo.recognized_devices', 'U') IS NULL
CREATE TABLE dbo.recognized_devices (
    device_id           char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    platform            varchar(16) NOT NULL,
    reinstall_hint_hash char(64) COLLATE Latin1_General_BIN2 NULL,
    status              varchar(16) NOT NULL CONSTRAINT df_recognized_devices_status DEFAULT 'active',
    created_at          datetimeoffset(3) NOT NULL CONSTRAINT df_recognized_devices_created DEFAULT SYSUTCDATETIME(),
    last_seen_at        datetimeoffset(3) NOT NULL CONSTRAINT df_recognized_devices_seen DEFAULT SYSUTCDATETIME()
);
GO

-- See dialect note: filtered, so multiple hint-less devices per platform are allowed.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'recognized_devices_platform_hint_unique')
CREATE UNIQUE INDEX recognized_devices_platform_hint_unique
    ON dbo.recognized_devices(platform, reinstall_hint_hash)
    WHERE reinstall_hint_hash IS NOT NULL;
GO

IF OBJECT_ID('dbo.app_installations', 'U') IS NULL
CREATE TABLE dbo.app_installations (
    installation_id         char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    device_id               char(36) COLLATE Latin1_General_BIN2 NOT NULL
                            CONSTRAINT fk_app_installations_device REFERENCES dbo.recognized_devices(device_id),
    key_algorithm           varchar(16) NOT NULL,
    public_key_jwk          nvarchar(max) NOT NULL CONSTRAINT ck_app_installations_jwk CHECK (ISJSON(public_key_jwk) = 1),
    -- Retained so first-generation RS256 rows stay verifiable beside ES256 keys.
    public_key_n            nvarchar(max) NULL,
    public_key_e            nvarchar(max) NULL,
    key_thumbprint          char(64) COLLATE Latin1_General_BIN2 NOT NULL UNIQUE,
    registration_method     varchar(32) NOT NULL,
    registration_confidence varchar(16) NOT NULL,
    status                  varchar(16) NOT NULL CONSTRAINT df_app_installations_status DEFAULT 'active',
    created_at              datetimeoffset(3) NOT NULL CONSTRAINT df_app_installations_created DEFAULT SYSUTCDATETIME(),
    last_seen_at            datetimeoffset(3) NOT NULL CONSTRAINT df_app_installations_seen DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'app_installations_device_idx')
CREATE INDEX app_installations_device_idx ON dbo.app_installations(device_id);
GO

IF OBJECT_ID('dbo.installation_challenges', 'U') IS NULL
CREATE TABLE dbo.installation_challenges (
    challenge_id    char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    installation_id char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_installation_challenges_install REFERENCES dbo.app_installations(installation_id),
    purpose         varchar(128) NOT NULL,
    payload_sha256  char(64) COLLATE Latin1_General_BIN2 NOT NULL,
    expires_at      datetimeoffset(3) NOT NULL,
    used_at         datetimeoffset(3) NULL,
    created_at      datetimeoffset(3) NOT NULL CONSTRAINT df_installation_challenges_created DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'installation_challenges_open_idx')
CREATE INDEX installation_challenges_open_idx
    ON dbo.installation_challenges(installation_id, expires_at)
    WHERE used_at IS NULL;
GO

IF OBJECT_ID('dbo.demo_accounts', 'U') IS NULL
CREATE TABLE dbo.demo_accounts (
    account_id    char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    handle_lookup char(64) COLLATE Latin1_General_BIN2 NOT NULL UNIQUE,
    password_hash varbinary(255) NOT NULL,
    created_at    datetimeoffset(3) NOT NULL CONSTRAINT df_demo_accounts_created DEFAULT SYSUTCDATETIME()
);
GO

IF OBJECT_ID('dbo.device_account_links', 'U') IS NULL
CREATE TABLE dbo.device_account_links (
    device_id             char(36) COLLATE Latin1_General_BIN2 NOT NULL
                          CONSTRAINT fk_device_account_links_device REFERENCES dbo.recognized_devices(device_id),
    account_id            char(36) COLLATE Latin1_General_BIN2 NOT NULL
                          CONSTRAINT fk_device_account_links_account REFERENCES dbo.demo_accounts(account_id),
    first_installation_id char(36) COLLATE Latin1_General_BIN2 NOT NULL
                          CONSTRAINT fk_device_account_links_install REFERENCES dbo.app_installations(installation_id),
    first_seen_at         datetimeoffset(3) NOT NULL CONSTRAINT df_device_account_links_first DEFAULT SYSUTCDATETIME(),
    last_seen_at          datetimeoffset(3) NOT NULL CONSTRAINT df_device_account_links_last DEFAULT SYSUTCDATETIME(),
    CONSTRAINT pk_device_account_links PRIMARY KEY (device_id, account_id)
);
GO

IF OBJECT_ID('dbo.refresh_sessions', 'U') IS NULL
CREATE TABLE dbo.refresh_sessions (
    session_id      char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    family_id       char(36) COLLATE Latin1_General_BIN2 NOT NULL,
    account_id      char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_refresh_sessions_account REFERENCES dbo.demo_accounts(account_id),
    device_id       char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_refresh_sessions_device REFERENCES dbo.recognized_devices(device_id),
    installation_id char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_refresh_sessions_install REFERENCES dbo.app_installations(installation_id),
    expires_at      datetimeoffset(3) NOT NULL,
    revoked_at      datetimeoffset(3) NULL,
    replaced_by     char(36) COLLATE Latin1_General_BIN2 NULL,
    created_at      datetimeoffset(3) NOT NULL CONSTRAINT df_refresh_sessions_created DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'refresh_sessions_family_idx')
CREATE INDEX refresh_sessions_family_idx ON dbo.refresh_sessions(family_id);
GO

-- Anti-replay. The primary key is the whole defence: the row is inserted only
-- after the request signature verifies, and a duplicate key IS the replay.
-- Do NOT reimplement this as MERGE (racy without HOLDLOCK) or as
-- IF NOT EXISTS(...) INSERT (racy under READ COMMITTED). Insert and catch the
-- duplicate-key error (2627/2601).
IF OBJECT_ID('dbo.access_proof_nonces', 'U') IS NULL
CREATE TABLE dbo.access_proof_nonces (
    nonce_hash       char(64) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    installation_id  char(36) COLLATE Latin1_General_BIN2 NOT NULL
                     CONSTRAINT fk_access_proof_nonces_install REFERENCES dbo.app_installations(installation_id),
    access_token_jti varchar(128) NOT NULL,
    created_at       datetimeoffset(3) NOT NULL CONSTRAINT df_access_proof_nonces_created DEFAULT SYSUTCDATETIME(),
    expires_at       datetimeoffset(3) NOT NULL
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'access_proof_nonces_installation_idx')
CREATE INDEX access_proof_nonces_installation_idx
    ON dbo.access_proof_nonces(installation_id, expires_at);
GO

IF OBJECT_ID('dbo.risk_policy_decisions', 'U') IS NULL
CREATE TABLE dbo.risk_policy_decisions (
    decision_id        char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    event_type         varchar(32) NOT NULL,
    account_id         char(36) COLLATE Latin1_General_BIN2 NULL,
    device_id          char(36) COLLATE Latin1_General_BIN2 NOT NULL
                       CONSTRAINT fk_risk_policy_device REFERENCES dbo.recognized_devices(device_id),
    installation_id    char(36) COLLATE Latin1_General_BIN2 NOT NULL
                       CONSTRAINT fk_risk_policy_install REFERENCES dbo.app_installations(installation_id),
    policy_mode        varchar(16) NOT NULL,
    recommended_action varchar(16) NOT NULL,
    effective_action   varchar(16) NOT NULL,
    score              int NOT NULL,
    reasons            nvarchar(max) NOT NULL CONSTRAINT ck_risk_policy_reasons CHECK (ISJSON(reasons) = 1),
    context            nvarchar(max) NOT NULL CONSTRAINT ck_risk_policy_context CHECK (ISJSON(context) = 1),
    created_at         datetimeoffset(3) NOT NULL CONSTRAINT df_risk_policy_created DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'risk_policy_decisions_device_idx')
CREATE INDEX risk_policy_decisions_device_idx ON dbo.risk_policy_decisions(device_id, created_at DESC);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'risk_policy_decisions_account_idx')
CREATE INDEX risk_policy_decisions_account_idx ON dbo.risk_policy_decisions(account_id, created_at DESC);
GO

IF OBJECT_ID('dbo.integrity_challenges', 'U') IS NULL
CREATE TABLE dbo.integrity_challenges (
    challenge_id    char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    installation_id char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_integrity_challenges_install REFERENCES dbo.app_installations(installation_id),
    device_id       char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_integrity_challenges_device REFERENCES dbo.recognized_devices(device_id),
    platform        varchar(16) NOT NULL,
    nonce_sha256    char(64) COLLATE Latin1_General_BIN2 NOT NULL,
    required_probes nvarchar(max) NOT NULL CONSTRAINT ck_integrity_challenges_probes CHECK (ISJSON(required_probes) = 1),
    expires_at      datetimeoffset(3) NOT NULL,
    used_at         datetimeoffset(3) NULL,
    created_at      datetimeoffset(3) NOT NULL CONSTRAINT df_integrity_challenges_created DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'integrity_challenges_installation_idx')
CREATE INDEX integrity_challenges_installation_idx
    ON dbo.integrity_challenges(installation_id, created_at DESC);
GO

-- Reported challenges are audit evidence. No ON DELETE CASCADE: expired
-- challenge cleanup must skip any challenge that has a report.
IF OBJECT_ID('dbo.integrity_reports', 'U') IS NULL
CREATE TABLE dbo.integrity_reports (
    report_id         char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    challenge_id      char(36) COLLATE Latin1_General_BIN2 NOT NULL UNIQUE
                      CONSTRAINT fk_integrity_reports_challenge REFERENCES dbo.integrity_challenges(challenge_id),
    installation_id   char(36) COLLATE Latin1_General_BIN2 NOT NULL
                      CONSTRAINT fk_integrity_reports_install REFERENCES dbo.app_installations(installation_id),
    device_id         char(36) COLLATE Latin1_General_BIN2 NOT NULL
                      CONSTRAINT fk_integrity_reports_device REFERENCES dbo.recognized_devices(device_id),
    platform          varchar(16) NOT NULL,
    collector_version int NOT NULL,
    score             int NOT NULL,
    verdict           varchar(16) NOT NULL,
    hard_block        bit NOT NULL CONSTRAINT df_integrity_reports_hardblock DEFAULT 0,
    reasons           nvarchar(max) NOT NULL CONSTRAINT ck_integrity_reports_reasons CHECK (ISJSON(reasons) = 1),
    probe_results     nvarchar(max) NOT NULL CONSTRAINT ck_integrity_reports_probes CHECK (ISJSON(probe_results) = 1),
    report_sha256     char(64) COLLATE Latin1_General_BIN2 NOT NULL,
    created_at        datetimeoffset(3) NOT NULL CONSTRAINT df_integrity_reports_created DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'integrity_reports_installation_idx')
CREATE INDEX integrity_reports_installation_idx ON dbo.integrity_reports(installation_id, created_at DESC);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'integrity_reports_device_idx')
CREATE INDEX integrity_reports_device_idx ON dbo.integrity_reports(device_id, created_at DESC);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 1)
-- Guarded like every other statement in this file, so the migration can be
-- re-run safely. The PostgreSQL counterpart uses ON CONFLICT DO NOTHING.
IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 1)
    INSERT INTO dbo.schema_migrations (version, description) VALUES (1, 'initial schema');
GO
