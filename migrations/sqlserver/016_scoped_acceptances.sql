-- Device Trust schema, SQL Server 2016+
-- Migration 016: an upgrade accepts exactly what was approved
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 76). The server
-- never deletes from session_acceptances or acceptance_lapses: grant the
-- application principal SELECT, INSERT, UPDATE on the first and SELECT, INSERT
-- on the second. MERGE never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 016_scoped_acceptances.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.session_acceptances', 'U') IS NULL
CREATE TABLE dbo.session_acceptances (
    acceptance_id            char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    family_id                char(36) COLLATE Latin1_General_BIN2 NOT NULL,
    account_id               char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_acceptances_account REFERENCES dbo.demo_accounts(account_id),
    device_id                char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_acceptances_device REFERENCES dbo.recognized_devices(device_id),
    installation_id          char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_acceptances_install REFERENCES dbo.app_installations(installation_id),
    route                    varchar(16) NOT NULL,
    request_id               char(36) COLLATE Latin1_General_BIN2 NULL,
    approved_by_installation char(36) COLLATE Latin1_General_BIN2 NULL,
    causes                   varchar(128) NOT NULL,
    reasons                  nvarchar(max) NOT NULL CONSTRAINT ck_acceptances_reasons CHECK (ISJSON(reasons) = 1),
    device_accounts          int NULL,
    account_devices          int NULL,
    evidence_quality         varchar(16) NULL,
    integrity_report_id      char(36) COLLATE Latin1_General_BIN2 NULL,
    apk_sha256               varchar(64) NULL,
    created_at               datetimeoffset(3) NOT NULL CONSTRAINT df_acceptances_created DEFAULT SYSUTCDATETIME(),
    expires_at               datetimeoffset(3) NOT NULL,
    revoked_at               datetimeoffset(3) NULL
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'session_acceptances_family_idx')
    CREATE INDEX session_acceptances_family_idx ON dbo.session_acceptances(family_id);
GO

IF OBJECT_ID('dbo.acceptance_lapses', 'U') IS NULL
CREATE TABLE dbo.acceptance_lapses (
    acceptance_id   char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT fk_lapses_acceptance REFERENCES dbo.session_acceptances(acceptance_id),
    reason_code     varchar(96) NOT NULL,
    source          varchar(16) NOT NULL,
    points          int NOT NULL,
    account_id      char(36) COLLATE Latin1_General_BIN2 NOT NULL,
    installation_id char(36) COLLATE Latin1_General_BIN2 NOT NULL,
    event_type      varchar(32) NOT NULL,
    occurred_at     datetimeoffset(3) NOT NULL CONSTRAINT df_lapses_occurred DEFAULT SYSUTCDATETIME(),
    CONSTRAINT pk_acceptance_lapses PRIMARY KEY (acceptance_id, reason_code)
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'acceptance_lapses_occurred_idx')
    CREATE INDEX acceptance_lapses_occurred_idx ON dbo.acceptance_lapses(occurred_at);
GO

IF COL_LENGTH('dbo.refresh_sessions', 'acceptance_id') IS NULL
    ALTER TABLE dbo.refresh_sessions ADD acceptance_id char(36) COLLATE Latin1_General_BIN2 NULL;
GO

IF COL_LENGTH('dbo.session_upgrade_requests', 'causes') IS NULL
    ALTER TABLE dbo.session_upgrade_requests ADD causes varchar(128) NULL;
GO

IF COL_LENGTH('dbo.session_upgrade_requests', 'reasons') IS NULL
    ALTER TABLE dbo.session_upgrade_requests
        ADD reasons nvarchar(max) NULL CONSTRAINT ck_upgrade_requests_reasons CHECK (ISJSON(reasons) = 1);
GO

IF COL_LENGTH('dbo.session_upgrade_requests', 'device_accounts') IS NULL
    ALTER TABLE dbo.session_upgrade_requests ADD device_accounts int NULL;
GO

IF COL_LENGTH('dbo.session_upgrade_requests', 'account_devices') IS NULL
    ALTER TABLE dbo.session_upgrade_requests ADD account_devices int NULL;
GO

IF COL_LENGTH('dbo.risk_policy_decisions', 'acceptance_id') IS NULL
    ALTER TABLE dbo.risk_policy_decisions ADD acceptance_id char(36) COLLATE Latin1_General_BIN2 NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('acceptance_auto_cover_reasons', '', 'Reason codes an approved session accepts automatically even if they appear after the approval, comma-separated. A business decision; empty (owner default) = every new reason needs a new decision. Collection problems are never covered.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 16)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (16, 'an upgrade accepts exactly what was approved');
GO
