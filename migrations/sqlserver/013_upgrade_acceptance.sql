-- Device Trust schema, SQL Server 2016+
-- Migration 013: an upgrade's acceptance, kept with the session
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 72). MERGE seeds
-- idempotently and never overwrites a value the DBA has tuned.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 013_upgrade_acceptance.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.refresh_sessions', 'accepted_causes') IS NULL
    ALTER TABLE dbo.refresh_sessions ADD accepted_causes varchar(128) NULL;
GO

IF COL_LENGTH('dbo.refresh_sessions', 'accepted_until') IS NULL
    ALTER TABLE dbo.refresh_sessions ADD accepted_until datetimeoffset(3) NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('upgrade_acceptance_hours', '720', 'Hours an upgrade keeps accepting the soft causes its proof covered (never past the 30-day refresh lifetime). 0 = none: protected requests and refreshes judge them again.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 13)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (13, 'upgrade acceptance kept with the session');
GO
