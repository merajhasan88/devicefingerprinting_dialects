-- Device Trust schema, SQL Server 2016+
-- Migration 018: approvals granted before migration 016 are carried over
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 76). MERGE never
-- overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 018_legacy_acceptances.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('legacy_acceptances', 'carry', 'Approvals granted before migration 016: carry (owner default) = keep each as what it covers at its first use, until its expiry; drop = they cover nothing and their users re-confirm.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 18)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (18, 'approvals granted before migration 016 are carried over');
GO
