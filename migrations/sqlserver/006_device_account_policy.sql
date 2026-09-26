-- Device Trust schema, SQL Server 2016+
-- Migration 006: DBA-tunable accounts-per-device policy
--
-- See the PostgreSQL counterpart for the rationale. MERGE seeds idempotently and
-- never overwrites a value the DBA has tuned.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 006_device_account_policy.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('device_accounts_elevated_count', '2', 'Accounts on one device that raise the score (elevated band).'),
    ('device_accounts_elevated_points', '35', 'Risk points at the elevated account count.'),
    ('device_accounts_review_count', '3', 'Accounts on one device that are held for review.'),
    ('device_accounts_review_points', '60', 'Risk points at the review account count.'),
    ('device_accounts_block_count', '4', 'Accounts on one device that are blocked outright.'),
    ('elevated_risk_refuses', '0', 'In enforce mode, 1 = an elevated (step-up band) decision refuses the request; 0 = recorded, not refused.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 6)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (6, 'DBA-tunable accounts-per-device policy');
GO
