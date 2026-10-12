-- Device Trust schema, SQL Server 2016+
-- Migration 012: DBA-tunable relationship-risk bands and devices-per-account policy
--
-- See the PostgreSQL counterpart for the rationale. MERGE seeds idempotently and
-- never overwrites a value the DBA has tuned.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 012_policy_bands_and_devices_per_account.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('policy_step_up_score', '30', 'Relationship-risk score from which a decision is step_up (recorded, allowed unless elevated_risk_refuses=1). Must be below policy_review_score.'),
    ('policy_review_score', '60', 'Relationship-risk score from which a decision is review (refused in enforce mode, or a limited session where listed). Must be below policy_block_score.'),
    ('policy_block_score', '90', 'Relationship-risk score from which a decision is block (always refused).'),
    ('account_devices_elevated_count', '2', 'Devices one account may use before its decisions are raised (elevated band). 0 = off.'),
    ('account_devices_elevated_points', '35', 'Risk points at the elevated devices-per-account count.'),
    ('account_devices_review_count', '3', 'Devices one account may use before its decisions are held for review. 0 = off.'),
    ('account_devices_review_points', '60', 'Risk points at the review devices-per-account count.'),
    ('account_devices_block_count', '5', 'Devices one account may use before it is blocked. 0 = off.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 12)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (12, 'DBA-tunable relationship bands and devices-per-account policy');
GO
