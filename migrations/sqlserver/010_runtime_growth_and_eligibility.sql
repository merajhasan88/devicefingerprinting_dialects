-- Device Trust schema, SQL Server 2016+
-- Migration 010: DBA-tunable W^X growth allowance and eligibility rules
--
-- See the PostgreSQL counterpart for the rationale (joint review R1,
-- DESIGN.md 69). MERGE seeds idempotently and never overwrites a value the
-- DBA has tuned.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 010_runtime_growth_and_eligibility.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('wx_far_above_baseline_percent', '200', 'W^X memory above this percentage of the build''s pinned baseline scores +40 (android_wx_far_above_baseline); between the baseline and this percentage it is expected runtime growth, advisory. 200 = twice the baseline. Minimum 100.'),
    ('developer_options_refuses', '0', 'Eligibility rule. 1 = in enforce mode an installation whose latest scan reports Developer options on is refused (integrity_device_ineligible) until they are off and a new scan is sent; 0 = advisory only.'),
    ('adb_enabled_refuses', '0', 'Eligibility rule. 1 = in enforce mode an installation whose latest scan reports USB debugging (ADB) on is refused (integrity_device_ineligible) until it is off and a new scan is sent; 0 = advisory only.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 10)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (10, 'DBA-tunable W^X growth allowance and eligibility rules');
GO
