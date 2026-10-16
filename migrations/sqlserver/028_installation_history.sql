-- Device Trust schema, SQL Server 2016+
-- Migration 028: each installation compared with its own earlier scans
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 84.4). MERGE
-- never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 028_installation_history.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('history_checks_enabled', '0', '1 = the installation history reasons add their points; 0 (owner default) = each scan is still compared with the installation''s earlier ones and the reasons recorded at 0 -- observe first.'),
    ('history_window_hours', '24', 'Hours of an installation''s scans that installation_verdict_flips counts. 1-720.'),
    ('installation_verdict_flips_count', '4', 'Switches between suspicious (integrity findings of 30 or more) and clean scans within history_window_hours that make installation_verdict_flips. 0 = off.'),
    ('installation_signer_changed_points', '60', 'Points for installation_signer_changed: the app''s signing certificates or package changed under the same installation -- a repackaged app.'),
    ('installation_device_changed_points', '60', 'Points for installation_device_changed: the phone model changed under the same installation, whose key cannot leave its phone.'),
    ('installation_os_downgraded_points', '40', 'Points for installation_os_downgraded: the OS or its security patch went back under the same installation.'),
    ('installation_collector_downgraded_points', '30', 'Points for installation_collector_downgraded: a scan from an older collector than the installation used before.'),
    ('installation_app_downgraded_points', '30', 'Points for installation_app_downgraded: the app went back to an older version under the same installation.'),
    ('installation_coverage_dropped_points', '30', 'Points for installation_coverage_dropped: measurements taken before now missing, unsupported or switched off with no app or OS update to explain it.'),
    ('installation_verdict_flips_points', '30', 'Points for installation_verdict_flips: scans that keep switching between suspicious and clean.'),
    ('installation_app_changed_points', '0', 'Points for installation_app_changed: the app build changed since the last scan, normally an update. Owner default 0 = recorded only.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 28)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (28, 'Each installation compared with its own earlier scans');
GO
