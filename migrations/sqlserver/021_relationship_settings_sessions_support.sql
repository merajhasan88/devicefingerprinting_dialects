-- Device Trust schema, SQL Server 2016+
-- Migration 021: the rest of the policy in the DBA's hands; session
-- lifetimes; support unlock and reset of an app PIN
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 79). MERGE never
-- overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 021_relationship_settings_sessions_support.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_pins', 'reset_until') IS NULL
    ALTER TABLE dbo.app_pins ADD reset_until datetimeoffset(3) NULL;
GO

ALTER TABLE dbo.app_pins ALTER COLUMN pin_hash varbinary(255) NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('new_device_points', '10', 'Points for a phone first seen less than new_device_hours ago. 0 switches the rule off.'),
    ('new_device_hours', '24', 'How long a newly recognized phone counts as new.'),
    ('known_device_new_installation_points', '15', 'Points for a new installation correlated to a phone already recognized (a reinstall). 0 switches the rule off.'),
    ('reinstall_window_hours', '24', 'Hours over which proven reinstalls on one phone are counted.'),
    ('reinstall_elevated_count', '3', 'Reinstalls in the window that add reinstall_elevated_points. 0 switches the rule off.'),
    ('reinstall_elevated_points', '35', 'Points at reinstall_elevated_count.'),
    ('reinstall_high_count', '4', 'Reinstalls in the window that add reinstall_high_points. 0 switches the rule off.'),
    ('reinstall_high_points', '60', 'Points at reinstall_high_count.'),
    ('reinstall_block_count', '5', 'Reinstalls in the window that block the phone. 0 switches the rule off.'),
    ('integrity_report_missing_points', '40', 'Points when an installation has never sent a signed integrity scan.'),
    ('integrity_report_stale_points', '35', 'Points when the latest scan is older than integrity_freshness_seconds.'),
    ('integrity_freshness_seconds', '600', 'How old the latest integrity scan may be and still count as fresh.'),
    ('device_integrity_history_block_points', '50', 'Points when another installation on the same phone was blocked by integrity within integrity_device_memory_hours.'),
    ('hardware_backing_policy', 'off', 'off, advisory or required: how a software-backed installation key is scored (it is only ever the phone''s claim). This one adds integrity points.'),
    ('refresh_idle_days', '30', 'A session ends after this many days without a refresh; each refresh extends it (owner default 30). 1-90.'),
    ('session_max_days', '0', 'A session ends this many days after its first sign-in, however often it refreshes. 0 = no limit (owner default). Up to 365.'),
    ('app_pin_support', 'off', 'What support staff may do to a customer''s app PIN through the business API, after verifying the customer: off, unlock, or unlock_and_reset.'),
    ('app_pin_support_reset_minutes', '15', 'After a support reset, minutes within which the customer may set a new PIN, once, even from a limited session, with the password.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 21)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (21, 'relationship rules, session lifetimes and app PIN support as DBA settings');
GO
