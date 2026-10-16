-- Device Trust schema, SQL Server 2016+
-- Migration 025: the critical review of 2026-10-16 -- conditions capped and kept
-- out of the device memory, measurements a path requires, every report and
-- decision stamped with the settings it was judged under, business API callers
-- named, new owner defaults for signals that scored 0
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 83). MERGE never
-- overwrites a tuned value; the UPDATEs change a setting only where it still
-- holds its earlier default of 0.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 025_review_2026_10_16.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.integrity_reports', 'measurement_status') IS NULL
    ALTER TABLE dbo.integrity_reports ADD measurement_status nvarchar(max) NULL;
GO

IF COL_LENGTH('dbo.integrity_reports', 'policy_version') IS NULL
    ALTER TABLE dbo.integrity_reports ADD policy_version varchar(16) NULL;
GO

IF COL_LENGTH('dbo.business_events', 'producer') IS NULL
    ALTER TABLE dbo.business_events ADD producer varchar(64) NULL;
GO

IF COL_LENGTH('dbo.server_observations', 'actor') IS NULL
    ALTER TABLE dbo.server_observations ADD actor varchar(64) NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('conditions_points_cap', '60', 'Most points the conditions add together -- apps that can read the screen, keyboard or notifications, remote-control apps, screen capture, fake GPS, an old patch, a VPN or proxy. Never kept in the device memory. 1-100.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN MATCHED THEN
    UPDATE SET description = s.description
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 25)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (25, 'Conditions capped and kept out of the device memory; required measurements; policy stamps; business API roles');
GO
