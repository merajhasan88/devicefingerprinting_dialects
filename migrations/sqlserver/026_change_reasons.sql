-- Device Trust schema, SQL Server 2016+
-- Migration 026: why a row was changed by hand -- a reason, the database login
-- and the time with every change of a DBA setting and of a phone's or an
-- installation's status
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 84). The triggers
-- compare values in a binary collation and by length, so a change PostgreSQL
-- sees -- case, trailing spaces -- is a change here too. They return at once
-- for an UPDATE that does not set the value, such as the server's own
-- last_seen_at updates.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 026_change_reasons.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.risk_policy_settings', 'change_reason') IS NULL
    ALTER TABLE dbo.risk_policy_settings ADD change_reason nvarchar(256) NULL;
GO

IF COL_LENGTH('dbo.risk_policy_settings', 'changed_by') IS NULL
    ALTER TABLE dbo.risk_policy_settings ADD changed_by nvarchar(128) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'status_reason') IS NULL
    ALTER TABLE dbo.app_installations ADD status_reason nvarchar(256) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'status_changed_by') IS NULL
    ALTER TABLE dbo.app_installations ADD status_changed_by nvarchar(128) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'status_changed_at') IS NULL
    ALTER TABLE dbo.app_installations ADD status_changed_at datetimeoffset(3) NULL;
GO

IF COL_LENGTH('dbo.recognized_devices', 'status_reason') IS NULL
    ALTER TABLE dbo.recognized_devices ADD status_reason nvarchar(256) NULL;
GO

IF COL_LENGTH('dbo.recognized_devices', 'status_changed_by') IS NULL
    ALTER TABLE dbo.recognized_devices ADD status_changed_by nvarchar(128) NULL;
GO

IF COL_LENGTH('dbo.recognized_devices', 'status_changed_at') IS NULL
    ALTER TABLE dbo.recognized_devices ADD status_changed_at datetimeoffset(3) NULL;
GO

UPDATE t
SET change_reason = N'Migration 025: the owner''s default since 2026-10-16; migration 023 had seeded 0'
FROM dbo.risk_policy_settings AS t
JOIN (VALUES
    ('source_vpn_listed_points', '10'),
    ('source_tor_exit_points', '30'),
    ('source_hosting_points', '15'),
    ('source_vpn_observed_points', '10'),
    ('source_vpn_observed_non_hosting_points', '10')
) AS s(setting_key, setting_value)
    ON t.setting_key = s.setting_key
   AND t.setting_value = s.setting_value
WHERE t.change_reason IS NULL;
GO

IF OBJECT_ID('dbo.risk_policy_settings_require_reason', 'TR') IS NOT NULL
    DROP TRIGGER dbo.risk_policy_settings_require_reason;
GO

CREATE TRIGGER dbo.risk_policy_settings_require_reason
ON dbo.risk_policy_settings
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRIGGER_NESTLEVEL(@@PROCID) > 1 OR NOT UPDATE(setting_value)
        RETURN;
    IF EXISTS (
        SELECT 1
        FROM inserted AS i
        JOIN deleted AS d ON d.setting_key = i.setting_key
        WHERE (i.setting_value COLLATE Latin1_General_BIN2 <> d.setting_value COLLATE Latin1_General_BIN2
               OR DATALENGTH(i.setting_value) <> DATALENGTH(d.setting_value))
          AND (i.change_reason IS NULL
               OR LTRIM(RTRIM(i.change_reason)) = N''
               OR (d.change_reason IS NOT NULL
                   AND i.change_reason COLLATE Latin1_General_BIN2 = d.change_reason COLLATE Latin1_General_BIN2
                   AND DATALENGTH(i.change_reason) = DATALENGTH(d.change_reason)))
    )
        THROW 51026, N'risk_policy_settings: say why it changes -- set change_reason, a new one, in the same UPDATE as setting_value', 1;
    UPDATE t
    SET changed_by = ORIGINAL_LOGIN(),
        updated_at = SYSUTCDATETIME()
    FROM dbo.risk_policy_settings AS t
    JOIN inserted AS i ON i.setting_key = t.setting_key
    JOIN deleted AS d ON d.setting_key = i.setting_key
    WHERE i.setting_value COLLATE Latin1_General_BIN2 <> d.setting_value COLLATE Latin1_General_BIN2
       OR DATALENGTH(i.setting_value) <> DATALENGTH(d.setting_value);
END;
GO

IF OBJECT_ID('dbo.app_installations_status_require_reason', 'TR') IS NOT NULL
    DROP TRIGGER dbo.app_installations_status_require_reason;
GO

CREATE TRIGGER dbo.app_installations_status_require_reason
ON dbo.app_installations
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRIGGER_NESTLEVEL(@@PROCID) > 1 OR NOT UPDATE(status)
        RETURN;
    IF EXISTS (
        SELECT 1
        FROM inserted AS i
        JOIN deleted AS d ON d.installation_id = i.installation_id
        WHERE (i.status COLLATE Latin1_General_BIN2 <> d.status COLLATE Latin1_General_BIN2
               OR DATALENGTH(i.status) <> DATALENGTH(d.status))
          AND (i.status_reason IS NULL
               OR LTRIM(RTRIM(i.status_reason)) = N''
               OR (d.status_reason IS NOT NULL
                   AND i.status_reason COLLATE Latin1_General_BIN2 = d.status_reason COLLATE Latin1_General_BIN2
                   AND DATALENGTH(i.status_reason) = DATALENGTH(d.status_reason)))
    )
        THROW 51026, N'app_installations: say why the status changes -- set status_reason, a new one, in the same UPDATE as status', 1;
    UPDATE t
    SET status_changed_by = ORIGINAL_LOGIN(),
        status_changed_at = SYSUTCDATETIME()
    FROM dbo.app_installations AS t
    JOIN inserted AS i ON i.installation_id = t.installation_id
    JOIN deleted AS d ON d.installation_id = i.installation_id
    WHERE i.status COLLATE Latin1_General_BIN2 <> d.status COLLATE Latin1_General_BIN2
       OR DATALENGTH(i.status) <> DATALENGTH(d.status);
END;
GO

IF OBJECT_ID('dbo.recognized_devices_status_require_reason', 'TR') IS NOT NULL
    DROP TRIGGER dbo.recognized_devices_status_require_reason;
GO

CREATE TRIGGER dbo.recognized_devices_status_require_reason
ON dbo.recognized_devices
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF TRIGGER_NESTLEVEL(@@PROCID) > 1 OR NOT UPDATE(status)
        RETURN;
    IF EXISTS (
        SELECT 1
        FROM inserted AS i
        JOIN deleted AS d ON d.device_id = i.device_id
        WHERE (i.status COLLATE Latin1_General_BIN2 <> d.status COLLATE Latin1_General_BIN2
               OR DATALENGTH(i.status) <> DATALENGTH(d.status))
          AND (i.status_reason IS NULL
               OR LTRIM(RTRIM(i.status_reason)) = N''
               OR (d.status_reason IS NOT NULL
                   AND i.status_reason COLLATE Latin1_General_BIN2 = d.status_reason COLLATE Latin1_General_BIN2
                   AND DATALENGTH(i.status_reason) = DATALENGTH(d.status_reason)))
    )
        THROW 51026, N'recognized_devices: say why the status changes -- set status_reason, a new one, in the same UPDATE as status', 1;
    UPDATE t
    SET status_changed_by = ORIGINAL_LOGIN(),
        status_changed_at = SYSUTCDATETIME()
    FROM dbo.recognized_devices AS t
    JOIN inserted AS i ON i.device_id = t.device_id
    JOIN deleted AS d ON d.device_id = i.device_id
    WHERE i.status COLLATE Latin1_General_BIN2 <> d.status COLLATE Latin1_General_BIN2
       OR DATALENGTH(i.status) <> DATALENGTH(d.status);
END;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 26)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (26, 'A reason, the database login and the time with every hand-made change of a setting or a status');
GO
