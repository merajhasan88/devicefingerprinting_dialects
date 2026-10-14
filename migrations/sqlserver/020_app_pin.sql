-- Device Trust schema, SQL Server 2016+
-- Migration 020: an app PIN the server checks, beside the screen-lock key
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 78). The server
-- never deletes from app_pins: grant the application principal SELECT,
-- INSERT, UPDATE on it. MERGE never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 020_app_pin.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.app_pins', 'U') IS NULL
CREATE TABLE dbo.app_pins (
    account_id          char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY
                        CONSTRAINT fk_app_pins_account REFERENCES dbo.demo_accounts(account_id),
    pin_hash            varbinary(255) NOT NULL,
    failures            int NOT NULL CONSTRAINT df_app_pins_failures DEFAULT 0,
    locked_at           datetimeoffset(3) NULL,
    set_at              datetimeoffset(3) NOT NULL CONSTRAINT df_app_pins_set DEFAULT SYSUTCDATETIME(),
    set_by_installation char(36) COLLATE Latin1_General_BIN2 NULL
                        CONSTRAINT fk_app_pins_install REFERENCES dbo.app_installations(installation_id)
);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('stepup_method', 'app_pin', 'How a step-up is proven wherever one is required (the step-up paths, approving another phone, the same-phone upgrade, an elevated scan): app_pin (owner default, checked by the server), screen_lock or screen_lock_and_app_pin.'),
    ('app_pin_required_paths', '', 'Paths that need the app PIN in addition to anything else, comma-separated (for example payee changes, large transfers). Empty: none.'),
    ('app_pin_length', '6', 'Digits in an app PIN, 4-12.'),
    ('app_pin_max_failures', '5', 'Wrong app PINs in a row before the PIN locks; the user then sets a new one with the account password. At least 1.'),
    ('device_app_pin_failures_count', '3', 'Wrong app PINs for one account from this phone in the window (DESIGN.md 77).'),
    ('device_app_pin_failures_points', '30', 'Points for device_app_pin_failures.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 20)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (20, 'an app PIN the server checks, beside the screen-lock key');
GO
