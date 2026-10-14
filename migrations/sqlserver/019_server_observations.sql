-- Device Trust schema, SQL Server 2016+
-- Migration 019: the server's own observations, measured into every decision
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 77). The server
-- never updates or deletes server_observations: grant the application
-- principal SELECT, INSERT on it. MERGE never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 019_server_observations.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.server_observations', 'U') IS NULL
CREATE TABLE dbo.server_observations (
    observation_id  char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    kind            varchar(48) NOT NULL,
    code            varchar(64) NULL,
    account_id      char(36) COLLATE Latin1_General_BIN2 NULL
                    CONSTRAINT fk_observations_account REFERENCES dbo.demo_accounts(account_id),
    device_id       char(36) COLLATE Latin1_General_BIN2 NULL
                    CONSTRAINT fk_observations_device REFERENCES dbo.recognized_devices(device_id),
    installation_id char(36) COLLATE Latin1_General_BIN2 NULL
                    CONSTRAINT fk_observations_install REFERENCES dbo.app_installations(installation_id),
    occurred_at     datetimeoffset(3) NOT NULL CONSTRAINT df_observations_occurred DEFAULT SYSUTCDATETIME()
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'server_observations_account_idx')
    CREATE INDEX server_observations_account_idx ON dbo.server_observations(account_id, occurred_at);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'server_observations_device_idx')
    CREATE INDEX server_observations_device_idx ON dbo.server_observations(device_id, occurred_at);
GO

-- Denied approvals are counted per requesting phone.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'session_upgrade_requests_device_idx')
    CREATE INDEX session_upgrade_requests_device_idx
        ON dbo.session_upgrade_requests(device_id, denied_at);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('cross_checks_enabled', '0', 'Score the server''s own observations with the rules below (DESIGN.md 77). 0 (owner default: observe first) = counted into every decision''s context, scored nowhere; 1 = each rule adds its points once its count is reached.'),
    ('cross_check_window_hours', '24', 'Hours the server''s observations are counted over, for the context and every rule below.'),
    ('account_sign_in_failures_elsewhere_count', '5', 'Wrong-password sign-ins to the account from OTHER phones in the window before a phone joined it. Judges only a phone joining now or within the window, never one there before them; a user mistyping on their own phone is not counted.'),
    ('account_sign_in_failures_elsewhere_points', '30', 'Points for account_sign_in_failures_elsewhere.'),
    ('device_sign_in_failures_many_accounts_count', '3', 'Different accounts with a wrong-password sign-in from this phone in the window.'),
    ('device_sign_in_failures_many_accounts_points', '60', 'Points for device_sign_in_failures_many_accounts.'),
    ('device_sign_in_unknown_accounts_count', '5', 'Sign-ins from this phone to accounts that do not exist, in the window.'),
    ('device_sign_in_unknown_accounts_points', '30', 'Points for device_sign_in_unknown_accounts.'),
    ('device_stepup_failures_count', '3', 'Step-up (screen-lock) proofs from this phone that did not verify, in the window. A request sent without a proof is not one.'),
    ('device_stepup_failures_points', '30', 'Points for device_stepup_failures.'),
    ('device_approvals_denied_count', '1', 'Approval requests from this phone that the account''s other phone denied, in the window.'),
    ('device_approvals_denied_points', '60', 'Points for device_approvals_denied.'),
    ('device_approval_budget_exhausted_count', '1', 'Approval requests from this phone refused because the account''s hourly budget was spent, in the window.'),
    ('device_approval_budget_exhausted_points', '30', 'Points for device_approval_budget_exhausted.'),
    ('device_stepup_reenrolments_count', '2', 'Step-up keys re-enrolled on this phone in the window.'),
    ('device_stepup_reenrolments_points', '30', 'Points for device_stepup_reenrolments.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 19)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (19, 'the server''s own observations, measured into every decision');
GO
