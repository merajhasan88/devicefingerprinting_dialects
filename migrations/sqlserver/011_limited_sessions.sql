-- Device Trust schema, SQL Server 2016+
-- Migration 011: limited sessions and their upgrade
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 67, 70). The
-- server never deletes from session_upgrade_requests: grant the application
-- principal SELECT, INSERT, UPDATE on it. MERGE never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 011_limited_sessions.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.refresh_sessions', 'scope') IS NULL
    ALTER TABLE dbo.refresh_sessions
        ADD scope varchar(16) NOT NULL CONSTRAINT df_refresh_sessions_scope DEFAULT 'full';
GO

IF COL_LENGTH('dbo.refresh_sessions', 'limited_causes') IS NULL
    ALTER TABLE dbo.refresh_sessions ADD limited_causes varchar(128) NULL;
GO

IF OBJECT_ID('dbo.session_upgrade_requests', 'U') IS NULL
CREATE TABLE dbo.session_upgrade_requests (
    request_id               char(36) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    route                    varchar(16) NOT NULL,
    account_id               char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_upgrade_requests_account REFERENCES dbo.demo_accounts(account_id),
    device_id                char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_upgrade_requests_device REFERENCES dbo.recognized_devices(device_id),
    installation_id          char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_upgrade_requests_install REFERENCES dbo.app_installations(installation_id),
    session_id               char(36) COLLATE Latin1_General_BIN2 NOT NULL
                             CONSTRAINT fk_upgrade_requests_session REFERENCES dbo.refresh_sessions(session_id),
    family_id                char(36) COLLATE Latin1_General_BIN2 NOT NULL,
    nonce_sha256             char(64) NULL,
    created_at               datetimeoffset(3) NOT NULL CONSTRAINT df_upgrade_requests_created DEFAULT SYSUTCDATETIME(),
    expires_at               datetimeoffset(3) NOT NULL,
    approved_by_installation char(36) COLLATE Latin1_General_BIN2 NULL
                             CONSTRAINT fk_upgrade_requests_approver REFERENCES dbo.app_installations(installation_id),
    approved_at              datetimeoffset(3) NULL,
    denied_at                datetimeoffset(3) NULL,
    consumed_at              datetimeoffset(3) NULL,
    assertion_method         nvarchar(64) NULL
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'session_upgrade_requests_account_idx')
CREATE INDEX session_upgrade_requests_account_idx
    ON dbo.session_upgrade_requests(account_id, created_at);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('limited_session_paths', '', 'Paths a limited session may reach besides the upgrade endpoints and the integrity scan, comma-separated. Empty: nothing else.'),
    ('limited_session_integrity_verdicts', 'elevated', 'Integrity verdicts that give a limited session instead of a 403 at login, registration and refresh (enforce mode): elevated and/or review. Empty: they refuse. A block always refuses.'),
    ('limited_session_policy_actions', 'step_up,review', 'Relationship outcomes that give a limited session instead of a 403 (enforce mode): step_up (refused only with elevated_risk_refuses=1) and/or review. Empty: they refuse. A block always refuses.'),
    ('upgrade_stepup_same_device', '0', '1 = a limited session may upgrade with a step-up proof from the same phone, only when every cause is integrity-related. Proves the screen lock, not who the user is.'),
    ('upgrade_other_device_approval', '1', '1 = a limited session may upgrade with an approval signed, with step-up, by another installation of the same account that holds a full session.'),
    ('upgrade_mfa_assertion', '0', '1 = a limited session may upgrade with an ES256 assertion signed by your identity backend (keys in UPGRADE_ASSERTION_JWKS_FILE). As strong as your MFA.'),
    ('upgrade_request_ttl_seconds', '300', 'Seconds an upgrade request (an approval request or an assertion nonce) stays valid. Minimum 30.'),
    ('upgrade_approvals_per_hour', '3', 'Approval requests one account may raise per hour, against prompt fatigue. 0 = none.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 11)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (11, 'limited sessions and their upgrade');
GO
