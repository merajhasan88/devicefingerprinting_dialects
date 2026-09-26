-- Device Trust schema, SQL Server 2016+
-- Migration 003: DBA-tunable risk policy settings
--
-- See the PostgreSQL counterpart for rationale. setting_key uses BIN2 collation
-- (migrations/README.md: the RDS default collation is case-insensitive); value
-- and description are nvarchar because a description is client-facing text that
-- varchar would corrupt; the timestamp is datetimeoffset defaulting to
-- SYSUTCDATETIME(), never GETDATE(). MERGE seeds idempotently (single-threaded
-- migration context, not the concurrent nonce path the README warns about).
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 003_risk_policy_settings.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.risk_policy_settings', 'U') IS NULL
    CREATE TABLE dbo.risk_policy_settings (
        setting_key   nvarchar(64) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
        setting_value nvarchar(256) NOT NULL,
        description   nvarchar(256) NULL,
        updated_at    datetimeoffset(3) NOT NULL DEFAULT SYSUTCDATETIME()
    );
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('stepup_mode', 'per_use', 'Step-up mode for sensitive ops: per_use (a) or windowed (b).'),
    ('stepup_window_seconds', '0', 'Hardware-enforced reuse window for windowed step-up; 0 = per-use.'),
    ('stepup_factor', 'passcode', 'Required device auth factor: passcode or biometric.'),
    ('rate_anomaly_enabled', '0', 'Enable per-key request-rate anomaly signal (advisory).'),
    ('rate_anomaly_max_requests', '120', 'Requests per key per window before the signal trips.'),
    ('rate_anomaly_window_seconds', '60', 'Window length for the request-rate anomaly signal.'),
    ('rate_anomaly_points', '30', 'Advisory risk points added when the rate signal trips.'),
    ('population_baseline_enabled', '0', 'Enable population-baseline deviation signal (advisory).'),
    ('population_baseline_metric', 'accounts_per_device', 'Relationship metric to threshold: accounts_per_device or installations_per_device.'),
    ('population_baseline_threshold', '10', 'Advisory when the chosen metric exceeds this consumer-set base.'),
    ('population_points', '30', 'Advisory risk points added when the population signal trips.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 3)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (3, 'DBA-tunable risk policy settings');
GO
