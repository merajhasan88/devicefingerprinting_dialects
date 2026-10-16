-- Device Trust schema, SQL Server 2016+
-- Migration 030: runtime baselines published by the release pipeline -- the
-- memory profile each app build shows, per OS level and process ABI
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 84.6). Grant the
-- application principal SELECT, INSERT, UPDATE on runtime_baselines. MERGE
-- never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 030_runtime_baselines.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.runtime_baselines', 'U') IS NULL
CREATE TABLE dbo.runtime_baselines (
    baseline_id     char(36) COLLATE Latin1_General_BIN2 NOT NULL
                    CONSTRAINT pk_runtime_baselines PRIMARY KEY,
    platform        varchar(16) NOT NULL,
    app_build       char(64) COLLATE Latin1_General_BIN2 NOT NULL,
    os_level        int NULL,
    abi             varchar(32) COLLATE Latin1_General_BIN2 NULL,
    release_label   nvarchar(64) NULL,
    wx_bytes_max    bigint NULL,
    wx_granularity  int NULL,
    anon_exec_max   int NULL,
    published_by    varchar(64) NOT NULL,
    published_at    datetimeoffset(3) NOT NULL CONSTRAINT df_runtime_baselines_published DEFAULT SYSUTCDATETIME(),
    retired_at      datetimeoffset(3) NULL
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'runtime_baselines_build_idx'
               AND object_id = OBJECT_ID('dbo.runtime_baselines'))
    CREATE INDEX runtime_baselines_build_idx ON dbo.runtime_baselines (platform, app_build);
GO

IF COL_LENGTH('dbo.integrity_reports', 'runtime_baseline_id') IS NULL
    ALTER TABLE dbo.integrity_reports ADD runtime_baseline_id char(36) COLLATE Latin1_General_BIN2 NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('exec_outside_baseline_points', '30', 'Points for android_exec_outside_baseline: more unlabelled executable memory than the release profile published for this build, OS level and ABI allows. Applies only where the release pipeline published one.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 30)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (30, 'Runtime baselines published by the release pipeline');
GO
