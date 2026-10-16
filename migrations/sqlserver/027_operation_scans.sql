-- Device Trust schema, SQL Server 2016+
-- Migration 027: a scan made for one operation, used once -- the request it
-- approves named in its challenge
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 84.3). Grant the
-- application principal SELECT, INSERT on operation_scan_uses; never UPDATE or
-- DELETE. MERGE never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 027_operation_scans.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.integrity_challenges', 'operation_sha256') IS NULL
    ALTER TABLE dbo.integrity_challenges ADD operation_sha256 char(64) COLLATE Latin1_General_BIN2 NULL;
GO

IF COL_LENGTH('dbo.integrity_reports', 'operation_sha256') IS NULL
    ALTER TABLE dbo.integrity_reports ADD operation_sha256 char(64) COLLATE Latin1_General_BIN2 NULL;
GO

IF OBJECT_ID('dbo.operation_scan_uses', 'U') IS NULL
CREATE TABLE dbo.operation_scan_uses (
    report_id        char(36) COLLATE Latin1_General_BIN2 NOT NULL
                     CONSTRAINT pk_operation_scan_uses PRIMARY KEY
                     CONSTRAINT fk_operation_scan_uses_report REFERENCES dbo.integrity_reports(report_id),
    installation_id  char(36) COLLATE Latin1_General_BIN2 NOT NULL
                     CONSTRAINT fk_operation_scan_uses_installation
                     REFERENCES dbo.app_installations(installation_id),
    used_by          varchar(64) NOT NULL,
    used_at          datetimeoffset(3) NOT NULL CONSTRAINT df_operation_scan_uses_used_at DEFAULT SYSUTCDATETIME()
);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('operation_scan_paths', '', 'Paths where a request needs a scan made for it alone: the app asks for a challenge naming the request (method, path, query, body SHA-256), scans, and sends the request with the report_id; each scan approves one request. Empty (owner default) = none.'),
    ('operation_scan_max_age_seconds', '120', 'How old a scan made for one operation may be when the operation arrives. 10-600.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 27)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (27, 'A scan made for one operation, used once');
GO
