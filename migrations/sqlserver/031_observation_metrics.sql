-- Device Trust schema, SQL Server 2016+
-- Migration 031: what observation-mode metrics need -- each decision's
-- recommendation and scan, each scan's app build, and an index to read
-- decisions by time
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 84.7).
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 031_observation_metrics.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.risk_policy_decisions', 'assessed') IS NULL
    ALTER TABLE dbo.risk_policy_decisions ADD assessed varchar(16) NULL;
GO

IF COL_LENGTH('dbo.risk_policy_decisions', 'integrity_report_id') IS NULL
    ALTER TABLE dbo.risk_policy_decisions ADD integrity_report_id char(36) COLLATE Latin1_General_BIN2 NULL;
GO

IF COL_LENGTH('dbo.integrity_reports', 'app_build') IS NULL
    ALTER TABLE dbo.integrity_reports ADD app_build char(64) COLLATE Latin1_General_BIN2 NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'risk_policy_decisions_created_idx')
    CREATE INDEX risk_policy_decisions_created_idx ON dbo.risk_policy_decisions(created_at, decision_id);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 31)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (31, 'Observation metrics: each decision''s recommendation and scan, each scan''s build');
GO
