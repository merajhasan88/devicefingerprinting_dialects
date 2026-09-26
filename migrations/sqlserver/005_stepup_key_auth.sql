-- Device Trust schema, SQL Server 2016+
-- Migration 005: how the step-up key is protected, as the client reports it
--
-- See the PostgreSQL counterpart for the rationale. Every column is NULLABLE;
-- NULL means "not reported", never "per-use".
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 005_stepup_key_auth.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_installations', 'stepup_key_factor') IS NULL
    ALTER TABLE dbo.app_installations ADD stepup_key_factor nvarchar(16) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'stepup_key_mode') IS NULL
    ALTER TABLE dbo.app_installations ADD stepup_key_mode nvarchar(16) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'stepup_key_window_seconds') IS NULL
    ALTER TABLE dbo.app_installations ADD stepup_key_window_seconds int NULL;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 5)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (5, 'reported step-up key factor, mode and window');
GO
