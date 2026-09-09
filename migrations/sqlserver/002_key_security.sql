-- Device Trust schema, SQL Server 2016+
-- Migration 002: record the key security level the client reports
--
-- See the PostgreSQL counterpart for the rationale. The columns are nvarchar
-- rather than varchar for the reason given in migrations/README.md: SQL Server
-- 2016/2017 have no UTF-8 collation, and a provider string is client-supplied
-- text that varchar would corrupt.
--
-- Every column is NULLABLE. NULL means "not reported" and must never be read
-- as "software".
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 002_key_security.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_installations', 'key_security_level') IS NULL
    ALTER TABLE dbo.app_installations ADD key_security_level nvarchar(32) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'key_hardware_backed') IS NULL
    ALTER TABLE dbo.app_installations ADD key_hardware_backed bit NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'key_provider') IS NULL
    ALTER TABLE dbo.app_installations ADD key_provider nvarchar(64) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 2)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (2, 'record reported key security level');
GO
