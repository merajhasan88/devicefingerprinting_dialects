-- Device Trust schema, SQL Server 2016+
-- Migration 004: optional per-installation step-up key
--
-- See the PostgreSQL counterpart. stepup_public_key_jwk is nvarchar(max) (the
-- JWK is client-supplied JSON, per the README JSON rule); both columns NULLABLE.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 004_stepup_key.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_installations', 'stepup_public_key_jwk') IS NULL
    ALTER TABLE dbo.app_installations ADD stepup_public_key_jwk nvarchar(max) NULL;
GO

IF COL_LENGTH('dbo.app_installations', 'stepup_key_algorithm') IS NULL
    ALTER TABLE dbo.app_installations ADD stepup_key_algorithm nvarchar(16) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 4)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (4, 'optional per-installation step-up key');
GO
