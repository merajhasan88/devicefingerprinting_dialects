-- Device Trust schema, SQL Server 2016+
-- Migration 007: which account re-enrolled an installation's step-up key
--
-- See the PostgreSQL counterpart. char(36) BIN2 like every other account id
-- in this schema; NULL means "bound at installation registration".
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 007_stepup_key_account.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_installations', 'stepup_key_account_id') IS NULL
    ALTER TABLE dbo.app_installations ADD stepup_key_account_id char(36) COLLATE Latin1_General_BIN2 NULL;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 7)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (7, 'account that re-enrolled the step-up key');
GO
