-- Device Trust schema, SQL Server 2016+
-- Migration 009: when a hint-linked installation was confirmed as belonging to its device
--
-- See the PostgreSQL counterpart for the reason (joint review R4, DESIGN.md 68)
-- and the backfill (every existing hint-linked installation is treated as
-- confirmed, so nothing changes for existing data). datetimeoffset(3) like
-- every other timestamp here. No row is deleted.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 009_installation_device_confirmed.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_installations', 'device_confirmed_at') IS NULL
    ALTER TABLE dbo.app_installations ADD device_confirmed_at datetimeoffset(3) NULL;
GO

UPDATE dbo.app_installations
SET device_confirmed_at = created_at
WHERE registration_method = 'reinstall_hint'
  AND device_confirmed_at IS NULL;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 9)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (9, 'hint-linked installation confirmed by a returning account (device_confirmed_at)');
GO
