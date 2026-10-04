-- Device Trust schema, SQL Server 2016+
-- Migration 008: when an installation first proved possession of its key
--
-- See the PostgreSQL counterpart for the reason (review F6, DESIGN.md 63) and
-- the backfill rule. datetimeoffset(3) like every other timestamp here; NULL
-- means "registered, never proven". No row is deleted.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 008_installation_verified.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.app_installations', 'verified_at') IS NULL
    ALTER TABLE dbo.app_installations ADD verified_at datetimeoffset(3) NULL;
GO

UPDATE dbo.app_installations
SET verified_at = created_at
WHERE verified_at IS NULL
  AND (
        EXISTS (SELECT 1 FROM dbo.integrity_reports r
                WHERE r.installation_id = dbo.app_installations.installation_id)
     OR EXISTS (SELECT 1 FROM dbo.refresh_sessions s
                WHERE s.installation_id = dbo.app_installations.installation_id)
     OR EXISTS (SELECT 1 FROM dbo.device_account_links l
                WHERE l.first_installation_id = dbo.app_installations.installation_id)
     OR EXISTS (SELECT 1 FROM dbo.installation_challenges c
                WHERE c.installation_id = dbo.app_installations.installation_id
                  AND c.used_at IS NOT NULL)
  );
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 8)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (8, 'installation key first proven (verified_at)');
GO
