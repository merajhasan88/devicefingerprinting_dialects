-- Device Trust schema, SQL Server 2016+
-- Migration 014: a newer approval request replaces the same phone's pending ones
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 75).
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 014_superseded_requests.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.session_upgrade_requests', 'superseded_at') IS NULL
    ALTER TABLE dbo.session_upgrade_requests ADD superseded_at datetimeoffset(3) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 14)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (14, 'a newer approval request supersedes the same phone''s pending ones');
GO
