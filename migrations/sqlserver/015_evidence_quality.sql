-- Device Trust schema, SQL Server 2016+
-- Migration 015: evidence quality kept apart from findings
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 76). MERGE seeds
-- idempotently and never overwrites a value the DBA has tuned.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 015_evidence_quality.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.integrity_reports', 'evidence_quality') IS NULL
    ALTER TABLE dbo.integrity_reports ADD evidence_quality varchar(16) NULL;
GO

IF COL_LENGTH('dbo.integrity_reports', 'finding_score') IS NULL
    ALTER TABLE dbo.integrity_reports ADD finding_score int NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'refresh_sessions_family_current_idx')
    CREATE INDEX refresh_sessions_family_current_idx
        ON dbo.refresh_sessions(family_id, revoked_at);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('collection_problems_block', '0', '1 = each failed or incomplete probe adds +30, three make a block, and that block is remembered for the device (every account on the phone) like a finding. 0 (owner default) = collection problems add +30 once and never enter the device memory.'),
    ('integrity_device_memory_hours', '24', 'Hours a blocked finding stays with the physical device across reinstalls. 0 = off.'),
    ('complete_evidence_paths', '', 'Paths that need a fresh, complete integrity scan (no failed, incomplete, contradictory or legacy evidence), comma-separated. Empty: none.'),
    ('complete_evidence_max_age_seconds', '600', 'How fresh that scan must be on complete_evidence_paths, in seconds. Minimum 30.'),
    ('incomplete_evidence_review_after', '3', 'Consecutive incomplete or invalid scans of one installation, with no complete scan between them, that escalate the verdict to review. 0 = off. Legacy collectors never count.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 15)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (15, 'evidence quality kept apart from findings');
GO
