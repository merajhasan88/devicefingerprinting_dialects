-- Device Trust schema, PostgreSQL 13+
-- Migration 015: evidence quality kept apart from findings
--
-- DESIGN.md 76 (review R3/R4/R6, owner decisions of 2026-10-13). Every
-- integrity report now records what was actually measured (evidence_quality:
-- complete, partial, incomplete, invalid or legacy) and the score of its
-- positive findings alone (finding_score). Collection problems -- probes that
-- failed, answered without their measurements, or contradicted themselves --
-- count once (+30) instead of +30 each, and never enter the device memory;
-- only findings do. A DBA who wants the earlier behaviour (each problem +30,
-- three a block, remembered for every account on the phone) sets
-- collection_problems_block = 1. Also seeded: the device-memory window (was
-- the INTEGRITY_DEVICE_MEMORY_HOURS environment variable, which remains the
-- fallback), and two counters -- operations that need a complete, fresh scan,
-- and escalation of evidence that stays incomplete. An index serves the
-- per-request check that the session's refresh family is still current.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 015_evidence_quality.sql

BEGIN;

ALTER TABLE integrity_reports
    ADD COLUMN IF NOT EXISTS evidence_quality VARCHAR(16);
ALTER TABLE integrity_reports
    ADD COLUMN IF NOT EXISTS finding_score INTEGER;

CREATE INDEX IF NOT EXISTS refresh_sessions_family_current_idx
    ON refresh_sessions(family_id, revoked_at);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('collection_problems_block', '0', '1 = each failed or incomplete probe adds +30, three make a block, and that block is remembered for the device (every account on the phone) like a finding. 0 (owner default) = collection problems add +30 once and never enter the device memory.'),
    ('integrity_device_memory_hours', '24', 'Hours a blocked finding stays with the physical device across reinstalls. 0 = off.'),
    ('complete_evidence_paths', '', 'Paths that need a fresh, complete integrity scan (no failed, incomplete, contradictory or legacy evidence), comma-separated. Empty: none.'),
    ('complete_evidence_max_age_seconds', '600', 'How fresh that scan must be on complete_evidence_paths, in seconds. Minimum 30.'),
    ('incomplete_evidence_review_after', '3', 'Consecutive incomplete or invalid scans of one installation, with no complete scan between them, that escalate the verdict to review. 0 = off. Legacy collectors never count.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (15, 'evidence quality kept apart from findings')
ON CONFLICT (version) DO NOTHING;

COMMIT;
