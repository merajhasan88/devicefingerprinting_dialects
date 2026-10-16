-- Device Trust schema, PostgreSQL 13+
-- Migration 031: what observation-mode metrics need -- each decision's
-- recommendation and scan, each scan's app build, and an index to read
-- decisions by time
--
-- DESIGN.md 84.7, item 7 of the eight the owner approved on 2026-10-14: before
-- any customer enforces, measure in observe mode how often legitimate users
-- would be restricted, how long they take to get back, and what each check
-- covers and finds. GET /v1/business/metrics (role metrics) reads them. A
-- decision stores what its four answers recommended (assessed) and the scan
-- it was judged on; a scan stores the build it came from. Rows from before
-- this migration have neither and are counted as unknown.
--
-- The index serves reading decisions by time. On a large table a DBA may
-- build it first with CREATE INDEX CONCURRENTLY, outside this script.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 031_observation_metrics.sql

BEGIN;

ALTER TABLE risk_policy_decisions ADD COLUMN IF NOT EXISTS assessed VARCHAR(16);
ALTER TABLE risk_policy_decisions ADD COLUMN IF NOT EXISTS integrity_report_id UUID;
ALTER TABLE integrity_reports ADD COLUMN IF NOT EXISTS app_build CHAR(64);

CREATE INDEX IF NOT EXISTS risk_policy_decisions_created_idx
    ON risk_policy_decisions(created_at, decision_id);

INSERT INTO schema_migrations (version, description)
VALUES (31, 'Observation metrics: each decision''s recommendation and scan, each scan''s build')
ON CONFLICT (version) DO NOTHING;

COMMIT;
