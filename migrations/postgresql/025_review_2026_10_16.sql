-- Device Trust schema, PostgreSQL 13+
-- Migration 025: the critical review of 2026-10-16 -- conditions capped and kept
-- out of the device memory, measurements a path requires, every report and
-- decision stamped with the settings it was judged under, business API callers
-- named, new owner defaults for signals that scored 0
--
-- DESIGN.md 83. New settings seed the owner's defaults; descriptions are ours, so
-- a row that already exists gets this migration's description and keeps its
-- value. The UPDATEs below give five settings that migration 023 seeded at 0
-- the owner's new defaults (2026-10-16) only where they are still 0: a
-- deployment that chose 0 deliberately sets it again afterwards.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 025_review_2026_10_16.sql

BEGIN;

ALTER TABLE integrity_reports ADD COLUMN IF NOT EXISTS measurement_status JSONB;
ALTER TABLE integrity_reports ADD COLUMN IF NOT EXISTS policy_version VARCHAR(16);
ALTER TABLE business_events ADD COLUMN IF NOT EXISTS producer VARCHAR(64);
ALTER TABLE server_observations ADD COLUMN IF NOT EXISTS actor VARCHAR(64);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('conditions_points_cap', '60', 'Most points the conditions add together -- apps that can read the screen, keyboard or notifications, remote-control apps, screen capture, fake GPS, an old patch, a VPN or proxy. Never kept in the device memory. 1-100.')
ON CONFLICT (setting_key) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO schema_migrations (version, description)
VALUES (25, 'Conditions capped and kept out of the device memory; required measurements; policy stamps; business API roles')
ON CONFLICT (version) DO NOTHING;

COMMIT;
