-- Device Trust schema, PostgreSQL 13+
-- Migration 030: runtime baselines published by the release pipeline -- the
-- memory profile each app build shows, per OS level and process ABI
--
-- DESIGN.md 84.6, item 6 of the eight the owner approved on 2026-10-14; review
-- R5 (2026-10-13): "Use build artifacts produced by your own release pipeline
-- to approve baseline profiles. Do not let the first client -- or an
-- automatically learned untrusted population -- establish the clean baseline."
-- The release pipeline measures each build on its reference phones and
-- publishes the profile through the business API (role baselines); the server
-- holds every scan of that build to the most specific profile that matches,
-- and names the one it used. Profiles are retired, never deleted.
--
-- Grant the application principal SELECT, INSERT, UPDATE on runtime_baselines.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 030_runtime_baselines.sql

BEGIN;

CREATE TABLE IF NOT EXISTS runtime_baselines (
    baseline_id     UUID PRIMARY KEY,
    platform        VARCHAR(16) NOT NULL,
    app_build       CHAR(64) NOT NULL,
    os_level        INTEGER,
    abi             VARCHAR(32),
    release_label   VARCHAR(64),
    wx_bytes_max    BIGINT,
    wx_granularity  INTEGER,
    anon_exec_max   INTEGER,
    published_by    VARCHAR(64) NOT NULL,
    published_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS runtime_baselines_build_idx ON runtime_baselines (platform, app_build);

ALTER TABLE integrity_reports ADD COLUMN IF NOT EXISTS runtime_baseline_id UUID;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('exec_outside_baseline_points', '30', 'Points for android_exec_outside_baseline: more unlabelled executable memory than the release profile published for this build, OS level and ABI allows. Applies only where the release pipeline published one.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (30, 'Runtime baselines published by the release pipeline')
ON CONFLICT (version) DO NOTHING;

COMMIT;
