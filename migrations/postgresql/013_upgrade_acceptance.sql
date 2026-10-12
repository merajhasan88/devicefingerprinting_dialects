-- Device Trust schema, PostgreSQL 13+
-- Migration 013: an upgrade's acceptance, kept with the session
--
-- DESIGN.md 72. When a limited session upgrades with a proof (a step-up on the
-- same phone, an approval from another phone, or the customer's MFA assertion)
-- while its soft causes remain, the full session records which causes the
-- proof accepted and until when. Protected requests and refreshes honour
-- exactly those causes; anything worse refuses or narrows the session again.
-- The owner's default keeps an acceptance for the refresh lifetime (720 hours);
-- 0 keeps none. Re-running never overwrites a tuned value.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 013_upgrade_acceptance.sql

BEGIN;

ALTER TABLE refresh_sessions
    ADD COLUMN IF NOT EXISTS accepted_causes VARCHAR(128);
ALTER TABLE refresh_sessions
    ADD COLUMN IF NOT EXISTS accepted_until TIMESTAMPTZ;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('upgrade_acceptance_hours', '720', 'Hours an upgrade keeps accepting the soft causes its proof covered (never past the 30-day refresh lifetime). 0 = none: protected requests and refreshes judge them again.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (13, 'upgrade acceptance kept with the session')
ON CONFLICT (version) DO NOTHING;

COMMIT;
