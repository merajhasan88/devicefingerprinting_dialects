-- Device Trust schema, PostgreSQL 13+
-- Migration 004: optional per-installation step-up key
--
-- A second, OPTIONAL P-256 key the client may register at enrolment (DESIGN.md
-- 51.2-51.3). The installation key stays unattended for routine PoP; the step-up
-- key is the hardware-bound, user-auth-gated one used only to approve sensitive
-- operations. Both columns are NULLABLE: an installation without a step-up key
-- behaves exactly as before, and step-up is only ever required on the paths a
-- deployment lists in risk_policy_settings.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 004_stepup_key.sql

BEGIN;

ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS stepup_public_key_jwk JSONB;
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS stepup_key_algorithm VARCHAR(16);

INSERT INTO schema_migrations (version, description)
VALUES (4, 'optional per-installation step-up key')
ON CONFLICT (version) DO NOTHING;

COMMIT;
