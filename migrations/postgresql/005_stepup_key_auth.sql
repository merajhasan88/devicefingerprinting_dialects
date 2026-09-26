-- Device Trust schema, PostgreSQL 13+
-- Migration 005: how the step-up key is protected, as the client reports it
--
-- The step-up key (migration 004) is generated so it cannot sign without a
-- device authentication. How strictly depends on the platform: per-use where
-- the hardware supports a passcode per signature (iOS, Android 11+), a short
-- hardware-enforced window where it does not (Android 9/10, DESIGN.md 53).
-- Recording the factor, mode and window the key was actually created with makes
-- a downgrade from the deployment policy visible to the operator instead of
-- silent.
--
-- A client claim, like key_security (migration 002): without key attestation
-- the server cannot re-verify it. Every column is NULLABLE, and NULL means "not
-- reported", never "per-use".
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 005_stepup_key_auth.sql

BEGIN;

ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS stepup_key_factor VARCHAR(16);
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS stepup_key_mode VARCHAR(16);
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS stepup_key_window_seconds INTEGER;

INSERT INTO schema_migrations (version, description)
VALUES (5, 'reported step-up key factor, mode and window')
ON CONFLICT (version) DO NOTHING;

COMMIT;
