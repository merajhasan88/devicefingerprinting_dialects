-- Device Trust schema, PostgreSQL 13+
-- Migration 009: when a hint-linked installation was confirmed as belonging to its device
--
-- A reinstall hint is client input: anyone holding a device's hint can link a
-- new, proven key to that device and report a block from it, which used to
-- spread to every installation of the device for the memory window (joint
-- review R4, DESIGN.md 68). An integrity block now spreads only from an
-- established installation -- the device's original one, or a hint-linked one
-- confirmed when an account that already belonged to the device, through an
-- established installation, signed in on it. device_confirmed_at records that.
--
-- Backfill: every EXISTING hint-linked installation is treated as confirmed,
-- so the rule changes nothing for data already present (owner condition: no
-- legitimate sign-in may be affected). New hint-linked installations start
-- unconfirmed. No row is deleted.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 009_installation_device_confirmed.sql

BEGIN;

ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS device_confirmed_at TIMESTAMPTZ;

UPDATE app_installations
SET device_confirmed_at = created_at
WHERE registration_method = 'reinstall_hint'
  AND device_confirmed_at IS NULL;

INSERT INTO schema_migrations (version, description)
VALUES (9, 'hint-linked installation confirmed by a returning account (device_confirmed_at)')
ON CONFLICT (version) DO NOTHING;

COMMIT;
