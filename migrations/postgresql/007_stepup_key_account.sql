-- Device Trust schema, PostgreSQL 13+
-- Migration 007: which account re-enrolled an installation's step-up key
--
-- A step-up key bound at installation registration serves every account on
-- that installation (NULL here, as before). A key re-enrolled later through
-- POST /v1/installations/stepup-key is scoped to the account whose password
-- re-enrolled it (DESIGN.md 58): otherwise anyone able to open a second
-- account on the device -- which needs only the installation key -- could
-- re-enrol with that account's password and pass step-up for the first
-- account.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 007_stepup_key_account.sql

BEGIN;

ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS stepup_key_account_id UUID;

INSERT INTO schema_migrations (version, description)
VALUES (7, 'account that re-enrolled the step-up key')
ON CONFLICT (version) DO NOTHING;

COMMIT;
