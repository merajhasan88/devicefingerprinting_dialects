-- Device Trust schema, PostgreSQL 13+
-- Migration 008: when an installation first proved possession of its key
--
-- Registration is public and proves nothing: anyone holding a device's
-- reinstall hint could register fresh public keys against it, and every such
-- row counted toward that device's installation and reinstall-velocity totals
-- -- five reach the reinstall block (review F6, DESIGN.md 63). verified_at is
-- set the first time the installation answers a challenge with its key; the
-- policy counts only installations that have.
--
-- Backfill: an existing installation counts as verified (at its creation time)
-- when it has anything that needed its key -- an integrity report, a refresh
-- session, a device-account link it created, or a consumed challenge. Rows
-- without any of these were never proven and stay NULL. No row is deleted.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 008_installation_verified.sql

BEGIN;

ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

UPDATE app_installations AS i
SET verified_at = i.created_at
WHERE i.verified_at IS NULL
  AND (
        EXISTS (SELECT 1 FROM integrity_reports r WHERE r.installation_id = i.installation_id)
     OR EXISTS (SELECT 1 FROM refresh_sessions s WHERE s.installation_id = i.installation_id)
     OR EXISTS (SELECT 1 FROM device_account_links l WHERE l.first_installation_id = i.installation_id)
     OR EXISTS (SELECT 1 FROM installation_challenges c
                WHERE c.installation_id = i.installation_id AND c.used_at IS NOT NULL)
  );

INSERT INTO schema_migrations (version, description)
VALUES (8, 'installation key first proven (verified_at)')
ON CONFLICT (version) DO NOTHING;

COMMIT;
