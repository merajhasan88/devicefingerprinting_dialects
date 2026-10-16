-- Device Trust schema, PostgreSQL 13+
-- Migration 026: why a row was changed by hand -- a reason, the database login
-- and the time with every change of a DBA setting and of a phone's or an
-- installation's status
--
-- DESIGN.md 84 (owner decision of 2026-10-16). The server never writes these
-- values; people do -- a DBA tuning risk_policy_settings, or revoking a phone or
-- an installation through its status. Each such row now records why its value
-- last changed (change_reason, status_reason), the database login that changed
-- it (changed_by, status_changed_by) and when (updated_at, status_changed_at).
-- A NULL reason means the value is as the migrations left it.
--
-- A trigger refuses a change of the value that does not come with a new reason,
-- and stamps the login and the time itself, so the record cannot go stale. A
-- later migration that changes an owner default therefore changes only the rows
-- no person changed -- change_reason NULL, or a reason a migration wrote, which
-- starts with "Migration " -- and gives its own reason. Descriptions are not
-- values: a migration may still rewrite them freely.
--
-- The five source-network points migration 025 raised from 0 are marked as its
-- doing where they hold its value and have no reason yet.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 026_change_reasons.sql

BEGIN;

ALTER TABLE risk_policy_settings ADD COLUMN IF NOT EXISTS change_reason VARCHAR(256);
ALTER TABLE risk_policy_settings ADD COLUMN IF NOT EXISTS changed_by VARCHAR(128);
ALTER TABLE app_installations ADD COLUMN IF NOT EXISTS status_reason VARCHAR(256);
ALTER TABLE app_installations ADD COLUMN IF NOT EXISTS status_changed_by VARCHAR(128);
ALTER TABLE app_installations ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
ALTER TABLE recognized_devices ADD COLUMN IF NOT EXISTS status_reason VARCHAR(256);
ALTER TABLE recognized_devices ADD COLUMN IF NOT EXISTS status_changed_by VARCHAR(128);
ALTER TABLE recognized_devices ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;

UPDATE risk_policy_settings AS t
SET change_reason = 'Migration 025: the owner''s default since 2026-10-16; migration 023 had seeded 0'
FROM (VALUES
    ('source_vpn_listed_points', '10'),
    ('source_tor_exit_points', '30'),
    ('source_hosting_points', '15'),
    ('source_vpn_observed_points', '10'),
    ('source_vpn_observed_non_hosting_points', '10')
) AS s(setting_key, setting_value)
WHERE t.setting_key = s.setting_key
  AND t.setting_value = s.setting_value
  AND t.change_reason IS NULL;

CREATE OR REPLACE FUNCTION risk_policy_settings_require_reason() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.change_reason IS NULL OR btrim(NEW.change_reason) = ''
       OR NEW.change_reason IS NOT DISTINCT FROM OLD.change_reason THEN
        RAISE EXCEPTION 'risk_policy_settings %: say why it changes -- set change_reason, a new one, in the same UPDATE as setting_value', NEW.setting_key
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.changed_by := session_user;
    NEW.updated_at := NOW();
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS risk_policy_settings_require_reason ON risk_policy_settings;
CREATE TRIGGER risk_policy_settings_require_reason
    BEFORE UPDATE OF setting_value ON risk_policy_settings
    FOR EACH ROW
    WHEN (OLD.setting_value IS DISTINCT FROM NEW.setting_value)
    EXECUTE FUNCTION risk_policy_settings_require_reason();

CREATE OR REPLACE FUNCTION status_require_reason() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status_reason IS NULL OR btrim(NEW.status_reason) = ''
       OR NEW.status_reason IS NOT DISTINCT FROM OLD.status_reason THEN
        RAISE EXCEPTION '%: say why the status changes -- set status_reason, a new one, in the same UPDATE as status', TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.status_changed_by := session_user;
    NEW.status_changed_at := NOW();
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS app_installations_status_require_reason ON app_installations;
CREATE TRIGGER app_installations_status_require_reason
    BEFORE UPDATE OF status ON app_installations
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION status_require_reason();

DROP TRIGGER IF EXISTS recognized_devices_status_require_reason ON recognized_devices;
CREATE TRIGGER recognized_devices_status_require_reason
    BEFORE UPDATE OF status ON recognized_devices
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION status_require_reason();

INSERT INTO schema_migrations (version, description)
VALUES (26, 'A reason, the database login and the time with every hand-made change of a setting or a status')
ON CONFLICT (version) DO NOTHING;

COMMIT;
