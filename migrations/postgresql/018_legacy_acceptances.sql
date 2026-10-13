-- Device Trust schema, PostgreSQL 13+
-- Migration 018: approvals granted before migration 016 are carried over
--
-- DESIGN.md 76 (owner decision of 2026-10-13). An approval granted before 016
-- recorded only its categories, not the reasons it approved, so the
-- reason-by-reason rule has nothing to compare against. With the owner's
-- default, 'carry', the first time such an approval is used the server
-- records what it covers at that moment -- collection problems excepted,
-- which are never approved -- and keeps it until the approval's own expiry;
-- from then on a new reason needs a new decision, and users do nothing.
-- 'drop' makes approvals not yet carried over cover nothing: their sessions
-- narrow at their next refresh and their users re-confirm.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 018_legacy_acceptances.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('legacy_acceptances', 'carry', 'Approvals granted before migration 016: carry (owner default) = keep each as what it covers at its first use, until its expiry; drop = they cover nothing and their users re-confirm.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (18, 'approvals granted before migration 016 are carried over')
ON CONFLICT (version) DO NOTHING;

COMMIT;
