-- Device Trust schema, PostgreSQL 13+
-- Migration 028: each installation compared with its own earlier scans
--
-- DESIGN.md 84.4, item 5 of the eight the owner approved on 2026-10-14. An
-- installation's key lives in one phone's keystore and dies with the app, so
-- the same installation cannot legitimately move to another phone, change its
-- signer, go back to an older OS or app, or stop measuring what it measured.
-- Every scan is compared with the installation's earlier ones and the
-- reasons recorded; they add points only where the DBA sets
-- history_checks_enabled -- observe first, as the cross-checks (019). The
-- points are the owner's proposals, to confirm on real traffic.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 028_installation_history.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('history_checks_enabled', '0', '1 = the installation history reasons add their points; 0 (owner default) = each scan is still compared with the installation''s earlier ones and the reasons recorded at 0 -- observe first.'),
    ('history_window_hours', '24', 'Hours of an installation''s scans that installation_verdict_flips counts. 1-720.'),
    ('installation_verdict_flips_count', '4', 'Switches between suspicious (integrity findings of 30 or more) and clean scans within history_window_hours that make installation_verdict_flips. 0 = off.'),
    ('installation_signer_changed_points', '60', 'Points for installation_signer_changed: the app''s signing certificates or package changed under the same installation -- a repackaged app.'),
    ('installation_device_changed_points', '60', 'Points for installation_device_changed: the phone model changed under the same installation, whose key cannot leave its phone.'),
    ('installation_os_downgraded_points', '40', 'Points for installation_os_downgraded: the OS or its security patch went back under the same installation.'),
    ('installation_collector_downgraded_points', '30', 'Points for installation_collector_downgraded: a scan from an older collector than the installation used before.'),
    ('installation_app_downgraded_points', '30', 'Points for installation_app_downgraded: the app went back to an older version under the same installation.'),
    ('installation_coverage_dropped_points', '30', 'Points for installation_coverage_dropped: measurements taken before now missing, unsupported or switched off with no app or OS update to explain it.'),
    ('installation_verdict_flips_points', '30', 'Points for installation_verdict_flips: scans that keep switching between suspicious and clean.'),
    ('installation_app_changed_points', '0', 'Points for installation_app_changed: the app build changed since the last scan, normally an update. Owner default 0 = recorded only.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (28, 'Each installation compared with its own earlier scans')
ON CONFLICT (version) DO NOTHING;

COMMIT;
