-- Device Trust schema, PostgreSQL 13+
-- Migration 021: the rest of the policy in the DBA's hands; session
-- lifetimes; support unlock and reset of an app PIN; the integrity-report feed
--
-- DESIGN.md 79 (owner decisions of 2026-10-14).
--
-- G1: the relationship rules that were still in the code or in environment
-- variables become DBA settings, each seeded at the value the code used: a new
-- phone, a known phone's new installation, reinstall velocity, a missing or
-- stale scan, another installation on the phone blocked, how fresh a scan
-- must be, and the hardware-backing policy. The environment variables remain
-- only as fallbacks for a missing row, like POLICY_*.
--
-- G8: how long a session lives. refresh_idle_days is today's behaviour -- each
-- refresh extends the session, so it ends after that many idle days -- and
-- session_max_days, 0 by default, can cap a session from its first sign-in.
--
-- Support: a business may let its support staff, after verifying the
-- customer, unlock a locked app PIN or allow one reset of it -- the next PIN
-- may then be set from a limited session, with the password, within
-- app_pin_support_reset_minutes. Off unless the DBA chooses a level;
-- app_pins.reset_until holds the grant, and pin_hash may now be empty for an
-- account granted a reset before it ever had a PIN.
--
-- The business feed of every integrity report (/v1/business/integrity-reports)
-- pages through them in time order; one index serves it. On a large table a
-- DBA may build it first with CREATE INDEX CONCURRENTLY, outside this script.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 021_relationship_settings_sessions_support.sql

BEGIN;

ALTER TABLE app_pins ADD COLUMN IF NOT EXISTS reset_until TIMESTAMPTZ;
ALTER TABLE app_pins ALTER COLUMN pin_hash DROP NOT NULL;

CREATE INDEX IF NOT EXISTS integrity_reports_created_idx
    ON integrity_reports(created_at, report_id);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('new_device_points', '10', 'Points for a phone first seen less than new_device_hours ago. 0 switches the rule off.'),
    ('new_device_hours', '24', 'How long a newly recognized phone counts as new.'),
    ('known_device_new_installation_points', '15', 'Points for a new installation correlated to a phone already recognized (a reinstall). 0 switches the rule off.'),
    ('reinstall_window_hours', '24', 'Hours over which proven reinstalls on one phone are counted.'),
    ('reinstall_elevated_count', '3', 'Reinstalls in the window that add reinstall_elevated_points. 0 switches the rule off.'),
    ('reinstall_elevated_points', '35', 'Points at reinstall_elevated_count.'),
    ('reinstall_high_count', '4', 'Reinstalls in the window that add reinstall_high_points. 0 switches the rule off.'),
    ('reinstall_high_points', '60', 'Points at reinstall_high_count.'),
    ('reinstall_block_count', '5', 'Reinstalls in the window that block the phone. 0 switches the rule off.'),
    ('integrity_report_missing_points', '40', 'Points when an installation has never sent a signed integrity scan.'),
    ('integrity_report_stale_points', '35', 'Points when the latest scan is older than integrity_freshness_seconds.'),
    ('integrity_freshness_seconds', '600', 'How old the latest integrity scan may be and still count as fresh.'),
    ('device_integrity_history_block_points', '50', 'Points when another installation on the same phone was blocked by integrity within integrity_device_memory_hours.'),
    ('hardware_backing_policy', 'off', 'off, advisory or required: how a software-backed installation key is scored (it is only ever the phone''s claim). This one adds integrity points.'),
    ('refresh_idle_days', '30', 'A session ends after this many days without a refresh; each refresh extends it (owner default 30). 1-90.'),
    ('session_max_days', '0', 'A session ends this many days after its first sign-in, however often it refreshes. 0 = no limit (owner default). Up to 365.'),
    ('app_pin_support', 'off', 'What support staff may do to a customer''s app PIN through the business API, after verifying the customer: off, unlock, or unlock_and_reset.'),
    ('app_pin_support_reset_minutes', '15', 'After a support reset, minutes within which the customer may set a new PIN, once, even from a limited session, with the password.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (21, 'relationship rules, session lifetimes and app PIN support as DBA settings')
ON CONFLICT (version) DO NOTHING;

COMMIT;
