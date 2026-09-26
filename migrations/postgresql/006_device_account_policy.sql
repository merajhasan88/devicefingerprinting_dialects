-- Device Trust schema, PostgreSQL 13+
-- Migration 006: DBA-tunable accounts-per-device policy
--
-- Seeds the owner's defaults for how many accounts may share one recognized
-- device (DESIGN.md 54): two is elevated but never refused -- a phone shared by
-- two people is legitimate; three is held for review; four is blocked. Whether
-- an elevated (step-up band) decision refuses a request at all is its own
-- setting, off by default. The consumer's DBA may change any of these; re-running
-- this script never overwrites a tuned value (ON CONFLICT DO NOTHING).
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 006_device_account_policy.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('device_accounts_elevated_count', '2', 'Accounts on one device that raise the score (elevated band).'),
    ('device_accounts_elevated_points', '35', 'Risk points at the elevated account count.'),
    ('device_accounts_review_count', '3', 'Accounts on one device that are held for review.'),
    ('device_accounts_review_points', '60', 'Risk points at the review account count.'),
    ('device_accounts_block_count', '4', 'Accounts on one device that are blocked outright.'),
    ('elevated_risk_refuses', '0', 'In enforce mode, 1 = an elevated (step-up band) decision refuses the request; 0 = recorded, not refused.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (6, 'DBA-tunable accounts-per-device policy')
ON CONFLICT (version) DO NOTHING;

COMMIT;
