-- Device Trust schema, PostgreSQL 13+
-- Migration 012: DBA-tunable relationship-risk bands and devices-per-account policy
--
-- The bands that turn a relationship-risk score into an action, and the counts
-- of devices one account may use, become risk_policy_settings rows seeded with
-- the owner's defaults: below 30 allow; 30-59 step-up (recorded, allowed unless
-- elevated_risk_refuses=1); 60-89 review (refused in enforce mode); 90 and
-- above block. A second device on an account is elevated (+35), a third or more
-- is held for review (+60), a fifth is blocked. A business whose users
-- legitimately share phones or carry more devices may retune any of them. The
-- POLICY_*_SCORE and POLICY_ACCOUNT_DEVICE_BLOCK_COUNT environment variables are
-- now only the fallbacks for a missing row. Re-running never overwrites a value.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 012_policy_bands_and_devices_per_account.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('policy_step_up_score', '30', 'Relationship-risk score from which a decision is step_up (recorded, allowed unless elevated_risk_refuses=1). Must be below policy_review_score.'),
    ('policy_review_score', '60', 'Relationship-risk score from which a decision is review (refused in enforce mode, or a limited session where listed). Must be below policy_block_score.'),
    ('policy_block_score', '90', 'Relationship-risk score from which a decision is block (always refused).'),
    ('account_devices_elevated_count', '2', 'Devices one account may use before its decisions are raised (elevated band). 0 = off.'),
    ('account_devices_elevated_points', '35', 'Risk points at the elevated devices-per-account count.'),
    ('account_devices_review_count', '3', 'Devices one account may use before its decisions are held for review. 0 = off.'),
    ('account_devices_review_points', '60', 'Risk points at the review devices-per-account count.'),
    ('account_devices_block_count', '5', 'Devices one account may use before it is blocked. 0 = off.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (12, 'DBA-tunable relationship bands and devices-per-account policy')
ON CONFLICT (version) DO NOTHING;

COMMIT;
