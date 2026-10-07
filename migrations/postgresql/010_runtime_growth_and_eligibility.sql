-- Device Trust schema, PostgreSQL 13+
-- Migration 010: DBA-tunable W^X growth allowance and eligibility rules
--
-- Joint review R1 (DESIGN.md 69). A runtime that generates code as a session
-- warms (.NET on Android) legitimately maps more writable-and-executable
-- memory than its pinned baseline; growth up to wx_far_above_baseline_percent
-- of the baseline is now advisory, and only growth beyond it scores
-- (android_wx_far_above_baseline, +40). Developer options and ADB are advisory
-- too; a deployment that wants them off makes that an eligibility rule, which
-- refuses explicitly (integrity_device_ineligible) instead of adding points.
-- The owner's defaults are seeded here; the consumer's DBA may change any of
-- them, and re-running this script never overwrites a tuned value.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 010_runtime_growth_and_eligibility.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('wx_far_above_baseline_percent', '200', 'W^X memory above this percentage of the build''s pinned baseline scores +40 (android_wx_far_above_baseline); between the baseline and this percentage it is expected runtime growth, advisory. 200 = twice the baseline. Minimum 100.'),
    ('developer_options_refuses', '0', 'Eligibility rule. 1 = in enforce mode an installation whose latest scan reports Developer options on is refused (integrity_device_ineligible) until they are off and a new scan is sent; 0 = advisory only.'),
    ('adb_enabled_refuses', '0', 'Eligibility rule. 1 = in enforce mode an installation whose latest scan reports USB debugging (ADB) on is refused (integrity_device_ineligible) until it is off and a new scan is sent; 0 = advisory only.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (10, 'DBA-tunable W^X growth allowance and eligibility rules')
ON CONFLICT (version) DO NOTHING;

COMMIT;
