-- Device Trust schema, PostgreSQL 13+
-- Migration 003: DBA-tunable risk policy settings
--
-- A per-deployment, DBA-owned key/value table for the risk-policy knobs the
-- server reads at runtime: step-up mode/factor/window (DESIGN.md 51.2-51.3) and
-- the server-side behavioural anomaly signals -- per-key request-rate and
-- population-baseline deviation (DESIGN.md 51.6). The application READS this
-- table and never writes it; the consumer's DBA tunes values with UPDATE, and
-- re-running this script never overwrites a tuned value (ON CONFLICT DO NOTHING).
--
-- Every anomaly signal ships DISABLED (..._enabled = '0'): opt-in and advisory,
-- never a lockout, per the false-positive rule in DESIGN.md.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 003_risk_policy_settings.sql

BEGIN;

CREATE TABLE IF NOT EXISTS risk_policy_settings (
    setting_key   VARCHAR(64) PRIMARY KEY,
    setting_value VARCHAR(256) NOT NULL,
    description   VARCHAR(256),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('stepup_mode', 'per_use', 'Step-up mode for sensitive ops: per_use (a) or windowed (b).'),
    ('stepup_window_seconds', '0', 'Hardware-enforced reuse window for windowed step-up; 0 = per-use.'),
    ('stepup_factor', 'passcode', 'Required device auth factor: passcode or biometric.'),
    ('stepup_required_paths', '', 'Comma-separated request paths requiring a valid step-up proof (empty = none).'),
    ('rate_anomaly_enabled', '0', 'Enable per-key request-rate anomaly signal (advisory).'),
    ('rate_anomaly_max_requests', '120', 'Requests per key per window before the signal trips.'),
    ('rate_anomaly_window_seconds', '60', 'Window length for the request-rate anomaly signal.'),
    ('rate_anomaly_points', '30', 'Advisory risk points added when the rate signal trips.'),
    ('population_baseline_enabled', '0', 'Enable population-baseline deviation signal (advisory).'),
    ('population_baseline_metric', 'accounts_per_device', 'Relationship metric to threshold: accounts_per_device or installations_per_device.'),
    ('population_baseline_threshold', '10', 'Advisory when the chosen metric exceeds this consumer-set base.'),
    ('population_points', '30', 'Advisory risk points added when the population signal trips.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (3, 'DBA-tunable risk policy settings')
ON CONFLICT (version) DO NOTHING;

COMMIT;
