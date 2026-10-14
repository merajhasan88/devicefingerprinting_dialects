-- Device Trust schema, PostgreSQL 13+
-- Migration 019: the server's own observations, measured into every decision
--
-- DESIGN.md 77. Corroboration that does not come from the phone: what this
-- server itself sees when it refuses or changes something -- a wrong password,
-- a sign-in to an account that does not exist, a step-up (screen-lock) proof
-- that does not verify, an approval request refused because the account's
-- hourly budget is spent, a step-up key re-enrolled. Each is recorded with the
-- account (when there is one) and the phone and installation whose key made
-- the request: the server's own opaque IDs -- no handle, no network address,
-- no personal data. Denied approvals are already rows of
-- session_upgrade_requests and are counted there.
--
-- Every risk decision's context carries the counts. Scoring them is the DBA's
-- switch, cross_checks_enabled, off by default: observe first. The counts and
-- points below are the proposed defaults a DBA tunes; 0 switches a rule off.
-- server_observations is audit evidence; the server never updates or deletes
-- it -- grant the application principal SELECT, INSERT.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 019_server_observations.sql

BEGIN;

CREATE TABLE IF NOT EXISTS server_observations (
    observation_id  UUID PRIMARY KEY,
    kind            VARCHAR(48) NOT NULL,
    code            VARCHAR(64),
    account_id      UUID REFERENCES demo_accounts(account_id),
    device_id       UUID REFERENCES recognized_devices(device_id),
    installation_id UUID REFERENCES app_installations(installation_id),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS server_observations_account_idx
    ON server_observations(account_id, occurred_at);
CREATE INDEX IF NOT EXISTS server_observations_device_idx
    ON server_observations(device_id, occurred_at);
-- Denied approvals are counted per requesting phone.
CREATE INDEX IF NOT EXISTS session_upgrade_requests_device_idx
    ON session_upgrade_requests(device_id, denied_at);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('cross_checks_enabled', '0', 'Score the server''s own observations with the rules below (DESIGN.md 77). 0 (owner default: observe first) = counted into every decision''s context, scored nowhere; 1 = each rule adds its points once its count is reached.'),
    ('cross_check_window_hours', '24', 'Hours the server''s observations are counted over, for the context and every rule below.'),
    ('account_sign_in_failures_elsewhere_count', '5', 'Wrong-password sign-ins to the account from OTHER phones in the window before a phone joined it. Judges only a phone joining now or within the window, never one there before them; a user mistyping on their own phone is not counted.'),
    ('account_sign_in_failures_elsewhere_points', '30', 'Points for account_sign_in_failures_elsewhere.'),
    ('device_sign_in_failures_many_accounts_count', '3', 'Different accounts with a wrong-password sign-in from this phone in the window.'),
    ('device_sign_in_failures_many_accounts_points', '60', 'Points for device_sign_in_failures_many_accounts.'),
    ('device_sign_in_unknown_accounts_count', '5', 'Sign-ins from this phone to accounts that do not exist, in the window.'),
    ('device_sign_in_unknown_accounts_points', '30', 'Points for device_sign_in_unknown_accounts.'),
    ('device_stepup_failures_count', '3', 'Step-up (screen-lock) proofs from this phone that did not verify, in the window. A request sent without a proof is not one.'),
    ('device_stepup_failures_points', '30', 'Points for device_stepup_failures.'),
    ('device_approvals_denied_count', '1', 'Approval requests from this phone that the account''s other phone denied, in the window.'),
    ('device_approvals_denied_points', '30', 'Points for device_approvals_denied.'),
    ('device_approvals_denied_effect', 'limit', 'limit (owner default) = a denied phone is held at review, a limited session, for the window, and a denial alone never blocks it; points = its points are added like any rule''s, and can reach block.'),
    ('device_approval_budget_exhausted_count', '1', 'Approval requests from this phone refused because the account''s hourly budget was spent, in the window.'),
    ('device_approval_budget_exhausted_points', '30', 'Points for device_approval_budget_exhausted.'),
    ('device_stepup_reenrolments_count', '2', 'Step-up keys re-enrolled on this phone in the window.'),
    ('device_stepup_reenrolments_points', '30', 'Points for device_stepup_reenrolments.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (19, 'the server''s own observations, measured into every decision')
ON CONFLICT (version) DO NOTHING;

COMMIT;
