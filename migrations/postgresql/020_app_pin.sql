-- Device Trust schema, PostgreSQL 13+
-- Migration 020: an app PIN the server checks, beside the screen-lock key
--
-- DESIGN.md 78 (owner decision of 2026-10-14: build every option, the DBA
-- chooses). A step-up -- the user proving they are present for a sensitive
-- operation -- can be the phone's screen-lock key (as before), an app PIN the
-- server checks, or both, per deployment (stepup_method), and the app PIN can
-- be required in addition on chosen paths (app_pin_required_paths). The
-- owner's default (2026-10-14) is the app PIN.
--
-- One PIN per account. Only a verifier is stored: bcrypt over an HMAC of the
-- account and the PIN, keyed by a secret derived from the server's root
-- secret, so a copy of this table alone cannot be searched; failed attempts
-- are counted here, and the PIN locks after app_pin_max_failures in a row
-- until the user sets a new one with the account password. app_pins is a
-- credential store: the server inserts and updates it and never deletes from
-- it -- grant the application principal SELECT, INSERT, UPDATE.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 020_app_pin.sql

BEGIN;

CREATE TABLE IF NOT EXISTS app_pins (
    account_id          UUID PRIMARY KEY REFERENCES demo_accounts(account_id),
    pin_hash            BYTEA NOT NULL,
    failures            INTEGER NOT NULL DEFAULT 0,
    locked_at           TIMESTAMPTZ,
    set_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    set_by_installation UUID REFERENCES app_installations(installation_id)
);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('stepup_method', 'app_pin', 'How a step-up is proven wherever one is required (the step-up paths, approving another phone, the same-phone upgrade, an elevated scan): app_pin (owner default, checked by the server), screen_lock or screen_lock_and_app_pin.'),
    ('app_pin_required_paths', '', 'Paths that need the app PIN in addition to anything else, comma-separated (for example payee changes, large transfers). Empty: none.'),
    ('app_pin_length', '6', 'Digits in an app PIN, 4-12.'),
    ('app_pin_max_failures', '5', 'Wrong app PINs in a row before the PIN locks; the user then sets a new one with the account password. At least 1.'),
    ('device_app_pin_failures_count', '3', 'Wrong app PINs for one account from this phone in the window (DESIGN.md 77).'),
    ('device_app_pin_failures_points', '30', 'Points for device_app_pin_failures.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (20, 'an app PIN the server checks, beside the screen-lock key')
ON CONFLICT (version) DO NOTHING;

COMMIT;
