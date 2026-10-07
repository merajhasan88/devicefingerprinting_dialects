-- Device Trust schema, PostgreSQL 13+
-- Migration 011: limited sessions and their upgrade
--
-- DESIGN.md 67 and 70. On a soft outcome at login, registration or refresh
-- (owner defaults: an elevated integrity verdict, a relationship step_up or
-- review), enforce mode issues a LIMITED session instead of a refusal. A limited
-- session reaches only the upgrade endpoints, the integrity scan and the paths
-- a DBA lists, and becomes full through /v1/auth/upgrade: by itself once the
-- soft cause has cleared, otherwise with one proof from a route the DBA enabled.
--
-- refresh_sessions.scope keeps the scope across refreshes (existing rows are
-- full). session_upgrade_requests records each approval request and assertion
-- nonce and what happened to it; it is audit evidence, and the server never
-- deletes from it -- grant the application principal SELECT, INSERT, UPDATE.
-- The owner's defaults are seeded; re-running never overwrites a tuned value.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 011_limited_sessions.sql

BEGIN;

ALTER TABLE refresh_sessions
    ADD COLUMN IF NOT EXISTS scope VARCHAR(16) NOT NULL DEFAULT 'full';
ALTER TABLE refresh_sessions
    ADD COLUMN IF NOT EXISTS limited_causes VARCHAR(128);

CREATE TABLE IF NOT EXISTS session_upgrade_requests (
    request_id               UUID PRIMARY KEY,
    route                    VARCHAR(16) NOT NULL,
    account_id               UUID NOT NULL REFERENCES demo_accounts(account_id),
    device_id                UUID NOT NULL REFERENCES recognized_devices(device_id),
    installation_id          UUID NOT NULL REFERENCES app_installations(installation_id),
    session_id               UUID NOT NULL REFERENCES refresh_sessions(session_id),
    family_id                UUID NOT NULL,
    nonce_sha256             CHAR(64),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMPTZ NOT NULL,
    approved_by_installation UUID REFERENCES app_installations(installation_id),
    approved_at              TIMESTAMPTZ,
    denied_at                TIMESTAMPTZ,
    consumed_at              TIMESTAMPTZ,
    assertion_method         VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS session_upgrade_requests_account_idx
    ON session_upgrade_requests(account_id, created_at DESC);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('limited_session_paths', '', 'Paths a limited session may reach besides the upgrade endpoints and the integrity scan, comma-separated. Empty: nothing else.'),
    ('limited_session_integrity_verdicts', 'elevated', 'Integrity verdicts that give a limited session instead of a 403 at login, registration and refresh (enforce mode): elevated and/or review. Empty: they refuse. A block always refuses.'),
    ('limited_session_policy_actions', 'step_up,review', 'Relationship outcomes that give a limited session instead of a 403 (enforce mode): step_up (refused only with elevated_risk_refuses=1) and/or review. Empty: they refuse. A block always refuses.'),
    ('upgrade_stepup_same_device', '0', '1 = a limited session may upgrade with a step-up proof from the same phone, only when every cause is integrity-related. Proves the screen lock, not who the user is.'),
    ('upgrade_other_device_approval', '1', '1 = a limited session may upgrade with an approval signed, with step-up, by another installation of the same account that holds a full session.'),
    ('upgrade_mfa_assertion', '0', '1 = a limited session may upgrade with an ES256 assertion signed by your identity backend (keys in UPGRADE_ASSERTION_JWKS_FILE). As strong as your MFA.'),
    ('upgrade_request_ttl_seconds', '300', 'Seconds an upgrade request (an approval request or an assertion nonce) stays valid. Minimum 30.'),
    ('upgrade_approvals_per_hour', '3', 'Approval requests one account may raise per hour, against prompt fatigue. 0 = none.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (11, 'limited sessions and their upgrade')
ON CONFLICT (version) DO NOTHING;

COMMIT;
