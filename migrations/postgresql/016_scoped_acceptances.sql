-- Device Trust schema, PostgreSQL 13+
-- Migration 016: an upgrade accepts exactly what was approved
--
-- DESIGN.md 76 (review R1, owner decisions of 2026-10-13). An upgrade made
-- with a proof used to accept whole categories (integrity_elevated,
-- risk_review) for up to 30 days, so a later, different finding in the same
-- band -- a tracer after approved runtime growth -- passed unseen. Each
-- acceptance is now a record: the reason codes and points that were approved,
-- the relationship counts seen then, who approved, which scan and build, and
-- when it lapses or was revoked. A new reason, more points, or more accounts
-- or devices than were approved is not covered: the session needs a new
-- decision, and the first time each new reason appears it is written to
-- acceptance_lapses -- the measurement the business reads; whether a reason
-- may be covered automatically is the business's decision
-- (acceptance_auto_cover_reasons, empty by default). Collection problems are
-- never accepted: only a complete scan clears them.
--
-- session_acceptances and acceptance_lapses are audit evidence; the server
-- never deletes from them -- grant the application principal SELECT, INSERT,
-- UPDATE (session_acceptances) and SELECT, INSERT (acceptance_lapses).
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 016_scoped_acceptances.sql

BEGIN;

CREATE TABLE IF NOT EXISTS session_acceptances (
    acceptance_id            UUID PRIMARY KEY,
    family_id                UUID NOT NULL,
    account_id               UUID NOT NULL REFERENCES demo_accounts(account_id),
    device_id                UUID NOT NULL REFERENCES recognized_devices(device_id),
    installation_id          UUID NOT NULL REFERENCES app_installations(installation_id),
    route                    VARCHAR(16) NOT NULL,
    request_id               UUID,
    approved_by_installation UUID,
    causes                   VARCHAR(128) NOT NULL,
    reasons                  JSONB NOT NULL,
    device_accounts          INTEGER,
    account_devices          INTEGER,
    evidence_quality         VARCHAR(16),
    integrity_report_id      UUID,
    apk_sha256               VARCHAR(64),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMPTZ NOT NULL,
    revoked_at               TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS session_acceptances_family_idx
    ON session_acceptances(family_id);

CREATE TABLE IF NOT EXISTS acceptance_lapses (
    acceptance_id   UUID NOT NULL REFERENCES session_acceptances(acceptance_id),
    reason_code     VARCHAR(96) NOT NULL,
    source          VARCHAR(16) NOT NULL,
    points          INTEGER NOT NULL,
    account_id      UUID NOT NULL,
    installation_id UUID NOT NULL,
    event_type      VARCHAR(32) NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (acceptance_id, reason_code)
);

CREATE INDEX IF NOT EXISTS acceptance_lapses_occurred_idx
    ON acceptance_lapses(occurred_at);

ALTER TABLE refresh_sessions
    ADD COLUMN IF NOT EXISTS acceptance_id UUID;
ALTER TABLE session_upgrade_requests
    ADD COLUMN IF NOT EXISTS causes VARCHAR(128);
ALTER TABLE session_upgrade_requests
    ADD COLUMN IF NOT EXISTS reasons JSONB;
ALTER TABLE session_upgrade_requests
    ADD COLUMN IF NOT EXISTS device_accounts INTEGER;
ALTER TABLE session_upgrade_requests
    ADD COLUMN IF NOT EXISTS account_devices INTEGER;
ALTER TABLE risk_policy_decisions
    ADD COLUMN IF NOT EXISTS acceptance_id UUID;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('acceptance_auto_cover_reasons', '', 'Reason codes an approved session accepts automatically even if they appear after the approval, comma-separated. A business decision; empty (owner default) = every new reason needs a new decision. Collection problems are never covered.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (16, 'an upgrade accepts exactly what was approved')
ON CONFLICT (version) DO NOTHING;

COMMIT;
