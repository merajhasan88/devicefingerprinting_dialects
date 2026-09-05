-- Device Trust schema, PostgreSQL 13+
-- Migration 001: initial schema
--
-- Run as a database owner/DDL role. The application does NOT create or alter
-- schema at runtime; it verifies the version recorded in schema_migrations at
-- startup and refuses to serve on a mismatch. Give the application principal
-- only DML rights (SELECT/INSERT/UPDATE/DELETE) on these tables.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 001_initial.sql
--
-- Safe to run against an existing database created by the retired runtime
-- schema guard: every statement is guarded.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recognized_devices (
    device_id           UUID PRIMARY KEY,
    platform            VARCHAR(16) NOT NULL,
    reinstall_hint_hash CHAR(64),
    status              VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recognized_devices_platform_hint_unique
        UNIQUE (platform, reinstall_hint_hash)
);

CREATE TABLE IF NOT EXISTS app_installations (
    installation_id         UUID PRIMARY KEY,
    device_id               UUID NOT NULL REFERENCES recognized_devices(device_id),
    key_algorithm           VARCHAR(16) NOT NULL,
    public_key_jwk          JSONB NOT NULL,
    -- Retained so first-generation RS256 rows stay verifiable beside ES256 keys.
    public_key_n            TEXT,
    public_key_e            TEXT,
    key_thumbprint          CHAR(64) NOT NULL UNIQUE,
    registration_method     VARCHAR(32) NOT NULL,
    registration_confidence VARCHAR(16) NOT NULL,
    status                  VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS app_installations_device_idx
    ON app_installations(device_id);

CREATE TABLE IF NOT EXISTS installation_challenges (
    challenge_id    UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    purpose         VARCHAR(128) NOT NULL,
    payload_sha256  CHAR(64) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index: only unconsumed challenges are ever looked up.
CREATE INDEX IF NOT EXISTS installation_challenges_open_idx
    ON installation_challenges(installation_id, expires_at)
    WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS demo_accounts (
    account_id    UUID PRIMARY KEY,
    handle_lookup CHAR(64) NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_account_links (
    device_id             UUID NOT NULL REFERENCES recognized_devices(device_id),
    account_id            UUID NOT NULL REFERENCES demo_accounts(account_id),
    first_installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    first_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, account_id)
);

CREATE TABLE IF NOT EXISTS refresh_sessions (
    session_id      UUID PRIMARY KEY,
    family_id       UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES demo_accounts(account_id),
    device_id       UUID NOT NULL REFERENCES recognized_devices(device_id),
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS refresh_sessions_family_idx
    ON refresh_sessions(family_id);

-- Anti-replay. The primary key is the whole defence: the row is inserted only
-- after the request signature verifies, and a duplicate key IS the replay.
CREATE TABLE IF NOT EXISTS access_proof_nonces (
    nonce_hash       CHAR(64) PRIMARY KEY,
    installation_id  UUID NOT NULL REFERENCES app_installations(installation_id),
    access_token_jti VARCHAR(128) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS access_proof_nonces_installation_idx
    ON access_proof_nonces(installation_id, expires_at);

CREATE TABLE IF NOT EXISTS risk_policy_decisions (
    decision_id        UUID PRIMARY KEY,
    event_type         VARCHAR(32) NOT NULL,
    account_id         UUID,
    device_id          UUID NOT NULL REFERENCES recognized_devices(device_id),
    installation_id    UUID NOT NULL REFERENCES app_installations(installation_id),
    policy_mode        VARCHAR(16) NOT NULL,
    recommended_action VARCHAR(16) NOT NULL,
    effective_action   VARCHAR(16) NOT NULL,
    score              INTEGER NOT NULL,
    reasons            JSONB NOT NULL,
    context            JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS risk_policy_decisions_device_idx
    ON risk_policy_decisions(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS risk_policy_decisions_account_idx
    ON risk_policy_decisions(account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS integrity_challenges (
    challenge_id    UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES app_installations(installation_id),
    device_id       UUID NOT NULL REFERENCES recognized_devices(device_id),
    platform        VARCHAR(16) NOT NULL,
    nonce_sha256    CHAR(64) NOT NULL,
    required_probes JSONB NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS integrity_challenges_installation_idx
    ON integrity_challenges(installation_id, created_at DESC);

-- Reported challenges are audit evidence. Never ON DELETE CASCADE: expired
-- challenge cleanup must skip any challenge that has a report.
CREATE TABLE IF NOT EXISTS integrity_reports (
    report_id         UUID PRIMARY KEY,
    challenge_id      UUID NOT NULL UNIQUE REFERENCES integrity_challenges(challenge_id),
    installation_id   UUID NOT NULL REFERENCES app_installations(installation_id),
    device_id         UUID NOT NULL REFERENCES recognized_devices(device_id),
    platform          VARCHAR(16) NOT NULL,
    collector_version INTEGER NOT NULL,
    score             INTEGER NOT NULL,
    verdict           VARCHAR(16) NOT NULL,
    hard_block        BOOLEAN NOT NULL DEFAULT FALSE,
    reasons           JSONB NOT NULL,
    probe_results     JSONB NOT NULL,
    report_sha256     CHAR(64) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS integrity_reports_installation_idx
    ON integrity_reports(installation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS integrity_reports_device_idx
    ON integrity_reports(device_id, created_at DESC);

INSERT INTO schema_migrations (version, description)
VALUES (1, 'initial schema')
ON CONFLICT (version) DO NOTHING;

COMMIT;
