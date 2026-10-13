-- Device Trust schema, PostgreSQL 13+
-- Migration 017: business events, combined with the phone-account graph
--
-- DESIGN.md 76 (owner decisions of 2026-10-13). The customer's own backend --
-- never the app -- reports business events (an advance, a payout, a failed
-- repayment, a chargeback, a credential change...) for an account, through an
-- authenticated server-to-server API. The server guarantees the measurements:
-- it stores each event as evidence, links it to the phone-account graph, and
-- returns the graph with per-account, per-device and per-component aggregates;
-- every risk decision's context carries the account's and the device's recent
-- counts. Whether any of it should refuse anything is the business's decision:
-- nothing here is scored.
--
-- No personal data: accounts are the server's opaque IDs; a subject reference
-- (a payee, a destination) is stored only as a keyed hash; event types and
-- outcomes are short codes, never free text. business_events is audit
-- evidence; the server never updates or deletes it -- grant the application
-- principal SELECT, INSERT.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 017_business_events.sql

BEGIN;

CREATE TABLE IF NOT EXISTS business_events (
    event_id     VARCHAR(64) PRIMARY KEY,
    account_id   UUID NOT NULL REFERENCES demo_accounts(account_id),
    event_type   VARCHAR(48) NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    amount_minor BIGINT,
    currency     CHAR(3),
    outcome      VARCHAR(32),
    subject_hash CHAR(64)
);

CREATE INDEX IF NOT EXISTS business_events_account_idx
    ON business_events(account_id, occurred_at);
CREATE INDEX IF NOT EXISTS business_events_subject_idx
    ON business_events(subject_hash, occurred_at);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('business_event_types', '', 'Business event types the server accepts, comma-separated. Empty: any well-formed type (a-z, 0-9, _).'),
    ('business_graph_depth', '2', 'Hops the phone-account graph API follows from its starting account or phone (account to phones is one hop). 1-4.'),
    ('business_graph_max_nodes', '200', 'Most accounts and phones the graph API returns; a larger component is cut and marked truncated.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (17, 'business events, combined with the phone-account graph')
ON CONFLICT (version) DO NOTHING;

COMMIT;
