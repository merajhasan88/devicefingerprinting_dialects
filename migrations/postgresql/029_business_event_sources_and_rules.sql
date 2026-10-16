-- Device Trust schema, PostgreSQL 13+
-- Migration 029: events from the business's other services -- which types each
-- caller may send, where each came from, and the business's own rules over them
--
-- DESIGN.md 84.5, item 4 of the eight the owner approved on 2026-10-14. An
-- event may carry the address it came from (a web sign-in, a password reset):
-- the server classifies it with the same lists as a request's own address
-- and keeps only its kinds and a keyed hash, never the address. The DBA may
-- limit each caller to its event types, and may write rules that score
-- events; none by default -- business rules are the business's.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 029_business_event_sources_and_rules.sql

BEGIN;

ALTER TABLE business_events ADD COLUMN IF NOT EXISTS source_kinds VARCHAR(128);
ALTER TABLE business_events ADD COLUMN IF NOT EXISTS source_hash CHAR(64);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('business_event_types_by_producer', '', 'Which event types each business API caller may send: caller:type+type, comma-separated. A caller not listed is held only to business_event_types. Empty (owner default) = no per-caller limit.'),
    ('business_event_rules', '', 'Your rules over business events, each type[/outcome][@source kind]:count:hours:points[:account|device|newcomer] -- e.g. chargeback:1:720:40. Each adds its points to a decision when it matches. Empty (owner default) = none: the business decides.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (29, 'Business events: types per caller, their source addresses, the DBA''s rules')
ON CONFLICT (version) DO NOTHING;

COMMIT;
