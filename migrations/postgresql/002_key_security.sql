-- Device Trust schema, PostgreSQL 13+
-- Migration 002: record the key security level the client reports
--
-- Why this exists. The client has always obtained security_level,
-- hardware_backed and provider from the platform keystore, and has always
-- required them to be present -- but never sent them, and the server had
-- nowhere to put them. A Secure Enclave / StrongBox key and a software
-- fallback key were therefore indistinguishable server-side, so a successful
-- enrolment proved nothing about hardware backing. See DESIGN.md 35.
--
-- Every column is NULLABLE, and that is load-bearing. NULL means "this client
-- did not report it" and must never be read as "software". Treating an absent
-- measurement as a good one is the defect recorded in DESIGN.md 28.8 (an
-- integrity bucket reporting compared_bytes: 0 and scoring as clean) and again
-- in the .NET session's wx_bytes finding. The same trap, a third time.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -f 002_key_security.sql

BEGIN;

ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS key_security_level VARCHAR(32);
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS key_hardware_backed BOOLEAN;
ALTER TABLE app_installations
    ADD COLUMN IF NOT EXISTS key_provider VARCHAR(64);

INSERT INTO schema_migrations (version, description)
VALUES (2, 'record reported key security level')
ON CONFLICT (version) DO NOTHING;

COMMIT;
