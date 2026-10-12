-- Device Trust schema, PostgreSQL 13+
-- Migration 014: a newer approval request replaces the same phone's pending ones
--
-- DESIGN.md 75. When an installation asks for approval again for the same
-- account, its earlier requests that are still pending are marked superseded,
-- so the approving phone sees one request per phone instead of duplicates.
-- The rows stay as evidence; only superseded_at is set. Approving or denying a
-- superseded request is refused with approval_superseded, and the requester
-- reads its state as superseded.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 014_superseded_requests.sql

BEGIN;

ALTER TABLE session_upgrade_requests
    ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;

INSERT INTO schema_migrations (version, description)
VALUES (14, 'a newer approval request supersedes the same phone''s pending ones')
ON CONFLICT (version) DO NOTHING;

COMMIT;
