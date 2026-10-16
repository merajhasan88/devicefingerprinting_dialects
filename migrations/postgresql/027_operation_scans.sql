-- Device Trust schema, PostgreSQL 13+
-- Migration 027: a scan made for one operation, used once -- the request it
-- approves named in its challenge
--
-- DESIGN.md 84.3, item 2 of the eight the owner approved on 2026-10-14. On a
-- path the DBA lists in operation_scan_paths the app first asks for a
-- challenge naming the exact request it is about to send -- method, path,
-- query and the SHA-256 of its body -- scans, and sends the request with the
-- scan's report_id. The server judges that scan, not the phone's latest one,
-- and only if it was made for this very request, is recent and complete, and
-- was not used before. A business backend that performs the operation itself
-- verifies the scan the same way through the business API (role operations).
--
-- Grant the application principal SELECT, INSERT on operation_scan_uses; never
-- UPDATE or DELETE: it is evidence of what each scan approved.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 027_operation_scans.sql

BEGIN;

ALTER TABLE integrity_challenges ADD COLUMN IF NOT EXISTS operation_sha256 CHAR(64);
ALTER TABLE integrity_reports ADD COLUMN IF NOT EXISTS operation_sha256 CHAR(64);

CREATE TABLE IF NOT EXISTS operation_scan_uses (
    report_id        UUID PRIMARY KEY REFERENCES integrity_reports(report_id),
    installation_id  UUID NOT NULL REFERENCES app_installations(installation_id),
    used_by          VARCHAR(64) NOT NULL,
    used_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('operation_scan_paths', '', 'Paths where a request needs a scan made for it alone: the app asks for a challenge naming the request (method, path, query, body SHA-256), scans, and sends the request with the report_id; each scan approves one request. Empty (owner default) = none.'),
    ('operation_scan_max_age_seconds', '120', 'How old a scan made for one operation may be when the operation arrives. 10-600.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (27, 'A scan made for one operation, used once')
ON CONFLICT (version) DO NOTHING;

COMMIT;
