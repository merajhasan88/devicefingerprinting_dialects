-- Device Trust schema, PostgreSQL 13+
-- Migration 022: the network probe's eligibility rules, optional measurements,
-- and request metadata
--
-- DESIGN.md 80 (owner decisions of 2026-10-15). Collectors from Android 4 and
-- iOS 3 volunteer two probes on every scan, device (the OS version and
-- security patch level) and network (a VPN, an HTTP proxy); a VPN or a proxy
-- is recorded at 0 points, and the eligibility rules below let a deployment
-- refuse them instead. optional_measurements names what else the server asks
-- for -- local_addresses, the phone's own IP addresses -- which a phone sends
-- only if its app's developers enabled it too; anything not requested is
-- dropped before a report is stored. record_source_ip and record_user_agent
-- keep the request's address and User-Agent in each risk decision's context.
-- Each is off unless the DBA turns it on: the address and the phone's own
-- addresses are personal data, kept as long as the decisions and reports are.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 022_network_and_optional_measurements.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('vpn_active_refuses', '0', 'Eligibility rule: 1 refuses a phone whose latest scan reports a VPN active (android_vpn_active, ios_vpn_active), with its own code and remedy; 0 (owner default) = recorded at 0 points. A phone whose app predates the network probe reports none.'),
    ('http_proxy_refuses', '0', 'Eligibility rule: 1 refuses a phone whose latest scan reports an HTTP proxy configured (android_http_proxy, ios_http_proxy); 0 (owner default) = recorded at 0 points.'),
    ('optional_measurements', '', 'Optional measurements the server asks each scan for, comma-separated: local_addresses = the phone''s own IP addresses. Empty (owner default) = none. Sent only if the app enables it too; anything not listed is dropped, never stored.'),
    ('record_source_ip', '0', '1 = keep the IP address each request came from in its risk decision''s context (source_ip); 0 (owner default) = not kept. Personal data: kept as long as the decisions are.'),
    ('record_user_agent', '0', '1 = keep each request''s User-Agent header in its risk decision''s context (user_agent); 0 (owner default) = not kept.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (22, 'network eligibility rules, optional measurements, request metadata')
ON CONFLICT (version) DO NOTHING;

COMMIT;
