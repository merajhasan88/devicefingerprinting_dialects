-- Device Trust schema, SQL Server 2016+
-- Migration 022: the network probe's eligibility rules, optional measurements,
-- and request metadata
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 80). MERGE never
-- overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 022_network_and_optional_measurements.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('vpn_active_refuses', '0', 'Eligibility rule: 1 refuses a phone whose latest scan reports a VPN active (android_vpn_active, ios_vpn_active), with its own code and remedy; 0 (owner default) = recorded at 0 points. A phone whose app predates the network probe reports none.'),
    ('http_proxy_refuses', '0', 'Eligibility rule: 1 refuses a phone whose latest scan reports an HTTP proxy configured (android_http_proxy, ios_http_proxy); 0 (owner default) = recorded at 0 points.'),
    ('optional_measurements', '', 'Optional measurements the server asks each scan for, comma-separated: local_addresses = the phone''s own IP addresses. Empty (owner default) = none. Sent only if the app enables it too; anything not listed is dropped, never stored.'),
    ('record_source_ip', '0', '1 = keep the IP address each request came from in its risk decision''s context (source_ip); 0 (owner default) = not kept. Personal data: kept as long as the decisions are.'),
    ('record_user_agent', '0', '1 = keep each request''s User-Agent header in its risk decision''s context (user_agent); 0 (owner default) = not kept.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 22)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (22, 'network eligibility rules, optional measurements, request metadata');
GO
