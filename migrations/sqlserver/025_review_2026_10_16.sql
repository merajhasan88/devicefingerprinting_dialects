-- Device Trust schema, SQL Server 2016+
-- Migration 025: the critical review of 2026-10-16 -- conditions capped and kept
-- out of the device memory, measurements a path requires, every report and
-- decision stamped with the settings it was judged under, business API callers
-- named, new owner defaults for signals that scored 0
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 83). MERGE never
-- overwrites a tuned value; the UPDATEs change a setting only where it still
-- holds its earlier default of 0.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 025_review_2026_10_16.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.integrity_reports', 'measurement_status') IS NULL
    ALTER TABLE dbo.integrity_reports ADD measurement_status nvarchar(max) NULL;
GO

IF COL_LENGTH('dbo.integrity_reports', 'policy_version') IS NULL
    ALTER TABLE dbo.integrity_reports ADD policy_version varchar(16) NULL;
GO

IF COL_LENGTH('dbo.business_events', 'producer') IS NULL
    ALTER TABLE dbo.business_events ADD producer varchar(64) NULL;
GO

IF COL_LENGTH('dbo.server_observations', 'actor') IS NULL
    ALTER TABLE dbo.server_observations ADD actor varchar(64) NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('conditions_points_cap', '60', 'Most points the conditions add together -- apps that can read the screen, keyboard or notifications, remote-control apps, screen capture, fake GPS, an old patch, a VPN or proxy. Never kept in the device memory. 1-100.'),
    ('vpn_active_points', '10', 'Points for android_vpn_active and ios_vpn_active (iOS infers it): privacy and work VPNs are common, so it nudges. 0 = recorded only.'),
    ('http_proxy_points', '15', 'Points for android_http_proxy and ios_http_proxy: traffic-editing tools set one, so do some company networks. 0 = recorded only.'),
    ('accessibility_hidden_points', '30', 'Points for android_accessibility_hidden: a service the system setting names but the Accessibility list omits, as an Android bug allowed malware until the December 2022 patch.'),
    ('accessibility_hidden_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with a hidden Accessibility service is refused until it is off and a new scan is sent; 0 (owner default) = no refusal.'),
    ('external_display_points', '10', 'Points for android_external_display and ios_external_display: a display besides the phone''s own was on during the scan -- a cast, a mirror or a monitor, not proof of capture. 0 = recorded only.'),
    ('external_display_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with another display on is refused until it is disconnected and a new scan is sent; 0 (owner default) = no refusal.'),
    ('location_max_age_seconds', '600', 'How recent the phone''s last location must be to count: an older fake-GPS fix is kept in the report but not scored, and an older location reads as stale. 30-86400.'),
    ('vpn_exit_min_device_age_days', '7', 'Days the server must have known a phone before its sightings count towards learning a VPN exit: freshly made-up phone identities cannot label an address. 0-365.'),
    ('screen_capture_points', '30', 'Points for android_screen_captured and ios_screen_captured: the app''s screen recorded or mirrored during the scan. Another display alone is external_display_points. 0 = recorded only.'),
    ('screen_capture_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose screen was being recorded or mirrored during the scan is refused until that stops and a new scan is sent; 0 (owner default) = no refusal.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN MATCHED THEN
    UPDATE SET description = s.description
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

UPDATE dbo.risk_policy_settings
SET setting_value = CASE WHEN setting_value = '0' THEN '10' ELSE setting_value END,
    description = 'Points when a request comes from an address on the public VPN list shipped with the server. 0 = recorded only.'
WHERE setting_key = 'source_vpn_listed_points';
UPDATE dbo.risk_policy_settings
SET setting_value = CASE WHEN setting_value = '0' THEN '30' ELSE setting_value END,
    description = 'Points when a request comes from a Tor exit: on its own, a step-up. 0 = recorded only.'
WHERE setting_key = 'source_tor_exit_points';
UPDATE dbo.risk_policy_settings
SET setting_value = CASE WHEN setting_value = '0' THEN '15' ELSE setting_value END,
    description = 'Points when a request comes from a hosting or data-centre network not known as a VPN: cloud phones and bots, also some company networks. 0 = recorded only.'
WHERE setting_key = 'source_hosting_points';
UPDATE dbo.risk_policy_settings
SET setting_value = CASE WHEN setting_value = '0' THEN '10' ELSE setting_value END,
    description = 'Points when a request comes from an address learned as a VPN exit in a hosting network, or of unknown kind. 0 = recorded only.'
WHERE setting_key = 'source_vpn_observed_points';
UPDATE dbo.risk_policy_settings
SET setting_value = CASE WHEN setting_value = '0' THEN '10' ELSE setting_value END,
    description = 'Points when a request comes from an address learned as a VPN exit outside hosting networks: a home or office VPN. 0 = recorded only.'
WHERE setting_key = 'source_vpn_observed_non_hosting_points';
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 25)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (25, 'Conditions capped and kept out of the device memory; required measurements; policy stamps; business API roles');
GO
