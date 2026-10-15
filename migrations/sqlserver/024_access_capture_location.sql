-- Device Trust schema, SQL Server 2016+
-- Migration 024: what can read or drive the phone (Accessibility, the keyboard,
-- notification access, device administrators, remote-control apps), screen
-- capture, location and mock locations, and the age of the security patch
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 82). No table
-- changes. MERGE never overwrites a tuned value: a row that already exists gets
-- this migration's description and keeps its value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 024_access_capture_location.sql

SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('optional_measurements', '', 'Optional measurements asked for on each scan, comma-separated: local_addresses, accessibility, notification_access, other_access, screen_capture, location, mock_location (guide 14). Empty (owner default) = none. Sent only where the app enables it too.'),
    ('app_store_installers', 'com.android.vending,com.sec.android.app.samsungapps,com.huawei.appmarket,com.heytap.market,com.oppo.market,com.xiaomi.mipicks,com.amazon.venezia', 'App stores by installer package, comma-separated: an app one of them installed is from a store; installed by anything else, sideloaded; a system app is the system''s. Add your market''s store.'),
    ('accessibility_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with an Accessibility service on from a sideloaded app is refused (integrity_device_ineligible) until it is off and a new scan is sent; 0 (owner default) = advisory.'),
    ('accessibility_non_system_refuses', '0', 'Eligibility rule. 1 = the same for an Accessibility service from any app that is not part of the system, store apps included (screen readers and password managers among them). 0 (owner default) = advisory.'),
    ('keyboard_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose keyboard in use is a sideloaded app is refused until another keyboard is chosen and a new scan is sent; 0 (owner default) = advisory.'),
    ('keyboard_non_system_refuses', '0', 'Eligibility rule. 1 = the same for a keyboard from any app that is not part of the system, store apps included. 0 (owner default) = advisory.'),
    ('notification_access_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone where a sideloaded app reads notifications is refused until its access is off and a new scan is sent; 0 (owner default) = advisory.'),
    ('notification_access_non_system_refuses', '0', 'Eligibility rule. 1 = the same for any app reading notifications that is not part of the system, store apps included (smartwatch apps among them). 0 (owner default) = advisory.'),
    ('device_admin_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with a sideloaded device-administrator app is refused until it is deactivated and a new scan is sent; 0 (owner default) = advisory.'),
    ('device_admin_non_system_refuses', '0', 'Eligibility rule. 1 = the same for any device-administrator app that is not part of the system, store apps included (company phone management among them). 0 (owner default) = advisory.'),
    ('remote_access_app_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with a remote-control app installed (AnyDesk, TeamViewer QuickSupport, RustDesk, AirDroid) is refused until it is removed and a new scan is sent; 0 (owner default) = advisory.'),
    ('screen_capture_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose screen was being recorded or mirrored during the scan is refused until that stops and a new scan is sent; 0 (owner default) = advisory.'),
    ('mock_location_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose last location came from a mock-location app is refused until a real location and a new scan are sent; 0 (owner default) = advisory.'),
    ('security_patch_max_age_days', '0', 'Days an Android phone''s security patch level may age before android_security_patch_outdated (0 points) is recorded. 0 (owner default) = never. 0-3650.'),
    ('security_patch_outdated_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose security patch is older than security_patch_max_age_days is refused until it is updated and a new scan is sent; 0 (owner default) = advisory.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN MATCHED THEN
    UPDATE SET description = s.description
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 24)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (24, 'Access, screen capture and location measurements; their eligibility rules; the security patch age');
GO
