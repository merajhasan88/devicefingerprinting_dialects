-- Device Trust schema, PostgreSQL 13+
-- Migration 024: what can read or drive the phone (Accessibility, the keyboard,
-- notification access, device administrators, remote-control apps), screen
-- capture, location and mock locations, and the age of the security patch
--
-- DESIGN.md 82 (owner decisions of 2026-10-15). Six optional measurements join
-- local_addresses behind the same two keys: the DBA lists them in
-- optional_measurements and the app's developers enable them; location and
-- mock_location also need the OS location permission, which only the app asks
-- for. Banking trojans that capture what is typed work through Accessibility, a
-- replacement keyboard, notification access or screen capture, so the phone
-- reports which apps hold them and who installed each; the server decides
-- whether each is the system's, from an app store (app_store_installers) or
-- sideloaded. Each finding scores the owner's default points (*_points), which
-- the DBA changes: the sideloaded holders and the deliberate manipulations
-- score, while what screen readers, password managers, store keyboards,
-- smartwatch apps and company management also hold stays at 0. Each has an
-- eligibility rule the DBA turns on. No table changes.
--
-- Descriptions are ours, values the DBA's: a row that already exists gets this
-- migration's description and keeps its value -- optional_measurements, seeded
-- by migration 022, is listed again only for its description.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 024_access_capture_location.sql

BEGIN;

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('optional_measurements', '', 'Optional measurements asked for on each scan, comma-separated: local_addresses, accessibility, notification_access, other_access, screen_capture, location, mock_location (guide 14). Empty (owner default) = none. Sent only where the app enables it too.'),
    ('app_store_installers', 'com.android.vending,com.sec.android.app.samsungapps,com.huawei.appmarket,com.heytap.market,com.oppo.market,com.xiaomi.mipicks,com.amazon.venezia', 'App stores by installer package, comma-separated: an app one of them installed is from a store; installed by anything else, sideloaded; a system app is the system''s. Add your market''s store.'),
    ('accessibility_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with an Accessibility service on from a sideloaded app is refused (integrity_device_ineligible) until it is off and a new scan is sent; 0 (owner default) = no refusal.'),
    ('accessibility_non_system_refuses', '0', 'Eligibility rule. 1 = the same for an Accessibility service from any app that is not part of the system, store apps included (screen readers and password managers among them). 0 (owner default) = no refusal.'),
    ('keyboard_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose keyboard in use is a sideloaded app is refused until another keyboard is chosen and a new scan is sent; 0 (owner default) = no refusal.'),
    ('keyboard_non_system_refuses', '0', 'Eligibility rule. 1 = the same for a keyboard from any app that is not part of the system, store apps included. 0 (owner default) = no refusal.'),
    ('notification_access_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone where a sideloaded app reads notifications is refused until its access is off and a new scan is sent; 0 (owner default) = no refusal.'),
    ('notification_access_non_system_refuses', '0', 'Eligibility rule. 1 = the same for any app reading notifications that is not part of the system, store apps included (smartwatch apps among them). 0 (owner default) = no refusal.'),
    ('device_admin_sideloaded_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with a sideloaded device-administrator app is refused until it is deactivated and a new scan is sent; 0 (owner default) = no refusal.'),
    ('device_admin_non_system_refuses', '0', 'Eligibility rule. 1 = the same for any device-administrator app that is not part of the system, store apps included (company phone management among them). 0 (owner default) = no refusal.'),
    ('remote_access_app_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone with a remote-control app installed (AnyDesk, TeamViewer QuickSupport, RustDesk, AirDroid) is refused until it is removed and a new scan is sent; 0 (owner default) = no refusal.'),
    ('screen_capture_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose screen was being recorded or mirrored during the scan is refused until that stops and a new scan is sent; 0 (owner default) = no refusal.'),
    ('mock_location_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose last location came from a mock-location app is refused until a real location and a new scan are sent; 0 (owner default) = no refusal.'),
    ('security_patch_max_age_days', '365', 'Days an Android phone''s security patch level may age before android_security_patch_outdated is recorded. Owner default 365; 0 = never. 0-3650.'),
    ('security_patch_outdated_refuses', '0', 'Eligibility rule. 1 = in enforce mode a phone whose security patch is older than security_patch_max_age_days is refused until it is updated and a new scan is sent; 0 (owner default) = no refusal.'),
    ('accessibility_sideloaded_points', '45', 'Points for android_accessibility_sideloaded: the banking-trojan signature, though a phone maker''s preloaded app with no installer looks the same. 0 = recorded only.'),
    ('accessibility_non_system_points', '0', 'Points for android_accessibility_non_system: screen readers and password managers from a store hold it too. Owner default 0. Added to the sideloaded points.'),
    ('keyboard_sideloaded_points', '30', 'Points for android_keyboard_sideloaded: a keyboard sees everything typed. 0 = recorded only.'),
    ('keyboard_non_system_points', '0', 'Points for android_keyboard_non_system: keyboards from a store too. Owner default 0. Added to the sideloaded points.'),
    ('notification_access_sideloaded_points', '30', 'Points for android_notification_access_sideloaded: one-time codes arrive as notifications. 0 = recorded only.'),
    ('notification_access_non_system_points', '0', 'Points for android_notification_access_non_system: smartwatch apps from a store too. Owner default 0. Added to the sideloaded points.'),
    ('device_admin_sideloaded_points', '30', 'Points for android_device_admin_sideloaded: malware uses it to resist removal. 0 = recorded only.'),
    ('device_admin_non_system_points', '0', 'Points for android_device_admin_non_system: company phone management too. Owner default 0. Added to the sideloaded points.'),
    ('remote_access_app_points', '20', 'Points for android_remote_access_app: installed, not necessarily running. With a sideloaded Accessibility service it reaches review. 0 = recorded only.'),
    ('screen_capture_points', '30', 'Points for android_screen_captured and ios_screen_captured: recorded, cast or mirrored during the scan, or another display on. 0 = recorded only.'),
    ('mock_location_points', '40', 'Points for android_mock_location and ios_mock_location: a location simulated by an app. 0 = recorded only.'),
    ('security_patch_outdated_points', '10', 'Points for android_security_patch_outdated: unpatched phones are legitimate users too, so it nudges, never decides. 0 = recorded only.')
ON CONFLICT (setting_key) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO schema_migrations (version, description)
VALUES (24, 'Access, screen capture and location measurements; their eligibility rules; the security patch age')
ON CONFLICT (version) DO NOTHING;

COMMIT;
