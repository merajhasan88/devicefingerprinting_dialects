-- Device Trust schema, PostgreSQL 13+
-- Migration 023: VPN exits learned from this server's own Android phones, and
-- what the source address of each request is
--
-- DESIGN.md 81 (owner decisions of 2026-10-15). iOS gives apps no way to see
-- a VPN, so the server recognises VPN exits by address. Two sources: public
-- lists shipped with the server (VPN providers' networks, Tor exits, hosting
-- networks), and its own Android phones -- Android says reliably whether the
-- app's own traffic goes through a VPN, and the server sees the address that
-- traffic arrives from. An address counts as a VPN exit once enough different
-- phones came through a VPN from it and almost none came direct: a phone's
-- own address -- a home line, a carrier's shared pool -- carries mostly direct
-- traffic even where an ad blocker uses the VPN interface. Learning keeps an
-- address per phone, personal data, so it is off until the DBA turns it on;
-- vpn_exit_sightings is never read by the business API and nothing in it is
-- published. Every signal costs 0 points until the DBA gives it points.
--
-- Grant the application principal SELECT, INSERT, UPDATE on vpn_exit_sightings.
--
--   psql "host=... dbname=... user=... sslmode=verify-full" -v ON_ERROR_STOP=1 -f 023_vpn_exits_and_source_network.sql

BEGIN;

CREATE TABLE IF NOT EXISTS vpn_exit_sightings (
    address          VARCHAR(45) NOT NULL,
    device_id        UUID NOT NULL REFERENCES recognized_devices(device_id),
    last_via_vpn_at  TIMESTAMPTZ,
    last_direct_at   TIMESTAMPTZ,
    scans_via_vpn    INTEGER NOT NULL DEFAULT 0,
    scans_direct     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (address, device_id)
);

INSERT INTO risk_policy_settings (setting_key, setting_value, description) VALUES
    ('vpn_exit_learning', '0', '1 = learn VPN exits from this server''s Android phones: keep, per phone, the address each scan came from and whether its traffic went through a VPN (personal data, kept even with record_source_ip off); 0 (owner default) = off.'),
    ('vpn_exit_min_phones', '3', 'Different Android phones that must have come through a VPN from one address in vpn_exit_window_days before it counts as a VPN exit. At least 1.'),
    ('vpn_exit_min_share_percent', '90', 'Of the Android phones seen from that address in the window, the share that must have come through a VPN: a phone''s own address carries mostly direct traffic. 1-100.'),
    ('vpn_exit_window_days', '30', 'Days of sightings the two rules above count. 1-365.'),
    ('source_vpn_listed_points', '0', 'Points when a request comes from an address on the public VPN list shipped with the server. 0 (owner default) = recorded only.'),
    ('source_tor_exit_points', '0', 'Points when a request comes from a Tor exit. 0 (owner default) = recorded only.'),
    ('source_hosting_points', '0', 'Points when a request comes from a hosting or data-centre network not known as a VPN. 0 (owner default) = recorded only.'),
    ('source_vpn_observed_points', '0', 'Points when a request comes from an address learned as a VPN exit in a hosting network, or of unknown kind. 0 (owner default) = recorded only.'),
    ('source_vpn_observed_non_hosting_points', '0', 'Points when a request comes from an address learned as a VPN exit outside hosting networks: a home or office VPN. 0 (owner default) = recorded only.')
ON CONFLICT (setting_key) DO NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (23, 'VPN exits learned from Android phones; the source network of each request')
ON CONFLICT (version) DO NOTHING;

COMMIT;
