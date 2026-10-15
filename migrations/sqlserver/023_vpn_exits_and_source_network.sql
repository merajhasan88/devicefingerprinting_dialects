-- Device Trust schema, SQL Server 2016+
-- Migration 023: VPN exits learned from this server's own Android phones, and
-- what the source address of each request is
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 81). Grant the
-- application principal SELECT, INSERT, UPDATE on vpn_exit_sightings. MERGE
-- never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 023_vpn_exits_and_source_network.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.vpn_exit_sightings', 'U') IS NULL
CREATE TABLE dbo.vpn_exit_sightings (
    address          varchar(45) COLLATE Latin1_General_BIN2 NOT NULL,
    device_id        char(36) COLLATE Latin1_General_BIN2 NOT NULL
                     CONSTRAINT fk_vpn_sightings_device REFERENCES dbo.recognized_devices(device_id),
    last_via_vpn_at  datetimeoffset(3) NULL,
    last_direct_at   datetimeoffset(3) NULL,
    scans_via_vpn    int NOT NULL CONSTRAINT df_vpn_sightings_via DEFAULT 0,
    scans_direct     int NOT NULL CONSTRAINT df_vpn_sightings_direct DEFAULT 0,
    CONSTRAINT pk_vpn_exit_sightings PRIMARY KEY (address, device_id)
);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('vpn_exit_learning', '0', '1 = learn VPN exits from this server''s Android phones: keep, per phone, the address each scan came from and whether its traffic went through a VPN (personal data, kept even with record_source_ip off); 0 (owner default) = off.'),
    ('vpn_exit_min_phones', '3', 'Different Android phones that must have come through a VPN from one address in vpn_exit_window_days before it counts as a VPN exit. At least 1.'),
    ('vpn_exit_min_share_percent', '90', 'Of the Android phones seen from that address in the window, the share that must have come through a VPN: a phone''s own address carries mostly direct traffic. 1-100.'),
    ('vpn_exit_window_days', '30', 'Days of sightings the two rules above count. 1-365.'),
    ('source_vpn_listed_points', '0', 'Points when a request comes from an address on the public VPN list shipped with the server. 0 (owner default) = recorded only.'),
    ('source_tor_exit_points', '0', 'Points when a request comes from a Tor exit. 0 (owner default) = recorded only.'),
    ('source_hosting_points', '0', 'Points when a request comes from a hosting or data-centre network not known as a VPN. 0 (owner default) = recorded only.'),
    ('source_vpn_observed_points', '0', 'Points when a request comes from an address learned as a VPN exit in a hosting network, or of unknown kind. 0 (owner default) = recorded only.'),
    ('source_vpn_observed_non_hosting_points', '0', 'Points when a request comes from an address learned as a VPN exit outside hosting networks: a home or office VPN. 0 (owner default) = recorded only.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 23)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (23, 'VPN exits learned from Android phones; the source network of each request');
GO
