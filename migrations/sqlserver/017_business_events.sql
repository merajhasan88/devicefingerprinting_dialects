-- Device Trust schema, SQL Server 2016+
-- Migration 017: business events, combined with the phone-account graph
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 76). The server
-- never updates or deletes business_events: grant the application principal
-- SELECT, INSERT on it. MERGE never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 017_business_events.sql

SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID('dbo.business_events', 'U') IS NULL
CREATE TABLE dbo.business_events (
    event_id     varchar(64) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY,
    account_id   char(36) COLLATE Latin1_General_BIN2 NOT NULL
                 CONSTRAINT fk_business_events_account REFERENCES dbo.demo_accounts(account_id),
    event_type   varchar(48) NOT NULL,
    occurred_at  datetimeoffset(3) NOT NULL,
    received_at  datetimeoffset(3) NOT NULL CONSTRAINT df_business_events_received DEFAULT SYSUTCDATETIME(),
    amount_minor bigint NULL,
    currency     char(3) NULL,
    outcome      varchar(32) NULL,
    subject_hash char(64) COLLATE Latin1_General_BIN2 NULL
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'business_events_account_idx')
    CREATE INDEX business_events_account_idx ON dbo.business_events(account_id, occurred_at);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'business_events_subject_idx')
    CREATE INDEX business_events_subject_idx ON dbo.business_events(subject_hash, occurred_at);
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('business_event_types', '', 'Business event types the server accepts, comma-separated. Empty: any well-formed type (a-z, 0-9, _).'),
    ('business_graph_depth', '2', 'Hops the phone-account graph API follows from its starting account or phone (account to phones is one hop). 1-4.'),
    ('business_graph_max_nodes', '200', 'Most accounts and phones the graph API returns; a larger component is cut and marked truncated.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 17)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (17, 'business events, combined with the phone-account graph');
GO
