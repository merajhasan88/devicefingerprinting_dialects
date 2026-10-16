-- Device Trust schema, SQL Server 2016+
-- Migration 029: events from the business's other services -- which types each
-- caller may send, where each came from, and the business's own rules over them
--
-- See the PostgreSQL counterpart for the rationale (DESIGN.md 84.5). MERGE
-- never overwrites a tuned value.
--
--   sqlcmd -S <host>,1433 -d <db> -U <ddl-user> -P <pass> -b -i 029_business_event_sources_and_rules.sql

SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.business_events', 'source_kinds') IS NULL
    ALTER TABLE dbo.business_events ADD source_kinds varchar(128) NULL;
GO

IF COL_LENGTH('dbo.business_events', 'source_hash') IS NULL
    ALTER TABLE dbo.business_events ADD source_hash char(64) COLLATE Latin1_General_BIN2 NULL;
GO

MERGE dbo.risk_policy_settings AS t
USING (VALUES
    ('business_event_types_by_producer', '', 'Which event types each business API caller may send: caller:type+type, comma-separated. A caller not listed is held only to business_event_types. Empty (owner default) = no per-caller limit.'),
    ('business_event_rules', '', 'Your rules over business events, each type[/outcome][@source kind]:count:hours:points[:account|device|newcomer] -- e.g. chargeback:1:720:40. Each adds its points to a decision when it matches. Empty (owner default) = none: the business decides.')
) AS s(setting_key, setting_value, description)
ON t.setting_key = s.setting_key
WHEN NOT MATCHED THEN
    INSERT (setting_key, setting_value, description)
    VALUES (s.setting_key, s.setting_value, s.description);
GO

IF NOT EXISTS (SELECT 1 FROM dbo.schema_migrations WHERE version = 29)
    INSERT INTO dbo.schema_migrations (version, description)
    VALUES (29, 'Business events: types per caller, their source addresses, the DBA''s rules');
GO
