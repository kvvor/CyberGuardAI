ALTER TABLE provider_settings ADD COLUMN lookup_recent timestamptz[] NOT NULL DEFAULT ARRAY[]::timestamptz[];
