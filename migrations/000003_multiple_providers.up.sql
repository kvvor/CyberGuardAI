ALTER TABLE provider_settings DROP CONSTRAINT provider_settings_pkey;
ALTER TABLE provider_settings DROP CONSTRAINT provider_settings_provider_check;
ALTER TABLE provider_settings ADD PRIMARY KEY (user_id, provider);
ALTER TABLE provider_settings ADD CHECK (provider IN ('openai', 'virustotal'));
ALTER TABLE provider_settings ADD COLUMN next_lookup_at timestamptz;
ALTER TABLE provider_settings ADD COLUMN lookup_day date;
ALTER TABLE provider_settings ADD COLUMN lookup_count integer NOT NULL DEFAULT 0;
