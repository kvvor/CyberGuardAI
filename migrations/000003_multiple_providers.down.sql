-- Refuse rollback if it would discard saved VirusTotal credentials.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM provider_settings WHERE provider <> 'openai') THEN
  RAISE EXCEPTION 'Remove non-OpenAI provider settings explicitly before rollback';
 END IF;
END $$;
ALTER TABLE provider_settings DROP CONSTRAINT provider_settings_pkey;
ALTER TABLE provider_settings DROP CONSTRAINT provider_settings_provider_check;
ALTER TABLE provider_settings ADD PRIMARY KEY (user_id);
ALTER TABLE provider_settings ADD CHECK (provider = 'openai');
ALTER TABLE provider_settings DROP COLUMN next_lookup_at;
ALTER TABLE provider_settings DROP COLUMN lookup_day;
ALTER TABLE provider_settings DROP COLUMN lookup_count;
