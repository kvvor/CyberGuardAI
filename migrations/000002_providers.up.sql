CREATE TABLE provider_settings (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 provider text NOT NULL CHECK(provider='openai'),
 model text NOT NULL,
 credential bytea,
 enabled boolean NOT NULL DEFAULT false,
 revision uuid NOT NULL,
 connection_status text NOT NULL DEFAULT 'untested',
 last_success_at timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now()
);
