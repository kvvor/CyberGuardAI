CREATE TABLE users (
 id uuid PRIMARY KEY,
 email text NOT NULL UNIQUE CHECK (email = lower(btrim(email))),
 display_name text NOT NULL,
 password_hash text,
 account_status text NOT NULL CHECK (account_status IN ('pending_activation','active','disabled')),
 must_change_password boolean NOT NULL DEFAULT true,
 temporary_password_hash text,
 temporary_password_expires_at timestamptz,
 temporary_password_used_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 last_login_at timestamptz,
 password_changed_at timestamptz,
 CHECK (account_status <> 'active' OR (password_hash IS NOT NULL AND NOT must_change_password))
);
CREATE TABLE sessions (
 token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash)=32),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash)=32),
 kind text NOT NULL CHECK (kind IN ('setup','regular')),
 created_at timestamptz NOT NULL DEFAULT now(),
 last_seen_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expiration_idx ON sessions(expires_at);
CREATE TABLE auth_security_events (
 id uuid PRIMARY KEY,
 user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 event_code text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE analyses (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 mode text NOT NULL CHECK (mode IN ('live','demo')),
 status text NOT NULL CHECK (status IN ('complete','partial')),
 verdict text NOT NULL CHECK (verdict IN ('legitimate','suspicious','phishing','inconclusive')),
 risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
 risk_level text NOT NULL CHECK (risk_level IN ('low','medium','high','critical')),
 subject text NOT NULL DEFAULT '',
 sender text NOT NULL DEFAULT '',
 scoring_version text NOT NULL,
 report jsonb NOT NULL CHECK (jsonb_typeof(report)='object'),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX analyses_owner_date_idx ON analyses(user_id,created_at DESC,id);
CREATE INDEX analyses_owner_mode_verdict_idx ON analyses(user_id,mode,verdict);
CREATE TABLE analysis_events (
 id uuid PRIMARY KEY,
 analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
 event_code text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
