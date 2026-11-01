CREATE SCHEMA IF NOT EXISTS control;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA control FROM PUBLIC;

CREATE TABLE IF NOT EXISTS control.users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'),
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control.sessions (
    token_hash char(64) PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES control.users(id),
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON control.sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON control.sessions(expires_at);

CREATE TABLE IF NOT EXISTS control.login_failures (
    peer text PRIMARY KEY,
    failures integer NOT NULL DEFAULT 0,
    window_start timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control.audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_id uuid,
    actor_username text,
    actor_role text,
    action text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'started', 'unknown', 'failed')),
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS control.operations (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES control.users(id),
    secret_id text NOT NULL,
    reason text NOT NULL CHECK (reason IN ('scheduled', 'suspected_exposure', 'manual_test')),
    status text NOT NULL CHECK (status IN ('in_progress', 'succeeded', 'failed', 'unknown')),
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

GRANT USAGE ON SCHEMA control TO control_api;
GRANT SELECT, INSERT, UPDATE ON control.users TO control_api;
GRANT SELECT, INSERT, DELETE ON control.sessions TO control_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON control.login_failures TO control_api;
GRANT SELECT, INSERT, UPDATE ON control.operations TO control_api;
GRANT SELECT, INSERT ON control.audit TO control_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA control TO control_api;
