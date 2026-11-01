CREATE TABLE IF NOT EXISTS control.scans (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES control.users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    findings_count integer NOT NULL CHECK (findings_count >= 0 AND findings_count <= 1000),
    result jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_created_idx ON control.scans(created_at DESC, id);

-- Reports are immutable to the service account, like the audit journal.
GRANT SELECT, INSERT ON control.scans TO control_api;
REVOKE UPDATE, DELETE, TRUNCATE ON control.scans FROM control_api;
