from ops_composer.db.migration_engine import Migration

OPS_COMPOSER = Migration(
    migration_id="0030_ops_composer",
    dependencies=("0021_auth_security",),
    up_sql="""
    CREATE TABLE credentials (
        credential_id uuid PRIMARY KEY,
        name text NOT NULL UNIQUE,
        credential_type text NOT NULL CHECK (credential_type IN ('PASSWORD')),
        username text NOT NULL,
        public_config jsonb NOT NULL DEFAULT '{}'::jsonb,
        current_version integer NOT NULL CHECK (current_version >= 1),
        enabled boolean NOT NULL DEFAULT TRUE,
        description text NOT NULL DEFAULT '',
        deleted_at timestamptz,
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL
    );

    CREATE TABLE credential_revisions (
        credential_id uuid NOT NULL REFERENCES credentials (credential_id) ON DELETE RESTRICT,
        version integer NOT NULL CHECK (version >= 1),
        encrypted_secret bytea NOT NULL,
        encryption_key_version integer NOT NULL CHECK (encryption_key_version >= 1),
        created_at timestamptz NOT NULL,
        PRIMARY KEY (credential_id, version)
    );

    CREATE TABLE hosts (
        host_id uuid PRIMARY KEY,
        name text NOT NULL UNIQUE,
        address text NOT NULL,
        ssh_port integer NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
        credential_id uuid NOT NULL REFERENCES credentials (credential_id) ON DELETE RESTRICT,
        python_interpreter text,
        enabled boolean NOT NULL DEFAULT TRUE,
        description text NOT NULL DEFAULT '',
        variables jsonb NOT NULL DEFAULT '{}'::jsonb,
        version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL
    );

    CREATE TABLE host_keys (
        host_id uuid NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
        algorithm text NOT NULL,
        public_key text NOT NULL,
        fingerprint text NOT NULL,
        trusted_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        trusted_at timestamptz NOT NULL,
        PRIMARY KEY (host_id, algorithm)
    );

    CREATE TABLE host_groups (
        group_id uuid PRIMARY KEY,
        name text NOT NULL UNIQUE,
        description text NOT NULL DEFAULT '',
        variables jsonb NOT NULL DEFAULT '{}'::jsonb,
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL
    );

    CREATE TABLE host_group_members (
        group_id uuid NOT NULL REFERENCES host_groups (group_id) ON DELETE CASCADE,
        host_id uuid NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
        created_at timestamptz NOT NULL,
        PRIMARY KEY (group_id, host_id)
    );
    CREATE INDEX idx_host_group_members_host ON host_group_members (host_id, group_id);

    CREATE TABLE runs (
        run_id uuid PRIMARY KEY,
        source_run_id uuid REFERENCES runs (run_id) ON DELETE SET NULL,
        kind text NOT NULL CHECK (kind IN ('PING', 'COMMAND', 'PLAYBOOK')),
        status text NOT NULL CHECK (status IN (
            'QUEUED', 'PREPARING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED',
            'CANCELED', 'TIMED_OUT', 'INTERRUPTED', 'REJECTED'
        )),
        target_spec jsonb NOT NULL,
        resolved_targets jsonb NOT NULL,
        operation_spec jsonb NOT NULL,
        inventory_snapshot jsonb NOT NULL,
        workspace_revision text,
        credential_versions jsonb NOT NULL,
        timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 86400),
        forks integer NOT NULL CHECK (forks BETWEEN 1 AND 100),
        cancel_requested_at timestamptz,
        claimed_by text,
        claimed_at timestamptz,
        started_at timestamptz,
        finished_at timestamptz,
        return_code integer,
        summary jsonb NOT NULL DEFAULT '{}'::jsonb,
        failure_code text,
        failure_message text,
        requested_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        idempotency_key text NOT NULL,
        request_fingerprint char(64) NOT NULL,
        next_event_sequence bigint NOT NULL DEFAULT 1 CHECK (next_event_sequence >= 1),
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL,
        UNIQUE (requested_by, idempotency_key)
    );
    CREATE INDEX idx_runs_queue ON runs (created_at, run_id) WHERE status = 'QUEUED';
    CREATE INDEX idx_runs_recent ON runs (created_at DESC, run_id DESC);
    CREATE INDEX idx_runs_claimed_by ON runs (claimed_by) WHERE claimed_by IS NOT NULL;

    CREATE TABLE run_targets (
        run_target_id uuid PRIMARY KEY,
        run_id uuid NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
        host_id uuid NOT NULL REFERENCES hosts (host_id) ON DELETE RESTRICT,
        host_name text NOT NULL,
        host_address text NOT NULL,
        status text NOT NULL CHECK (status IN (
            'PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELED',
            'SKIPPED', 'UNREACHABLE', 'INTERRUPTED'
        )),
        return_code integer,
        stdout text NOT NULL DEFAULT '',
        stderr text NOT NULL DEFAULT '',
        result jsonb NOT NULL DEFAULT '{}'::jsonb,
        output_truncated boolean NOT NULL DEFAULT FALSE,
        changed_count integer NOT NULL DEFAULT 0 CHECK (changed_count >= 0),
        failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
        unreachable_count integer NOT NULL DEFAULT 0 CHECK (unreachable_count >= 0),
        started_at timestamptz,
        finished_at timestamptz,
        UNIQUE (run_id, host_id)
    );
    CREATE INDEX idx_run_targets_run ON run_targets (run_id, host_name);

    CREATE TABLE run_events (
        run_event_id uuid PRIMARY KEY,
        run_id uuid NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
        run_target_id uuid REFERENCES run_targets (run_target_id) ON DELETE SET NULL,
        sequence bigint NOT NULL CHECK (sequence >= 1),
        event_type text NOT NULL,
        task text,
        stdout text,
        event_data jsonb NOT NULL DEFAULT '{}'::jsonb,
        created_at timestamptz NOT NULL,
        UNIQUE (run_id, sequence)
    );
    CREATE INDEX idx_run_events_replay ON run_events (run_id, sequence);

    CREATE TABLE host_run_locks (
        host_id uuid PRIMARY KEY REFERENCES hosts (host_id) ON DELETE CASCADE,
        run_id uuid NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
        worker_id text NOT NULL,
        acquired_at timestamptz NOT NULL,
        expires_at timestamptz NOT NULL,
        CHECK (expires_at > acquired_at)
    );

    CREATE TABLE worker_leases (
        worker_id text PRIMARY KEY,
        run_id uuid REFERENCES runs (run_id) ON DELETE SET NULL,
        heartbeat_at timestamptz NOT NULL,
        expires_at timestamptz NOT NULL,
        CHECK (expires_at > heartbeat_at)
    );
    CREATE INDEX idx_worker_leases_expiry ON worker_leases (expires_at);

    CREATE TABLE settings (
        setting_key text PRIMARY KEY,
        value jsonb NOT NULL,
        updated_by uuid REFERENCES users (user_id) ON DELETE SET NULL,
        updated_at timestamptz NOT NULL
    );
    """,
)
