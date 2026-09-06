from ops_composer.db.migration_engine import Migration

WEB_SHELL = Migration(
    migration_id="0060_web_shell",
    dependencies=("0050_playbooks",),
    up_sql="""
    CREATE TABLE web_shell_sessions (
        web_shell_session_id uuid PRIMARY KEY,
        host_id uuid NOT NULL REFERENCES hosts (host_id) ON DELETE RESTRICT,
        actor_user_id uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        auth_session_id uuid NOT NULL,
        credential_id uuid NOT NULL,
        credential_version integer NOT NULL CHECK (credential_version >= 1),
        host_name text NOT NULL CHECK (length(host_name) BETWEEN 1 AND 128),
        host_address text NOT NULL CHECK (length(host_address) BETWEEN 1 AND 253),
        ssh_port integer NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
        username text NOT NULL CHECK (length(username) BETWEEN 1 AND 128),
        state text NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'CLOSE_REQUESTED')),
        api_instance_id text NOT NULL CHECK (length(api_instance_id) BETWEEN 1 AND 255),
        owner_id text CHECK (owner_id IS NULL OR length(owner_id) BETWEEN 1 AND 255),
        ticket_expires_at timestamptz NOT NULL,
        lease_expires_at timestamptz NOT NULL,
        connected_at timestamptz,
        last_activity_at timestamptz,
        close_requested_at timestamptz,
        created_at timestamptz NOT NULL,
        FOREIGN KEY (credential_id, credential_version)
            REFERENCES credential_revisions (credential_id, version) ON DELETE RESTRICT,
        CHECK (ticket_expires_at > created_at),
        CHECK (lease_expires_at > created_at),
        CHECK (
            (state = 'PENDING' AND owner_id IS NULL AND connected_at IS NULL)
            OR
            (state IN ('ACTIVE', 'CLOSE_REQUESTED') AND owner_id IS NOT NULL
                AND connected_at IS NOT NULL)
        )
    );
    CREATE INDEX idx_web_shell_sessions_live
        ON web_shell_sessions (lease_expires_at, web_shell_session_id);
    CREATE INDEX idx_web_shell_sessions_actor
        ON web_shell_sessions (actor_user_id, created_at DESC);

    ALTER TABLE host_run_locks RENAME TO host_execution_locks;
    ALTER TABLE host_execution_locks ALTER COLUMN run_id DROP NOT NULL;
    ALTER TABLE host_execution_locks RENAME COLUMN worker_id TO owner_id;
    ALTER TABLE host_execution_locks
        ADD COLUMN web_shell_session_id uuid
            REFERENCES web_shell_sessions (web_shell_session_id) ON DELETE CASCADE;
    ALTER TABLE host_execution_locks
        ADD CONSTRAINT ck_host_execution_lock_owner CHECK (
            (run_id IS NOT NULL AND web_shell_session_id IS NULL)
            OR (run_id IS NULL AND web_shell_session_id IS NOT NULL)
        );

    ALTER TABLE audit_events DROP CONSTRAINT audit_events_event_action_check;
    ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_action_check CHECK (
        event_action IN (
            'REQUEST_COMPLETED', 'REQUEST_REJECTED', 'REQUEST_VALIDATION_FAILED',
            'UNHANDLED_EXCEPTION', 'APP_STARTING', 'APP_READY', 'APP_STOPPED',
            'DATABASE_UNAVAILABLE', 'DATABASE_RECOVERED', 'MIGRATION_STARTED',
            'MIGRATION_COMPLETED', 'MIGRATION_FAILED', 'MIGRATION_VALIDATION_FAILED',
            'MASTER_KEY_INITIALIZED', 'MASTER_KEY_VALIDATED',
            'MASTER_KEY_VALIDATION_FAILED', 'PLAYBOOK_WORKSPACE_FAILED',
            'RUNTIME_DIRECTORY_FAILED', 'AUDIT_PERSIST_FAILED', 'AUDIT_EXPORTED',
            'AUDIT_RETENTION_PURGED', 'ADMIN_BOOTSTRAPPED', 'ADMIN_BOOTSTRAP_REJECTED',
            'AUTH_LOGIN_SUCCEEDED', 'AUTH_LOGIN_FAILED', 'AUTH_RATE_LIMITED',
            'AUTH_SESSION_INVALID', 'AUTH_LOGOUT_SUCCEEDED', 'ORIGIN_DENIED',
            'CSRF_DENIED', 'AUTH_PURGE_COMPLETED', 'CREDENTIAL_CREATED',
            'CREDENTIAL_ROTATED', 'CREDENTIAL_DELETED', 'HOST_CREATED', 'HOST_UPDATED',
            'HOST_DELETED', 'GROUP_CREATED', 'GROUP_UPDATED', 'GROUP_DELETED',
            'HOST_KEY_SCAN_STARTED', 'HOST_KEY_SCAN_SUCCEEDED', 'HOST_KEY_SCAN_FAILED',
            'HOST_KEY_CONFIRMED', 'HOST_KEY_CHANGED', 'RUN_CREATED',
            'RUN_IDEMPOTENT_REPLAY', 'RUN_IDEMPOTENCY_CONFLICT',
            'RUN_TARGET_RESOLUTION_FAILED', 'RUN_CANCEL_REQUESTED',
            'RUN_CANCEL_REJECTED', 'RUN_RETRY_CREATED', 'WORKER_STARTED',
            'WORKER_READY', 'WORKER_STOPPED', 'WORKER_LOOP_FAILED',
            'STALE_RUNS_RECOVERED', 'RUN_CLAIMED', 'HOST_LOCK_COLLISION',
            'RUN_PREPARATION_FAILED', 'RUNTIME_DIRECTORY_CREATED',
            'RUNTIME_DIRECTORY_CLEANED', 'RUN_STARTED', 'HOST_COMPLETED',
            'RUN_SUCCEEDED', 'RUN_PARTIAL', 'RUN_FAILED', 'RUN_REJECTED',
            'RUN_CANCELED', 'RUN_TIMED_OUT', 'RUN_INTERRUPTED',
            'PLAYBOOK_CREATED', 'PLAYBOOK_UPDATED', 'PLAYBOOK_DELETED',
            'PLAYBOOK_VALIDATION_SUCCEEDED', 'PLAYBOOK_VALIDATION_FAILED',
            'PLAYBOOK_SOURCE_DISABLED', 'WEB_SHELL_REQUESTED', 'WEB_SHELL_STARTED',
            'WEB_SHELL_CLOSE_REQUESTED', 'WEB_SHELL_CLOSED', 'WEB_SHELL_DENIED',
            'WEB_SHELL_FAILED', 'WEB_SHELL_TIMED_OUT', 'WEB_SHELL_STALE_RECOVERED'
        )
    );
    """,
)
