from __future__ import annotations

from ops_composer.db.migration_engine import Migration

PLAYBOOKS = Migration(
    migration_id="0050_playbooks",
    dependencies=("0040_audit_events",),
    up_sql="""
    CREATE TABLE playbooks (
        playbook_id uuid PRIMARY KEY,
        name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
        description text NOT NULL DEFAULT '' CHECK (length(description) <= 1024),
        enabled boolean NOT NULL DEFAULT TRUE,
        current_revision integer NOT NULL CHECK (current_revision >= 1),
        version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
        created_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        updated_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        deleted_at timestamptz,
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL
    );
    CREATE UNIQUE INDEX uq_playbooks_active_name
        ON playbooks (lower(name)) WHERE deleted_at IS NULL;
    CREATE INDEX idx_playbooks_active_updated
        ON playbooks (updated_at DESC, playbook_id DESC) WHERE deleted_at IS NULL;

    CREATE TABLE playbook_revisions (
        playbook_id uuid NOT NULL REFERENCES playbooks (playbook_id) ON DELETE RESTRICT,
        revision integer NOT NULL CHECK (revision >= 1),
        content text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 1048576),
        sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
        size_bytes integer NOT NULL CHECK (
            size_bytes BETWEEN 1 AND 1048576 AND size_bytes = octet_length(content)
        ),
        validator_version text NOT NULL CHECK (length(validator_version) BETWEEN 1 AND 128),
        validated_at timestamptz NOT NULL,
        created_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        created_at timestamptz NOT NULL,
        PRIMARY KEY (playbook_id, revision)
    );

    CREATE FUNCTION reject_playbook_revision_mutation() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'playbook revisions are immutable' USING ERRCODE = '55000';
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER playbook_revisions_reject_mutation
        BEFORE UPDATE OR DELETE ON playbook_revisions
        FOR EACH ROW EXECUTE FUNCTION reject_playbook_revision_mutation();

    ALTER TABLE playbooks ADD CONSTRAINT fk_playbooks_current_revision
        FOREIGN KEY (playbook_id, current_revision)
        REFERENCES playbook_revisions (playbook_id, revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

    ALTER TABLE runs
        ADD COLUMN playbook_id uuid,
        ADD COLUMN playbook_revision integer,
        ADD CONSTRAINT ck_runs_playbook_reference_pair CHECK (
            (playbook_id IS NULL) = (playbook_revision IS NULL)
        ),
        ADD CONSTRAINT ck_runs_playbook_reference_kind CHECK (
            playbook_id IS NULL OR kind = 'PLAYBOOK'
        ),
        ADD CONSTRAINT fk_runs_playbook_revision FOREIGN KEY (
            playbook_id, playbook_revision
        ) REFERENCES playbook_revisions (playbook_id, revision) ON DELETE RESTRICT;
    CREATE INDEX idx_runs_playbook_revision
        ON runs (playbook_id, playbook_revision) WHERE playbook_id IS NOT NULL;

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
            'PLAYBOOK_SOURCE_DISABLED'
        )
    );
    """,
)
