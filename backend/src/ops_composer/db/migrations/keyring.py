from __future__ import annotations

from ops_composer.db.migration_engine import Migration

KEYRING = Migration(
    migration_id="0080_credential_keyring",
    dependencies=("0070_multi_admin_governance",),
    up_sql="""
    ALTER TABLE credentials DROP CONSTRAINT credentials_credential_type_check;
    ALTER TABLE credentials ADD CONSTRAINT credentials_credential_type_check CHECK (
        credential_type IN ('PASSWORD', 'SSH_PRIVATE_KEY')
    );
    ALTER TABLE credentials
        ADD COLUMN lock_version integer NOT NULL DEFAULT 1 CHECK (lock_version >= 1);
    ALTER TABLE web_shell_sessions
        ADD COLUMN credential_type text NOT NULL DEFAULT 'PASSWORD'
        CHECK (credential_type IN ('PASSWORD', 'SSH_PRIVATE_KEY'));

    CREATE TABLE credential_secret_envelopes (
        credential_id uuid NOT NULL,
        revision integer NOT NULL CHECK (revision >= 1),
        encrypted_secret bytea NOT NULL,
        encryption_key_version integer NOT NULL CHECK (encryption_key_version >= 1),
        updated_at timestamptz NOT NULL,
        PRIMARY KEY (credential_id, revision),
        FOREIGN KEY (credential_id, revision)
            REFERENCES credential_revisions (credential_id, version) ON DELETE RESTRICT
    );
    INSERT INTO credential_secret_envelopes (
        credential_id, revision, encrypted_secret, encryption_key_version, updated_at
    ) SELECT credential_id, version, encrypted_secret, encryption_key_version, created_at
      FROM credential_revisions;
    ALTER TABLE credential_revisions
        DROP COLUMN encrypted_secret,
        DROP COLUMN encryption_key_version;

    CREATE FUNCTION reject_credential_revision_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'credential revisions are immutable' USING ERRCODE = '55000';
    END;
    $$;
    CREATE TRIGGER credential_revisions_reject_mutation
        BEFORE UPDATE OR DELETE ON credential_revisions
        FOR EACH ROW EXECUTE FUNCTION reject_credential_revision_mutation();

    CREATE TABLE encryption_key_registry (
        key_version integer PRIMARY KEY CHECK (key_version >= 1),
        verification_envelope bytea NOT NULL,
        registered_at timestamptz NOT NULL,
        retired_at timestamptz
    );

    CREATE TABLE system_secret_envelopes (
        secret_name text PRIMARY KEY CHECK (length(secret_name) BETWEEN 1 AND 128),
        encrypted_secret bytea NOT NULL,
        encryption_key_version integer NOT NULL CHECK (encryption_key_version >= 1),
        updated_at timestamptz NOT NULL
    );

    CREATE TABLE key_rotation_jobs (
        key_rotation_job_id uuid PRIMARY KEY,
        target_key_version integer NOT NULL CHECK (target_key_version >= 1),
        state text NOT NULL CHECK (state IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED')),
        requested_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        claimed_by text,
        lease_expires_at timestamptz,
        processed_count bigint NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
        remaining_count bigint,
        error_code text CHECK (error_code IS NULL OR length(error_code) <= 128),
        created_at timestamptz NOT NULL,
        started_at timestamptz,
        finished_at timestamptz,
        updated_at timestamptz NOT NULL,
        CHECK ((state = 'RUNNING') = (claimed_by IS NOT NULL)),
        CHECK (lease_expires_at IS NULL OR started_at IS NOT NULL)
    );
    CREATE UNIQUE INDEX uq_key_rotation_jobs_active
        ON key_rotation_jobs ((TRUE)) WHERE state IN ('PENDING', 'RUNNING');
    CREATE INDEX idx_key_rotation_jobs_recent
        ON key_rotation_jobs (created_at DESC, key_rotation_job_id DESC);
    """,
)
