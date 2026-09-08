from __future__ import annotations

from ops_composer.db.migration_engine import Migration

PLAYBOOK_PROJECTS = Migration(
    migration_id="0090_playbook_projects",
    dependencies=("0080_credential_keyring",),
    up_sql="""
    ALTER TABLE playbook_revisions DROP CONSTRAINT playbook_revisions_content_check;
    ALTER TABLE playbook_revisions DROP CONSTRAINT playbook_revisions_check;
    ALTER TABLE playbook_revisions ALTER COLUMN content DROP NOT NULL;
    ALTER TABLE playbook_revisions
        ADD COLUMN revision_format text NOT NULL DEFAULT 'LEGACY_SINGLE_YAML',
        ADD COLUMN entrypoint text,
        ADD COLUMN parameter_schema jsonb NOT NULL DEFAULT
            '{"type":"object","properties":{},"additionalProperties":false}'::jsonb,
        ADD COLUMN supports_check_mode boolean NOT NULL DEFAULT FALSE;
    ALTER TABLE playbook_revisions ADD CONSTRAINT playbook_revisions_format_check CHECK (
        revision_format IN ('LEGACY_SINGLE_YAML', 'PROJECT')
    );
    ALTER TABLE playbook_revisions ADD CONSTRAINT playbook_revisions_content_format_check CHECK (
        (revision_format = 'LEGACY_SINGLE_YAML'
            AND content IS NOT NULL
            AND octet_length(content) BETWEEN 1 AND 1048576
            AND entrypoint IS NULL)
        OR
        (revision_format = 'PROJECT' AND content IS NULL AND entrypoint IS NOT NULL)
    );
    ALTER TABLE playbook_revisions ADD CONSTRAINT playbook_revisions_size_bytes_check CHECK (
        size_bytes BETWEEN 1 AND 10485760
    );
    ALTER TABLE playbook_revisions ADD CONSTRAINT playbook_revisions_schema_check CHECK (
        jsonb_typeof(parameter_schema) = 'object'
    );

    CREATE TABLE playbook_revision_files (
        playbook_id uuid NOT NULL,
        revision integer NOT NULL CHECK (revision >= 1),
        path text NOT NULL CHECK (length(path) BETWEEN 1 AND 512),
        content text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 1048576),
        sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
        size_bytes integer NOT NULL CHECK (
            size_bytes BETWEEN 1 AND 1048576 AND size_bytes = octet_length(content)
        ),
        PRIMARY KEY (playbook_id, revision, path),
        FOREIGN KEY (playbook_id, revision)
            REFERENCES playbook_revisions (playbook_id, revision) ON DELETE RESTRICT
    );
    CREATE INDEX idx_playbook_revision_files_revision
        ON playbook_revision_files (playbook_id, revision, path);
    CREATE FUNCTION reject_playbook_revision_file_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'playbook revision files are immutable' USING ERRCODE = '55000';
    END;
    $$;
    CREATE TRIGGER playbook_revision_files_reject_mutation
        BEFORE UPDATE OR DELETE ON playbook_revision_files
        FOR EACH ROW EXECUTE FUNCTION reject_playbook_revision_file_mutation();

    ALTER TABLE runs
        ADD COLUMN request_fingerprint_scheme text NOT NULL DEFAULT 'LEGACY_SHA256'
            CHECK (request_fingerprint_scheme IN ('LEGACY_SHA256', 'HMAC_SHA256_V1'));

    CREATE TABLE run_secret_inputs (
        run_id uuid PRIMARY KEY REFERENCES runs (run_id) ON DELETE CASCADE,
        encrypted_payload bytea NOT NULL,
        encryption_key_version integer NOT NULL CHECK (encryption_key_version >= 1),
        parameter_names text[] NOT NULL,
        created_at timestamptz NOT NULL,
        CHECK (cardinality(parameter_names) BETWEEN 1 AND 256)
    );

    ALTER TABLE audit_events DROP CONSTRAINT audit_events_event_action_check;
    ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_action_check CHECK (
        event_action ~ '^[A-Z][A-Z0-9_]{0,127}$'
    );
    """,
)
