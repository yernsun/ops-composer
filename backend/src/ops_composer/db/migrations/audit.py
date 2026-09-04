from __future__ import annotations

from ops_composer.db.migration_engine import Migration

AUDIT = Migration(
    migration_id="0040_audit_events",
    dependencies=("0030_ops_composer",),
    up_sql="""
    CREATE TABLE audit_events (
        audit_event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        occurred_at timestamptz NOT NULL,
        schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
        severity text NOT NULL CHECK (severity IN (
            'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
        )),
        source text NOT NULL CHECK (source IN ('API', 'WORKER', 'CLI', 'SYSTEM')),
        service text NOT NULL CHECK (length(service) BETWEEN 1 AND 32),
        event_action text NOT NULL CHECK (
            event_action ~ '^[A-Z][A-Z0-9_]{0,127}$'
        ),
        event_outcome text NOT NULL CHECK (event_outcome IN (
            'STARTED', 'SUCCEEDED', 'FAILED', 'DENIED', 'NOOP'
        )),
        request_id text CHECK (request_id IS NULL OR length(request_id) <= 128),
        correlation_id text CHECK (
            correlation_id IS NULL OR length(correlation_id) <= 128
        ),
        actor_user_id uuid,
        session_id uuid,
        run_id uuid,
        run_target_id uuid,
        worker_id text CHECK (worker_id IS NULL OR length(worker_id) <= 255),
        resource_type text CHECK (
            resource_type IS NULL OR length(resource_type) <= 64
        ),
        resource_id text CHECK (resource_id IS NULL OR length(resource_id) <= 255),
        duration_ms double precision CHECK (duration_ms IS NULL OR duration_ms >= 0),
        error_code text CHECK (error_code IS NULL OR length(error_code) <= 128),
        exception_type text CHECK (
            exception_type IS NULL OR length(exception_type) <= 255
        ),
        failure_stage text CHECK (
            failure_stage IS NULL OR length(failure_stage) <= 128
        ),
        retryable boolean,
        metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
            jsonb_typeof(metadata) = 'object'
        )
    );

    CREATE INDEX idx_audit_events_recent
        ON audit_events (occurred_at DESC, audit_event_id DESC);
    CREATE INDEX idx_audit_events_action_recent
        ON audit_events (event_action, occurred_at DESC, audit_event_id DESC);
    CREATE INDEX idx_audit_events_run_recent
        ON audit_events (run_id, occurred_at DESC, audit_event_id DESC)
        WHERE run_id IS NOT NULL;
    CREATE INDEX idx_audit_events_actor_recent
        ON audit_events (actor_user_id, occurred_at DESC, audit_event_id DESC)
        WHERE actor_user_id IS NOT NULL;
    CREATE INDEX idx_audit_events_resource_recent
        ON audit_events (resource_type, resource_id, occurred_at DESC, audit_event_id DESC)
        WHERE resource_type IS NOT NULL AND resource_id IS NOT NULL;

    CREATE FUNCTION reject_audit_event_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = '55000';
    END;
    $$;

    CREATE TRIGGER audit_events_reject_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION reject_audit_event_update();
    """,
)
