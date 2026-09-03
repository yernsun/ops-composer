from ops_composer.db.migration_engine import Migration

AUTH_SECURITY = Migration(
    migration_id="0021_auth_security",
    dependencies=("0020_auth",),
    up_sql="""
    CREATE TABLE auth_rate_limits (
        scope text NOT NULL,
        subject_hash char(64) NOT NULL,
        window_started_at timestamptz NOT NULL,
        attempt_count integer NOT NULL CHECK (attempt_count >= 1),
        expires_at timestamptz NOT NULL,
        PRIMARY KEY (scope, subject_hash, window_started_at),
        CHECK (expires_at > window_started_at)
    );
    CREATE INDEX idx_auth_rate_limits_expires_at ON auth_rate_limits (expires_at);
    """,
)
