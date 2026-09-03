from ops_composer.db.migration_engine import Migration

AUTH = Migration(
    migration_id="0020_auth",
    dependencies=("0001_core",),
    up_sql="""
    CREATE TABLE users (
        user_id uuid PRIMARY KEY,
        singleton_key boolean NOT NULL DEFAULT TRUE UNIQUE CHECK (singleton_key),
        username text NOT NULL,
        password_hash text NOT NULL,
        status text NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
        version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL,
        password_updated_at timestamptz NOT NULL
    );
    CREATE UNIQUE INDEX uq_users_username_canonical ON users ((lower(username)));

    CREATE TABLE sessions (
        session_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
        token_hash char(64) NOT NULL UNIQUE,
        csrf_hash char(64) NOT NULL,
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL,
        CHECK (expires_at > created_at)
    );
    CREATE INDEX idx_sessions_user_expires ON sessions (user_id, expires_at);
    CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
    """,
)
