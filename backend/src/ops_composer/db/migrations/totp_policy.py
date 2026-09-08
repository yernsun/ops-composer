from __future__ import annotations

from ops_composer.db.migration_engine import Migration

TOTP_POLICY = Migration(
    migration_id="0100_totp_policy",
    dependencies=("0090_playbook_projects",),
    up_sql="""
    ALTER TABLE sessions ADD COLUMN reauthenticated_at timestamptz;
    UPDATE sessions SET reauthenticated_at = GREATEST(mfa_verified_at, created_at)
        WHERE elevated_until IS NOT NULL;
    ALTER TABLE sessions DROP CONSTRAINT sessions_elevation_check;
    ALTER TABLE sessions ADD CONSTRAINT sessions_elevation_check CHECK (
        (reauthenticated_at IS NULL OR reauthenticated_at >= created_at) AND
        (elevated_until IS NULL OR (
            reauthenticated_at IS NOT NULL AND elevated_until >= reauthenticated_at
        ))
    );
    """,
)
