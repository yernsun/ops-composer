from __future__ import annotations

from ops_composer.db.migration_engine import Migration

GOVERNANCE = Migration(
    migration_id="0070_multi_admin_governance",
    dependencies=("0060_web_shell",),
    up_sql="""
    ALTER TABLE users DROP CONSTRAINT users_singleton_key_key;
    ALTER TABLE users DROP COLUMN singleton_key;
    ALTER TABLE users DROP CONSTRAINT users_status_check;
    ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
    ALTER TABLE users ALTER COLUMN password_updated_at DROP NOT NULL;
    ALTER TABLE users
        ADD COLUMN role text NOT NULL DEFAULT 'OWNER',
        ADD COLUMN mfa_enrollment_required boolean NOT NULL DEFAULT TRUE,
        ADD COLUMN activated_at timestamptz;
    ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (
        status IN ('PENDING_ACTIVATION', 'ACTIVE', 'DISABLED')
    );
    ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (
        role IN ('OWNER', 'ADMIN', 'OPERATOR', 'AUDITOR')
    );
    ALTER TABLE users ADD CONSTRAINT users_password_state_check CHECK (
        status <> 'ACTIVE' OR (password_hash IS NOT NULL AND password_updated_at IS NOT NULL)
    );
    UPDATE users SET role = 'OWNER', mfa_enrollment_required = TRUE,
        activated_at = COALESCE(activated_at, created_at);
    DELETE FROM sessions;

    ALTER TABLE sessions
        ADD COLUMN mfa_verified_at timestamptz,
        ADD COLUMN elevated_until timestamptz;
    ALTER TABLE sessions ADD CONSTRAINT sessions_elevation_check CHECK (
        elevated_until IS NULL OR (
            mfa_verified_at IS NOT NULL AND elevated_until >= mfa_verified_at
        )
    );

    CREATE TABLE user_activation_tokens (
        activation_token_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
        token_hash char(64) NOT NULL UNIQUE,
        created_by uuid NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz,
        created_at timestamptz NOT NULL,
        CHECK (expires_at > created_at),
        CHECK (consumed_at IS NULL OR consumed_at >= created_at)
    );
    CREATE UNIQUE INDEX uq_user_activation_tokens_live
        ON user_activation_tokens (user_id) WHERE consumed_at IS NULL;
    CREATE INDEX idx_user_activation_tokens_expiry
        ON user_activation_tokens (expires_at) WHERE consumed_at IS NULL;

    CREATE TABLE user_mfa_factors (
        user_id uuid PRIMARY KEY REFERENCES users (user_id) ON DELETE CASCADE,
        encrypted_totp_secret bytea NOT NULL,
        encryption_key_version integer NOT NULL CHECK (encryption_key_version >= 1),
        last_accepted_step bigint,
        confirmed_at timestamptz,
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL,
        CHECK (last_accepted_step IS NULL OR last_accepted_step >= 0),
        CHECK (updated_at >= created_at)
    );

    CREATE TABLE user_recovery_codes (
        recovery_code_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
        code_hash char(64) NOT NULL,
        used_at timestamptz,
        created_at timestamptz NOT NULL,
        UNIQUE (user_id, code_hash),
        CHECK (used_at IS NULL OR used_at >= created_at)
    );
    CREATE INDEX idx_user_recovery_codes_unused
        ON user_recovery_codes (user_id, recovery_code_id) WHERE used_at IS NULL;

    CREATE TABLE auth_challenges (
        challenge_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
        token_hash char(64) NOT NULL UNIQUE,
        purpose text NOT NULL CHECK (purpose IN ('LOGIN_MFA', 'MFA_ENROLLMENT')),
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz,
        created_at timestamptz NOT NULL,
        CHECK (expires_at > created_at),
        CHECK (consumed_at IS NULL OR consumed_at >= created_at)
    );
    CREATE INDEX idx_auth_challenges_expiry
        ON auth_challenges (expires_at) WHERE consumed_at IS NULL;

    CREATE FUNCTION reject_user_delete() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'users are retained for audit history' USING ERRCODE = '55000';
    END;
    $$;
    CREATE TRIGGER users_reject_delete
        BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION reject_user_delete();

    CREATE FUNCTION enforce_active_owner() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        PERFORM pg_advisory_xact_lock(133701070);
        IF NOT EXISTS (
            SELECT 1 FROM users WHERE role = 'OWNER' AND status = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION 'at least one active owner is required'
                USING ERRCODE = '23514', CONSTRAINT = 'ck_users_active_owner';
        END IF;
        RETURN NULL;
    END;
    $$;
    CREATE CONSTRAINT TRIGGER users_require_active_owner
        AFTER UPDATE OF role, status ON users
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION enforce_active_owner();
    """,
)
