from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql
from psycopg.errors import UniqueViolation

from ops_composer.auth.errors import AdminAlreadyExistsError
from ops_composer.auth.models import (
    ActivationGrant,
    ChallengePurpose,
    ConsumedChallenge,
    MfaFactor,
    PasswordCredential,
    SessionPrincipal,
    UserIdentity,
    UserRole,
    UserWithCredential,
    permissions_for_role,
)
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow


def _identity_from_row(row: RepositoryRow) -> UserIdentity:
    return UserIdentity.model_validate(
        {
            "user_id": row["user_id"],
            "username": row["username"],
            "status": row["status"],
            "role": row.get("role", UserRole.OPERATOR),
            "mfa_enrollment_required": row.get("mfa_enrollment_required", False),
            "activated_at": row.get("activated_at"),
            "version": row["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


class AuthRepository(BaseRepository, Protocol):
    async def add_admin(
        self, identity: UserIdentity, credential: PasswordCredential
    ) -> UserIdentity: ...

    async def count_users(self) -> int: ...

    async def list_users(self) -> tuple[UserIdentity, ...]: ...

    async def get_user(self, user_id: UUID) -> UserIdentity | None: ...

    async def add_user(self, identity: UserIdentity) -> UserIdentity: ...

    async def update_user(
        self,
        user_id: UUID,
        *,
        role: UserRole,
        status: str,
        expected_version: int,
        updated_at: datetime,
    ) -> UserIdentity | None: ...

    async def find_user_by_username(self, username: str) -> UserWithCredential | None: ...

    async def update_password_hash(
        self, user_id: UUID, password_hash: str, updated_at: datetime
    ) -> None: ...

    async def activate_user(
        self,
        user_id: UUID,
        *,
        password_hash: str,
        mfa_enrollment_required: bool,
        activated_at: datetime,
    ) -> UserIdentity: ...

    async def invalidate_activation_tokens(self, user_id: UUID, consumed_at: datetime) -> None: ...

    async def add_activation_token(
        self,
        *,
        activation_token_id: UUID,
        user_id: UUID,
        token_hash: str,
        created_by: UUID,
        expires_at: datetime,
        created_at: datetime,
    ) -> None: ...

    async def consume_activation_token(
        self, token_hash: str, consumed_at: datetime
    ) -> ActivationGrant | None: ...

    async def add_session(
        self,
        *,
        session_id: UUID,
        user_id: UUID,
        token_hash: str,
        csrf_hash: str,
        expires_at: datetime,
        created_at: datetime,
        mfa_verified_at: datetime | None = None,
        elevated_until: datetime | None = None,
    ) -> None: ...

    async def resolve_session(self, token_hash: str, now: datetime) -> SessionPrincipal | None: ...

    async def delete_session(self, session_id: UUID) -> None: ...

    async def delete_user_sessions(self, user_id: UUID) -> int: ...

    async def elevate_session(
        self, session_id: UUID, elevated_until: datetime
    ) -> SessionPrincipal | None: ...

    async def add_challenge(
        self,
        *,
        challenge_id: UUID,
        user_id: UUID,
        token_hash: str,
        purpose: ChallengePurpose,
        expires_at: datetime,
        created_at: datetime,
    ) -> None: ...

    async def consume_challenge(
        self, token_hash: str, consumed_at: datetime
    ) -> ConsumedChallenge | None: ...

    async def resolve_challenge(
        self, token_hash: str, now: datetime
    ) -> ConsumedChallenge | None: ...

    async def mark_challenge_consumed(self, challenge_id: UUID, consumed_at: datetime) -> bool: ...

    async def get_mfa_factor(self, user_id: UUID) -> MfaFactor | None: ...

    async def put_mfa_factor(self, factor: MfaFactor) -> None: ...

    async def confirm_mfa_factor(self, user_id: UUID, confirmed_at: datetime) -> None: ...

    async def accept_totp_step(self, user_id: UUID, step: int, updated_at: datetime) -> bool: ...

    async def replace_recovery_codes(
        self, user_id: UUID, rows: tuple[tuple[UUID, str], ...], created_at: datetime
    ) -> None: ...

    async def consume_recovery_code(
        self, user_id: UUID, code_hash: str, used_at: datetime
    ) -> bool: ...

    async def reset_mfa(self, user_id: UUID, updated_at: datetime) -> None: ...

    async def count_unused_recovery_codes(self, user_id: UUID) -> int: ...

    async def count_active_owners(self) -> int: ...

    async def consume_rate_limit(
        self,
        *,
        scope: str,
        subject_hash: str,
        window_started_at: datetime,
        expires_at: datetime,
    ) -> int: ...

    async def clear_rate_limit(
        self, *, scope: str, subject_hash: str, window_started_at: datetime
    ) -> None: ...

    async def purge_expired(self, now: datetime) -> tuple[int, int]: ...

    async def count_expired(self, now: datetime) -> tuple[int, int]: ...


class PostgresAuthRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    async def add_admin(
        self, identity: UserIdentity, credential: PasswordCredential
    ) -> UserIdentity:
        values = identity.model_dump(mode="python") | credential.model_dump(mode="python")
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO users ("
                    "user_id, username, password_hash, status, role, mfa_enrollment_required, "
                    "version, created_at, updated_at, password_updated_at, activated_at"
                    ") VALUES ("
                    "%(user_id)s, %(username)s, %(password_hash)s, %(status)s, %(role)s, "
                    "%(mfa_enrollment_required)s, %(version)s, %(created_at)s, %(updated_at)s, "
                    "%(password_updated_at)s, %(activated_at)s"
                    ") RETURNING user_id, username, status, role, mfa_enrollment_required, "
                    "activated_at, version, created_at, updated_at"
                ),
                values,
                prepare=True,
            )
        except UniqueViolation as error:
            raise AdminAlreadyExistsError() from error
        if row is None:
            raise RuntimeError("administrator insert returned no row")
        return _identity_from_row(row)

    async def count_users(self) -> int:
        row = await self.connection.fetch_one(
            sql.SQL("SELECT count(*) AS count FROM users"), prepare=True
        )
        if row is None:
            raise RuntimeError("administrator count returned no row")
        return int(row["count"])

    async def list_users(self) -> tuple[UserIdentity, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT user_id, username, status, role, mfa_enrollment_required, "
                "activated_at, version, created_at, updated_at FROM users "
                "ORDER BY lower(username), user_id"
            ),
            prepare=True,
        )
        return tuple(_identity_from_row(row) for row in rows)

    async def get_user(self, user_id: UUID) -> UserIdentity | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT user_id, username, status, role, mfa_enrollment_required, "
                "activated_at, version, created_at, updated_at FROM users "
                "WHERE user_id = %(user_id)s"
            ),
            {"user_id": user_id},
            prepare=True,
        )
        return _identity_from_row(row) if row is not None else None

    async def add_user(self, identity: UserIdentity) -> UserIdentity:
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO users (user_id, username, password_hash, status, role, "
                    "mfa_enrollment_required, version, created_at, updated_at, "
                    "password_updated_at, activated_at) VALUES (%(user_id)s, %(username)s, "
                    "NULL, %(status)s, %(role)s, %(mfa_enrollment_required)s, %(version)s, "
                    "%(created_at)s, %(updated_at)s, NULL, %(activated_at)s) "
                    "RETURNING user_id, username, status, role, mfa_enrollment_required, "
                    "activated_at, version, created_at, updated_at"
                ),
                identity.model_dump(mode="python"),
                prepare=True,
            )
        except UniqueViolation as error:
            raise AdminAlreadyExistsError() from error
        if row is None:
            raise RuntimeError("user insert returned no row")
        return _identity_from_row(row)

    async def update_user(
        self,
        user_id: UUID,
        *,
        role: UserRole,
        status: str,
        expected_version: int,
        updated_at: datetime,
    ) -> UserIdentity | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE users SET role = %(role)s, status = %(status)s, "
                "mfa_enrollment_required = CASE "
                "WHEN %(role)s IN ('OWNER', 'ADMIN') AND NOT EXISTS ("
                "SELECT 1 FROM user_mfa_factors f WHERE f.user_id = users.user_id "
                "AND f.confirmed_at IS NOT NULL) THEN TRUE ELSE mfa_enrollment_required END, "
                "version = version + 1, updated_at = %(updated_at)s "
                "WHERE user_id = %(user_id)s AND version = %(expected_version)s "
                "RETURNING user_id, username, status, role, mfa_enrollment_required, "
                "activated_at, version, created_at, updated_at"
            ),
            {
                "user_id": user_id,
                "role": role,
                "status": status,
                "expected_version": expected_version,
                "updated_at": updated_at,
            },
            prepare=True,
        )
        return _identity_from_row(row) if row is not None else None

    async def find_user_by_username(self, username: str) -> UserWithCredential | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT user_id, username, password_hash, status, role, "
                "mfa_enrollment_required, activated_at, version, created_at, "
                "updated_at, password_updated_at FROM users "
                "WHERE lower(username) = %(username)s"
            ),
            {"username": username},
            prepare=True,
        )
        if row is None:
            return None
        identity = _identity_from_row(row)
        return UserWithCredential(
            identity=identity,
            credential=PasswordCredential(
                user_id=identity.user_id,
                password_hash=row["password_hash"],
                password_updated_at=row["password_updated_at"],
            ),
        )

    async def activate_user(
        self,
        user_id: UUID,
        *,
        password_hash: str,
        mfa_enrollment_required: bool,
        activated_at: datetime,
    ) -> UserIdentity:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE users SET password_hash = %(password_hash)s, status = 'ACTIVE', "
                "mfa_enrollment_required = %(mfa_enrollment_required)s, "
                "password_updated_at = %(activated_at)s, activated_at = %(activated_at)s, "
                "updated_at = %(activated_at)s, version = version + 1 "
                "WHERE user_id = %(user_id)s AND status = 'PENDING_ACTIVATION' "
                "RETURNING user_id, username, status, role, mfa_enrollment_required, "
                "activated_at, version, created_at, updated_at"
            ),
            {
                "user_id": user_id,
                "password_hash": password_hash,
                "mfa_enrollment_required": mfa_enrollment_required,
                "activated_at": activated_at,
            },
            prepare=True,
        )
        if row is None:
            raise RuntimeError("pending user activation returned no row")
        return _identity_from_row(row)

    async def invalidate_activation_tokens(self, user_id: UUID, consumed_at: datetime) -> None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE user_activation_tokens SET consumed_at = %(consumed_at)s "
                "WHERE user_id = %(user_id)s AND consumed_at IS NULL"
            ),
            {"user_id": user_id, "consumed_at": consumed_at},
            prepare=True,
        )

    async def add_activation_token(
        self,
        *,
        activation_token_id: UUID,
        user_id: UUID,
        token_hash: str,
        created_by: UUID,
        expires_at: datetime,
        created_at: datetime,
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO user_activation_tokens (activation_token_id, user_id, token_hash, "
                "created_by, expires_at, created_at) VALUES (%(activation_token_id)s, "
                "%(user_id)s, %(token_hash)s, %(created_by)s, %(expires_at)s, %(created_at)s)"
            ),
            {
                "activation_token_id": activation_token_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "created_by": created_by,
                "expires_at": expires_at,
                "created_at": created_at,
            },
            prepare=True,
        )

    async def consume_activation_token(
        self, token_hash: str, consumed_at: datetime
    ) -> ActivationGrant | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE user_activation_tokens t SET consumed_at = %(consumed_at)s "
                "FROM users u WHERE t.token_hash = %(token_hash)s AND t.user_id = u.user_id "
                "AND t.consumed_at IS NULL AND t.expires_at > %(consumed_at)s "
                "AND u.status = 'PENDING_ACTIVATION' RETURNING t.activation_token_id, "
                "u.user_id, u.username, u.status, u.role, u.mfa_enrollment_required, "
                "u.activated_at, u.version, u.created_at, u.updated_at"
            ),
            {"token_hash": token_hash, "consumed_at": consumed_at},
            prepare=True,
        )
        if row is None:
            return None
        return ActivationGrant(
            activation_token_id=row["activation_token_id"], user=_identity_from_row(row)
        )

    async def update_password_hash(
        self, user_id: UUID, password_hash: str, updated_at: datetime
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE users SET password_hash = %(password_hash)s, "
                "password_updated_at = %(updated_at)s, updated_at = %(updated_at)s, "
                "version = version + 1 WHERE user_id = %(user_id)s"
            ),
            {"user_id": user_id, "password_hash": password_hash, "updated_at": updated_at},
            prepare=True,
        )

    async def add_session(
        self,
        *,
        session_id: UUID,
        user_id: UUID,
        token_hash: str,
        csrf_hash: str,
        expires_at: datetime,
        created_at: datetime,
        mfa_verified_at: datetime | None = None,
        elevated_until: datetime | None = None,
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO sessions (session_id, user_id, token_hash, csrf_hash, "
                "expires_at, created_at, mfa_verified_at, elevated_until) VALUES ("
                "%(session_id)s, %(user_id)s, "
                "%(token_hash)s, %(csrf_hash)s, %(expires_at)s, %(created_at)s, "
                "%(mfa_verified_at)s, %(elevated_until)s)"
            ),
            {
                "session_id": session_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "csrf_hash": csrf_hash,
                "expires_at": expires_at,
                "created_at": created_at,
                "mfa_verified_at": mfa_verified_at,
                "elevated_until": elevated_until,
            },
            prepare=True,
        )

    async def resolve_session(self, token_hash: str, now: datetime) -> SessionPrincipal | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT s.session_id, s.user_id, u.username, u.role, "
                "u.mfa_enrollment_required, s.csrf_hash, s.expires_at, "
                "s.mfa_verified_at, s.elevated_until, "
                "EXISTS (SELECT 1 FROM user_mfa_factors f WHERE f.user_id = u.user_id "
                "AND f.confirmed_at IS NOT NULL) AS mfa_enabled "
                "FROM sessions s JOIN users u ON u.user_id = s.user_id "
                "WHERE s.token_hash = %(token_hash)s AND s.expires_at > %(now)s "
                "AND u.status = 'ACTIVE'"
            ),
            {"token_hash": token_hash, "now": now},
            prepare=True,
        )
        if row is None:
            return None
        role = UserRole(row["role"])
        return SessionPrincipal.model_validate({**row, "permissions": permissions_for_role(role)})

    async def delete_session(self, session_id: UUID) -> None:
        await self.connection.execute(
            sql.SQL("DELETE FROM sessions WHERE session_id = %(session_id)s"),
            {"session_id": session_id},
            prepare=True,
        )

    async def delete_user_sessions(self, user_id: UUID) -> int:
        return await self.connection.execute(
            sql.SQL("DELETE FROM sessions WHERE user_id = %(user_id)s"),
            {"user_id": user_id},
            prepare=True,
        )

    async def elevate_session(
        self, session_id: UUID, elevated_until: datetime
    ) -> SessionPrincipal | None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE sessions SET elevated_until = %(elevated_until)s "
                "WHERE session_id = %(session_id)s"
            ),
            {"session_id": session_id, "elevated_until": elevated_until},
            prepare=True,
        )
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT s.session_id, s.user_id, u.username, u.role, "
                "u.mfa_enrollment_required, s.csrf_hash, s.expires_at, "
                "s.mfa_verified_at, s.elevated_until, TRUE AS mfa_enabled "
                "FROM sessions s JOIN users u ON u.user_id = s.user_id "
                "WHERE s.session_id = %(session_id)s AND u.status = 'ACTIVE'"
            ),
            {"session_id": session_id},
            prepare=True,
        )
        if row is None:
            return None
        role = UserRole(row["role"])
        return SessionPrincipal.model_validate({**row, "permissions": permissions_for_role(role)})

    async def add_challenge(
        self,
        *,
        challenge_id: UUID,
        user_id: UUID,
        token_hash: str,
        purpose: ChallengePurpose,
        expires_at: datetime,
        created_at: datetime,
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO auth_challenges (challenge_id, user_id, token_hash, purpose, "
                "expires_at, created_at) VALUES (%(challenge_id)s, %(user_id)s, "
                "%(token_hash)s, %(purpose)s, %(expires_at)s, %(created_at)s)"
            ),
            {
                "challenge_id": challenge_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "purpose": purpose,
                "expires_at": expires_at,
                "created_at": created_at,
            },
            prepare=True,
        )

    async def consume_challenge(
        self, token_hash: str, consumed_at: datetime
    ) -> ConsumedChallenge | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE auth_challenges SET consumed_at = %(consumed_at)s "
                "WHERE token_hash = %(token_hash)s AND consumed_at IS NULL "
                "AND expires_at > %(consumed_at)s RETURNING challenge_id, user_id, purpose"
            ),
            {"token_hash": token_hash, "consumed_at": consumed_at},
            prepare=True,
        )
        return ConsumedChallenge.model_validate(row) if row is not None else None

    async def resolve_challenge(self, token_hash: str, now: datetime) -> ConsumedChallenge | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT challenge_id, user_id, purpose FROM auth_challenges "
                "WHERE token_hash = %(token_hash)s AND consumed_at IS NULL "
                "AND expires_at > %(now)s FOR UPDATE"
            ),
            {"token_hash": token_hash, "now": now},
            prepare=True,
        )
        return ConsumedChallenge.model_validate(row) if row is not None else None

    async def mark_challenge_consumed(self, challenge_id: UUID, consumed_at: datetime) -> bool:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE auth_challenges SET consumed_at = %(consumed_at)s "
                "WHERE challenge_id = %(challenge_id)s AND consumed_at IS NULL "
                "RETURNING challenge_id"
            ),
            {"challenge_id": challenge_id, "consumed_at": consumed_at},
            prepare=True,
        )
        return row is not None

    async def get_mfa_factor(self, user_id: UUID) -> MfaFactor | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT user_id, encrypted_totp_secret, encryption_key_version, "
                "last_accepted_step, confirmed_at, created_at, updated_at "
                "FROM user_mfa_factors WHERE user_id = %(user_id)s"
            ),
            {"user_id": user_id},
            prepare=True,
        )
        return MfaFactor.model_validate(row) if row is not None else None

    async def put_mfa_factor(self, factor: MfaFactor) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO user_mfa_factors (user_id, encrypted_totp_secret, "
                "encryption_key_version, last_accepted_step, confirmed_at, created_at, "
                "updated_at) VALUES (%(user_id)s, %(encrypted_totp_secret)s, "
                "%(encryption_key_version)s, %(last_accepted_step)s, %(confirmed_at)s, "
                "%(created_at)s, %(updated_at)s) ON CONFLICT (user_id) DO UPDATE SET "
                "encrypted_totp_secret = EXCLUDED.encrypted_totp_secret, "
                "encryption_key_version = EXCLUDED.encryption_key_version, "
                "last_accepted_step = NULL, confirmed_at = NULL, "
                "updated_at = EXCLUDED.updated_at"
            ),
            factor.model_dump(mode="python"),
            prepare=True,
        )

    async def confirm_mfa_factor(self, user_id: UUID, confirmed_at: datetime) -> None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE user_mfa_factors SET confirmed_at = %(confirmed_at)s, "
                "updated_at = %(confirmed_at)s WHERE user_id = %(user_id)s"
            ),
            {"user_id": user_id, "confirmed_at": confirmed_at},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL(
                "UPDATE users SET mfa_enrollment_required = FALSE, updated_at = %(confirmed_at)s, "
                "version = version + 1 WHERE user_id = %(user_id)s"
            ),
            {"user_id": user_id, "confirmed_at": confirmed_at},
            prepare=True,
        )

    async def accept_totp_step(self, user_id: UUID, step: int, updated_at: datetime) -> bool:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE user_mfa_factors SET last_accepted_step = %(step)s, "
                "updated_at = %(updated_at)s WHERE user_id = %(user_id)s "
                "AND confirmed_at IS NOT NULL AND (last_accepted_step IS NULL "
                "OR last_accepted_step < %(step)s) RETURNING user_id"
            ),
            {"user_id": user_id, "step": step, "updated_at": updated_at},
            prepare=True,
        )
        return row is not None

    async def replace_recovery_codes(
        self, user_id: UUID, rows: tuple[tuple[UUID, str], ...], created_at: datetime
    ) -> None:
        await self.connection.execute(
            sql.SQL("DELETE FROM user_recovery_codes WHERE user_id = %(user_id)s"),
            {"user_id": user_id},
            prepare=True,
        )
        await self.connection.execute_many(
            sql.SQL(
                "INSERT INTO user_recovery_codes (recovery_code_id, user_id, code_hash, "
                "created_at) VALUES (%(recovery_code_id)s, %(user_id)s, %(code_hash)s, "
                "%(created_at)s)"
            ),
            (
                {
                    "recovery_code_id": recovery_code_id,
                    "user_id": user_id,
                    "code_hash": code_hash,
                    "created_at": created_at,
                }
                for recovery_code_id, code_hash in rows
            ),
        )

    async def consume_recovery_code(self, user_id: UUID, code_hash: str, used_at: datetime) -> bool:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE user_recovery_codes SET used_at = %(used_at)s "
                "WHERE user_id = %(user_id)s AND code_hash = %(code_hash)s "
                "AND used_at IS NULL RETURNING recovery_code_id"
            ),
            {"user_id": user_id, "code_hash": code_hash, "used_at": used_at},
            prepare=True,
        )
        return row is not None

    async def reset_mfa(self, user_id: UUID, updated_at: datetime) -> None:
        await self.connection.execute(
            sql.SQL("DELETE FROM user_recovery_codes WHERE user_id = %(user_id)s"),
            {"user_id": user_id},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL("DELETE FROM user_mfa_factors WHERE user_id = %(user_id)s"),
            {"user_id": user_id},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL("DELETE FROM sessions WHERE user_id = %(user_id)s"),
            {"user_id": user_id},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL(
                "UPDATE users SET mfa_enrollment_required = TRUE, updated_at = %(updated_at)s, "
                "version = version + 1 WHERE user_id = %(user_id)s"
            ),
            {"user_id": user_id, "updated_at": updated_at},
            prepare=True,
        )

    async def count_unused_recovery_codes(self, user_id: UUID) -> int:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT count(*) AS count FROM user_recovery_codes "
                "WHERE user_id = %(user_id)s AND used_at IS NULL"
            ),
            {"user_id": user_id},
            prepare=True,
        )
        if row is None:
            raise RuntimeError("recovery-code count returned no row")
        return int(row["count"])

    async def count_active_owners(self) -> int:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT count(*) AS count FROM users "
                "WHERE role = 'OWNER' AND status = 'ACTIVE'"
            ),
            prepare=True,
        )
        if row is None:
            raise RuntimeError("active-owner count returned no row")
        return int(row["count"])

    async def consume_rate_limit(
        self,
        *,
        scope: str,
        subject_hash: str,
        window_started_at: datetime,
        expires_at: datetime,
    ) -> int:
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO auth_rate_limits (scope, subject_hash, window_started_at, "
                "attempt_count, expires_at) VALUES (%(scope)s, %(subject_hash)s, "
                "%(window_started_at)s, 1, %(expires_at)s) "
                "ON CONFLICT (scope, subject_hash, window_started_at) DO UPDATE "
                "SET attempt_count = auth_rate_limits.attempt_count + 1, "
                "expires_at = EXCLUDED.expires_at RETURNING attempt_count"
            ),
            {
                "scope": scope,
                "subject_hash": subject_hash,
                "window_started_at": window_started_at,
                "expires_at": expires_at,
            },
            prepare=True,
        )
        if row is None:
            raise RuntimeError("rate-limit upsert returned no row")
        return int(row["attempt_count"])

    async def clear_rate_limit(
        self, *, scope: str, subject_hash: str, window_started_at: datetime
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "DELETE FROM auth_rate_limits WHERE scope = %(scope)s "
                "AND subject_hash = %(subject_hash)s "
                "AND window_started_at = %(window_started_at)s"
            ),
            {
                "scope": scope,
                "subject_hash": subject_hash,
                "window_started_at": window_started_at,
            },
            prepare=True,
        )

    async def purge_expired(self, now: datetime) -> tuple[int, int]:
        sessions = await self.connection.execute(
            sql.SQL("DELETE FROM sessions WHERE expires_at <= %(now)s"),
            {"now": now},
            prepare=True,
        )
        limits = await self.connection.execute(
            sql.SQL("DELETE FROM auth_rate_limits WHERE expires_at <= %(now)s"),
            {"now": now},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL("DELETE FROM auth_challenges WHERE expires_at <= %(now)s"),
            {"now": now},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL(
                "DELETE FROM user_activation_tokens WHERE expires_at <= %(now)s "
                "OR consumed_at IS NOT NULL"
            ),
            {"now": now},
            prepare=True,
        )
        return sessions, limits

    async def count_expired(self, now: datetime) -> tuple[int, int]:
        session_row = await self.connection.fetch_one(
            sql.SQL("SELECT count(*) AS count FROM sessions WHERE expires_at <= %(now)s"),
            {"now": now},
            prepare=True,
        )
        rate_row = await self.connection.fetch_one(
            sql.SQL("SELECT count(*) AS count FROM auth_rate_limits WHERE expires_at <= %(now)s"),
            {"now": now},
            prepare=True,
        )
        if session_row is None or rate_row is None:
            raise RuntimeError("expired-auth count query returned no row")
        return int(session_row["count"]), int(rate_row["count"])
