from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql
from psycopg.errors import UniqueViolation

from ops_composer.auth.errors import AdminAlreadyExistsError
from ops_composer.auth.models import (
    PasswordCredential,
    SessionPrincipal,
    UserIdentity,
    UserWithCredential,
)
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow


def _identity_from_row(row: RepositoryRow) -> UserIdentity:
    return UserIdentity.model_validate(
        {
            "user_id": row["user_id"],
            "username": row["username"],
            "status": row["status"],
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

    async def find_user_by_username(self, username: str) -> UserWithCredential | None: ...

    async def update_password_hash(
        self, user_id: UUID, password_hash: str, updated_at: datetime
    ) -> None: ...

    async def add_session(
        self,
        *,
        session_id: UUID,
        user_id: UUID,
        token_hash: str,
        csrf_hash: str,
        expires_at: datetime,
        created_at: datetime,
    ) -> None: ...

    async def resolve_session(self, token_hash: str, now: datetime) -> SessionPrincipal | None: ...

    async def delete_session(self, session_id: UUID) -> None: ...

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
                    "user_id, singleton_key, username, password_hash, status, version, "
                    "created_at, updated_at, password_updated_at"
                    ") VALUES ("
                    "%(user_id)s, TRUE, %(username)s, %(password_hash)s, %(status)s, "
                    "%(version)s, %(created_at)s, %(updated_at)s, %(password_updated_at)s"
                    ") RETURNING user_id, username, status, version, created_at, updated_at"
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

    async def find_user_by_username(self, username: str) -> UserWithCredential | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT user_id, username, password_hash, status, version, created_at, "
                "updated_at, password_updated_at FROM users WHERE lower(username) = %(username)s"
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
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO sessions (session_id, user_id, token_hash, csrf_hash, "
                "expires_at, created_at) VALUES (%(session_id)s, %(user_id)s, "
                "%(token_hash)s, %(csrf_hash)s, %(expires_at)s, %(created_at)s)"
            ),
            {
                "session_id": session_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "csrf_hash": csrf_hash,
                "expires_at": expires_at,
                "created_at": created_at,
            },
            prepare=True,
        )

    async def resolve_session(self, token_hash: str, now: datetime) -> SessionPrincipal | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT s.session_id, s.user_id, u.username, s.csrf_hash, s.expires_at "
                "FROM sessions s JOIN users u ON u.user_id = s.user_id "
                "WHERE s.token_hash = %(token_hash)s AND s.expires_at > %(now)s "
                "AND u.status = 'ACTIVE'"
            ),
            {"token_hash": token_hash, "now": now},
            prepare=True,
        )
        return SessionPrincipal.model_validate(row) if row is not None else None

    async def delete_session(self, session_id: UUID) -> None:
        await self.connection.execute(
            sql.SQL("DELETE FROM sessions WHERE session_id = %(session_id)s"),
            {"session_id": session_id},
            prepare=True,
        )

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
