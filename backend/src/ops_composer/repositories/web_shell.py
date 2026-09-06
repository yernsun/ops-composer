from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql

from ops_composer.domain.web_shell import WebShellSession
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow

WEB_SHELL_ADMISSION_LOCK_KEY = 718_340_241
WEB_SHELL_COLUMNS = sql.SQL(
    "web_shell_session_id, host_id, actor_user_id, auth_session_id, credential_id, "
    "credential_version, host_name, host_address, ssh_port, username, state, api_instance_id, "
    "owner_id, ticket_expires_at, lease_expires_at, connected_at, last_activity_at, "
    "close_requested_at, created_at"
)


def _session(row: RepositoryRow) -> WebShellSession:
    return WebShellSession.model_validate(row)


class WebShellRepository(BaseRepository, Protocol):
    async def acquire_admission_lock(self) -> None: ...
    async def cleanup_expired(self, now: datetime) -> int: ...
    async def count_live(self, now: datetime) -> int: ...
    async def add(self, session: WebShellSession) -> WebShellSession: ...
    async def acquire_host_lock(
        self,
        host_id: UUID,
        web_shell_session_id: UUID,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
    ) -> bool: ...
    async def get(
        self, web_shell_session_id: UUID, *, for_update: bool = False
    ) -> WebShellSession | None: ...
    async def activate(
        self,
        web_shell_session_id: UUID,
        auth_session_id: UUID,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
    ) -> WebShellSession | None: ...
    async def heartbeat(
        self,
        web_shell_session_id: UUID,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
        last_activity_at: datetime,
    ) -> bool: ...
    async def mark_close_requested(
        self, web_shell_session_id: UUID, actor_user_id: UUID, now: datetime
    ) -> WebShellSession | None: ...
    async def delete(
        self, web_shell_session_id: UUID, owner_id: str | None = None
    ) -> WebShellSession | None: ...


class PostgresWebShellRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    async def acquire_admission_lock(self) -> None:
        await self.connection.fetch_one(
            sql.SQL("SELECT pg_advisory_xact_lock(%(admission_lock_key)s) AS acquired"),
            {"admission_lock_key": WEB_SHELL_ADMISSION_LOCK_KEY},
            prepare=True,
        )

    async def cleanup_expired(self, now: datetime) -> int:
        return await self.connection.execute(
            sql.SQL(
                "DELETE FROM web_shell_sessions WHERE "
                "(state = 'PENDING' AND ticket_expires_at <= %(now)s) OR "
                "(state IN ('ACTIVE', 'CLOSE_REQUESTED') AND lease_expires_at <= %(now)s)"
            ),
            {"now": now},
            prepare=True,
        )

    async def count_live(self, now: datetime) -> int:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT count(*) AS count FROM web_shell_sessions WHERE "
                "(state = 'PENDING' AND ticket_expires_at > %(now)s) OR "
                "(state IN ('ACTIVE', 'CLOSE_REQUESTED') AND lease_expires_at > %(now)s)"
            ),
            {"now": now},
            prepare=True,
        )
        if row is None:
            raise RuntimeError("Web Shell session count returned no row")
        return int(row["count"])

    async def add(self, session: WebShellSession) -> WebShellSession:
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO web_shell_sessions (web_shell_session_id, host_id, actor_user_id, "
                "auth_session_id, credential_id, credential_version, host_name, host_address, "
                "ssh_port, username, state, api_instance_id, owner_id, ticket_expires_at, "
                "lease_expires_at, connected_at, last_activity_at, close_requested_at, "
                "created_at) VALUES "
                "(%(web_shell_session_id)s, %(host_id)s, %(actor_user_id)s, "
                "%(auth_session_id)s, %(credential_id)s, %(credential_version)s, "
                "%(host_name)s, %(host_address)s, %(ssh_port)s, %(username)s, %(state)s, "
                "%(api_instance_id)s, %(owner_id)s, %(ticket_expires_at)s, "
                "%(lease_expires_at)s, %(connected_at)s, %(last_activity_at)s, "
                "%(close_requested_at)s, %(created_at)s) RETURNING {}"
            ).format(WEB_SHELL_COLUMNS),
            session.model_dump(mode="python"),
            prepare=True,
        )
        if row is None:
            raise RuntimeError("Web Shell session insert returned no row")
        return _session(row)

    async def acquire_host_lock(
        self,
        host_id: UUID,
        web_shell_session_id: UUID,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
    ) -> bool:
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO host_execution_locks (host_id, run_id, owner_id, acquired_at, "
                "expires_at, web_shell_session_id) VALUES (%(host_id)s, NULL, %(owner_id)s, "
                "%(now)s, %(expires_at)s, %(web_shell_session_id)s) "
                "ON CONFLICT (host_id) DO UPDATE SET run_id = NULL, owner_id = EXCLUDED.owner_id, "
                "acquired_at = EXCLUDED.acquired_at, expires_at = EXCLUDED.expires_at, "
                "web_shell_session_id = EXCLUDED.web_shell_session_id "
                "WHERE host_execution_locks.expires_at <= %(now)s RETURNING host_id"
            ),
            {
                "host_id": host_id,
                "web_shell_session_id": web_shell_session_id,
                "owner_id": owner_id,
                "now": now,
                "expires_at": expires_at,
            },
            prepare=True,
        )
        return row is not None

    async def get(
        self, web_shell_session_id: UUID, *, for_update: bool = False
    ) -> WebShellSession | None:
        suffix = sql.SQL(" FOR UPDATE") if for_update else sql.SQL("")
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT {} FROM web_shell_sessions "
                "WHERE web_shell_session_id = %(web_shell_session_id)s"
            ).format(WEB_SHELL_COLUMNS)
            + suffix,
            {"web_shell_session_id": web_shell_session_id},
            prepare=False,
        )
        return _session(row) if row is not None else None

    async def activate(
        self,
        web_shell_session_id: UUID,
        auth_session_id: UUID,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
    ) -> WebShellSession | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE web_shell_sessions ws SET state = 'ACTIVE', owner_id = %(owner_id)s, "
                "connected_at = %(now)s, last_activity_at = %(now)s, "
                "lease_expires_at = %(expires_at)s WHERE "
                "ws.web_shell_session_id = %(web_shell_session_id)s "
                "AND ws.auth_session_id = %(auth_session_id)s AND ws.state = 'PENDING' "
                "AND ws.ticket_expires_at > %(now)s AND EXISTS ("
                "SELECT 1 FROM sessions s JOIN users u ON u.user_id = s.user_id "
                "WHERE s.session_id = ws.auth_session_id AND s.expires_at > %(now)s "
                "AND u.status = 'ACTIVE') RETURNING {}"
            ).format(WEB_SHELL_COLUMNS),
            {
                "web_shell_session_id": web_shell_session_id,
                "auth_session_id": auth_session_id,
                "owner_id": owner_id,
                "now": now,
                "expires_at": expires_at,
            },
            prepare=True,
        )
        if row is None:
            return None
        updated = await self.connection.execute(
            sql.SQL(
                "UPDATE host_execution_locks SET owner_id = %(owner_id)s, "
                "expires_at = %(expires_at)s WHERE "
                "web_shell_session_id = %(web_shell_session_id)s AND expires_at > %(now)s"
            ),
            {
                "web_shell_session_id": web_shell_session_id,
                "owner_id": owner_id,
                "expires_at": expires_at,
                "now": now,
            },
            prepare=True,
        )
        if updated != 1:
            raise RuntimeError("Web Shell host lock was lost before connection")
        return _session(row)

    async def heartbeat(
        self,
        web_shell_session_id: UUID,
        owner_id: str,
        now: datetime,
        expires_at: datetime,
        last_activity_at: datetime,
    ) -> bool:
        row = await self.connection.fetch_one(
            sql.SQL(
                "WITH refreshed AS (UPDATE web_shell_sessions ws SET "
                "lease_expires_at = %(expires_at)s, last_activity_at = %(last_activity_at)s "
                "WHERE ws.web_shell_session_id = %(web_shell_session_id)s "
                "AND ws.owner_id = %(owner_id)s AND ws.state = 'ACTIVE' AND EXISTS ("
                "SELECT 1 FROM sessions s JOIN users u ON u.user_id = s.user_id "
                "WHERE s.session_id = ws.auth_session_id AND s.expires_at > %(now)s "
                "AND u.status = 'ACTIVE') RETURNING ws.web_shell_session_id), "
                "lock_refreshed AS (UPDATE host_execution_locks SET expires_at = %(expires_at)s "
                "WHERE web_shell_session_id IN (SELECT web_shell_session_id FROM refreshed) "
                "AND owner_id = %(owner_id)s RETURNING host_id) "
                "SELECT EXISTS (SELECT 1 FROM refreshed) AND "
                "EXISTS (SELECT 1 FROM lock_refreshed) AS refreshed"
            ),
            {
                "web_shell_session_id": web_shell_session_id,
                "owner_id": owner_id,
                "now": now,
                "expires_at": expires_at,
                "last_activity_at": last_activity_at,
            },
            prepare=True,
        )
        return bool(row and row["refreshed"])

    async def mark_close_requested(
        self, web_shell_session_id: UUID, actor_user_id: UUID, now: datetime
    ) -> WebShellSession | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE web_shell_sessions SET state = 'CLOSE_REQUESTED', "
                "close_requested_at = %(now)s WHERE "
                "web_shell_session_id = %(web_shell_session_id)s "
                "AND actor_user_id = %(actor_user_id)s AND state = 'ACTIVE' RETURNING {}"
            ).format(WEB_SHELL_COLUMNS),
            {
                "web_shell_session_id": web_shell_session_id,
                "actor_user_id": actor_user_id,
                "now": now,
            },
            prepare=True,
        )
        return _session(row) if row is not None else None

    async def delete(
        self, web_shell_session_id: UUID, owner_id: str | None = None
    ) -> WebShellSession | None:
        if owner_id is None:
            query = sql.SQL(
                "DELETE FROM web_shell_sessions WHERE "
                "web_shell_session_id = %(web_shell_session_id)s RETURNING {}"
            ).format(WEB_SHELL_COLUMNS)
            parameters: dict[str, object] = {"web_shell_session_id": web_shell_session_id}
        else:
            query = sql.SQL(
                "DELETE FROM web_shell_sessions WHERE "
                "web_shell_session_id = %(web_shell_session_id)s "
                "AND owner_id = %(owner_id)s RETURNING {}"
            ).format(WEB_SHELL_COLUMNS)
            parameters = {
                "web_shell_session_id": web_shell_session_id,
                "owner_id": owner_id,
            }
        row = await self.connection.fetch_one(query, parameters, prepare=False)
        return _session(row) if row is not None else None
