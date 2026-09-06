from __future__ import annotations

import asyncio
import sys
from contextlib import AsyncExitStack
from functools import cached_property
from types import TracebackType

from ops_composer.auth.repository import PostgresAuthRepository
from ops_composer.db.registry import MIGRATIONS
from ops_composer.db.repository_connection import PsycopgRepositoryConnection
from ops_composer.db.types import DbPool
from ops_composer.repositories.assets import PostgresAssetRepository
from ops_composer.repositories.audit import PostgresAuditRepository
from ops_composer.repositories.base import RepositoryConnection
from ops_composer.repositories.health import PostgresHealthRepository
from ops_composer.repositories.playbooks import PostgresPlaybookRepository
from ops_composer.repositories.runs import PostgresRunRepository
from ops_composer.repositories.web_shell import PostgresWebShellRepository

EXPECTED_MIGRATION_CHECKSUMS = {
    migration.migration_id: migration.checksum for migration in MIGRATIONS
}


class UnitOfWork:
    """One pooled transaction, one task, one use, and lazy repositories."""

    def __init__(self, pool: DbPool) -> None:
        self._pool = pool
        self._contexts = AsyncExitStack()
        self._repository_connection: PsycopgRepositoryConnection | None = None
        self._owner: asyncio.Task[object] | None = None
        self._entered = False
        self._closed = False

    async def __aenter__(self) -> UnitOfWork:
        if self._entered or self._closed:
            raise RuntimeError("UnitOfWork instances are single-use")
        owner = asyncio.current_task()
        if owner is None:
            raise RuntimeError("UnitOfWork requires an active asyncio task")
        self._owner = owner
        self._entered = True
        try:
            connection = await self._contexts.enter_async_context(self._pool.connection())
            await self._contexts.enter_async_context(connection.transaction())
            self._repository_connection = PsycopgRepositoryConnection(connection, owner)
            return self
        except BaseException:
            self._closed = True
            await self._contexts.__aexit__(*sys.exc_info())
            raise

    def assert_owner(self) -> None:
        if not self._entered or self._closed:
            raise RuntimeError("UnitOfWork is not active")
        if asyncio.current_task() is not self._owner:
            raise RuntimeError("UnitOfWork cannot cross asyncio task boundaries")

    def _require_connection(self) -> RepositoryConnection:
        self.assert_owner()
        connection = self._repository_connection
        if connection is None:
            raise RuntimeError("UnitOfWork repository connection was not initialized")
        return connection

    @cached_property
    def health(self) -> PostgresHealthRepository:
        """Return migration-aware readiness persistence for this transaction."""

        return PostgresHealthRepository(
            self._require_connection(),
            expected_migrations=EXPECTED_MIGRATION_CHECKSUMS,
        )

    @cached_property
    def auth(self) -> PostgresAuthRepository:
        """Return authentication persistence for this transaction."""

        return PostgresAuthRepository(self._require_connection())

    @cached_property
    def assets(self) -> PostgresAssetRepository:
        """Return host, group, credential, and host-key persistence."""

        return PostgresAssetRepository(self._require_connection())

    @cached_property
    def runs(self) -> PostgresRunRepository:
        """Return durable queue, execution, Lease, lock, and event persistence."""

        return PostgresRunRepository(self._require_connection())

    @cached_property
    def playbooks(self) -> PostgresPlaybookRepository:
        """Return database-backed Playbook and immutable revision persistence."""

        return PostgresPlaybookRepository(self._require_connection())

    @cached_property
    def audit(self) -> PostgresAuditRepository:
        """Return append-only operational audit persistence."""

        return PostgresAuditRepository(self._require_connection())

    @cached_property
    def web_shell(self) -> PostgresWebShellRepository:
        """Return Web Shell ticket, lease, and Host Lock persistence."""

        return PostgresWebShellRepository(self._require_connection())

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.assert_owner()
        repository_connection = self._repository_connection
        self._closed = True
        if repository_connection is not None:
            repository_connection.finish()
        try:
            await self._contexts.__aexit__(exc_type, exc_value, traceback)
        finally:
            self._repository_connection = None
