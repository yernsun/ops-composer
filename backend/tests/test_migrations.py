from __future__ import annotations

from datetime import UTC, datetime
from types import TracebackType
from typing import cast
from unittest.mock import AsyncMock

import pytest

from ops_composer.db.migration_engine import (
    Migration,
    MigrationError,
    MigrationRunner,
    ordered_migrations,
)
from ops_composer.db.migrations.auth import AUTH
from ops_composer.db.migrations.auth_security import AUTH_SECURITY
from ops_composer.db.migrations.core import CORE
from ops_composer.db.migrations.ops_composer import OPS_COMPOSER
from ops_composer.db.types import DbConnection
from ops_composer.repositories.base import RepositoryConnection
from ops_composer.repositories.health import PostgresHealthRepository


def migration(migration_id: str, dependencies: tuple[str, ...] = ()) -> Migration:
    return Migration(migration_id=migration_id, dependencies=dependencies, up_sql="SELECT 1;")


def test_migration_dag_is_topologically_sorted() -> None:
    result = ordered_migrations((migration("b", ("a",)), migration("a")))
    assert [entry.migration_id for entry in result] == ["a", "b"]


def test_migration_dag_rejects_cycles() -> None:
    with pytest.raises(MigrationError, match="cycle"):
        ordered_migrations((migration("a", ("b",)), migration("b", ("a",))))


def test_migration_dag_rejects_duplicates_and_missing_dependencies() -> None:
    with pytest.raises(MigrationError, match="duplicate migration ID"):
        ordered_migrations((migration("a"), migration("a")))
    with pytest.raises(MigrationError, match="missing dependencies"):
        ordered_migrations((migration("a", ("missing",)),))


def test_checksum_covers_dependencies_and_sql() -> None:
    assert migration("a").checksum != migration("b").checksum
    assert migration("a").checksum != Migration("a", (), "SELECT 2;").checksum


@pytest.mark.asyncio
async def test_current_validation_rejects_pending_but_history_validation_allows_it() -> None:
    applied = migration("a")
    pending = migration("b", ("a",))
    runner = MigrationRunner(cast(DbConnection, object()), (applied, pending))
    runner._tracking_exists = AsyncMock(return_value=True)  # type: ignore[method-assign]
    runner._applied = AsyncMock(  # type: ignore[method-assign]
        return_value={"a": (applied.checksum, datetime.now(UTC))}
    )

    await runner.validate_history()
    with pytest.raises(MigrationError, match=r"pending migrations.*b"):
        await runner.validate_current()
    with pytest.raises(MigrationError, match=r"pending migrations.*b"):
        await runner.validate()


class _MigrationCursor:
    def __init__(self) -> None:
        self.fetchone_result: dict[str, object] | None = None
        self.fetchall_result: list[dict[str, object]] = []
        self.executed: list[tuple[object, object | None]] = []

    async def __aenter__(self) -> _MigrationCursor:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def execute(self, query: object, parameters: object | None = None) -> None:
        self.executed.append((query, parameters))

    async def fetchone(self) -> dict[str, object] | None:
        return self.fetchone_result

    async def fetchall(self) -> list[dict[str, object]]:
        return self.fetchall_result


class _MigrationTransaction:
    def __init__(self) -> None:
        self.entered = False
        self.exited = False

    async def __aenter__(self) -> _MigrationTransaction:
        self.entered = True
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.exited = True


class _MigrationConnection:
    def __init__(self) -> None:
        self.cursor_value = _MigrationCursor()
        self.transaction_value = _MigrationTransaction()

    def cursor(self) -> _MigrationCursor:
        return self.cursor_value

    def transaction(self) -> _MigrationTransaction:
        return self.transaction_value


@pytest.mark.asyncio
async def test_migration_runner_reads_history_status_and_applies_pending_rows() -> None:
    first = migration("a")
    second = migration("b", ("a",))
    connection = _MigrationConnection()
    runner = MigrationRunner(cast(DbConnection, connection), (first, second))

    connection.cursor_value.fetchone_result = None
    assert not await runner._tracking_exists()
    connection.cursor_value.fetchone_result = {"table_name": "schema_migrations"}
    assert await runner._tracking_exists()
    applied_at = datetime.now(UTC)
    connection.cursor_value.fetchall_result = [
        {"migration_id": "a", "checksum": first.checksum, "applied_at": applied_at}
    ]
    assert await runner._applied() == {"a": (first.checksum, applied_at)}
    runner._applied = AsyncMock(  # type: ignore[method-assign]
        return_value={"a": (first.checksum, applied_at)}
    )
    statuses = await runner.status()
    assert [status.state for status in statuses] == [
        "applied",
        "pending",
    ]

    runner.validate_history = AsyncMock()  # type: ignore[method-assign]
    runner._applied = AsyncMock(return_value={})  # type: ignore[method-assign]
    executed_before_up = len(connection.cursor_value.executed)
    assert await runner.up() == ("a", "b")
    assert connection.transaction_value.entered
    assert connection.transaction_value.exited
    assert len(connection.cursor_value.executed) - executed_before_up == 6


@pytest.mark.asyncio
async def test_migration_history_rejects_uninitialized_unknown_and_modified_rows() -> None:
    known = migration("known")
    runner = MigrationRunner(cast(DbConnection, object()), (known,))
    runner._tracking_exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
    with pytest.raises(MigrationError, match="not initialized"):
        await runner.validate_history()

    runner._tracking_exists = AsyncMock(return_value=True)  # type: ignore[method-assign]
    runner._applied = AsyncMock(  # type: ignore[method-assign]
        return_value={"unknown": ("checksum", datetime.now(UTC))}
    )
    with pytest.raises(MigrationError, match="unknown migrations"):
        await runner.validate_history()

    runner._applied = AsyncMock(  # type: ignore[method-assign]
        return_value={"known": ("modified", datetime.now(UTC))}
    )
    with pytest.raises(MigrationError, match="checksum mismatch"):
        await runner.validate_history()


@pytest.mark.asyncio
async def test_readiness_repository_requires_exact_current_checksums() -> None:
    connection = AsyncMock()
    connection.fetch_one.return_value = {"table_name": "schema_migrations"}
    connection.fetch_all.return_value = [{"migration_id": "0001_core", "checksum": "old-checksum"}]
    repository = PostgresHealthRepository(
        cast(RepositoryConnection, connection),
        expected_migrations={"0001_core": "current-checksum"},
    )

    assert await repository.is_ready() is False
    connection.fetch_all.return_value = [
        {"migration_id": "0001_core", "checksum": "current-checksum"}
    ]
    assert await repository.is_ready() is True


def test_ops_composer_schema_is_forward_only_and_postgresql_native() -> None:
    result = ordered_migrations((OPS_COMPOSER, AUTH_SECURITY, AUTH, CORE))
    assert [entry.migration_id for entry in result] == [
        "0001_core",
        "0020_auth",
        "0021_auth_security",
        "0030_ops_composer",
    ]
    schema_sql = OPS_COMPOSER.up_sql.lower()
    assert "jsonb" in schema_sql
    assert "timestamptz" in schema_sql
    assert "bytea" in schema_sql
    assert "credential_type in ('password')" in schema_sql
    assert "sqlite" not in schema_sql
