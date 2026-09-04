from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from psycopg import DatabaseError, sql
from psycopg.conninfo import make_conninfo

from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditQuery,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.domain.ops import HostGroup
from ops_composer.services.audit import AuditService, new_audit_event
from ops_composer.uow.factory import UnitOfWorkFactory


def _database_url() -> str:
    value = os.getenv("TEST_DATABASE_URL")
    if not value:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL audit integration tests")
    return value


@pytest.mark.asyncio
async def test_postgresql_audit_atomicity_filters_cursor_immutability_and_retention() -> None:
    database_url = _database_url()
    schema = f"ops_audit_{uuid4().hex}"
    control_pool = create_pool(database_url)
    await control_pool.open()
    try:
        async with control_pool.connection() as connection:
            await connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            await connection.commit()

        isolated_url = make_conninfo(database_url, options=f"-c search_path={schema}")
        pool = create_pool(isolated_url)
        await pool.open()
        try:
            async with pool.connection() as connection:
                await MigrationRunner(connection, MIGRATIONS).up()
                await MigrationRunner(connection, MIGRATIONS).validate_current()

            factory = UnitOfWorkFactory(pool)
            service = AuditService(factory)
            actor_id = uuid4()
            run_id = uuid4()
            now = utc_now()
            sentinel = "audit-plaintext-secret-Q9v3"
            recent_events = (
                new_audit_event(
                    AuditAction.RUN_CREATED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.API,
                    actor_user_id=actor_id,
                    run_id=run_id,
                    resource_type="run",
                    resource_id=run_id,
                    metadata={"password": sentinel, "target_count": 2},
                ).model_copy(update={"occurred_at": now - timedelta(minutes=2)}),
                new_audit_event(
                    AuditAction.RUN_FAILED,
                    AuditOutcome.FAILED,
                    source=AuditSource.WORKER,
                    severity=AuditSeverity.WARNING,
                    run_id=run_id,
                    worker_id="integration-worker",
                    resource_type="run",
                    resource_id=run_id,
                    error_code="RUNNER_ERROR",
                    failure_stage="runner_execution",
                    retryable=True,
                ).model_copy(update={"occurred_at": now - timedelta(minutes=1)}),
            )
            old_events = tuple(
                new_audit_event(
                    AuditAction.AUTH_LOGIN_FAILED,
                    AuditOutcome.DENIED,
                    source=AuditSource.API,
                    severity=AuditSeverity.WARNING,
                    error_code="invalid_credentials",
                ).model_copy(update={"occurred_at": now - timedelta(days=181, seconds=index)})
                for index in range(3)
            )
            async with factory() as unit_of_work:
                for event in (*recent_events, *old_events):
                    await unit_of_work.audit.append(event)

            filtered = await service.list(
                AuditQuery(
                    since=now - timedelta(hours=1),
                    until=now + timedelta(hours=1),
                    action=AuditAction.RUN_FAILED,
                    outcome=AuditOutcome.FAILED,
                    source=AuditSource.WORKER,
                    run_id=run_id,
                    resource_type="run",
                    resource_id=str(run_id),
                    error_code="RUNNER_ERROR",
                )
            )
            assert len(filtered) == 1
            assert filtered[0].event_action is AuditAction.RUN_FAILED

            first_page = await service.list(
                AuditQuery(since=now - timedelta(hours=1), run_id=run_id, limit=1)
            )
            second_page = await service.list(
                AuditQuery(
                    since=now - timedelta(hours=1),
                    run_id=run_id,
                    before_id=first_page[-1].audit_event_id,
                    limit=1,
                )
            )
            assert first_page[0].audit_event_id != second_page[0].audit_event_id
            assert first_page[0].occurred_at > second_page[0].occurred_at

            rolled_back_group = HostGroup(
                group_id=uuid4(),
                name="audit-rollback",
                description="",
                variables={},
                created_at=now,
                updated_at=now,
            )
            rolled_back_event = new_audit_event(
                AuditAction.GROUP_CREATED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                resource_type="group",
                resource_id=rolled_back_group.group_id,
            )
            with pytest.raises(RuntimeError, match="rollback audit transaction"):
                async with factory() as unit_of_work:
                    await unit_of_work.assets.add_group(rolled_back_group)
                    await unit_of_work.audit.append(rolled_back_event)
                    raise RuntimeError("rollback audit transaction")
            async with factory() as unit_of_work:
                assert await unit_of_work.assets.get_group(rolled_back_group.group_id) is None
            assert not await service.list(
                AuditQuery(
                    since=now - timedelta(hours=1),
                    resource_type="group",
                    resource_id=str(rolled_back_group.group_id),
                )
            )

            async with pool.connection() as connection:
                with pytest.raises(DatabaseError) as immutable:
                    await connection.execute(
                        sql.SQL(
                            "UPDATE audit_events SET event_outcome = %(outcome)s "
                            "WHERE audit_event_id = %(audit_event_id)s"
                        ),
                        {
                            "outcome": AuditOutcome.NOOP.value,
                            "audit_event_id": first_page[0].audit_event_id,
                        },
                    )
                assert immutable.value.sqlstate == "55000"
                await connection.rollback()

            cutoff = now - timedelta(days=180)
            async with factory() as locked_unit:
                acquired, deleted = await locked_unit.audit.purge_batch(cutoff, 1)
                assert acquired is True
                assert deleted == 1
                competing_acquired, competing_deleted = await service.purge_before(cutoff)
                assert competing_acquired is False
                assert competing_deleted == 0

            acquired, deleted = await service.purge_before(cutoff)
            assert acquired is True
            assert deleted == 2
            assert await service.count_before(cutoff) == 0

            async with pool.connection() as connection:
                row = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT coalesce(string_agg(row_to_json(events)::text, ''), '') "
                            "AS audit_text FROM audit_events AS events"
                        )
                    )
                ).fetchone()
                assert row is not None
                assert sentinel not in row["audit_text"]
        finally:
            await pool.close()
    finally:
        async with control_pool.connection() as connection:
            await connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
            await connection.commit()
        await control_pool.close()
