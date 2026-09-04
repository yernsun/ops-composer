from __future__ import annotations

from datetime import datetime
from typing import Protocol

from psycopg import sql
from psycopg.types.json import Jsonb

from ops_composer.db.query import SqlPredicateBuilder
from ops_composer.domain.audit import AuditEvent, AuditEventDraft, AuditQuery
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow

AUDIT_CLEANUP_LOCK_KEY = 718_340_240
AUDIT_COLUMNS = sql.SQL(
    "audit_event_id, occurred_at, schema_version, severity, source, service, "
    "event_action, event_outcome, request_id, correlation_id, actor_user_id, session_id, "
    "run_id, run_target_id, worker_id, resource_type, resource_id, duration_ms, "
    "error_code, exception_type, failure_stage, retryable, metadata"
)


def _audit_event(row: RepositoryRow) -> AuditEvent:
    return AuditEvent.model_validate(row)


class AuditRepository(BaseRepository, Protocol):
    async def append(self, event: AuditEventDraft) -> AuditEvent: ...
    async def list_events(self, query: AuditQuery) -> tuple[AuditEvent, ...]: ...
    async def count_before(self, cutoff: datetime) -> int: ...
    async def purge_batch(self, cutoff: datetime, batch_size: int) -> tuple[bool, int]: ...


class PostgresAuditRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    async def append(self, event: AuditEventDraft) -> AuditEvent:
        values = event.model_dump(mode="python")
        values["metadata"] = Jsonb(values["metadata"])
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO audit_events (occurred_at, schema_version, severity, source, "
                "service, event_action, event_outcome, request_id, correlation_id, "
                "actor_user_id, session_id, run_id, run_target_id, worker_id, resource_type, "
                "resource_id, duration_ms, error_code, exception_type, failure_stage, "
                "retryable, metadata) VALUES (%(occurred_at)s, %(schema_version)s, "
                "%(severity)s, %(source)s, %(service)s, %(event_action)s, %(event_outcome)s, "
                "%(request_id)s, %(correlation_id)s, %(actor_user_id)s, %(session_id)s, "
                "%(run_id)s, %(run_target_id)s, %(worker_id)s, %(resource_type)s, "
                "%(resource_id)s, %(duration_ms)s, %(error_code)s, %(exception_type)s, "
                "%(failure_stage)s, %(retryable)s, %(metadata)s) RETURNING {}"
            ).format(AUDIT_COLUMNS),
            values,
            prepare=True,
        )
        if row is None:
            raise RuntimeError("audit event insert returned no row")
        return _audit_event(row)

    async def list_events(self, query: AuditQuery) -> tuple[AuditEvent, ...]:
        filters = SqlPredicateBuilder()
        filters.add_greater_than_or_equal(
            sql.Identifier("occurred_at"), "audit_since", query.since
        )
        if query.until is not None:
            filters.add(
                sql.SQL("occurred_at < %(audit_until)s"),
                {"audit_until": query.until},
            )
        if query.action is not None:
            filters.add_equals(
                sql.Identifier("event_action"), "audit_action", query.action.value
            )
        if query.outcome is not None:
            filters.add_equals(
                sql.Identifier("event_outcome"), "audit_outcome", query.outcome.value
            )
        if query.source is not None:
            filters.add_equals(sql.Identifier("source"), "audit_source", query.source.value)
        if query.run_id is not None:
            filters.add_equals(sql.Identifier("run_id"), "audit_run_id", query.run_id)
        if query.actor_user_id is not None:
            filters.add_equals(
                sql.Identifier("actor_user_id"),
                "audit_actor_user_id",
                query.actor_user_id,
            )
        if query.resource_type is not None:
            filters.add_equals(
                sql.Identifier("resource_type"),
                "audit_resource_type",
                query.resource_type,
            )
        if query.resource_id is not None:
            filters.add_equals(
                sql.Identifier("resource_id"), "audit_resource_id", query.resource_id
            )
        if query.error_code is not None:
            filters.add_equals(
                sql.Identifier("error_code"), "audit_error_code", query.error_code
            )
        if query.before_id is not None:
            filters.add(
                sql.SQL(
                    "(occurred_at, audit_event_id) < (SELECT occurred_at, audit_event_id "
                    "FROM audit_events WHERE audit_event_id = %(audit_before_id)s)"
                ),
                {"audit_before_id": query.before_id},
            )
        predicate, parameters = filters.build()
        parameters["audit_limit"] = query.limit
        rows = await self.connection.fetch_all(
            sql.SQL("SELECT {} FROM audit_events WHERE ").format(AUDIT_COLUMNS)
            + predicate
            + sql.SQL(" ORDER BY occurred_at DESC, audit_event_id DESC LIMIT %(audit_limit)s"),
            parameters,
            prepare=False,
        )
        return tuple(_audit_event(row) for row in rows)

    async def count_before(self, cutoff: datetime) -> int:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT count(*) AS count FROM audit_events "
                "WHERE occurred_at < %(audit_cutoff)s"
            ),
            {"audit_cutoff": cutoff},
            prepare=True,
        )
        if row is None:
            raise RuntimeError("audit retention count returned no row")
        return int(row["count"])

    async def purge_batch(self, cutoff: datetime, batch_size: int) -> tuple[bool, int]:
        lock_row = await self.connection.fetch_one(
            sql.SQL("SELECT pg_try_advisory_xact_lock(%(audit_lock_key)s) AS acquired"),
            {"audit_lock_key": AUDIT_CLEANUP_LOCK_KEY},
            prepare=True,
        )
        if lock_row is None or not bool(lock_row["acquired"]):
            return False, 0
        rows = await self.connection.fetch_all(
            sql.SQL(
                "WITH expired AS (SELECT audit_event_id FROM audit_events "
                "WHERE occurred_at < %(audit_cutoff)s ORDER BY occurred_at, audit_event_id "
                "FOR UPDATE SKIP LOCKED LIMIT %(audit_batch_size)s) "
                "DELETE FROM audit_events AS events USING expired "
                "WHERE events.audit_event_id = expired.audit_event_id "
                "RETURNING events.audit_event_id"
            ),
            {"audit_cutoff": cutoff, "audit_batch_size": batch_size},
            prepare=True,
        )
        return True, len(rows)
