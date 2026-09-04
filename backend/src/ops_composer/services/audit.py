from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime, timedelta
from uuid import UUID

from ops_composer.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditEventDraft,
    AuditOutcome,
    AuditQuery,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.observability import (
    current_log_context,
    log_event,
    safe_exception_fields,
    sanitize_metadata,
)
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.uow.unit import UnitOfWork

AUDIT_PURGE_BATCH_SIZE = 5_000
AUDIT_WRITE_TIMEOUT_SECONDS = 2.0


def _context_uuid(context: Mapping[str, object], name: str) -> UUID | None:
    value = context.get(name)
    if value is None:
        return None
    return value if isinstance(value, UUID) else UUID(str(value))


def new_audit_event(
    action: AuditAction,
    outcome: AuditOutcome,
    *,
    source: AuditSource,
    severity: AuditSeverity = AuditSeverity.INFO,
    actor_user_id: UUID | None = None,
    session_id: UUID | None = None,
    run_id: UUID | None = None,
    run_target_id: UUID | None = None,
    worker_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | UUID | int | None = None,
    duration_ms: float | None = None,
    error_code: str | None = None,
    exception_type: str | None = None,
    failure_stage: str | None = None,
    retryable: bool | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AuditEventDraft:
    context = current_log_context()
    service = {
        AuditSource.API: "api",
        AuditSource.WORKER: "worker",
        AuditSource.CLI: "cli",
        AuditSource.SYSTEM: "system",
    }[source]
    return AuditEventDraft(
        occurred_at=utc_now(),
        severity=severity,
        source=source,
        service=service,
        event_action=action,
        event_outcome=outcome,
        request_id=(str(context["request_id"]) if "request_id" in context else None),
        correlation_id=(
            str(context["correlation_id"]) if "correlation_id" in context else None
        ),
        actor_user_id=actor_user_id or _context_uuid(context, "actor_user_id"),
        session_id=session_id or _context_uuid(context, "session_id"),
        run_id=run_id or _context_uuid(context, "run_id"),
        run_target_id=run_target_id or _context_uuid(context, "run_target_id"),
        worker_id=worker_id or (
            str(context["worker_id"]) if "worker_id" in context else None
        ),
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        duration_ms=duration_ms,
        error_code=error_code,
        exception_type=exception_type,
        failure_stage=failure_stage,
        retryable=retryable,
        metadata=sanitize_metadata(metadata),
    )


def emit_audit_event(event: AuditEventDraft, *, exc_info: bool = False) -> None:
    log_event(
        event.event_action,
        event.event_outcome,
        source=event.source,
        severity=event.severity,
        metadata=event.metadata,
        request_id=event.request_id,
        correlation_id=event.correlation_id,
        actor_user_id=event.actor_user_id,
        session_id=event.session_id,
        run_id=event.run_id,
        run_target_id=event.run_target_id,
        worker_id=event.worker_id,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        duration_ms=event.duration_ms,
        error_code=event.error_code,
        exception_type=event.exception_type,
        failure_stage=event.failure_stage,
        retryable=event.retryable,
        exc_info=exc_info,
    )


class AuditService:
    def __init__(self, unit_of_work_factory: UnitOfWorkFactory) -> None:
        self._unit_of_work_factory = unit_of_work_factory

    @staticmethod
    async def append_in_transaction(
        unit_of_work: UnitOfWork, event: AuditEventDraft
    ) -> AuditEvent:
        return await unit_of_work.audit.append(event)

    async def record(self, event: AuditEventDraft) -> AuditEvent:
        async with self._unit_of_work_factory() as unit_of_work:
            persisted = await unit_of_work.audit.append(event)
        emit_audit_event(persisted)
        return persisted

    async def record_best_effort(self, event: AuditEventDraft) -> AuditEvent | None:
        try:
            async with asyncio.timeout(AUDIT_WRITE_TIMEOUT_SECONDS):
                async with self._unit_of_work_factory() as unit_of_work:
                    persisted = await unit_of_work.audit.append(event)
        except Exception as error:
            emit_audit_event(event)
            details = safe_exception_fields(error)
            log_event(
                AuditAction.AUDIT_PERSIST_FAILED,
                AuditOutcome.FAILED,
                source=event.source,
                severity=AuditSeverity.ERROR,
                message="audit event persistence failed",
                error_code="audit_persist_failed",
                failure_stage="audit_insert",
                retryable=True,
                metadata={
                    **details,
                    "original_action": event.event_action.value,
                },
                exception_type=type(error).__name__,
            )
            return None
        emit_audit_event(persisted)
        return persisted

    async def list(self, query: AuditQuery) -> tuple[AuditEvent, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.audit.list_events(query)

    async def count_before(self, cutoff: datetime) -> int:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.audit.count_before(cutoff)

    async def count_expired(self, retention_days: int) -> int:
        return await self.count_before(utc_now() - timedelta(days=retention_days))

    async def purge_batch(
        self,
        retention_days: int,
        *,
        batch_size: int = AUDIT_PURGE_BATCH_SIZE,
    ) -> tuple[bool, int]:
        cutoff = utc_now() - timedelta(days=retention_days)
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.audit.purge_batch(cutoff, batch_size)

    async def purge_before(
        self,
        cutoff: datetime,
        *,
        batch_size: int = AUDIT_PURGE_BATCH_SIZE,
    ) -> tuple[bool, int]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.audit.purge_batch(cutoff, batch_size)
