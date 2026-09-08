from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from ops_composer.api.dependencies import UnitOfWorkFactoryDep, prevent_auth_caching
from ops_composer.api.models import StrictApiModel
from ops_composer.auth.api import CurrentSessionDep
from ops_composer.auth.models import Permission
from ops_composer.auth.service import require_permission
from ops_composer.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.services.audit import AuditService, new_audit_event

router = APIRouter(
    prefix="/api/v1/audit-events",
    tags=["audit"],
    dependencies=[Depends(prevent_auth_caching)],
)


class AuditEventResponse(StrictApiModel):
    audit_event_id: int
    occurred_at: datetime
    schema_version: int
    severity: AuditSeverity
    source: AuditSource
    service: str
    event_action: AuditAction
    event_outcome: AuditOutcome
    request_id: str | None
    correlation_id: str | None
    actor_user_id: UUID | None
    session_id: UUID | None
    run_id: UUID | None
    run_target_id: UUID | None
    worker_id: str | None
    resource_type: str | None
    resource_id: str | None
    duration_ms: float | None
    error_code: str | None
    exception_type: str | None
    failure_stage: str | None
    retryable: bool | None
    metadata: dict[str, object]

    @classmethod
    def from_domain(cls, event: AuditEvent) -> AuditEventResponse:
        return cls.model_validate(event.model_dump(mode="python"))


class AuditPageResponse(StrictApiModel):
    items: tuple[AuditEventResponse, ...]
    next_cursor: int | None


def _query(
    *,
    since: datetime | None,
    until: datetime | None,
    action: AuditAction | None,
    outcome: AuditOutcome | None,
    source: AuditSource | None,
    run_id: UUID | None,
    actor_user_id: UUID | None,
    resource_type: str | None,
    resource_id: str | None,
    error_code: str | None,
    before_id: int | None,
    limit: int,
) -> AuditQuery:
    return AuditQuery(
        since=since or utc_now() - timedelta(hours=24),
        until=until,
        action=action,
        outcome=outcome,
        source=source,
        run_id=run_id,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        error_code=error_code,
        before_id=before_id,
        limit=limit,
    )


@router.get("", operation_id="listAuditEvents")
async def list_audit_events(
    factory: UnitOfWorkFactoryDep,
    principal: CurrentSessionDep,
    since: datetime | None = None,
    until: datetime | None = None,
    action: AuditAction | None = None,
    outcome: AuditOutcome | None = None,
    source: AuditSource | None = None,
    run_id: Annotated[UUID | None, Query(alias="runId")] = None,
    actor_user_id: Annotated[UUID | None, Query(alias="actorUserId")] = None,
    resource_type: Annotated[str | None, Query(alias="resourceType", max_length=64)] = None,
    resource_id: Annotated[str | None, Query(alias="resourceId", max_length=255)] = None,
    error_code: Annotated[str | None, Query(alias="errorCode", max_length=128)] = None,
    before_id: Annotated[int | None, Query(alias="beforeId", ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> AuditPageResponse:
    require_permission(principal, Permission.AUDIT_READ)
    query = _query(
        since=since,
        until=until,
        action=action,
        outcome=outcome,
        source=source,
        run_id=run_id,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        error_code=error_code,
        before_id=before_id,
        limit=limit,
    )
    events = await AuditService(factory).list(query)
    return AuditPageResponse(
        items=tuple(AuditEventResponse.from_domain(event) for event in events),
        next_cursor=events[-1].audit_event_id if len(events) == query.limit else None,
    )


@router.get("/export", operation_id="exportAuditEvents")
async def export_audit_events(
    factory: UnitOfWorkFactoryDep,
    principal: CurrentSessionDep,
    since: datetime,
    until: datetime,
    action: AuditAction | None = None,
    outcome: AuditOutcome | None = None,
    source: AuditSource | None = None,
    run_id: Annotated[UUID | None, Query(alias="runId")] = None,
    actor_user_id: Annotated[UUID | None, Query(alias="actorUserId")] = None,
    resource_type: Annotated[str | None, Query(alias="resourceType", max_length=64)] = None,
    resource_id: Annotated[str | None, Query(alias="resourceId", max_length=255)] = None,
    error_code: Annotated[str | None, Query(alias="errorCode", max_length=128)] = None,
) -> StreamingResponse:
    require_permission(principal, Permission.AUDIT_READ)
    base_query = _query(
        since=since,
        until=until,
        action=action,
        outcome=outcome,
        source=source,
        run_id=run_id,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        error_code=error_code,
        before_id=None,
        limit=500,
    )
    service = AuditService(factory)
    await service.record_best_effort(
        new_audit_event(
            AuditAction.AUDIT_EXPORTED,
            AuditOutcome.SUCCEEDED,
            source=AuditSource.API,
            actor_user_id=principal.user_id,
            session_id=principal.session_id,
            resource_type="audit_export",
            metadata={"since": since, "until": until},
        )
    )

    async def stream() -> AsyncIterator[bytes]:
        cursor: int | None = None
        while True:
            page = await service.list(base_query.model_copy(update={"before_id": cursor}))
            for event in page:
                yield (
                    json.dumps(
                        AuditEventResponse.from_domain(event).model_dump(
                            mode="json", by_alias=True
                        ),
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
            if len(page) < base_query.limit:
                break
            cursor = page[-1].audit_event_id

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="ops-composer-audit.jsonl"',
            "X-Content-Type-Options": "nosniff",
        },
    )
