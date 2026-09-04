from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import Field, model_validator

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.auth.api import CurrentSessionDep, UnsafeSessionDep
from ops_composer.domain.ops import (
    TERMINAL_RUN_STATUSES,
    CommandMode,
    PlaybookReference,
    PlaybookSource,
    Run,
    RunEvent,
    RunTarget,
    TargetKind,
)
from ops_composer.observability import bind_log_context
from ops_composer.services.runs import RunService
from ops_composer.settings import get_settings

router = APIRouter(prefix="/api/v1", tags=["runs"])
IdempotencyKey = Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=200)]


class TargetRequest(StrictApiModel):
    kind: TargetKind
    host_ids: tuple[UUID, ...] = ()
    group_id: UUID | None = None


class CommandRunRequest(StrictApiModel):
    target: TargetRequest
    mode: CommandMode = CommandMode.COMMAND
    command: str = Field(min_length=1, max_length=4096)
    become: str = Field(default="CREDENTIAL_DEFAULT")
    shell_confirmed: bool = False
    timeout_seconds: int = Field(default=60, ge=1, le=900)
    forks: int = Field(default=5, ge=1, le=20)


class PlaybookReferenceRequest(StrictApiModel):
    source: PlaybookSource
    playbook_id: UUID | None = None
    path: str | None = Field(default=None, min_length=1, max_length=1024)

    @model_validator(mode="after")
    def require_source_identifier(self) -> PlaybookReferenceRequest:
        PlaybookReference.model_validate(self.model_dump())
        return self

    def to_domain(self) -> PlaybookReference:
        return PlaybookReference.model_validate(self.model_dump())


class PlaybookRunRequest(StrictApiModel):
    target: TargetRequest
    playbook: PlaybookReferenceRequest | None = None
    playbook_path: str | None = Field(
        default=None,
        min_length=1,
        max_length=1024,
        json_schema_extra={"deprecated": True},
    )
    extra_vars: dict[str, object] = Field(default_factory=dict)
    tags: tuple[str, ...] = ()
    skip_tags: tuple[str, ...] = ()
    timeout_seconds: int = Field(default=1800, ge=1, le=86400)
    forks: int = Field(default=5, ge=1, le=20)

    @model_validator(mode="after")
    def require_one_playbook_reference(self) -> PlaybookRunRequest:
        if (self.playbook is None) == (self.playbook_path is None):
            raise ValueError("provide exactly one of playbook or playbookPath")
        return self

    def reference(self) -> PlaybookReference:
        if self.playbook is not None:
            return self.playbook.to_domain()
        if self.playbook_path is None:
            raise ValueError("playbook reference is missing")
        return PlaybookReference(source=PlaybookSource.MOUNT, path=self.playbook_path)


class RunDetailResponse(StrictApiModel):
    run: Run
    targets: tuple[RunTarget, ...]


class OverviewResponse(StrictApiModel):
    host_count: int = Field(ge=0)
    enabled_host_count: int = Field(ge=0)
    runs_today: int = Field(ge=0)
    failed_runs: int = Field(ge=0)
    active_runs: int = Field(ge=0)


def _service(factory: UnitOfWorkFactoryDep) -> RunService:
    settings = get_settings()
    return RunService(factory, settings)


@router.get("/overview", operation_id="getOverview")
async def overview(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> OverviewResponse:
    return OverviewResponse.model_validate(await _service(factory).dashboard())


@router.get("/runs", operation_id="listRuns")
async def list_runs(
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> tuple[Run, ...]:
    return await _service(factory).list(limit=limit, offset=offset)


@router.get("/runs/{run_id}", operation_id="getRun")
async def get_run(
    run_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> RunDetailResponse:
    bind_log_context(run_id=run_id)
    run, targets = await _service(factory).detail(run_id)
    return RunDetailResponse(run=run, targets=targets)


@router.post(
    "/runs/commands",
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="createCommandRun",
)
async def create_command_run(
    request: CommandRunRequest,
    idempotency_key: IdempotencyKey,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Run:
    run = await _service(factory).create_command(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        target_kind=request.target.kind,
        host_ids=request.target.host_ids,
        group_id=request.target.group_id,
        mode=request.mode,
        command=request.command,
        become=request.become,
        shell_confirmed=request.shell_confirmed,
        timeout_seconds=request.timeout_seconds,
        forks=request.forks,
    )
    bind_log_context(run_id=run.run_id, correlation_id=str(run.run_id))
    return run


@router.post(
    "/runs/playbooks",
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="createPlaybookRun",
)
async def create_playbook_run(
    request: PlaybookRunRequest,
    idempotency_key: IdempotencyKey,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Run:
    run = await _service(factory).create_playbook(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        target_kind=request.target.kind,
        host_ids=request.target.host_ids,
        group_id=request.target.group_id,
        playbook=request.reference(),
        extra_vars=request.extra_vars,
        tags=request.tags,
        skip_tags=request.skip_tags,
        timeout_seconds=request.timeout_seconds,
        forks=request.forks,
    )
    bind_log_context(run_id=run.run_id, correlation_id=str(run.run_id))
    return run


@router.post(
    "/hosts/{host_id}/test",
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="testHost",
)
async def test_host(
    host_id: UUID,
    idempotency_key: IdempotencyKey,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Run:
    run = await _service(factory).create_ping(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        host_id=host_id,
    )
    bind_log_context(run_id=run.run_id, correlation_id=str(run.run_id))
    return run


@router.post("/runs/{run_id}/cancel", operation_id="cancelRun")
async def cancel_run(
    run_id: UUID,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Run:
    bind_log_context(run_id=run_id, correlation_id=str(run_id))
    return await _service(factory).cancel(run_id, requested_by=principal.user_id)


@router.post(
    "/runs/{run_id}/retry",
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="retryRun",
)
async def retry_run(
    run_id: UUID,
    idempotency_key: IdempotencyKey,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Run:
    bind_log_context(run_id=run_id, correlation_id=str(run_id))
    run = await _service(factory).retry(
        run_id, requested_by=principal.user_id, idempotency_key=idempotency_key
    )
    bind_log_context(run_id=run.run_id, correlation_id=str(run.run_id))
    return run


@router.get("/runs/{run_id}/events", operation_id="listRunEvents")
async def list_run_events(
    run_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
    after: int = Query(default=0, ge=0),
) -> tuple[RunEvent, ...]:
    bind_log_context(run_id=run_id)
    return await _service(factory).events_after(run_id, after)


@router.get("/runs/{run_id}/events/stream", operation_id="streamRunEvents")
async def stream_run_events(
    run_id: UUID,
    request: Request,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
    after: int = Query(default=0, ge=0),
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    bind_log_context(run_id=run_id)
    service = _service(factory)
    run = await service.get(run_id)
    cursor = after
    if last_event_id is not None:
        try:
            cursor = max(cursor, int(last_event_id))
        except ValueError:
            cursor = after

    async def generate() -> AsyncIterator[str]:
        nonlocal cursor, run
        quiet_polls = 0
        while True:
            if await request.is_disconnected():
                return
            events = await service.events_after(run_id, cursor)
            if events:
                quiet_polls = 0
                for event in events:
                    cursor = event.sequence
                    yield (
                        f"id: {event.sequence}\n"
                        "event: run-event\n"
                        f"data: {event.model_dump_json(by_alias=True)}\n\n"
                    )
            else:
                quiet_polls += 1
                if quiet_polls % 20 == 0:
                    yield ": keep-alive\n\n"
            run = await service.get(run_id)
            if run.status in TERMINAL_RUN_STATUSES and not events:
                return
            await asyncio.sleep(get_settings().sse_poll_interval_seconds)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
        },
    )
