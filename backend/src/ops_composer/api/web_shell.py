from __future__ import annotations

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, WebSocket, status
from pydantic import AwareDatetime

from ops_composer.api.models import StrictApiModel
from ops_composer.auth.api import UnsafeSessionDep
from ops_composer.auth.errors import AuthError
from ops_composer.auth.service import AuthService
from ops_composer.domain.audit import AuditAction, AuditOutcome, AuditSeverity, AuditSource
from ops_composer.services.audit import AuditService, new_audit_event
from ops_composer.settings import get_settings
from ops_composer.web_shell_manager import WebShellManager

router = APIRouter(prefix="/api/v1", tags=["web-shell"])


class WebShellSessionResponse(StrictApiModel):
    web_shell_session_id: UUID
    host_id: UUID
    host_name: str
    address: str
    ssh_port: int
    username: str
    stream_path: str
    ticket_expires_at: AwareDatetime
    idle_timeout_seconds: int
    max_duration_seconds: int


def get_web_shell_manager(request: Request) -> WebShellManager:
    return cast(WebShellManager, request.app.state.web_shell_manager)


WebShellManagerDep = Annotated[WebShellManager, Depends(get_web_shell_manager)]


@router.post(
    "/hosts/{host_id}/web-shell-sessions",
    response_model=WebShellSessionResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="createWebShellSession",
)
async def create_web_shell_session(
    host_id: UUID,
    response: Response,
    manager: WebShellManagerDep,
    principal: UnsafeSessionDep,
) -> WebShellSessionResponse:
    session = await manager.create(host_id, principal)
    settings = get_settings()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return WebShellSessionResponse(
        web_shell_session_id=session.web_shell_session_id,
        host_id=session.host_id,
        host_name=session.host_name,
        address=session.host_address,
        ssh_port=session.ssh_port,
        username=session.username,
        stream_path=(
            f"/api/v1/web-shell-sessions/{session.web_shell_session_id}/stream"
        ),
        ticket_expires_at=session.ticket_expires_at,
        idle_timeout_seconds=settings.web_shell_idle_timeout_seconds,
        max_duration_seconds=settings.web_shell_max_duration_seconds,
    )


@router.delete(
    "/web-shell-sessions/{web_shell_session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="closeWebShellSession",
)
async def close_web_shell_session(
    web_shell_session_id: UUID,
    manager: WebShellManagerDep,
    principal: UnsafeSessionDep,
) -> Response:
    await manager.request_close(web_shell_session_id, principal)
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _deny_websocket(
    websocket: WebSocket,
    *,
    code: int,
    error_code: str,
    actor_user_id: UUID | None = None,
    auth_session_id: UUID | None = None,
    web_shell_session_id: UUID,
) -> None:
    factory = getattr(websocket.app.state, "unit_of_work_factory", None)
    if factory is not None:
        await AuditService(factory).record_best_effort(
            new_audit_event(
                AuditAction.WEB_SHELL_DENIED,
                AuditOutcome.DENIED,
                source=AuditSource.API,
                severity=AuditSeverity.WARNING,
                actor_user_id=actor_user_id,
                session_id=auth_session_id,
                resource_type="web_shell_session",
                resource_id=web_shell_session_id,
                error_code=error_code,
                failure_stage="websocket_handshake",
                retryable=False,
            )
        )
    await websocket.close(code=code)


@router.websocket("/web-shell-sessions/{web_shell_session_id}/stream")
async def stream_web_shell(
    websocket: WebSocket,
    web_shell_session_id: UUID,
) -> None:
    settings = get_settings()
    origin = websocket.headers.get("origin", "").rstrip("/")
    if origin not in settings.allowed_origins:
        await _deny_websocket(
            websocket,
            code=4403,
            error_code="origin_not_allowed",
            web_shell_session_id=web_shell_session_id,
        )
        return
    session_token = websocket.cookies.get(settings.session_cookie_name)
    if not session_token:
        await _deny_websocket(
            websocket,
            code=4401,
            error_code="authentication_required",
            web_shell_session_id=web_shell_session_id,
        )
        return
    factory = websocket.app.state.unit_of_work_factory
    try:
        principal = await AuthService(factory, settings).resolve(session_token)
    except AuthError as error:
        await _deny_websocket(
            websocket,
            code=4401,
            error_code=error.code,
            web_shell_session_id=web_shell_session_id,
        )
        return
    manager = cast(WebShellManager, websocket.app.state.web_shell_manager)
    await manager.stream(websocket, web_shell_session_id, principal)
