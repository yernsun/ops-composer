from __future__ import annotations

import time
from uuid import uuid4

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ops_composer.domain.audit import AuditAction, AuditOutcome, AuditSeverity, AuditSource
from ops_composer.observability import (
    JsonLogFormatter,
    allow_rate_limited_event,
    bind_log_context,
    configure_logging,
    current_request_id,
    log_context,
    log_event,
    valid_request_id,
)
from ops_composer.services.audit import AuditService, emit_audit_event, new_audit_event

__all__ = (
    "JsonLogFormatter",
    "RequestContextMiddleware",
    "bind_log_context",
    "configure_logging",
    "current_request_id",
)


def _request_id(headers: list[tuple[bytes, bytes]]) -> str:
    values = [value for name, value in headers if name.lower() == b"x-request-id"]
    if len(values) != 1:
        return uuid4().hex
    try:
        candidate = values[0].decode("ascii")
    except UnicodeDecodeError:
        return uuid4().hex
    return candidate if valid_request_id(candidate) else uuid4().hex


class RequestContextMiddleware:
    """Attach safe correlation context and emit body-free structured access logs."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = _request_id(scope.get("headers", []))
        started = time.perf_counter()
        status_code = 500

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers = [item for item in headers if item[0].lower() != b"x-request-id"]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        with log_context(
            request_id=request_id,
            correlation_id=request_id,
            actor_user_id=None,
            session_id=None,
            run_id=None,
            run_target_id=None,
            worker_id=None,
        ):
            try:
                await self._app(scope, receive, send_with_request_id)
            except Exception as error:
                event = new_audit_event(
                    AuditAction.UNHANDLED_EXCEPTION,
                    AuditOutcome.FAILED,
                    source=AuditSource.API,
                    severity=AuditSeverity.ERROR,
                    failure_stage="request_dispatch",
                    exception_type=type(error).__name__,
                    retryable=False,
                )
                application = scope.get("app")
                factory = getattr(
                    getattr(application, "state", None),
                    "unit_of_work_factory",
                    None,
                )
                if factory is not None:
                    await AuditService(factory).record_best_effort(event)
                else:
                    emit_audit_event(event, exc_info=True)
                raise
            finally:
                duration_ms = round((time.perf_counter() - started) * 1000, 3)
                route = scope.get("route")
                route_path = getattr(route, "path", None)
                path = route_path if isinstance(route_path, str) else "<unmatched>"
                severity = (
                    AuditSeverity.DEBUG
                    if status_code < 400 and path in {"/health/live", "/health/ready"}
                    else AuditSeverity.WARNING
                    if status_code >= 400
                    else AuditSeverity.INFO
                )
                if not (
                    path == "/health/ready"
                    and status_code >= 500
                    and not allow_rate_limited_event("health-ready-failed")
                ):
                    log_event(
                        AuditAction.REQUEST_COMPLETED,
                        AuditOutcome.SUCCEEDED if status_code < 400 else AuditOutcome.FAILED,
                        source=AuditSource.API,
                        severity=severity,
                        message="request completed",
                        method=scope.get("method"),
                        path=path,
                        status=status_code,
                        duration_ms=duration_ms,
                    )
