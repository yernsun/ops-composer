from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ops_composer.api.dependencies import get_unit_of_work_factory
from ops_composer.api.observability import current_request_id
from ops_composer.auth.errors import AuthError
from ops_composer.domain.audit import (
    AuditAction,
    AuditEventDraft,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.errors import OpsError
from ops_composer.services.audit import AuditService, emit_audit_event, new_audit_event


def _payload(
    code: str,
    message: str,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "details": details,
        "requestId": current_request_id(),
    }


def _validation_details(error: RequestValidationError) -> dict[str, object]:
    errors: list[dict[str, Any]] = []
    for detail in error.errors():
        errors.append({key: detail[key] for key in ("type", "loc", "msg") if key in detail})
    return {"errors": errors}


def _route_path(request: Request) -> str:
    route_path = getattr(request.scope.get("route"), "path", None)
    return route_path if isinstance(route_path, str) else "<unmatched>"


async def _record_failure(
    request: Request, event: AuditEventDraft, *, already_recorded: bool
) -> None:
    if already_recorded:
        return
    try:
        factory = get_unit_of_work_factory(request)
    except (AttributeError, TypeError):
        emit_audit_event(event)
        return
    await AuditService(factory).record_best_effort(event)


def _auth_action(error: AuthError) -> AuditAction:
    return {
        "invalid_credentials": AuditAction.AUTH_LOGIN_FAILED,
        "auth_rate_limited": AuditAction.AUTH_RATE_LIMITED,
        "invalid_or_expired_session": AuditAction.AUTH_SESSION_INVALID,
        "authentication_required": AuditAction.AUTH_SESSION_INVALID,
        "origin_not_allowed": AuditAction.ORIGIN_DENIED,
        "csrf_failed": AuditAction.CSRF_DENIED,
        "admin_already_exists": AuditAction.ADMIN_BOOTSTRAP_REJECTED,
    }.get(error.code, AuditAction.REQUEST_REJECTED)


def _ops_action(error: OpsError) -> AuditAction:
    return {
        "idempotency_key_reused": AuditAction.RUN_IDEMPOTENCY_CONFLICT,
        "host_key_changed": AuditAction.HOST_KEY_CHANGED,
        "host_key_confirmation_required": AuditAction.RUN_TARGET_RESOLUTION_FAILED,
        "run_not_cancelable": AuditAction.RUN_CANCEL_REJECTED,
        "playbook_invalid": AuditAction.PLAYBOOK_VALIDATION_FAILED,
        "playbook_source_disabled": AuditAction.PLAYBOOK_SOURCE_DISABLED,
    }.get(error.code, AuditAction.REQUEST_REJECTED)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def request_validation_failed(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        details = _validation_details(error)
        validation_errors = details["errors"]
        if not isinstance(validation_errors, list):
            validation_errors = []
        safe_errors = [
            {
                "type": item.get("type"),
                "location": item.get("loc"),
            }
            for item in validation_errors
            if isinstance(item, dict)
        ]
        await _record_failure(
            request,
            new_audit_event(
                AuditAction.REQUEST_VALIDATION_FAILED,
                AuditOutcome.DENIED,
                source=AuditSource.API,
                severity=AuditSeverity.WARNING,
                error_code="request_validation_failed",
                failure_stage="request_validation",
                retryable=False,
                metadata={
                    "method": request.method,
                    "path": _route_path(request),
                    "errors": safe_errors,
                },
            ),
            already_recorded=False,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=_payload(
                "request_validation_failed",
                "request validation failed",
                details,
            ),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.exception_handler(AuthError)
    async def authentication_failed(request: Request, error: AuthError) -> JSONResponse:
        await _record_failure(
            request,
            new_audit_event(
                _auth_action(error),
                AuditOutcome.DENIED,
                source=AuditSource.API,
                severity=AuditSeverity.WARNING,
                error_code=error.code,
                failure_stage="authentication",
                retryable=error.code in {"auth_rate_limited", "invalid_or_expired_session"},
                metadata={
                    "method": request.method,
                    "path": _route_path(request),
                    **error.audit_metadata,
                },
            ),
            already_recorded=error.audit_recorded,
        )
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        if error.retry_after_seconds is not None:
            headers["Retry-After"] = str(error.retry_after_seconds)
        return JSONResponse(
            status_code=error.status_code,
            content=_payload(error.code, error.public_message),
            headers=headers,
        )

    @app.exception_handler(OpsError)
    async def operation_failed(request: Request, error: OpsError) -> JSONResponse:
        await _record_failure(
            request,
            new_audit_event(
                _ops_action(error),
                AuditOutcome.DENIED if error.status_code < 500 else AuditOutcome.FAILED,
                source=AuditSource.API,
                severity=AuditSeverity.WARNING,
                error_code=error.code,
                failure_stage="business_operation",
                retryable=error.status_code >= 500,
                metadata={
                    "method": request.method,
                    "path": _route_path(request),
                    "details": error.details or {},
                },
            ),
            already_recorded=error.audit_recorded,
        )
        return JSONResponse(
            status_code=error.status_code,
            content=_payload(error.code, error.message, error.details),
        )

    @app.exception_handler(HTTPException)
    async def http_failed(request: Request, error: HTTPException) -> JSONResponse:
        await _record_failure(
            request,
            new_audit_event(
                AuditAction.REQUEST_REJECTED,
                AuditOutcome.DENIED,
                source=AuditSource.API,
                severity=AuditSeverity.WARNING,
                error_code="http_error",
                failure_stage="http_routing",
                retryable=False,
                metadata={
                    "method": request.method,
                    "path": _route_path(request),
                    "status": error.status_code,
                },
            ),
            already_recorded=_route_path(request) == "/health/ready",
        )
        message = error.detail if isinstance(error.detail, str) else "request failed"
        return JSONResponse(
            status_code=error.status_code,
            content=_payload("http_error", message),
            headers=error.headers,
        )

    @app.exception_handler(PermissionError)
    async def permission_denied(request: Request, error: PermissionError) -> JSONResponse:
        await _record_failure(
            request,
            new_audit_event(
                AuditAction.REQUEST_REJECTED,
                AuditOutcome.DENIED,
                source=AuditSource.API,
                severity=AuditSeverity.WARNING,
                error_code="forbidden",
                failure_stage="authorization",
                retryable=False,
                metadata={"method": request.method, "path": _route_path(request)},
            ),
            already_recorded=False,
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=_payload("forbidden", str(error)),
        )
