from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ops_composer.api.observability import current_request_id
from ops_composer.auth.errors import AuthError
from ops_composer.domain.errors import OpsError

logger = logging.getLogger("app.errors")


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


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def request_validation_failed(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        logger.warning(
            "request validation failed",
            extra={
                "event": "request_validation_failed",
                "request_id": current_request_id(),
                "method": request.method,
                "path": request.url.path,
                "validation_errors": _validation_details(error)["errors"],
            },
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=_payload(
                "request_validation_failed",
                "request validation failed",
                _validation_details(error),
            ),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.exception_handler(AuthError)
    async def authentication_failed(_: Request, error: AuthError) -> JSONResponse:
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        if error.retry_after_seconds is not None:
            headers["Retry-After"] = str(error.retry_after_seconds)
        return JSONResponse(
            status_code=error.status_code,
            content=_payload(error.code, error.public_message),
            headers=headers,
        )

    @app.exception_handler(OpsError)
    async def operation_failed(_: Request, error: OpsError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content=_payload(error.code, error.message, error.details),
        )

    @app.exception_handler(HTTPException)
    async def http_failed(_: Request, error: HTTPException) -> JSONResponse:
        message = error.detail if isinstance(error.detail, str) else "request failed"
        return JSONResponse(
            status_code=error.status_code,
            content=_payload("http_error", message),
            headers=error.headers,
        )

    @app.exception_handler(PermissionError)
    async def permission_denied(_: Request, error: PermissionError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=_payload("forbidden", str(error)),
        )
