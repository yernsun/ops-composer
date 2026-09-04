from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from ops_composer.api.errors import install_error_handlers
from ops_composer.api.observability import RequestContextMiddleware
from ops_composer.auth.errors import AuthRateLimitedError, InvalidCredentialsError
from ops_composer.domain.errors import HostKeyChangedError, NotFoundError


@pytest.mark.asyncio
async def test_error_handlers_return_stable_envelopes_for_all_error_families() -> None:
    application = FastAPI()
    install_error_handlers(application)
    application.add_middleware(RequestContextMiddleware)

    @application.get("/invalid-login")
    async def invalid_login() -> None:
        raise InvalidCredentialsError()

    @application.get("/limited")
    async def limited() -> None:
        raise AuthRateLimitedError(retry_after_seconds=17)

    @application.get("/changed")
    async def changed() -> None:
        raise HostKeyChangedError()

    @application.get("/missing")
    async def missing() -> None:
        raise NotFoundError(details={"resource": "host"})

    @application.get("/teapot")
    async def teapot() -> None:
        raise HTTPException(status_code=418, detail={"unsafe": "detail"})

    @application.get("/unhandled")
    async def unhandled() -> None:
        raise RuntimeError("password=must-not-be-returned")

    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        invalid = await client.get("/invalid-login", headers={"X-Request-ID": "auth-1"})
        rate_limited = await client.get("/limited")
        changed_response = await client.get("/changed")
        missing_response = await client.get("/missing")
        teapot_response = await client.get("/teapot")
        unhandled_response = await client.get("/unhandled")

    assert invalid.status_code == 401
    assert invalid.json() == {
        "code": "invalid_credentials",
        "message": "invalid credentials",
        "details": None,
        "requestId": "auth-1",
    }
    assert rate_limited.status_code == 429
    assert rate_limited.headers["Retry-After"] == "17"
    assert changed_response.status_code == 409
    assert changed_response.json()["code"] == "host_key_changed"
    assert missing_response.status_code == 404
    assert missing_response.json()["details"] == {"resource": "host"}
    assert teapot_response.status_code == 418
    assert teapot_response.json()["message"] == "request failed"
    assert unhandled_response.status_code == 500
    assert "must-not-be-returned" not in unhandled_response.text


@pytest.mark.asyncio
async def test_request_context_replaces_invalid_and_duplicate_ids() -> None:
    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)

    @application.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        invalid = await client.get("/ok", headers={"X-Request-ID": "contains spaces"})
        duplicate = await client.get(
            "/ok",
            headers=[("X-Request-ID", "first"), ("X-Request-ID", "second")],
        )

    for response in (invalid, duplicate):
        generated = response.headers["X-Request-ID"]
        assert generated not in {"contains spaces", "first", "second"}
        assert len(generated) == 32
