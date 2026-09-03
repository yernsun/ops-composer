from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest
from argon2 import PasswordHasher
from argon2.low_level import Type
from fastapi import FastAPI, Response
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.requests import Request

import ops_composer.auth.api as auth_api
from ops_composer.api.errors import install_error_handlers
from ops_composer.api.observability import RequestContextMiddleware
from ops_composer.auth.api import LoginRequest, _set_session_cookies, get_unsafe_session
from ops_composer.auth.errors import (
    AuthenticationRequiredError,
    AuthRateLimitedError,
    CsrfValidationError,
    OriginNotAllowedError,
)
from ops_composer.auth.models import IssuedSession, SessionPrincipal
from ops_composer.auth.security import (
    generate_token,
    hash_password,
    hash_token,
    hmac_subject,
    token_matches,
    verify_password,
)
from ops_composer.auth.service import AuthService, RateLimitSpec, canonical_username, fixed_window
from ops_composer.domain.base import utc_now
from ops_composer.main import app as fastapi_app
from ops_composer.settings import (
    COOKIE_PREFIX,
    DEVELOPMENT_RATE_LIMIT_SECRET,
    Settings,
    get_settings,
)
from ops_composer.uow.factory import UnitOfWorkFactory


def test_opaque_tokens_are_hashed_and_constant_time_checked() -> None:
    token = generate_token()
    digest = hash_token(token)
    assert token not in digest
    assert token_matches(token, digest)
    assert not token_matches(token + "x", digest)


def test_argon2id_password_round_trip_and_dummy_path() -> None:
    digest = hash_password("correct horse battery staple")
    assert digest.startswith("$argon2id$")
    assert verify_password(digest, "correct horse battery staple").valid
    assert not verify_password(digest, "wrong password").valid
    assert not verify_password(None, "wrong password").valid

    legacy = PasswordHasher(
        time_cost=1,
        memory_cost=8 * 1024,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    ).hash("correct horse battery staple")
    assert verify_password(legacy, "correct horse battery staple").needs_rehash


def test_login_request_normalizes_username_but_preserves_password() -> None:
    request = LoginRequest.model_validate(
        {"username": "  ADMIN  ", "password": "  long password  "}
    )
    assert request.username == "ADMIN"
    assert request.password.get_secret_value() == "  long password  "
    assert "long password" not in repr(request)
    assert canonical_username(request.username) == "admin"

    with pytest.raises(ValidationError):
        LoginRequest.model_validate({"username": "   ", "password": "password"})
    with pytest.raises(ValidationError):
        LoginRequest.model_validate({"username": "admin", "password": "password", "isAdmin": True})


def test_rate_limit_subjects_are_hmaced_and_fixed_windows_are_stable() -> None:
    first = hmac_subject("a" * 32, "login:username", "admin")
    second = hmac_subject("a" * 32, "login:client", "admin")
    assert len(first) == 64
    assert "admin" not in first
    assert first != second

    now = datetime(2026, 9, 3, 12, 4, 59, tzinfo=UTC)
    start, end = fixed_window(now, 300)
    assert start == datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    assert end == datetime(2026, 9, 3, 12, 5, tzinfo=UTC)


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "production",
        "database_url": "postgresql://safe:secret@db/app",
        "allowed_origins_csv": "https://app.example.com",
        "session_cookie_secure": True,
        "auth_rate_limit_secret": "x" * 32,
        "master_key": base64.b64encode(b"production-master-key-material!!").decode(),
        "forwarded_allow_ips_csv": "172.20.0.20",
    }
    values.update(overrides)
    return Settings(**values)


def test_production_configuration_fails_closed() -> None:
    with pytest.raises(ValidationError, match="secure session cookies"):
        _production_settings(session_cookie_secure=False)
    with pytest.raises(ValidationError, match="unique 32-byte"):
        _production_settings(auth_rate_limit_secret=DEVELOPMENT_RATE_LIMIT_SECRET)
    with pytest.raises(ValidationError, match="OPS_COMPOSER_MASTER_KEY"):
        _production_settings(master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    with pytest.raises(ValidationError, match="trusted proxy"):
        _production_settings(forwarded_allow_ips_csv="")
    with pytest.raises(ValidationError, match="without credentials or paths"):
        _production_settings(allowed_origins_csv="https://app.example.com/login")


@pytest.mark.parametrize("value", ["*", "0.0.0.0/0", "::/0", "not-an-ip", "172.20.0.1/24"])
def test_production_requires_explicit_valid_trusted_proxies(value: str) -> None:
    with pytest.raises(ValidationError, match=r"trusted proxy|FORWARDED_ALLOW_IPS"):
        _production_settings(forwarded_allow_ips_csv=value)


def test_production_uses_host_only_secure_session_cookies() -> None:
    settings = _production_settings(allowed_origins_csv="https://app.example.com/")
    assert settings.session_cookie_name == f"__Host-{COOKIE_PREFIX}-session"
    assert settings.csrf_cookie_name == f"__Host-{COOKIE_PREFIX}-csrf"
    assert settings.allowed_origins == frozenset({"https://app.example.com"})

    now = utc_now()
    issued = IssuedSession(
        principal=SessionPrincipal(
            session_id=uuid4(),
            user_id=uuid4(),
            username="admin",
            csrf_hash=hash_token("csrf-token"),
            expires_at=now + timedelta(days=1),
        ),
        session_token=generate_token(),
        csrf_token=generate_token(),
    )
    response = Response()
    _set_session_cookies(response, issued, settings)

    cookies = response.headers.getlist("set-cookie")
    assert len(cookies) == 2
    session_cookie = next(value for value in cookies if settings.session_cookie_name in value)
    csrf_cookie = next(value for value in cookies if settings.csrf_cookie_name in value)
    for value in cookies:
        assert "Secure" in value
        assert "SameSite=strict" in value
        assert "Path=/" in value
        assert "Domain=" not in value
    assert "HttpOnly" in session_cookie
    assert "HttpOnly" not in csrf_cookie


def _dependency_names(route: APIRoute) -> set[str]:
    names: set[str] = set()

    def collect(dependant: object) -> None:
        for dependency in getattr(dependant, "dependencies", ()):
            name = getattr(getattr(dependency, "call", None), "__name__", None)
            if isinstance(name, str):
                names.add(name)
            collect(dependency)

    collect(route.dependant)
    return names


def _api_routes() -> list[APIRoute]:
    routes: list[APIRoute] = []
    for included in fastapi_app.routes:
        if isinstance(included, APIRoute):
            routes.append(included)
        original_router = getattr(included, "original_router", None)
        routes.extend(
            route for route in getattr(original_router, "routes", ()) if isinstance(route, APIRoute)
        )
    return routes


def test_unsafe_routes_share_origin_csrf_and_no_store_dependencies() -> None:
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}
    routes = _api_routes()
    unsafe_routes = [route for route in routes if route.methods & unsafe_methods]
    assert unsafe_routes
    read_only_posts = {
        "/api/v1/inventory/validate",
        "/api/v1/inventory/preview",
        "/api/v1/inventory/resolve",
    }
    for route in unsafe_routes:
        dependencies = _dependency_names(route)
        if route.path == "/api/v1/auth/login":
            assert "require_allowed_origin" in dependencies
        elif route.path in read_only_posts:
            assert "get_current_session" in dependencies
        else:
            assert "get_unsafe_session" in dependencies

    auth_routes = [route for route in routes if route.path.startswith("/api/v1/auth/")]
    assert auth_routes
    assert all("prevent_auth_caching" in _dependency_names(route) for route in auth_routes)


def _request(
    *,
    method: str = "POST",
    path: str = "/api/v1/auth/login",
    csrf_cookie: str | None = None,
    csrf_header: str | None = None,
    session_token: str | None = None,
    origin: str | None = None,
    with_client: bool = True,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    cookies: list[bytes] = []
    if session_token is not None:
        cookies.append(f"{get_settings().session_cookie_name}={session_token}".encode())
    if csrf_cookie is not None:
        cookies.append(f"{get_settings().csrf_cookie_name}={csrf_cookie}".encode())
    if cookies:
        headers.append((b"cookie", b"; ".join(cookies)))
    if csrf_header is not None:
        headers.append((b"x-csrf-token", csrf_header.encode()))
    scope: dict[str, object] = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "server": ("localhost", 8000),
    }
    if with_client:
        scope["client"] = ("127.0.0.1", 12345)
    return Request(scope)


@pytest.mark.asyncio
async def test_auth_api_dependencies_delegate_and_bind_csrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(allowed_origins_csv="http://localhost:5173")
    monkeypatch.setattr(auth_api, "get_settings", lambda: settings)
    now = utc_now()
    csrf = generate_token()
    principal = SessionPrincipal(
        session_id=uuid4(),
        user_id=uuid4(),
        username="admin",
        csrf_hash=hash_token(csrf),
        expires_at=now + timedelta(days=1),
    )
    issued = IssuedSession(
        principal=principal,
        session_token=generate_token(),
        csrf_token=generate_token(),
    )
    service = type(
        "FakeAuthService",
        (),
        {
            "login": AsyncMock(return_value=issued),
            "resolve": AsyncMock(return_value=principal),
            "logout": AsyncMock(),
            "require_csrf": Mock(),
        },
    )()
    monkeypatch.setattr(auth_api, "_service", lambda _factory: service)
    factory = cast(UnitOfWorkFactory, object())

    with pytest.raises(AuthenticationRequiredError):
        await auth_api.get_current_session(_request(), factory)
    assert (
        await auth_api.get_current_session(_request(session_token="opaque-session"), factory)
        == principal
    )

    raw = _request(origin="http://localhost:5173")
    auth_api.require_allowed_origin(raw)
    with pytest.raises(OriginNotAllowedError):
        auth_api.require_allowed_origin(_request(origin="https://attacker.invalid"))
    assert auth_api._client_key(raw) == "127.0.0.1"
    assert auth_api._client_key(_request(with_client=False)) == "unknown-client"

    response = Response()
    result = await auth_api.login(
        LoginRequest(username="admin", password="password"), raw, response, factory, None
    )
    assert result.username == "admin"
    assert len(response.headers.getlist("set-cookie")) == 2

    authenticated = _request(
        path="/api/v1/hosts",
        csrf_cookie=csrf,
        csrf_header=csrf,
        origin="http://localhost:5173",
    )
    assert await get_unsafe_session(authenticated, factory, principal) == principal
    service.require_csrf.assert_called_once_with(principal, csrf)
    with pytest.raises(CsrfValidationError):
        await get_unsafe_session(
            _request(
                path="/api/v1/hosts",
                csrf_cookie=csrf,
                origin="http://localhost:5173",
            ),
            factory,
            principal,
        )


class _RateRepository:
    async def consume_rate_limit(self, **_: object) -> int:
        return 2


class _RateContext:
    auth = _RateRepository()

    def __init__(self, exits: list[type[BaseException] | None]) -> None:
        self._exits = exits

    async def __aenter__(self) -> _RateContext:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object,
    ) -> None:
        self._exits.append(exc_type)


class _RateFactory:
    def __init__(self) -> None:
        self.exits: list[type[BaseException] | None] = []

    def __call__(self) -> _RateContext:
        return _RateContext(self.exits)


@pytest.mark.asyncio
async def test_rate_limit_transaction_commits_before_rejection() -> None:
    factory = _RateFactory()
    service = AuthService(
        cast(UnitOfWorkFactory, factory), Settings(auth_rate_limit_secret="x" * 32)
    )
    with pytest.raises(AuthRateLimitedError):
        await service._consume_rate_limit(
            RateLimitSpec(
                scope="login:username_ip", subject="admin|127.0.0.1", maximum=1, window_seconds=300
            )
        )
    assert factory.exits == [None]


@pytest.mark.asyncio
async def test_auth_validation_errors_are_redacted_and_use_error_envelope() -> None:
    app = FastAPI()
    install_error_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    @app.post("/api/v1/auth/login")
    async def validate_login(_request: LoginRequest) -> None:
        return None

    secret = "do-not-leak-this-password"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            headers={"X-Request-ID": "auth-validation-1"},
            json={"username": "", "password": secret},
        )
    payload = response.json()
    assert response.status_code == 422
    assert payload["code"] == "request_validation_failed"
    assert payload["message"] == "request validation failed"
    assert payload["requestId"] == "auth-validation-1"
    assert "details" in payload
    assert secret not in response.text
    assert response.headers["cache-control"] == "no-store"
