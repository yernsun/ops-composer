from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request
from typer.testing import CliRunner

import ops_composer.cli as cli_module
import ops_composer.main as main_module
from ops_composer.api.dependencies import get_unit_of_work_factory, prevent_auth_caching
from ops_composer.api.health import readiness
from ops_composer.db.migration_engine import MigrationState, MigrationStatus
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *_: object) -> None:
        return None


class _Pool:
    def __init__(self) -> None:
        self.connection_value = object()
        self.opened = False
        self.closed = False

    async def open(self) -> None:
        self.opened = True

    async def close(self) -> None:
        self.closed = True

    def connection(self) -> _AsyncContext:
        return _AsyncContext(self.connection_value)


class _MigrationRunner:
    def __init__(self) -> None:
        self.validated = False
        self.current_validated = False
        self.applied: tuple[str, ...] = ("0001_core",)

    async def status(self) -> tuple[MigrationStatus, ...]:
        return (
            MigrationStatus(
                migration_id="0001_core",
                checksum="a" * 64,
                state=MigrationState.APPLIED,
                applied_at=datetime.now(UTC),
            ),
        )

    async def validate(self) -> None:
        self.validated = True

    async def validate_current(self) -> None:
        self.current_validated = True

    async def up(self) -> tuple[str, ...]:
        return self.applied


@pytest.mark.asyncio
async def test_cli_runner_and_application_lifespan_close_their_pools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli_pool = _Pool()
    created_runners: list[_MigrationRunner] = []

    def migration_runner(_connection: object, _migrations: object) -> _MigrationRunner:
        runner = _MigrationRunner()
        created_runners.append(runner)
        return runner

    monkeypatch.setattr(cli_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(cli_module, "create_pool", lambda _database_url: cli_pool)
    monkeypatch.setattr(cli_module, "MigrationRunner", migration_runner)

    async with cli_module._runner() as runner:
        assert runner is created_runners[0]
    assert cli_pool.opened and cli_pool.closed

    app_pool = _Pool()
    monkeypatch.setattr(main_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(main_module, "create_pool", lambda _database_url: app_pool)
    monkeypatch.setattr(main_module, "MigrationRunner", migration_runner)
    ensured: list[bool] = []

    class _CredentialService:
        def __init__(self, *_args: object) -> None:
            pass

        async def ensure_master_key(self) -> None:
            ensured.append(True)

    monkeypatch.setattr(main_module, "CredentialService", _CredentialService)
    application = FastAPI()
    async with main_module.lifespan(application):
        assert application.state.database_pool is app_pool
        assert isinstance(application.state.unit_of_work_factory, UnitOfWorkFactory)
        assert created_runners[-1].current_validated
        assert ensured == [True]
    assert app_pool.opened and app_pool.closed


def test_migration_and_configuration_cli_commands_cover_operator_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _MigrationRunner()

    @asynccontextmanager
    async def fake_runner() -> AsyncIterator[_MigrationRunner]:
        yield runner

    class _Settings:
        def safe_summary(self) -> dict[str, object]:
            return {
                "environment": "development",
                "database": "postgresql",
                "database_configured": True,
                "authentication": {
                    "mode": "single-administrator",
                    "allowed_origins": ["http://localhost:5173"],
                    "cookies_secure": False,
                    "trusted_proxies": ["127.0.0.1"],
                },
            }

    monkeypatch.setattr(cli_module, "_runner", fake_runner)
    monkeypatch.setattr(cli_module, "Settings", _Settings)
    command = CliRunner()

    status_result = command.invoke(cli_module.app, ["migrate", "status"])
    assert status_result.exit_code == 0
    assert "applied" in status_result.stdout
    assert "0001_core" in status_result.stdout

    validate_result = command.invoke(cli_module.app, ["migrate", "validate"])
    assert validate_result.exit_code == 0
    assert "migration history is valid" in validate_result.stdout
    assert runner.validated

    up_result = command.invoke(cli_module.app, ["migrate", "up"])
    assert up_result.exit_code == 0
    assert "applied: 0001_core" in up_result.stdout
    runner.applied = ()
    empty_up_result = command.invoke(cli_module.app, ["migrate", "up"])
    assert empty_up_result.exit_code == 0
    assert "applied: none" in empty_up_result.stdout

    config_result = command.invoke(cli_module.app, ["config", "check"])
    assert config_result.exit_code == 0
    assert '"environment": "development"' in config_result.stdout
    assert '"database": "postgresql"' in config_result.stdout
    assert '"mode": "single-administrator"' in config_result.stdout
    assert '"allowed_origins"' in config_result.stdout
    assert "http://localhost:5173" in config_result.stdout


@pytest.mark.asyncio
async def test_dependencies_and_readiness_cover_healthy_and_unhealthy_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = cast(UnitOfWorkFactory, object())
    application = FastAPI()
    application.state.unit_of_work_factory = factory
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/health/ready",
            "raw_path": b"/health/ready",
            "query_string": b"",
            "headers": [],
            "app": application,
        }
    )
    assert get_unit_of_work_factory(request) is factory

    response = Response()
    prevent_auth_caching(response)
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    class _HealthService:
        ready = True

        def __init__(self, _factory: UnitOfWorkFactory) -> None:
            pass

        async def is_ready(self) -> bool:
            return self.ready

    monkeypatch.setattr("ops_composer.api.health.HealthService", _HealthService)
    assert (await readiness(factory)).status == "ready"
    _HealthService.ready = False
    with pytest.raises(HTTPException) as error:
        await readiness(factory)
    assert error.value.status_code == 503


class _ServicePool(_Pool):
    pass


def test_auth_purge_cli_executes_dry_run_and_delete_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pools: list[_ServicePool] = []
    dry_runs: list[bool] = []

    def create_service_pool(_database_url: str) -> _ServicePool:
        pool = _ServicePool()
        pools.append(pool)
        return pool

    class _AuthService:
        def __init__(self, _factory: UnitOfWorkFactory, _settings: Settings) -> None:
            pass

        async def purge_expired(self, *, dry_run: bool) -> tuple[int, int]:
            dry_runs.append(dry_run)
            return (2, 3)

    monkeypatch.setattr(cli_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(cli_module, "create_pool", create_service_pool)
    monkeypatch.setattr(cli_module, "AuthService", _AuthService)
    command = CliRunner()

    dry_result = command.invoke(cli_module.app, ["purge-expired-auth", "--dry-run"])
    assert dry_result.exit_code == 0
    assert "would_purge sessions=2 rate_limits=3" in dry_result.stdout
    delete_result = command.invoke(cli_module.app, ["purge-expired-auth"])
    assert delete_result.exit_code == 0
    assert "purged sessions=2 rate_limits=3" in delete_result.stdout
    assert dry_runs == [True, False]
    assert all(pool.opened and pool.closed for pool in pools)
