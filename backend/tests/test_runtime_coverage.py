from __future__ import annotations

import json
import stat
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException, Response
from starlette.requests import Request
from typer.testing import CliRunner

import ops_composer.cli as cli_module
import ops_composer.main as main_module
from ops_composer.api.dependencies import get_unit_of_work_factory, prevent_auth_caching
from ops_composer.api.health import readiness
from ops_composer.auth.errors import AdminAlreadyExistsError
from ops_composer.db.migration_engine import MigrationState, MigrationStatus
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

    manager_lifecycle: list[str] = []

    class _WebShellManager:
        def __init__(self, *_args: object) -> None:
            pass

        async def start(self) -> None:
            manager_lifecycle.append("started")

        async def stop(self) -> None:
            manager_lifecycle.append("stopped")

    monkeypatch.setattr(main_module, "WebShellManager", _WebShellManager)
    application = FastAPI()
    async with main_module.lifespan(application):
        assert application.state.database_pool is app_pool
        assert isinstance(application.state.unit_of_work_factory, UnitOfWorkFactory)
        assert created_runners[-1].current_validated
        assert ensured == [True]
        assert manager_lifecycle == ["started"]
    assert app_pool.opened and app_pool.closed
    assert manager_lifecycle == ["started", "stopped"]


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


class _AuditService:
    def __init__(self) -> None:
        now = utc_now()
        self.events = (
            AuditEvent(
                audit_event_id=2,
                occurred_at=now,
                severity=AuditSeverity.WARNING,
                source=AuditSource.WORKER,
                service="worker",
                event_action=AuditAction.RUN_FAILED,
                event_outcome=AuditOutcome.FAILED,
                run_id=uuid4(),
                resource_type="run",
                resource_id="run-2",
                error_code="RUNNER_ERROR",
                metadata={"target_count": 2},
            ),
            AuditEvent(
                audit_event_id=1,
                occurred_at=now - timedelta(minutes=1),
                severity=AuditSeverity.INFO,
                source=AuditSource.API,
                service="api",
                event_action=AuditAction.RUN_CREATED,
                event_outcome=AuditOutcome.SUCCEEDED,
                resource_type="run",
                resource_id="run-1",
            ),
        )
        self.queries: list[AuditQuery] = []
        self.recorded: list[AuditEventDraft] = []
        self.purge_calls = 0

    async def list(self, query: AuditQuery) -> tuple[AuditEvent, ...]:
        self.queries.append(query)
        return self.events if query.before_id is None else ()

    async def count_before(self, _cutoff: datetime) -> int:
        return 3

    async def purge_before(self, _cutoff: datetime) -> tuple[bool, int]:
        self.purge_calls += 1
        return (True, 3) if self.purge_calls == 1 else (True, 0)

    async def record_best_effort(self, event: AuditEventDraft) -> None:
        self.recorded.append(event)


def test_audit_cli_lists_exports_and_purges_with_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service = _AuditService()

    @asynccontextmanager
    async def audit_runtime() -> AsyncIterator[tuple[_AuditService, Settings]]:
        yield service, Settings(audit_retention_days=180)

    monkeypatch.setattr(cli_module, "_audit_runtime", audit_runtime)
    command = CliRunner()
    since = "2026-09-01T00:00:00Z"
    until = "2026-09-05T00:00:00+00:00"

    listed = command.invoke(
        cli_module.app,
        [
            "audit",
            "list",
            "--since",
            since,
            "--until",
            until,
            "--action",
            "run_failed",
            "--outcome",
            "failed",
            "--source",
            "worker",
            "--run-id",
            str(service.events[0].run_id),
            "--actor-user-id",
            str(uuid4()),
            "--resource-type",
            "run",
            "--resource-id",
            "run-2",
            "--error-code",
            "RUNNER_ERROR",
            "--before-id",
            "20",
            "--limit",
            "50",
            "--jsonl",
        ],
    )
    assert listed.exit_code == 0
    assert listed.stdout == ""
    query = service.queries[-1]
    assert query.action is AuditAction.RUN_FAILED
    assert query.outcome is AuditOutcome.FAILED
    assert query.source is AuditSource.WORKER
    assert query.before_id == 20

    table = command.invoke(cli_module.app, ["audit", "list"])
    assert table.exit_code == 0
    assert "occurred_at" in table.stdout
    assert "RUN_FAILED" in table.stdout
    assert "run:run-2" in table.stdout
    jsonl = command.invoke(cli_module.app, ["audit", "list", "--jsonl"])
    assert jsonl.exit_code == 0
    assert json.loads(jsonl.stdout.splitlines()[0])["event_action"] == "RUN_FAILED"

    destination = tmp_path / "audit.jsonl"
    exported = command.invoke(
        cli_module.app,
        [
            "audit",
            "export",
            "--since",
            since,
            "--until",
            until,
            "--output",
            str(destination),
        ],
    )
    assert exported.exit_code == 0
    assert "exported=2" in exported.stdout
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event_action"] == "RUN_FAILED"
    refused = command.invoke(
        cli_module.app,
        [
            "audit",
            "export",
            "--since",
            since,
            "--until",
            until,
            "--output",
            str(destination),
        ],
    )
    assert refused.exit_code == 2
    forced = command.invoke(
        cli_module.app,
        [
            "audit",
            "export",
            "--since",
            since,
            "--until",
            until,
            "--output",
            str(destination),
            "--force",
        ],
    )
    assert forced.exit_code == 0
    assert any(event.event_action is AuditAction.AUDIT_EXPORTED for event in service.recorded)

    dry_run = command.invoke(
        cli_module.app,
        ["audit", "purge", "--before", "2026-09-01T00:00:00Z"],
    )
    assert dry_run.exit_code == 0
    assert "would_purge=3" in dry_run.stdout
    executed = command.invoke(
        cli_module.app,
        ["audit", "purge", "--before", "2026-09-01T00:00:00Z", "--execute"],
    )
    assert executed.exit_code == 0
    assert "purged=3" in executed.stdout
    assert any(
        event.event_action is AuditAction.AUDIT_RETENTION_PURGED
        for event in service.recorded
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["audit", "list", "--since", "not-a-timestamp"],
        ["audit", "list", "--since", "2026-09-01T00:00:00"],
        ["audit", "list", "--action", "unknown"],
        ["audit", "list", "--outcome", "unknown"],
        ["audit", "list", "--source", "unknown"],
    ],
)
def test_audit_cli_rejects_unsafe_filters(arguments: list[str]) -> None:
    result = CliRunner().invoke(cli_module.app, arguments)
    assert result.exit_code != 0


def test_cli_startup_migration_failures_and_admin_bootstrap_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured: list[dict[str, object]] = []

    def configured_logging(**values: object) -> None:
        configured.append(values)

    monkeypatch.setattr(cli_module, "configure_logging", configured_logging)
    monkeypatch.setattr(cli_module, "bind_log_context", lambda **_values: None)
    monkeypatch.setattr(cli_module, "get_settings", lambda: Settings(log_level="WARNING"))
    cli_module._configure_logging("migration")
    assert configured[-1]["service"] == "migration"
    assert configured[-1]["level"] == "WARNING"

    def invalid_settings() -> Settings:
        return Settings(app_env="production")

    monkeypatch.setattr(cli_module, "get_settings", invalid_settings)
    cli_module._configure_logging()
    assert configured[-1] == {"service": "cli"}

    runner = _MigrationRunner()

    @asynccontextmanager
    async def fake_runner() -> AsyncIterator[_MigrationRunner]:
        yield runner

    monkeypatch.setattr(cli_module, "_runner", fake_runner)
    command = CliRunner()

    async def invalid_history() -> None:
        raise RuntimeError("migration validation failed")

    runner.validate = invalid_history  # type: ignore[method-assign]
    assert command.invoke(cli_module.app, ["migrate", "validate"]).exit_code == 1

    async def failed_apply() -> tuple[str, ...]:
        raise RuntimeError("migration apply failed")

    runner.up = failed_apply  # type: ignore[method-assign]
    assert command.invoke(cli_module.app, ["migrate", "up"]).exit_code == 1

    pools: list[_ServicePool] = []

    def create_service_pool(_database_url: str) -> _ServicePool:
        pool = _ServicePool()
        pools.append(pool)
        return pool

    bootstrap_mode = {"value": "success"}

    class _AuthService:
        def __init__(self, _factory: UnitOfWorkFactory, _settings: Settings) -> None:
            pass

        async def bootstrap(self, username: str, _password: str) -> object:
            if bootstrap_mode["value"] == "exists":
                raise AdminAlreadyExistsError()
            if bootstrap_mode["value"] == "invalid":
                raise ValueError("password is invalid")
            return type("Identity", (), {"username": username})()

    monkeypatch.setattr(cli_module, "get_settings", lambda: Settings())
    monkeypatch.setattr(cli_module, "create_pool", create_service_pool)
    monkeypatch.setattr(cli_module, "AuthService", _AuthService)

    success = command.invoke(
        cli_module.app,
        ["admin", "bootstrap", "--username", "operator"],
        input="long-enough-password\nlong-enough-password\n",
    )
    assert success.exit_code == 0
    assert "administrator 'operator' created" in success.stdout

    bootstrap_mode["value"] = "exists"
    exists = command.invoke(
        cli_module.app,
        ["admin", "bootstrap"],
        input="long-enough-password\nlong-enough-password\n",
    )
    assert exists.exit_code == 1
    assert "already been bootstrapped" in exists.stderr

    bootstrap_mode["value"] = "invalid"
    invalid = command.invoke(
        cli_module.app,
        ["admin", "bootstrap"],
        input="long-enough-password\nlong-enough-password\n",
    )
    assert invalid.exit_code == 2
    assert "password is invalid" in invalid.stderr
    assert all(pool.opened and pool.closed for pool in pools)


def test_audit_cli_rejects_bad_export_targets_and_reports_busy_purge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service = _AuditService()

    async def busy_purge(_cutoff: datetime) -> tuple[bool, int]:
        return False, 0

    service.purge_before = busy_purge  # type: ignore[method-assign]

    @asynccontextmanager
    async def audit_runtime() -> AsyncIterator[tuple[_AuditService, Settings]]:
        yield service, Settings()

    monkeypatch.setattr(cli_module, "_audit_runtime", audit_runtime)
    command = CliRunner()
    options = [
        "audit",
        "export",
        "--since",
        "2026-09-01T00:00:00Z",
        "--until",
        "2026-09-02T00:00:00Z",
        "--output",
    ]
    missing_parent = command.invoke(
        cli_module.app,
        [*options, str(tmp_path / "missing" / "audit.jsonl")],
    )
    assert missing_parent.exit_code == 2
    directory_target = tmp_path / "directory"
    directory_target.mkdir()
    invalid_target = command.invoke(
        cli_module.app,
        [*options, str(directory_target), "--force"],
    )
    assert invalid_target.exit_code == 2
    busy = command.invoke(cli_module.app, ["audit", "purge", "--execute"])
    assert busy.exit_code == 0
    assert "lock=busy" in busy.stdout


def test_worker_cli_handles_operator_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    async def interrupted(_settings: Settings) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "run_worker", interrupted)
    monkeypatch.setattr(cli_module, "get_settings", lambda: Settings())
    result = CliRunner().invoke(cli_module.app, ["worker"])
    assert result.exit_code == 0
    assert "worker stopped" in result.stdout
