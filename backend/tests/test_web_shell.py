from __future__ import annotations

import asyncio
import base64
import errno
import os
import pty
import signal
import stat
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from fastapi import Response
from pydantic import SecretStr
from pydantic import ValidationError as PydanticValidationError
from starlette.websockets import WebSocketDisconnect, WebSocketState

from ops_composer.api.web_shell import (
    close_web_shell_session,
    create_web_shell_session,
    stream_web_shell,
)
from ops_composer.auth.models import SessionPrincipal
from ops_composer.domain.audit import AuditAction
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    HostBusyError,
    HostKeyConfirmationRequiredError,
    NotFoundError,
    ValidationError,
    WebShellCapacityError,
    WebShellSessionExpiredError,
    WebShellUnavailableError,
)
from ops_composer.domain.ops import CredentialRevision, Host, HostKey, ResolvedHost
from ops_composer.domain.web_shell import (
    WebShellCloseReason,
    WebShellLaunch,
    WebShellSession,
    WebShellState,
)
from ops_composer.repositories.base import RepositoryConnection
from ops_composer.repositories.web_shell import PostgresWebShellRepository
from ops_composer.services.crypto import CredentialCipher
from ops_composer.services.web_shell import WebShellService
from ops_composer.settings import Settings
from ops_composer.ssh_terminal import SshTerminal, SshTerminalStartError
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.web_shell_manager import ActiveWebShell, WebShellManager

MASTER_KEY = base64.b64encode(b"0123456789abcdef" * 2).decode()


def _principal() -> SessionPrincipal:
    return SessionPrincipal(
        session_id=uuid4(),
        user_id=uuid4(),
        username="admin",
        csrf_hash="hash",
        expires_at=utc_now() + timedelta(hours=1),
    )


def _host(credential_id: UUID) -> Host:
    now = utc_now()
    return Host(
        host_id=uuid4(),
        name="web-01",
        address="192.0.2.44",
        ssh_port=2222,
        credential_id=credential_id,
        enabled=True,
        description="test host",
        version=1,
        created_at=now,
        updated_at=now,
    )


def _resolved(host: Host) -> ResolvedHost:
    return ResolvedHost(
        host_id=host.host_id,
        name=host.name,
        address=host.address,
        ssh_port=host.ssh_port,
        credential_id=host.credential_id,
        credential_version=3,
        credential_username="deploy",
    )


def _host_key(host_id: UUID, principal: SessionPrincipal) -> HostKey:
    return HostKey(
        host_id=host_id,
        algorithm="ssh-ed25519",
        public_key="AAAAC3NzaC1lZDI1NTE5AAAAITestOnly",
        fingerprint="SHA256:test-only",
        trusted_by=principal.user_id,
        trusted_at=utc_now(),
    )


def _session(
    host: Host,
    principal: SessionPrincipal,
    *,
    state: WebShellState = WebShellState.PENDING,
    owner_id: str | None = None,
) -> WebShellSession:
    now = utc_now()
    return WebShellSession(
        web_shell_session_id=uuid4(),
        host_id=host.host_id,
        actor_user_id=principal.user_id,
        auth_session_id=principal.session_id,
        credential_id=host.credential_id,
        credential_version=3,
        host_name=host.name,
        host_address=host.address,
        ssh_port=host.ssh_port,
        username="deploy",
        state=state,
        api_instance_id="api-test",
        owner_id=owner_id,
        ticket_expires_at=now + timedelta(seconds=30),
        lease_expires_at=now + timedelta(seconds=30),
        connected_at=now if state is not WebShellState.PENDING else None,
        last_activity_at=now if state is not WebShellState.PENDING else None,
        created_at=now,
    )


class _Audit:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def append(self, event: Any) -> None:
        self.events.append(event)


class _Assets:
    def __init__(
        self,
        host: Host,
        resolved: ResolvedHost,
        keys: tuple[HostKey, ...],
        revision: CredentialRevision,
    ) -> None:
        self.host = host
        self.resolved = resolved
        self.keys = keys
        self.revision = revision

    async def get_host(self, host_id: UUID) -> Host | None:
        return self.host if host_id == self.host.host_id else None

    async def resolve_host_ids(self, _host_ids: tuple[UUID, ...]) -> tuple[ResolvedHost, ...]:
        return (self.resolved,)

    async def list_host_keys(self, _host_id: UUID) -> tuple[HostKey, ...]:
        return self.keys

    async def get_credential_revision(
        self, _credential_id: UUID, _version: int
    ) -> CredentialRevision | None:
        return self.revision


class _WebShellRepository:
    def __init__(self) -> None:
        self.live = 0
        self.cleanup_count = 0
        self.lock_acquired = True
        self.current: WebShellSession | None = None
        self.active: WebShellSession | None = None
        self.heartbeat_refreshed = True
        self.added: WebShellSession | None = None
        self.deleted: list[tuple[UUID, str | None]] = []

    async def acquire_admission_lock(self) -> None:
        return None

    async def cleanup_expired(self, _now: object) -> int:
        return self.cleanup_count

    async def count_live(self, _now: object) -> int:
        return self.live

    async def add(self, session: WebShellSession) -> WebShellSession:
        self.added = session
        self.current = session
        return session

    async def acquire_host_lock(self, *_args: object) -> bool:
        return self.lock_acquired

    async def get(self, _session_id: UUID, *, for_update: bool = False) -> WebShellSession | None:
        del for_update
        return self.current

    async def activate(self, *_args: object) -> WebShellSession | None:
        return self.active

    async def heartbeat(self, *_args: object) -> bool:
        return self.heartbeat_refreshed

    async def mark_close_requested(
        self, _session_id: UUID, _actor_user_id: UUID, _now: object
    ) -> WebShellSession | None:
        return self.current

    async def delete(
        self, session_id: UUID, owner_id: str | None = None
    ) -> WebShellSession | None:
        self.deleted.append((session_id, owner_id))
        current = self.current
        self.current = None
        return current


class _Unit:
    def __init__(self, assets: _Assets, web_shell: _WebShellRepository) -> None:
        self.assets = assets
        self.web_shell = web_shell
        self.audit = _Audit()

    async def __aenter__(self) -> _Unit:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None


class _Factory:
    def __init__(self, unit: _Unit) -> None:
        self.unit = unit

    def __call__(self) -> _Unit:
        return self.unit


def _service_fixture() -> tuple[
    WebShellService,
    _Unit,
    _WebShellRepository,
    SessionPrincipal,
    Host,
    CredentialCipher,
]:
    principal = _principal()
    credential_id = uuid4()
    host = _host(credential_id)
    cipher = CredentialCipher(MASTER_KEY, 1)
    revision = CredentialRevision(
        credential_id=credential_id,
        version=3,
        encrypted_secret=cipher.encrypt(credential_id, 3, {"password": "sentinel-password"}),
        encryption_key_version=1,
        created_at=utc_now(),
    )
    repository = _WebShellRepository()
    assets = _Assets(host, _resolved(host), (_host_key(host.host_id, principal),), revision)
    unit = _Unit(assets, repository)
    service = WebShellService(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY),
        cipher,
    )
    return service, unit, repository, principal, host, cipher


@pytest.mark.asyncio
async def test_service_admission_pins_credential_and_acquires_shared_host_lock() -> None:
    service, unit, repository, principal, host, _cipher = _service_fixture()
    repository.cleanup_count = 2

    created = await service.create(host.host_id, principal, "api-test")

    assert created.host_id == host.host_id
    assert created.credential_version == 3
    assert created.api_instance_id == "api-test"
    assert created.state is WebShellState.PENDING
    assert [event.event_action for event in unit.audit.events] == [
        AuditAction.WEB_SHELL_STALE_RECOVERED,
        AuditAction.WEB_SHELL_REQUESTED,
    ]


@pytest.mark.asyncio
async def test_service_rejects_capacity_host_lock_and_missing_trust() -> None:
    service, unit, repository, principal, host, _cipher = _service_fixture()
    repository.live = 5
    with pytest.raises(WebShellCapacityError):
        await service.create(host.host_id, principal, "api-test")

    repository.live = 0
    repository.lock_acquired = False
    with pytest.raises(HostBusyError):
        await service.create(host.host_id, principal, "api-test")

    repository.lock_acquired = True
    unit.assets.keys = ()
    with pytest.raises(HostKeyConfirmationRequiredError):
        await service.create(host.host_id, principal, "api-test")


@pytest.mark.asyncio
async def test_claim_consumes_ticket_and_decrypts_only_the_pinned_revision() -> None:
    service, unit, repository, principal, host, _cipher = _service_fixture()
    pending = _session(host, principal)
    active = pending.model_copy(
        update={
            "state": WebShellState.ACTIVE,
            "owner_id": "api-test:stream",
            "connected_at": utc_now(),
            "last_activity_at": utc_now(),
        }
    )
    repository.current = pending
    repository.active = active

    launch = await service.claim(pending.web_shell_session_id, principal, "api-test:stream")

    assert launch.password.get_secret_value() == "sentinel-password"
    assert "[192.0.2.44]:2222 ssh-ed25519" in launch.known_hosts
    assert unit.audit.events[-1].event_action is AuditAction.WEB_SHELL_STARTED

    repository.current = active
    with pytest.raises(WebShellSessionExpiredError):
        await service.claim(pending.web_shell_session_id, principal, "api-test:second")


@pytest.mark.asyncio
async def test_heartbeat_distinguishes_close_request_from_invalid_auth() -> None:
    service, _unit, repository, principal, host, _cipher = _service_fixture()
    active = _session(host, principal, state=WebShellState.ACTIVE, owner_id="owner")
    repository.current = active
    assert await service.heartbeat(active.web_shell_session_id, "owner", utc_now()) is None

    repository.heartbeat_refreshed = False
    repository.current = active.model_copy(update={"state": WebShellState.CLOSE_REQUESTED})
    assert (
        await service.heartbeat(active.web_shell_session_id, "owner", utc_now())
        is WebShellCloseReason.USER_REQUESTED
    )

    repository.current = active
    assert (
        await service.heartbeat(active.web_shell_session_id, "other-owner", utc_now())
        is WebShellCloseReason.AUTH_SESSION_INVALID
    )


@pytest.mark.asyncio
async def test_close_finish_and_stale_recovery_preserve_only_lifecycle_audit() -> None:
    service, unit, repository, principal, host, _cipher = _service_fixture()
    pending = _session(host, principal)
    repository.current = pending
    await service.request_close(pending.web_shell_session_id, principal)
    assert repository.deleted[-1] == (pending.web_shell_session_id, None)
    assert unit.audit.events[-1].event_action is AuditAction.WEB_SHELL_CLOSED

    active = _session(host, principal, state=WebShellState.ACTIVE, owner_id="owner")
    repository.current = active
    await service.finish(
        active.web_shell_session_id,
        "owner",
        WebShellCloseReason.IDLE_TIMEOUT,
        duration_ms=1200,
        exit_code=None,
    )
    event = unit.audit.events[-1]
    assert event.event_action is AuditAction.WEB_SHELL_TIMED_OUT
    assert "sentinel-password" not in event.model_dump_json()

    repository.cleanup_count = 1
    assert await service.recover_stale() == 1
    stale_event = cast(Any, unit.audit.events[-1])
    assert stale_event.event_action is AuditAction.WEB_SHELL_STALE_RECOVERED


@pytest.mark.asyncio
async def test_service_rejects_missing_disabled_and_unusable_hosts() -> None:
    service, unit, repository, principal, host, _cipher = _service_fixture()
    unit.assets.get_host = AsyncMock(return_value=None)  # type: ignore[method-assign]
    with pytest.raises(NotFoundError):
        await service.create(host.host_id, principal, "api-test")

    unit.assets.get_host = AsyncMock(  # type: ignore[method-assign]
        return_value=host.model_copy(update={"enabled": False})
    )
    with pytest.raises(ValidationError, match="host is disabled"):
        await service.create(host.host_id, principal, "api-test")

    unit.assets.get_host = AsyncMock(return_value=host)  # type: ignore[method-assign]
    unit.assets.resolve_host_ids = AsyncMock(return_value=())  # type: ignore[method-assign]
    with pytest.raises(ValidationError, match="credential is missing"):
        await service.create(host.host_id, principal, "api-test")
    assert repository.added is None


@pytest.mark.asyncio
async def test_claim_rejects_lost_ticket_credential_key_password_and_host_key() -> None:
    service, unit, repository, principal, host, cipher = _service_fixture()
    pending = _session(host, principal)
    active = pending.model_copy(
        update={
            "state": WebShellState.ACTIVE,
            "owner_id": "owner",
            "connected_at": utc_now(),
            "last_activity_at": utc_now(),
        }
    )
    repository.current = pending
    repository.active = None
    with pytest.raises(WebShellSessionExpiredError):
        await service.claim(pending.web_shell_session_id, principal, "owner")

    repository.active = active
    unit.assets.revision = None  # type: ignore[assignment]
    with pytest.raises(WebShellUnavailableError, match="revision"):
        await service.claim(pending.web_shell_session_id, principal, "owner")

    wrong_key = CredentialRevision(
        credential_id=active.credential_id,
        version=active.credential_version,
        encrypted_secret=b"not-decrypted",
        encryption_key_version=2,
        created_at=utc_now(),
    )
    unit.assets.revision = wrong_key
    with pytest.raises(WebShellUnavailableError, match="key version"):
        await service.claim(pending.web_shell_session_id, principal, "owner")

    invalid_password = wrong_key.model_copy(
        update={
            "encrypted_secret": cipher.encrypt(
                active.credential_id, active.credential_version, {"password": "line\nbreak"}
            ),
            "encryption_key_version": 1,
        }
    )
    unit.assets.revision = invalid_password
    with pytest.raises(WebShellUnavailableError, match="password"):
        await service.claim(pending.web_shell_session_id, principal, "owner")

    valid_revision = invalid_password.model_copy(
        update={
            "encrypted_secret": cipher.encrypt(
                active.credential_id, active.credential_version, {"password": "valid"}
            )
        }
    )
    unit.assets.revision = valid_revision
    unit.assets.keys = ()
    with pytest.raises(HostKeyConfirmationRequiredError):
        await service.claim(pending.web_shell_session_id, principal, "owner")


@pytest.mark.asyncio
async def test_service_close_noops_active_request_and_failed_claim_cleanup() -> None:
    service, unit, repository, principal, host, _cipher = _service_fixture()
    repository.current = None
    await service.request_close(uuid4(), principal)
    await service.finish(
        uuid4(),
        "owner",
        WebShellCloseReason.START_FAILED,
        duration_ms=1,
        exit_code=1,
    )
    assert not unit.audit.events

    active = _session(host, principal, state=WebShellState.ACTIVE, owner_id="owner")
    repository.current = active
    await service.request_close(active.web_shell_session_id, principal)
    assert unit.audit.events[-1].event_action is AuditAction.WEB_SHELL_CLOSE_REQUESTED

    repository.current = active
    await service.discard_failed_claim(
        active.web_shell_session_id, "owner", WebShellCloseReason.START_FAILED
    )
    assert unit.audit.events[-1].event_action is AuditAction.WEB_SHELL_FAILED

    successful = service._finished_event(
        active,
        WebShellCloseReason.REMOTE_EXIT,
        duration_ms=2,
        exit_code=0,
    )
    assert successful.event_action is AuditAction.WEB_SHELL_CLOSED


@pytest.mark.asyncio
async def test_repository_uses_named_parameters_and_generic_host_lock() -> None:
    connection = AsyncMock()
    repository = PostgresWebShellRepository(cast(RepositoryConnection, connection))
    service, _unit, _fake_repository, principal, host, _cipher = _service_fixture()
    del service
    session = _session(host, principal)
    row = session.model_dump(mode="python")
    connection.fetch_one.side_effect = [
        {"acquired": None},
        {"count": 1},
        row,
        {"host_id": host.host_id},
        row,
    ]
    connection.execute.return_value = 2

    await repository.acquire_admission_lock()
    assert await repository.count_live(utc_now()) == 1
    assert await repository.add(session) == session
    assert await repository.acquire_host_lock(
        host.host_id,
        session.web_shell_session_id,
        "pending:api",
        utc_now(),
        utc_now() + timedelta(seconds=30),
    )
    assert await repository.get(session.web_shell_session_id) == session
    assert await repository.cleanup_expired(utc_now()) == 2

    rendered_queries = "\n".join(str(call.args[0]) for call in connection.fetch_one.call_args_list)
    assert "host_execution_locks" in rendered_queries
    assert "ON CONFLICT (host_id) DO UPDATE" in rendered_queries
    for call in connection.fetch_one.call_args_list:
        if len(call.args) > 1:
            assert isinstance(call.args[1], dict)


@pytest.mark.asyncio
async def test_repository_handles_empty_rows_and_lost_lock() -> None:
    connection = AsyncMock()
    repository = PostgresWebShellRepository(cast(RepositoryConnection, connection))
    _service, _unit, _fake_repository, principal, host, _cipher = _service_fixture()
    session = _session(host, principal)
    row = session.model_dump(mode="python")

    connection.fetch_one.return_value = None
    with pytest.raises(RuntimeError, match="count returned no row"):
        await repository.count_live(utc_now())
    with pytest.raises(RuntimeError, match="insert returned no row"):
        await repository.add(session)
    assert not await repository.acquire_host_lock(
        host.host_id,
        session.web_shell_session_id,
        "owner",
        utc_now(),
        utc_now() + timedelta(seconds=30),
    )
    assert await repository.get(session.web_shell_session_id, for_update=True) is None
    assert (
        await repository.activate(
            session.web_shell_session_id,
            principal.session_id,
            "owner",
            utc_now(),
            utc_now() + timedelta(seconds=30),
        )
        is None
    )
    assert not await repository.heartbeat(
        session.web_shell_session_id,
        "owner",
        utc_now(),
        utc_now() + timedelta(seconds=30),
        utc_now(),
    )
    assert (
        await repository.mark_close_requested(
            session.web_shell_session_id, principal.user_id, utc_now()
        )
        is None
    )
    assert await repository.delete(session.web_shell_session_id) is None

    connection.fetch_one.return_value = row
    connection.execute.return_value = 0
    with pytest.raises(RuntimeError, match="host lock was lost"):
        await repository.activate(
            session.web_shell_session_id,
            principal.session_id,
            "owner",
            utc_now(),
            utc_now() + timedelta(seconds=30),
        )
    connection.execute.return_value = 1
    assert (
        await repository.activate(
            session.web_shell_session_id,
            principal.session_id,
            "owner",
            utc_now(),
            utc_now() + timedelta(seconds=30),
        )
        == session
    )
    connection.fetch_one.return_value = {"refreshed": True}
    assert await repository.heartbeat(
        session.web_shell_session_id,
        "owner",
        utc_now(),
        utc_now() + timedelta(seconds=30),
        utc_now(),
    )
    connection.fetch_one.return_value = row
    assert (
        await repository.mark_close_requested(
            session.web_shell_session_id, principal.user_id, utc_now()
        )
        == session
    )
    assert await repository.delete(session.web_shell_session_id, "owner") == session


class _FakeProcess:
    pid = 999_999
    returncode: int | None = 0

    async def wait(self) -> int:
        return 0

    def kill(self) -> None:
        self.returncode = -9


@pytest.mark.asyncio
async def test_ssh_terminal_passes_password_only_through_anonymous_pipe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _unit, _repository, principal, host, _cipher = _service_fixture()
    del service
    session = _session(host, principal)
    launch = WebShellLaunch(
        session=session,
        password=SecretStr("pipe-only-sentinel"),
        known_hosts="[192.0.2.44]:2222 ssh-ed25519 AAAATest\n",
    )
    captured: dict[str, Any] = {}
    password_reader = -1

    async def create_process(*args: object, **kwargs: Any) -> _FakeProcess:
        nonlocal password_reader
        captured["args"] = args
        captured["kwargs"] = kwargs
        password_reader = os.dup(kwargs["pass_fds"][0])
        return _FakeProcess()

    monkeypatch.setattr("asyncio.create_subprocess_exec", create_process)
    terminal = await SshTerminal.start(launch, tmp_path)
    assert os.read(password_reader, 1024) == b"pipe-only-sentinel\n"
    os.close(password_reader)

    serialized_launch = repr((captured["args"], captured["kwargs"]))
    assert "pipe-only-sentinel" not in serialized_launch
    assert "StrictHostKeyChecking=yes" in serialized_launch
    assert captured["kwargs"]["env"] == {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
    }
    runtime_path = tmp_path / "web-shell" / str(session.web_shell_session_id)
    assert stat.S_IMODE(runtime_path.stat().st_mode) == 0o700
    assert stat.S_IMODE((runtime_path / "known_hosts").stat().st_mode) == 0o600
    await terminal.close()
    assert not runtime_path.exists()


@pytest.mark.asyncio
async def test_ssh_terminal_replaces_stale_runtime_and_cleans_up_start_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _service, _unit, _repository, principal, host, _cipher = _service_fixture()
    session = _session(host, principal)
    launch = WebShellLaunch(
        session=session,
        password=SecretStr("pipe-only-sentinel"),
        known_hosts="[192.0.2.44]:2222 ssh-ed25519 AAAATest\n",
    )
    runtime_path = tmp_path / "web-shell" / str(session.web_shell_session_id)
    runtime_path.mkdir(parents=True)
    (runtime_path / "stale").write_text("stale", encoding="utf-8")

    async def fail_process(*_args: object, **_kwargs: object) -> _FakeProcess:
        raise OSError("executable unavailable")

    monkeypatch.setattr("asyncio.create_subprocess_exec", fail_process)
    with pytest.raises(SshTerminalStartError, match="local SSH terminal startup failed"):
        await SshTerminal.start(launch, tmp_path)
    assert not runtime_path.exists()


@pytest.mark.asyncio
async def test_ssh_terminal_nonblocking_io_resize_and_closed_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    master_fd, slave_fd = pty.openpty()
    os.set_blocking(master_fd, False)
    runtime_path = tmp_path / "web-shell" / uuid4().hex
    runtime_path.mkdir(parents=True)
    terminal = SshTerminal(cast(Any, _FakeProcess()), master_fd, runtime_path)

    read_task = asyncio.create_task(terminal.read(1024))
    await asyncio.sleep(0)
    os.write(slave_fd, b"terminal-output\n")
    assert b"terminal-output" in await asyncio.wait_for(read_task, timeout=1)
    await asyncio.wait_for(terminal._wait_writable(), timeout=1)

    signals: list[int] = []

    def missing_process(_pid: int, process_signal: int) -> None:
        signals.append(process_signal)
        raise ProcessLookupError

    monkeypatch.setattr("ops_composer.ssh_terminal.os.killpg", missing_process)
    terminal.resize(140, 50)
    assert signals == [signal.SIGWINCH]
    assert await terminal.wait() == 0
    assert terminal.returncode == 0

    os.close(master_fd)
    assert await terminal.read(1024) == b""
    await terminal.write(b"ignored")
    os.close(slave_fd)
    await terminal.close()
    await terminal.close()
    assert not runtime_path.exists()


class _StoppingProcess:
    pid = 999_998

    def __init__(self) -> None:
        self.returncode: int | None = None

    async def wait(self) -> int:
        if self.returncode is None:
            raise TimeoutError
        return self.returncode


@pytest.mark.asyncio
async def test_ssh_terminal_escalates_process_group_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    master_fd, slave_fd = pty.openpty()
    runtime_path = tmp_path / "web-shell" / uuid4().hex
    runtime_path.mkdir(parents=True)
    process = _StoppingProcess()
    terminal = SshTerminal(cast(Any, process), master_fd, runtime_path)
    delivered: list[int] = []

    def signal_group(_pid: int, process_signal: int) -> None:
        delivered.append(process_signal)
        if process_signal is signal.SIGKILL:
            process.returncode = -signal.SIGKILL

    monkeypatch.setattr("ops_composer.ssh_terminal.os.killpg", signal_group)
    await terminal.close()
    os.close(slave_fd)

    assert delivered == [signal.SIGTERM, signal.SIGKILL]
    assert process.returncode == -signal.SIGKILL
    assert not runtime_path.exists()


@pytest.mark.asyncio
async def test_ssh_terminal_reraises_unexpected_io_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    master_fd, slave_fd = pty.openpty()
    runtime_path = tmp_path / "web-shell" / uuid4().hex
    runtime_path.mkdir(parents=True)
    terminal = SshTerminal(cast(Any, _FakeProcess()), master_fd, runtime_path)

    def fail_read(_descriptor: int, _maximum: int) -> bytes:
        raise OSError(errno.EPERM, "denied")

    monkeypatch.setattr("ops_composer.ssh_terminal.os.read", fail_read)
    with pytest.raises(OSError, match="denied"):
        await terminal.read(1)

    def fail_write(_descriptor: int, _value: object) -> int:
        raise OSError(errno.EPERM, "denied")

    monkeypatch.setattr("ops_composer.ssh_terminal.os.write", fail_write)
    with pytest.raises(OSError, match="denied"):
        await terminal.write(b"input")

    os.close(slave_fd)
    await terminal.close()


class _FakeTerminal:
    def __init__(self) -> None:
        self.returncode: int | None = 0
        self.closed = False
        self.resizes: list[tuple[int, int]] = []

    async def read(self, _maximum: int) -> bytes:
        return b""

    async def write(self, _data: bytes) -> None:
        return None

    def resize(self, columns: int, rows: int) -> None:
        self.resizes.append((columns, rows))

    async def wait(self) -> int:
        return 0

    async def close(self) -> None:
        self.closed = True


class _FakeWebSocket:
    def __init__(self) -> None:
        self.application_state = WebSocketState.CONNECTING
        self.messages: list[dict[str, object]] = []
        self.closed: tuple[int, str] | None = None
        self.headers: dict[str, str] = {"origin": "http://localhost:5173"}
        self.cookies: dict[str, str] = {"ops-composer-session": "session-token"}
        self.app = SimpleNamespace(state=SimpleNamespace())

    async def accept(self) -> None:
        self.application_state = WebSocketState.CONNECTED

    async def send_json(self, value: dict[str, object]) -> None:
        self.messages.append(value)

    async def send_bytes(self, _value: bytes) -> None:
        return None

    async def receive(self) -> dict[str, object]:
        await AsyncIteratorNever()
        raise AssertionError("unreachable")

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)
        self.application_state = WebSocketState.DISCONNECTED


class AsyncIteratorNever:
    def __await__(self) -> Any:
        async def wait_forever() -> None:
            await __import__("asyncio").Event().wait()

        return wait_forever().__await__()


class _ManagerService:
    def __init__(self, launch: WebShellLaunch) -> None:
        self.launch = launch
        self.finished: list[tuple[UUID, str, WebShellCloseReason]] = []

    async def claim(self, *_args: object) -> WebShellLaunch:
        return self.launch

    async def finish(
        self,
        session_id: UUID,
        owner_id: str,
        reason: WebShellCloseReason,
        **_kwargs: object,
    ) -> None:
        self.finished.append((session_id, owner_id, reason))

    async def heartbeat(self, *_args: object) -> WebShellCloseReason | None:
        return None


class _ApiManager:
    def __init__(self, session: WebShellSession) -> None:
        self.session = session
        self.created: list[tuple[UUID, SessionPrincipal]] = []
        self.closed: list[tuple[UUID, SessionPrincipal]] = []

    async def create(
        self, host_id: UUID, principal: SessionPrincipal
    ) -> WebShellSession:
        self.created.append((host_id, principal))
        return self.session

    async def request_close(
        self, session_id: UUID, principal: SessionPrincipal
    ) -> None:
        self.closed.append((session_id, principal))


@pytest.mark.asyncio
async def test_rest_contract_returns_no_store_stream_metadata() -> None:
    _service, _unit, _repository, principal, host, _cipher = _service_fixture()
    session = _session(host, principal)
    manager = _ApiManager(session)
    response = Response()

    payload = await create_web_shell_session(
        host.host_id,
        response,
        cast(Any, manager),
        principal,
    )

    assert payload.web_shell_session_id == session.web_shell_session_id
    assert payload.stream_path.endswith(f"/{session.web_shell_session_id}/stream")
    assert payload.idle_timeout_seconds == 1800
    assert response.headers["cache-control"] == "no-store"
    result = await close_web_shell_session(
        session.web_shell_session_id,
        cast(Any, manager),
        principal,
    )
    assert result.status_code == 204
    assert manager.closed == [(session.web_shell_session_id, principal)]


@pytest.mark.asyncio
async def test_websocket_rejects_origin_and_missing_cookie_before_upgrade() -> None:
    websocket = _FakeWebSocket()
    websocket.headers["origin"] = "https://untrusted.example"
    await stream_web_shell(cast(Any, websocket), uuid4())
    assert websocket.closed == (4403, "")

    websocket = _FakeWebSocket()
    websocket.cookies.clear()
    await stream_web_shell(cast(Any, websocket), uuid4())
    assert websocket.closed == (4401, "")


@pytest.mark.asyncio
async def test_manager_validates_ticket_before_accept_and_finalizes_remote_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _service, unit, _repository, principal, host, _cipher = _service_fixture()
    launch = WebShellLaunch(
        session=_session(host, principal),
        password=SecretStr("not-logged"),
        known_hosts="host ssh-ed25519 AAAA\n",
    )
    settings = Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path)
    manager = WebShellManager(cast(UnitOfWorkFactory, _Factory(unit)), settings, _cipher)
    manager_service = _ManagerService(launch)
    manager._service = cast(Any, manager_service)
    terminal = _FakeTerminal()

    async def start_terminal(*_args: object, **_kwargs: object) -> _FakeTerminal:
        return terminal

    monkeypatch.setattr(SshTerminal, "start", start_terminal)
    websocket = _FakeWebSocket()
    await manager.stream(cast(Any, websocket), launch.session.web_shell_session_id, principal)

    assert websocket.messages[0]["type"] == "ready"
    assert websocket.messages[-1]["type"] == "closed"
    assert websocket.closed == (1000, "")
    assert terminal.closed
    assert manager_service.finished[-1][2] is WebShellCloseReason.REMOTE_EXIT


@pytest.mark.asyncio
async def test_manager_releases_claim_when_local_pty_start_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    launch = WebShellLaunch(
        session=_session(host, principal),
        password=SecretStr("not-logged"),
        known_hosts="host ssh-ed25519 AAAA\n",
    )
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    manager_service = _ManagerService(launch)
    manager._service = cast(Any, manager_service)

    async def fail_start(*_args: object, **_kwargs: object) -> SshTerminal:
        raise SshTerminalStartError("safe failure")

    monkeypatch.setattr(SshTerminal, "start", fail_start)
    websocket = _FakeWebSocket()
    await manager.stream(cast(Any, websocket), launch.session.web_shell_session_id, principal)

    assert manager_service.finished[-1][2] is WebShellCloseReason.START_FAILED
    assert any(message.get("code") == "web_shell_unavailable" for message in websocket.messages)


@pytest.mark.asyncio
async def test_manager_consumes_ticket_before_accepting_websocket(tmp_path: Path) -> None:
    _service, unit, _repository, principal, _host_value, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    claim = AsyncMock(side_effect=WebShellSessionExpiredError())
    manager._service = cast(Any, SimpleNamespace(claim=claim))
    websocket = _FakeWebSocket()

    await manager.stream(cast(Any, websocket), uuid4(), principal)

    assert websocket.closed == (4408, "web_shell_session_expired")
    assert not websocket.messages


@pytest.mark.asyncio
async def test_manager_resize_protocol_enforces_bounds(tmp_path: Path) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    terminal = _FakeTerminal()
    active = ActiveWebShell(
        session=_session(host, principal),
        terminal=cast(Any, terminal),
        owner_id="owner",
        started_monotonic=0,
        last_activity_monotonic=0,
        last_activity_at=utc_now(),
    )
    websocket = _FakeWebSocket()
    websocket.application_state = WebSocketState.CONNECTED

    assert (
        await manager._handle_control(
            cast(Any, websocket), active, '{"type":"resize","columns":120,"rows":40}'
        )
        is None
    )
    assert terminal.resizes == [(120, 40)]
    assert (
        await manager._handle_control(
            cast(Any, websocket), active, '{"type":"resize","columns":10,"rows":40}'
        )
        is WebShellCloseReason.PROTOCOL_ERROR
    )
    assert websocket.messages[-1]["code"] == "web_shell_protocol_error"


def test_web_shell_limits_are_validated_together() -> None:
    settings = Settings(
        web_shell_max_sessions=50,
        web_shell_idle_timeout_seconds=300,
        web_shell_max_duration_seconds=300,
    )
    assert settings.web_shell_max_sessions == 50
    with pytest.raises(PydanticValidationError, match="greater than or equal"):
        Settings(
            web_shell_idle_timeout_seconds=600,
            web_shell_max_duration_seconds=300,
        )


@pytest.mark.asyncio
async def test_manager_lifecycle_create_and_close_active_session(tmp_path: Path) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    session = _session(host, principal, state=WebShellState.ACTIVE, owner_id="owner")
    lifecycle = SimpleNamespace(
        recover_stale=AsyncMock(return_value=2),
        create=AsyncMock(return_value=session),
        request_close=AsyncMock(),
    )
    manager._service = cast(Any, lifecycle)
    terminal = _FakeTerminal()
    finished = asyncio.Event()
    finished.set()
    active = ActiveWebShell(
        session=session,
        terminal=cast(Any, terminal),
        owner_id="owner",
        started_monotonic=0,
        last_activity_monotonic=0,
        last_activity_at=utc_now(),
        finished=finished,
    )
    manager._active[session.web_shell_session_id] = active

    await manager.start()
    assert await manager.create(host.host_id, principal) == session
    await manager.request_close(session.web_shell_session_id, principal)
    await manager.stop()

    lifecycle.recover_stale.assert_awaited_once()
    lifecycle.create.assert_awaited_once_with(host.host_id, principal, manager.instance_id)
    lifecycle.request_close.assert_awaited_once_with(session.web_shell_session_id, principal)
    assert active.requested_close_reason is WebShellCloseReason.SERVER_SHUTDOWN
    assert terminal.closed


class _ScriptedTerminal(_FakeTerminal):
    def __init__(self, reads: list[bytes] | None = None) -> None:
        super().__init__()
        self.reads = list(reads or [])
        self.writes: list[bytes] = []
        self.wait_forever = asyncio.Event()

    async def read(self, _maximum: int) -> bytes:
        if self.reads:
            return self.reads.pop(0)
        await self.wait_forever.wait()
        return b""

    async def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def wait(self) -> int:
        await self.wait_forever.wait()
        return self.returncode or 0


class _ScriptedWebSocket(_FakeWebSocket):
    def __init__(self, incoming: list[dict[str, object] | BaseException] | None = None) -> None:
        super().__init__()
        self.application_state = WebSocketState.CONNECTED
        self.incoming = list(incoming or [])
        self.binary_messages: list[bytes] = []
        self.block_sends = False

    async def receive(self) -> dict[str, object]:
        if not self.incoming:
            await AsyncIteratorNever()
            raise AssertionError("unreachable")
        value = self.incoming.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    async def send_bytes(self, value: bytes) -> None:
        if self.block_sends:
            await AsyncIteratorNever()
        self.binary_messages.append(value)


def _active_session(
    host: Host,
    principal: SessionPrincipal,
    terminal: _FakeTerminal,
) -> ActiveWebShell:
    now = time.monotonic()
    return ActiveWebShell(
        session=_session(host, principal, state=WebShellState.ACTIVE, owner_id="owner"),
        terminal=cast(Any, terminal),
        owner_id="owner",
        started_monotonic=now,
        last_activity_monotonic=now,
        last_activity_at=utc_now(),
    )


@pytest.mark.asyncio
async def test_manager_pumps_binary_input_output_and_control_frames(tmp_path: Path) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    output_terminal = _ScriptedTerminal([b"first", b"second", b""])
    output_socket = _ScriptedWebSocket()
    output_active = _active_session(host, principal, output_terminal)
    assert (
        await manager._pump_output(cast(Any, output_socket), output_active)
        is WebShellCloseReason.REMOTE_EXIT
    )
    assert output_socket.binary_messages == [b"first", b"second"]

    input_terminal = _ScriptedTerminal()
    input_socket = _ScriptedWebSocket(
        [
            {"type": "websocket.receive", "bytes": b"whoami\r"},
            {
                "type": "websocket.receive",
                "text": '{"type":"resize","columns":132,"rows":43}',
            },
            {"type": "websocket.receive", "text": '{"type":"close"}'},
        ]
    )
    input_active = _active_session(host, principal, input_terminal)
    assert (
        await manager._pump_input(cast(Any, input_socket), input_active)
        is WebShellCloseReason.USER_REQUESTED
    )
    assert input_terminal.writes == [b"whoami\r"]
    assert input_terminal.resizes == [(132, 43)]


@pytest.mark.asyncio
async def test_manager_rejects_invalid_frames_and_slow_consumers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    terminal = _ScriptedTerminal()
    active = _active_session(host, principal, terminal)

    oversized = _ScriptedWebSocket(
        [{"type": "websocket.receive", "bytes": b"x" * (64 * 1024 + 1)}]
    )
    assert (
        await manager._pump_input(cast(Any, oversized), active)
        is WebShellCloseReason.PROTOCOL_ERROR
    )
    assert oversized.messages[-1]["code"] == "web_shell_frame_too_large"

    disconnected = _ScriptedWebSocket(
        [{"type": "websocket.disconnect"}]
    )
    assert (
        await manager._pump_input(cast(Any, disconnected), active)
        is WebShellCloseReason.CLIENT_DISCONNECTED
    )
    raised = _ScriptedWebSocket([WebSocketDisconnect()])
    assert (
        await manager._pump_input(cast(Any, raised), active)
        is WebShellCloseReason.CLIENT_DISCONNECTED
    )

    for control in ("not-json", "[]", '{"type":"unknown"}'):
        assert (
            await manager._handle_control(cast(Any, oversized), active, control)
            is WebShellCloseReason.PROTOCOL_ERROR
        )
    assert (
        await manager._handle_control(
            cast(Any, oversized),
            active,
            '{"type":"resize","columns":true,"rows":40}',
        )
        is WebShellCloseReason.PROTOCOL_ERROR
    )

    slow_terminal = _ScriptedTerminal([b"output"])
    slow_socket = _ScriptedWebSocket()
    slow_socket.block_sends = True
    monkeypatch.setattr(
        "ops_composer.web_shell_manager.WEB_SHELL_SEND_TIMEOUT_SECONDS", 0.001
    )
    assert (
        await manager._pump_output(
            cast(Any, slow_socket), _active_session(host, principal, slow_terminal)
        )
        is WebShellCloseReason.SLOW_CONSUMER
    )


@pytest.mark.asyncio
async def test_manager_monitor_covers_shutdown_timeouts_auth_and_database_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    settings = Settings(
        app_env="test",
        master_key=MASTER_KEY,
        runtime_dir=tmp_path,
        web_shell_idle_timeout_seconds=60,
        web_shell_max_duration_seconds=300,
    )
    manager = WebShellManager(cast(UnitOfWorkFactory, _Factory(unit)), settings, cipher)

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("ops_composer.web_shell_manager.asyncio.sleep", no_sleep)
    terminal = _ScriptedTerminal()

    active = _active_session(host, principal, terminal)
    manager._shutdown.set()
    assert (
        await manager._monitor(active, "owner")
        is WebShellCloseReason.SERVER_SHUTDOWN
    )
    manager._shutdown.clear()

    active = _active_session(host, principal, terminal)
    active.started_monotonic -= 301
    assert await manager._monitor(active, "owner") is WebShellCloseReason.MAX_DURATION

    active = _active_session(host, principal, terminal)
    active.last_activity_monotonic -= 61
    assert await manager._monitor(active, "owner") is WebShellCloseReason.IDLE_TIMEOUT

    active = _active_session(host, principal, terminal)
    manager._service = cast(
        Any, SimpleNamespace(heartbeat=AsyncMock(side_effect=RuntimeError("database down")))
    )
    assert (
        await manager._monitor(active, "owner")
        is WebShellCloseReason.DATABASE_UNAVAILABLE
    )

    active = _active_session(host, principal, terminal)
    manager._service = cast(
        Any,
        SimpleNamespace(
            heartbeat=AsyncMock(return_value=WebShellCloseReason.AUTH_SESSION_INVALID)
        ),
    )
    assert (
        await manager._monitor(active, "owner")
        is WebShellCloseReason.AUTH_SESSION_INVALID
    )


@pytest.mark.asyncio
async def test_manager_selects_each_stream_completion_reason(tmp_path: Path) -> None:
    _service, unit, _repository, principal, host, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )

    async def blocked(*_args: object) -> WebShellCloseReason:
        await asyncio.Event().wait()
        return WebShellCloseReason.CLIENT_DISCONNECTED

    for winner, expected in (
        ("monitor", WebShellCloseReason.IDLE_TIMEOUT),
        ("input", WebShellCloseReason.USER_REQUESTED),
        ("output", WebShellCloseReason.SLOW_CONSUMER),
    ):
        terminal = _ScriptedTerminal()
        active = _active_session(host, principal, terminal)

        async def completed(
            *_args: object, expected_reason: WebShellCloseReason = expected
        ) -> WebShellCloseReason:
            return expected_reason

        manager._pump_output = cast(Any, completed if winner == "output" else blocked)
        manager._pump_input = cast(Any, completed if winner == "input" else blocked)
        manager._monitor = cast(Any, completed if winner == "monitor" else blocked)
        reason, exit_code = await manager._serve(cast(Any, _FakeWebSocket()), active, "owner")
        assert reason is expected
        assert exit_code is None

    terminal = _ScriptedTerminal()
    active = _active_session(host, principal, terminal)
    active.requested_close_reason = WebShellCloseReason.USER_REQUESTED

    async def remote_exit(*_args: object) -> WebShellCloseReason:
        return WebShellCloseReason.REMOTE_EXIT

    manager._pump_output = cast(Any, remote_exit)
    manager._pump_input = cast(Any, blocked)
    manager._monitor = cast(Any, blocked)
    reason, _ = await manager._serve(cast(Any, _FakeWebSocket()), active, "owner")
    assert reason is WebShellCloseReason.USER_REQUESTED


@pytest.mark.asyncio
async def test_manager_rejects_unexpected_preclaim_failure(
    tmp_path: Path,
) -> None:
    _service, unit, _repository, principal, _host_value, cipher = _service_fixture()
    manager = WebShellManager(
        cast(UnitOfWorkFactory, _Factory(unit)),
        Settings(app_env="test", master_key=MASTER_KEY, runtime_dir=tmp_path),
        cipher,
    )
    manager._service = cast(
        Any, SimpleNamespace(claim=AsyncMock(side_effect=RuntimeError("database unavailable")))
    )
    websocket = _FakeWebSocket()

    await manager.stream(cast(Any, websocket), uuid4(), principal)

    assert websocket.closed == (4408, "web_shell_unavailable")
    assert not websocket.messages
