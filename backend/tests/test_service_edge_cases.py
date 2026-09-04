from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI

import ops_composer.main as main_module
import ops_composer.services.assets as assets_module
from ops_composer.domain.audit import AuditAction, AuditEventDraft
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    ClaimCollisionError,
    ConflictError,
    NotFoundError,
    RunNotCancelableError,
    ValidationError,
)
from ops_composer.domain.ops import (
    CommandMode,
    Credential,
    CredentialRevision,
    CredentialType,
    Host,
    HostGroup,
    Playbook,
    PlaybookReference,
    PlaybookSource,
    ResolvedHost,
    Run,
    RunEvent,
    RunKind,
    RunStatus,
    RunTarget,
    RunTargetStatus,
    TargetKind,
)
from ops_composer.services.assets import (
    AssetService,
    CredentialService,
    _validate_address,
    _validate_variables,
)
from ops_composer.services.crypto import CredentialCipher
from ops_composer.services.runs import RunService, WorkerCoordinator, _safe_operation_metadata
from ops_composer.services.system import SystemService
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


class _Context:
    def __init__(self, unit: object) -> None:
        self.unit = unit

    async def __aenter__(self) -> object:
        return self.unit

    async def __aexit__(self, *_args: object) -> None:
        return None


class _Factory:
    def __init__(self, unit: object) -> None:
        self.unit = unit

    def __call__(self) -> _Context:
        return _Context(self.unit)


class _AuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEventDraft] = []

    async def append(self, event: AuditEventDraft) -> AuditEventDraft:
        self.events.append(event)
        return event


def _factory(*, assets: object | None = None, runs: object | None = None) -> _Factory:
    unit = SimpleNamespace(
        assets=assets or SimpleNamespace(),
        runs=runs or SimpleNamespace(),
        audit=_AuditRepository(),
        health=SimpleNamespace(is_ready=AsyncMock(return_value=True)),
    )
    return _Factory(unit)


def _cipher() -> CredentialCipher:
    key = base64.b64encode(b"service-edge-key" * 2).decode()
    return CredentialCipher(key, 1)


def _credential(*, enabled: bool = True, version: int = 1) -> Credential:
    now = utc_now()
    return Credential(
        credential_id=uuid4(),
        name="production-password",
        credential_type=CredentialType.PASSWORD,
        username="root",
        public_config={"becomeEnabled": False},
        current_version=version,
        enabled=enabled,
        description="test",
        created_at=now,
        updated_at=now,
    )


def _host(credential_id: UUID | None = None) -> Host:
    now = utc_now()
    return Host(
        host_id=uuid4(),
        name="worker-01",
        address="192.0.2.20",
        ssh_port=22,
        credential_id=credential_id or uuid4(),
        python_interpreter="/usr/bin/python3",
        enabled=True,
        description="test",
        variables={},
        version=1,
        created_at=now,
        updated_at=now,
    )


def _group(host_id: UUID | None = None) -> HostGroup:
    now = utc_now()
    return HostGroup(
        group_id=uuid4(),
        name="workers",
        description="test",
        variables={},
        host_ids=(host_id,) if host_id else (),
        created_at=now,
        updated_at=now,
    )


def _resolved_host() -> ResolvedHost:
    return ResolvedHost(
        host_id=uuid4(),
        name="worker-01",
        address="192.0.2.20",
        ssh_port=22,
        credential_id=uuid4(),
        credential_version=1,
        credential_username="root",
    )


def _run(host: ResolvedHost, *, status: RunStatus = RunStatus.QUEUED) -> Run:
    now = utc_now()
    return Run(
        run_id=uuid4(),
        kind=RunKind.COMMAND,
        status=status,
        target_spec={"kind": "HOSTS", "hostIds": [str(host.host_id)]},
        resolved_targets=[
            {
                "hostId": str(host.host_id),
                "name": host.name,
                "address": host.address,
                "sshPort": host.ssh_port,
                "credentialId": str(host.credential_id),
                "credentialVersion": host.credential_version,
            }
        ],
        operation_spec={"mode": "COMMAND", "command": "true"},
        inventory_snapshot={"all": {"hosts": {host.name: {}}}},
        credential_versions={str(host.credential_id): 1},
        timeout_seconds=30,
        forks=1,
        requested_by=uuid4(),
        idempotency_key="service-edge-run",
        request_fingerprint="b" * 64,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_credential_service_rejects_invalid_inputs_versions_and_missing_rows() -> None:
    repository = SimpleNamespace(
        list_credentials=AsyncMock(return_value=()),
        get_setting=AsyncMock(return_value={"version": 2, "envelope": "invalid"}),
        get_credential=AsyncMock(return_value=None),
        get_credential_revision=AsyncMock(return_value=None),
        delete_credential=AsyncMock(return_value=True),
        add_credential=AsyncMock(),
        rotate_credential=AsyncMock(return_value=None),
    )
    factory = _factory(assets=repository)
    service = CredentialService(cast(UnitOfWorkFactory, factory), _cipher())

    assert await service.list() == ()
    with pytest.raises(ValueError, match="metadata is invalid"):
        await service.ensure_master_key()
    with pytest.raises(NotFoundError):
        await service.get(uuid4())
    for values in (
        {"name": "", "username": "root", "password": "secret", "become_method": "sudo"},
        {"name": "name", "username": "root", "password": "secret", "become_method": "wheel"},
    ):
        with pytest.raises(ValidationError):
            await service.create(
                **values,
                become_password=None,
                become_enabled=False,
                become_user="root",
                description="",
            )
    with pytest.raises(ValidationError, match="password is required"):
        await service.rotate(uuid4(), password="", become_password=None)
    with pytest.raises(NotFoundError):
        await service.rotate(uuid4(), password="new", become_password=None)
    with pytest.raises(NotFoundError, match="revision"):
        await service.decrypt_revision(uuid4(), 1)

    credential = _credential()
    repository.get_credential.return_value = credential
    revision = CredentialRevision(
        credential_id=credential.credential_id,
        version=1,
        encrypted_secret=b"not-used",
        encryption_key_version=2,
        created_at=utc_now(),
    )
    repository.get_credential_revision.return_value = revision
    with pytest.raises(ValidationError, match="key version"):
        await service.decrypt_revision(credential.credential_id, 1)

    await service.delete(credential.credential_id)
    assert factory.unit.audit.events[-1].event_action is AuditAction.CREDENTIAL_DELETED
    repository.delete_credential.return_value = False
    with pytest.raises(ConflictError):
        await service.delete(credential.credential_id)


@pytest.mark.asyncio
async def test_asset_service_validates_mutations_memberships_and_empty_targets() -> None:
    credential = _credential()
    host = _host(credential.credential_id)
    group = _group(host.host_id)
    repository = SimpleNamespace(
        get_credential=AsyncMock(return_value=credential),
        get_host=AsyncMock(return_value=host),
        update_host=AsyncMock(return_value=None),
        delete_host=AsyncMock(return_value=True),
        list_hosts=AsyncMock(return_value=(host,)),
        get_group=AsyncMock(return_value=group),
        update_group=AsyncMock(return_value=None),
        delete_group=AsyncMock(return_value=True),
        resolve_all_hosts=AsyncMock(return_value=()),
        resolve_host_ids=AsyncMock(return_value=()),
        resolve_group_hosts=AsyncMock(return_value=()),
        list_host_keys=AsyncMock(return_value=()),
    )
    factory = _factory(assets=repository)
    service = AssetService(cast(UnitOfWorkFactory, factory))

    with pytest.raises(ValidationError):
        _validate_variables({"ansible_password": "forbidden"})
    with pytest.raises(ValidationError, match="IPv4"):
        _validate_address("not a host name")
    assert _validate_address(" 2001:db8::1 ") == "2001:db8::1"

    with pytest.raises(ValidationError, match="host name"):
        await service.create_host(
            name="invalid host",
            address="192.0.2.1",
            ssh_port=22,
            credential_id=credential.credential_id,
            python_interpreter=None,
            enabled=True,
            description="",
            variables={},
        )
    repository.get_credential.return_value = None
    with pytest.raises(ValidationError, match="credential"):
        await service.create_host(
            name="valid-host",
            address="192.0.2.1",
            ssh_port=22,
            credential_id=credential.credential_id,
            python_interpreter=None,
            enabled=True,
            description="",
            variables={},
        )
    repository.get_credential.return_value = credential

    repository.get_host.return_value = None
    with pytest.raises(NotFoundError):
        await service.update_host(host.host_id, expected_version=1, name="valid")
    repository.get_host.return_value = host
    with pytest.raises(ValidationError, match="object"):
        await service.update_host(host.host_id, expected_version=1, variables="invalid")
    with pytest.raises(ValidationError, match="host name"):
        await service.update_host(host.host_id, expected_version=1, name="invalid host")
    with pytest.raises(ConflictError, match="modified"):
        await service.update_host(host.host_id, expected_version=1, name="valid-host")

    await service.delete_host(host.host_id)
    repository.delete_host.return_value = False
    with pytest.raises(ConflictError):
        await service.delete_host(host.host_id)

    with pytest.raises(ValidationError, match="group name"):
        await service.create_group(name="invalid group", description="", variables={}, host_ids=())
    with pytest.raises(ValidationError, match="duplicate"):
        await service._validate_host_ids(repository, (host.host_id, host.host_id))
    with pytest.raises(ValidationError, match="unknown"):
        await service._validate_host_ids(repository, (uuid4(),))

    repository.get_group.return_value = None
    with pytest.raises(NotFoundError):
        await service.update_group(
            group.group_id,
            name="workers",
            description="",
            variables={},
            host_ids=(),
        )
    repository.get_group.return_value = group
    with pytest.raises(NotFoundError):
        await service.update_group(
            group.group_id,
            name="workers",
            description="",
            variables={},
            host_ids=(host.host_id,),
        )
    await service.delete_group(group.group_id)
    repository.delete_group.return_value = False
    with pytest.raises(NotFoundError):
        await service.delete_group(group.group_id)

    with pytest.raises(ValidationError, match="at least one"):
        await service.resolve(target_kind=TargetKind.HOSTS)
    with pytest.raises(ValidationError, match="missing"):
        await service.resolve(target_kind=TargetKind.HOSTS, host_ids=(host.host_id,))
    repository.get_group.return_value = None
    with pytest.raises(NotFoundError, match="group"):
        await service.resolve(target_kind=TargetKind.GROUP, group_id=group.group_id)
    with pytest.raises(ValidationError, match="groupId"):
        await service.resolve(target_kind=TargetKind.GROUP)
    with pytest.raises(ValidationError, match="no enabled"):
        await service.resolve(target_kind=TargetKind.ALL)

    repository.get_host.return_value = None
    with pytest.raises(NotFoundError):
        await service.list_host_keys(host.host_id)


@pytest.mark.asyncio
async def test_host_key_scan_handles_valid_empty_unusable_and_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _host()
    service = AssetService(cast(UnitOfWorkFactory, object()))
    audit_events: list[AuditEventDraft] = []

    async def get_host(_host_id: UUID) -> Host:
        return host

    class _Audit:
        def __init__(self, _factory: object) -> None:
            pass

        async def record_best_effort(self, event: AuditEventDraft) -> None:
            audit_events.append(event)

    class _Process:
        output: ClassVar[bytes] = b""
        returncode: ClassVar[int] = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return self.output, b""

    async def process(*_args: object, **_kwargs: object) -> _Process:
        return _Process()

    monkeypatch.setattr(service, "get_host", get_host)
    monkeypatch.setattr(assets_module, "AuditService", _Audit)
    monkeypatch.setattr(assets_module.asyncio, "create_subprocess_exec", process)
    key = base64.b64encode(b"host-key-material").decode()
    _Process.output = (
        b"# comment\nmalformed\nexample ssh-rsa a\n"
        + f"example ssh-ed25519 {key}\n".encode()
    )
    result = await service.scan_host_keys(host.host_id)
    assert result[0]["algorithm"] == "ssh-ed25519"
    assert result[0]["fingerprint"].startswith("SHA256:")

    _Process.output = b""
    with pytest.raises(ValidationError, match="no keys"):
        await service.scan_host_keys(host.host_id)

    _Process.output = b"# comment\nexample ssh-rsa a\n"
    with pytest.raises(ValidationError, match="usable"):
        await service.scan_host_keys(host.host_id)

    async def missing_binary(*_args: object, **_kwargs: object) -> _Process:
        raise FileNotFoundError

    monkeypatch.setattr(assets_module.asyncio, "create_subprocess_exec", missing_binary)
    with pytest.raises(ValidationError, match="scan failed"):
        await service.scan_host_keys(host.host_id)
    assert AuditAction.HOST_KEY_SCAN_SUCCEEDED in {
        event.event_action for event in audit_events
    }
    assert AuditAction.HOST_KEY_SCAN_FAILED in {event.event_action for event in audit_events}


class _RunRepository:
    def __init__(self, run: Run | None = None) -> None:
        self.run = run
        self.targets_value: tuple[RunTarget, ...] = ()
        self.created: Run | None = None
        self.events: list[RunEvent] = []
        self.cancel_result: Run | None = None
        self.finish_result: Run | None = run
        self.claim_error: Exception | None = None

    async def get_by_idempotency_key(
        self, requested_by: UUID, idempotency_key: str
    ) -> Run | None:
        if (
            self.run is not None
            and self.run.requested_by == requested_by
            and self.run.idempotency_key == idempotency_key
        ):
            return self.run
        return None

    async def create_or_get(
        self, run: Run, targets: tuple[RunTarget, ...]
    ) -> tuple[Run, bool]:
        self.created = run
        self.targets_value = targets
        return run, True

    async def append_event(self, event: RunEvent) -> RunEvent:
        self.events.append(event)
        return event

    async def get(self, _run_id: UUID) -> Run | None:
        return self.run

    async def targets(self, _run_id: UUID) -> tuple[RunTarget, ...]:
        return self.targets_value

    async def list(self, *, limit: int, offset: int) -> tuple[Run, ...]:
        assert limit >= 0 and offset >= 0
        return (self.run,) if self.run else ()

    async def request_cancel(self, _run_id: UUID, _now: object) -> Run | None:
        return self.cancel_result

    async def events_after(
        self, _run_id: UUID, _sequence: int, _limit: int
    ) -> tuple[RunEvent, ...]:
        return tuple(self.events)

    async def dashboard(self) -> dict[str, object]:
        return {"runsToday": len(self.events)}

    async def heartbeat(self, *_args: object) -> None:
        return None

    async def claim_next(self, *_args: object) -> Run | None:
        if self.claim_error is not None:
            raise self.claim_error
        return self.run

    async def mark_running(self, *_args: object) -> None:
        return None

    async def cancellation_requested(self, _run_id: UUID) -> bool:
        return True

    async def finish_target(self, *_args: object) -> None:
        return None

    async def finish(self, *_args: object) -> Run | None:
        return self.finish_result

    async def recover_stale(self, *_args: object) -> int:
        return 0


@pytest.mark.asyncio
async def test_run_service_validates_creates_queries_and_cancels(tmp_path: Path) -> None:
    host = _resolved_host()
    repository = _RunRepository()
    assets = SimpleNamespace(
        resolve_host_ids=AsyncMock(return_value=(host,)),
        resolve_all_hosts=AsyncMock(return_value=(host,)),
        get_group=AsyncMock(return_value=object()),
        resolve_group_hosts=AsyncMock(return_value=(host,)),
        host_ids_without_keys=AsyncMock(return_value=()),
    )
    factory = _factory(assets=assets, runs=repository)
    playbook = Playbook(
        path="playbooks/site.yml",
        name="Site",
        size=42,
        modified_at=utc_now(),
        sha256="c" * 64,
    )

    class _Playbooks:
        async def get(self, _path: str) -> Playbook:
            return playbook

    service = RunService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_workspace=tmp_path),
        cast(Any, _Playbooks()),
    )
    base = {
        "requested_by": uuid4(),
        "idempotency_key": "valid-idempotency",
        "target_kind": TargetKind.HOSTS,
        "host_ids": (host.host_id,),
        "group_id": None,
        "mode": CommandMode.COMMAND,
        "command": "true",
        "become": "CREDENTIAL_DEFAULT",
        "shell_confirmed": False,
        "timeout_seconds": 30,
        "forks": 1,
    }
    for changes in (
        {"command": ""},
        {"command": "x\0y"},
        {"mode": CommandMode.SHELL},
        {"become": "INVALID"},
        {"timeout_seconds": 0},
        {"forks": 21},
        {"idempotency_key": "short"},
    ):
        arguments = {**base, **changes}
        with pytest.raises(ValidationError):
            await service.create_command(**arguments)

    ping = await service.create_ping(
        requested_by=cast(UUID, base["requested_by"]),
        idempotency_key="ping-idempotency",
        host_id=host.host_id,
    )
    assert ping.kind is RunKind.PING
    playbook_run = await service.create_playbook(
        requested_by=cast(UUID, base["requested_by"]),
        idempotency_key="playbook-idempotency",
        target_kind=TargetKind.ALL,
        host_ids=(),
        group_id=None,
        playbook=PlaybookReference(source=PlaybookSource.MOUNT, path=playbook.path),
        extra_vars={"region": "test", "nested": [1, 2]},
        tags=("safe",),
        skip_tags=(),
        timeout_seconds=60,
        forks=2,
    )
    assert playbook_run.kind is RunKind.PLAYBOOK
    with pytest.raises(ValidationError, match="outside"):
        await service.create_playbook(
            requested_by=cast(UUID, base["requested_by"]),
            idempotency_key="invalid-playbook",
            target_kind=TargetKind.ALL,
            host_ids=(),
            group_id=None,
            playbook=PlaybookReference(source=PlaybookSource.MOUNT, path=playbook.path),
            extra_vars={},
            tags=(),
            skip_tags=(),
            timeout_seconds=0,
            forks=1,
        )
    assert _safe_operation_metadata(RunKind.PING, {}) == {"module": "ansible.builtin.ping"}
    assert _safe_operation_metadata(
        RunKind.PLAYBOOK,
        {"playbookPath": playbook.path, "extraVars": [], "tags": "bad", "skipTags": []},
    )["variable_names"] == []

    repository.run = ping
    assert await service.get(ping.run_id) is ping
    assert (await service.detail(ping.run_id))[0] is ping
    assert await service.list(limit=20, offset=0) == (ping,)
    assert await service.dashboard() == {"runsToday": len(repository.events)}
    assert await service.events_after(ping.run_id, 0) == tuple(repository.events)

    repository.cancel_result = ping.model_copy(
        update={"status": RunStatus.CANCELED, "cancel_requested_at": utc_now()}
    )
    canceled = await service.cancel(ping.run_id, requested_by=ping.requested_by)
    assert canceled.status is RunStatus.CANCELED
    repository.run = ping.model_copy(update={"status": RunStatus.SUCCEEDED})
    with pytest.raises(RunNotCancelableError):
        await service.cancel(ping.run_id, requested_by=ping.requested_by)
    repository.run = None
    with pytest.raises(NotFoundError):
        await service.get(ping.run_id)
    with pytest.raises(NotFoundError):
        await service.detail(ping.run_id)
    with pytest.raises(NotFoundError):
        await service.events_after(ping.run_id, 0)
    with pytest.raises(NotFoundError):
        await service.cancel(ping.run_id, requested_by=ping.requested_by)


@pytest.mark.asyncio
async def test_run_target_resolution_retry_and_worker_coordination_failures() -> None:
    host = _resolved_host()
    run = _run(host, status=RunStatus.FAILED)
    repository = _RunRepository(run)
    assets = SimpleNamespace(
        resolve_all_hosts=AsyncMock(return_value=()),
        resolve_host_ids=AsyncMock(return_value=()),
        get_group=AsyncMock(return_value=None),
        resolve_group_hosts=AsyncMock(return_value=()),
    )
    factory = _factory(assets=assets, runs=repository)
    service = RunService(cast(UnitOfWorkFactory, factory), Settings())

    for target_kind, host_ids, group_id in (
        (TargetKind.ALL, (), None),
        (TargetKind.HOSTS, (), None),
        (TargetKind.HOSTS, (host.host_id,), None),
        (TargetKind.GROUP, (), uuid4()),
        (TargetKind.GROUP, (), None),
    ):
        with pytest.raises((ValidationError, NotFoundError)):
            await service._resolve(
                cast(Any, factory.unit),
                target_kind=target_kind,
                host_ids=host_ids,
                group_id=group_id,
            )

    with pytest.raises(ValidationError, match="snapshot"):
        await service.retry(
            run.run_id,
            requested_by=run.requested_by,
            idempotency_key="retry-idempotency",
        )
    repository.run = None
    with pytest.raises(NotFoundError):
        await service.retry(
            run.run_id,
            requested_by=run.requested_by,
            idempotency_key="retry-idempotency",
        )

    repository.run = run
    coordinator = WorkerCoordinator(cast(UnitOfWorkFactory, factory), Settings(), "worker-edge")
    repository.claim_error = ClaimCollisionError()
    assert await coordinator.claim() is None
    repository.claim_error = None
    repository.run = None
    assert await coordinator.claim() is None

    long_output = "界" * 600
    event = await coordinator.append_event(run.run_id, event_type="stdout", stdout=long_output)
    assert event.stdout is not None
    assert len(event.stdout.encode()) <= Settings().max_event_output_bytes
    assert await coordinator.cancellation_requested(run.run_id)
    await coordinator.mark_running(run.run_id)
    await coordinator.finish_target(
        run.run_id,
        uuid4(),
        host_id=host.host_id,
        host_name=host.name,
        status=RunTargetStatus.FAILED,
        return_code=2,
        stdout="failed",
        stderr="",
        result={},
        output_truncated=False,
        changed_count=0,
        failed_count=1,
        unreachable_count=0,
    )
    repository.finish_result = None
    with pytest.raises(RuntimeError, match="no longer owns"):
        await coordinator.finish(
            run.run_id,
            status=RunStatus.FAILED,
            return_code=2,
            summary={"failed": 1},
            failure_code="FAILED",
        )


@pytest.mark.asyncio
async def test_system_doctor_and_application_lifespan_failure_stages(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    factory = _factory()
    (tmp_path / "playbooks").mkdir()
    service = SystemService(
        cast(UnitOfWorkFactory, factory), Settings(playbook_workspace=tmp_path)
    )
    report = await service.doctor()
    assert report["database"] == {"ok": True}
    assert cast(dict[str, object], report["playbookWorkspace"])["ok"]
    factory.unit.health.is_ready.side_effect = ConnectionError("offline")
    assert (await service.doctor())["database"] == {"ok": False}

    class _Pool:
        def __init__(self, open_error: Exception | None = None) -> None:
            self.open_error = open_error
            self.closed = False

        async def open(self) -> None:
            if self.open_error:
                raise self.open_error

        async def close(self) -> None:
            self.closed = True

        def connection(self) -> _Context:
            return _Context(object())

    class _Migration:
        failure: ClassVar[Exception | None] = None

        def __init__(self, *_args: object) -> None:
            pass

        async def validate_current(self) -> None:
            if self.failure:
                raise self.failure

    class _Credential:
        failure: ClassVar[Exception | None] = None

        def __init__(self, *_args: object) -> None:
            pass

        async def ensure_master_key(self) -> None:
            if self.failure:
                raise self.failure

    class _Audit:
        events: ClassVar[list[AuditEventDraft]] = []

        def __init__(self, _factory: object) -> None:
            pass

        async def record_best_effort(self, event: AuditEventDraft) -> None:
            self.events.append(event)

    pools: list[_Pool] = []

    def create_pool(_url: str) -> _Pool:
        pool = _Pool()
        pools.append(pool)
        return pool

    monkeypatch.setattr(main_module, "get_settings", lambda: Settings(runtime_dir=tmp_path / "ok"))
    monkeypatch.setattr(main_module, "create_pool", create_pool)
    monkeypatch.setattr(main_module, "MigrationRunner", _Migration)
    monkeypatch.setattr(main_module, "CredentialService", _Credential)
    monkeypatch.setattr(main_module, "AuditService", _Audit)

    _Migration.failure = RuntimeError("migration mismatch")
    with pytest.raises(RuntimeError, match="migration mismatch"):
        async with main_module.lifespan(FastAPI()):
            pass
    assert pools[-1].closed

    _Migration.failure = None
    _Credential.failure = ValueError("master key mismatch")
    with pytest.raises(ValueError, match="master key mismatch"):
        async with main_module.lifespan(FastAPI()):
            pass
    assert pools[-1].closed

    _Credential.failure = None
    runtime_file = tmp_path / "runtime-file"
    runtime_file.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(
        main_module,
        "get_settings",
        lambda: Settings(runtime_dir=runtime_file),
    )
    with pytest.raises(OSError):
        async with main_module.lifespan(FastAPI()):
            pass
    assert pools[-1].closed
    actions = {event.event_action for event in _Audit.events}
    assert AuditAction.MASTER_KEY_VALIDATION_FAILED in actions
    assert AuditAction.RUNTIME_DIRECTORY_FAILED in actions

    unavailable = _Pool(ConnectionError("offline"))
    monkeypatch.setattr(main_module, "create_pool", lambda _url: unavailable)
    with pytest.raises(ConnectionError):
        async with main_module.lifespan(FastAPI()):
            pass


def test_create_app_mounts_existing_frontend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "index.html").write_text("<main>OpsComposer</main>", encoding="utf-8")
    monkeypatch.setattr(main_module, "get_settings", lambda: Settings(static_dir=tmp_path))
    application = main_module.create_app()
    assert any(getattr(route, "name", None) == "frontend" for route in application.routes)
