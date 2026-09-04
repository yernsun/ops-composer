from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import stat
from collections.abc import Callable
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any, ClassVar, cast
from uuid import UUID, uuid4

import pytest

import ops_composer.worker as worker_module
from ops_composer.domain.audit import AuditAction, AuditEventDraft, AuditOutcome
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import HostKeyConfirmationRequiredError, NotFoundError
from ops_composer.domain.ops import (
    HostKey,
    PlaybookRevision,
    PlaybookSource,
    ResolvedHost,
    Run,
    RunKind,
    RunStatus,
    RunTarget,
    RunTargetStatus,
)
from ops_composer.services.inventory import build_inventory
from ops_composer.settings import Settings
from ops_composer.worker import (
    AnsibleExecutor,
    _known_hosts,
    _purge_expired_audit,
    _runtime_inventory,
    execute_run,
    run_worker,
)


def _master_key() -> str:
    return base64.b64encode(b"worker-test-key!" * 2).decode()


def _host(name: str = "worker-01", *, port: int = 22, become: bool = False) -> ResolvedHost:
    return ResolvedHost(
        host_id=uuid4(),
        name=name,
        address="192.0.2.10",
        ssh_port=port,
        credential_id=uuid4(),
        credential_version=2,
        credential_username="operator",
        credential_public_config={
            "becomeEnabled": become,
            "becomeMethod": "sudo",
            "becomeUser": "root",
        },
        python_interpreter="/usr/bin/python3",
    )


def _run(
    hosts: tuple[ResolvedHost, ...],
    *,
    kind: RunKind = RunKind.COMMAND,
    operation: dict[str, object] | None = None,
    workspace_revision: str | None = None,
) -> Run:
    now = utc_now()
    if operation is None:
        operation = {"mode": "COMMAND", "command": "true", "become": "CREDENTIAL_DEFAULT"}
    return Run(
        run_id=uuid4(),
        kind=kind,
        status=RunStatus.PREPARING,
        target_spec={"kind": "HOSTS", "hostIds": [str(host.host_id) for host in hosts]},
        resolved_targets=[
            {
                "hostId": str(host.host_id),
                "name": host.name,
                "address": host.address,
                "sshPort": host.ssh_port,
                "credentialId": str(host.credential_id),
                "credentialVersion": host.credential_version,
            }
            for host in hosts
        ],
        operation_spec=operation,
        inventory_snapshot=build_inventory(hosts),
        workspace_revision=workspace_revision,
        credential_versions={str(host.credential_id): host.credential_version for host in hosts},
        timeout_seconds=30,
        forks=max(1, len(hosts)),
        requested_by=uuid4(),
        idempotency_key="worker-test-idempotency",
        request_fingerprint="a" * 64,
        created_at=now,
        updated_at=now,
    )


def _target(run: Run, host: ResolvedHost) -> RunTarget:
    return RunTarget(
        run_target_id=uuid4(),
        run_id=run.run_id,
        host_id=host.host_id,
        host_name=host.name,
        host_address=host.address,
        status=RunTargetStatus.RUNNING,
    )


def test_ansible_executor_builds_ping_command_shell_and_playbook_invocations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    playbooks = workspace / "playbooks"
    playbooks.mkdir(parents=True)
    playbook = playbooks / "site.yml"
    playbook.write_text("- hosts: all\n  gather_facts: false\n  tasks: []\n", encoding="utf-8")
    settings = Settings(playbook_workspace=workspace, runtime_dir=tmp_path / "runtime")
    calls: list[dict[str, Any]] = []

    class _Runner:
        @staticmethod
        def run(**kwargs: Any) -> object:
            calls.append(kwargs)
            return SimpleNamespace(rc=0, status="successful")

    monkeypatch.setattr(worker_module.importlib, "import_module", lambda _name: _Runner)
    executor = AnsibleExecutor(settings)
    host = _host()
    runtime = tmp_path / "private"
    inventory = runtime / "inventory.yml"
    cancel = Event()

    cases = (
        _run((host,), kind=RunKind.PING, operation={"module": "ansible.builtin.ping"}),
        _run((host,), operation={"mode": "COMMAND", "command": "uname -a"}),
        _run((host,), operation={"mode": "SHELL", "command": "printf ok"}),
        _run(
            (host,),
            kind=RunKind.PLAYBOOK,
            operation={
                "playbookPath": "playbooks/site.yml",
                "extraVars": {"region": "test"},
                "tags": ["safe", 3],
                "skipTags": "invalid-list",
            },
        ),
    )
    for run in cases:
        assert executor.run(
            run,
            inventory_path=inventory,
            runtime_path=runtime,
            cancel=cancel,
            event_handler=lambda _event: True,
        ) == (0, "successful")

    assert calls[0]["module"] == "ansible.builtin.ping"
    assert calls[0]["module_args"] == ""
    assert calls[1]["module"] == "ansible.builtin.command"
    assert json.loads(calls[1]["module_args"]) == {"cmd": "uname -a"}
    assert calls[2]["module"] == "ansible.builtin.shell"
    assert calls[3]["playbook"] == str(playbook)
    assert calls[3]["tags"] == "safe,3"
    assert calls[3]["skip_tags"] == ""
    assert calls[3]["envvars"]["ANSIBLE_HOST_KEY_CHECKING"] == "True"


@pytest.mark.asyncio
async def test_runtime_inventory_validates_snapshots_caches_secrets_and_known_hosts() -> None:
    host = _host(become=True)
    second = host.model_copy(update={"host_id": uuid4(), "name": "worker-02", "ssh_port": 2222})
    run = _run((host, second))

    class _Credentials:
        calls = 0

        async def decrypt_revision(self, _credential_id: UUID, _version: int) -> dict[str, str]:
            self.calls += 1
            return {"password": "ssh-password"}

    credentials = _Credentials()
    inventory, secrets = await _runtime_inventory(run, cast(Any, credentials))
    variables = cast(dict[str, Any], cast(dict[str, Any], inventory["all"])["hosts"])
    assert credentials.calls == 1
    assert variables[host.name]["ansible_become_password"] == "ssh-password"
    assert variables[second.name]["ansible_password"] == "ssh-password"
    assert secrets == ("ssh-password", "ssh-password")

    for invalid in ({}, {"all": {}}, {"all": {"hosts": {}}}):
        invalid_run = run.model_copy(update={"inventory_snapshot": invalid})
        with pytest.raises(ValueError, match="inventory"):
            await _runtime_inventory(invalid_run, cast(Any, _Credentials()))

    now = utc_now()
    keys = {
        host.host_id: (
            HostKey(
                host_id=host.host_id,
                algorithm="ssh-ed25519",
                public_key="AAAAC3NzaC1lZDI1NTE5AAAA",
                fingerprint="SHA256:first",
                trusted_by=uuid4(),
                trusted_at=now,
            ),
        ),
        second.host_id: (
            HostKey(
                host_id=second.host_id,
                algorithm="ssh-rsa",
                public_key="AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
                fingerprint="SHA256:second",
                trusted_by=uuid4(),
                trusted_at=now,
            ),
        ),
    }

    class _Assets:
        async def list_host_keys(self, host_id: UUID) -> tuple[HostKey, ...]:
            return keys.get(host_id, ())

    known_hosts = await _known_hosts(run, cast(Any, _Assets()))
    assert "192.0.2.10 ssh-ed25519" in known_hosts
    assert "[192.0.2.10]:2222 ssh-rsa" in known_hosts
    keys[second.host_id] = ()
    with pytest.raises(HostKeyConfirmationRequiredError, match="confirmation is required"):
        await _known_hosts(run, cast(Any, _Assets()))


class _Coordinator:
    worker_id = "worker-tests"

    def __init__(self, *, cancel: bool = False, heartbeat_error: bool = False) -> None:
        self.cancel = cancel
        self.heartbeat_error = heartbeat_error
        self.events: list[dict[str, object]] = []
        self.targets: list[dict[str, object]] = []
        self.finished: list[dict[str, object]] = []

    async def heartbeat(self, _run_id: UUID | None = None) -> None:
        if self.heartbeat_error:
            raise RuntimeError("lease update failed")

    async def cancellation_requested(self, _run_id: UUID) -> bool:
        return self.cancel

    async def mark_running(self, _run_id: UUID) -> None:
        return None

    async def append_event(self, _run_id: UUID, **values: object) -> object:
        self.events.append(values)
        return object()

    async def finish_target(self, _run_id: UUID, _target_id: UUID, **values: object) -> None:
        self.targets.append(values)

    async def finish(self, _run_id: UUID, **values: object) -> Run:
        self.finished.append(values)
        return cast(Run, object())


class _NoopAudit:
    events: ClassVar[list[AuditEventDraft]] = []

    def __init__(self, _factory: object) -> None:
        pass

    async def record_best_effort(self, event: AuditEventDraft) -> None:
        self.events.append(event)


async def _install_execution_fakes(
    monkeypatch: pytest.MonkeyPatch,
    run: Run,
    targets: tuple[RunTarget, ...],
) -> None:
    class _RunService:
        def __init__(self, *_args: object) -> None:
            pass

        async def detail(self, _run_id: UUID) -> tuple[Run, tuple[RunTarget, ...]]:
            return run, targets

    async def runtime_inventory(
        _run: Run, _credentials: object
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        return _run.inventory_snapshot, ("sentinel-run-secret",)

    async def known_hosts(_run: Run, _assets: object) -> str:
        return "192.0.2.10 ssh-ed25519 AAAA\n"

    async def inline_thread(
        function: Callable[..., tuple[int | None, str]], *args: object, **kwargs: object
    ) -> tuple[int | None, str]:
        return function(*args, **kwargs)

    monkeypatch.setattr(worker_module, "RunService", _RunService)
    monkeypatch.setattr(worker_module, "CredentialService", lambda *_args: object())
    monkeypatch.setattr(worker_module, "AssetService", lambda *_args: object())
    monkeypatch.setattr(worker_module, "AuditService", _NoopAudit)
    monkeypatch.setattr(worker_module, "_runtime_inventory", runtime_inventory)
    monkeypatch.setattr(worker_module, "_known_hosts", known_hosts)
    monkeypatch.setattr(worker_module.asyncio, "to_thread", inline_thread)


@pytest.mark.asyncio
async def test_execute_run_covers_event_states_timeout_failure_and_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hosts = (_host("ok"), _host("unreachable"), _host("failed"))
    run = _run(hosts)
    targets = tuple(_target(run, host) for host in hosts)
    await _install_execution_fakes(monkeypatch, run, targets)
    coordinator = _Coordinator()

    events: tuple[dict[str, Any], ...] = (
        {
            "event": "runner_on_skipped",
            "stdout": "sentinel-run-secret",
            "event_data": {"host": "ok", "task": "skip"},
        },
        {
            "event": "runner_on_unreachable",
            "stdout": "offline",
            "event_data": {"host": "unreachable"},
        },
        {
            "event": "runner_on_failed",
            "event_data": {"host": "failed"},
        },
        {"stdout": "orphan output", "event_data": "not-an-object"},
    )

    def timed_out(
        _executor: AnsibleExecutor,
        _run: Run,
        *,
        event_handler: Callable[[dict[str, Any]], bool],
        **_kwargs: object,
    ) -> tuple[int, str]:
        for event in events:
            event_handler(event)
        return 2, "timeout"

    monkeypatch.setattr(AnsibleExecutor, "run", timed_out)
    original_exit = worker_module.RuntimeDirectory.__exit__
    monkeypatch.setattr(worker_module.RuntimeDirectory, "__exit__", lambda *_args: None)
    settings = Settings(runtime_dir=tmp_path / "runtime", master_key=_master_key())
    await execute_run(
        run,
        factory=cast(Any, object()),
        settings=settings,
        coordinator=cast(Any, coordinator),
    )
    monkeypatch.setattr(worker_module.RuntimeDirectory, "__exit__", original_exit)

    assert coordinator.finished[-1]["status"] is RunStatus.TIMED_OUT
    assert {item["status"] for item in coordinator.targets} == {
        RunTargetStatus.SKIPPED,
        RunTargetStatus.UNREACHABLE,
        RunTargetStatus.FAILED,
    }
    assert "sentinel-run-secret" not in str(coordinator.events)
    assert any(
        event.event_action is AuditAction.RUNTIME_DIRECTORY_CLEANED
        for event in _NoopAudit.events
    )

    failing_run = _run((_host("no-events"),))
    await _install_execution_fakes(
        monkeypatch, failing_run, (_target(failing_run, _host("different")),)
    )
    failing_coordinator = _Coordinator()
    monkeypatch.setattr(AnsibleExecutor, "run", lambda *_args, **_kwargs: (2, "failed"))
    await execute_run(
        failing_run,
        factory=cast(Any, object()),
        settings=Settings(runtime_dir=tmp_path / "runtime-2", master_key=_master_key()),
        coordinator=cast(Any, failing_coordinator),
    )
    assert failing_coordinator.finished[-1]["status"] is RunStatus.FAILED


@pytest.mark.asyncio
async def test_execute_run_handles_preparation_and_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    host = _host()
    run = _run((host,))
    coordinator = _Coordinator()

    class _MissingRunService:
        def __init__(self, *_args: object) -> None:
            pass

        async def detail(self, _run_id: UUID) -> tuple[Run, tuple[RunTarget, ...]]:
            raise NotFoundError("run not found")

    monkeypatch.setattr(worker_module, "RunService", _MissingRunService)
    monkeypatch.setattr(worker_module, "CredentialService", lambda *_args: object())
    monkeypatch.setattr(worker_module, "AssetService", lambda *_args: object())
    monkeypatch.setattr(worker_module, "AuditService", _NoopAudit)
    await asyncio.wait_for(
        execute_run(
            run,
            factory=cast(Any, object()),
            settings=Settings(runtime_dir=tmp_path / "missing", master_key=_master_key()),
            coordinator=cast(Any, coordinator),
        ),
        timeout=2,
    )
    assert coordinator.finished[-1]["status"] is RunStatus.REJECTED

    canceled = _run((host,))
    await _install_execution_fakes(monkeypatch, canceled, (_target(canceled, host),))
    cancel_coordinator = _Coordinator(cancel=True)

    def waits_for_cancel(
        _executor: AnsibleExecutor,
        _run: Run,
        *,
        cancel: Event,
        **_kwargs: object,
    ) -> tuple[int, str]:
        assert cancel.wait(1)
        return 1, "canceled"

    monkeypatch.setattr(AnsibleExecutor, "run", waits_for_cancel)

    async def canceled_inline_thread(
        function: Callable[..., tuple[int | None, str]], *args: object, **kwargs: object
    ) -> tuple[int | None, str]:
        cast(Event, kwargs["cancel"]).set()
        return function(*args, **kwargs)

    monkeypatch.setattr(worker_module.asyncio, "to_thread", canceled_inline_thread)
    await asyncio.wait_for(
        execute_run(
            canceled,
            factory=cast(Any, object()),
            settings=Settings(runtime_dir=tmp_path / "cancel", master_key=_master_key()),
            coordinator=cast(Any, cancel_coordinator),
        ),
        timeout=2,
    )
    assert cancel_coordinator.finished[-1]["status"] is RunStatus.CANCELED
    assert cancel_coordinator.targets[-1]["status"] is RunTargetStatus.CANCELED


@pytest.mark.asyncio
async def test_database_playbook_worker_uses_pinned_revision_in_private_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    host = _host()
    content = (
        "---\n- name: Pinned\n  hosts: all\n  gather_facts: false\n"
        "  tasks: []\n# worker-playbook-sentinel\n"
    )
    digest = hashlib.sha256(content.encode()).hexdigest()
    playbook_id = uuid4()
    base_run = _run(
        (host,),
        kind=RunKind.PLAYBOOK,
        operation={
            "playbook": {
                "source": PlaybookSource.DATABASE.value,
                "playbookId": str(playbook_id),
                "revision": 4,
                "sha256": digest,
            },
            "extraVars": {},
            "tags": [],
            "skipTags": [],
        },
        workspace_revision=digest,
    )
    run = base_run.model_copy(
        update={"playbook_id": playbook_id, "playbook_revision": 4}
    )
    target = _target(run, host)
    await _install_execution_fakes(monkeypatch, run, (target,))
    revision = PlaybookRevision(
        playbook_id=playbook_id,
        revision=4,
        content=content,
        sha256=digest,
        size_bytes=len(content.encode()),
        validator_version="ansible-core test",
        validated_at=utc_now(),
        created_by=uuid4(),
        created_at=utc_now(),
    )

    class _Playbooks:
        async def get_revision(
            self, requested_id: UUID, requested_revision: int
        ) -> PlaybookRevision | None:
            assert (requested_id, requested_revision) == (playbook_id, 4)
            return revision

    class _Unit:
        playbooks = _Playbooks()

    class _Context:
        async def __aenter__(self) -> _Unit:
            return _Unit()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class _Factory:
        def __call__(self) -> _Context:
            return _Context()

    observed: dict[str, object] = {}

    def execute_database_playbook(
        _executor: AnsibleExecutor,
        _run: Run,
        *,
        playbook_path: Path,
        playbook_project_dir: Path,
        **_kwargs: object,
    ) -> tuple[int, str]:
        observed["content"] = playbook_path.read_text(encoding="utf-8")
        observed["file_mode"] = stat.S_IMODE(playbook_path.stat().st_mode)
        observed["directory_mode"] = stat.S_IMODE(playbook_project_dir.stat().st_mode)
        observed["isolated"] = playbook_project_dir == playbook_path.parent
        return 0, "successful"

    monkeypatch.setattr(AnsibleExecutor, "run", execute_database_playbook)
    coordinator = _Coordinator()
    settings = Settings(
        playbook_source_mode="mount",
        playbook_workspace=tmp_path / "must-not-be-read",
        runtime_dir=tmp_path / "runtime-database",
        master_key=_master_key(),
    )
    await execute_run(
        run,
        factory=cast(Any, _Factory()),
        settings=settings,
        coordinator=cast(Any, coordinator),
    )

    assert observed == {
        "content": content,
        "file_mode": 0o600,
        "directory_mode": 0o700,
        "isolated": True,
    }
    assert coordinator.finished[-1]["status"] is RunStatus.SUCCEEDED
    assert not (settings.runtime_dir / str(run.run_id)).exists()
    assert "worker-playbook-sentinel" not in str(coordinator.events)

    tampered = run.model_copy(update={"workspace_revision": "0" * 64})
    await _install_execution_fakes(monkeypatch, tampered, (_target(tampered, host),))
    rejected = _Coordinator()
    await execute_run(
        tampered,
        factory=cast(Any, _Factory()),
        settings=settings,
        coordinator=cast(Any, rejected),
    )
    assert rejected.finished[-1]["status"] is RunStatus.REJECTED

@pytest.mark.asyncio
async def test_audit_retention_worker_handles_batches_busy_lock_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[AuditEventDraft] = []
    logged: list[tuple[AuditAction, AuditOutcome]] = []

    class _Audit:
        responses: ClassVar[list[object]] = []

        def __init__(self, _factory: object) -> None:
            pass

        async def purge_batch(self, _retention_days: int) -> tuple[bool, int]:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return cast(tuple[bool, int], response)

        async def record_best_effort(self, event: AuditEventDraft) -> None:
            recorded.append(event)

    monkeypatch.setattr(worker_module, "AuditService", _Audit)
    monkeypatch.setattr(
        worker_module,
        "log_event",
        lambda action, outcome, **_values: logged.append((action, outcome)),
    )
    settings = Settings(audit_retention_days=180)

    _Audit.responses = [(True, 5000), (True, 17), (True, 0)]
    await _purge_expired_audit(cast(Any, object()), settings, worker_id="worker-a")
    assert recorded[-1].metadata["purged_count"] == 5017

    _Audit.responses = [(False, 0)]
    await _purge_expired_audit(cast(Any, object()), settings, worker_id="worker-b")
    assert logged[-1] == (AuditAction.AUDIT_RETENTION_PURGED, AuditOutcome.NOOP)

    _Audit.responses = [RuntimeError("database offline")]
    await _purge_expired_audit(cast(Any, object()), settings, worker_id="worker-c")
    assert logged[-1] == (AuditAction.AUDIT_RETENTION_PURGED, AuditOutcome.FAILED)


class _PoolContext:
    async def __aenter__(self) -> object:
        return object()

    async def __aexit__(self, *_args: object) -> None:
        return None


class _WorkerPool:
    def __init__(self, *, open_error: Exception | None = None) -> None:
        self.open_error = open_error
        self.closed = False

    async def open(self) -> None:
        if self.open_error is not None:
            raise self.open_error

    async def close(self) -> None:
        self.closed = True

    def connection(self) -> _PoolContext:
        return _PoolContext()


@pytest.mark.asyncio
async def test_run_worker_logs_database_recovery_and_closes_on_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pool = _WorkerPool()
    audit_events: list[AuditEventDraft] = []
    active = _run((_host(),))

    class _Migration:
        def __init__(self, *_args: object) -> None:
            pass

        async def validate_current(self) -> None:
            return None

    class _Credential:
        def __init__(self, *_args: object) -> None:
            pass

        async def ensure_master_key(self) -> None:
            return None

    class _Audit:
        def __init__(self, _factory: object) -> None:
            pass

        async def record_best_effort(self, event: AuditEventDraft) -> None:
            audit_events.append(event)

    class _WorkerCoordinator:
        def __init__(self, *_args: object) -> None:
            self.heartbeats = 0
            self.claims = 0
            self.finished: list[RunStatus] = []

        async def recover_stale(self) -> int:
            return 1

        async def heartbeat(self) -> None:
            self.heartbeats += 1
            if self.heartbeats == 3:
                raise asyncio.CancelledError

        async def claim(self) -> Run | None:
            self.claims += 1
            return active if self.claims == 1 else None

        async def finish(self, _run_id: UUID, *, status: RunStatus, **_values: object) -> None:
            self.finished.append(status)

    async def failed_execution(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("execution boundary")

    async def no_sleep(_seconds: float) -> None:
        return None

    async def no_purge(*_args: object, **_kwargs: object) -> None:
        return None

    orphan = tmp_path / "runtime" / str(uuid4())
    orphan.mkdir(parents=True)
    monkeypatch.setenv("OPS_COMPOSER_WORKER_ID", "worker-fixed")
    monkeypatch.setattr(worker_module, "create_pool", lambda _url: pool)
    monkeypatch.setattr(worker_module, "MigrationRunner", _Migration)
    monkeypatch.setattr(worker_module, "CredentialService", _Credential)
    monkeypatch.setattr(worker_module, "AuditService", _Audit)
    monkeypatch.setattr(worker_module, "WorkerCoordinator", _WorkerCoordinator)
    monkeypatch.setattr(worker_module, "execute_run", failed_execution)
    monkeypatch.setattr(worker_module, "_purge_expired_audit", no_purge)
    monkeypatch.setattr(worker_module.asyncio, "sleep", no_sleep)

    with pytest.raises(asyncio.CancelledError):
        await run_worker(
            Settings(runtime_dir=tmp_path / "runtime", master_key=_master_key())
        )
    assert pool.closed
    assert not orphan.exists()
    actions = [event.event_action for event in audit_events]
    assert AuditAction.RUNTIME_DIRECTORY_CLEANED in actions
    assert AuditAction.WORKER_READY in actions
    assert AuditAction.DATABASE_RECOVERED in actions
    assert AuditAction.WORKER_STOPPED in actions


@pytest.mark.asyncio
async def test_run_worker_reports_each_startup_failure_without_masking_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit_events: list[AuditEventDraft] = []

    class _Audit:
        def __init__(self, _factory: object) -> None:
            pass

        async def record_best_effort(self, event: AuditEventDraft) -> None:
            audit_events.append(event)

    monkeypatch.setattr(worker_module, "AuditService", _Audit)

    unavailable = _WorkerPool(open_error=ConnectionError("database offline"))
    monkeypatch.setattr(worker_module, "create_pool", lambda _url: unavailable)
    with pytest.raises(ConnectionError):
        await run_worker(Settings(runtime_dir=tmp_path / "unavailable", master_key=_master_key()))

    class _MigrationFailure:
        def __init__(self, *_args: object) -> None:
            pass

        async def validate_current(self) -> None:
            raise RuntimeError("migration invalid")

    migration_pool = _WorkerPool()
    monkeypatch.setattr(worker_module, "create_pool", lambda _url: migration_pool)
    monkeypatch.setattr(worker_module, "MigrationRunner", _MigrationFailure)
    with pytest.raises(RuntimeError, match="migration invalid"):
        await run_worker(Settings(runtime_dir=tmp_path / "migration", master_key=_master_key()))
    assert migration_pool.closed

    class _MigrationOk(_MigrationFailure):
        async def validate_current(self) -> None:
            return None

    class _CredentialFailure:
        def __init__(self, *_args: object) -> None:
            pass

        async def ensure_master_key(self) -> None:
            raise ValueError("key mismatch")

    key_pool = _WorkerPool()
    monkeypatch.setattr(worker_module, "create_pool", lambda _url: key_pool)
    monkeypatch.setattr(worker_module, "MigrationRunner", _MigrationOk)
    monkeypatch.setattr(worker_module, "CredentialService", _CredentialFailure)
    with pytest.raises(ValueError, match="key mismatch"):
        await run_worker(Settings(runtime_dir=tmp_path / "key", master_key=_master_key()))
    assert key_pool.closed
    assert AuditAction.MASTER_KEY_VALIDATION_FAILED in {
        event.event_action for event in audit_events
    }
