from __future__ import annotations

import base64
import inspect
import json
import os
import shlex
import stat
from datetime import timedelta
from pathlib import Path
from typing import cast
from urllib.parse import quote, quote_plus
from uuid import UUID, uuid4

import pytest
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

import ops_composer.api.runs as runs_api
from ops_composer.domain.audit import AuditEventDraft
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    HostKeyChangedError,
    IdempotencyConflictError,
    ValidationError,
)
from ops_composer.domain.ops import (
    CommandMode,
    ResolvedHost,
    Run,
    RunEvent,
    RunKind,
    RunStatus,
    RunTarget,
    RunTargetStatus,
    TargetKind,
)
from ops_composer.main import SpaStaticFiles
from ops_composer.repositories.runs import PostgresRunRepository
from ops_composer.services.assets import AssetService
from ops_composer.services.crypto import CredentialCipher, redact_secrets
from ops_composer.services.inventory import build_inventory, render_inventory
from ops_composer.services.playbooks import PlaybookCatalog
from ops_composer.services.runs import RunService, _validate_extra_vars
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.worker import (
    RuntimeDirectory,
    TargetAccumulator,
    _runtime_inventory,
    _sanitize,
    cleanup_orphan_runtime,
)


def _key(byte: bytes = b"k") -> str:
    return base64.b64encode(byte * 32).decode()


def test_credential_cipher_is_authenticated_version_bound_and_not_plaintext() -> None:
    credential_id = uuid4()
    cipher = CredentialCipher(_key(), 1)
    secret = {"password": "correct horse battery staple", "becomePassword": "sudo secret"}
    envelope = cipher.encrypt(credential_id, 3, secret)

    assert b"correct horse battery staple" not in envelope
    assert b"sudo secret" not in envelope
    assert cipher.decrypt(credential_id, 3, envelope) == secret
    with pytest.raises(ValueError, match="authentication failed"):
        cipher.decrypt(credential_id, 4, envelope)
    tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
    with pytest.raises(ValueError, match="authentication failed"):
        cipher.decrypt(credential_id, 3, tampered)

    check = cipher.encrypt_check()
    cipher.validate_check(check)
    with pytest.raises(ValueError, match="does not match"):
        CredentialCipher(_key(b"z"), 1).validate_check(check)


def test_secret_redaction_covers_exact_shell_json_and_url_encodings() -> None:
    secret = "p@ss word'\""
    variants = (
        secret,
        shlex.quote(secret),
        json.dumps(secret)[1:-1],
        quote(secret, safe=""),
        quote_plus(secret, safe=""),
    )
    for variant in variants:
        assert redact_secrets(variant, (secret,)) == "[REDACTED]"
    sanitized = _sanitize(
        {"stdout": f"value={secret}", "password": "another", "nested": [secret]},
        (secret,),
    )
    assert sanitized == {
        "stdout": "value=[REDACTED]",
        "password": "[REDACTED]",
        "nested": ["[REDACTED]"],
    }


def _resolved_host(*, become: bool = False) -> ResolvedHost:
    return ResolvedHost(
        host_id=uuid4(),
        name="worker-01",
        address="192.0.2.10",
        ssh_port=2222,
        credential_id=uuid4(),
        credential_version=7,
        credential_username="deployer",
        credential_public_config={
            "becomeEnabled": become,
            "becomeMethod": "sudo",
            "becomeUser": "root",
        },
        python_interpreter="/usr/bin/python3",
        host_variables={"environment": "test"},
        group_variables={"region": "ap-southeast"},
    )


def _run(host: ResolvedHost, *, become: str = "CREDENTIAL_DEFAULT") -> Run:
    now = utc_now()
    return Run(
        run_id=uuid4(),
        kind=RunKind.COMMAND,
        status=RunStatus.QUEUED,
        target_spec={"kind": "HOSTS", "hostIds": [str(host.host_id)], "groupId": None},
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
        operation_spec={"mode": "COMMAND", "command": "id", "become": become},
        inventory_snapshot=build_inventory((host,)),
        credential_versions={str(host.credential_id): host.credential_version},
        timeout_seconds=60,
        forks=1,
        requested_by=uuid4(),
        idempotency_key="idempotency-key",
        request_fingerprint="f" * 64,
        created_at=now,
        updated_at=now,
    )


class _Credentials:
    async def decrypt_revision(self, _credential_id: UUID, version: int) -> dict[str, str]:
        assert version == 7
        return {"password": "ssh secret", "becomePassword": "sudo secret"}


@pytest.mark.asyncio
async def test_inventory_snapshot_is_secret_free_and_become_override_is_runtime_only() -> None:
    host = _resolved_host(become=False)
    safe = build_inventory((host,))
    rendered = render_inventory(safe)
    assert "ssh secret" not in rendered
    assert "ansible_password" not in rendered
    assert "ansible_become" not in rendered

    enabled, secrets = await _runtime_inventory(
        _run(host, become="ENABLED"), cast(object, _Credentials())
    )
    variables = cast(dict[str, object], cast(dict[str, object], enabled["all"])["hosts"])
    target = cast(dict[str, object], variables[host.name])
    assert target["ansible_password"] == "ssh secret"
    assert target["ansible_become"] is True
    assert target["ansible_become_password"] == "sudo secret"
    assert secrets == ("ssh secret", "sudo secret")

    default_enabled = _resolved_host(become=True)
    disabled, _ = await _runtime_inventory(
        _run(default_enabled, become="DISABLED"), cast(object, _Credentials())
    )
    disabled_hosts = cast(dict[str, object], cast(dict[str, object], disabled["all"])["hosts"])
    disabled_target = cast(dict[str, object], disabled_hosts[default_enabled.name])
    assert "ansible_become" not in disabled_target
    assert "ansible_become_password" not in disabled_target


def test_runtime_directory_permissions_truncation_and_orphan_cleanup(tmp_path: Path) -> None:
    run_id = uuid4()
    root = tmp_path / "runtime"
    with RuntimeDirectory(root, run_id) as runtime:
        secret_file = runtime.write("nested/inventory.yml", "secret")
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(runtime.path.stat().st_mode) == 0o700
        assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert not (root / str(run_id)).exists()

    orphan = root / str(uuid4())
    orphan.mkdir()
    keep = root / "operator-notes"
    keep.mkdir()
    cleanup_orphan_runtime(root)
    assert not orphan.exists()
    assert keep.exists()

    host = _resolved_host()
    target = RunTarget(
        run_target_id=uuid4(),
        run_id=uuid4(),
        host_id=host.host_id,
        host_name=host.name,
        host_address=host.address,
        status=RunTargetStatus.RUNNING,
    )
    accumulator = TargetAccumulator(target=target)
    accumulator.add_output("abcdefgh", 5)
    assert "".join(accumulator.chunks) == "abcde"
    assert accumulator.truncated


@pytest.mark.asyncio
async def test_playbook_catalog_rejects_traversal_symlinks_and_invalid_roots(
    tmp_path: Path,
) -> None:
    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    good = playbooks / "status.yml"
    good.write_text("- hosts: all\n  gather_facts: false\n  tasks: []\n", encoding="utf-8")
    (playbooks / "vars.yml").write_text("key: value\n", encoding="utf-8")
    outside = tmp_path / "outside.yml"
    outside.write_text("- hosts: all\n", encoding="utf-8")
    (playbooks / "escape.yml").symlink_to(outside)

    catalog = PlaybookCatalog(tmp_path)
    result = await catalog.list()
    assert [item.path for item in result] == ["playbooks/status.yml"]
    assert (await catalog.get("playbooks/status.yml")).sha256
    with pytest.raises(ValidationError, match="relative"):
        catalog.resolve(str(good.resolve()))
    with pytest.raises(ValidationError, match="escapes"):
        catalog.resolve("playbooks/../../outside.yml")
    with pytest.raises(ValidationError, match="escapes"):
        catalog.resolve("playbooks/escape.yml")
    with pytest.raises(ValidationError, match="root must be a list"):
        await catalog.get("playbooks/vars.yml")


@pytest.mark.parametrize(
    "extra_vars",
    [
        {"dbPassword": "plaintext"},
        {"nested": {"api_token": "plaintext"}},
        {"ansible_user": "root"},
        {"values": [{"private-key": "plaintext"}]},
    ],
)
def test_secret_and_connection_extra_vars_are_rejected(extra_vars: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="not supported"):
        _validate_extra_vars(extra_vars)


class _AssetsRepository:
    def __init__(self, host: ResolvedHost) -> None:
        self.host = host

    async def resolve_host_ids(self, _host_ids: tuple[UUID, ...]) -> tuple[ResolvedHost, ...]:
        return (self.host,)


class _RunsRepository:
    def __init__(self) -> None:
        self.runs: dict[UUID, Run] = {}
        self.idempotency: dict[tuple[UUID, str], UUID] = {}
        self.run_targets: dict[UUID, tuple[RunTarget, ...]] = {}
        self.events: list[RunEvent] = []

    async def create_or_get(self, run: Run, targets: tuple[RunTarget, ...]) -> tuple[Run, bool]:
        key = (run.requested_by, run.idempotency_key)
        existing_id = self.idempotency.get(key)
        if existing_id is not None:
            return self.runs[existing_id], False
        self.idempotency[key] = run.run_id
        self.runs[run.run_id] = run
        self.run_targets[run.run_id] = targets
        return run, True

    async def append_event(self, event: RunEvent) -> RunEvent:
        persisted = event.model_copy(update={"sequence": len(self.events) + 1})
        self.events.append(persisted)
        return persisted

    async def get(self, run_id: UUID) -> Run | None:
        return self.runs.get(run_id)

    async def targets(self, run_id: UUID) -> tuple[RunTarget, ...]:
        return self.run_targets.get(run_id, ())


class _AuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEventDraft] = []

    async def append(self, event: AuditEventDraft) -> AuditEventDraft:
        self.events.append(event)
        return event


class _Unit:
    def __init__(self, assets: _AssetsRepository, runs: _RunsRepository) -> None:
        self.assets = assets
        self.runs = runs
        self.audit = _AuditRepository()


class _UnitContext:
    def __init__(self, unit: _Unit) -> None:
        self.unit = unit

    async def __aenter__(self) -> _Unit:
        return self.unit

    async def __aexit__(self, *_args: object) -> None:
        return None


class _Factory:
    def __init__(self, unit: _Unit) -> None:
        self.unit = unit

    def __call__(self) -> _UnitContext:
        return _UnitContext(self.unit)


@pytest.mark.asyncio
async def test_run_creation_is_idempotent_and_retry_clones_immutable_snapshots() -> None:
    host = _resolved_host()
    runs = _RunsRepository()
    factory = _Factory(_Unit(_AssetsRepository(host), runs))
    service = RunService(cast(UnitOfWorkFactory, factory), Settings())
    requested_by = uuid4()
    arguments = {
        "requested_by": requested_by,
        "idempotency_key": "create-command-0001",
        "target_kind": TargetKind.HOSTS,
        "host_ids": (host.host_id,),
        "group_id": None,
        "mode": CommandMode.COMMAND,
        "command": "uname -a",
        "become": "CREDENTIAL_DEFAULT",
        "shell_confirmed": False,
        "timeout_seconds": 60,
        "forks": 1,
    }
    created = await service.create_command(**arguments)
    duplicate = await service.create_command(**arguments)
    assert duplicate.run_id == created.run_id
    assert len(runs.runs) == 1
    assert len(runs.events) == 1
    assert "ansible_password" not in json.dumps(created.inventory_snapshot)

    changed = dict(arguments)
    changed["command"] = "hostname"
    with pytest.raises(IdempotencyConflictError):
        await service.create_command(**changed)

    runs.runs[created.run_id] = created.model_copy(update={"status": RunStatus.FAILED})
    original_target = runs.run_targets[created.run_id][0]
    factory.unit.assets.host = host.model_copy(
        update={"address": "198.51.100.99", "credential_version": 8}
    )
    retried = await service.retry(
        created.run_id,
        requested_by=requested_by,
        idempotency_key="retry-command-0001",
    )
    assert retried.run_id != created.run_id
    assert retried.source_run_id == created.run_id
    assert retried.resolved_targets == created.resolved_targets
    assert retried.credential_versions == created.credential_versions
    retried_target = runs.run_targets[retried.run_id][0]
    assert retried_target.host_address == original_target.host_address


@pytest.mark.asyncio
async def test_only_terminal_runs_can_be_retried() -> None:
    host = _resolved_host()
    runs = _RunsRepository()
    factory = _Factory(_Unit(_AssetsRepository(host), runs))
    service = RunService(cast(UnitOfWorkFactory, factory), Settings())
    source = _run(host)
    runs.runs[source.run_id] = source
    runs.run_targets[source.run_id] = (
        RunTarget(
            run_target_id=uuid4(),
            run_id=source.run_id,
            host_id=host.host_id,
            host_name=host.name,
            host_address=host.address,
            status=RunTargetStatus.PENDING,
        ),
    )
    with pytest.raises(ValidationError, match="terminal"):
        await service.retry(
            source.run_id,
            requested_by=source.requested_by,
            idempotency_key="retry-command-0002",
        )


def test_queue_repository_uses_postgresql_claim_lock_lease_and_returning() -> None:
    source = inspect.getsource(PostgresRunRepository)
    assert "FOR UPDATE OF r SKIP LOCKED" in source
    assert "FROM candidate WHERE r.run_id = candidate.run_id RETURNING {}" in source
    assert ").format(QUALIFIED_RUN_COLUMNS)" in source
    assert "ON CONFLICT (host_id) DO NOTHING RETURNING host_id" in source
    assert "UPDATE runs SET next_event_sequence = next_event_sequence + 1" in source
    assert "RETURNING next_event_sequence - 1 AS sequence" in source
    assert "WORKER_LEASE_EXPIRED" in source
    assert "redis" not in source.casefold()


@pytest.mark.asyncio
async def test_spa_static_files_fall_back_only_for_client_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def static_response(_self: StaticFiles, path: str, _scope: Scope) -> Response:
        if path == "index.html":
            return Response("<main>OpsComposer</main>")
        if path == "assets/app.js":
            return Response("console.log('ok')")
        if Path(path).suffix:
            raise StarletteHTTPException(status_code=404)
        return Response(status_code=404)

    monkeypatch.setattr(StaticFiles, "get_response", static_response)
    files = SpaStaticFiles(directory=tmp_path, html=True)
    scope = cast(Scope, {"type": "http", "method": "GET", "headers": []})
    route = await files.get_response("runs/4ca03ac6-781c-4832-835d-5372e392ecae", scope)
    asset = await files.get_response("assets/app.js", scope)
    with pytest.raises(StarletteHTTPException) as missing:
        await files.get_response("assets/missing.js", scope)
    assert route.status_code == 200
    assert asset.status_code == 200
    assert missing.value.status_code == 404


@pytest.mark.asyncio
async def test_sse_uses_one_replayable_event_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    host = _resolved_host()
    run = _run(host).model_copy(update={"status": RunStatus.SUCCEEDED, "finished_at": utc_now()})
    event = RunEvent(
        run_event_id=uuid4(),
        run_id=run.run_id,
        sequence=9,
        event_type="runner_on_ok",
        stdout="ok",
        event_data={"host": host.name},
        created_at=utc_now(),
    )

    class _Service:
        calls = 0

        async def get(self, _run_id: UUID) -> Run:
            return run

        async def events_after(self, _run_id: UUID, sequence: int) -> tuple[RunEvent, ...]:
            self.calls += 1
            assert sequence in {3, 9}
            return (event,) if self.calls == 1 else ()

    class _Request:
        async def is_disconnected(self) -> bool:
            return False

    monkeypatch.setattr(runs_api, "_service", lambda _factory: _Service())
    response = await runs_api.stream_run_events(
        run.run_id,
        cast(object, _Request()),
        cast(UnitOfWorkFactory, object()),
        cast(object, object()),
        after=3,
        last_event_id="2",
    )
    chunk = await anext(response.body_iterator)
    text = chunk.decode() if isinstance(chunk, bytes) else chunk
    assert "id: 9\n" in text
    assert "event: run-event\n" in text
    assert '"eventType":"runner_on_ok"' in text


@pytest.mark.asyncio
async def test_host_key_confirmation_reports_a_specific_change_error() -> None:
    service = AssetService(cast(UnitOfWorkFactory, object()))

    async def scan(_host_id: UUID) -> tuple[dict[str, str], ...]:
        return (
            {
                "algorithm": "ssh-ed25519",
                "publicKey": "AAAAC3NzaC1lZDI1NTE5AAAA",
                "fingerprint": "SHA256:new",
            },
        )

    service.scan_host_keys = scan  # type: ignore[method-assign]
    with pytest.raises(HostKeyChangedError):
        await service.confirm_host_key(
            uuid4(), algorithm="ssh-ed25519", fingerprint="SHA256:old", user_id=uuid4()
        )


def test_runtime_defaults_do_not_reference_external_middleware() -> None:
    settings = Settings()
    fields = Settings.model_fields
    assert settings.database_url.startswith("postgresql://")
    assert not {"redis_url", "broker_url", "sqlite_path", "object_store_url"} & fields.keys()
    assert os.fspath(settings.runtime_dir)
    assert timedelta(seconds=settings.worker_lease_seconds) < timedelta(
        seconds=settings.worker_stale_after_seconds
    )
