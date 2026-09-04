from __future__ import annotations

from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

import ops_composer.api.assets as assets_api
import ops_composer.api.runs as runs_api
import ops_composer.api.system as system_api
from ops_composer.auth.models import SessionPrincipal
from ops_composer.domain.base import utc_now
from ops_composer.domain.ops import (
    CommandMode,
    Credential,
    CredentialType,
    Host,
    HostGroup,
    HostKey,
    Playbook,
    ResolvedHost,
    Run,
    RunEvent,
    RunKind,
    RunStatus,
    RunTarget,
    RunTargetStatus,
    TargetKind,
)
from ops_composer.observability import log_context
from ops_composer.uow.factory import UnitOfWorkFactory


def _principal() -> SessionPrincipal:
    now = utc_now()
    return SessionPrincipal(
        session_id=uuid4(),
        user_id=uuid4(),
        username="admin",
        csrf_hash="csrf-hash",
        expires_at=now,
    )


def _models() -> tuple[
    Credential,
    Host,
    HostGroup,
    HostKey,
    ResolvedHost,
    Run,
    RunTarget,
    RunEvent,
    Playbook,
]:
    now = utc_now()
    credential = Credential(
        credential_id=uuid4(),
        name="credential",
        credential_type=CredentialType.PASSWORD,
        username="root",
        public_config={},
        current_version=1,
        enabled=True,
        description="",
        created_at=now,
        updated_at=now,
    )
    host = Host(
        host_id=uuid4(),
        name="host-01",
        address="192.0.2.10",
        ssh_port=22,
        credential_id=credential.credential_id,
        python_interpreter="/usr/bin/python3",
        enabled=True,
        description="",
        variables={},
        version=1,
        created_at=now,
        updated_at=now,
    )
    group = HostGroup(
        group_id=uuid4(),
        name="group-01",
        description="",
        variables={},
        host_ids=(host.host_id,),
        created_at=now,
        updated_at=now,
    )
    host_key = HostKey(
        host_id=host.host_id,
        algorithm="ssh-ed25519",
        public_key="AAAAC3NzaC1lZDI1NTE5AAAA",
        fingerprint="SHA256:test",
        trusted_by=uuid4(),
        trusted_at=now,
    )
    resolved = ResolvedHost(
        host_id=host.host_id,
        name=host.name,
        address=host.address,
        ssh_port=host.ssh_port,
        credential_id=credential.credential_id,
        credential_version=1,
        credential_username=credential.username,
        credential_public_config={},
        python_interpreter=host.python_interpreter,
        host_variables={},
        group_variables={},
    )
    run = Run(
        run_id=uuid4(),
        kind=RunKind.COMMAND,
        status=RunStatus.QUEUED,
        target_spec={"kind": "HOSTS"},
        resolved_targets=[],
        operation_spec={"mode": "COMMAND", "command": "true"},
        inventory_snapshot={},
        credential_versions={},
        timeout_seconds=30,
        forks=1,
        requested_by=uuid4(),
        idempotency_key="route-test-key",
        request_fingerprint="f" * 64,
        created_at=now,
        updated_at=now,
    )
    target = RunTarget(
        run_target_id=uuid4(),
        run_id=run.run_id,
        host_id=host.host_id,
        host_name=host.name,
        host_address=host.address,
        status=RunTargetStatus.PENDING,
    )
    event = RunEvent(
        run_event_id=uuid4(),
        run_id=run.run_id,
        sequence=1,
        event_type="run_queued",
        created_at=now,
    )
    playbook = Playbook(
        path="playbooks/status.yml",
        name="status",
        size=20,
        modified_at=now,
        sha256="a" * 64,
    )
    return credential, host, group, host_key, resolved, run, target, event, playbook


@pytest.mark.asyncio
async def test_asset_api_routes_delegate_without_exposing_secret_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, host, group, host_key, resolved, *_ = _models()
    principal = _principal()
    factory = cast(UnitOfWorkFactory, object())
    credentials = Mock()
    credentials.list = AsyncMock(return_value=(credential,))
    credentials.create = AsyncMock(return_value=credential)
    credentials.get = AsyncMock(return_value=credential)
    credentials.rotate = AsyncMock(return_value=credential)
    credentials.delete = AsyncMock()
    assets = Mock()
    assets.list_hosts = AsyncMock(return_value=(host,))
    assets.create_host = AsyncMock(return_value=host)
    assets.get_host = AsyncMock(return_value=host)
    assets.update_host = AsyncMock(return_value=host)
    assets.delete_host = AsyncMock()
    assets.list_groups = AsyncMock(return_value=(group,))
    assets.create_group = AsyncMock(return_value=group)
    assets.update_group = AsyncMock(return_value=group)
    assets.delete_group = AsyncMock()
    assets.resolve = AsyncMock(return_value=(resolved,))
    assets.list_host_keys = AsyncMock(return_value=(host_key,))
    assets.scan_host_keys = AsyncMock(
        return_value=(
            {
                "algorithm": host_key.algorithm,
                "publicKey": host_key.public_key,
                "fingerprint": host_key.fingerprint,
            },
        )
    )
    assets.confirm_host_key = AsyncMock(return_value=host_key)
    monkeypatch.setattr(assets_api, "_credentials", lambda _factory: credentials)
    monkeypatch.setattr(assets_api, "_assets", lambda _factory: assets)

    assert await assets_api.list_credentials(factory, principal) == (credential,)
    create_request = assets_api.CredentialCreateRequest(
        name="credential",
        username="root",
        password="ssh-password",
        become_password="sudo-password",
        become_enabled=True,
    )
    assert await assets_api.create_credential(create_request, factory, principal) == credential
    assert credentials.create.await_args.kwargs["password"] == "ssh-password"
    fetched_credential = await assets_api.get_credential(
        credential.credential_id, factory, principal
    )
    assert fetched_credential == credential
    rotate_request = assets_api.CredentialRotateRequest(
        password="rotated-password",
        become_password=None,
    )
    assert (
        await assets_api.rotate_credential(
            credential.credential_id, rotate_request, factory, principal
        )
        == credential
    )
    deleted_credential = await assets_api.delete_credential(
        credential.credential_id, factory, principal
    )
    assert deleted_credential.status_code == 204

    host_request = assets_api.HostCreateRequest(
        name=host.name,
        address=host.address,
        ssh_port=host.ssh_port,
        credential_id=credential.credential_id,
    )
    assert await assets_api.list_hosts(factory, principal) == (host,)
    assert await assets_api.create_host(host_request, factory, principal) == host
    assert await assets_api.get_host(host.host_id, factory, principal) == host
    update_request = assets_api.HostUpdateRequest(
        **host_request.model_dump(),
        version=host.version,
    )
    assert await assets_api.update_host(host.host_id, update_request, factory, principal) == host
    assert (await assets_api.delete_host(host.host_id, factory, principal)).status_code == 204

    group_request = assets_api.GroupRequest(name=group.name, host_ids=group.host_ids)
    assert await assets_api.list_groups(factory, principal) == (group,)
    assert await assets_api.create_group(group_request, factory, principal) == group
    assert await assets_api.update_group(group.group_id, group_request, factory, principal) == group
    assert (await assets_api.delete_group(group.group_id, factory, principal)).status_code == 204

    preview = await assets_api.preview_inventory(
        assets_api.TargetRequest(kind=TargetKind.HOSTS, host_ids=(host.host_id,)),
        factory,
        principal,
    )
    assert preview.host_count == 1
    assert "ansible_password" not in preview.yaml
    assert await assets_api.list_host_keys(host.host_id, factory, principal) == (host_key,)
    scanned = await assets_api.scan_host_keys(host.host_id, factory, principal)
    assert scanned[0].fingerprint == host_key.fingerprint
    confirmed = await assets_api.confirm_host_key(
        host.host_id,
        assets_api.HostKeyConfirmRequest(
            algorithm=host_key.algorithm,
            fingerprint=host_key.fingerprint,
        ),
        factory,
        principal,
        idempotency_key="host-key-route",
    )
    assert confirmed == host_key


@pytest.mark.asyncio
async def test_run_playbook_and_system_routes_delegate_and_bind_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    *_, run, target, event, playbook = _models()
    principal = _principal()
    factory = cast(UnitOfWorkFactory, object())
    service = Mock()
    service.dashboard = AsyncMock(
        return_value={
            "host_count": 2,
            "enabled_host_count": 2,
            "runs_today": 5,
            "failed_runs": 2,
            "active_runs": 0,
        }
    )
    service.list = AsyncMock(return_value=(run,))
    service.detail = AsyncMock(return_value=(run, (target,)))
    service.create_command = AsyncMock(return_value=run)
    service.create_playbook = AsyncMock(return_value=run)
    service.create_ping = AsyncMock(return_value=run)
    service.cancel = AsyncMock(return_value=run)
    retried = run.model_copy(update={"run_id": uuid4(), "source_run_id": run.run_id})
    service.retry = AsyncMock(return_value=retried)
    service.events_after = AsyncMock(return_value=(event,))
    monkeypatch.setattr(runs_api, "_service", lambda _factory: service)

    with log_context():
        overview = await runs_api.overview(factory, principal)
        assert overview.model_dump(by_alias=True) == {
            "hostCount": 2,
            "enabledHostCount": 2,
            "runsToday": 5,
            "failedRuns": 2,
            "activeRuns": 0,
        }
        assert await runs_api.list_runs(factory, principal, limit=10, offset=2) == (run,)
        detail = await runs_api.get_run(run.run_id, factory, principal)
        assert detail.targets == (target,)
        target_request = runs_api.TargetRequest(
            kind=TargetKind.HOSTS,
            host_ids=(target.host_id,),
        )
        command_request = runs_api.CommandRunRequest(
            target=target_request,
            mode=CommandMode.SHELL,
            command="printf ok",
            shell_confirmed=True,
        )
        assert (
            await runs_api.create_command_run(
                command_request, "command-route-key", factory, principal
            )
            == run
        )
        playbook_request = runs_api.PlaybookRunRequest(
            target=target_request,
            playbook_path=playbook.path,
            extra_vars={"region": "test"},
            tags=("safe",),
            skip_tags=("slow",),
        )
        assert (
            await runs_api.create_playbook_run(
                playbook_request, "playbook-route-key", factory, principal
            )
            == run
        )
        assert (
            await runs_api.test_host(target.host_id, "ping-route-key", factory, principal)
            == run
        )
        assert await runs_api.cancel_run(run.run_id, factory, principal) == run
        assert (
            await runs_api.retry_run(run.run_id, "retry-route-key", factory, principal)
            == retried
        )
        assert await runs_api.list_run_events(run.run_id, factory, principal, after=3) == (
            event,
        )

    class _Catalog:
        def __init__(self, _workspace: Path) -> None:
            pass

        async def list(self) -> tuple[Playbook, ...]:
            return (playbook,)

        async def get(self, path: str) -> Playbook:
            assert path == playbook.path
            return playbook

        async def syntax_check(self, path: str) -> tuple[bool, str]:
            assert path == playbook.path
            return True, "syntax-ok"

    monkeypatch.setattr(runs_api, "PlaybookCatalog", _Catalog)
    assert await runs_api.list_playbooks(principal) == (playbook,)
    assert await runs_api.get_playbook(playbook.path, principal) == playbook
    validation = await runs_api.validate_playbook(
        runs_api.PlaybookValidationRequest(path=playbook.path), principal
    )
    assert validation.valid is True
    assert validation.output == "syntax-ok"

    class _SystemService:
        def __init__(self, _factory: UnitOfWorkFactory, _settings: object) -> None:
            pass

        async def doctor(self) -> dict[str, object]:
            return {"database": "pass"}

    monkeypatch.setattr(system_api, "SystemService", _SystemService)
    assert (await system_api.system_info(principal))["database"] == "PostgreSQL 16 / Psycopg 3"
    assert await system_api.system_doctor(factory, principal) == {"database": "pass"}
