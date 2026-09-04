from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.errors import ObjectNotInPrerequisiteState

from ops_composer.auth.service import AuthService
from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    ConflictError,
    HostKeyConfirmationRequiredError,
    IdempotencyConflictError,
    NotFoundError,
    PlaybookInvalidError,
    PlaybookVersionConflictError,
    ValidationError,
)
from ops_composer.domain.ops import (
    CommandMode,
    HostGroup,
    PlaybookReference,
    PlaybookSource,
    RunStatus,
    TargetKind,
)
from ops_composer.services.assets import AssetService, CredentialService
from ops_composer.services.crypto import CredentialCipher
from ops_composer.services.playbooks import PlaybookService
from ops_composer.services.runs import RunService, WorkerCoordinator
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.worker import AnsibleExecutor, execute_run


def _database_url() -> str:
    value = os.getenv("TEST_DATABASE_URL")
    if not value:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL queue integration tests")
    return value


@pytest.mark.asyncio
async def test_postgresql_queue_idempotency_lease_lock_events_and_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database_url = _database_url()
    schema = f"ops_queue_{uuid4().hex}"
    control_pool = create_pool(database_url)
    await control_pool.open()
    try:
        async with control_pool.connection() as connection:
            await connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            await connection.commit()

        isolated_url = make_conninfo(database_url, options=f"-c search_path={schema}")
        pool = create_pool(isolated_url)
        await pool.open()
        try:
            async with pool.connection() as connection:
                await MigrationRunner(connection, MIGRATIONS).up()
                await MigrationRunner(connection, MIGRATIONS).validate_current()

            master_key = base64.b64encode(b"0123456789abcdef" * 2).decode()
            settings = Settings(
                app_env="test",
                database_url=isolated_url,
                master_key=master_key,
                runtime_dir=tmp_path / "runtime",
                worker_lease_seconds=5,
                worker_stale_after_seconds=10,
            )
            factory = UnitOfWorkFactory(pool)
            administrator = await AuthService(factory, settings).bootstrap(
                "admin", "correct horse battery staple"
            )
            credentials = CredentialService(factory, CredentialCipher(master_key, 1))
            await credentials.ensure_master_key()
            await credentials.ensure_master_key()
            credential = await credentials.create(
                name="integration-password",
                username="root",
                password="database-must-not-contain-this-secret",
                become_password="sudo-must-not-be-plaintext",
                become_enabled=True,
                become_method="sudo",
                become_user="root",
                description="integration",
            )
            assert credential in await credentials.list()
            assert await credentials.get(credential.credential_id) == credential
            original_secret = await credentials.decrypt_revision(credential.credential_id, 1)
            assert original_secret["password"] == "database-must-not-contain-this-secret"
            rotated = await credentials.rotate(
                credential.credential_id,
                password="rotated-database-secret",
                become_password="rotated-sudo-secret",
            )
            assert rotated.current_version == 2
            assert (await credentials.decrypt_revision(credential.credential_id, 2)) == {
                "password": "rotated-database-secret",
                "becomePassword": "rotated-sudo-secret",
            }
            assets = AssetService(factory)
            host = await assets.create_host(
                name="integration-host",
                address="192.0.2.20",
                ssh_port=22,
                credential_id=credential.credential_id,
                python_interpreter="/usr/bin/python3",
                enabled=True,
                description="integration",
                variables={"environment": "test"},
            )
            assert host in await assets.list_hosts()
            assert await assets.get_host(host.host_id) == host
            host = await assets.update_host(
                host.host_id,
                expected_version=host.version,
                name="integration-host-renamed",
                address="192.0.2.21",
                ssh_port=2222,
                credential_id=credential.credential_id,
                python_interpreter="/usr/bin/python3",
                enabled=True,
                description="updated integration host",
                variables={"environment": "test", "role": "worker"},
            )
            assert host.version == 2
            group = await assets.create_group(
                name="integration-group",
                description="integration targets",
                variables={"region": "test-1"},
                host_ids=(host.host_id,),
            )
            assert group in await assets.list_groups()
            assert (await assets.resolve(target_kind=TargetKind.ALL))[0].host_id == host.host_id
            assert (
                await assets.resolve(
                    target_kind=TargetKind.HOSTS,
                    host_ids=(host.host_id,),
                )
            )[0].host_id == host.host_id
            assert (
                await assets.resolve(target_kind=TargetKind.GROUP, group_id=group.group_id)
            )[0].group_variables == {"region": "test-1"}
            group = await assets.update_group(
                group.group_id,
                name="integration-group-renamed",
                description="updated targets",
                variables={"region": "test-2"},
                host_ids=(host.host_id,),
            )
            assert group.name == "integration-group-renamed"

            runs = RunService(factory, settings)
            with pytest.raises(HostKeyConfirmationRequiredError):
                await runs.create_ping(
                    requested_by=administrator.user_id,
                    idempotency_key="missing-host-key-postgres",
                    host_id=host.host_id,
                )
            async with pool.connection() as connection:
                row = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT count(*) AS count FROM runs "
                            "WHERE idempotency_key = %(idempotency_key)s"
                        ),
                        {"idempotency_key": "missing-host-key-postgres"},
                    )
                ).fetchone()
                assert row is not None
                assert row["count"] == 0

            async def scanned_keys(_host_id):
                return (
                    {
                        "algorithm": "ssh-ed25519",
                        "publicKey": "AAAAC3NzaC1lZDI1NTE5AAAA",
                        "fingerprint": "SHA256:integration-key",
                    },
                )

            monkeypatch.setattr(assets, "scan_host_keys", scanned_keys)
            trusted_key = await assets.confirm_host_key(
                host.host_id,
                algorithm="ssh-ed25519",
                fingerprint="SHA256:integration-key",
                user_id=administrator.user_id,
            )
            assert trusted_key in await assets.list_host_keys(host.host_id)

            with pytest.raises(ConflictError):
                await credentials.delete(credential.credential_id)
            with pytest.raises(NotFoundError):
                await assets.get_host(uuid4())
            with pytest.raises(ValidationError):
                await assets.resolve(target_kind=TargetKind.HOSTS, host_ids=(uuid4(),))
            with pytest.raises(ValidationError):
                await assets.resolve(target_kind=TargetKind.GROUP)

            async with pool.connection() as connection:
                row = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT encrypted_secret FROM credential_revisions "
                            "WHERE credential_id = %(credential_id)s"
                        ),
                        {"credential_id": credential.credential_id},
                    )
                ).fetchone()
                assert row is not None
                assert b"database-must-not-contain-this-secret" not in row["encrypted_secret"]

            async def create(key: str, command: str = "true"):
                return await runs.create_command(
                    requested_by=administrator.user_id,
                    idempotency_key=key,
                    target_kind=TargetKind.HOSTS,
                    host_ids=(host.host_id,),
                    group_id=None,
                    mode=CommandMode.COMMAND,
                    command=command,
                    become="CREDENTIAL_DEFAULT",
                    shell_confirmed=False,
                    timeout_seconds=30,
                    forks=1,
                )

            first, duplicate = await asyncio.gather(
                create("postgres-idempotency-0001"),
                create("postgres-idempotency-0001"),
            )
            assert first.run_id == duplicate.run_id
            with pytest.raises(IdempotencyConflictError):
                await create("postgres-idempotency-0001", "hostname")
            second = await create("postgres-idempotency-0002")

            worker_a = WorkerCoordinator(factory, settings, "worker-a")
            worker_b = WorkerCoordinator(factory, settings, "worker-b")
            claimed_first = await worker_a.claim()
            assert claimed_first is not None
            assert claimed_first.run_id == first.run_id
            assert await worker_b.claim() is None

            await worker_a.mark_running(first.run_id)
            await worker_a.finish(
                first.run_id,
                status=RunStatus.SUCCEEDED,
                return_code=0,
                summary={"total": 1, "succeeded": 1, "failed": 0},
            )
            claimed_second = await worker_b.claim()
            assert claimed_second is not None
            assert claimed_second.run_id == second.run_id
            await worker_b.mark_running(second.run_id)

            expired = utc_now() - timedelta(seconds=1)
            stale_started = expired - timedelta(seconds=settings.worker_lease_seconds)
            async with pool.connection() as connection, connection.transaction():
                await connection.execute(
                    sql.SQL(
                        "UPDATE worker_leases SET heartbeat_at = %(stale_started)s, "
                        "expires_at = %(expired)s "
                        "WHERE worker_id = %(worker_id)s"
                    ),
                    {
                        "stale_started": stale_started,
                        "expired": expired,
                        "worker_id": "worker-b",
                    },
                )
                await connection.execute(
                    sql.SQL(
                        "UPDATE host_run_locks SET acquired_at = %(stale_started)s, "
                        "expires_at = %(expired)s "
                        "WHERE worker_id = %(worker_id)s"
                    ),
                    {
                        "stale_started": stale_started,
                        "expired": expired,
                        "worker_id": "worker-b",
                    },
                )
            recovery = WorkerCoordinator(factory, settings, "worker-recovery")
            assert await recovery.recover_stale() == 1
            assert (await runs.get(second.run_id)).status is RunStatus.INTERRUPTED

            successful = await create("postgres-execution-success")
            execution_worker = WorkerCoordinator(factory, settings, "worker-execution")
            claimed_success = await execution_worker.claim()
            assert claimed_success is not None
            assert claimed_success.run_id == successful.run_id

            def successful_execution(_executor, _run, *, event_handler, **_kwargs):
                event_handler(
                    {
                        "event": "runner_on_ok",
                        "stdout": "rotated-database-secret must be redacted",
                        "event_data": {
                            "host": host.name,
                            "task": "safe task",
                            "res": {"changed": True},
                        },
                    }
                )
                return 0, "successful"

            monkeypatch.setattr(AnsibleExecutor, "run", successful_execution)
            await execute_run(
                claimed_success,
                factory=factory,
                settings=settings,
                coordinator=execution_worker,
            )
            completed, completed_targets = await runs.detail(successful.run_id)
            assert completed.status is RunStatus.SUCCEEDED
            assert completed_targets[0].status.value == "SUCCEEDED"
            assert completed_targets[0].changed_count == 1
            assert "rotated-database-secret" not in completed_targets[0].stdout
            assert not (settings.runtime_dir / str(successful.run_id)).exists()

            second_host = await assets.create_host(
                name="integration-host-two",
                address="192.0.2.22",
                ssh_port=22,
                credential_id=credential.credential_id,
                python_interpreter=None,
                enabled=True,
                description="partial target",
                variables={},
            )
            await assets.confirm_host_key(
                second_host.host_id,
                algorithm="ssh-ed25519",
                fingerprint="SHA256:integration-key",
                user_id=administrator.user_id,
            )
            partial = await runs.create_command(
                requested_by=administrator.user_id,
                idempotency_key="postgres-execution-partial",
                target_kind=TargetKind.HOSTS,
                host_ids=(host.host_id, second_host.host_id),
                group_id=None,
                mode=CommandMode.COMMAND,
                command="true",
                become="CREDENTIAL_DEFAULT",
                shell_confirmed=False,
                timeout_seconds=30,
                forks=2,
            )
            partial_worker = WorkerCoordinator(factory, settings, "worker-partial")
            claimed_partial = await partial_worker.claim()
            assert claimed_partial is not None
            assert claimed_partial.run_id == partial.run_id

            def partial_execution(_executor, _run, *, event_handler, **_kwargs):
                event_handler(
                    {
                        "event": "runner_on_ok",
                        "stdout": "first host ok",
                        "event_data": {"host": host.name, "res": {"changed": False}},
                    }
                )
                event_handler(
                    {
                        "event": "runner_on_failed",
                        "stdout": "second host failed",
                        "event_data": {"host": second_host.name, "res": {"failed": True}},
                    }
                )
                return 2, "failed"

            monkeypatch.setattr(AnsibleExecutor, "run", partial_execution)
            await execute_run(
                claimed_partial,
                factory=factory,
                settings=settings,
                coordinator=partial_worker,
            )
            assert (await runs.get(partial.run_id)).status is RunStatus.PARTIAL

            failed = await create("postgres-execution-error")
            failed_worker = WorkerCoordinator(factory, settings, "worker-failed")
            claimed_failed = await failed_worker.claim()
            assert claimed_failed is not None
            assert claimed_failed.run_id == failed.run_id

            def failed_execution(_executor, _run, **_kwargs):
                raise RuntimeError("password=rotated-database-secret")

            monkeypatch.setattr(AnsibleExecutor, "run", failed_execution)
            await execute_run(
                claimed_failed,
                factory=factory,
                settings=settings,
                coordinator=failed_worker,
            )
            failed_result = await runs.get(failed.run_id)
            assert failed_result.status is RunStatus.FAILED
            assert failed_result.failure_message == "runner execution failed"
            assert "rotated-database-secret" not in json.dumps(
                [
                    event.model_dump(mode="json")
                    for event in await runs.events_after(failed.run_id, 0)
                ]
            )

            assert await runs.dashboard() == {
                "host_count": 2,
                "enabled_host_count": 2,
                "runs_today": 5,
                "failed_runs": 3,
                "active_runs": 0,
            }

            appended = await asyncio.gather(
                *(
                    worker_a.append_event(first.run_id, event_type=f"concurrent_{index}")
                    for index in range(12)
                )
            )
            sequences = [event.sequence for event in appended]
            assert len(set(sequences)) == 12
            replayed = await runs.events_after(first.run_id, 0)
            assert [event.sequence for event in replayed] == sorted(
                event.sequence for event in replayed
            )

            now = utc_now()
            rolled_back = HostGroup(
                group_id=uuid4(),
                name="must-rollback",
                description="",
                variables={},
                created_at=now,
                updated_at=now,
            )
            with pytest.raises(RuntimeError, match="force rollback"):
                async with factory() as unit_of_work:
                    await unit_of_work.assets.add_group(rolled_back)
                    raise RuntimeError("force rollback")
            assert all(
                group.group_id != rolled_back.group_id for group in await assets.list_groups()
            )

            playbooks = PlaybookService(factory, settings)
            revision_one_content = (
                "---\n- name: Database revision one\n  hosts: all\n"
                "  gather_facts: false\n  tasks:\n"
                "    - name: Ping\n      ansible.builtin.ping:\n"
                "# sentinel-database-playbook-content\n"
            )
            database_playbook = await playbooks.create_database(
                actor_user_id=administrator.user_id,
                name="Database site",
                description="integration database Playbook",
                enabled=True,
                content=revision_one_content,
            )
            with pytest.raises(ConflictError):
                await playbooks.create_database(
                    actor_user_id=administrator.user_id,
                    name="database SITE",
                    description="case-insensitive duplicate",
                    enabled=True,
                    content=revision_one_content,
                )
            with pytest.raises(PlaybookInvalidError):
                await playbooks.create_database(
                    actor_user_id=administrator.user_id,
                    name="Invalid root",
                    description="invalid",
                    enabled=True,
                    content="key: value\n",
                )

            revision_two_content = revision_one_content.replace(
                "revision one", "revision two"
            )
            database_playbook = await playbooks.update_database(
                database_playbook.playbook.playbook_id,
                actor_user_id=administrator.user_id,
                expected_version=database_playbook.playbook.version,
                name=database_playbook.playbook.name,
                description=database_playbook.playbook.description,
                enabled=True,
                content=revision_two_content,
            )
            with pytest.raises(PlaybookVersionConflictError):
                await playbooks.update_database(
                    database_playbook.playbook.playbook_id,
                    actor_user_id=administrator.user_id,
                    expected_version=1,
                    name=database_playbook.playbook.name,
                    description="stale update",
                    enabled=True,
                    content=revision_one_content,
                )

            pinned_run = await runs.create_playbook(
                requested_by=administrator.user_id,
                idempotency_key="postgres-database-playbook-run",
                target_kind=TargetKind.HOSTS,
                host_ids=(host.host_id,),
                group_id=None,
                playbook=PlaybookReference(
                    source=PlaybookSource.DATABASE,
                    playbook_id=database_playbook.playbook.playbook_id,
                ),
                extra_vars={"region": "test"},
                tags=(),
                skip_tags=(),
                timeout_seconds=30,
                forks=1,
            )
            assert pinned_run.playbook_revision == 2
            assert pinned_run.workspace_revision == database_playbook.revision.sha256

            revision_three = await playbooks.update_database(
                database_playbook.playbook.playbook_id,
                actor_user_id=administrator.user_id,
                expected_version=database_playbook.playbook.version,
                name=database_playbook.playbook.name,
                description="changed after queueing",
                enabled=False,
                content=revision_one_content.replace("revision one", "revision three"),
            )
            await playbooks.delete_database(
                revision_three.playbook.playbook_id,
                actor_user_id=administrator.user_id,
                expected_version=revision_three.playbook.version,
            )
            with pytest.raises(NotFoundError):
                await playbooks.get_database(revision_three.playbook.playbook_id)

            replayed_pinned_run = await runs.create_playbook(
                requested_by=administrator.user_id,
                idempotency_key="postgres-database-playbook-run",
                target_kind=TargetKind.HOSTS,
                host_ids=(host.host_id,),
                group_id=None,
                playbook=PlaybookReference(
                    source=PlaybookSource.DATABASE,
                    playbook_id=database_playbook.playbook.playbook_id,
                ),
                extra_vars={"region": "test"},
                tags=(),
                skip_tags=(),
                timeout_seconds=30,
                forks=1,
            )
            assert replayed_pinned_run.run_id == pinned_run.run_id

            playbook_worker = WorkerCoordinator(factory, settings, "worker-playbook")
            claimed_playbook = await playbook_worker.claim()
            assert claimed_playbook is not None
            assert claimed_playbook.run_id == pinned_run.run_id

            def database_playbook_execution(
                _executor,
                _run,
                *,
                playbook_path,
                playbook_project_dir,
                event_handler,
                **_kwargs,
            ):
                assert playbook_path.read_text(encoding="utf-8") == revision_two_content
                assert stat.S_IMODE(playbook_path.stat().st_mode) == 0o600
                assert stat.S_IMODE(playbook_project_dir.stat().st_mode) == 0o700
                assert playbook_path.parent == playbook_project_dir
                assert playbook_project_dir != settings.playbook_workspace
                event_handler(
                    {
                        "event": "runner_on_ok",
                        "stdout": "database Playbook finished",
                        "event_data": {"host": host.name, "res": {"changed": False}},
                    }
                )
                return 0, "successful"

            monkeypatch.setattr(AnsibleExecutor, "run", database_playbook_execution)
            await execute_run(
                claimed_playbook,
                factory=factory,
                settings=settings,
                coordinator=playbook_worker,
            )
            completed_playbook = await runs.get(pinned_run.run_id)
            assert completed_playbook.status is RunStatus.SUCCEEDED
            assert not (settings.runtime_dir / str(pinned_run.run_id)).exists()

            retried_playbook = await runs.retry(
                pinned_run.run_id,
                requested_by=administrator.user_id,
                idempotency_key="postgres-database-playbook-retry",
            )
            assert retried_playbook.playbook_id == pinned_run.playbook_id
            assert retried_playbook.playbook_revision == pinned_run.playbook_revision
            assert retried_playbook.workspace_revision == pinned_run.workspace_revision

            async with pool.connection() as connection:
                revision_count = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT count(*) AS count FROM playbook_revisions "
                            "WHERE playbook_id = %(playbook_id)s"
                        ),
                        {"playbook_id": pinned_run.playbook_id},
                    )
                ).fetchone()
                audit_payload = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT coalesce(string_agg(metadata::text, ''), '') AS payload "
                            "FROM audit_events WHERE resource_id = %(resource_id)s"
                        ),
                        {"resource_id": str(pinned_run.playbook_id)},
                    )
                ).fetchone()
            assert revision_count is not None and revision_count["count"] == 3
            assert audit_payload is not None
            assert "sentinel-database-playbook-content" not in audit_payload["payload"]
            assert "sentinel-database-playbook-content" not in json.dumps(
                [
                    event.model_dump(mode="json")
                    for event in await runs.events_after(pinned_run.run_id, 0)
                ]
            )
            for mutation in (
                sql.SQL(
                    "UPDATE playbook_revisions SET content = %(content)s "
                    "WHERE playbook_id = %(playbook_id)s AND revision = %(revision)s"
                ),
                sql.SQL(
                    "DELETE FROM playbook_revisions WHERE playbook_id = %(playbook_id)s "
                    "AND revision = %(revision)s"
                ),
            ):
                with pytest.raises(ObjectNotInPrerequisiteState):
                    async with pool.connection() as connection:
                        await connection.execute(
                            mutation,
                            {
                                "content": "---\n- hosts: all\n",
                                "playbook_id": pinned_run.playbook_id,
                                "revision": pinned_run.playbook_revision,
                            },
                        )
        finally:
            await pool.close()
    finally:
        async with control_pool.connection() as connection:
            await connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
            await connection.commit()
        await control_pool.close()
