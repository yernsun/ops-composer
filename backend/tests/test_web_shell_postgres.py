from __future__ import annotations

import asyncio
import base64
import os
from datetime import timedelta
from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from ops_composer.auth.service import AuthService
from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import WebShellCapacityError, WebShellSessionExpiredError
from ops_composer.domain.ops import CommandMode, RunStatus, TargetKind
from ops_composer.domain.web_shell import WebShellCloseReason
from ops_composer.services.assets import AssetService, CredentialService
from ops_composer.services.crypto import CredentialCipher
from ops_composer.services.runs import RunService, WorkerCoordinator
from ops_composer.services.web_shell import WebShellService
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


def _database_url() -> str:
    value = os.getenv("TEST_DATABASE_URL")
    if not value:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL Web Shell integration tests")
    return value


@pytest.mark.asyncio
async def test_web_shell_migration_capacity_ticket_lease_and_shared_host_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    database_url = _database_url()
    schema = f"ops_web_shell_{uuid4().hex}"
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
                applied = await MigrationRunner(connection, MIGRATIONS[:-1]).up()
                assert applied[-1] == "0050_playbooks"

            master_key = base64.b64encode(b"0123456789abcdef" * 2).decode()
            settings = Settings(
                app_env="test",
                database_url=isolated_url,
                master_key=master_key,
                runtime_dir=tmp_path / "runtime",
                web_shell_max_sessions=1,
                worker_lease_seconds=5,
                worker_stale_after_seconds=10,
            )
            factory = UnitOfWorkFactory(pool)
            auth = AuthService(factory, settings)
            administrator = await auth.bootstrap("admin", "correct horse battery staple")
            issued = await auth.login(
                "admin", "correct horse battery staple", "web-shell-integration"
            )
            cipher = CredentialCipher(master_key, 1)
            credentials = CredentialService(factory, cipher)
            await credentials.ensure_master_key()
            credential = await credentials.create(
                name="web-shell-password",
                username="deploy",
                password="web-shell-secret-sentinel",
                become_password=None,
                become_enabled=False,
                become_method="sudo",
                become_user="root",
                description="Web Shell integration",
            )
            assets = AssetService(factory)
            host = await assets.create_host(
                name="shell-host-one",
                address="192.0.2.80",
                ssh_port=22,
                credential_id=credential.credential_id,
                python_interpreter="/usr/bin/python3",
                enabled=True,
                description="first",
                variables={},
            )

            async def scanned_keys(_host_id):
                return (
                    {
                        "algorithm": "ssh-ed25519",
                        "publicKey": "AAAAC3NzaC1lZDI1NTE5AAAA",
                        "fingerprint": "SHA256:web-shell-integration",
                    },
                )

            monkeypatch.setattr(assets, "scan_host_keys", scanned_keys)
            await assets.confirm_host_key(
                host.host_id,
                algorithm="ssh-ed25519",
                fingerprint="SHA256:web-shell-integration",
                user_id=administrator.user_id,
            )
            runs = RunService(factory, settings)
            queued = await runs.create_command(
                requested_by=administrator.user_id,
                idempotency_key="web-shell-shared-lock-run",
                target_kind=TargetKind.HOSTS,
                host_ids=(host.host_id,),
                group_id=None,
                mode=CommandMode.COMMAND,
                command="true",
                become="DISABLED",
                shell_confirmed=False,
                timeout_seconds=30,
                forks=1,
            )

            lock_started = utc_now()
            lock_expires = lock_started + timedelta(seconds=30)
            async with pool.connection() as connection, connection.transaction():
                await connection.execute(
                    sql.SQL(
                        "INSERT INTO host_run_locks "
                        "(host_id, run_id, worker_id, acquired_at, expires_at) VALUES "
                        "(%(host_id)s, %(run_id)s, %(worker_id)s, %(acquired_at)s, "
                        "%(expires_at)s)"
                    ),
                    {
                        "host_id": host.host_id,
                        "run_id": queued.run_id,
                        "worker_id": "worker-before-upgrade",
                        "acquired_at": lock_started,
                        "expires_at": lock_expires,
                    },
                )
            async with pool.connection() as connection:
                assert await MigrationRunner(connection, MIGRATIONS).up() == ("0060_web_shell",)
                await MigrationRunner(connection, MIGRATIONS).validate_current()
                migrated = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT run_id, web_shell_session_id, owner_id "
                            "FROM host_execution_locks WHERE host_id = %(host_id)s"
                        ),
                        {"host_id": host.host_id},
                    )
                ).fetchone()
                assert migrated == {
                    "run_id": queued.run_id,
                    "web_shell_session_id": None,
                    "owner_id": "worker-before-upgrade",
                }
                await connection.execute(
                    sql.SQL("DELETE FROM host_execution_locks WHERE host_id = %(host_id)s"),
                    {"host_id": host.host_id},
                )
                await connection.commit()

            web_shell = WebShellService(factory, settings, cipher)
            pending = await web_shell.create(host.host_id, issued.principal, "api-integration")
            worker = WorkerCoordinator(factory, settings, "worker-integration")
            assert await worker.claim() is None

            launch = await web_shell.claim(
                pending.web_shell_session_id,
                issued.principal,
                "api-integration:connection",
            )
            assert launch.password.get_secret_value() == "web-shell-secret-sentinel"
            assert "web-shell-secret-sentinel" not in repr(launch)
            with pytest.raises(WebShellSessionExpiredError):
                await web_shell.claim(
                    pending.web_shell_session_id,
                    issued.principal,
                    "api-integration:duplicate",
                )
            assert (
                await web_shell.heartbeat(
                    pending.web_shell_session_id,
                    "api-integration:connection",
                    utc_now(),
                )
                is None
            )
            await auth.logout(issued.principal)
            assert (
                await web_shell.heartbeat(
                    pending.web_shell_session_id,
                    "api-integration:connection",
                    utc_now(),
                )
                is WebShellCloseReason.AUTH_SESSION_INVALID
            )
            await web_shell.finish(
                pending.web_shell_session_id,
                "api-integration:connection",
                WebShellCloseReason.AUTH_SESSION_INVALID,
                duration_ms=10,
                exit_code=None,
            )

            claimed = await worker.claim()
            assert claimed is not None and claimed.run_id == queued.run_id
            await worker.mark_running(queued.run_id)
            await worker.finish(
                queued.run_id,
                status=RunStatus.SUCCEEDED,
                return_code=0,
                summary={"total": 1, "succeeded": 1, "failed": 0},
            )

            issued = await auth.login(
                "admin", "correct horse battery staple", "web-shell-capacity"
            )
            second_host = await assets.create_host(
                name="shell-host-two",
                address="192.0.2.81",
                ssh_port=22,
                credential_id=credential.credential_id,
                python_interpreter="/usr/bin/python3",
                enabled=True,
                description="second",
                variables={},
            )
            await assets.confirm_host_key(
                second_host.host_id,
                algorithm="ssh-ed25519",
                fingerprint="SHA256:web-shell-integration",
                user_id=administrator.user_id,
            )
            concurrent = await asyncio.gather(
                web_shell.create(host.host_id, issued.principal, "api-capacity-a"),
                web_shell.create(second_host.host_id, issued.principal, "api-capacity-b"),
                return_exceptions=True,
            )
            created = [item for item in concurrent if not isinstance(item, BaseException)]
            rejected = [item for item in concurrent if isinstance(item, WebShellCapacityError)]
            assert len(created) == 1
            assert len(rejected) == 1
            capacity_session = created[0]
            await web_shell.request_close(capacity_session.web_shell_session_id, issued.principal)

            stale = await web_shell.create(host.host_id, issued.principal, "api-stale")
            expired = utc_now() - timedelta(seconds=1)
            acquired = expired - timedelta(seconds=30)
            async with pool.connection() as connection, connection.transaction():
                await connection.execute(
                    sql.SQL(
                        "UPDATE web_shell_sessions SET created_at = %(acquired)s, "
                        "ticket_expires_at = %(expired)s, lease_expires_at = %(expired)s "
                        "WHERE web_shell_session_id = %(session_id)s"
                    ),
                    {
                        "acquired": acquired,
                        "expired": expired,
                        "session_id": stale.web_shell_session_id,
                    },
                )
                await connection.execute(
                    sql.SQL(
                        "UPDATE host_execution_locks SET acquired_at = %(acquired)s, "
                        "expires_at = %(expired)s WHERE "
                        "web_shell_session_id = %(session_id)s"
                    ),
                    {
                        "acquired": acquired,
                        "expired": expired,
                        "session_id": stale.web_shell_session_id,
                    },
                )
            assert await web_shell.recover_stale() == 1

            async with pool.connection() as connection:
                remaining = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT count(*) AS count FROM host_execution_locks "
                            "WHERE web_shell_session_id = %(session_id)s"
                        ),
                        {"session_id": stale.web_shell_session_id},
                    )
                ).fetchone()
                audit_dump = await (
                    await connection.execute(
                        sql.SQL(
                            "SELECT string_agg(metadata::text, '') AS body FROM audit_events"
                        )
                    )
                ).fetchone()
                assert remaining is not None and remaining["count"] == 0
                assert audit_dump is not None
                assert "web-shell-secret-sentinel" not in (audit_dump["body"] or "")
        finally:
            await pool.close()
    finally:
        async with control_pool.connection() as connection:
            await connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
            await connection.commit()
        await control_pool.close()
