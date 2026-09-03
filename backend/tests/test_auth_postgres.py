from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from ops_composer.auth.errors import (
    AdminAlreadyExistsError,
    AuthRateLimitedError,
    InvalidCredentialsError,
    InvalidSessionError,
)
from ops_composer.auth.service import AuthService
from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.base import utc_now
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


def _database_url() -> str:
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
    return database_url


@pytest.mark.asyncio
async def test_postgres_migrations_single_admin_sessions_and_shared_rate_limits() -> None:
    database_url = _database_url()
    schema = f"ops_auth_{uuid4().hex}"
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
                applied = await MigrationRunner(connection, MIGRATIONS).up()
                assert applied == tuple(migration.migration_id for migration in MIGRATIONS)
                await MigrationRunner(connection, MIGRATIONS).validate_current()

            settings = Settings(
                app_env="test",
                database_url=isolated_url,
                auth_rate_limit_secret="integration-test-rate-limit-secret",
                auth_login_username_ip_limit=100,
                auth_login_ip_limit=100,
            )
            service = AuthService(UnitOfWorkFactory(pool), settings)
            identity = await service.bootstrap("  ADMIN  ", "correct horse battery staple")
            assert identity.username == "admin"
            with pytest.raises(AdminAlreadyExistsError):
                await service.bootstrap("other", "another correct horse battery staple")

            with pytest.raises(InvalidCredentialsError):
                await service.login("admin", "wrong password", "integration-client")
            issued = await service.login(
                "ADMIN", "correct horse battery staple", "integration-client"
            )
            resolved = await service.resolve(issued.session_token.get_secret_value())
            assert resolved.user_id == identity.user_id
            assert resolved.username == "admin"

            await service.logout(resolved)
            with pytest.raises(InvalidSessionError):
                await service.resolve(issued.session_token.get_secret_value())

            limited = AuthService(
                UnitOfWorkFactory(pool),
                Settings(
                    app_env="test",
                    database_url=isolated_url,
                    auth_rate_limit_secret="shared-integration-rate-limit-secret",
                    auth_login_username_ip_limit=1,
                    auth_login_ip_limit=100,
                ),
            )
            with pytest.raises(InvalidCredentialsError):
                await limited.login("missing", "wrong password", "shared-client")
            with pytest.raises(AuthRateLimitedError):
                await limited.login("missing", "wrong password", "shared-client")

            async with UnitOfWorkFactory(pool)() as unit_of_work:
                sessions, limits = await unit_of_work.auth.purge_expired(
                    utc_now() + timedelta(days=365)
                )
            assert sessions >= 0
            assert limits > 0
        finally:
            await pool.close()
    finally:
        async with control_pool.connection() as connection:
            await connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
            await connection.commit()
        await control_pool.close()
