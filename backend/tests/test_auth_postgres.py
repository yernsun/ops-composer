from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from ops_composer.auth.errors import (
    ActivationExpiredError,
    AdminAlreadyExistsError,
    AuthRateLimitedError,
    InvalidCredentialsError,
    InvalidMfaCodeError,
    InvalidSessionError,
    LastOwnerRequiredError,
    PermissionDeniedError,
    UserVersionConflictError,
)
from ops_composer.auth.models import (
    ChallengePurpose,
    IssuedChallenge,
    IssuedSession,
    UserRole,
    UserStatus,
)
from ops_composer.auth.security import totp_code
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
async def test_postgres_migrations_owner_mfa_sessions_and_shared_rate_limits() -> None:
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
            assert isinstance(issued, IssuedChallenge)
            assert issued.purpose is ChallengePurpose.MFA_ENROLLMENT
            assert issued.enrollment_secret is not None
            secret = issued.enrollment_secret.get_secret_value()
            step = int(utc_now().timestamp() // 30)
            completed = await service.complete_mfa(
                issued.challenge_token.get_secret_value(),
                totp_code(secret, step),
                expected_purpose=ChallengePurpose.MFA_ENROLLMENT,
            )
            assert len(completed.recovery_codes) == 10
            resolved = await service.resolve(
                completed.issued.session_token.get_secret_value()
            )
            assert resolved.user_id == identity.user_id
            assert resolved.username == "admin"
            assert resolved.role is UserRole.OWNER
            assert resolved.mfa_enabled
            assert resolved.elevated_until is not None

            created_operator = await service.create_user(
                resolved,
                username="operator",
                role=UserRole.OPERATOR,
            )
            assert created_operator.user.status is UserStatus.PENDING_ACTIVATION
            activated_operator = await service.activate(
                created_operator.activation_code,
                "operator correct horse battery staple",
            )
            assert isinstance(activated_operator, IssuedSession)
            with pytest.raises(ActivationExpiredError):
                await service.activate(
                    created_operator.activation_code,
                    "operator correct horse battery staple",
                )

            operator_principal = activated_operator.principal
            operator_security = await service.security_status(operator_principal)
            assert not operator_security.mfa_enabled
            await service.change_password(
                operator_principal,
                current_password="operator correct horse battery staple",
                new_password="operator replacement battery staple",
                mfa_value=None,
            )
            with pytest.raises(InvalidSessionError):
                await service.resolve(
                    activated_operator.session_token.get_secret_value()
                )

            reauthenticated = await service.reauthenticate(
                resolved,
                "correct horse battery staple",
                completed.recovery_codes[0],
            )
            assert reauthenticated.elevated_until is not None
            regenerated = await service.regenerate_recovery_codes(reauthenticated)
            assert len(regenerated) == 10
            owner_security = await service.security_status(reauthenticated)
            assert owner_security.mfa_enabled
            assert owner_security.unused_recovery_codes == 10

            created_admin = await service.create_user(
                reauthenticated,
                username="secondary-admin",
                role=UserRole.ADMIN,
            )
            admin_activation = await service.activate(
                created_admin.activation_code,
                "secondary admin battery staple",
            )
            assert isinstance(admin_activation, IssuedChallenge)
            assert admin_activation.enrollment_secret is not None
            admin_secret = admin_activation.enrollment_secret.get_secret_value()
            admin_completed = await service.complete_mfa(
                admin_activation.challenge_token.get_secret_value(),
                totp_code(admin_secret, int(utc_now().timestamp() // 30)),
                expected_purpose=ChallengePurpose.MFA_ENROLLMENT,
            )
            assert admin_completed.issued.principal.role is UserRole.ADMIN
            with pytest.raises(InvalidMfaCodeError):
                await service.reauthenticate(
                    admin_completed.issued.principal,
                    "secondary admin battery staple",
                    totp_code(admin_secret, int(utc_now().timestamp() // 30)),
                )
            await service.reset_user_mfa(
                reauthenticated,
                created_admin.user.user_id,
            )
            with pytest.raises(InvalidSessionError):
                await service.resolve(
                    admin_completed.issued.session_token.get_secret_value()
                )
            with pytest.raises(PermissionDeniedError):
                await service.reset_user_mfa(reauthenticated, identity.user_id)

            created_auditor = await service.create_user(
                reauthenticated,
                username="audit-reader",
                role=UserRole.AUDITOR,
            )
            reissued_auditor = await service.reissue_activation(
                reauthenticated,
                created_auditor.user.user_id,
            )
            with pytest.raises(ActivationExpiredError):
                await service.activate(
                    created_auditor.activation_code,
                    "audit reader battery staple",
                )
            auditor_session = await service.activate(
                reissued_auditor.activation_code,
                "audit reader battery staple",
            )
            assert isinstance(auditor_session, IssuedSession)
            assert auditor_session.principal.role is UserRole.AUDITOR

            operator = next(
                user
                for user in await service.list_users(reauthenticated)
                if user.user_id == created_operator.user.user_id
            )
            updated_operator = await service.update_user(
                reauthenticated,
                operator.user_id,
                role=UserRole.AUDITOR,
                status=UserStatus.ACTIVE,
                expected_version=operator.version,
            )
            assert updated_operator.role is UserRole.AUDITOR
            with pytest.raises(UserVersionConflictError):
                await service.update_user(
                    reauthenticated,
                    operator.user_id,
                    role=UserRole.AUDITOR,
                    status=UserStatus.ACTIVE,
                    expected_version=operator.version,
                )
            with pytest.raises(LastOwnerRequiredError):
                owner = next(
                    user
                    for user in await service.list_users(reauthenticated)
                    if user.user_id == identity.user_id
                )
                await service.update_user(
                    reauthenticated,
                    identity.user_id,
                    role=UserRole.ADMIN,
                    status=UserStatus.ACTIVE,
                    expected_version=owner.version,
                )

            await service.logout(resolved)
            with pytest.raises(InvalidSessionError):
                await service.resolve(completed.issued.session_token.get_secret_value())

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

            reset = await service.break_glass_reset_mfa(
                "admin",
                "RESET MFA FOR admin",
            )
            assert reset.mfa_enrollment_required
            with pytest.raises(ValueError):
                await service.break_glass_reset_mfa("admin", "wrong confirmation")
        finally:
            await pool.close()
    finally:
        async with control_pool.connection() as connection:
            await connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
            await connection.commit()
        await control_pool.close()
