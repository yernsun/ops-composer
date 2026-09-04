from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.types import Scope

from ops_composer.api.assets import router as assets_router
from ops_composer.api.errors import install_error_handlers
from ops_composer.api.health import router as health_router
from ops_composer.api.observability import RequestContextMiddleware, configure_logging
from ops_composer.api.playbooks import router as playbooks_router
from ops_composer.api.runs import router as runs_router
from ops_composer.api.system import router as system_router
from ops_composer.auth.api import router as auth_router
from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.observability import log_event, safe_exception_fields
from ops_composer.services.assets import CredentialService
from ops_composer.services.audit import AuditService, new_audit_event
from ops_composer.services.crypto import CredentialCipher
from ops_composer.settings import get_settings
from ops_composer.uow.factory import UnitOfWorkFactory


class SpaStaticFiles(StaticFiles):
    """Serve the Vue entry point for client-side routes, while keeping asset 404s."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as error:
            if error.status_code != 404 or Path(path).suffix:
                raise
            return await super().get_response("index.html", scope)
        if response.status_code == 404 and not Path(path).suffix:
            return await super().get_response("index.html", scope)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    log_event(
        AuditAction.APP_STARTING,
        AuditOutcome.STARTED,
        source=AuditSource.SYSTEM,
        message="API process is starting",
    )
    pool = create_pool(settings.database_url)
    try:
        await pool.open()
    except Exception as error:
        log_event(
            AuditAction.DATABASE_UNAVAILABLE,
            AuditOutcome.FAILED,
            source=AuditSource.SYSTEM,
            severity=AuditSeverity.CRITICAL,
            message="API could not open the PostgreSQL connection pool",
            failure_stage="database_pool_open",
            retryable=True,
            exception_type=type(error).__name__,
            metadata=safe_exception_fields(error),
            exc_info=True,
        )
        raise
    audit_service: AuditService | None = None
    ready = False
    try:
        try:
            async with pool.connection() as connection:
                await MigrationRunner(connection, MIGRATIONS).validate_current()
        except Exception as error:
            log_event(
                AuditAction.MIGRATION_VALIDATION_FAILED,
                AuditOutcome.FAILED,
                source=AuditSource.SYSTEM,
                severity=AuditSeverity.CRITICAL,
                message="API migration validation failed",
                failure_stage="migration_validation",
                retryable=False,
                exception_type=type(error).__name__,
                metadata=safe_exception_fields(error),
                exc_info=True,
            )
            raise
        factory = UnitOfWorkFactory(pool)
        audit_service = AuditService(factory)
        cipher = CredentialCipher(
            settings.master_key.get_secret_value(), settings.master_key_version
        )
        try:
            await CredentialService(factory, cipher).ensure_master_key()
        except Exception as error:
            await audit_service.record_best_effort(
                new_audit_event(
                    AuditAction.MASTER_KEY_VALIDATION_FAILED,
                    AuditOutcome.FAILED,
                    source=AuditSource.SYSTEM,
                    severity=AuditSeverity.CRITICAL,
                    failure_stage="master_key_validation",
                    retryable=False,
                    exception_type=type(error).__name__,
                    metadata=safe_exception_fields(error),
                )
            )
            raise
        try:
            settings.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            settings.runtime_dir.chmod(0o700)
        except OSError as error:
            await audit_service.record_best_effort(
                new_audit_event(
                    AuditAction.RUNTIME_DIRECTORY_FAILED,
                    AuditOutcome.FAILED,
                    source=AuditSource.SYSTEM,
                    severity=AuditSeverity.CRITICAL,
                    failure_stage="runtime_directory",
                    retryable=False,
                    exception_type=type(error).__name__,
                    metadata=safe_exception_fields(error),
                )
            )
            raise
        app.state.database_pool = pool
        app.state.unit_of_work_factory = factory
        await audit_service.record_best_effort(
            new_audit_event(
                AuditAction.APP_READY,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.SYSTEM,
            )
        )
        ready = True
        yield
    finally:
        if audit_service is not None and ready:
            await audit_service.record_best_effort(
                new_audit_event(
                    AuditAction.APP_STOPPED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.SYSTEM,
                )
            )
        await pool.close()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(
        service="api",
        environment=settings.app_env.value,
        level=settings.log_level.value,
    )
    application = FastAPI(
        title="OpsComposer API",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.add_middleware(RequestContextMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Idempotency-Key", "X-Request-ID"],
    )
    application.include_router(health_router)
    application.include_router(auth_router)
    application.include_router(assets_router)
    application.include_router(playbooks_router)
    application.include_router(runs_router)
    application.include_router(system_router)
    install_error_handlers(application)
    static_dir = Path(settings.static_dir)
    if (static_dir / "index.html").is_file():
        application.mount("/", SpaStaticFiles(directory=static_dir, html=True), name="frontend")
    return application


app = create_app()
