from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

import typer
from pydantic import ValidationError

from ops_composer.auth.errors import AdminAlreadyExistsError
from ops_composer.auth.service import AuthService
from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.observability import (
    bind_log_context,
    configure_logging,
    log_event,
    safe_exception_fields,
)
from ops_composer.services.audit import AuditService, new_audit_event
from ops_composer.settings import Settings, get_settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.worker import run_worker

app = typer.Typer(no_args_is_help=True, help="OpsComposer administration")
migrate = typer.Typer(help="Manage immutable checksum migrations")
configuration = typer.Typer(help="Inspect redacted runtime configuration")
admin = typer.Typer(help="Bootstrap the single administrator")
audit = typer.Typer(help="Query, export, and retain PostgreSQL business audit events")
app.add_typer(migrate, name="migrate")
app.add_typer(configuration, name="config")
app.add_typer(admin, name="admin")
app.add_typer(audit, name="audit")


def _configure_logging(service: str = "cli") -> None:
    try:
        settings = get_settings()
    except ValidationError:
        configure_logging(service=service)
        return
    configure_logging(
        service=service,
        environment=settings.app_env.value,
        level=settings.log_level.value,
    )
    bind_log_context(correlation_id=uuid4().hex)


def _safe_configuration_errors(error: ValidationError) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for detail in error.errors(include_url=False, include_context=False, include_input=False):
        location = ".".join(str(part) for part in detail.get("loc", ())) or "settings"
        errors.append(
            {
                "location": location,
                "type": str(detail.get("type", "validation_error")),
                "message": str(detail.get("msg", "invalid value")),
            }
        )
    return errors


@asynccontextmanager
async def _runner() -> AsyncIterator[MigrationRunner]:
    settings = get_settings()
    pool = create_pool(settings.database_url)
    await pool.open()
    try:
        async with pool.connection() as connection:
            yield MigrationRunner(connection, MIGRATIONS)
    finally:
        await pool.close()


@asynccontextmanager
async def _audit_runtime() -> AsyncIterator[tuple[AuditService, Settings]]:
    settings = get_settings()
    pool = create_pool(settings.database_url)
    await pool.open()
    try:
        yield AuditService(UnitOfWorkFactory(pool)), settings
    finally:
        await pool.close()


def _timestamp(value: str, *, option: str) -> datetime:
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise typer.BadParameter("must be an ISO-8601 timestamp", param_hint=option) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise typer.BadParameter("must include a timezone", param_hint=option)
    return parsed.astimezone(UTC)


def _audit_action(value: str | None) -> AuditAction | None:
    if value is None:
        return None
    try:
        return AuditAction(value.strip().upper())
    except ValueError as error:
        raise typer.BadParameter("unknown audit action", param_hint="--action") from error


def _audit_outcome(value: str | None) -> AuditOutcome | None:
    if value is None:
        return None
    try:
        return AuditOutcome(value.strip().upper())
    except ValueError as error:
        raise typer.BadParameter("unknown audit outcome", param_hint="--outcome") from error


def _audit_source(value: str | None) -> AuditSource | None:
    if value is None:
        return None
    try:
        return AuditSource(value.strip().upper())
    except ValueError as error:
        raise typer.BadParameter("unknown audit source", param_hint="--source") from error


def _query(
    *,
    since: str | None,
    until: str | None,
    action: str | None,
    outcome: str | None,
    source: str | None,
    run_id: UUID | None,
    actor_user_id: UUID | None,
    resource_type: str | None,
    resource_id: str | None,
    error_code: str | None,
    before_id: int | None,
    limit: int,
) -> AuditQuery:
    return AuditQuery(
        since=(
            _timestamp(since, option="--since")
            if since is not None
            else utc_now() - timedelta(hours=24)
        ),
        until=_timestamp(until, option="--until") if until is not None else None,
        action=_audit_action(action),
        outcome=_audit_outcome(outcome),
        source=_audit_source(source),
        run_id=run_id,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        error_code=error_code,
        before_id=before_id,
        limit=limit,
    )


@migrate.command("status")
def migration_status() -> None:
    async def run() -> None:
        async with _runner() as runner:
            for entry in await runner.status():
                typer.echo(f"{entry.state.value:8} {entry.migration_id} {entry.checksum[:12]}")

    asyncio.run(run())


@migrate.command("validate")
def migration_validate() -> None:
    async def run() -> None:
        async with _runner() as runner:
            await runner.validate()

    try:
        asyncio.run(run())
    except Exception as error:
        log_event(
            AuditAction.MIGRATION_VALIDATION_FAILED,
            AuditOutcome.FAILED,
            source=AuditSource.CLI,
            severity=AuditSeverity.ERROR,
            message="migration validation failed",
            failure_stage="migration_validation",
            retryable=False,
            exception_type=type(error).__name__,
            metadata=safe_exception_fields(error),
            exc_info=True,
        )
        raise
    typer.echo("migration history is valid")


@migrate.command("up")
def migration_up() -> None:
    async def run() -> tuple[str, ...]:
        async with _runner() as runner:
            return await runner.up()

    log_event(
        AuditAction.MIGRATION_STARTED,
        AuditOutcome.STARTED,
        source=AuditSource.CLI,
        message="migration apply started",
    )
    try:
        applied = asyncio.run(run())
    except Exception as error:
        log_event(
            AuditAction.MIGRATION_FAILED,
            AuditOutcome.FAILED,
            source=AuditSource.CLI,
            severity=AuditSeverity.ERROR,
            message="migration apply failed",
            failure_stage="migration_apply",
            retryable=False,
            exception_type=type(error).__name__,
            metadata=safe_exception_fields(error),
            exc_info=True,
        )
        raise
    log_event(
        AuditAction.MIGRATION_COMPLETED,
        AuditOutcome.SUCCEEDED if applied else AuditOutcome.NOOP,
        source=AuditSource.CLI,
        message="migration apply completed",
        metadata={"applied_count": len(applied), "migration_ids": applied},
    )
    typer.echo("applied: " + (", ".join(applied) if applied else "none"))


@configuration.command("check")
def configuration_check(
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        summary = Settings().safe_summary()
    except ValidationError as error:
        errors = _safe_configuration_errors(error)
        if as_json:
            typer.echo(json.dumps({"ok": False, "errors": errors}, sort_keys=True))
        else:
            typer.secho("configuration invalid", fg=typer.colors.RED, err=True)
            for detail in errors:
                typer.echo(
                    f"- {detail['location']}: {detail['message']} ({detail['type']})",
                    err=True,
                )
        raise typer.Exit(code=2) from error
    if as_json:
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        typer.echo(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


@admin.command("bootstrap")
def admin_bootstrap(
    username: Annotated[str, typer.Option("--username", "-u")] = "admin",
) -> None:
    """Create the only administrator; the password is never accepted on argv."""

    password = typer.prompt(
        "Administrator password",
        hide_input=True,
        confirmation_prompt=True,
    )

    async def run() -> str:
        settings = get_settings()
        pool = create_pool(settings.database_url)
        await pool.open()
        try:
            factory = UnitOfWorkFactory(pool)
            service = AuthService(factory, settings)
            try:
                identity = await service.bootstrap(username, password)
            except AdminAlreadyExistsError as error:
                await AuditService(factory).record_best_effort(
                    new_audit_event(
                        AuditAction.ADMIN_BOOTSTRAP_REJECTED,
                        AuditOutcome.DENIED,
                        source=AuditSource.CLI,
                        error_code=error.code,
                        failure_stage="admin_bootstrap",
                        retryable=False,
                    )
                )
                error.audit_recorded = True
                raise
            return identity.username
        finally:
            await pool.close()

    try:
        created_username = asyncio.run(run())
    except AdminAlreadyExistsError as error:
        typer.secho(error.public_message, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from error
    except ValueError as error:
        typer.secho(str(error), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from error
    typer.secho(f"administrator '{created_username}' created", fg=typer.colors.GREEN)


@app.command("purge-expired-auth")
def purge_expired_auth(
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    async def run() -> tuple[int, int]:
        settings = get_settings()
        pool = create_pool(settings.database_url)
        await pool.open()
        try:
            return await AuthService(UnitOfWorkFactory(pool), settings).purge_expired(
                dry_run=dry_run
            )
        finally:
            await pool.close()

    sessions, rate_limits = asyncio.run(run())
    action = "would_purge" if dry_run else "purged"
    typer.echo(f"{action} sessions={sessions} rate_limits={rate_limits}")


@audit.command("list")
def audit_list(
    since: Annotated[str | None, typer.Option(help="Inclusive ISO-8601 lower bound")] = None,
    until: Annotated[str | None, typer.Option(help="Exclusive ISO-8601 upper bound")] = None,
    action: Annotated[str | None, typer.Option(help="Exact event action")] = None,
    outcome: Annotated[str | None, typer.Option(help="Exact event outcome")] = None,
    source: Annotated[str | None, typer.Option(help="API, WORKER, CLI, or SYSTEM")] = None,
    run_id: Annotated[UUID | None, typer.Option()] = None,
    actor_user_id: Annotated[UUID | None, typer.Option()] = None,
    resource_type: Annotated[str | None, typer.Option()] = None,
    resource_id: Annotated[str | None, typer.Option()] = None,
    error_code: Annotated[str | None, typer.Option()] = None,
    before_id: Annotated[int | None, typer.Option(min=1)] = None,
    limit: Annotated[int, typer.Option(min=1, max=10_000)] = 200,
    as_jsonl: Annotated[bool, typer.Option("--jsonl")] = False,
) -> None:
    query = _query(
        since=since,
        until=until,
        action=action,
        outcome=outcome,
        source=source,
        run_id=run_id,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        error_code=error_code,
        before_id=before_id,
        limit=limit,
    )

    async def run() -> tuple[AuditEvent, ...]:
        async with _audit_runtime() as (service, _):
            return await service.list(query)

    events = asyncio.run(run())
    if as_jsonl:
        for event in events:
            typer.echo(
                json.dumps(
                    event.model_dump(mode="json"),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        return
    typer.echo(
        "id\toccurred_at\tseverity\tsource\taction\toutcome\tresource\terror_code"
    )
    for value in events:
        event = value
        resource = (
            f"{event.resource_type}:{event.resource_id}"
            if event.resource_type is not None
            else "-"
        )
        typer.echo(
            "\t".join(
                (
                    str(event.audit_event_id),
                    event.occurred_at.isoformat(),
                    event.severity.value,
                    event.source.value,
                    event.event_action.value,
                    event.event_outcome.value,
                    resource,
                    event.error_code or "-",
                )
            )
        )


@audit.command("export")
def audit_export(
    since: Annotated[str, typer.Option(help="Inclusive ISO-8601 lower bound")],
    until: Annotated[str, typer.Option(help="Exclusive ISO-8601 upper bound")],
    output: Annotated[Path, typer.Option("--output", "-o")],
    action: Annotated[str | None, typer.Option()] = None,
    outcome: Annotated[str | None, typer.Option()] = None,
    source: Annotated[str | None, typer.Option()] = None,
    run_id: Annotated[UUID | None, typer.Option()] = None,
    actor_user_id: Annotated[UUID | None, typer.Option()] = None,
    resource_type: Annotated[str | None, typer.Option()] = None,
    resource_id: Annotated[str | None, typer.Option()] = None,
    error_code: Annotated[str | None, typer.Option()] = None,
    force: Annotated[bool, typer.Option(help="Replace an existing regular file")] = False,
) -> None:
    base_query = _query(
        since=since,
        until=until,
        action=action,
        outcome=outcome,
        source=source,
        run_id=run_id,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        error_code=error_code,
        before_id=None,
        limit=1_000,
    )
    destination = output.expanduser().resolve(strict=False)
    if not destination.parent.is_dir():
        raise typer.BadParameter("output parent directory does not exist", param_hint="--output")
    if destination.exists() and not force:
        raise typer.BadParameter("output already exists; use --force", param_hint="--output")
    if destination.exists() and not destination.is_file():
        raise typer.BadParameter("output must be a regular file", param_hint="--output")
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")

    async def run() -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        total = 0
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                async with _audit_runtime() as (service, _):
                    cursor: int | None = None
                    while True:
                        page = await service.list(
                            base_query.model_copy(update={"before_id": cursor})
                        )
                        for event in page:
                            stream.write(
                                json.dumps(
                                    event.model_dump(mode="json"),
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                    sort_keys=True,
                                )
                                + "\n"
                            )
                        total += len(page)
                        if len(page) < base_query.limit:
                            break
                        cursor = page[-1].audit_event_id
                stream.flush()
                os.fsync(stream.fileno())
            if force:
                os.replace(temporary, destination)
            else:
                os.link(temporary, destination)
                os.unlink(temporary)
            return total
        except BaseException:
            if temporary.exists():
                temporary.unlink()
            raise

    exported = asyncio.run(run())

    async def record_export() -> None:
        async with _audit_runtime() as (service, _):
            await service.record_best_effort(
                new_audit_event(
                    AuditAction.AUDIT_EXPORTED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.CLI,
                    resource_type="audit_export",
                    resource_id=destination.name,
                    metadata={"event_count": exported},
                )
            )

    asyncio.run(record_export())
    typer.echo(f"exported={exported} output={destination}")


@audit.command("purge")
def audit_purge(
    before: Annotated[
        str | None,
        typer.Option(help="Delete events before this ISO-8601 timestamp"),
    ] = None,
    execute: Annotated[
        bool,
        typer.Option(help="Perform deletion; omission is a dry run"),
    ] = False,
) -> None:
    async def run() -> tuple[datetime, int, bool]:
        async with _audit_runtime() as (service, settings):
            cutoff = (
                _timestamp(before, option="--before")
                if before is not None
                else utc_now() - timedelta(days=settings.audit_retention_days)
            )
            count = await service.count_before(cutoff)
            if not execute:
                return cutoff, count, True
            purged = 0
            acquired = True
            while True:
                acquired, batch = await service.purge_before(cutoff)
                if not acquired or batch == 0:
                    break
                purged += batch
            await service.record_best_effort(
                new_audit_event(
                    AuditAction.AUDIT_RETENTION_PURGED,
                    AuditOutcome.SUCCEEDED if acquired else AuditOutcome.NOOP,
                    source=AuditSource.CLI,
                    metadata={
                        "cutoff": cutoff,
                        "purged_count": purged,
                        "lock_acquired": acquired,
                    },
                )
            )
            return cutoff, purged, acquired

    cutoff, count, acquired = asyncio.run(run())
    action_text = "purged" if execute else "would_purge"
    suffix = "" if acquired else " lock=busy"
    typer.echo(f"{action_text}={count} before={cutoff.isoformat()}{suffix}")


@app.command("worker")
def worker() -> None:
    """Run the PostgreSQL-backed single-concurrency worker loop."""

    try:
        asyncio.run(run_worker(get_settings()))
    except KeyboardInterrupt:
        typer.echo("worker stopped")


def main() -> None:
    _configure_logging()
    app()
