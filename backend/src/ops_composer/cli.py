from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import typer
from pydantic import ValidationError

from ops_composer.auth.errors import AdminAlreadyExistsError
from ops_composer.auth.service import AuthService
from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.settings import Settings, get_settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.worker import run_worker

app = typer.Typer(no_args_is_help=True, help="OpsComposer administration")
migrate = typer.Typer(help="Manage immutable checksum migrations")
configuration = typer.Typer(help="Inspect redacted runtime configuration")
admin = typer.Typer(help="Bootstrap the single administrator")
app.add_typer(migrate, name="migrate")
app.add_typer(configuration, name="config")
app.add_typer(admin, name="admin")


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

    asyncio.run(run())
    typer.echo("migration history is valid")


@migrate.command("up")
def migration_up() -> None:
    async def run() -> tuple[str, ...]:
        async with _runner() as runner:
            return await runner.up()

    applied = asyncio.run(run())
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
            service = AuthService(UnitOfWorkFactory(pool), settings)
            identity = await service.bootstrap(username, password)
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


@app.command("worker")
def worker() -> None:
    """Run the PostgreSQL-backed single-concurrency worker loop."""

    try:
        asyncio.run(run_worker(get_settings()))
    except KeyboardInterrupt:
        typer.echo("worker stopped")


def main() -> None:
    app()
